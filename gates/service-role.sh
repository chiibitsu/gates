#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
#
# No request-path module can reach the service-role secret.
#
# WHY THIS GATE EXISTS. In a Supabase app, Row Level Security is the whole authorisation
# story for user data, and `service_role` bypasses RLS by design — it can read and rewrite
# any row, including the authorship columns that decide who owns what. So the guarantee
# "a user cannot rewrite another user's rows" does not rest on the policies; it rests on
# NOTHING IN THE REQUEST PATH EVER HOLDING THE SERVICE-ROLE KEY. That was previously
# enforced by a comment ("Never construct a service-role client in request handling code")
# and by two zod schemas in one file. A comment is not a gate, and the audit pack said so.
#
# WHAT IT CHECKS, AND WHY IT IS SHAPED THIS WAY. Not "does anyone call createClient with
# the service key" — a constructor can be wrapped, renamed, or re-exported, and a gate that
# matches constructor names is narrower than the sentence it prints. The secret is what
# makes a client service-role: no secret, no bypass. So the check is REACHABILITY of the
# secret through the module graph, starting from the modules the framework itself invokes
# per request. That is a property of the import graph, not of a spelling.
#
# WHERE IT CANNOT ANSWER. Following the graph means resolving imports, and a shell script
# with a regex is not a JavaScript parser. A dynamic `import(expr)`, a path alias this file
# cannot map, a local specifier that resolves to no file on disk — in every one of those the
# honest answer is "I do not know what that pulls in", and this gate says UNKNOWN and goes
# red. It does NOT assume clean. Assuming clean on the branch you could not read is how a
# check ends up narrower than its own message.
source "$(dirname "$0")/lib.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---------------------------------------------------------------------------
# Applicability. This gate is about Next.js request-path modules; run against a tree that
# is not a Next.js app it has nothing to walk. Saying "ok" over an empty walk is the false
# success this toolkit refuses, so the two cases are separated and both are stated out loud:
#   - not a Next.js app        -> ok, with the reason printed
#   - a Next.js app with no findable request path -> UNKNOWN, because a Next.js app HAS one
#     and failing to find it means this gate does not understand the layout.
# ---------------------------------------------------------------------------
PKG="$ROOT/package.json"
if [ ! -f "$PKG" ] || ! grep -qE '"next"[[:space:]]*:' "$PKG"; then
  echo "not a Next.js app (no package.json depending on \"next\") — no request path to walk"
  finish
fi

# ---------------------------------------------------------------------------
# The SPEC half: the terms whose presence in a module means that module can reach
# service-role. Per-repo override, same shape as denylist.txt and required-files.txt.
# Absent file = these built-ins, which are the Supabase and this-template spellings.
# ---------------------------------------------------------------------------
TERMS_FILE="$ROOT/scripts/gates/service-role-terms.txt"
TERMS="$WORK/terms"
if [ -f "$TERMS_FILE" ]; then
  while IFS= read -r t || [ -n "$t" ]; do
    t="$(clean_list_line "$t")"
    [ -n "$t" ] && printf '%s\n' "$t"
  done < "$TERMS_FILE" > "$TERMS"
  if [ ! -s "$TERMS" ]; then
    # An empty override is a check that can never fire, wearing the name of one.
    fail "scripts/gates/service-role-terms.txt exists but lists no terms — a term list that matches nothing is not a check"
    finish
  fi
else
  cat > "$TERMS" <<'TERMS_DEFAULT'
SUPABASE_SECRET_KEY
SUPABASE_SERVICE_ROLE_KEY
SUPABASE_SERVICE_KEY
SERVICE_ROLE_KEY
service_role
serviceRole
parseServerEnv
TERMS_DEFAULT
fi

# ---------------------------------------------------------------------------
# Path alias resolution, read from tsconfig.json. If tsconfig declares `paths` and this
# cannot extract the `@/*` mapping, ALIAS_ROOT stays empty and every `@/...` specifier
# resolves to nothing — which lands in the UNKNOWN branch below rather than being skipped.
# The failure to understand the config surfaces as an unreadable import, which is what it is.
# ---------------------------------------------------------------------------
ALIAS_ROOT=""
if [ -f "$ROOT/tsconfig.json" ]; then
  alias_target="$(grep -oE '"@/\*"[[:space:]]*:[[:space:]]*\[[[:space:]]*"[^"]+"' "$ROOT/tsconfig.json" 2>/dev/null | sed -E 's/.*"([^"]+)"$/\1/' | head -1)"
  if [ -n "$alias_target" ]; then
    alias_target="${alias_target%/\*}"
    alias_target="${alias_target#./}"
    ALIAS_ROOT="$ROOT/$alias_target"
  fi
fi

# ---------------------------------------------------------------------------
# The request path: the modules Next.js itself invokes per request. Named explicitly rather
# than inferred, because "which files serve a request" is a framework convention, not
# something readable off the tree.
# ---------------------------------------------------------------------------
SEEDS="$WORK/seeds"
: > "$SEEDS"
for d in "$ROOT/src/app" "$ROOT/app" "$ROOT/src/pages" "$ROOT/pages"; do
  [ -d "$d" ] || continue
  find "$d" -type f \( -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.jsx' -o -name '*.mjs' -o -name '*.cjs' \) >> "$SEEDS"
done
for f in "$ROOT/src/middleware" "$ROOT/middleware" "$ROOT/src/proxy" "$ROOT/proxy"; do
  for ext in .ts .tsx .js .jsx .mjs .cjs; do
    [ -f "$f$ext" ] && printf '%s\n' "$f$ext" >> "$SEEDS"
  done
done
# NOTE on the toolkit's own fixtures: every other gate in this repo needs an explicit
# `fixtures/<gate>/bad/` filter, because they grep the whole tree and would otherwise report
# their own planted failures. This gate does not, and must not pretend to. Seeds are read
# from FIXED framework paths ($ROOT/src/app, $ROOT/app, $ROOT/src/pages, $ROOT/pages,
# middleware.*, proxy.*) — never by searching the tree for something app-shaped — so a
# fixture tree at fixtures/service-role/bad/src/app is not reachable from a walk rooted at
# this repo, and a filter here could never fire. A filter that cannot fire is a line that
# tells a reader they are protected by something that is not running.

if [ ! -s "$SEEDS" ]; then
  unknown "this tree depends on \"next\" but no request-path module was found under src/app, app, src/pages, pages, middleware.* or proxy.* — the gate does not understand this layout and will not report a pass it did not establish"
  finish
fi

# ---------------------------------------------------------------------------
# Walk. Visited set and queue are plain files: bash 3.2 has no associative arrays and this
# toolkit is not going to be the reason a gate silently does nothing on someone's laptop.
# ---------------------------------------------------------------------------
QUEUE="$WORK/queue"; SEEN="$WORK/seen"; EDGES="$WORK/edges"
: > "$QUEUE"; : > "$SEEN"; : > "$EDGES"

# The walk records EDGES — one `importer<TAB>imported` line per resolved import — and
# nothing else. Which request-path modules reach a given file is then COMPUTED from that
# graph, not carried along during the walk.
#
# Carrying it along is what the two previous versions of this file did, and both were wrong
# in the same direction. Each module is walked once, so whichever seed arrived first is the
# only one that propagates past it: src/lib/supabase/server.ts is imported by three
# request-path modules, and src/lib/env.ts behind it was therefore attributed to exactly
# one of them. The gate printed "1 request-path module(s) reach ..." over a tree where the
# answer was three. Not a wrong colour — the right colour with a count a reader would act
# on. Reachability is a property of the whole graph; it cannot be accumulated by a traversal
# that visits each node once.
enqueue() { # $1 = absolute file to walk
  grep -Fxq -- "$1" "$SEEN" 2>/dev/null && return 0
  printf '%s\n' "$1" >> "$SEEN"
  printf '%s\n' "$1" >> "$QUEUE"
}

# Every request-path module from which $1 is reachable, one per line. A reverse breadth-first
# search over $EDGES, intersected with the seed list at the end — so a seed that names a term
# in its own body comes back as itself, and a shared library comes back with all of them.
seeds_of() { # $1 = file
  local frontier="$WORK/rbfs.frontier" nxt="$WORK/rbfs.next" vis="$WORK/rbfs.visited"
  printf '%s\n' "$1" > "$frontier"
  printf '%s\n' "$1" > "$vis"
  while [ -s "$frontier" ]; do
    awk -F'\t' 'NR==FNR { want[$0]; next } ($2 in want) { print $1 }' "$frontier" "$EDGES" | sort -u > "$nxt"
    if [ -s "$nxt" ]; then
      grep -Fxv -f "$vis" -- "$nxt" > "$nxt.new" 2>/dev/null || : > "$nxt.new"
      mv "$nxt.new" "$nxt"
    fi
    [ -s "$nxt" ] || break
    cat "$nxt" >> "$vis"
    mv "$nxt" "$frontier"
  done
  [ -s "$SEEDS" ] || return 0
  grep -Fxf "$SEEDS" -- "$vis" 2>/dev/null | sort -u
}

rel() { printf '%s' "${1#"$ROOT"/}"; }

# Seed the walk. This loop was once lost to a bad edit, and the gate then walked NOTHING and
# printed `ok` — a clean bill of health over zero files read. That is the failure mode this
# whole toolkit is against, produced by the toolkit, so the guard after the walk exists to
# make it unrepresentable rather than merely fixed.
while IFS= read -r sd; do
  [ -n "$sd" ] && enqueue "$sd"
done < "$SEEDS"

# Resolve one specifier. 0 = resolved (path on stdout), 1 = bare/third-party (out of scope),
# 2 = local but resolves to no file (UNKNOWN).
resolve() { # $1 = specifier, $2 = importing file
  local spec="$1" base ext cand
  case "$spec" in
    ./*|../*) base="$(dirname -- "$2")/$spec" ;;
    @/*)      [ -n "$ALIAS_ROOT" ] || return 2; base="$ALIAS_ROOT/${spec#@/}" ;;
    /*)       base="$ROOT$spec" ;;
    *)        return 1 ;;
  esac
  for ext in "" .ts .tsx .js .jsx .mjs .cjs /index.ts /index.tsx /index.js /index.jsx; do
    cand="$base$ext"
    if [ -f "$cand" ]; then printf '%s' "$cand"; return 0; fi
  done
  return 2
}

# ---------------------------------------------------------------------------
# TWO PHASES, and they cannot be merged.
#
# Phase 1 walks the graph and records nothing but structure. Phase 2 scans for terms.
#
# The single-pass version scanned each module as it was dequeued, and read the reach map at
# that moment — but the map is still being written by the rest of the walk. src/lib/env.ts
# was dequeued after one request-path module had reached it and before the other three did,
# so the finding named one and the reader would have taken that for the list. A report
# assembled from a half-built index is a narrower claim than the sentence it prints, which
# is the same defect one level up from the one this gate looks for.
# ---------------------------------------------------------------------------

# ---- phase 1: walk ----
n=0
while :; do
  n=$((n+1))
  file="$(sed -n "${n}p" "$QUEUE")"
  [ -z "$file" ] && break

  # A branch of the graph this gate cannot follow. Reported here, against the module that
  # contains it, rather than assumed harmless.
  if grep -qE '(^|[^A-Za-z0-9_$.])(import|require)[[:space:]]*\([[:space:]]*[^'"'"'")[:space:]]' -- "$file" 2>/dev/null; then
    unknown "$(rel "$file") contains a non-literal import() or require() — this gate cannot tell what it pulls in, so it will not call this path clean"
  fi

  set +e
  specs="$(grep -oE "(from|import|require)[[:space:]]*\(?[[:space:]]*['\"][^'\"]+['\"]" -- "$file" 2>/dev/null | sed -E "s/.*['\"]([^'\"]+)['\"]\$/\1/")"
  set -e
  while IFS= read -r spec; do
    [ -n "$spec" ] || continue
    set +e
    target="$(resolve "$spec" "$file")"
    rc=$?
    set -e
    case "$rc" in
      0) printf '%s\t%s\n' "$file" "$target" >> "$EDGES"; enqueue "$target" ;;
      1) : ;;  # bare specifier: a published package, out of this gate's reach by design
      2) unknown "$(rel "$file") imports '$spec', which this gate could not resolve to a file — an unread module is not a clean one" ;;
    esac
  done <<< "$specs"
done

# A walk that visited nothing cannot have established anything. $SEEDS was non-empty by the
# check above, so every seed should be in $SEEN; if it is not, the walk did not run and no
# result it produces means anything.
if [ ! -s "$SEEN" ]; then
  unknown "the module walk visited no files despite $(grep -c . "$SEEDS") request-path module(s) being found — the gate did not run, and a gate that did not run does not pass"
  finish
fi

# ---- phase 2: scan ----
while IFS= read -r file; do
  [ -n "$file" ] || continue
  while IFS= read -r term; do
    [ -n "$term" ] || continue
    set +e
    hits="$(grep -nF -e "$term" -- "$file" 2>"$WORK/err")"
    grc=$?
    set -e
    if [ "$grc" -gt 1 ]; then
      # A search that errored is not a search that found nothing.
      unknown "search for '$term' failed (grep exit $grc) in $(rel "$file")"
      continue
    fi
    [ -n "$hits" ] || continue
    reached_by="$(seeds_of "$file")"
    if [ "$(printf '%s\n' "$reached_by" | grep -cFx -- "$file")" -gt 0 ] && [ "$(printf '%s\n' "$reached_by" | grep -c .)" -eq 1 ]; then
      fail "request-path module $(rel "$file") names the service-role term '$term':"
    else
      fail "$(printf '%s\n' "$reached_by" | grep -c .) request-path module(s) reach the service-role term '$term' through $(rel "$file"):"
      printf '%s\n' "$reached_by" | while IFS= read -r sd; do
        [ -n "$sd" ] && echo "    via $(rel "$sd")"
      done
    fi
    printf '%s\n' "$hits" | sed "s|^|    $(rel "$file"):|"
  done < "$TERMS"
done < "$SEEN"

finish
