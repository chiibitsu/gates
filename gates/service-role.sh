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
# Path alias resolution, read from tsconfig.json.
#
# EVERY declared alias, not just `@/*`. The version that only understood `@/*` sent every
# other alias down the "bare specifier" branch, where it was skipped as a published package —
# so `import { key } from "~/lib/secret"` in a repo that maps `"~/*": ["./src/*"]` was a local
# module the gate declared out of scope and never read. A false green, in the branch whose
# whole job is deciding what counts as reachable.
#
# The parse is also GUARDED at every step. It used to be one unguarded
# `x="$(grep ... | sed ... | head -1)"`, and under `set -e` with `pipefail` a grep that
# matched nothing returned 1 through the pipeline and ended the gate on the spot — exit 1,
# no output, before a single check ran. Any repo whose tsconfig declared paths without an
# `@/*` key got a red with no reason in it, which reads as a broken gate rather than as the
# gate saying anything. Every command substitution here ends in `|| true` for that reason.
# ---------------------------------------------------------------------------
TSCONFIG="$ROOT/tsconfig.json"
ALIASES="$WORK/aliases"
: > "$ALIASES"
BASE_DIR="$ROOT"
if [ -f "$TSCONFIG" ]; then
  base_url="$(sed -nE 's/.*"baseUrl"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$TSCONFIG" 2>/dev/null | head -1 || true)"
  base_url="${base_url#./}"; base_url="${base_url%/}"
  if [ -n "$base_url" ] && [ "$base_url" != "." ]; then BASE_DIR="$ROOT/$base_url"; fi

  # The `paths` object, isolated exactly rather than read line by line.
  #
  # Brace depth from the `"paths"` key captures the block whatever its layout; joining it to
  # one line and cutting from `"paths": {` to the next `}` then leaves the alias body alone.
  # That last cut is exact, not a guess: a tsconfig `paths` value is an array of strings, so
  # the first `}` after the opening one is always its close.
  #
  # A line-anchored sed was here first, and it read a normal multi-line tsconfig correctly
  # while parsing nothing at all out of a single-line one. The guard below turned that into
  # an UNKNOWN rather than a false pass, which is the guard doing its job — but a legal
  # tsconfig that makes the gate permanently red is still the gate being wrong about a tree
  # it could have read.
  awk '
    !inp && /"paths"[[:space:]]*:/ { inp = 1 }
    inp {
      o = gsub(/\{/, "{"); c = gsub(/\}/, "}")
      depth += o - c
      print
      if (started && depth <= 0) exit
      if (o > 0) started = 1
    }
  ' "$TSCONFIG" > "$WORK/pathsblock" 2>/dev/null || true

  tr -d '\n' < "$WORK/pathsblock" \
    | sed -E 's/.*"paths"[[:space:]]*:[[:space:]]*\{//; s/\}.*//' > "$WORK/pathsbody" 2>/dev/null || true

  # "<key>": [ "<first target>" — extracted by shape, from anywhere in the alias body, so the
  # same code reads a pretty-printed tsconfig and a minified one.
  grep -oE '"[^"]+"[[:space:]]*:[[:space:]]*\[[[:space:]]*"[^"]+"' "$WORK/pathsbody" 2>/dev/null \
    | sed -E 's/"([^"]+)"[[:space:]]*:[[:space:]]*\[[[:space:]]*"([^"]+)"/\1\t\2/' > "$ALIASES" 2>/dev/null || true

  # `extends` is not followed. A base config holding the aliases leaves $ALIASES empty, and an
  # `@/lib/secret` then matches no alias, is called a published package, and is skipped — a
  # false green. Following the chain is a real change; saying so is not.
  if grep -q '"extends"' "$TSCONFIG" 2>/dev/null && [ ! -s "$ALIASES" ]; then
    unknown "tsconfig.json uses \"extends\" and no alias was parsed from this file — the base config is not followed, so an aliased import here would be mistaken for a published package"
  fi
  if [ -s "$WORK/pathsbody" ] && [ ! -s "$ALIASES" ]; then
    unknown "tsconfig.json declares compilerOptions.paths but this gate parsed no alias out of it — every aliased import below is therefore unresolved, and none of them will be called clean"
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
#
# The three outcomes are the whole point. 1 is a claim — "this is a published package, not
# this repo's source" — and it is only safe to make about a specifier that matches NO
# declared alias. Anything that looks local and does not resolve is 2, never 1.
resolve() { # $1 = specifier, $2 = importing file
  local spec="$1" bases="" matched=0 key target prefix t b ext cand cdir found=""
  case "$spec" in
    ./*|../*) bases="$(dirname -- "$2")/$spec"; matched=1 ;;
    /*)       bases="$ROOT$spec"; matched=1 ;;
    *)
      while IFS="$(printf '\t')" read -r key target; do
        [ -n "$key" ] || continue
        case "$key" in
          *\*)
            prefix="${key%\*}"
            case "$spec" in
              "$prefix"*)
                matched=1
                t="${target%\*}"; t="${t#./}"
                bases="$bases
$BASE_DIR/$t${spec#"$prefix"}"
                ;;
            esac
            ;;
          *)
            if [ "$spec" = "$key" ]; then
              matched=1
              t="${target#./}"
              bases="$bases
$BASE_DIR/$t"
            fi
            ;;
        esac
      done < "$ALIASES"
      ;;
  esac
  if [ "$matched" -ne 1 ]; then return 1; fi
  while IFS= read -r b; do
    [ -n "$b" ] || continue
    # .d.ts and friends included: `import type { Database } from "@/types/supabase"` against a
    # src/types/supabase.d.ts resolved to nothing, which this gate calls UNKNOWN — a permanent
    # blocking red on a perfectly ordinary line. The selftest cannot catch a false red (its own
    # note says the fixture model holds bad trees only), so it is fixed here on report.
    for ext in "" .ts .tsx .d.ts .mts .cts .js .jsx .mjs .cjs /index.ts /index.tsx /index.d.ts /index.js /index.jsx; do
      cand="$b$ext"
      # CANONICALISED, not merely tested for existence. Without this the resolved path keeps
      # whatever `..` the importer's specifier put in it, and TWO SPELLINGS OF ONE FILE ARE
      # TWO NODES. That cost two defects, both shipped in v1.1.0:
      #
      #   - a file imported as `@/lib/x` from one module and `../../lib/x` from another was
      #     counted twice: two findings for one file, each claiming "1 request-path
      #     module(s)". That is the very miscount the note above says the edge-list rewrite
      #     fixed. The rewrite fixed seed-carrying. It did not fix this, so the note claimed
      #     more than the fix delivered — in the comment about that exact defect.
      #   - an ordinary circular import (a.ts <-> b.ts) grew a longer spelling every hop, so
      #     the SEEN set never matched and the walk did not terminate. Measured at 20s with
      #     ZERO output before a timeout killed it. In CI that is a hang, not a red, and a
      #     hang is the one outcome that reports nothing at all.
      #
      # `cd` + `pwd -P` resolves `..` and symlinks both, and only works on a path that
      # exists — which is why it runs after the -f test rather than as a string rewrite.
      if [ -f "$cand" ]; then
        cdir="$(cd -- "$(dirname -- "$cand")" 2>/dev/null && pwd -P)" || continue
        found="$cdir/$(basename -- "$cand")"
        break
      fi
    done
    if [ -n "$found" ]; then break; fi
  done <<< "$bases"
  if [ -n "$found" ]; then printf '%s' "$found"; return 0; fi
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

  # SCANNED WITH NEWLINES COLLAPSED, because a line-at-a-time grep does not see a statement
  # that spans lines — and the statement most likely to span lines is the one this gate must
  # not miss. Shipped in v1.1.0, measured:
  #
  #     const mod = await import(
  #       process.env.MODULE_NAME ?? "@/lib/secret"
  #     );
  #
  # produced `ok [service-role]`, exit 0, over a page that reaches SUPABASE_SERVICE_ROLE_KEY.
  # The guard did not fire because `import(` and the non-literal argument were on different
  # lines, and the extractor did not follow it for the same reason. A FALSE GREEN in the
  # security gate, from a formatting choice Prettier makes on its own.
  #
  # The cost of flattening: a `//` comment now runs into the code after it, so a mention of
  # `import(` inside a comment can raise a spurious UNKNOWN. That is over-inclusive — a false
  # RED, visible and arguable — and this repository takes that trade every time over a false
  # green. It belongs with the other "regex, not a parser" gaps in the README.
  tr '\n' ' ' < "$file" > "$WORK/flat" 2>/dev/null || : > "$WORK/flat"

  # A branch of the graph this gate cannot follow. Reported here, against the module that
  # contains it, rather than assumed harmless.
  if grep -qE '(^|[^A-Za-z0-9_$.])(import|require)[[:space:]]*\([[:space:]]*[^'"'"'")[:space:]]' -- "$WORK/flat" 2>/dev/null; then
    unknown "$(rel "$file") contains a non-literal import() or require() — this gate cannot tell what it pulls in, so it will not call this path clean"
  fi

  set +e
  # BOTH passes, unioned. Flattening alone was a REGRESSION and it went in the direction this
  # change exists to fix: `grep -o` matches non-overlapping, so a string ending in `from "`
  # swallows the real import after it. Measured —
  #
  #     const label = "imported from ";
  #     import { key } from "../lib/secret";
  #
  # gave `ok [service-role]`, exit 0, over a module reaching SUPABASE_SERVICE_ROLE_KEY, on a
  # tree the PREVIOUS version caught. The line pass finds ordinary imports with no window to
  # swallow across; the flat pass finds the multi-line ones. Garbage the flat pass invents out
  # of a swallowed span resolves as a bare specifier and is skipped, so the union only ever
  # adds edges.
  specs="$(
    { grep -oE "(from|import|require)[[:space:]]*\(?[[:space:]]*['\"][^'\"]+['\"]" -- "$file" 2>/dev/null
      grep -oE "(from|import|require)[[:space:]]*\(?[[:space:]]*['\"][^'\"]+['\"]" -- "$WORK/flat" 2>/dev/null
    } | sed -E "s/.*['\"]([^'\"]+)['\"]\$/\1/" | sort -u
  )"
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
