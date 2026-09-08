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
# THE EXTRACTOR IS A TOKENISER, NOT A REGEX — and that is the fourth attempt at this code.
#
# `grep -o` matches NON-OVERLAPPING, so a string ending in the word `from` immediately before
# a quote consumed the rest of the line up to the next quote as one "specifier". Every
# version built on that had to choose which way to be wrong, and each of three consecutive
# review rounds found the choice:
#
#   - report the invented span      -> a blocking UNKNOWN naming an import that does not
#                                      exist, on ordinary source: `Array.from(",")`, a regex
#                                      literal, `{ note: "Imported from " }`. No action a
#                                      fixer can take.
#   - drop the invented span        -> a REAL import swallowed into the span is dropped with
#                                      it. Measured: `const label = "imported from ";
#                                      import { admin } from "../lib/admin";` on one line
#                                      went `ok`, exit 0, over a module reaching the secret.
#
# Both are the same defect, and neither is fixable by choosing a better filter, because the
# filter is downstream of the damage. So the scan tokenises: strings, template literals,
# line and block comments and regex literals are recognised as what they are, and a
# specifier is emitted only from a real `from`/`import`/`require` position. There is no
# invented span left to report or to drop, and the `flat` pass and its `//`-comment cost are
# gone with it.
# ---------------------------------------------------------------------------
SCAN="$WORK/scan.awk"
cat > "$SCAN" <<'SCANAWK'
# Streaming JavaScript scanner. One record per line: "S<specifier>" for a literal import
# specifier, or "N" for a branch this gate cannot read. A string that merely ENDS in the word
# `from` produces nothing at all.
#
# LINE-INCREMENTAL, NOT SLURPED, for the reason recorded in the SQL scanner: `buf = buf $0
# "\n"` is quadratic in mawk and took 12.1s on a 1.1MB generated types file against 0.11s for
# the greps it replaced. State is carried across lines instead.
function isregexpos(c) {
  return (c == "" || c == "(" || c == "," || c == "=" || c == ":" || c == "[" || c == "!" ||
          c == "&" || c == "|" || c == "?" || c == "{" || c == "}" || c == ";" || c == "+" ||
          c == "-" || c == "*" || c == "%" || c == "<" || c == ">" || c == "~" || c == "^" ||
          c == "k")
}
function want(w) { return (w == "from" || w == "import" || w == "require") }
# JSX text is not JavaScript: `<p>Copied from "a" to "b"</p>` puts `from` before a quote and
# nothing short of a JSX parser tells that from an import. A module specifier carries none of
# these characters. Dropping such a candidate is only safe because the extractor no longer
# invents spans — see the note in the gate.
function plausible(v) { return (v != "" && v !~ /[<>{}]/) }
# CLEARING A PENDING import(/require( IS THE REPORT. The first version decided this with a
# lookahead on the rest of the line, which cannot see a `import(` whose argument is on the NEXT
# line — the exact multi-line dynamic import that was a false green two releases ago, silently
# reintroduced. In a token stream the rule is simply: a pending import( closed by anything that
# is not a literal is a branch this gate cannot follow, whatever line that token is on.
function clearpend() {
  if (paren == 1 && (pend == "import" || pend == "require")) print "N"
  pend = ""; paren = 0
}
{
  n = length($0); i = 1
  while (i <= n) {
    c = substr($0, i, 1)
    if (mode == 1) {                                  # inside /* */
      if (c == "*" && substr($0, i + 1, 1) == "/") { mode = 0; i += 2; continue }
      i++; continue
    }
    if (mode == 2) {                                  # inside a template literal
      if (c == "\\") { tv = tv substr($0, i + 1, 1); i += 2; continue }
      if (c == "$" && substr($0, i + 1, 1) == "{") {
        interp = 1; tdepth = 1; i += 2
        while (i <= n && tdepth > 0) {
          c = substr($0, i, 1)
          if (c == "{") tdepth++
          else if (c == "}") tdepth--
          i++
        }
        continue
      }
      if (c == "`") {
        mode = 0; i++
        if (want(pend)) { if (interp) print "N"; else if (plausible(tv)) print "S" tv }
        pend = ""; paren = 0; last = "v"; tv = ""; interp = 0
        continue
      }
      tv = tv c; i++; continue
    }
    if (c == " " || c == "\t" || c == "\r") { i++; continue }
    if (c == "/" && substr($0, i + 1, 1) == "/") break          # rest of THIS line
    if (c == "/" && substr($0, i + 1, 1) == "*") { mode = 1; i += 2; continue }
    if (c == "/" && isregexpos(last)) {
      i++; incls = 0
      while (i <= n) {
        c = substr($0, i, 1)
        if (c == "\\") { i += 2; continue }
        if (c == "[") incls = 1
        else if (c == "]") incls = 0
        else if (c == "/" && !incls) { i++; break }
        i++
      }
      last = "v"; clearpend(); continue
    }
    if (c == "\"" || c == "'") {
      # Line-bounded on purpose. An apostrophe in JSX text would otherwise open a string that
      # runs to the end of the file; ending it at the line boundary costs nothing, because a
      # real specifier never spans lines.
      q = c; i++; v = ""
      while (i <= n) {
        c = substr($0, i, 1)
        if (c == "\\") { v = v substr($0, i + 1, 1); i += 2; continue }
        if (c == q) { i++; break }
        v = v c; i++
      }
      if (want(pend) && plausible(v)) print "S" v
      pend = ""; paren = 0; last = "v"; continue
    }
    if (c == "`") { mode = 2; tv = ""; interp = 0; i++; continue }
    if (c ~ /[A-Za-z_$]/) {
      v = ""
      while (i <= n) { c = substr($0, i, 1); if (c !~ /[A-Za-z0-9_$]/) break; v = v c; i++ }
      # `.from` is a method name, not a keyword: `Array.from(",")` put the string after it in
      # the specifier slot.
      if (want(v) && last != ".") { clearpend(); pend = v; paren = 0 } else clearpend()
      last = (v == "return" || v == "typeof" || v == "case" || v == "in" || v == "of" ||
              v == "new" || v == "delete" || v == "void" || v == "do" || v == "else" ||
              v == "yield" || v == "await") ? "k" : "w"
      continue
    }
    if (c == "(") {
      # `from` is never followed by `(` in an import — `import x from "y"` has no parens.
      if (pend == "from") { clearpend(); last = "("; i++; continue }
      if (pend != "" && paren == 0) paren = 1
      else clearpend()
      last = "("; i++; continue
    }
    clearpend(); last = c; i++
  }
  if (mode == 2) tv = tv "\n"
}
END {
  # A SCANNER THAT LOST SYNC MUST NOT REPORT A CLEAN FILE. A template literal or block comment
  # still open at end of file means everything after it was read as something it is not.
  # Measured before this guard: one stray backtick in JSX text (`<p>Press the ` key</p>`)
  # consumed the rest of the file and a `require("@/lib/admin")` below it reported `ok`,
  # exit 0, over a module reaching the secret.
  if (mode == 2 || mode == 1) print "N"
}
SCANAWK

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
TSCONFIG_RAW="$ROOT/tsconfig.json"
# tsconfig.json permits comments, and every read below has to see past them. `grep -q
# '"baseUrl"'` armed the baseUrl fallback on a COMMENTED-OUT key: a config carrying
# `// "baseUrl": ".",` and no live one made `import React from "react"` resolve to a repo
# directory named react/ and reported a violation against the package. A commented-out line
# is not configuration.
TSCONFIG="$WORK/tsconfig.json"
if [ -f "$TSCONFIG_RAW" ]; then
  awk '
    { buf = buf $0 "\n" }
    END {
      n = length(buf); i = 1
      while (i <= n) {
        c = substr(buf, i, 1)
        if (c == "\"") {
          printf "%s", c; i++
          while (i <= n) {
            c = substr(buf, i, 1)
            if (c == "\\") { printf "%s", substr(buf, i, 2); i += 2; continue }
            printf "%s", c; i++
            if (c == "\"") break
          }
          continue
        }
        if (c == "/" && substr(buf, i + 1, 1) == "/") { while (i <= n && substr(buf, i, 1) != "\n") i++; continue }
        if (c == "/" && substr(buf, i + 1, 1) == "*") {
          i += 2
          while (i <= n && !(substr(buf, i, 1) == "*" && substr(buf, i + 1, 1) == "/")) i++
          i += 2; continue
        }
        printf "%s", c; i++
      }
    }
  ' "$TSCONFIG_RAW" > "$TSCONFIG" 2>/dev/null || cp -- "$TSCONFIG_RAW" "$TSCONFIG" 2>/dev/null || :
fi
# Named in the UNKNOWN below only when it is actually there. The message said "no alias
# declared in tsconfig.json" on a tree with no tsconfig.json at all, which sends a reader
# to open a file that does not exist.
if [ -f "$TSCONFIG" ]; then TSCONFIG_NOTE=" in tsconfig.json"; else TSCONFIG_NOTE=" (no tsconfig.json in this tree)"; fi
ALIASES="$WORK/aliases"
: > "$ALIASES"
BASE_DIR="$ROOT"
BASEURL_SET=0
if [ -f "$TSCONFIG" ]; then
  base_url="$(sed -nE 's/.*"baseUrl"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/p' "$TSCONFIG" 2>/dev/null | head -1 || true)"
  base_url="${base_url#./}"; base_url="${base_url%/}"
  if [ -n "$base_url" ] && [ "$base_url" != "." ]; then BASE_DIR="$ROOT/$base_url"; fi
  # ARMED ON THE KEY'S PRESENCE, NOT ON ITS VALUE. The first version of the baseUrl fallback
  # armed on `[ -n "$base_url" ] && [ "$base_url" != "." ]` — the same condition that decides
  # whether BASE_DIR moves — and `"baseUrl": "."` is the spelling in Next.js's own Absolute
  # Imports documentation and the one create-next-app ships. So the fallback did not arm on
  # the commonest spelling, and the false green it was written to close stayed open there:
  #
  #     import { admin } from "lib/supabase-admin";     ->  ok    exit 0
  #     import { admin } from "../lib/supabase-admin";  ->  FAIL  exit 1
  #
  # Identical to the reproduction in the commit that claimed to fix it, on a different value
  # of the same key — and the shipped fixture used "src", so the selftest was green over the
  # half that worked. BASE_DIR is already $ROOT when the value is "." or "./", so nothing else
  # needs to change: the key being there is the whole condition.
  if grep -q '"baseUrl"' "$TSCONFIG" 2>/dev/null; then BASEURL_SET=1; fi

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
# "It matched no declared alias" and "it is a published package" are not the same sentence,
# and resolve() used to print the second while only having checked the first. `@/lib/secret`
# in a tree whose tsconfig declares some OTHER alias matches nothing here — and it cannot be
# a package either: npm has no empty scope. The gate called it a dependency and skipped it,
# so a request-path module importing it read as clean. Measured on a tree reaching
# SUPABASE_SERVICE_ROLE_KEY: `ok [service-role]`, exit 0. A FALSE GREEN, from a classifier
# whose claim was wider than its test — this repository's recurring defect, again, in the
# branch that decides what is out of scope.
#
# So the claim is now tested. A specifier that is neither a declared alias nor a well-formed
# package name is UNKNOWN: this gate does not know what it is, and will not call it clean.
is_package_specifier() {
  local sc nm
  case "$1" in
    @*/*)
      sc="${1#@}"; sc="${sc%%/*}"
      case "$sc" in ""|[!A-Za-z0-9]*) return 1 ;; esac
      nm="${1#@*/}"
      case "$nm" in ""|[!A-Za-z0-9]*) return 1 ;; esac
      return 0 ;;
    @*)           return 1 ;;   # a scope with no package under it
    [A-Za-z0-9]*) return 0 ;;   # react, node:fs, @-less subpaths
    *)            return 1 ;;   # ~/..., #internal/..., ./ and ../ never reach here
  esac
}

resolve() { # $1 = specifier, $2 = importing file
  local spec="$1" bases="" matched=0 fallback=0 key target prefix t b bb cands ext cand cdir found=""
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
      # `baseUrl` WITHOUT A MATCHING `paths` ENTRY IS STILL A LOCAL IMPORT. This is Next.js's
      # documented "Absolute Imports" shape: `baseUrl: "src"` alone makes `lib/supabase-admin`
      # mean `src/lib/supabase-admin.ts`, with no alias declared anywhere. This gate PARSED
      # that baseUrl — it is `BASE_DIR` for every alias target above — and then skipped the
      # bare specifier as a published package. Measured, same file and same secret, twice:
      #
      #     import { admin } from "lib/supabase-admin";     ->  ok [service-role]   exit 0
      #     import { admin } from "../lib/supabase-admin";  ->  FAIL x2             exit 1
      #
      # A FALSE GREEN selected by nothing but the spelling of the import. TypeScript resolves
      # baseUrl-relative first and falls back to node_modules, so this does the same: probe
      # under BASE_DIR, and if nothing is there the specifier really is a package (rc 1, not a
      # red). Only when an explicit baseUrl was declared — without one there is no such shape
      # to resolve, and every bare specifier is a dependency exactly as before.
      # NOT GATED ON THE NAME LOOKING LIKE A PACKAGE. It was, and that made the probe skip
      # exactly the specifiers most likely to be baseUrl-relative: `_components/Button` — a
      # leading underscore is not a valid npm name, and underscore-prefixed private folders
      # are an ordinary Next.js convention — resolved to a real file under BASE_DIR and was
      # reported UNKNOWN anyway. A probe that refuses to look at a path because the path is
      # not a package name is answering a different question from the one it was asked.
      #
      # `#`-prefixed specifiers are the exception and stay out: TypeScript and Node resolve
      # those through package.json `imports`, not by appending them to baseUrl, so probing
      # BASE_DIR for one would be a guess dressed as a resolution.
      case "$spec" in
        '#'*) : ;;
        *)
          if [ "$matched" -ne 1 ] && [ "$BASEURL_SET" = 1 ]; then
            matched=1; fallback=1
            bases="$BASE_DIR/$spec"
          fi
          ;;
      esac
      ;;
  esac
  if [ "$matched" -ne 1 ]; then
    if is_package_specifier "$spec"; then return 1; fi
    return 3
  fi
  while IFS= read -r b; do
    [ -n "$b" ] || continue
    # THE SPECIFIER'S EXTENSION IS THE EMITTED ONE, NOT THE SOURCE'S. Under
    # `moduleResolution: nodenext` (and with `verbatimModuleSyntax`) TypeScript requires the
    # import to name the file JavaScript will load — `./mod.mjs` — while the file on disk is
    # `mod.mts`. The probe below only ever appended extensions, so it tested `mod.mjs.mts`
    # and nothing else, resolved to no file, and reported UNKNOWN. A FALSE RED on the modern
    # default resolution mode: the gate blocking a tree it simply could not spell.
    #
    # The mapping is TypeScript's own and is one-to-one: .mjs<-.mts, .cjs<-.cts, .js<-.ts|.tsx,
    # .jsx<-.tsx. The emitted spelling is kept in the list as well, because a plain JS project
    # has the .js on disk and both must resolve.
    # THE SOURCE COMES FIRST, AND THE DECLARATION FILES ARE IN THE LIST. Verified with tsc:
    # with both `admin.mts` and a stale emitted `admin.mjs` beside it, `import "./admin.mjs"`
    # resolves to the .mts — so probing the emitted spelling first reads the stale artefact,
    # and a secret added to the source reads as `ok`, exit 0. And `import type { X } from
    # "./types.js"` against a `types.d.ts` type-checks clean under nodenext, which this list
    # has to know or it re-opens the very `.d.ts` false red the extension list was widened to
    # close one release ago.
    #
    # AND THE DECLARATION COMES LAST, which the first version of this list got backwards. With
    # a `.js` module and a hand-written `.d.ts` beside it, probing the declaration first
    # resolved to a file that BY CONSTRUCTION cannot hold a secret, and the module Node
    # actually loads was never read. Measured: `lib/admin.js` reaching
    # SUPABASE_SERVICE_ROLE_KEY with a `lib/admin.d.ts` next to it gave `ok`, exit 0 — and
    # deleting the .d.ts turned the same tree red, which is the sidecar doing the hiding.
    # `tsc --traceResolution` does prefer the declaration, but that is TypeScript answering
    # "where are the types"; this gate asks "what code runs in the request path", and a
    # declaration file is never that answer. Last still closes the false red above, because
    # that case has no implementation file to find.
    cands="$b"
    case "$b" in
      *.mjs) cands="${b%.mjs}.mts
$b
${b%.mjs}.d.mts" ;;
      *.cjs) cands="${b%.cjs}.cts
$b
${b%.cjs}.d.cts" ;;
      *.jsx) cands="${b%.jsx}.tsx
$b" ;;
      *.js)  cands="${b%.js}.ts
${b%.js}.tsx
$b
${b%.js}.d.ts" ;;
    esac
    while IFS= read -r bb; do
    [ -n "$bb" ] || continue
    # .d.ts and friends included: `import type { Database } from "@/types/supabase"` against a
    # src/types/supabase.d.ts resolved to nothing, which this gate calls UNKNOWN — a permanent
    # blocking red on a perfectly ordinary line. The selftest cannot catch a false red (its own
    # note says the fixture model holds bad trees only), so it is fixed here on report.
    # Implementations before declarations here too, and for the same reason as the `cands`
    # note above: `.d.ts` sat ahead of `.js`, so an extensionless `"../lib/admin"` against a
    # `lib/admin.js` with a `lib/admin.d.ts` beside it resolved to the declaration. That one
    # is older than this release; the fix for the ordering above is the fix for this.
    for ext in "" .ts .tsx .mts .cts .js .jsx .mjs .cjs .d.ts .d.mts .d.cts /index.ts /index.tsx /index.js /index.jsx /index.d.ts; do
      cand="$bb$ext"
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
    done <<< "$cands"
    if [ -n "$found" ]; then break; fi
  done <<< "$bases"
  if [ -n "$found" ]; then printf '%s' "$found"; return 0; fi
  # A baseUrl probe that found nothing is TypeScript's own fallthrough to node_modules — but
  # only for a name that could BE a package. Reporting UNKNOWN for every miss would turn
  # `import React from "react"` red in any repo declaring a baseUrl; calling every miss a
  # package would silently skip `_components/Button` when that file is simply absent. So the
  # claim is tested here, exactly as it is for a specifier that never reached the probe.
  if [ "$fallback" = 1 ]; then
    if is_package_specifier "$spec"; then return 1; fi
    return 3
  fi
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

  # One tokenised pass. `N` is a branch this gate cannot follow — an import() or require()
  # whose argument is not a literal — reported against the module that contains it rather
  # than assumed harmless. `S<specifier>` is a literal specifier from a real import position.
  set +e
  recs="$(awk -f "$SCAN" -- "$file" 2>/dev/null)"
  set -e
  nonliteral=0
  : > "$WORK/specs"
  while IFS= read -r rec; do
    case "$rec" in
      "") continue ;;
      N)  nonliteral=1 ;;
      S*) printf '%s\n' "${rec#S}" >> "$WORK/specs" ;;
    esac
  done <<< "$recs"
  if [ "$nonliteral" = 1 ]; then
    unknown "$(rel "$file") contains a non-literal import() or require() — this gate cannot tell what it pulls in, so it will not call this path clean"
  fi
  set +e
  specs="$(sort -u "$WORK/specs" 2>/dev/null)"
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
      3) unknown "$(rel "$file") imports '$spec', which matches no path alias this gate could read$TSCONFIG_NOTE and is not a well-formed package name — this gate cannot say what it is, and will not call it a dependency to skip it" ;;
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
