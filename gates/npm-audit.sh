#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# No production dependency in any package-lock.json carries a known high or critical
# advisory. `next` 16.3.7 shipped through a green pipeline carrying six of them; nothing
# here read an advisory database, so nothing said so.
#
# THIS GATE IS NOT HERMETIC and says so. It asks the npm registry's advisory endpoint, so
# the same tree can go red tomorrow when a new advisory is published — that is the point of
# it — and it cannot run offline. When it cannot get an answer it reports UNKNOWN, which is
# red, never ok: a registry that did not answer is not a tree with no advisories.
#
# What it can and cannot read, stated rather than inferred:
#   - package-lock.json, at any depth, outside node_modules. `--omit=dev`: production
#     dependencies only, because a dev-only advisory does not ship.
#   - yarn.lock, pnpm-lock.yaml and npm-shrinkwrap.json are NOT read. A tree holding one is
#     UNKNOWN, not clean: silence about a lockfile the gate cannot parse is a pass it has not
#     earned.
source "$(dirname "$0")/lib.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Every lockfile-shaped file, outside dependency and VCS directories. A SYMLINK counts: npm
# follows one when it installs, and `-type f` alone skipped a `package-lock.json` tracked as a
# link to a real lockfile, leaving nothing audited and printing ok over a tree whose lock npm
# itself reports a high advisory in. The listing goes to a
# file and find's own status is checked BEFORE it is read: `done < <(find ...)` discards that
# status, and zero lines out of a failed search is not the same fact as zero lockfiles.
set +e
find "$ROOT" \( -name node_modules -o -name .git \) -prune -o \
  \( -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml \) \
  \( -type f -o -type l \) -print > "$WORK/locks" 2> "$WORK/find.err"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  fail "search failed (find exit $rc) — a lockfile this gate could not list is not an audited one:"
  head -5 "$WORK/find.err" | sed 's/^/    /'
fi

# The toolkit's OWN planted failures, excluded by shell prefix match — never by building a
# regex out of $ROOT. Same arrangement as nextjs-env, and for the same reason: published
# releases filter on the `fixtures/<gate>/bad/` prefix.
is_fixture() { # $1 = absolute path
  local prefix="$ROOT/fixtures/" rest gate
  case "$1" in "$prefix"*) rest="${1#"$prefix"}" ;; *) return 1 ;; esac
  gate="${rest%%/*}"
  case "${rest#"$gate"/}" in bad/*) return 0 ;; esac
  return 1
}

audited=0
HAVE_NPM=1; command -v npm >/dev/null 2>&1 && command -v node >/dev/null 2>&1 || HAVE_NPM=0
# `timeout` is coreutils and absent on a stock macOS. Without it the audit runs unbounded,
# which is a hang rather than a wrong answer; CI is Linux and has it.
TIMEOUT=()
command -v timeout >/dev/null 2>&1 && TIMEOUT=(timeout 120)

while IFS= read -r lock; do
  [ -n "$lock" ] || continue
  is_fixture "$lock" && continue
  rel="${lock#"$ROOT"/}"
  if [ -L "$lock" ] && [ ! -e "$lock" ]; then
    unknown "$rel: symlink whose target does not exist — there is no lockfile behind it to audit"
    continue
  fi
  case "$(basename -- "$lock")" in
    yarn.lock|pnpm-lock.yaml|npm-shrinkwrap.json)
      unknown "$rel: lockfile format this gate does not read — its dependencies were not audited"
      continue
      ;;
  esac
  if [ "$HAVE_NPM" = 0 ]; then
    unknown "$rel: npm or node is not installed, so nothing could be audited"
    continue
  fi
  audited=$((audited+1))
  dir="$(dirname -- "$lock")"
  set +e
  # `--workspaces=false --prefix .`: without them, a lockfile inside an npm workspace member is
  # never the one audited. npm sets the prefix to the WORKSPACE ROOT whenever the current
  # directory is inside a workspace, so `cd` into the member audits the root's lock again and
  # reports on a file other than the one named in the message — ok over a high advisory,
  # measured: the root lock clean, packages/web's lock holding lodash@4.17.20.
  ( cd -- "$dir" && "${TIMEOUT[@]}" npm audit --package-lock-only --omit=dev --json --fetch-retries=1 \
      --workspaces=false --prefix . > "$WORK/out.json" 2> "$WORK/out.err" )
  rc=$?
  set -e
  if [ "$rc" -eq 124 ]; then
    unknown "$rel: npm audit timed out after 120s — nothing was audited"
    continue
  fi
  # Decided from the JSON, never from npm's exit status: npm exits 1 both for "found
  # advisories" and for "could not ask", which is the exact confusion this gate exists to
  # keep apart. A report counts only if it parses, carries no `error`, and holds a
  # vulnerability tally. Anything else is UNKNOWN.
  verdict="$(node -e '
    const fs = require("fs");
    let j;
    try { j = JSON.parse(fs.readFileSync(process.argv[1], "utf8")); }
    catch (e) { console.log("UNKNOWN\tnpm audit printed no parseable JSON"); process.exit(0); }
    if (j.error || !j.metadata || !j.metadata.vulnerabilities || typeof j.vulnerabilities !== "object") {
      const why = (j.error && (j.error.code || j.error.summary)) || j.message || "no vulnerability report in the output";
      console.log("UNKNOWN\t" + String(why).replace(/\s+/g, " ").slice(0, 200));
      process.exit(0);
    }
    console.log("OK");
    for (const [name, v] of Object.entries(j.vulnerabilities)) {
      if (v.severity !== "high" && v.severity !== "critical") continue;
      const title = (v.via || []).filter((x) => typeof x === "object").map((x) => x.title).filter(Boolean)[0] || "";
      console.log("VULN\t" + name + "\t" + v.severity + "\t" + title);
    }
  ' "$WORK/out.json" 2>"$WORK/node.err")" || verdict=""
  first="${verdict%%$'\n'*}"
  case "$first" in
    OK) ;;
    UNKNOWN*) unknown "$rel: audit could not be completed (${first#UNKNOWN$'\t'})"; continue ;;
    *) unknown "$rel: could not read npm audit's answer"; continue ;;
  esac
  while IFS=$'\t' read -r tag name sev title; do
    [ "$tag" = VULN ] || continue
    fail "$rel: $name ($sev) $title"
  done <<< "$verdict"
done < "$WORK/locks"

if [ "$audited" -eq 0 ] && [ "$UNKNOWNS" -eq 0 ] && [ "$FAILS" -eq 0 ]; then
  echo "ok [$GATE] no package-lock.json to audit"; exit 0
fi
finish
