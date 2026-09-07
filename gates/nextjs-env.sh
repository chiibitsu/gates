#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# The Next.js-specific footguns, and ONLY those. Three checks: a NEXT_PUBLIC_ variable
# named like a server secret, a tracked .env that is not .env.example, and an optional
# per-repo denylist of names and slugs.
#
# This gate used to also match credential SHAPES. That regex is deleted. Credential values
# are check_secrets.py's job and gitleaks'. What is left is the one thing neither does.
source "$(dirname "$0")/lib.sh"

X=(--exclude=nextjs-env.sh --exclude=denylist.txt --exclude=package-lock.json --exclude='*.lock')

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Run one search and leave its surviving lines in $WORK/hits. NOTHING here decides from a
# pipeline's exit status, and nothing pipes into `grep -q`.
#
# `grep -q` exits the moment it sees its first match. Upstream then takes SIGPIPE, and under
# `set -o pipefail` the whole condition reads FALSE — so a file with 20,000 violations
# reported `ok` while a file with one was caught. A gate that gets quieter the worse the
# tree is, is worse than no gate.
#
# grep's exit codes are also separated here: 0 is matches, 1 is none, anything else is an
# ERROR. Collapsing 2 into "no matches" is how the previous version of this file went green
# when its own filter crashed.
scan() { # "$@" = grep arguments after the flags in X
  local rc=0
  set +e
  tgrep "${X[@]}" "$@" "$ROOT" > "$WORK/raw" 2> "$WORK/err"
  rc=$?
  set -e
  if [ "$rc" -gt 1 ]; then
    fail "search failed (grep exit $rc) — this gate reports nothing rather than a false pass:"
    sed 's/^/    /' "$WORK/err" | head -5
    return 0
  fi
  not_fixture < "$WORK/raw" > "$WORK/hits"
}

# The toolkit's OWN planted failures, excluded by shell prefix match — never by building a
# regex out of $ROOT, which aborts grep on a checkout path containing `(`.
not_fixture() {
  local prefix="$ROOT/fixtures/" line rest gate
  while IFS= read -r line; do
    rest=""
    case "$line" in "$prefix"*) rest="${line#"$prefix"}" ;; esac
    if [ -n "$rest" ]; then
      gate="${rest%%/*}"
      case "${rest#"$gate"/}" in bad/*) continue ;; esac
    fi
    printf '%s\n' "$line"
  done
}

# 1. A server-only key exposed to the browser bundle via the NEXT_PUBLIC_ prefix. Names,
#    deliberately: the mistake this catches IS a naming mistake.
scan --exclude=AGENTS.md --exclude-dir=docs --exclude-dir=product \
     'NEXT_PUBLIC_[A-Z0-9_]*(SERVICE|SECRET|PRIVATE)'
if [ -s "$WORK/hits" ]; then
  fail "NEXT_PUBLIC_ variable named like a server secret:"; cat "$WORK/hits"
fi

# 2. A committed .env file. .env.example is the one that is meant to be tracked.
if in_git_repo "$ROOT"; then
  git -C "$ROOT" ls-files | grep -E '(^|/)\.env(\..*)?$' | grep -vE '\.example$' > "$WORK/env" || true
  if [ -s "$WORK/env" ]; then
    fail ".env file is tracked:"; cat "$WORK/env"
  fi
fi

# 3. Optional denylist: names that must never appear (client names, repo slugs, owner
#    handles). One per line, case-insensitive. Absent file = skipped.
DL="$ROOT/scripts/gates/denylist.txt"
if [ -f "$DL" ]; then
  while IFS= read -r term; do
    term="${term%%#*}"; term="$(echo "$term" | xargs)"; [ -z "$term" ] && continue
    scan -i -F -- "$term"
    if [ -s "$WORK/hits" ]; then
      fail "denylisted term '$term' present:"; cat "$WORK/hits"
    fi
  done < "$DL"
fi
finish
