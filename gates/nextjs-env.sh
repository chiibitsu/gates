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

# Print the first few lines of a captured stderr, indented.
#
# Written head-then-sed, and never `sed ... | head`. `head` closes the pipe after its fifth
# line, `sed` upstream takes SIGPIPE, and under `set -o pipefail` the pipeline returns 141 —
# which `set -e` turned into the gate exiting mid-run, before `finish` and before the two
# checks that had not run yet. The gate went quiet at exactly the moment it had the most to
# say. Same short-circuiting reader that the `grep -q` note below is about.
show_err() { head -5 "$1" | sed 's/^/    /'; }

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
scan() { # "$@" = grep arguments, MATCHER INCLUDED (-E, -F, ...), before the root
  local rc=0
  # Truncated up front, on every path. The error branch below used to return without
  # writing it, so the caller then read the PREVIOUS search's hits and attributed them to
  # this one — the denylist check printing a NEXT_PUBLIC_ line as evidence of a denylisted
  # term. Wrong text under the right heading is still a wrong answer.
  : > "$WORK/hits"
  set +e
  tgrep "${X[@]}" "$@" "$ROOT" > "$WORK/raw" 2> "$WORK/err"
  rc=$?
  set -e
  if [ "$rc" -gt 1 ]; then
    fail "search failed (grep exit $rc) — this gate reports nothing rather than a false pass:"
    show_err "$WORK/err"
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
      case "${rest#"$gate"/}" in bad/*|cases/*) continue ;; esac
    fi
    printf '%s\n' "$line"
  done
}

# Strip a trailing comment and the whitespace around what is left, in the shell. `xargs` was
# doing this, and `xargs` parses quotes: a denylist line holding an apostrophe made it exit
# non-zero inside a command substitution, which under `set -e` killed the gate.
clean_term() {
  local t="${1%%#*}"
  t="${t#"${t%%[![:space:]]*}"}"
  t="${t%"${t##*[![:space:]]}"}"
  printf '%s' "$t"
}

# 1. A server-only key exposed to the browser bundle via the NEXT_PUBLIC_ prefix. Names,
#    deliberately: the mistake this catches IS a naming mistake.
scan -E --exclude=AGENTS.md --exclude-dir=docs --exclude-dir=product \
     -e 'NEXT_PUBLIC_[A-Z0-9_]*(SERVICE|SECRET|PRIVATE)'
if [ -s "$WORK/hits" ]; then
  fail "NEXT_PUBLIC_ variable named like a server secret:"; cat "$WORK/hits"
fi

# 2. A committed .env file. .env.example is the one that is meant to be tracked.
if in_git_repo "$ROOT"; then
  # No `|| true` on any of this. It used to wrap the whole pipeline, so a git that FAILED
  # outright — a corrupt index exits 128 — produced an empty result file, which is
  # indistinguishable from "no tracked .env", and the gate printed ok. Ask git, then look at
  # what git said before believing the answer.
  set +e
  git -C "$ROOT" ls-files > "$WORK/tracked" 2> "$WORK/err"
  gitrc=$?
  set -e
  if [ "$gitrc" -ne 0 ]; then
    fail "git ls-files failed (exit $gitrc) — cannot tell whether a .env is tracked:"
    show_err "$WORK/err"
  else
    set +e
    grep -E '(^|/)\.env(\..*)?$' "$WORK/tracked" > "$WORK/envcand" 2> "$WORK/err"
    grc=$?
    set -e
    if [ "$grc" -gt 1 ]; then
      fail "filtering the tracked file list failed (grep exit $grc):"; show_err "$WORK/err"
    else
      set +e
      grep -vE '\.example$' "$WORK/envcand" > "$WORK/env" 2> "$WORK/err"
      grc=$?
      set -e
      if [ "$grc" -gt 1 ]; then
        fail "filtering the tracked file list failed (grep exit $grc):"; show_err "$WORK/err"
      elif [ -s "$WORK/env" ]; then
        fail ".env file is tracked:"; cat "$WORK/env"
      fi
    fi
  fi
fi

# 3. Optional denylist: names that must never appear (client names, repo slugs, owner
#    handles). One per line, case-insensitive. Absent file = skipped.
DL="$ROOT/scripts/gates/denylist.txt"
if [ -f "$DL" ]; then
  # `|| [ -n "$term" ]` so a last line with no trailing newline is still read.
  while IFS= read -r term || [ -n "$term" ]; do
    term="$(clean_term "$term")"
    if [ -z "$term" ]; then continue; fi
    # -F, and the matcher is passed here rather than baked into tgrep. A denylisted term is
    # a literal — a client name with a `.` or a `+` in it is not a regex — and the previous
    # version passed -F on top of a hardcoded -E, so grep rejected every denylist search
    # with "conflicting matchers specified" and the error branch failed the gate. Any repo
    # with a non-empty denylist could not go green, which is the other way a gate stops
    # being read.
    scan -iF -e "$term"
    if [ -s "$WORK/hits" ]; then
      fail "denylisted term '$term' present:"; cat "$WORK/hits"
    fi
  done < "$DL"
fi
finish
