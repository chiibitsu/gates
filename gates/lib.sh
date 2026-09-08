#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# Shared helpers for the gate toolkit. Every gate:
#   - takes the tree to check as arg 1, or in $GATE_ROOT. There is NO default. This
#     toolkit is checked out beside the repo it inspects, not inside it, so the old
#     "two directories up from this script" fallback would have pointed every gate at
#     the toolkit's own tree and passed while checking nothing — the exact silent
#     false-success this repo exists to refuse. Missing root is a hard exit 2, never 0.
#   - prints one line per violation and exits 1 on any, 0 on none;
#   - has a fixture under fixtures/<gate>/bad that MUST make it exit 1.
#     selftest.sh enforces that. A gate that cannot fail is not a gate.
set -euo pipefail
GATE="$(basename "${BASH_SOURCE[1]}" .sh)"
ROOT="${1:-${GATE_ROOT:-}}"
if [ -z "$ROOT" ]; then
  echo "FAIL [$GATE] no root given: pass the tree to check as argument 1 or set GATE_ROOT" >&2
  exit 2
fi
if [ ! -d "$ROOT" ]; then
  echo "FAIL [$GATE] root is not a directory: $ROOT" >&2
  exit 2
fi
# Absolute and symlink-resolved, so the root-relative exclusions in the gates below
# compare against the same spelling grep and find will print.
# `cd --`, not `cd`. A root spelled `-root` is a legal relative directory name, and every
# gate downstream hands $ROOT to grep or find as a trailing operand — where a leading dash
# is read as an option, not a path. Making ROOT absolute here is what keeps those safe, so
# this line has to survive a root that starts with one.
ROOT="$(cd -- "$ROOT" && pwd -P)"
# `.git` is a DIRECTORY only in a classic checkout. In a linked worktree or a submodule it
# is a FILE, and a `[ -d "$ROOT/.git" ]` test therefore skipped every git-backed check and
# reported ok over a tree it never asked git about. Ask git, don't guess from the layout.
in_git_repo() { git -C "$1" rev-parse --is-inside-work-tree >/dev/null 2>&1; }
# One line of a per-repo config list — a denylist term, a required-files path — with its
# trailing comment removed, surrounding whitespace trimmed, and a matched pair of wrapping
# quotes unwrapped.
#
# This was `echo "$line" | xargs` in two gates. xargs PARSES quotes: one apostrophe in a
# manifest and it exits non-zero, which inside a command substitution under `set -e` ends
# the gate on the spot — every entry after that line unchecked and `finish` never reached.
# It is also the only reason quoted entries ever worked, so the unwrapping is explicit here
# rather than a side effect of a tool being used for the wrong job. Shared, so the two gates
# cannot drift apart on what a config line means.
clean_list_line() {
  local t="$1" q rest
  t="${t#"${t%%[![:space:]]*}"}"
  # A QUOTED entry is read to its closing quote and taken verbatim. Comment stripping used to
  # run first, so a term like 'C# Consulting' was cut back to 'C and matched nothing — and
  # quoting is exactly what someone does BECAUSE the value holds a space or a hash, so doing
  # it must not disarm the check. An unbalanced quote falls through to the ordinary path
  # rather than swallowing the line.
  case "$t" in
    \'*|\"*)
      q="${t:0:1}"; rest="${t:1}"
      case "$rest" in
        *"$q"*) printf '%s' "${rest%%"$q"*}"; return 0 ;;
      esac
      ;;
  esac
  t="${t%%#*}"
  t="${t%"${t##*[![:space:]]}"}"
  printf '%s' "$t"
}
FAILS=0
fail() { echo "FAIL [$GATE] $*"; FAILS=$((FAILS+1)); }
UNKNOWNS=0
# "I could not check this" — the answer a gate must be able to give, and the one it must
# never give quietly.
#
# There is NO third colour. A GitHub Actions check run is green or it is not; `exit 2` does
# not buy a neutral state, and a `::warning` annotation leaves the run green. So UNKNOWN is
# RED, the same red as a violation, and the distinction between "I looked and found a
# problem" and "I could not look" lives entirely in this line and in the annotation — never
# in the colour, and never in the exit code.
#
# Exit 1, not 2, on purpose. selftest.sh's failure leg reads a non-1 exit as the gate
# ERRORING rather than reporting, and lib.sh already spends 2 on "no root given". Reusing 2
# here would have made an honest UNKNOWN indistinguishable from a broken invocation, in the
# one file whose job is telling those apart.
unknown() {
  echo "UNKNOWN [$GATE] $*"
  # ::error, never ::warning. A warning annotation is yellow text on a green run, and a
  # green run is exactly what "could not check" must not produce.
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "::error title=UNKNOWN ($GATE)::$*"
  fi
  UNKNOWNS=$((UNKNOWNS+1))
}
finish() {
  if [ "$UNKNOWNS" -gt 0 ]; then
    # Both counts, always, and UNKNOWN named first. A run that reports "0 violations" while
    # three files went unread is the false green this whole toolkit exists to refuse.
    echo "$UNKNOWNS unknown(s) and $FAILS violation(s) [$GATE] — UNKNOWN is red: the gate could not check, which is not a pass"
    exit 1
  fi
  if [ "$FAILS" -eq 0 ]; then echo "ok [$GATE]"; exit 0; fi
  echo "$FAILS violation(s) [$GATE]"; exit 1
}
# grep over a tree, skipping build and dependency output. The MATCHER is the caller's to
# pass (-E, -F, ...). It used to be hardcoded to -E here, so a caller that added -F to search
# for a literal term handed grep two matchers; grep answered "conflicting matchers specified"
# and exited 2 on every such search, which made the per-repo denylist unusable in any repo
# that had one. A helper that dictates the matcher is a helper that decides the search.
tgrep() { grep -rn --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=coverage "$@"; }
