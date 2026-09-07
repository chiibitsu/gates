#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# Every path in required-files.txt exists (and is git-tracked when inside a repo), dotfiles
# included. The published template once shipped without .github/, .claude/, .gitignore or a
# backup doc; clients deployed it with no gates and no hooks and nobody noticed for weeks.
source "$(dirname "$0")/lib.sh"
LIST="$ROOT/scripts/gates/required-files.txt"
[ -f "$LIST" ] || { fail "missing manifest scripts/gates/required-files.txt"; finish; }
# `|| [ -n "$p" ]` so a last line with no trailing newline is still read.
while IFS= read -r p || [ -n "$p" ]; do
  # clean_list_line, not `echo | xargs`. xargs parses quotes, so a single apostrophe in a
  # path ended the gate mid-manifest under `set -e` — with every entry after it unchecked
  # and `finish` never reached, which is a check that stopped early wearing a normal exit.
  p="$(clean_list_line "$p")"
  if [ -z "$p" ]; then continue; fi
  if [ ! -e "$ROOT/$p" ]; then fail "missing: $p"; continue; fi
  if [ -f "$ROOT/$p" ] && in_git_repo "$ROOT"; then
    git -C "$ROOT" ls-files --error-unmatch "$p" >/dev/null 2>&1 || fail "untracked: $p"
  fi
done < "$LIST"
finish
