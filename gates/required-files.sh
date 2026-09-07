#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# Every path in required-files.txt exists (and is git-tracked when inside a repo), dotfiles
# included. The published template once shipped without .github/, .claude/, .gitignore or a
# backup doc; clients deployed it with no gates and no hooks and nobody noticed for weeks.
source "$(dirname "$0")/lib.sh"
LIST="$ROOT/scripts/gates/required-files.txt"
[ -f "$LIST" ] || { fail "missing manifest scripts/gates/required-files.txt"; finish; }
while IFS= read -r p; do
  p="${p%%#*}"; p="$(echo "$p" | xargs)"; [ -z "$p" ] && continue
  if [ ! -e "$ROOT/$p" ]; then fail "missing: $p"; continue; fi
  if [ -d "$ROOT/.git" ] && [ -f "$ROOT/$p" ]; then
    git -C "$ROOT" ls-files --error-unmatch "$p" >/dev/null 2>&1 || fail "untracked: $p"
  fi
done < "$LIST"
finish
