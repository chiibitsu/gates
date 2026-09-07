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
ROOT="$(cd "$ROOT" && pwd -P)"
FAILS=0
fail() { echo "FAIL [$GATE] $*"; FAILS=$((FAILS+1)); }
finish() {
  if [ "$FAILS" -eq 0 ]; then echo "ok [$GATE]"; exit 0; fi
  echo "$FAILS violation(s) [$GATE]"; exit 1
}
# grep over a tree, skipping build and dependency output
tgrep() { grep -rEn --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next --exclude-dir=coverage "$@"; }
