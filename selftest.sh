#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
#
# Proves every gate can fail, then runs it on a real tree.
#
#   ./selftest.sh [TARGET_TREE]      TARGET_TREE defaults to this repo
#
# For each gate in gates/:
#   1. the FAILURE leg — run it against fixtures/<gate>/bad and require a non-zero exit.
#      A gate with no fixture fails this test. check_secrets.py's failure leg is its own
#      --selftest instead: canary, fingerprint and negative-probe checks that assert the
#      scanner still detects and still redacts.
#   2. the TREE leg — run it against TARGET_TREE and require exit 0.
#
# Why both directions, every run: 17 of the 51 sessions in the AI Improvements log are a
# mechanism reporting success while doing nothing, and in 7 of those the thing that failed
# open was a check or a CI gate itself. A gate that has never been seen to fail is not
# known to work. "A gate that cannot fail is not a gate." — Angeline S. Viray, vibeOS,
# templates/tier1-ci.yml.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
TARGET="${1:-$HERE}"
[ -d "$TARGET" ] || { echo "selftest: target tree does not exist: $TARGET"; exit 2; }
TARGET="$(cd "$TARGET" && pwd -P)"
FX="$HERE/fixtures"
OUT="$(mktemp)"
bad=0

echo "selftest: toolkit $HERE"
echo "selftest: target  $TARGET"
echo

# The two vendored Python gates are byte-identical to their vibeOS originals (bar one
# attribution comment) and take no root argument by design: each derives the repo it
# checks from its own location, two directories up. So to point one at a tree other than
# this toolkit, a copy has to sit one directory below that tree. STAGE puts it there;
# UNSTAGE removes it. Nothing else in this repo mutates the tree it inspects.
STAGE_DIR=""
unstage() { [ -n "$STAGE_DIR" ] && rm -rf "$STAGE_DIR"; STAGE_DIR=""; }
stage() { # $1 = tree to check
  unstage
  STAGE_DIR="$1/.gates-selftest"
  rm -rf "$STAGE_DIR"; mkdir -p "$STAGE_DIR"
  cp "$HERE/gates/check_secrets.py" "$HERE/gates/check_references.py" "$STAGE_DIR/"
}
cleanup() { unstage; rm -f "$OUT"; }
trap cleanup EXIT

# Run one gate against one tree. Echoes nothing; returns the gate's exit status.
run_gate() { # $1 = gate file, $2 = tree
  local g="$1" tree="$2" name
  name="$(basename "$g")"
  case "$name" in
    *.sh) bash "$g" "$tree" >"$OUT" 2>&1 ;;
    *.py) stage "$tree"; python3 "$STAGE_DIR/$name" >"$OUT" 2>&1; local rc=$?; unstage; return $rc ;;
  esac
}

for g in "$HERE"/gates/*.sh "$HERE"/gates/*.py; do
  name="$(basename "$g")"
  gate="${name%.*}"
  [ "$gate" = lib ] && continue
  fixture="$FX/$gate/bad"

  # ---- 1. the failure leg ----
  if [ "$gate" = check_secrets ]; then
    # Its own probes are the fixture. Run from a staging directory holding BOTH vendored
    # scripts: the redaction-drift comparison looks for check_references.py at
    # <repo>/scripts/ and reports itself SKIPPED when it is absent — run from gates/ it
    # silently checks less than it says it does, which is the defect this file hunts.
    st="$(mktemp -d)"; mkdir -p "$st/scripts"
    cp "$HERE/gates/check_secrets.py" "$HERE/gates/check_references.py" "$st/scripts/"
    if python3 "$st/scripts/check_secrets.py" --selftest >"$OUT" 2>&1; then
      echo "ok  $gate proves itself: $(head -1 "$OUT")"
    else
      echo "SELFTEST FAIL: $gate --selftest did not pass"; sed 's/^/    /' "$OUT"; bad=1
    fi
    rm -rf "$st"
  elif [ ! -d "$fixture" ]; then
    echo "SELFTEST FAIL: $gate has no fixture at fixtures/$gate/bad — it does not count as a gate"
    bad=1
  else
    run_gate "$g" "$fixture"
    rc=$?
    if [ "$rc" -eq 0 ]; then
      echo "SELFTEST FAIL: $gate PASSED its bad fixture (it cannot fail)"; sed 's/^/    /' "$OUT"; bad=1
    elif [ "$rc" -ne 1 ]; then
      # Exit 2 is lib.sh's "no root given" and a Python traceback is anything else.
      # Either way the gate errored rather than reporting a violation, and an error is
      # not evidence that the check works.
      echo "SELFTEST FAIL: $gate errored (exit $rc) on its bad fixture instead of reporting a violation"
      sed 's/^/    /' "$OUT"; bad=1
    else
      echo "ok  $gate catches its bad fixture"
    fi
  fi

  # ---- 2. the tree leg ----
  run_gate "$g" "$TARGET"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "GATE FAIL: $gate fails on the target tree (exit $rc)"; sed 's/^/    /' "$OUT"; bad=1
  else
    echo "ok  $gate passes the target tree"
  fi
done

echo
if [ "$bad" = 0 ]; then
  echo "selftest: every gate was shown to fail, and none fails on this tree"
else
  echo "selftest: FAILED"
fi
exit $bad
