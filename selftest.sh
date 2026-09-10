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
#   2. the CASE leg — run it against every fixtures/<gate>/bad/cases/<name> and require exit 1
#      AND a FAIL line from each (for the shell gates; see the marker note beside the loop).
#      The bad fixture is one tree holding many violations, so it proves only that SOMETHING
#      in it fails; a shape that stopped being detected hides behind the others still failing.
#      A case is one tree holding one shape, so it can only pass by that shape still being
#      caught. The FAIL line is half of that: UNKNOWN is also red, so without it a gate that
#      lost the shape and merely tripped over a blind spot on the same tree still "passed".
#      Every false green a reviewer finds gets a case here.
#   3. the UNKNOWN leg — run it against every fixtures/<gate>/bad/unknown/<name> and require
#      a RED exit that carries an UNKNOWN line and no FAIL line. "Could not check" must be
#      as blocking as "found a violation" and must not be mistakable for one.
#   4. the TREE leg — run it against TARGET_TREE and require exit 0. A gate that rejects a
#      VALID form shows up only on this leg: the fixture model holds bad trees, so a false
#      RED cannot be planted in one.
#
# Why both directions, every run: 17 of the 51 sessions in the AI Improvements log are a
# mechanism reporting success while doing nothing, and in 7 of those the thing that failed
# open was a check or a CI gate itself. A gate that has never been seen to fail is not
# known to work. "A gate that cannot fail is not a gate." — Angeline S. Viray, vibeOS,
# templates/tier1-ci.yml.
set -uo pipefail

HERE="$(cd -- "$(dirname -- "$0")" && pwd -P)"
TARGET="${1:-$HERE}"
[ -d "$TARGET" ] || { echo "selftest: target tree does not exist: $TARGET"; exit 2; }
# `cd --`, and the result is checked. A target spelled `-tgt` is a legal directory name;
# without the `--` bash read the `-t` as an option, the cd failed, TARGET became EMPTY, and
# every gate was then run against nothing and reported as failing a tree the harness never
# looked at. This is the same defect the gates themselves carried, in the thing that checks
# them — so it could have reported all of them broken while checking none.
TARGET="$(cd -- "$TARGET" && pwd -P)" || { echo "selftest: cannot enter target tree: $TARGET"; exit 2; }
[ -n "$TARGET" ] || { echo "selftest: target tree resolved to nothing"; exit 2; }
FX="$HERE/fixtures"
OUT="$(mktemp)"
bad=0

# ---------------------------------------------------------------------------
# Do the gates that exist and the gates that are supposed to exist agree?
#
# The UNIVERSE is read from the system: whatever is in gates/. The SPEC is gates/MANIFEST.txt.
# They are asserted against each other BY NAME, in BOTH directions, and neither is used to
# filter the other — iterating "the manifest entries that have files" or "the files that are
# in the manifest" would make a mismatch unobservable, which is the whole thing being
# checked.
#
# Without this, deleting a gate file was invisible. The loop below read the directory, ran
# one fewer gate, and printed "every gate was shown to fail" — a true sentence about a
# smaller set, in a report whose reader has no way to know the set changed. The check and
# its message have to cover the same ground, and here they did not.
# ---------------------------------------------------------------------------
MANIFEST="$HERE/gates/MANIFEST.txt"
if [ ! -f "$MANIFEST" ]; then
  echo "SELFTEST FAIL: gates/MANIFEST.txt is missing — there is nothing to check the gates directory against"
  exit 1
fi
SPEC="$(mktemp)"; UNIVERSE="$(mktemp)"
# No trap here. `trap ... EXIT` REPLACES the previous EXIT trap rather than adding to it, so
# the one this file already sets further down would have silently dropped whatever was
# registered here. Both files are removed by that single cleanup instead.
sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$MANIFEST" \
  | awk 'NF { print $1 }' | sort > "$SPEC"
# `[ -f ]` on every one, because an unmatched glob stays LITERAL in bash unless nullglob is
# set. Both patterns match today; remove the last .py gate and `$HERE/gates/*.py` survives as
# itself, basename yields `*.py`, and the universe gains an entry named `*`. The cross-check
# below then reports `gates/* exists but is not named in gates/MANIFEST.txt` and the
# trackedness loop reports the same literal as untracked — two messages sending a reader after
# a file called `*`, printed by the check whose entire job is telling the truth about which
# gates exist. Reproduced before fixing.
for g in "$HERE"/gates/*.sh "$HERE"/gates/*.py; do
  [ -f "$g" ] || continue
  n="$(basename "$g")"; echo "${n%.*}"
done | sort > "$UNIVERSE"

# Present on disk is not the same as present in a clone. required-files.txt used to carry
# every gate path for exactly this check; those lines are gone now that MANIFEST.txt is the
# single list of gate names, so the trackedness they were buying is bought here instead —
# otherwise collapsing the duplicate would have quietly dropped a check with it.
if git -C "$HERE" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  for g in "$HERE"/gates/*.sh "$HERE"/gates/*.py "$MANIFEST"; do
    [ -f "$g" ] || continue
    rp="${g#"$HERE"/}"
    git -C "$HERE" ls-files --error-unmatch -- "$rp" >/dev/null 2>&1 || {
      echo "SELFTEST FAIL: $rp is not git-tracked — it exists here and would not exist in a clone"
      bad=1
    }
  done
fi

manifest_ok=1
while IFS= read -r n; do
  [ -n "$n" ] || continue
  grep -Fxq -- "$n" "$SPEC" || { echo "SELFTEST FAIL: gates/$n exists but is not named in gates/MANIFEST.txt"; manifest_ok=0; bad=1; }
done < "$UNIVERSE"
while IFS= read -r n; do
  [ -n "$n" ] || continue
  grep -Fxq -- "$n" "$UNIVERSE" || { echo "SELFTEST FAIL: gates/MANIFEST.txt names '$n' but there is no gates/$n.sh or gates/$n.py"; manifest_ok=0; bad=1; }
done < "$SPEC"
if [ "$manifest_ok" = 1 ]; then
  echo "ok  gates/ and gates/MANIFEST.txt agree, both directions ($(grep -c . "$UNIVERSE") gates)"
fi

# The mode column, read from the same single list. selftest.sh does not carry gate names of
# its own; a literal `check_secrets` in this file's control flow was a second enumeration
# that nothing checked against the first.
mode_of() { # $1 = gate name
  sed -e 's/#.*//' "$MANIFEST" | awk -v g="$1" 'NF && $1 == g { print $2; found=1 } END { if (!found) print "MISSING" }'
}

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
  # mktemp -d, never a fixed path. The fixed `.gates-selftest` was deleted unconditionally
  # before every staged run, so a target repository that happened to hold a directory of
  # that name lost it — the toolkit destroying data in the tree it was asked to inspect.
  STAGE_DIR="$(mktemp -d "$1/.gates-selftest.XXXXXX")"
  cp "$HERE/gates/check_secrets.py" "$HERE/gates/check_references.py" "$STAGE_DIR/"
}
cleanup() { unstage; rm -f "$OUT" "$SPEC" "$UNIVERSE"; }
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
  [ -f "$g" ] || continue
  name="$(basename "$g")"
  gate="${name%.*}"
  mode="$(mode_of "$gate")"
  [ "$mode" = library ] && continue
  if [ "$mode" = MISSING ]; then
    # Already reported by the cross-check above; skip rather than test it under a mode
    # this file would have to invent.
    continue
  fi
  fixture="$FX/$gate/bad"

  # THE VIOLATION MARKER IS A PROPERTY OF THE GATE, NOT OF THE HARNESS. `FAIL [` and
  # `UNKNOWN [` come from `fail()` and `unknown()` in gates/lib.sh — the SHELL gates' helpers.
  # The two vendored Python gates print their own lines (`references: N broken reference(s)`,
  # `secrets: N possible credential(s) committed`) and cannot emit either marker, so asserting
  # the marker for them would report a gate that detected its planted shape perfectly as
  # having a blind spot. That is an assertion BROADER than its message, inside the leg written
  # to catch assertions narrower than theirs.
  #
  # MEASURED, not reasoned. A fixture citing a missing path was planted at
  # fixtures/check_references/bad/cases/broken-path/ and run: the gate found it exactly
  # ("references: 1 broken reference(s)"), and the unguarded harness answered "went red on
  # case 'broken-path' without printing a FAIL line — the red is a blind spot, not the planted
  # violation". With the guard below it reports `ok  check_references catches case
  # 'broken-path'`, which is what happened.
  #
  # The fixture is not kept, and the reason is a second finding rather than a tidy-up: unlike
  # every shell gate, the vendored check_references.py has NO fixtures/ filter, so the planted
  # citation is validated as though it were real and the TREE leg goes red on it. No Python
  # gate can carry a cases/ fixture until that changes — and changing it means editing a
  # vendored file, which is a policy decision and not this file's to make. So this guard is
  # correct and currently unexercised, and that is stated here rather than left to look like
  # dead code. This file's own header invites the fixture ("Every false green a reviewer finds
  # gets a case here"); today the invitation cannot be accepted for these two gates.
  #
  # Losing the marker check for them costs nothing it was buying: the marker exists to tell a
  # violation from an UNKNOWN, and a gate with no UNKNOWN outcome has nothing to confuse. For
  # those gates a red is a violation by construction, and the exit code is the whole claim.
  case "$name" in
    *.sh) markers=1 ;;
    *)    markers=0 ;;
  esac

  # ---- 1. the failure leg ----
  if [ "$mode" = selftest ]; then
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

  # ---- 2. the case leg ----
  #
  # Cases live UNDER bad/, not beside it. Every gate that filters out this toolkit's own
  # planted failures filters on the `fixtures/<gate>/bad/` prefix, including the versions
  # already tagged and pinned — and .github/workflows/caller-smoke.yml runs a PINNED
  # RELEASE of this toolkit over this tree, exactly as a consumer would. A `cases/` beside
  # `bad/` was invisible to that release's filter, so adding the first one turned the
  # consumer job red on a fixture. A layout only the working copy understands is a layout
  # that breaks its own published versions.
  cases="$FX/$gate/bad/cases"
  if [ -d "$cases" ]; then
    for c in "$cases"/*/; do
      [ -d "$c" ] || continue
      cname="$(basename "$c")"
      run_gate "$g" "${c%/}"
      rc=$?
      # THE RED IS NOT ENOUGH, and this leg used to accept it. A case fixture plants one
      # violation and the claim printed is "catches case '<name>'" — but UNKNOWN is also red,
      # so a gate that lost the ability to see the planted shape and merely tripped over a
      # blind spot on the same tree passed this leg while the shape went undetected. That is
      # an assertion narrower than its own message, in the code written to catch exactly
      # that. The UNKNOWN leg below already asserts both halves; this one now does too.
      n_fail="$(grep -c '^FAIL \[' "$OUT" || true)"
      if [ "$rc" -eq 0 ]; then
        echo "SELFTEST FAIL: $gate PASSED case '$cname' — that shape is no longer detected"
        sed 's/^/    /' "$OUT"; bad=1
      elif [ "$rc" -ne 1 ]; then
        echo "SELFTEST FAIL: $gate errored (exit $rc) on case '$cname' instead of reporting a violation"
        sed 's/^/    /' "$OUT"; bad=1
      elif [ "$markers" = 1 ] && [ "$n_fail" -eq 0 ]; then
        echo "SELFTEST FAIL: $gate went red on case '$cname' without printing a FAIL line — the red is a blind spot, not the planted violation"
        sed 's/^/    /' "$OUT"; bad=1
      else
        echo "ok  $gate catches case '$cname'"
      fi
    done
  fi

  # ---- 3. the UNKNOWN leg ----
  #
  # "I could not check this" is a distinct outcome and needs its own proof. These fixtures
  # must make the gate go RED — a gate that cannot check and says nothing is the false green
  # this toolkit exists to refuse — while reporting NO violation, because a violation it did
  # not find is not what happened. Both halves are asserted; requiring only the red would be
  # satisfied by a gate that reported a phantom FAIL, which reads to a fixer as a bug in
  # their code rather than a blind spot in the gate.
  #
  # Under bad/, like cases/, and for the same reason: published versions of this toolkit
  # filter their own planted failures on the `fixtures/<gate>/bad/` prefix, and
  # caller-smoke.yml runs a pinned release over this tree.
  unknowns="$FX/$gate/bad/unknown"
  if [ -d "$unknowns" ]; then
    for u in "$unknowns"/*/; do
      [ -d "$u" ] || continue
      uname="$(basename "$u")"
      run_gate "$g" "${u%/}"
      rc=$?
      n_unknown="$(grep -c '^UNKNOWN \[' "$OUT" || true)"
      n_fail="$(grep -c '^FAIL \[' "$OUT" || true)"
      if [ "$rc" -eq 0 ]; then
        echo "SELFTEST FAIL: $gate went GREEN on unknown case '$uname' — it could not check and said so with a pass"
        sed 's/^/    /' "$OUT"; bad=1
      elif [ "$markers" = 1 ] && [ "$n_unknown" -eq 0 ]; then
        echo "SELFTEST FAIL: $gate went red on unknown case '$uname' without printing an UNKNOWN line — the reader cannot tell a blind spot from a violation"
        sed 's/^/    /' "$OUT"; bad=1
      elif [ "$markers" = 1 ] && [ "$n_fail" -gt 0 ]; then
        echo "SELFTEST FAIL: $gate reported $n_fail violation(s) on unknown case '$uname', which plants none — it is blaming the tree for its own blind spot"
        sed 's/^/    /' "$OUT"; bad=1
      else
        echo "ok  $gate reports UNKNOWN (red, no violation) on '$uname'"
      fi
    done
  fi

  # ---- 4. the tree leg ----
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
