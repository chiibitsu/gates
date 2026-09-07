#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# Every third-party GitHub Action is pinned to a 40-char commit SHA. A tag or branch is a
# moving target: Trivy's action shipped 75 malicious tags in March 2026, and this repo once
# ran actions/checkout@v4 on a workflow holding a write token.
source "$(dirname "$0")/lib.sh"
WF="$ROOT/.github/workflows"
[ -d "$WF" ] || { echo "ok [$GATE] no workflows"; exit 0; }

# EXTRACTION IS ONE PASS, IN awk, AND IT IS THE ONLY PLACE TEXT IS INTERPRETED.
#
# This gate has now produced five defects, every one of them the same mistake: a regex that
# recognised the spellings of `uses` somebody had thought of, and read straight past the
# rest. In order — the token-anchored `uses:` missed `uses :` and `'uses':`; a line-level
# test for `./` dropped a mutable tag because a COMMENT mentioned a local action; a
# line-level test for `docker://` rejected a correctly pinned action for the same reason; a
# value continued on the next line was skipped in silence; and a flow mapping, `- {uses: x}`,
# was not matched at all — then matched only when `uses` was its FIRST key.
#
# Patching the anchor once more would have been the sixth patch on one confusion. So the
# reading is consolidated: strip the comment, then find EVERY `uses` key on what is left and
# emit its value. Decisions below run on values, and a comment cannot reach them.
#
# It is still not a YAML parser and it does not pretend to be. What it is, is one place to
# be wrong instead of five.
read -r -d '' AWK_EXTRACT <<'AWK' || true
{
  line = $0

  # Drop a trailing comment: the first # that starts the line or follows whitespace. A # is
  # only a comment in YAML in those positions, and no action reference contains one.
  code = line
  n = length(code)
  for (i = 1; i <= n; i++) {
    c = substr(code, i, 1)
    if (c == "#" && (i == 1 || substr(code, i - 1, 1) ~ /[ \t]/)) {
      code = substr(code, 1, i - 1)
      break
    }
  }

  # Every `uses` key on the line, not just the first. `steps: [{uses: a}, {uses: b}]` is one
  # line holding two steps, and stopping at the first left the second unchecked.
  rest = code
  while (match(rest, /(^|[ \t{,[])["']?uses["']?[ \t]*:[ \t]*/)) {
    val = substr(rest, RSTART + RLENGTH)
    rest = val

    # The value ends at the first thing that cannot be part of an action reference.
    if (match(val, /[ \t,}\]]/)) val = substr(val, 1, RSTART - 1)
    gsub(/^["']|["']$/, "", val)

    printf "%s\t%s\t%s\t%s\n", FILENAME, FNR, val, line
  }
}
AWK

FILES="$(mktemp)"; ERR="$(mktemp)"
trap 'rm -f "$FILES" "$ERR"' EXIT

# find's status is checked before anything is read from its output. A directory this gate
# could not descend into is not a directory whose actions are pinned, and the previous
# version fed an unreadable tree's zero lines straight into the loop and printed ok.
set +e
find "$WF" -type f \( -name '*.yml' -o -name '*.yaml' \) -print0 > "$FILES" 2> "$ERR"
rc=$?
set -e
if [ "$rc" -ne 0 ]; then
  fail "could not list workflow files (find exit $rc) — a workflow this gate cannot read is not a pinned one:"
  # head first, then sed: `sed | head` leaves sed on the wrong end of a SIGPIPE, and pipefail
  # turns that into 141, which set -e reads as the gate itself failing.
  head -5 "$ERR" | sed 's/^/    /'
fi

if [ -s "$FILES" ]; then
  # -print0 and mapfile -d '', so a workflow path holding a space or a newline is one path.
  # $(cat) would have split it into several that do not exist, and awk would have been asked
  # about files that are not there instead of the file that is.
  mapfile -d '' -t WFILES < "$FILES"
  while IFS="$(printf '\t')" read -r file lineno val line; do
    if [ -z "$val" ]; then
      # `uses:` with its value on the NEXT line is legal YAML and GitHub runs it. This gate
      # reads one line at a time and cannot see that value; it used to skip the step, which
      # is a pass. A form the gate cannot evaluate is not a form it has cleared.
      fail "$file:$lineno:$line (value is on a following line; put the pinned value on the uses: line)"
      continue
    fi
    ref="${val##*@}"
    case "$val" in
      ./*)
        # A local action lives in this repo and has no ref to pin.
        continue
        ;;
      docker://*)
        # Container actions are pinned by IMAGE DIGEST, not by a git commit. Demanding 40 hex
        # of `docker://image@sha256:<64 hex>` rejected the strongest pin that form has.
        if ! [[ "$ref" =~ ^sha256:[0-9a-f]{64}$ ]]; then
          fail "$file:$lineno:$line (container action: pin by @sha256:<digest>)"
        fi
        ;;
      *)
        if ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then fail "$file:$lineno:$line"; fi
        ;;
    esac
  done < <(awk "$AWK_EXTRACT" "${WFILES[@]}")
fi
finish
