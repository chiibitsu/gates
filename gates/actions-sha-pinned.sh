#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# Every third-party GitHub Action is pinned to a 40-char commit SHA. A tag or branch is a
# moving target: Trivy's action shipped 75 malicious tags in March 2026, and this repo once
# ran actions/checkout@v4 on a workflow holding a write token.
source "$(dirname "$0")/lib.sh"
WF="$ROOT/.github/workflows"
[ -d "$WF" ] || { echo "ok [$GATE] no workflows"; exit 0; }

# The KEY is matched as YAML spells it, not as it is usually typed. `uses : x` and
# `'uses': x` are both valid mappings that GitHub reads as an ordinary `uses` field, and a
# pattern anchored on the literal token `uses:` found neither — so a mutable tag walked
# through the pinning gate under a legal spelling. This is still a grep and not a YAML
# parser; what changed is that it errs toward matching more keys, and every extra match
# costs at most a false red on a line someone can look at.
KEY="^[[:space:]]*-?[[:space:]]*['\"]?uses['\"]?[[:space:]]*:[[:space:]]*"
# The same key, unanchored, for pulling the VALUE back out of a matched line.
VALKEY="['\"]?uses['\"]?[[:space:]]*:[[:space:]]*"

while IFS= read -r line; do
  # Everything the gate decides on comes from the VALUE, never from the whole line. Testing
  # the line for `docker://` sent `uses: actions/checkout@<sha> # docker://example` into the
  # container branch and rejected a correctly pinned action — a comment is not a value.
  # awk's match() is leftmost, so a second `uses:` later in a comment cannot win.
  val="$(printf '%s' "$line" | awk -v re="$VALKEY" '{ if (match($0, re)) print substr($0, RSTART + RLENGTH) }')"
  val="${val%%[[:space:]]*}"          # the value ends at the first space; an inline comment is past it
  val="${val#\"}"; val="${val#\'}"    # a quoted value is legal YAML
  val="${val%\"}"; val="${val%\'}"
  [ -n "$val" ] || continue
  ref="${val##*@}"
  case "$val" in
    docker://*)
      # Container actions are pinned by IMAGE DIGEST, not by a git commit. Demanding 40 hex
      # of `docker://image@sha256:<64 hex>` failed the strongest pin available for that form.
      if ! [[ "$ref" =~ ^sha256:[0-9a-f]{64}$ ]]; then
        fail "$line (container action: pin by @sha256:<digest>)"
      fi
      ;;
    *)
      if ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then fail "$line"; fi
      ;;
  esac
done < <(grep -rEn "${KEY}[^./[:space:]]" "$WF" --include='*.yml' --include='*.yaml' \
           | grep -vE "['\"]?uses['\"]?[[:space:]]*:[[:space:]]*['\"]?\./")
finish
