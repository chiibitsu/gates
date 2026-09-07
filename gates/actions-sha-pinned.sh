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

while IFS= read -r line; do
  ref="${line##*@}"; ref="${ref%% *}"; ref="${ref%%#*}"
  # A quoted value — `uses: "owner/repo@<sha>"` — is legal YAML and left the closing quote
  # glued to the ref, so a correctly pinned action was reported as unpinned. A gate that
  # goes red on compliant input is a gate people learn to merge past, which is how a real
  # finding gets ignored later.
  ref="${ref%\"}"; ref="${ref%\'}"
  if [ "${line#*docker://}" != "$line" ]; then
    # Container actions are pinned by IMAGE DIGEST, not by a git commit. Demanding 40 hex
    # of `docker://image@sha256:<64 hex>` failed the strongest pin available for that form.
    if ! [[ "$ref" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      fail "$line (container action: pin by @sha256:<digest>)"
    fi
  elif ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then
    fail "$line"
  fi
done < <(grep -rEn "${KEY}[^./[:space:]]" "$WF" --include='*.yml' --include='*.yaml' \
           | grep -vE "['\"]?uses['\"]?[[:space:]]*:[[:space:]]*['\"]?\./")
finish
