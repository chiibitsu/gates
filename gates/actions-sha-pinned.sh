#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# Every third-party GitHub Action is pinned to a 40-char commit SHA. A tag or branch is a
# moving target: Trivy's action shipped 75 malicious tags in March 2026, and this repo once
# ran actions/checkout@v4 on a workflow holding a write token.
source "$(dirname "$0")/lib.sh"
WF="$ROOT/.github/workflows"
[ -d "$WF" ] || { echo "ok [$GATE] no workflows"; exit 0; }
while IFS= read -r line; do
  ref="${line##*@}"; ref="${ref%% *}"; ref="${ref%%#*}"
  if ! [[ "$ref" =~ ^[0-9a-f]{40}$ ]]; then fail "$line"; fi
done < <(grep -rEn '^\s*-?\s*uses:\s*[^./]' "$WF" --include='*.yml' --include='*.yaml' | grep -v 'uses:\s*\./')
finish
