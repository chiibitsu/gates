#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# The Next.js-specific footguns, and ONLY those. Three checks: a NEXT_PUBLIC_ variable
# named like a server secret, a tracked .env that is not .env.example, and an optional
# per-repo denylist of names and slugs.
#
# This gate used to also match credential SHAPES. That regex is deleted. Three scanners
# were matching the same shapes in three places — this one, gitleaks, and
# check_secrets.py — and this was the weakest of the three: tree only, no history, no
# commit metadata, no ref names, no redaction of what it printed. Duplicated defences
# drift, and the copy nobody maintains is the one people trust. Credential values are
# check_secrets.py's job and gitleaks' job. What is left here is the one thing neither
# of them does.
#
# The denylist stays: two live clients' repo names once shipped into a public template
# and cost a history rewrite. Names, not shapes — no other scanner looks for those.
source "$(dirname "$0")/lib.sh"

X=(--exclude=nextjs-env.sh --exclude=denylist.txt --exclude=package-lock.json --exclude='*.lock')

# The toolkit's OWN planted failures, excluded ROOT-RELATIVELY. A blanket
# --exclude-dir=fixtures would also exclude the fixture when the gate is pointed AT the
# fixture, and the gate could then no longer fail — which is how the first version of
# proxy-location.sh went permanently green. Only `<root>/fixtures/<gate>/bad/` is
# dropped, and only when the root IS the tree containing it, so pointing this gate at
# fixtures/nextjs-env/bad still trips it.
# Prefix matching in the shell, NOT a regex. ROOT was interpolated into a `grep -E`
# pattern, so a checkout path containing `(` made grep abort — and the `|| true` that
# swallowed the error turned the abort into an empty result, which reads exactly like
# "no violations". A gate that goes green because its own filter crashed is the failure
# this toolkit exists to refuse, and it was sitting inside the filter.
not_fixture() {
  local prefix="$ROOT/fixtures/" line rest gate
  while IFS= read -r line; do
    rest=""
    case "$line" in "$prefix"*) rest="${line#"$prefix"}" ;; esac
    if [ -n "$rest" ]; then
      gate="${rest%%/*}"
      case "${rest#"$gate"/}" in bad/*) continue ;; esac
    fi
    printf '%s\n' "$line"
  done
}

# 1. A server-only key exposed to the browser bundle via the NEXT_PUBLIC_ prefix.
#    Names, deliberately: this is the one check in the toolkit that reads names rather
#    than values, because the mistake it catches IS a naming mistake.
if tgrep "${X[@]}" --exclude=AGENTS.md --exclude-dir=docs --exclude-dir=product \
     'NEXT_PUBLIC_[A-Z0-9_]*(SERVICE|SECRET|PRIVATE)' "$ROOT" 2>/dev/null | not_fixture | grep -q .; then
  fail "NEXT_PUBLIC_ variable named like a server secret:"
  tgrep "${X[@]}" --exclude=AGENTS.md --exclude-dir=docs --exclude-dir=product \
    'NEXT_PUBLIC_[A-Z0-9_]*(SERVICE|SECRET|PRIVATE)' "$ROOT" 2>/dev/null | not_fixture
fi

# 2. A committed .env file (only meaningful inside a git repo). .env.example is the
#    one that is meant to be tracked.
if in_git_repo "$ROOT"; then
  # mktemp, not a PID-derived name in a world-writable directory: on a shared runner that
  # name is guessable and pre-creatable.
  ENVHITS="$(mktemp)"
  if git -C "$ROOT" ls-files | grep -E '(^|/)\.env(\..*)?$' | grep -vE '\.example$' > "$ENVHITS"; then
    fail ".env file is tracked:"; cat "$ENVHITS"
  fi
  rm -f "$ENVHITS"
fi

# 3. Optional denylist: names that must never appear in this repo (client names, repo
#    slugs, owner handles). One per line, case-insensitive. Absent file = skipped.
DL="$ROOT/scripts/gates/denylist.txt"
if [ -f "$DL" ]; then
  while IFS= read -r term; do
    term="${term%%#*}"; term="$(echo "$term" | xargs)"; [ -z "$term" ] && continue
    if tgrep "${X[@]}" -i -F -- "$term" "$ROOT" 2>/dev/null | not_fixture | grep -q .; then
      fail "denylisted term '$term' present:"
      tgrep "${X[@]}" -i -F -- "$term" "$ROOT" 2>/dev/null | not_fixture
    fi
  done < "$DL"
fi
finish
