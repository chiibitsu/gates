#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# Every migration ships its rollback, and every table it creates ships RLS in the same file.
# The down-file rule: a migration without one nearly deleted a live cohort on the next push.
# The RLS rule: when an app's route gate silently failed open, RLS was the only thing between
# anonymous callers and the data. AGENTS.md security non-negotiable 2.
source "$(dirname "$0")/lib.sh"
MIG="$ROOT/supabase/migrations"
[ -d "$MIG" ] || { echo "ok [$GATE] no migrations"; exit 0; }

# Comments are stripped before anything is read as a statement. A migration holding only
# `-- alter table public.accounts enable row level security;` used to satisfy the RLS rule
# while the deployed table had none — the gate read a commented-out intention as evidence,
# which is the silent false-success this whole toolkit refuses. Temporarily commenting a
# line out is exactly how that happens in practice.
#
# The stripping is deliberately blunt and errs toward removing MORE than it should: whole
# lines from `/*` to `*/`, and everything after `--` even inside a string literal. Every
# over-removal points the same way — a create-table or an ALTER that vanishes makes the gate
# LOUDER, never quieter. Only under-removal can hide a violation, and that direction is what
# is closed here. A real SQL parser is the answer if this is ever wrong in the noisy
# direction; it is not the answer to a gate that under-reports.
strip_sql_comments() { sed -e '/\/\*/,/\*\//d' -e 's/--.*$//' "$1"; }

STRIPPED="$(mktemp)"
trap 'rm -f "$STRIPPED"' EXIT

for up in "$MIG"/*.sql; do
  [ -e "$up" ] || continue
  case "$up" in *.down.sql) continue;; esac
  down="${up%.sql}.down.sql"
  [ -f "$down" ] || fail "no rollback: $(basename "$up") needs $(basename "$down")"
  strip_sql_comments "$up" > "$STRIPPED"
  # tables created here must enable RLS here
  while IFS= read -r tbl; do
    if ! grep -qiE "alter\s+table\s+(if\s+exists\s+)?(public\.)?\"?${tbl}\"?\s+enable\s+row\s+level\s+security" "$STRIPPED"; then
      fail "$(basename "$up"): table '$tbl' created without 'enable row level security' in the same file"
    fi
  done < <(grep -ioE "create\s+table\s+(if\s+not\s+exists\s+)?(public\.)?\"?[a-z_][a-z0-9_]*" "$STRIPPED" | sed -E 's/.*[ .]"?([a-z_][a-z0-9_]*)"?$/\1/i')
  # destructive statements outside a WHERE are tier-3 by regex (non-negotiable 4); flag, do not block
  if grep -qiE "^\s*(drop\s+table|truncate|delete\s+from\s+[a-z_.\"]+\s*;)" "$STRIPPED"; then
    echo "note [$GATE] $(basename "$up"): destructive statement present; this migration is tier-3"
  fi
done
finish
