#!/usr/bin/env bash
# Part of chiibitsu/gates by Angeline S. Viray (Chiibitsu Labs). MIT. https://github.com/chiibitsu/gates
# Every migration ships its rollback, and every table it creates ships RLS in the same file.
# The down-file rule: a migration without one nearly deleted a live cohort on the next push.
# The RLS rule: when an app's route gate silently failed open, RLS was the only thing between
# anonymous callers and the data. AGENTS.md security non-negotiable 2.
source "$(dirname "$0")/lib.sh"
MIG="$ROOT/supabase/migrations"
[ -d "$MIG" ] || { echo "ok [$GATE] no migrations"; exit 0; }
for up in "$MIG"/*.sql; do
  [ -e "$up" ] || continue
  case "$up" in *.down.sql) continue;; esac
  down="${up%.sql}.down.sql"
  [ -f "$down" ] || fail "no rollback: $(basename "$up") needs $(basename "$down")"
  # tables created here must enable RLS here
  while IFS= read -r tbl; do
    if ! grep -qiE "alter\s+table\s+(if\s+exists\s+)?(public\.)?\"?${tbl}\"?\s+enable\s+row\s+level\s+security" "$up"; then
      fail "$(basename "$up"): table '$tbl' created without 'enable row level security' in the same file"
    fi
  done < <(grep -ioE "create\s+table\s+(if\s+not\s+exists\s+)?(public\.)?\"?[a-z_][a-z0-9_]*" "$up" | sed -E 's/.*[ .]"?([a-z_][a-z0-9_]*)"?$/\1/i')
  # destructive statements outside a WHERE are tier-3 by regex (non-negotiable 4); flag, do not block
  if grep -qiE "^\s*(drop\s+table|truncate|delete\s+from\s+[a-z_.\"]+\s*;)" "$up"; then
    echo "note [$GATE] $(basename "$up"): destructive statement present; this migration is tier-3"
  fi
done
finish
