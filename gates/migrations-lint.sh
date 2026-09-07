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
# while the deployed table had none — the gate read a commented-out intention as evidence.
#
# The first version of this stripper was a sed line range, `/\/\*/,/\*\//d`, and it was
# worse than the bug it fixed. A range that OPENS and CLOSES on one line does not close
# there: sed starts deleting at `/* note */ create table ...` and keeps deleting until the
# next line holding `*/`, or to end of file. Two tables created with no RLS anywhere
# reported clean, because the statements that would have been checked were deleted before
# anything looked at them.
#
# It was written on the reasoning that over-removal "makes the gate louder, never quieter".
# That reasoning is wrong and is worth keeping written down: removing an ALTER is louder,
# removing a CREATE TABLE is silent. Comment stripping has no safe direction to lean in.
# It has to be correct, so this is a real one-pass stripper: block spans are removed
# wherever they open and close, SQL after a closing `*/` on the same line survives, and a
# `--` inside a block comment is not treated as a line comment.
#
# What it still cannot do, stated rather than assumed away: `--` or `/*` inside a string
# literal is read as a comment. A migration with `insert into t values ('a -- b')` loses
# the rest of that line. That is a real gap, not a safe one — a create table sharing that
# line would go unchecked. A SQL parser is the fix if it ever bites; a regex that pretends
# to know about quoting is not.
strip_sql_comments() {
  awk '
    BEGIN { inblk = 0 }
    {
      line = $0; out = ""
      while (length(line) > 0) {
        if (inblk) {
          p = index(line, "*/")
          if (p == 0) { line = ""; break }
          line = substr(line, p + 2); inblk = 0
        } else {
          pb = index(line, "/*"); pl = index(line, "--")
          if (pl > 0 && (pb == 0 || pl < pb)) { out = out substr(line, 1, pl - 1); line = ""; break }
          if (pb > 0) { out = out substr(line, 1, pb - 1); line = substr(line, pb + 2); inblk = 1 }
          else { out = out line; line = "" }
        }
      }
      print out
    }
  ' "$1"
}

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
