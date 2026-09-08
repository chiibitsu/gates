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
  # tables created here must enable RLS here.
  #
  # THE SCHEMA QUALIFIER IS PART OF THE TABLE'S IDENTITY AND IS CARRIED THROUGH. Three
  # spellings had to be reconciled, and getting two of them right while dropping the third
  # cost a false green:
  #
  #   - `create table "public"."orders"` is one identifier per quoted part. The pattern used
  #     to name only `public\.` unquoted, so the leading `"?` swallowed the opening quote and
  #     `public` was read as the TABLE. Where a table genuinely named `public` had RLS the
  #     file PASSED and `orders` was never checked; where it did not, the violation named the
  #     wrong table — a red a fixer cannot act on.
  #   - Fixing that by matching ANY schema generically on both sides, while the create side
  #     still discarded the schema, made the check assert only "SOME table called orders, in
  #     SOME schema, has RLS" — under a message naming one specific table. Measured:
  #     `create table public.orders` + `alter table archive.orders enable row level security`
  #     went from red to `ok`, over a state PostgreSQL 16 accepts and in which public.orders
  #     really is unprotected. Two schemas holding a same-named table is an ordinary layout.
  #     A widened matcher under an unwidened message is this repository's recurring defect,
  #     introduced here in the very commit that removed another instance of it.
  #   - So the pair travels together. Unqualified is normalised to `public`, which is what an
  #     unqualified name resolves to under the default search_path, and an unqualified ALTER
  #     is therefore accepted only for a table created in `public`.
  #
  # `unlogged` and `temp`/`temporary` tables are matched too. They were invisible to
  # `create[[:space:]]+table`, so an `create unlogged table orders` with no RLS anywhere was
  # never checked at all — `ok`, exit 0. RLS applies to unlogged tables; verified on
  # PostgreSQL 16. Whitespace around the qualifier dot (`public . orders`, which Postgres
  # accepts) is matched for the same reason: a spelling the gate cannot read is a table the
  # gate does not check.
  while IFS="$(printf '\t')" read -r sch tbl; do
    [ -n "$tbl" ] || continue
    if [ "$sch" = "public" ]; then
      qual="(\"?public\"?[[:space:]]*\.[[:space:]]*)?"
    else
      qual="\"?${sch}\"?[[:space:]]*\.[[:space:]]*"
    fi
    if ! grep -qiE "alter[[:space:]]+table[[:space:]]+(if[[:space:]]+exists[[:space:]]+)?${qual}\"?${tbl}\"?[[:space:]]+enable[[:space:]]+row[[:space:]]+level[[:space:]]+security" "$STRIPPED"; then
      fail "$(basename "$up"): table '$sch.$tbl' created without 'enable row level security' in the same file"
    fi
  done < <(
    # Lowercased with `tr` before any sed runs, so no step needs a case-insensitive sed flag.
    # `s///i` is a GNU extension and this repository has already been bitten once by a GNU-only
    # regex feature silently matching nothing on BSD (`\s`, 18 occurrences, fixed in v1.2.1).
    grep -ioE "create[[:space:]]+((global|local)[[:space:]]+)?((temporary|temp|unlogged)[[:space:]]+)?table[[:space:]]+(if[[:space:]]+not[[:space:]]+exists[[:space:]]+)?(\"?[a-z_][a-z0-9_]*\"?[[:space:]]*\.[[:space:]]*)?\"?[a-z_][a-z0-9_]*" "$STRIPPED" \
      | tr '[:upper:]' '[:lower:]' \
      | sed -E 's/"//g; s/[[:space:]]*\.[[:space:]]*/./; s/^create[[:space:]]+((global|local)[[:space:]]+)?((temporary|temp|unlogged)[[:space:]]+)?table[[:space:]]+(if[[:space:]]+not[[:space:]]+exists[[:space:]]+)?//' \
      | awk -F. 'NF==2 {print $1"\t"$2; next} {print "public\t"$1}'
  )
  # destructive statements outside a WHERE are tier-3 by regex (non-negotiable 4); flag, do not block
  if grep -qiE "^[[:space:]]*(drop[[:space:]]+table|truncate|delete[[:space:]]+from[[:space:]]+[a-z_.\"]+[[:space:]]*;)" "$STRIPPED"; then
    echo "note [$GATE] $(basename "$up"): destructive statement present; this migration is tier-3"
  fi
done
finish
