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
WORK_TOK="$(mktemp)"
WORK_C="$(mktemp)"
WORK_R="$(mktemp)"
trap 'rm -f "$STRIPPED" "$WORK_TOK" "$WORK_C" "$WORK_R"' EXIT

for up in "$MIG"/*.sql; do
  [ -e "$up" ] || continue
  case "$up" in *.down.sql) continue;; esac
  down="${up%.sql}.down.sql"
  [ -f "$down" ] || fail "no rollback: $(basename "$up") needs $(basename "$down")"
  strip_sql_comments "$up" > "$STRIPPED"
  # TABLES CREATED HERE MUST ENABLE RLS HERE — DECIDED BY TOKENISING, NOT BY MATCHING.
  #
  # This check was a regex three times over and produced a finding in each of three
  # consecutive review rounds, alternating direction every time:
  #
  #   - `create table "public"."orders"` read `public` as the table. Where a table genuinely
  #     named `public` had RLS the file PASSED — a false green.
  #   - Widening the ALTER side to any schema while the create side discarded it made the
  #     check assert "SOME table called orders, in SOME schema, has RLS" under a message
  #     naming one table: `alter table archive.orders` satisfied `create table public.orders`.
  #     Another false green, added by the commit that removed the first one.
  #   - Carrying the pair fixed that and broke four compliant files instead:
  #     `mydb.public.orders`, `public."order items"`, `public."a.b"`, and `ALTER TABLE ONLY`
  #     (which is what pg_dump emits) — reds naming tables that do not exist.
  #   - And still open after all three: a quoted identifier lost its case, so
  #     `create table public."Orders"` was satisfied by RLS on `orders`, which PostgreSQL
  #     treats as a different table and which is what Prisma and Drizzle emit; a `""` inside
  #     a quoted name ended the name early; a name containing a regex metacharacter built a
  #     matcher wider than itself; a `create table` whose name sat on the NEXT line was not
  #     seen at all, because grep is line-scoped — a silent pass.
  #
  # Every one of those is the same defect: a pattern deciding a question that needs a parse.
  # So the statements are tokenised once, both sides through the SAME scanner, and the two
  # (schema, table) pairs are compared as STRINGS. There is no interpolated regex left to be
  # wider than the name it was given, no case flag to fold a quoted identifier, and no line
  # boundary to hide a statement behind.
  : > "$WORK_C"; : > "$WORK_R"
  awk '
    # Emits three lines per statement found: kind ("C" create / "R" rls-enabled), schema, table.
    # Three lines rather than one delimited line because a quoted identifier may contain any
    # character, a tab and a newline included, and a delimiter a value can contain is not a
    # delimiter. Newline inside a quoted identifier would still break this; that is recorded in
    # the README rather than claimed away.
    function parse_name(p,   j) {
      NAME_N = 0; j = p
      while (1) {
        if (tk[j] == "W" || tk[j] == "Q") { NAME_N++; NAME_P[NAME_N] = tv[j]; j++ } else return 0
        if (tk[j] == "D") { j++; continue }
        break
      }
      NAME_END = j
      return 1
    }
    function emit(kind,   sch, tbl) {
      tbl = NAME_P[NAME_N]
      sch = (NAME_N >= 2) ? NAME_P[NAME_N - 1] : "public"
      if (tbl == "") return
      print kind; print sch; print tbl
    }
    { buf = buf $0 "\n" }
    END {
      n = length(buf); i = 1; ntok = 0
      while (i <= n) {
        c = substr(buf, i, 1)
        if (c == " " || c == "\t" || c == "\r" || c == "\n") { i++; continue }
        if (c == "\"") {
          # A quoted identifier. `""` inside it is one embedded quote, which the old
          # `"[^"]*"` regex ended the identifier on — `public."say ""hi"""` was read as table
          # `say`, a violation naming a table that does not exist over a compliant file.
          i++; v = ""
          while (i <= n) {
            c = substr(buf, i, 1)
            if (c == "\"") {
              if (substr(buf, i + 1, 1) == "\"") { v = v "\""; i += 2; continue }
              i++; break
            }
            v = v c; i++
          }
          # CASE IS PRESERVED. PostgreSQL folds an unquoted identifier to lower case and keeps a
          # quoted one exactly, so `"Orders"` and `orders` are two different tables. Lowercasing
          # both and matching case-insensitively let RLS on one satisfy a create of the other —
          # a false green, and PascalCase quoted names are what Prisma and Drizzle emit.
          ntok++; tk[ntok] = "Q"; tv[ntok] = v
          continue
        }
        if (c ~ /[A-Za-z_]/) {
          v = ""
          while (i <= n) { c = substr(buf, i, 1); if (c !~ /[A-Za-z0-9_$]/) break; v = v c; i++ }
          ntok++; tk[ntok] = "W"; tv[ntok] = tolower(v)
          continue
        }
        if (c == ".") { ntok++; tk[ntok] = "D"; tv[ntok] = "."; i++; continue }
        ntok++; tk[ntok] = "P"; tv[ntok] = c; i++
      }
      for (p = 1; p <= ntok; p++) {
        if (tk[p] != "W") continue
        if (tv[p] == "create") {
          q = p + 1
          if (tk[q] == "W" && (tv[q] == "global" || tv[q] == "local")) q++
          if (tk[q] == "W" && (tv[q] == "temporary" || tv[q] == "temp" || tv[q] == "unlogged")) q++
          if (!(tk[q] == "W" && tv[q] == "table")) continue
          q++
          if (tk[q] == "W" && tv[q] == "if" && tk[q+1] == "W" && tv[q+1] == "not" && tk[q+2] == "W" && tv[q+2] == "exists") q += 3
          if (!parse_name(q)) continue
          emit("C")
        } else if (tv[p] == "alter") {
          q = p + 1
          if (!(tk[q] == "W" && tv[q] == "table")) continue
          q++
          if (tk[q] == "W" && tv[q] == "if" && tk[q+1] == "W" && tv[q+1] == "exists") q += 2
          if (tk[q] == "W" && tv[q] == "only") q++
          if (!parse_name(q)) continue
          q = NAME_END
          if (tk[q] == "W" && tv[q] == "enable" && tk[q+1] == "W" && tv[q+1] == "row" &&
              tk[q+2] == "W" && tv[q+2] == "level" && tk[q+3] == "W" && tv[q+3] == "security") emit("R")
        }
      }
    }
  ' "$STRIPPED" > "$WORK_TOK"

  # Read back as line triples. A delimiter a value can contain is not a delimiter, and a
  # quoted identifier may contain any character.
  c_n=0; r_n=0
  while IFS= read -r kind && IFS= read -r sch && IFS= read -r tbl; do
    case "$kind" in
      C) c_n=$((c_n+1)); C_SCH[$c_n]="$sch"; C_TBL[$c_n]="$tbl" ;;
      R) r_n=$((r_n+1)); R_SCH[$r_n]="$sch"; R_TBL[$r_n]="$tbl" ;;
    esac
  done < "$WORK_TOK"

  i=1
  while [ "$i" -le "$c_n" ]; do
    found=0
    j=1
    while [ "$j" -le "$r_n" ]; do
      if [ "${C_SCH[$i]}" = "${R_SCH[$j]}" ] && [ "${C_TBL[$i]}" = "${R_TBL[$j]}" ]; then found=1; break; fi
      j=$((j+1))
    done
    if [ "$found" -eq 0 ]; then
      fail "$(basename "$up"): table '${C_SCH[$i]}.${C_TBL[$i]}' created without 'enable row level security' in the same file"
    fi
    i=$((i+1))
  done
  unset C_SCH C_TBL R_SCH R_TBL

  # destructive statements outside a WHERE are tier-3 by regex (non-negotiable 4); flag, do not block
  if grep -qiE "^[[:space:]]*(drop[[:space:]]+table|truncate|delete[[:space:]]+from[[:space:]]+[a-z_.\"]+[[:space:]]*;)" "$STRIPPED"; then
    echo "note [$GATE] $(basename "$up"): destructive statement present; this migration is tier-3"
  fi
done
finish
