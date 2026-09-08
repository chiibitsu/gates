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
          line = substr(line, p + 2); inblk = 0; out = out " "
        } else {
          pb = index(line, "/*"); pl = index(line, "--")
          if (pl > 0 && (pb == 0 || pl < pb)) { out = out substr(line, 1, pl - 1); line = ""; break }
          # A SPACE, not nothing. Concatenating the text before `/*` to the text after `*/`
          # made `create/*x*/table public.orders` one word, `createtable`, and the statement
          # a silent pass. A comment separates tokens; removing it must not join them.
          if (pb > 0) { out = out substr(line, 1, pb - 1) " "; line = substr(line, pb + 2); inblk = 1 }
          else { out = out line; line = "" }
        }
      }
      print out
    }
  ' "$1"
}

STRIPPED="$(mktemp)"
SQLSCAN="$(mktemp)"
cat > "$SQLSCAN" <<'SQLSCANAWK'
# Streaming SQL scanner. One record per line: kind <TAB> schema <TAB> table, where kind is
# "C" (create table), "R" (RLS enabled) or "U" (this scanner could not answer). Values are
# escaped, because a quoted identifier may contain a tab or a newline and a delimiter a value
# can contain is not a delimiter.
#
# LINE-INCREMENTAL, NOT SLURPED. The first version built the whole file with `buf = buf $0
# "\n"`, which mawk reallocates and copies every line: 12.1s on a 1.1MB file against 0.11s for
# the greps it replaced, and quadratic, so it got worse with size. A gates job that takes
# minutes and scales the wrong way is the shape of the hang this repository has already been
# bitten by once. State is carried across lines instead; nothing accumulates but the current
# token and the current name.
function esc(v) { gsub(/\\/, "\\\\", v); gsub(/\t/, "\\t", v); gsub(/\n/, "\\n", v); return v }
function emitpair(kind,   tbl, sch) {
  if (nn == 0) return
  tbl = P[nn]; sch = (nn >= 2) ? P[nn - 1] : "public"
  if (tbl == "") return
  print kind "\t" esc(sch) "\t" esc(tbl)
}
function tok(k, v,   again) {
  again = 1
  while (again) {
    again = 0
    if (st == 0) {
      if (k == "W" && v == "create") st = 1
      else if (k == "W" && v == "alter") st = 4
    } else if (st == 1) {
      if (k == "W" && (v == "global" || v == "local" || v == "temporary" || v == "temp" || v == "unlogged")) { }
      else if (k == "W" && v == "table") st = 2
      else { st = 0; again = 1 }
    } else if (st == 2) {
      if (k == "W" && (v == "if" || v == "not" || v == "exists")) { }
      else if (k == "W" || k == "Q") { nn = 1; P[1] = v; st = 3; wantpart = 0 }
      else { st = 0; again = 1 }
    } else if (st == 3) {
      if (k == "D") wantpart = 1
      else if (wantpart && (k == "W" || k == "Q")) { P[++nn] = v; wantpart = 0 }
      else if (wantpart) { st = 0; nn = 0; again = 1 }
      else { emitpair("C"); st = 0; nn = 0; again = 1 }
    } else if (st == 4) {
      if (k == "W" && v == "table") st = 5
      else { st = 0; again = 1 }
    } else if (st == 5) {
      if (k == "W" && (v == "if" || v == "exists" || v == "only")) { }
      else if (k == "W" || k == "Q") { nn = 1; P[1] = v; st = 6; wantpart = 0 }
      else { st = 0; again = 1 }
    } else if (st == 6) {
      if (k == "D") wantpart = 1
      else if (wantpart && (k == "W" || k == "Q")) { P[++nn] = v; wantpart = 0 }
      else if (wantpart) { st = 0; nn = 0; again = 1 }
      else { st = 7; es = 0; again = 1 }
    } else if (st == 7) {
      if (k == "W" && es == 0 && v == "enable") es = 1
      else if (k == "W" && es == 1 && v == "row") es = 2
      else if (k == "W" && es == 2 && v == "level") es = 3
      else if (k == "W" && es == 3 && v == "security") { emitpair("R"); st = 0; nn = 0 }
      else { st = 0; nn = 0; again = 1 }
    }
  }
}
{
  n = length($0); i = 1
  while (i <= n) {
    c = substr($0, i, 1)
    # A DOUBLE-QUOTED IDENTIFIER, possibly spanning lines. `""` inside it is one embedded
    # quote.
    if (inq) {
      if (c == "\"") {
        if (substr($0, i + 1, 1) == "\"") { qv = qv "\""; i += 2; continue }
        inq = 0; i++; tok("Q", qv); qv = ""; continue
      }
      qv = qv c; i++; continue
    }
    # A SINGLE-QUOTED STRING. This state did not exist, and without it ONE `"` inside an
    # ordinary string literal — an inch mark, a quoted word in prose — opened an identifier
    # that ate every following statement. Measured: a file whose only `"` was in
    # `values ('24" monitor')` and whose `create table` had no RLS anywhere reported `ok`,
    # exit 0. A silent pass, introduced by the rewrite that was meant to end them.
    if (ins) {
      if (c == "'") {
        if (substr($0, i + 1, 1) == "'") { sv = sv "'"; i += 2; continue }
        ins = 0; i++
        if (tolower(sv) ~ /create/ && tolower(sv) ~ /table/) ddl = 1
        sv = ""; continue
      }
      sv = sv c; i++; continue
    }
    if (c == " " || c == "\t" || c == "\r") { i++; continue }
    if (c == "\"") { inq = 1; qv = ""; i++; continue }
    if (c == "'")  { ins = 1; sv = ""; i++; continue }
    if (c ~ /[A-Za-z_]/) {
      v = ""
      while (i <= n) { c = substr($0, i, 1); if (c !~ /[A-Za-z0-9_$]/) break; v = v c; i++ }
      tok("W", tolower(v)); continue
    }
    if (c == ".") { tok("D", "."); i++; continue }
    tok("P", c); i++
  }
  if (inq) qv = qv "\n"
  if (ins) sv = sv "\n"
}
END {
  if (st == 3) emitpair("C")
  # A SCANNER THAT LOST SYNC MUST NOT REPORT A CLEAN FILE. An unterminated quoted identifier
  # or string means everything after it was read as something it is not, so the only honest
  # answer about the rest of the file is that this gate could not read it.
  if (inq) print "U\tunterminated-quoted-identifier\t"
  if (ins) print "U\tunterminated-string\t"
  # DDL inside a string literal is executed by `execute`, and this scanner treats the string
  # as data — the alternative, reading it, named tables nobody created and sent fixers to
  # edit their data. Neither is a check, so it says so.
  if (ddl) print "U\tddl-inside-a-string-literal\t"
}
SQLSCANAWK
WORK_TOK="$(mktemp)"
WORK_C="$(mktemp)"
WORK_R="$(mktemp)"
trap 'rm -f "$STRIPPED" "$SQLSCAN" "$WORK_TOK" "$WORK_C" "$WORK_R"' EXIT

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
  awk -f "$SQLSCAN" "$STRIPPED" > "$WORK_TOK"

  # ONE LINE PER RECORD, TAB-SEPARATED, VALUES ESCAPED. It was three lines per record, and a
  # quoted identifier containing a newline then shifted every following triple: a file with
  # `public."we<newline>ird"` and two more non-compliant tables reported ONE violation, naming
  # `public.we` — a table that does not exist — and did not report the other two at all. A
  # reader who "fixed" the named table would have got a green over an unguarded schema. The
  # comment beside it claimed the limitation was "recorded in the README"; the word newline
  # does not appear in that file. Escaping is exact for comparison, because both sides are
  # escaped by the same function, and the escaped form is what the message prints.
  c_n=0; r_n=0
  while IFS="$(printf '\t')" read -r kind sch tbl; do
    case "$kind" in
      C) c_n=$((c_n+1)); C_SCH[$c_n]="$sch"; C_TBL[$c_n]="$tbl" ;;
      R) r_n=$((r_n+1)); R_SCH[$r_n]="$sch"; R_TBL[$r_n]="$tbl" ;;
      U) unknown "$(basename "$up"): $sch — this gate could not read the statements after it, and will not call the file clean" ;;
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
