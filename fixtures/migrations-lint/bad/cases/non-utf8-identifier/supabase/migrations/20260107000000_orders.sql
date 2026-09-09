-- A LATIN1 byte in a quoted identifier. `grep` without `-a` calls the records file
-- binary under an ordinary UTF-8 locale, SUPPRESSES the matching line and still exits 0,
-- so this table never reached the comparison and was never checked. The clean table
-- beside it was, which is what made the loss invisible: one violation reported where
-- two are planted. PostgreSQL 16 confirms both tables are real and both have RLS off.
create table public.clean (id int);
create table public."año" (id int);
