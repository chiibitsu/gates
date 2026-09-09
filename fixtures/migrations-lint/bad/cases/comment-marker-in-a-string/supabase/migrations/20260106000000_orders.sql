-- A `/*` INSIDE a string literal. Comment stripping used to run as a separate stage with no
-- string state, so this opened a block comment that deleted every line until the `*/` in the
-- string below it — taking the create table with it. Verified against PostgreSQL 16: the file
-- applies cleanly and leaves public.orders with RLS off, while the gate reported ok, exit 0.
-- The two surviving quotes pair up, so the unterminated-string guard never fired either.
create table public.notes (body text);
alter table public.notes enable row level security;

insert into public.notes (body) values ('x /* y');

create table public.orders (id int);

insert into public.notes (body) values ('*/ z');
