-- ONE double quote inside an ordinary string literal. The scanner had no single-quoted-string
-- state, so this `"` opened a quoted identifier that ran to the end of the file and every
-- statement after it was invisible: the create below had no RLS anywhere and the file
-- reported ok, exit 0. An inch mark in seed data is enough to do it.
insert into public.products (name) values ('24" monitor');

create table public.orders (
  id uuid primary key,
  owner_id uuid not null
);
