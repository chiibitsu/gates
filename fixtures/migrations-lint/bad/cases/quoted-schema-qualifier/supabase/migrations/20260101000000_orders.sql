-- The schema qualifier is quoted SEPARATELY from the table: "public"."orders". The extractor
-- read the first identifier it could and took `public` for the table name, so the RLS check
-- below was run against a table called public rather than against orders.
--
-- This fixture is shaped to discriminate. A table actually named `public` exists here and
-- does enable RLS, so the broken reading finds what it is looking for and the file passes,
-- with orders — the real table, with no RLS — never checked at all. A gate that reads the
-- name correctly checks orders, finds no RLS, and goes red. Before the fix: green. After: red.
create table public.public (id uuid primary key);
alter table public.public enable row level security;

create table "public"."orders" (id uuid primary key);
