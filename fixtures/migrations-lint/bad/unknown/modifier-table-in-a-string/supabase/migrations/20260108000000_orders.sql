-- `execute` running DDL this gate cannot follow must be UNKNOWN, and it was — until the
-- modifier allowance in that test was written as {0,2}, which mawk miscompiles to zero
-- repetitions when the group starts with a +-quantified bracket. The allowance was inert and
-- the test became exactly `create table`, so this line passed over silently. PostgreSQL 16
-- confirms it creates a persistent unlogged table with RLS off.
create table public.o (id int);
alter table public.o enable row level security;

do $x$ begin execute 'CREATE UNLOGGED TABLE public.x (id int)'; end $x$;
