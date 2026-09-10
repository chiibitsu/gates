-- RLS ON A DIFFERENT SCHEMA'S SAME-NAMED TABLE. The create side discarded the schema
-- qualifier after reading it, so the check asked only "does SOME table called orders, in SOME
-- schema, have RLS?" while the message named one specific table. Both statements below are
-- accepted by PostgreSQL and the resulting state really does leave public.orders unprotected.
-- Two schemas holding a same-named table is an ordinary layout, not a contrivance.
create table public.orders (id uuid primary key, owner uuid);

create table archive.orders (id uuid primary key, owner uuid);
alter table archive.orders enable row level security;
