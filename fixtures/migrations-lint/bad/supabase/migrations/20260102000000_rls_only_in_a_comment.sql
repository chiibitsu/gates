-- The rollback exists and the table is created, so ONLY the RLS rule can trip here.
create table public.accounts (id uuid primary key);
-- alter table public.accounts enable row level security;
/*
alter table public.accounts enable row level security;
*/
