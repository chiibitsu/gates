-- Rollback for the up migration beside this file. It exists so the down-file rule is
-- satisfied and ONLY the RLS rule can trip the fixture — and it does real work, because a
-- rollback file that exists and rolls nothing back is the same false comfort this toolkit
-- refuses everywhere else.
drop table if exists public.accounts;
