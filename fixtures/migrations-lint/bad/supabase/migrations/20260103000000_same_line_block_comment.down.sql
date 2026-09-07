-- Rollback for the up migration beside this file. Reverses both creations; see the note in
-- the 20260102 rollback for why it is not left empty.
drop table if exists public.gadgets;
drop table if exists public.widgets;
