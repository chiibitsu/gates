-- A same-line block comment must not swallow the statement after it. `widgets` is created
-- here and never gets RLS, so this file must trip the gate. `gadgets` is created and DOES
-- get RLS on a line following a closed block comment, so a stripper that over-deletes
-- would report it too — and that extra violation is the regression signal.
/* note */ create table public.widgets (id uuid primary key);
/* note */ create table public.gadgets (id uuid primary key);
/* note */ alter table public.gadgets enable row level security;
