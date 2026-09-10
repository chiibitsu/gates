-- A dollar-quoted body is data, like any other string. Scanning it as SQL made the create
-- below a FAIL naming public.tmp — a table that does not exist at definition time and is
-- created only when the function runs. A red on a compliant file, naming a table nobody
-- created, which is the shape this gate refuses.
--
-- `do $$ … $$` does execute immediately, so a create inside one is real; but the gate cannot
-- see whether RLS follows it inside the body either. UNKNOWN is the honest answer for both:
-- still red, still blocking, and claiming nothing it has not established.
create function public.f() returns void language plpgsql as $$
begin
  create table public.tmp (id int);
end
$$;
