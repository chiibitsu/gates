-- `if` and `exists` are non-reserved in PostgreSQL and are legal table names — the create
-- side already knew that. The ALTER side swallowed them wherever they appeared, so it bound
-- `enable` as the table name here, emitted no RLS record, and reported a violation on a file
-- that enables RLS correctly. The planted violation is `orders`, which genuinely has none;
-- the point of the file is that `if` must NOT also be reported.
create table if (id int);
alter table if enable row level security;

create table public.orders (id int);
