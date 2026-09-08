-- PostgreSQL folds an unquoted identifier to lower case and keeps a quoted one exactly, so
-- "Orders" and orders are two different tables. The extractor lowercased both and the RLS
-- search was case-insensitive, so RLS on one satisfied a create of the other — a false green.
-- The quoted PascalCase form is what Prisma and Drizzle emit, so this is not a contrivance.
create table public."Orders" (id uuid primary key, owner uuid);

create table public.orders (id uuid primary key, owner uuid);
alter table public.orders enable row level security;
