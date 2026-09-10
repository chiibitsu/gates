-- The table name is on the line after `create table`. grep is line-scoped, so the statement
-- was not seen at all and the file passed with no RLS anywhere in it: a silent green, which
-- is the one outcome this toolkit refuses. The tokeniser reads statements, not lines.
create table
  public.orders (
    id uuid primary key,
    owner uuid
  );
