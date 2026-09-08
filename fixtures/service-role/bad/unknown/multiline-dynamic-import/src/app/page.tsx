export default async function Page() {
  // The specifier sits on its own line, which is what Prettier does to a long import().
  // A line-at-a-time scan sees neither the call nor the argument as one statement.
  const mod = await import(
    process.env.MODULE_NAME ?? "./safe"
  );
  return <main>{String(mod.value)}</main>;
}
