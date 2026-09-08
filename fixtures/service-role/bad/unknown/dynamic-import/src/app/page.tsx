export default async function Page() {
  const name = process.env.MODULE_NAME ?? "./safe";
  const mod = await import(name);
  return <main>{String(mod.value)}</main>;
}
