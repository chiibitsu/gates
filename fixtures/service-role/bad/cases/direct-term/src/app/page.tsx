export default function Page() {
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  return <main>{key ? "y" : "n"}</main>;
}
