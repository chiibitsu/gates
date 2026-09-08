export async function GET() {
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  return new Response(key ? "ok" : "no key");
}
