export function middleware() {
  const key = process.env.SUPABASE_SECRET_KEY;
  return new Response(key ? "y" : "n");
}
