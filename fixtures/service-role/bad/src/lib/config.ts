// Reachable from src/app/page.tsx. The request path can therefore construct a
// service-role client, which is the whole thing the gate forbids.
export const adminConfig = {
  url: process.env.SUPABASE_URL,
  key: process.env.SUPABASE_SECRET_KEY,
};
