export default function handler(_req, res) {
  res.status(200).json({ hasKey: Boolean(process.env.SUPABASE_SERVICE_ROLE_KEY) });
}
