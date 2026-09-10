// Next.js "Absolute Imports": baseUrl alone, no paths alias anywhere. `lib/supabase-admin`
// means `src/lib/supabase-admin.ts`. The gate parsed this baseUrl — it is the base for every
// alias target — and still skipped this bare specifier as a published package. Written
// `../lib/supabase-admin`, the same file and the same secret were caught.
import { admin } from "lib/supabase-admin";

export default function Page() {
  return admin;
}
