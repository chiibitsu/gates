// `"baseUrl": "."` is the spelling in Next.js's own Absolute Imports documentation and the
// one create-next-app ships. The first version of the baseUrl fallback armed on the VALUE
// rather than on the key being present, and "." is exactly the value it excluded — so the
// false green it was written to close stayed open on the commonest spelling, while the
// fixture beside this one used "src" and kept the selftest green over the half that worked.
import { admin } from "lib/supabase-admin";

export default function Page() {
  return admin;
}
