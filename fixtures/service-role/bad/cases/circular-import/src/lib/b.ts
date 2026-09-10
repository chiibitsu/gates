// b imports a, a imports b. Before the paths were canonicalised this pair grew a longer
// spelling every hop, the visited set never matched, and the walk did not terminate.
import { a } from "./a";
export const b = a ?? process.env.SUPABASE_SECRET_KEY;
