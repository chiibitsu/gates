// "@/lib/secret" matches no alias declared above, and npm has no empty scope, so it cannot
// be a published package either. The gate must not skip it as a dependency: it does not
// know what it is, and an unread module is not a clean one.
import { key } from "@/lib/secret";

export default function Page() {
  return key;
}
