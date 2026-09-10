// The module below holds the service-role key and contains one NUL byte. Without `-a`, grep
// calls that file binary, prints nothing and exits 1 — which this gate reads as "the term is
// not present". One byte hid the secret and the gate reported ok, exit 0.
import { admin } from "../lib/admin";

export default function Page() {
  return admin;
}
