// A hand-written declaration sits beside the implementation. Probing the declaration first
// resolved to a file that BY CONSTRUCTION cannot hold a secret, and lib/admin.js — the module
// Node actually loads — was never read. Deleting the .d.ts turned the same tree red, which is
// the sidecar doing the hiding.
import { admin } from "../lib/admin.js";

export default function Page() {
  return admin;
}
