// nodenext makes the import name the EMITTED file (.mjs) while the source is .mts.
// The gate must follow that mapping; appending extensions to "./admin.mjs" finds nothing.
import { admin } from "./admin.mjs";

export default function Page() {
  return admin;
}
