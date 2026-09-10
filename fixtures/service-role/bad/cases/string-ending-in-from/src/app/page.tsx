// The string ends in `from "`. With the whole file flattened to one line and grep -o
// matching non-overlapping, that span swallows the opening quote of the real import
// below it, and the edge to src/lib/secret.ts disappears. Caught as a regression before
// it shipped; kept here so it cannot come back.
const label = "imported from ";
import { key } from "../lib/secret";
export default function Page() {
  return <main>{label}{key ? "y" : "n"}</main>;
}
