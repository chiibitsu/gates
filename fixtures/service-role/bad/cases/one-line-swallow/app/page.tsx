// A string ending in the word `from`, immediately before a real import, on ONE physical line.
// This is the shape that broke the old grep extractor in both directions: reporting the
// invented span was a blocking UNKNOWN naming an import that does not exist, and dropping it
// lost the real import below and returned `ok`, exit 0, over a module reaching the secret.
//
// The tokeniser does neither — it recognises the string as a string and the import as an
// import, so this fixture asserts the VIOLATION, not a blind spot. It lived under
// bad/unknown/ for exactly one commit, which is the record of the gate having got better:
// the honest answer moved from "I could not read this" to "here is what it reaches".
//
// cases/string-ending-in-from is this file with a newline between the two statements.
const label = "imported from "; import { admin } from "../lib/admin";

export default function Page() {
  return admin;
}
