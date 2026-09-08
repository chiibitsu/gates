// `grep -o` matches non-overlapping, so a string ending in `from "` swallows the import that
// follows it. With both statements on ONE line, both extractor passes see the same span and
// there is no unswallowed copy to fall back on. That span must still be REPORTED: a wide
// artefact filter dropped it silently and the module below was never walked — a false green
// made by the filter that was removing a false red. This is the sibling of
// cases/string-ending-in-from, which is this file with a newline between the statements.
const label = "imported from "; import { admin } from "../lib/admin";

export default function Page() {
  return admin;
}
