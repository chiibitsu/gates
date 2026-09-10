// A slash after `}` is division here, not a regex. Treating `}` as a regex position made the
// scanner consume the rest of the line looking for a closing slash — swallowing the real
// import beside it. ok, exit 0, on a module reaching the key, where the pre-tokeniser
// extractor caught it. A block close can precede a regex, so this trades a rare false red
// for a false green, which is the trade this toolkit takes every time.
const x = {} / foo; import { admin } from "../lib/admin";

export default function Page() {
  return admin;
}
