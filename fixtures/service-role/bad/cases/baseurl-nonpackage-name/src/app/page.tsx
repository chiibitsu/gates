// An underscore-prefixed private folder is an ordinary Next.js convention, and a leading
// underscore is not a valid npm package name. The baseUrl probe was gated on the specifier
// LOOKING like a package, so it skipped exactly the names most likely to be baseUrl-relative:
// this file resolves under baseUrl and was reported UNKNOWN anyway — a red on a tree the gate
// could read perfectly well, and one that hides the violation underneath it.
import { admin } from "_components/Button";

export default function Page() {
  return admin;
}
