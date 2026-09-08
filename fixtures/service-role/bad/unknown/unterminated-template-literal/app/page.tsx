// A stray backtick in JSX text. It is not a template literal, but nothing short of a JSX
// parser can tell — so the scan opens one and runs to the end of the file, and every import
// below it is read as template-literal text. Before the sync-loss guard this file reported
// ok, exit 0, over a module that reaches the secret through the require() below.
export function Hint() {
  return <p>Press the ` key to continue</p>;
}

const { admin } = require("../lib/admin");

export default function Page() {
  return admin;
}
