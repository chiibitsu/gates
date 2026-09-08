import { key } from "~/lib/secret";
export default function Page() { return <main>{key ? "y" : "n"}</main>; }
