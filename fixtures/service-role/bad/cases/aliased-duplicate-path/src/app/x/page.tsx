import { key } from "../../lib/secret";
export default function X() { return <main>{key ? "y" : "n"}</main>; }
