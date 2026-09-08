import { adminConfig } from "@/lib/config";
export default function Page() {
  return <main>{adminConfig.url}</main>;
}
