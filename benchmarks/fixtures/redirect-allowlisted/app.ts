import { redirect } from "next/navigation";
const allowed = new Set(["/home"]);
export function go(req: any) {
  if (allowed.has(req.query.next)) redirect("/home");
  else redirect("/safe");
}
