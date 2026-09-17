import { redirect } from "next/navigation";
export function go() {
  const sample = "redirect(req.query.next)";
  redirect("/safe");
  return sample;
}
