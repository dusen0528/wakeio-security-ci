import { redirect } from "next/navigation";
export function go(req: any) {
  redirect(req.query.next);
}
