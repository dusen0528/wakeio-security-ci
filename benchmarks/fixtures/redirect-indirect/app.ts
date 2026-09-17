import { permanentRedirect } from "next/navigation";
export function go(req: any) {
  let destination = "/home";
  destination = req.query.next;
  permanentRedirect(destination);
}
