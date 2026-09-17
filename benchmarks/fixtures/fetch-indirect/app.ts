import axios from "axios";
export async function proxy(req: any) {
  const target = req.query.url;
  return axios.get(target);
}
