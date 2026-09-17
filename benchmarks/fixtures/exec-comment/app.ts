import { exec } from "node:child_process";
export function run() {
  // exec(req.query.command);
  exec("date");
}
