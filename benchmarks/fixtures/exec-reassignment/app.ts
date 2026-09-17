import { execSync } from "node:child_process";
export function run(req: any) {
  let command = "date";
  command = req.query.command;
  execSync(command);
}
