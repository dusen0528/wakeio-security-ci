import { exec } from "node:child_process";
export function run(req: any) {
  const command = req.query.command;
  exec(command);
}
