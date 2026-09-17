function executeQuery(statement: string, db: any) {
  return db.query(statement);
}

import { makeStatement } from "./source.js";

export function load(req: any, db: any) {
  return executeQuery(makeStatement(req), db);
}
