import { makeStatement } from './statement.js';
export function handler(req: any) {
  return db.query(makeStatement(req.query.term));
}
