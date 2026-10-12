import { makeStatement as statementFor } from './statement.js';
export function handler(req: any) {
  return db.execute(statementFor(req.query.term));
}
