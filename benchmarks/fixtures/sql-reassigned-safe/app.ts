export function load(req: any, db: any) {
  let statement = req.query.sql;
  statement = "SELECT 1";
  return db.query(statement);
}
