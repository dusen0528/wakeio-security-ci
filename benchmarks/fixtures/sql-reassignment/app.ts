export function load(req: any, db: any) {
  let statement = "SELECT 1";
  statement = req.query.statement;
  return db.execute(statement);
}
