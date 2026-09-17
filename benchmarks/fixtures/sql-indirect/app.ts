export function load(req: any, db: any) {
  const statement = `SELECT * FROM users WHERE id = '${req.query.id}'`;
  return db.query(statement);
}
