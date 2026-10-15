export function load(req: any, db: any) {
  return db.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
}
