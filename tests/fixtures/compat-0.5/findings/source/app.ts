export function load(req: any, db: any) {
  return db.query(req.query.sql);
}
