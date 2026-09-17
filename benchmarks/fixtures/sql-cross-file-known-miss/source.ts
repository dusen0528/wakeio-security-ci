export function makeStatement(req: any) {
  return `SELECT * FROM users WHERE id = '${req.query.id}'`;
}
