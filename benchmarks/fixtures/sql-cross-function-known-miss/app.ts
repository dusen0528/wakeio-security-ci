function executeQuery(statement: string, db: any) {
  return db.query(statement);
}

export function load(req: any, db: any) {
  const statement = `SELECT * FROM users WHERE id = '${req.query.id}'`;
  return executeQuery(statement, db);
}
