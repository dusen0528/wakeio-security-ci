class Repository {
  search(term: string) {
    return db.query('SELECT id FROM products WHERE name = $1', [term]);
  }
}
const repository = new Repository();
export function handler(req: any, res: any) {
  return repository.search(req.query.term);
}
