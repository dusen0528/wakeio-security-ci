export function makeStatement(term: string) {
  return `SELECT id FROM products WHERE name = '${term}'`;
}
