export function GET(request: any) {
  const term = request.nextUrl.searchParams.get('term');
  return db.query(`SELECT id FROM products WHERE name = '${term}'`);
}
