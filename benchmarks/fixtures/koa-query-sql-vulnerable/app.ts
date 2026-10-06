export async function handler(ctx: any) {
  const term = ctx.request.query.term;
  ctx.body = await db.query(`SELECT id FROM products WHERE name = '${term}'`);
}
