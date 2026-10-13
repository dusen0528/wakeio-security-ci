import Application from 'koa';
const app = new Application();
app.use(async (incoming, continuation) => {
  const term = incoming.request.query.ownedKoaQueryMarker;
  db.query(`SELECT id FROM products WHERE name = '${term}'`);
  await fetch(term);
  eval(term);
});
