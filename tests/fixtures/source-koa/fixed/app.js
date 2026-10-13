import Application from 'koa';
const app = new Application();
app.use(async (incoming, continuation) => {
  const term = incoming.request.query.ownedKoaQueryMarker;
  db.query('SELECT id FROM products WHERE name = $1', [term]);
  await fetch('https://owned.invalid/resource');
  JSON.parse(term);
});
