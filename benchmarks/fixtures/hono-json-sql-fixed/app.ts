import { Hono } from 'hono';
import { Pool } from 'pg';
const app = new Hono();
const db = new Pool();
app.post('/search', async (context) => {
  const payload = await context.req.json();
  const term = payload.term;
  return db.query('SELECT id FROM items WHERE name = $1', [term]);
});
export default app;
