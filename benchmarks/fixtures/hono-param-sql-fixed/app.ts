import { Hono } from 'hono';
import { Pool } from 'pg';
const app = new Hono();
const db = new Pool();
app.get('/items/:id', (context) => {
  const id = context.req.param('id');
  return db.query('SELECT id FROM items WHERE id = $1', [id]);
});
export default app;
