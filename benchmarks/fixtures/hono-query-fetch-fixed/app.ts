import { Hono } from 'hono';
const app = new Hono();
app.get('/proxy', (context) => {
  const destination = context.req.query('target');
  return fetch('https://fixed.example/owned');
});
export default app;
