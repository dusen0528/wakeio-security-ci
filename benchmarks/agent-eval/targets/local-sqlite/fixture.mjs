import { createServer } from 'node:http';
import { DatabaseSync } from 'node:sqlite';

// The existing native-dast-sqlite fixture has only one switchable endpoint. Separate sites keep final/tuning and negative labels unambiguous.
export async function startFixture({ activeConsent = false } = {}) {
  if (!activeConsent) throw Error('active_consent_required');
  const db = new DatabaseSync(':memory:');
  db.exec('CREATE TABLE items (id INTEGER PRIMARY KEY, label TEXT NOT NULL)');
  const requests = [];
  const reset = () => { db.exec("DELETE FROM items; INSERT INTO items VALUES (1, 'synthetic')"); requests.length = 0; };
  reset();
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    requests.push({ method: req.method, path: url.pathname });
    res.setHeader('content-type', 'application/json');
    if (req.method !== 'GET' || !['/items','/lookup','/catalog','/inventory'].includes(url.pathname)) { res.writeHead(404); res.end('{}'); return; }
    const id = url.searchParams.get('id');
    try {
      const row = ['/items','/catalog'].includes(url.pathname)
        ? db.prepare(`SELECT COUNT(*) AS count FROM items WHERE id = ${id}`).get()
        : db.prepare('SELECT COUNT(*) AS count FROM items WHERE id = ?').get(id);
      res.end(JSON.stringify(row));
    } catch { res.writeHead(400); res.end('{"error":"invalid query"}'); }
  });
  try { await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject)); }
  catch (error) { db.close(); throw error; }
  let closed = false;
  return { origin: `http://127.0.0.1:${server.address().port}`, requests, reset,
    async close() { if (closed) return; closed = true; server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); db.close(); },
  };
}
