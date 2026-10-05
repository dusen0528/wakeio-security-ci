// Actual owner predicate patch, with normal protected fields preserved.
export function handle(req, res, view) {
  if (view.identity(req, res)) return;
  const actor = view.actor(req.headers.authorization);
  const row = view.readResource(req.url, actor);
  if (!row) return view.json(res, 404, { error: 'missing' });
  if (actor !== row.owner) return view.json(res, actor === 'anonymous' ? 401 : 403, { error: 'denied' });
  return view.json(res, 200, { id: row.id, canary: row.canary, title: row.title, contents: row.contents });
}
