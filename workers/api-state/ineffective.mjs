// Status-only patch still sends the stored protected data to another principal.
export function handle(req, res, view) {
  if (view.identity(req, res)) return;
  const actor = view.actor(req.headers.authorization);
  const row = view.readResource(req.url, actor);
  if (!row) return view.json(res, 404, { error: 'missing' });
  if (actor === 'anonymous') return view.json(res, 401, { error: 'denied' });
  return view.json(res, actor === row.owner ? 200 : 403, { id: row.id, canary: row.canary, title: row.title, contents: row.contents });
}
