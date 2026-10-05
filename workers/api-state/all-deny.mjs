// Rejects the attack but also breaks the legitimate owner operation.
export function handle(req, res, view) {
  if (view.identity(req, res)) return;
  view.readResource(req.url, view.actor(req.headers.authorization));
  return view.json(res, 403, { error: 'denied' });
}
