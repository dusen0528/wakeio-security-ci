export function handle(request, view) {
  if (request.actor !== view.read(request.resourceId)?.owner) return { status: request.actor === 2 ? 401 : 403, body: { denied: true } };
  view.write(request.resourceId, { contents: 'Owned unintended normal field replacement' });
  return { status: 200, body: { accepted: true } };
}
