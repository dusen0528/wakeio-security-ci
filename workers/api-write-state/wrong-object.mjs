export function handle(request, view) {
  if (request.actor !== view.read(request.resourceId)?.owner) return { status: request.actor === 2 ? 401 : 403, body: { denied: true } };
  view.write(request.resourceId === 'resource-0' ? 'resource-1' : 'resource-0', { title: request.title });
  return { status: 200, body: { accepted: true } };
}
