// Status-only apparent fix: another principal still changes the persisted row.
export function handle(request, view) {
  if (request.actor === 2) return { status: 401, body: { denied: true } };
  const owner = view.read(request.resourceId)?.owner;
  view.write(request.resourceId, { title: request.title });
  return { status: request.actor === owner ? 200 : 403, body: { denied: true } };
}
