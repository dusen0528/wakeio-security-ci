// Author-owned fixture: authenticated access is mistaken for object ownership.
export function handle(request, view) {
  if (request.actor === 2) return { status: 401, body: { denied: true } };
  view.write(request.resourceId, { title: request.title });
  return { status: 200, body: { accepted: true } };
}
