// A misleading acknowledgement does not establish a persisted unauthorized write.
export function handle(request, view) {
  if (request.actor === view.read(request.resourceId)?.owner) view.write(request.resourceId, { title: request.title });
  return { status: 200, body: { accepted: true } };
}
