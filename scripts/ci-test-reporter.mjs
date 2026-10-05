// Project only Node test events. Test stdout/diagnostic text is never receipt data.
export default async function* reporter(source) {
  for await (const event of source) {
    const data = event.data;
    if (event.type === 'test:pass' || event.type === 'test:fail') {
      yield JSON.stringify({ type: event.type, file: data.file ?? null, name: data.name,
        skip: Boolean(data.skip), todo: Boolean(data.todo), nesting: data.nesting }) + '\n';
    } else if (event.type === 'test:summary') {
      yield JSON.stringify({ type: event.type, file: data.file ?? null, counts: data.counts,
        success: data.success, durationMs: data.duration_ms }) + '\n';
    }
  }
}
