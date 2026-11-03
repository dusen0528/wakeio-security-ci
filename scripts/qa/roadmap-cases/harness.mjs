import { createServer, get } from 'node:http';
import { createServer as createPortProbe } from 'node:net';
import { once } from 'node:events';
import { captureProcess } from './process.mjs';
import { writeArtifact } from './artifacts.mjs';

const cliBody = '{"surface":"node-cli","value":42}\n';
const httpBody = '{"surface":"loopback-http","value":42}\n';

async function requestHttp(port, signal) {
  return await new Promise((resolve, reject) => {
    const request = get({ host: '127.0.0.1', port, path: '/', agent: false, signal }, response => {
      const chunks = [];
      let bytes = 0;
      response.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > 65536) response.destroy(new RangeError('http_output_limit'));
        else chunks.push(chunk);
      });
      response.once('error', reject);
      response.once('end', () => resolve({ status: response.statusCode, headers: response.headers,
        body: Buffer.concat(chunks).toString('utf8'), complete: response.complete }));
    });
    request.once('error', reject);
  });
}

async function portReleased(port) {
  if (port === null) return true;
  const probe = createPortProbe();
  const listening = once(probe, 'listening', { signal: AbortSignal.timeout(2000) });
  try {
    probe.listen(port, '127.0.0.1');
    await listening;
    const closed = once(probe, 'close');
    probe.close();
    await closed;
    return true;
  } catch (error) {
    probe.close();
    if (!(error instanceof Error)) throw error;
    return false;
  }
}

export async function runCase({ out, mutate }) {
  const mutations = [undefined, 'child-abort', 'truncated-output', 'output-limit',
    'child-fail', 'handler-error', 'long-child', 'incomplete-cleanup'];
  if (!mutations.includes(mutate)) {
    const cleanup = { confirmed: true, children: [], port: null, portReleased: true };
    await writeArtifact(out, 'cleanup.json', cleanup);
    return { status: 'unavailable', artifacts: ['cleanup.json'], cleanup };
  }
  const controller = new AbortController();
  const interrupt = () => controller.abort();
  // Install cancellation before creating any resource.
  process.on('SIGINT', interrupt); process.on('SIGTERM', interrupt);
  const deadline = setTimeout(interrupt, 10000);
  const server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json', 'x-qa-surface': 'real-http' });
    response.end(httpBody);
  });
  let port = null, child = null, http = null, status = 'unavailable', failure = null;
  let serverClosed = false;
  const artifacts = [];
  try {
    const listening = once(server, 'listening', { signal: controller.signal });
    server.listen(0, '127.0.0.1');
    await listening;
    const address = server.address();
    if (address === null || typeof address === 'string') throw new TypeError('invalid_loopback_address');
    port = address.port;
    // HTTP runs against a real ephemeral socket, never a supplied response object.
    http = await requestHttp(port, controller.signal);
    artifacts.push(await writeArtifact(out, 'http.json', { request: { method: 'GET', host: '127.0.0.1', port, path: '/' }, ...http }));
    process.stdout.write(JSON.stringify({ event: 'case_ready', port }) + '\n');
    const script = mutate === 'child-abort' || mutate === 'handler-error' || mutate === 'long-child'
      ? 'process.stdout.write("READY\\n"); process.on("SIGTERM",()=>{}); setInterval(()=>{},1000)'
      : mutate === 'output-limit' ? 'process.stdout.write("x".repeat(100000)); setInterval(()=>{},1000)'
      : mutate === 'truncated-output' ? 'process.stdout.write("{\\"surface\\":")'
      : `process.stdout.write(${JSON.stringify(cliBody)}); process.stderr.write("password=qa-private\\n"); process.exitCode=${mutate === 'child-fail' ? 7 : 0}`;
    child = await captureProcess(process.execPath, ['-e', script], {
      signal: controller.signal, timeoutMs: mutate === 'long-child' ? 300 : 5000,
      onStdout: text => {
        if (text.includes('READY\n') && mutate === 'child-abort') controller.abort();
        if (text.includes('READY\n') && mutate === 'handler-error') throw new TypeError('qa_handler_failure');
      },
    });
    artifacts.push(await writeArtifact(out, 'cli.json', child));
    if (!child.cleanup.confirmed || child.reason || child.truncated || controller.signal.aborted) status = 'unavailable';
    else status = child.exitCode === 0 && child.stdout === cliBody && http.status === 200
      && http.complete && http.headers['content-type'] === 'application/json'
      && http.headers['x-qa-surface'] === 'real-http' && http.body === httpBody ? 'pass' : 'fail';
  } catch (error) {
    // Case boundary: preserve cleanup even when an event, handler or capture fails.
    failure = error instanceof Error ? error.name : 'non_error_exception';
    status = 'unavailable';
  } finally {
    clearTimeout(deadline);
    try {
      const closed = once(server, 'close', { signal: AbortSignal.timeout(2000) });
      server.close(); server.closeAllConnections();
      await closed;
      serverClosed = true;
    } catch (error) {
      failure ??= error instanceof Error ? error.name : 'non_error_cleanup';
    }
  }
  try {
    const released = await portReleased(port);
    const cleanup = { confirmed: serverClosed && released && (child?.cleanup.confirmed ?? true)
      && mutate !== 'incomplete-cleanup', children: child ? [child.cleanup] : [], port, portReleased: released, serverClosed };
    if (!cleanup.confirmed || controller.signal.aborted) status = 'unavailable';
    artifacts.push(await writeArtifact(out, 'cleanup.json', cleanup));
    if (failure) artifacts.push(await writeArtifact(out, 'failure.json', { reason: failure }));
    return { status, artifacts, cleanup };
  } finally {
    process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', interrupt);
  }
}
