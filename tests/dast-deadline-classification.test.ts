import test from 'node:test';
import assert from 'node:assert/strict';
import { ClientRequest, createServer } from 'node:http';
import { runDast, parseDastPolicy } from '../src/dast.js';
import { createReport, evaluateGate } from '../src/report.js';

// Owned loopback fixture only. It stalls/resets HTTP; it executes no query or target code.
async function ownedTarget(onRequest: () => void) {
  let requests = 0, closed!: () => void;
  const socketClosed = new Promise<void>(resolve => { closed = resolve; });
  const server = createServer(request => {
    requests++;
    request.socket.once('close', closed);
    onRequest();
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  const address = server.address(); assert.ok(address && typeof address !== 'string');
  const origin = `http://127.0.0.1:${address.port}`;
  return { origin, socketClosed, requests: () => requests,
    async close() { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); } };
}

const profiles = ['numeric', 'quoted', 'numeric-auth', 'quoted-auth'] as const;
function policy(origin: string, profile: typeof profiles[number]) {
  const authenticated = profile.endsWith('-auth'), quoted = profile.startsWith('quoted');
  return { version: quoted ? 3 : authenticated ? 2 : 1, kind: 'sql-boolean-differential',
    profile: quoted ? 'single-quoted' : 'numeric', baseUrl: `${origin}/`, url: `${origin}/items?id=1`, parameter: 'id',
    oracle: { jsonPointer: '/count', expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 },
    ...(authenticated ? { authorizationEnv: 'OWNED_DEADLINE_AUTH',
      identity: { path: '/identity', status: 200, jsonPointer: '/principal', equals: 'owned-principal' } } : {}) };
}

for (const profile of profiles) {
  for (const cause of ['socket-deadline', 'caller-cancelled', 'connection-reset'] as const) {
    test(`DAST ${profile}: ${cause} retains the explicit first failure before wall-clock deadline`, { timeout: 5000 }, async t => {
      const controller = new AbortController();
      let request!: ClientRequest, timeoutCallback: (() => void) | undefined, socketTimeouts = 0;
      // Drive the actual url-network request timeout callback after the owned
      // server receives the request, before the outer timer can abort. This
      // deterministically represents transport/global deadline timer ordering.
      const timeout = t.mock.method(ClientRequest.prototype, 'setTimeout', function(this: ClientRequest, _ms: number, callback?: () => void) {
        request = this; timeoutCallback = callback; return this;
      });
      const owned = await ownedTarget(() => {
        if (cause === 'connection-reset') { request.destroy(new Error('owned connection reset')); return; }
        if (cause === 'caller-cancelled') controller.abort();
        assert.ok(timeoutCallback);
        socketTimeouts++;
        timeoutCallback.call(request);
      });
      const now = Date.now(), clock = t.mock.method(Date, 'now', () => now);
      try {
        const [check] = await runDast({ policy: parseDastPolicy(policy(owned.origin, profile)).policy, consent: true, allowPrivate: true,
          timeoutMs: 1000, signal: controller.signal, env: { OWNED_DEADLINE_AUTH: 'Bearer owned-deadline-fixture' } });
        assert.ok(check); assert.equal(check.status, 'partial'); assert.equal(check.findings.length, 0);
        const execution = check.dastExecution; assert.ok(execution);
        const expected = cause === 'socket-deadline' ? 'deadline' : cause === 'caller-cancelled' ? 'cancelled' : 'transport_error';
        assert.equal(execution.stopReason, expected);
        assert.equal(execution.steps[0]?.reason, expected);
        assert.equal(execution.steps[0]?.outcome, 'inconclusive');
        assert.equal(execution.counts.httpAttempts, 1);
        assert.equal(execution.counts.evaluated, 0);
        assert.equal(execution.counts.notAttempted, execution.steps.length - 1);
        assert.ok(execution.steps.slice(1).every(step => step.outcome === 'not_attempted' && step.httpAttempts === 0));
        assert.equal(socketTimeouts, cause === 'connection-reset' ? 0 : 1);
        assert.equal(controller.signal.aborted, cause === 'caller-cancelled');
        assert.equal(owned.requests(), 1);
        await owned.socketClosed;
        const report = createReport([check], 'url', new Date(0));
        assert.equal(evaluateGate(report, 'none').exitCode, 2);
        assert.equal(evaluateGate(report, 'high').exitCode, 2);
      } finally { clock.mock.restore(); timeout.mock.restore(); await owned.close(); }
    });
  }
}
