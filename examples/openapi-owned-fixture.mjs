// Runnable OpenAPI adapter example, confined to a newly generated own fixture.
import { buildOpenApiPolicy, runOpenApiPolicy, createReport, exitCode } from '../build/src/index.js';
import { startOwnedDastFixture } from './dast-owned-fixture.mjs';

if (process.argv.slice(2).some(arg => arg !== '--vulnerable') || process.argv.slice(2).length > 1) throw Error('Use --vulnerable or no arguments');
const fixture = await startOwnedDastFixture(process.argv.includes('--vulnerable') ? 'nested' : 'safe');
try {
  const policy = fixture.policy();
  const input = {
    document: {
      openapi: '3.0.3',
      paths: {
        '/whoami': { get: { operationId: 'identity', responses: { 200: { description: 'Synthetic principal' } } } },
        '/records/{id}': {
          get: {
            operationId: 'readOwnedRecord',
            parameters: [{ name: 'id', in: 'path', required: true, schema: { $ref: '#/components/schemas/FixtureId' } }],
            responses: { 200: { description: 'Synthetic owner control' }, 403: { description: 'Synthetic denial control' } },
          },
        },
      },
      components: { schemas: { FixtureId: { type: 'string' } } },
    },
    baseUrl: fixture.baseUrl,
    actors: policy.actors,
    operations: [
      { id: 'identity', method: 'GET', path: '/whoami', operationId: 'identity' },
      ...policy.cases.map(c => ({ id: c.id, method: 'GET', path: '/records/{id}', operationId: 'readOwnedRecord', pathParameters: { id: c.allow.resource.equals } })),
    ],
    cases: policy.cases.map(c => ({ id: c.id, operation: c.id, allow: c.allow, deny: c.deny })),
  };
  // Pure compilation is also exposed for review before making any requests.
  const compiled = buildOpenApiPolicy(input);
  const startedAt = new Date();
  const checks = await runOpenApiPolicy({ input, env: fixture.env, allowPrivate: true, timeoutMs: 5000 });
  const report = createReport(checks, 'api', startedAt);
  process.stdout.write(JSON.stringify({ scope: 'generated-owned-loopback-openapi-get', cases: compiled.cases.length, status: checks[0].status, findings: checks[0].findings.length, requests: checks[0].metrics.requestCount, elapsedMs: checks[0].metrics.elapsedMs }) + '\n');
  process.exitCode = exitCode(report, 'high');
} finally { await fixture.close(); }
