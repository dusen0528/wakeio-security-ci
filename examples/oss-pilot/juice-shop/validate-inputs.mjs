#!/usr/bin/env node
/** Offline fixture consistency only. This is not an execution approval or launcher. */
import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const DIRECTORY = fileURLToPath(new URL('.', import.meta.url));
const COMMIT = 'f189f521266f42c6bd05884468292000cee852ed';
const ARCHIVE_SHA256 = '6148dcce8fe7d990a86bf8457a0e9a07821c127d498c76da1a3bc7dba12a77e5';
const REPOSITORY = 'https://github.com/juice-shop/juice-shop';
const SOURCE = `${REPOSITORY}/blob/${COMMIT}`;
const SEARCH = '/rest/products/search';
const CASES = [
  { alias: 'search_normal', file: 'schema-normal.json', name: 'normal', operationId: 'pilotSearchNormal', value: 'nomatcheswhatsoever' },
  { alias: 'search_error', file: 'schema-error.json', name: 'error', operationId: 'pilotSearchError', value: "';" },
];

function check(condition, location) {
  if (!condition) throw new Error(`invalid_pilot_inputs: ${location}`);
}
function equal(actual, expected, location) { check(isDeepStrictEqual(actual, expected), location); }
function keys(value, expected, location) {
  check(value !== null && typeof value === 'object' && !Array.isArray(value), location);
  equal(Object.keys(value).sort(), [...expected].sort(), location);
}
function read(directory, name) {
  // Only these fixed local files are read; aliases, URLs and schema references are never opened.
  const path = resolve(directory, name);
  const stat = lstatSync(path);
  check(stat.isFile() && stat.size <= 64 * 1024, name);
  const bytes = readFileSync(path);
  check(bytes.length <= 64 * 1024, name);
  let value;
  try { value = JSON.parse(bytes.toString('utf8')); }
  catch { throw new Error(`invalid_pilot_inputs: ${name}`); }
  return { bytes, value };
}

function expectedSchema(item) {
  return {
    openapi: '3.0.3',
    info: {
      title: `Owner-authored Juice Shop bounded search ${item.name}`,
      version: '20.3.0',
      description: 'Pilot input derived from pinned public route behavior; not the upstream OpenAPI specification',
    },
    'x-wakeio-input-source': 'owner-authored',
    paths: { [SEARCH]: { get: {
      operationId: item.operationId,
      parameters: [{ name: 'q', in: 'query', required: true, schema: { type: 'string', enum: [item.value] } }],
      responses: { '200': {
        description: 'Normal search response; a 500 is an observed server error',
        content: { 'application/json': { schema: {
          type: 'object', required: ['status', 'data'],
          properties: { status: { type: 'string', enum: ['success'] }, data: { type: 'array', items: { type: 'object' } } },
        } } },
      } },
    } } },
  };
}

/** Read-only and deliberately specific to the reviewed, unapproved Juice Shop template. */
export function validatePilotInputs(directory = DIRECTORY) {
  const manifest = read(directory, 'manifest.json').value;
  keys(manifest, ['version', 'kind', 'project', 'release', 'source', 'archive', 'runtime', 'execution',
    'inputsSource', 'upstreamSpec', 'ownerOptions', 'readinessBudget', 'evidence'], 'manifest');
  equal([manifest.version, manifest.kind, manifest.project, manifest.release, manifest.inputsSource],
    [1, 'wakeio.oss-pilot-inputs', 'OWASP Juice Shop', '20.3.0', 'owner-authored'], 'manifest_identity');
  equal(manifest.source, {
    repository: REPOSITORY, tag: 'v20.3.0', commit: COMMIT, license: 'MIT', licenseUrl: `${SOURCE}/LICENSE`,
  }, 'source_pin');
  equal(manifest.archive, {
    name: 'juice-shop-20.3.0_node22_linux_x64.tgz',
    url: `${REPOSITORY}/releases/download/v20.3.0/juice-shop-20.3.0_node22_linux_x64.tgz`,
    sha256: ARCHIVE_SHA256,
    digestSource: 'https://api.github.com/repos/juice-shop/juice-shop/releases/tags/v20.3.0',
    verification: 'release-metadata-only', downloadedBytesVerified: false,
  }, 'archive_metadata');
  equal(manifest.runtime, {
    platform: 'linux', architecture: 'x64', nodeMajor: 22, exactVersion: null, sha256: null, approval: 'pending',
  }, 'runtime_unapproved');
  keys(manifest.execution, ['status', 'origin', 'reason'], 'execution');
  equal([manifest.execution.status, manifest.execution.origin], ['blocked', null], 'execution_blocked');
  check(typeof manifest.execution.reason === 'string' && manifest.execution.reason.length > 0, 'execution_reason');
  keys(manifest.upstreamSpec, ['url', 'used', 'reason'], 'upstream_spec');
  equal([manifest.upstreamSpec.url, manifest.upstreamSpec.used], [`${SOURCE}/swagger.yml`, false], 'upstream_spec_unused');
  check(typeof manifest.upstreamSpec.reason === 'string' && manifest.upstreamSpec.reason.length > 0, 'upstream_spec_reason');
  equal(manifest.ownerOptions, {
    maxRequests: 16, timeoutMs: 120000, ratePerSecond: 2, concurrency: 1, allowPrivate: true, failOn: 'medium',
  }, 'owner_options');
  equal(manifest.readinessBudget, { maxRequests: 12, timeoutMs: 60000, countedSeparatelyFromScan: true }, 'readiness_budget');
  equal(manifest.evidence, {
    targetExecuted: false, scanExecuted: false, rerunExecuted: false,
    classification: 'server-error observation; not SQL injection confirmation or data extraction',
  }, 'evidence');

  equal(read(directory, 'inventory.json').value, {
    version: 1, kind: 'wakeio.oss-pilot-inventory', inputSource: 'owner-authored', sourceCommit: COMMIT,
    discoveryStatus: 'not-run', coverage: "Reviewed subset only; not the application's complete API inventory",
    endpoints: [
      { method: 'GET', path: '/rest/admin/application-version', purpose: 'readiness-only', authentication: 'anonymous', source: `${SOURCE}/server.ts` },
      { method: 'GET', path: SEARCH, purpose: 'scan', authentication: 'anonymous', parameter: 'q', inputSource: 'owner-authored',
        sources: [`${SOURCE}/server.ts`, `${SOURCE}/routes/search.ts`, `${SOURCE}/test/api/search.test.ts`] },
    ],
  }, 'reviewed_inventory');
  equal(read(directory, 'run-plan.template.json').value, {
    version: 1, kind: 'wakeio.execution-plan', origin: null,
    tasks: CASES.map(item => ({ id: `t-search-${item.name}`, engine: 'schemathesis', schema: item.alias,
      operations: [SEARCH], seed: 1, maxRequests: 8 })),
  }, 'blocked_plan');

  const inputs = read(directory, 'inputs.json').value;
  keys(inputs, ['version', 'inputs'], 'inputs');
  equal(inputs.version, 1, 'inputs_version');
  check(Array.isArray(inputs.inputs) && inputs.inputs.length === CASES.length, 'inputs_count');
  for (const [index, item] of CASES.entries()) {
    const input = inputs.inputs[index];
    keys(input, ['id', 'path', 'sha256'], 'input_keys');
    equal([input.id, input.path], [item.alias, item.file], 'input_alias');
    check(typeof input.sha256 === 'string' && /^[a-f0-9]{64}$/.test(input.sha256), 'input_digest');
    const schema = read(directory, item.file);
    equal(createHash('sha256').update(schema.bytes).digest('hex'), input.sha256, 'raw_schema_digest');
    // Exact reviewed shape rejects POST, added paths, servers, references, authentication and bodies.
    equal(schema.value, expectedSchema(item), `schema_${item.name}`);
  }
  return Object.freeze({
    inputsValidated: true, execution: 'blocked', archiveVerification: 'release-metadata-only',
    downloadedBytesVerified: false, runtimeApproved: false,
    message: 'Inputs validated; execution remains blocked. No archive bytes, runtime or target were verified; no execution is authorized.',
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    check(process.argv.length === 2, 'arguments');
    console.log(JSON.stringify(validatePilotInputs(), null, 2));
  } catch {
    console.error(JSON.stringify({ inputsValidated: false, execution: 'blocked', message: 'Pilot input validation failed; execution remains blocked.' }));
    process.exitCode = 1;
  }
}
