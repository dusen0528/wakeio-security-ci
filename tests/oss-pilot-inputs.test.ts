import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { parseExecutionInputs, parseExecutionPlan } from '../src/agent-dast/plan.js';
import { selectOpenApiLiveOperations } from '../src/openapi.js';

const directory = fileURLToPath(new URL('../../examples/oss-pilot/juice-shop/', import.meta.url));
const validatorUrl = new URL('../../examples/oss-pilot/juice-shop/validate-inputs.mjs', import.meta.url);
const { validatePilotInputs } = await import(validatorUrl.href) as {
  validatePilotInputs: (directory?: string) => {
    inputsValidated: true; execution: 'blocked'; archiveVerification: 'release-metadata-only';
    downloadedBytesVerified: false; runtimeApproved: false; message: string;
  };
};
const files = ['manifest.json', 'inventory.json', 'inputs.json', 'run-plan.template.json', 'schema-normal.json', 'schema-error.json'];
const SEARCH = '/rest/products/search';
type JsonObject = Record<string, any>;
async function json(root: string, name: string): Promise<JsonObject> {
  return JSON.parse(await readFile(join(root, name), 'utf8')) as JsonObject;
}
async function edit(root: string, name: string, change: (value: JsonObject) => void): Promise<void> {
  const value = await json(root, name);
  change(value);
  await writeFile(join(root, name), `${JSON.stringify(value, null, 2)}\n`);
}
async function fixture(run: (root: string) => Promise<void>): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-oss-pilot-inputs-'));
  try {
    await Promise.all(files.map(name => copyFile(join(directory, name), join(root, name))));
    await run(root);
  } finally { await rm(root, { recursive: true, force: true }); }
}
async function rehash(root: string, name: string): Promise<void> {
  const digest = createHash('sha256').update(await readFile(join(root, name))).digest('hex');
  await edit(root, 'inputs.json', value => { value.inputs.find((input: JsonObject) => input.path === name).sha256 = digest; });
}

test('OSS pilot: read-only validator accepts fixture consistency while keeping execution blocked', async () => {
  const before = await Promise.all(files.map(name => readFile(join(directory, name))));
  const result = validatePilotInputs();
  assert.equal(result.inputsValidated, true);
  assert.equal(result.execution, 'blocked');
  assert.equal(result.archiveVerification, 'release-metadata-only');
  assert.equal(result.downloadedBytesVerified, false);
  assert.equal(result.runtimeApproved, false);
  assert.match(result.message, /no execution is authorized/);
  assert.ok(Object.isFrozen(result));
  const cli = spawnSync(process.execPath, [fileURLToPath(validatorUrl)], { encoding: 'utf8', timeout: 5000 });
  assert.equal(cli.status, 0, cli.stderr);
  assert.deepEqual(JSON.parse(cli.stdout), result);
  const after = await Promise.all(files.map(name => readFile(join(directory, name))));
  assert.deepEqual(after, before);
});

test('OSS pilot: CLI needs only fixture read access and rejects approval arguments or invalid inputs', async () => {
  const permission = process.allowedNodeEnvironmentFlags.has('--permission') ? '--permission' : '--experimental-permission';
  const cli = spawnSync(process.execPath, [permission, `--allow-fs-read=${directory}`,
    fileURLToPath(validatorUrl)], { encoding: 'utf8', timeout: 5000 });
  assert.equal(cli.status, 0, cli.stderr);
  assert.equal(JSON.parse(cli.stdout).execution, 'blocked');
  const argument = spawnSync(process.execPath, [fileURLToPath(validatorUrl), '--approve'], { encoding: 'utf8', timeout: 5000 });
  assert.equal(argument.status, 1);
  assert.equal(JSON.parse(argument.stderr).execution, 'blocked');
  await fixture(async root => {
    const script = join(root, 'validate-inputs.mjs');
    await copyFile(fileURLToPath(validatorUrl), script);
    await writeFile(join(root, 'manifest.json'), '{');
    const invalid = spawnSync(process.execPath, [script], { encoding: 'utf8', timeout: 5000 });
    assert.equal(invalid.status, 1);
    assert.deepEqual(JSON.parse(invalid.stderr), {
      inputsValidated: false, execution: 'blocked', message: 'Pilot input validation failed; execution remains blocked.',
    });
    assert.equal(invalid.stdout, '');
  });
});

test('OSS pilot: null-origin template stays rejected; a synthetic copy only passes existing offline parsers', async () => {
  const template = await json(directory, 'run-plan.template.json');
  assert.equal(template.origin, null);
  assert.throws(() => parseExecutionPlan(template), /invalid_execution_plan/);
  // No listener, HTTP client, target or runner is created. The synthetic origin is parser data only.
  const plan = parseExecutionPlan({ ...template, origin: 'http://127.0.0.1:3000' });
  const inputs = parseExecutionInputs(await json(directory, 'inputs.json'));
  assert.equal(template.origin, null);
  assert.equal(plan.tasks.length, 2);
  assert.equal(plan.tasks.reduce((sum, task) => sum + task.maxRequests, 0), 16);
  const expected = [
    { alias: 'search_normal', operationId: 'pilotSearchNormal', value: 'nomatcheswhatsoever' },
    { alias: 'search_error', operationId: 'pilotSearchError', value: "';" },
  ];
  for (const [index, task] of plan.tasks.entries()) {
    assert.equal(task.engine, 'schemathesis');
    if (task.engine !== 'schemathesis') assert.fail('Expected a reviewed schemathesis task');
    assert.equal(task.schema, expected[index].alias);
    assert.equal(task.seed, 1);
    assert.equal(task.maxRequests, 8);
    const input = inputs.inputs.find(input => input.id === task.schema);
    assert.ok(input);
    const bytes = await readFile(join(directory, input.path));
    assert.equal(createHash('sha256').update(bytes).digest('hex'), input.sha256);
    const schema = JSON.parse(bytes.toString('utf8'));
    const selected = selectOpenApiLiveOperations(schema, task.operations.map(path => ({ method: 'GET', path })));
    assert.deepEqual(selected.operations, [{ method: 'GET', path: SEARCH }]);
    assert.equal(schema.paths[SEARCH].get.operationId, expected[index].operationId);
    assert.deepEqual(schema.paths[SEARCH].get.parameters, [{ name: 'q', in: 'query', required: true,
      schema: { type: 'string', enum: [expected[index].value] } }]);
  }
});

test('OSS pilot: missing source pin, changed archive digest and verification overclaims are rejected', async () => {
  const mutations: Array<(value: JsonObject) => void> = [
    value => { delete value.source.commit; },
    value => { value.source.commit = '0'.repeat(40); },
    value => { value.archive.sha256 = '0'.repeat(64); },
    value => { value.archive.verification = 'bytes-verified'; },
    value => { value.archive.downloadedBytesVerified = true; },
    value => { value.upstreamSpec.used = true; },
    value => { value.evidence.scanExecuted = true; },
  ];
  for (const mutation of mutations) await fixture(async root => {
    await edit(root, 'manifest.json', mutation);
    assert.throws(() => validatePilotInputs(root), /invalid_pilot_inputs/);
  });
});

test('OSS pilot: runtime fake pins, approval and any configured origin remain rejected', async () => {
  const mutations: Array<(value: JsonObject) => void> = [
    value => { value.runtime.exactVersion = '22.0.0'; },
    value => { value.runtime.sha256 = 'a'.repeat(64); },
    value => { value.runtime.approval = 'approved'; },
    value => { value.execution.status = 'approved'; },
    value => { value.execution.origin = 'http://127.0.0.1:3000'; },
  ];
  for (const mutation of mutations) await fixture(async root => {
    await edit(root, 'manifest.json', mutation);
    assert.throws(() => validatePilotInputs(root), /invalid_pilot_inputs/);
  });
  await fixture(async root => {
    await edit(root, 'run-plan.template.json', value => { value.origin = 'http://127.0.0.1:3000'; });
    assert.throws(() => validatePilotInputs(root), /blocked_plan/);
  });
});

test('OSS pilot: raw bytes rather than reserialized JSON bind the schema inputs', async () => {
  await fixture(async root => {
    const bytes = await readFile(join(root, 'schema-normal.json'));
    await writeFile(join(root, 'schema-normal.json'), Buffer.concat([bytes, Buffer.from('\n')]));
    assert.throws(() => validatePilotInputs(root), /raw_schema_digest/);
    await rehash(root, 'schema-normal.json');
    assert.equal(validatePilotInputs(root).execution, 'blocked');
  });
  await fixture(async root => {
    await edit(root, 'inputs.json', value => { value.inputs[0].sha256 = '0'.repeat(64); });
    assert.throws(() => validatePilotInputs(root), /raw_schema_digest/);
  });
});

test('OSS pilot: owner-authored labels are required in every applicable fixture', async () => {
  for (const [name, mutate] of [
    ['manifest.json', (value: JsonObject) => { value.inputsSource = 'upstream'; }],
    ['inventory.json', (value: JsonObject) => { value.inputSource = 'discovered'; }],
    ['inventory.json', (value: JsonObject) => { value.endpoints[1].inputSource = 'upstream'; }],
    ['schema-normal.json', (value: JsonObject) => { value['x-wakeio-input-source'] = 'upstream'; }],
    ['schema-error.json', (value: JsonObject) => { delete value['x-wakeio-input-source']; }],
  ] as const) await fixture(async root => {
    await edit(root, name, mutate);
    if (name.startsWith('schema-')) await rehash(root, name);
    assert.throws(() => validatePilotInputs(root), /invalid_pilot_inputs/);
  });
});

test('OSS pilot: operation and alias mismatch, input path traversal and plan extensions are denied', async () => {
  const mutations: Array<[string, (value: JsonObject) => void]> = [
    ['run-plan.template.json', value => { value.tasks[0].operations = ['/rest/admin/application-version']; }],
    ['run-plan.template.json', value => { value.tasks[0].schema = 'search_error'; }],
    ['run-plan.template.json', value => { value.tasks[0].authPolicy = 'unexpected'; }],
    ['run-plan.template.json', value => { value.manifest = 'manifest.json'; }],
    ['inputs.json', value => { value.inputs[0].id = 'wrong_alias'; }],
    ['inputs.json', value => { value.inputs[0].path = '../schema-normal.json'; }],
    ['schema-normal.json', value => { value.paths[SEARCH].get.operationId = 'wrongOperation'; }],
  ];
  for (const [name, mutate] of mutations) await fixture(async root => {
    await edit(root, name, mutate);
    if (name.startsWith('schema-')) await rehash(root, name);
    assert.throws(() => validatePilotInputs(root), /invalid_pilot_inputs/);
  });
});

test('OSS pilot: POST, extra paths, servers, references, authentication and bodies cannot expand the scan', async () => {
  const mutations: Array<(value: JsonObject) => void> = [
    value => { value.paths[SEARCH].post = value.paths[SEARCH].get; },
    value => { value.paths['/extra'] = value.paths[SEARCH]; },
    value => { value.servers = [{ url: 'https://unapproved.invalid' }]; },
    value => { value.paths[SEARCH].servers = [{ url: 'https://unapproved.invalid' }]; },
    value => { value.paths[SEARCH].get.servers = [{ url: 'https://unapproved.invalid' }]; },
    value => { value.paths[SEARCH].get.parameters[0].schema.$ref = 'https://unapproved.invalid/schema'; },
    value => { value.security = [{ bearer: [] }]; },
    value => { value.components = { securitySchemes: { bearer: { type: 'http', scheme: 'bearer' } } }; },
    value => { value.paths[SEARCH].get.security = [{ bearer: [] }]; },
    value => { value.paths[SEARCH].get.requestBody = { content: {} }; },
    value => { value.paths[SEARCH].get.parameters.push({ name: 'other', in: 'query', schema: { type: 'string' } }); },
    value => { value.paths[SEARCH].get.parameters[0].required = false; },
    value => { value.paths[SEARCH].get.parameters[0].schema.enum.push('additional'); },
    value => { value.paths[SEARCH].get.parameters[0].schema.enum = ["';"]; },
  ];
  for (const mutation of mutations) await fixture(async root => {
    await edit(root, 'schema-normal.json', mutation);
    await rehash(root, 'schema-normal.json');
    assert.throws(() => validatePilotInputs(root), /schema_normal/);
  });
  const schema = await json(directory, 'schema-normal.json');
  assert.throws(() => selectOpenApiLiveOperations(schema, [{ method: 'POST', path: SEARCH }]));
  assert.throws(() => selectOpenApiLiveOperations(schema, [{ method: 'GET', path: '/extra' }]));
});

test('OSS pilot: endpoint purposes and exact task, global and readiness budgets stay bounded', async () => {
  const mutations: Array<[string, (value: JsonObject) => void]> = [
    ['inventory.json', value => { value.endpoints.push(value.endpoints[1]); }],
    ['inventory.json', value => { value.endpoints[0].purpose = 'scan'; }],
    ['inventory.json', value => { value.endpoints[1].method = 'POST'; }],
    ['run-plan.template.json', value => { value.tasks.push(value.tasks[0]); }],
    ['run-plan.template.json', value => { value.tasks[0].maxRequests = 9; }],
    ['run-plan.template.json', value => { value.tasks[0].seed = 2; }],
    ...Object.entries({ maxRequests: 17, timeoutMs: 120001, ratePerSecond: 3, concurrency: 2, failOn: 'high', allowPrivate: false })
      .map(([key, replacement]): [string, (value: JsonObject) => void] =>
        ['manifest.json', value => { value.ownerOptions[key] = replacement; }]),
    ['manifest.json', value => { value.readinessBudget.maxRequests = 13; }],
    ['manifest.json', value => { value.readinessBudget.countedSeparatelyFromScan = false; }],
  ];
  for (const [name, mutate] of mutations) await fixture(async root => {
    await edit(root, name, mutate);
    assert.throws(() => validatePilotInputs(root), /invalid_pilot_inputs/);
  });
});
