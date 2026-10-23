import { createHash } from 'node:crypto';
import { isDeepStrictEqual } from 'node:util';
import { basename, dirname, join, resolve } from 'node:path';
import { snapshotJsonData } from './json-snapshot.js';
import { readJsonInputBytes } from './json-input.js';
import { buildSurfaceInventory } from './init-dast.js';
import { OPENAPI_MAX_INPUT_BYTES, OPENAPI_MAX_LIVE_OPERATIONS, selectOpenApiLiveOperations } from './openapi.js';
import { EXECUTION_PLAN_MAX_TASKS, executionOrigin, parseExecutionInputs, parseExecutionPlan } from './agent-dast/plan.js';
import { offlineDirectory, offlineErrorCode, writeOfflineBundle } from './offline-output.js';

const PRESET = 'openapi-get-contract';
const PRESET_MAX_BYTES = 64 * 1024;
const sha = (bytes: string | Buffer) => createHash('sha256').update(bytes).digest('hex');
const json = (value: unknown) => JSON.stringify(value, null, 2) + '\n';
export const PROVENANCE_NOTICE = 'provenance는 기록만 되고 아직 실행 시 검증되지 않음';
export const PRESET_USAGE = `  wakeio-security-ci plan --preset FILE --inventory FILE --openapi LOCAL_JSON --out NEW_DIR
    [--url HTTP_ORIGIN] [--max-requests N]

Generate a six-file offline bundle for a locally running HTTP app. No request or engine execution.
GETs are sorted and split into 16 operations per task, at most 16 tasks (256 GETs).
The sum of task maxRequests must fit the owner budget (default 64, range 1..20000).
${PROVENANCE_NOTICE}. Provenance is recorded only; runtime verification is not implemented.
Exit 0: bundle generated. Exit 2: refused. Existing run-plan is unchanged.
`;

function fail(code: string): never { throw Error(code); }
function keys(value: unknown, names: string[], code: string): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) fail(code);
}
function decode(bytes: Buffer, code: string, max: number): unknown {
  if (bytes.length > max) fail('input_limit');
  let parsed: unknown;
  try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { fail(code); }
  return snapshotJsonData(parsed, () => fail(code), () => fail('input_limit'));
}
function origin(value: unknown): string {
  if (typeof value !== 'string' || /[\\?#]/.test(value)) fail('invalid_origin');
  try { return executionOrigin(value); } catch { return fail('invalid_origin'); }
}

/** Local data only. Original inputs remain byte-for-byte copies; no runtime is invoked. */
export function buildPresetBundle(presetBytes: Buffer, inventoryBytes: Buffer, openapiBytes: Buffer, url?: string, budget = 64) {
  if (!Number.isSafeInteger(budget) || budget < 1 || budget > 20000) fail('invalid_arguments');
  const inventory = decode(inventoryBytes, 'invalid_inventory', OPENAPI_MAX_INPUT_BYTES);
  keys(inventory, ['schema', 'openapiDigest', 'origin', 'scope', 'surfaces', 'unverified', 'counts'], 'invalid_inventory');
  if (inventory.schema !== 'wakeio.surface-inventory/v1' || typeof inventory.openapiDigest !== 'string'
    || !/^[a-f0-9]{64}$/.test(inventory.openapiDigest) || inventory.origin !== null && typeof inventory.origin !== 'string') fail('invalid_inventory');
  const preset = decode(presetBytes, 'invalid_preset', PRESET_MAX_BYTES);
  keys(preset, ['schema', 'id', 'operations', 'seed', 'maxRequests'], 'invalid_preset');
  if (preset.schema !== 'wakeio.plan-preset/v1' || preset.id !== PRESET
    || !Number.isSafeInteger(preset.seed) || Number(preset.seed) < 1 || Number(preset.seed) > 2147483647
    || !Number.isSafeInteger(preset.maxRequests) || Number(preset.maxRequests) < 1 || Number(preset.maxRequests) > 64) fail('invalid_preset');
  const document = decode(openapiBytes, 'invalid_openapi', OPENAPI_MAX_INPUT_BYTES);
  if (sha(openapiBytes) !== inventory.openapiDigest) fail('openapi_digest_mismatch');
  const expected = buildSurfaceInventory(openapiBytes, inventory.origin === null ? undefined : inventory.origin);
  if (!isDeepStrictEqual(inventory, snapshotJsonData(expected))) fail('inventory_mismatch');
  const selectedOrigin = inventory.origin === null ? url === undefined ? fail('origin_required') : origin(url) : origin(inventory.origin);
  if (url !== undefined && origin(url) !== selectedOrigin) fail('origin_mismatch');
  if (new URL(selectedOrigin).protocol !== 'http:') fail('preset_https_unsupported');
  if (expected.scope.openapi_get === 'partial') fail('inventory_partial');
  const available = new Set(expected.surfaces.map(surface => surface.pathTemplate));
  let operations: string[];
  if (preset.operations === 'all') operations = [...available];
  else {
    if (!Array.isArray(preset.operations) || !preset.operations.length) fail('invalid_preset');
    operations = preset.operations.map(item => {
      keys(item, ['method', 'pathTemplate'], 'invalid_preset');
      if (item.method !== 'GET' || typeof item.pathTemplate !== 'string') fail('invalid_preset');
      if (!available.has(item.pathTemplate)) fail('surface_not_in_inventory');
      return item.pathTemplate;
    });
    if (new Set(operations).size !== operations.length) fail('invalid_preset');
  }
  operations.sort();
  if (!operations.length) fail('no_operations');
  if (operations.length > EXECUTION_PLAN_MAX_TASKS * OPENAPI_MAX_LIVE_OPERATIONS) fail('operation_limit');
  const tasks = [];
  for (let index = 0; index < operations.length; index += OPENAPI_MAX_LIVE_OPERATIONS) {
    const chunk = operations.slice(index, index + OPENAPI_MAX_LIVE_OPERATIONS);
    if (Number(preset.maxRequests) < chunk.length) fail('insufficient_budget');
    tasks.push({ id: `t-openapi-get-contract-${String(tasks.length + 1).padStart(2, '0')}`, engine: 'schemathesis',
      schema: 'openapi', operations: chunk, seed: preset.seed, maxRequests: preset.maxRequests });
  }
  if (tasks.reduce((total, task) => total + Number(task.maxRequests), 0) > budget) fail('insufficient_budget');
  for (const task of tasks) selectOpenApiLiveOperations(document, task.operations.map(path => ({ method: 'GET', path })));
  const plan = parseExecutionPlan({ version: 1, kind: 'wakeio.execution-plan', origin: selectedOrigin, tasks });
  const planBytes = json(plan);
  const provenance = { schema: 'wakeio.plan-provenance/v1', planSha256: sha(planBytes), preset: { id: PRESET, sha256: sha(presetBytes) },
    inventory: { sha256: sha(inventoryBytes), openapiDigest: sha(openapiBytes) }, maxRequests: budget };
  const provenanceBytes = json(provenance);
  const inputs = parseExecutionInputs({ version: 1, inputs: [
    { id: 'inventory', path: 'inventory.json', sha256: sha(inventoryBytes) },
    { id: 'openapi', path: 'openapi.json', sha256: sha(openapiBytes) },
    { id: 'preset', path: 'preset.json', sha256: sha(presetBytes) },
    { id: 'provenance', path: 'plan-provenance.json', sha256: sha(provenanceBytes) },
  ] });
  const files: ReadonlyArray<readonly [string, string | Buffer]> = [['execution-plan.json', planBytes], ['inputs.json', json(inputs)],
    ['openapi.json', openapiBytes], ['inventory.json', inventoryBytes], ['preset.json', presetBytes], ['plan-provenance.json', provenanceBytes]];
  return { plan, inputs, provenance, files };
}

export async function presetPlanMain(argv: readonly string[]): Promise<number> {
  try {
    const flags = new Map<string, string>();
    for (let index = 1; index < argv.length; index++) {
      const [name, ...assigned] = argv[index]!.split('=');
      if (!['--preset', '--inventory', '--openapi', '--out', '--url', '--max-requests'].includes(name!) || flags.has(name!)) fail('invalid_arguments');
      const value = assigned.length ? assigned.join('=') : argv[++index];
      if (!value || value.startsWith('-') || /[\u0000-\u001f\u007f]/.test(value)) fail('invalid_arguments');
      flags.set(name!, value);
    }
    if (!['--preset', '--inventory', '--openapi', '--out'].every(flag => flags.has(flag))) fail('invalid_arguments');
    const limit = flags.get('--max-requests');
    if (limit !== undefined && !/^[1-9][0-9]{0,4}$/.test(limit)) fail('invalid_arguments');
    const budget = limit === undefined ? 64 : Number(limit);
    if (budget > 20000) fail('invalid_arguments');
    const buffers: Buffer[] = [];
    for (const [flag, cap] of [['--preset', PRESET_MAX_BYTES], ['--inventory', OPENAPI_MAX_INPUT_BYTES], ['--openapi', OPENAPI_MAX_INPUT_BYTES]] as const) {
      const path = resolve(flags.get(flag)!); await offlineDirectory(dirname(path));
      buffers.push(await readJsonInputBytes(path, cap));
    }
    const destination = resolve(flags.get('--out')!);
    const output = join(await offlineDirectory(dirname(destination)), basename(destination));
    const bundle = buildPresetBundle(buffers[0]!, buffers[1]!, buffers[2]!, flags.get('--url'), budget);
    await writeOfflineBundle(output, bundle.files);
    const operations = bundle.plan.tasks.reduce((total, task) => total + (task.engine === 'schemathesis' ? task.operations.length : 0), 0);
    process.stdout.write(`Plan status=generated preset=${PRESET} tasks=${bundle.plan.tasks.length} operations=${operations} maxRequests=${budget}\n${PROVENANCE_NOTICE}\nProvenance is recorded only; it is not yet verified at execution time.\n`);
    return 0;
  } catch (error) { process.stderr.write(offlineErrorCode(error, 'invalid_preset') + '\n'); return 2; }
}
