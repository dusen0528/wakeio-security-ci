#!/usr/bin/env node
// Evaluator boundary. This module and its manifest must never be scanner mounts.
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { lstat, readFile, realpath, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const exec = promisify(execFile);
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const schema = JSON.parse(await readFile(resolve(root, 'schemas/testbed.v1.json'), 'utf8'));
export const SCANNER_IMAGE = 'node@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d';
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export class TestbedError extends Error {
  constructor(code, location = '') { super(`${code}${location ? ':' + location : ''}`); this.code = code; }
}
const fail = (code, location) => { throw new TestbedError(code, location); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);

// Only the schema vocabulary used by this contract is needed; no external refs,
// dynamic compilation, dependencies or executable schema keywords are accepted.
function check(value, rule, location = '$') {
  if (rule.$ref) return check(value, schema.$defs[rule.$ref.split('/').at(-1)], location);
  if ('const' in rule && value !== rule.const) fail('schema_const', location);
  if (rule.enum && !rule.enum.includes(value)) fail('schema_enum', location);
  if (rule.type) {
    const types = Array.isArray(rule.type) ? rule.type : [rule.type];
    const valid = types.some(type => {
      switch (type) {
        case 'object': return object(value);
        case 'array': return Array.isArray(value);
        case 'integer': return Number.isSafeInteger(value);
        case 'null': return value === null;
        case 'string': case 'boolean': return typeof value === type;
        default: return fail('unsupported_schema_type', location);
      }
    });
    if (!valid) fail('schema_type', location);
  }
  if (typeof value === 'string') {
    if (value.length < (rule.minLength ?? 0) || value.length > (rule.maxLength ?? 4096)
      || (rule.pattern && !new RegExp(rule.pattern).test(value))) fail('schema_string', location);
  }
  if (typeof value === 'number' && (value < (rule.minimum ?? -Infinity) || value > (rule.maximum ?? Infinity))) fail('schema_number', location);
  if (Array.isArray(value)) {
    if (value.length < (rule.minItems ?? 0) || value.length > (rule.maxItems ?? 4096)) fail('schema_array', location);
    if (rule.uniqueItems && new Set(value.map(v => JSON.stringify(v))).size !== value.length) fail('schema_unique', location);
    value.forEach((v, i) => check(v, rule.items, `${location}[${i}]`));
  }
  if (object(value)) {
    if (Object.keys(value).length < (rule.minProperties ?? 0)) fail('schema_object', location);
    for (const key of rule.required ?? []) if (!Object.hasOwn(value, key)) fail('schema_required', `${location}.${key}`);
    for (const [key, v] of Object.entries(value)) {
      if (rule.properties && Object.hasOwn(rule.properties, key)) check(v, rule.properties[key], `${location}.${key}`);
      else if (object(rule.additionalProperties)) check(v, rule.additionalProperties, `${location}.${key}`);
      else if (rule.additionalProperties === false) fail('schema_unknown', `${location}.${key}`);
    }
  }
}

export function parseManifest(value) {
  check(value, schema);
  const pins = new Set();
  for (const pin of value.privateFiles) {
    if (pin.path.split('/').some(p => p === '.' || p === '..') || pins.has(pin.path)) fail('invalid_pin_path', pin.path);
    pins.add(pin.path);
  }
  const requirePin = path => { if (!pins.has(path)) fail('missing_pin', path); };
  const ids = new Set();
  for (const target of value.targets) {
    if (ids.has(target.id)) fail('duplicate_target', target.id);
    ids.add(target.id);
    requirePin(target.source.pinPath);
    const variants = new Set();
    for (const variant of target.variants) {
      if (variants.has(variant.id)) fail('duplicate_variant', variant.id);
      variants.add(variant.id); requirePin(variant.pinPath);
    }
    const units = new Set();
    for (const truth of target.truth) {
      requirePin(truth.pinPath);
      if (!target.actors.includes(truth.actor)) fail('unknown_actor', truth.actor);
      if (!target.operations.includes(truth.operation) || !target.operations.includes(truth.normalControl.operation)) fail('unknown_operation', target.id);
      const expected = Object.keys(truth.singleSite);
      if (expected.length !== variants.size || expected.some(v => !variants.has(v))) fail('variant_expectations', target.id);
      const unit = JSON.stringify([truth.cwe, truth.operation, truth.input, truth.actor, truth.chain?.id ?? null]);
      if (units.has(unit)) fail('duplicate_truth_unit', target.id);
      units.add(unit);
      if (truth.chain) {
        const expectedChain = Object.keys(truth.chain.expected);
        if (expectedChain.length !== variants.size || expectedChain.some(v => !variants.has(v))) fail('chain_variant_expectations', target.id);
        const consumers = new Set(), edges = new Set();
        for (const edge of truth.chain.edges) {
          if (edge.producer >= edge.consumer || edge.consumer >= truth.chain.steps.length) fail('invalid_causal_edge', truth.chain.id);
          const key = `${edge.producer}:${edge.consumer}`;
          if (edges.has(key)) fail('duplicate_causal_edge', truth.chain.id);
          edges.add(key); consumers.add(edge.consumer);
        }
        if (consumers.size !== truth.chain.steps.length - 1) fail('disconnected_chain', truth.chain.id);
      }
    }
  }
  for (const prerequisite of value.prerequisites) {
    if (ids.has(prerequisite.id)) fail('duplicate_target', prerequisite.id);
    ids.add(prerequisite.id);
    prerequisite.pinPaths.forEach(requirePin);
  }
  return value;
}

async function regularFile(path, maxBytes = 2 * 1024 * 1024) {
  const canonical = await realpath(path), stat = await lstat(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > maxBytes) fail('unsafe_file', path);
  return canonical;
}

export async function loadManifest(path = resolve(root, 'benchmarks/testbeds/manifest.json')) {
  await regularFile(path);
  const bytes = await readFile(path), data = parseManifest(JSON.parse(bytes.toString('utf8')));
  const pinBytes = new Map();
  for (const pin of data.privateFiles) {
    let bytes;
    if (pin.commit === null) {
      const file = resolve(root, pin.path);
      if (!file.startsWith(root + sep) || await regularFile(file) !== file) fail('unsafe_pin', pin.path);
      bytes = await readFile(file);
    } else {
      const result = await exec('git', ['--no-replace-objects', 'show', `${pin.commit}:${pin.path}`], {
        cwd: root, encoding: 'buffer', maxBuffer: 2 * 1024 * 1024, timeout: 10000,
        env: { PATH: '/usr/bin:/bin', GIT_MASTER: '1', GIT_PAGER: 'cat', GIT_TERMINAL_PROMPT: '0',
          GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_NO_LAZY_FETCH: '1', GIT_OPTIONAL_LOCKS: '0',
          TMPDIR: process.env.TMPDIR, NODE_COMPILE_CACHE: process.env.NODE_COMPILE_CACHE,
          BUN_RUNTIME_TRANSPILER_CACHE_PATH: process.env.BUN_RUNTIME_TRANSPILER_CACHE_PATH },
      });
      bytes = result.stdout;
    }
    if (sha256(bytes) !== pin.sha256) fail('stale_pin', pin.path);
    pinBytes.set(pin.path, bytes.toString('utf8'));
  }
  for (const target of data.targets) {
    const provenance = pinBytes.get(target.source.pinPath);
    if (!provenance.includes(target.source.commit) || !provenance.includes(target.image)) fail('source_image_binding', target.id);
    for (const variant of target.variants) if (!pinBytes.get(variant.pinPath).includes(variant.artifactSha256)) fail('variant_pin_binding', variant.id);
  }
  return { data, sha256: sha256(bytes) };
}

export function scannerInput(data) {
  // Deliberate allowlist, not deletion of known private keys. No input payload,
  // labels, reset recipe, proof, pin paths, miss, single-site or chain truth.
  return { schema: 'wakeio.testbed-input/v1', targets: data.targets.map(target => ({
    id: target.id, version: target.version, image: target.image, service: target.service, actors: target.actors,
    operations: target.operations,
  })) };
}

export async function inspectScanner({ id, input, scanner }) {
  if (!/^[a-f0-9]{64}$/.test(id)) fail('invalid_container_id');
  const scannerFile = await regularFile(scanner, 32 * 1024 * 1024);
  if (scannerFile !== resolve(root, 'dist-action/wakeio-security-ci.mjs')) fail('scanner_code_path');
  const allowed = new Map([['/input/inventory.mjs', await regularFile(input)], ['/scanner.mjs', scannerFile]]);
  const { stdout } = await exec('docker', ['inspect', '--type', 'container', id], { timeout: 30000, maxBuffer: 2 * 1024 * 1024 });
  const [inspection] = JSON.parse(stdout);
  if (inspection.Id !== id || inspection.Config.Image !== SCANNER_IMAGE || !inspection.Config.Labels?.['wakeio.t4']) fail('scanner_identity');
  if (JSON.stringify(inspection.Config.Entrypoint) !== '["node"]'
    || JSON.stringify(inspection.Config.Cmd) !== JSON.stringify(['/scanner.mjs', 'scan', '--source', '/input', '--tools', 'none', '--out', '/tmp/report'])) fail('scanner_command');
  const host = inspection.HostConfig;
  if (host.NetworkMode !== 'none' || host.Privileged || !host.ReadonlyRootfs || host.PidMode || host.IpcMode === 'host'
    || host.Devices?.length || host.VolumesFrom?.length || host.PortBindings && Object.keys(host.PortBindings).length) fail('scanner_isolation');
  if (!host.CapDrop?.includes('ALL') || !host.SecurityOpt?.includes('no-new-privileges')) fail('scanner_privileges');
  if (inspection.Mounts.length !== allowed.size) fail('scanner_mount_count');
  for (const mount of inspection.Mounts) {
    if (mount.Type !== 'bind' || mount.RW || allowed.get(mount.Destination) !== mount.Source) fail('scanner_private_mount');
  }
  const { stdout: imageBytes } = await exec('docker', ['image', 'inspect', SCANNER_IMAGE], { timeout: 30000, maxBuffer: 2 * 1024 * 1024 });
  const [image] = JSON.parse(imageBytes);
  if (inspection.Image !== image.Id || JSON.stringify(inspection.Config.Env) !== JSON.stringify(image.Config.Env)) fail('scanner_environment');
  return inspection;
}

async function main(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i], value = argv[i + 1];
    if (!['--manifest', '--out', '--scanner-out', '--inspect', '--input', '--scanner'].includes(flag) || !value || value.startsWith('--') || Object.hasOwn(options, flag)) fail('invalid_arguments');
    options[flag] = value;
  }
  const manifest = await loadManifest(options['--manifest']);
  const projection = 'export const inventory = ' + JSON.stringify(scannerInput(manifest.data)) + ';\n';
  if (options['--scanner-out']) await writeFile(options['--scanner-out'], projection, { flag: 'wx', mode: 0o600 });
  let inspection;
  if (options['--inspect']) {
    if (!options['--input'] || !options['--scanner']) fail('missing_inspection_inputs');
    if (!Buffer.from(projection).equals(await readFile(options['--input']))) fail('scanner_input_mismatch');
    inspection = await inspectScanner({ id: options['--inspect'], input: options['--input'], scanner: options['--scanner'] });
  } else if (options['--input'] || options['--scanner']) fail('missing_inspection');
  const receipt = { status: 'pass', manifestSha256: manifest.sha256, scannerInputSha256: sha256(projection),
    scope: manifest.data.scope, targets: manifest.data.targets.length, prerequisites: manifest.data.prerequisites,
    ...(inspection ? { inspection } : {}) };
  if (options['--out']) await writeFile(options['--out'], JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx' });
  process.stdout.write(JSON.stringify(receipt) + '\n');
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  // CLI boundary: all filesystem, JSON, process and contract failures are non-success.
  main(process.argv.slice(2)).catch(error => {
    process.stderr.write(JSON.stringify({ status: 'fail', reason: error instanceof Error ? error.message : 'unknown_failure' }) + '\n');
    process.exitCode = 2;
  });
}
