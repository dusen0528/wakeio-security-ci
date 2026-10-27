import { posix } from 'node:path';
import { snapshotJsonData } from '../../json-snapshot.js';
import type { TargetSpec } from '../types.js';

export interface NormalizedComposeInput {
  readonly executable: false;
  readonly requires: readonly ['source-snapshot', 'trusted-postgres-pin', 'verified-isolation'];
  readonly app: { service: string; dependency: string; build: { context: string; dockerfile: string }; port: number;
    command: string[] | null; entrypoint: string[] | null;
    environment: { name: string; dependency: string; field: 'url' | 'username' | 'password' }[] };
  readonly postgres: { service: string; declaredImage: string;
    imagePin: 'required-from-trusted-builder'; config: 'trusted-builder-only' };
  readonly hostPorts: readonly [];
  readonly inheritEnvironment: false;
}
function invalid(): never { throw new TypeError('invalid_runtime_compose'); }
function record(value: unknown, allowed: readonly string[], required: readonly string[] = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) invalid();
  const data = value as Record<string, unknown>;
  if (Object.keys(data).some(key => !allowed.includes(key))
    || required.some(key => !Object.hasOwn(data, key))) invalid();
  return data;
}
function text(value: unknown, max = 512): string {
  if (typeof value !== 'string' || !value || value.length > max || /[\x00-\x1f\x7f$]/.test(value)) invalid();
  return value;
}
function path(value: unknown, directory = false): string {
  let name = text(value);
  if (name.startsWith('./')) name = name.slice(2);
  if (directory && name === '.') return name;
  if (!/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(name)
    || name.split('/').some(part => part === '.' || part === '..')) invalid();
  return name;
}
function service(value: unknown): string {
  const name = text(value, 63);
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(name)) invalid();
  return name;
}
function argv(value: unknown): string[] | null {
  if (value === undefined) return null;
  if (!Array.isArray(value) || value.length < 1 || value.length > 128) invalid();
  const args = value.map(arg => text(arg, 4096));
  if (args.reduce((total, arg) => total + Buffer.byteLength(arg) + 1, 0) > 64 * 1024) invalid();
  return args;
}
const ENV_FIELDS = {
  SPRING_DATASOURCE_URL: 'url', SPRING_DATASOURCE_USERNAME: 'username', SPRING_DATASOURCE_PASSWORD: 'password',
} as const;
function environment(value: unknown, dependency: string): NormalizedComposeInput['app']['environment'] {
  if (value === undefined) return [];
  const data = record(value, Object.keys(ENV_FIELDS));
  return Object.keys(data).sort().map(name => {
    const field = ENV_FIELDS[name as keyof typeof ENV_FIELDS];
    // Product references, never raw credentials or Compose's bare-name environment inheritance.
    if (data[name] !== `wakeio:postgres.${field}`) invalid();
    return { name, dependency, field };
  });
}
function relation(raw: TargetSpec) {
  const data = snapshotJsonData(raw, invalid);
  if (!data || typeof data !== 'object' || Array.isArray(data)) invalid();
  const spec = data as TargetSpec;
  const build = record(spec.build, ['kind', 'file', 'service'], ['kind', 'file', 'service']);
  if (build.kind !== 'compose' || !Array.isArray(spec.dependencies) || spec.dependencies.length !== 1) invalid();
  const dependency = record(spec.dependencies[0], ['service', 'observer'], ['service', 'observer']);
  if (dependency.observer !== 'pg-log') invalid();
  const app = service(build.service), pg = service(dependency.service);
  if (app === pg || !spec.entry || !Number.isSafeInteger(spec.entry.port)
    || spec.entry.port < 1 || spec.entry.port > 65535) invalid();
  return { app, pg, port: spec.entry.port, directory: posix.dirname(path(build.file)) };
}

/** Pure own-data subset. Caller must first reject YAML duplicate keys/tags/anchors/aliases/merge syntax.
 * No file access, image trust, Docker authority or executable manifest is produced here.
 */
export function normaliseCompose(input: unknown, spec: TargetSpec): NormalizedComposeInput {
  const names = relation(spec), root = record(snapshotJsonData(input, invalid), ['services'], ['services']);
  const services = record(root.services, [names.app, names.pg], [names.app, names.pg]);
  const app = record(services[names.app], ['build', 'command', 'entrypoint', 'environment', 'depends_on'], ['build']);
  const build = record(app.build, ['context', 'dockerfile'], ['context', 'dockerfile']);
  const context = path(build.context, true), dockerfile = path(build.dockerfile);
  const pg = record(services[names.pg], ['image'], ['image']);
  const image = text(pg.image, 160);
  if (!/^(?:docker\.io\/library\/)?postgres@sha256:[a-f0-9]{64}$/.test(image)) invalid();
  if (app.depends_on !== undefined && (!Array.isArray(app.depends_on)
    || app.depends_on.length !== 1 || app.depends_on[0] !== names.pg)) invalid();
  return { executable: false, requires: ['source-snapshot', 'trusted-postgres-pin', 'verified-isolation'],
    app: { service: names.app, dependency: names.pg,
      build: { context: posix.join(names.directory, context), dockerfile }, port: names.port,
      command: argv(app.command), entrypoint: argv(app.entrypoint),
      environment: environment(app.environment, names.pg) },
    postgres: { service: names.pg, declaredImage: image,
      imagePin: 'required-from-trusted-builder', config: 'trusted-builder-only' },
    hostPorts: [], inheritEnvironment: false };
}
