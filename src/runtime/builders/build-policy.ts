import { snapshotJsonData } from '../../json-snapshot.js';

const HOST = 'repo.maven.apache.org';
const SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9_.+-]*$/;
const GROUP = /^[A-Za-z0-9_][A-Za-z0-9_-]*$/;
const FILE = /^(.*)\.(jar|pom|module|xml|zip|tar\.gz)(?:\.asc)?(?:\.(?:sha1|sha256|sha512|md5))?$/;
export interface MavenRepositoryRequest {
  readonly method: 'GET' | 'HEAD';
  readonly scheme: 'https';
  readonly host: typeof HOST;
  readonly port: 443;
  readonly path: string;
  readonly kind: 'artifact' | 'metadata';
  readonly egressEnforced: false;
}
function invalid(): never { throw new TypeError('invalid_maven_repository_request'); }

function metadata(parts: readonly string[]): boolean {
  const last = parts.at(-1);
  if (!last || !/^maven-metadata\.xml(?:\.asc)?(?:\.(?:sha1|sha256|sha512|md5))?$/.test(last)) return false;
  const base = parts.slice(0, -1);
  const name = base.at(-1);
  return name !== undefined && (base.length >= 2 && base.slice(0, -1).every(part => GROUP.test(part))
    && SEGMENT.test(name) || base.length >= 3 && base.slice(0, -2).every(part => GROUP.test(part))
    && base.slice(-2).every(part => SEGMENT.test(part)));
}

function artifact(parts: readonly string[]): boolean {
  const file = parts.at(-1), version = parts.at(-2), name = parts.at(-3);
  if (!file || !version || !name || parts.length < 4 || !parts.slice(0, -3).every(part => GROUP.test(part))
    || !SEGMENT.test(name) || !SEGMENT.test(version)) return false;
  const stem = FILE.exec(file)?.[1];
  if (!stem) return false;
  const prefix = `${name}-${version}`;
  if (stem === prefix || stem.startsWith(prefix + '-') && SEGMENT.test(stem.slice(prefix.length + 1))) return true;
  const snapshot = `${name}-${version.slice(0, -9)}-`;
  return version.endsWith('-SNAPSHOT') && stem.startsWith(snapshot)
    && /^\d{8}\.\d{6}-\d+(?:-[A-Za-z0-9_][A-Za-z0-9_.+-]*)?$/.test(stem.slice(snapshot.length));
}

/** M1 62db8cb canonical Maven policy, type-narrowed without its unchecked assertions.
 * The guest mirror consumes this exact module; only actual network witnesses prove enforcement.
 */
export function normaliseMavenRequest(input: unknown): MavenRepositoryRequest {
  const data = snapshotJsonData(input, invalid);
  if (!data || typeof data !== 'object' || Array.isArray(data)) invalid();
  const r = Object.fromEntries(Object.entries(data));
  const keys = ['method', 'scheme', 'host', 'port', 'hostHeader', 'path'];
  if (Object.keys(r).length !== keys.length || Object.keys(r).some(key => !keys.includes(key))) invalid();
  if (r.method !== 'GET' && r.method !== 'HEAD' || r.scheme !== 'https' || r.host !== HOST || r.port !== 443
    || r.hostHeader !== HOST && r.hostHeader !== `${HOST}:443`) invalid();
  if (typeof r.path !== 'string' || r.path.length > 2048 || !r.path.startsWith('/maven2/')
    || /[\x00-\x20\x7f%?#\\]/.test(r.path) || r.path.includes('//')) invalid();
  const parts = r.path.slice('/maven2/'.length).split('/');
  if (parts.some(part => !part || part === '.' || part === '..')) invalid();
  const isMetadata = metadata(parts);
  if (!isMetadata && !artifact(parts)) invalid();
  return Object.freeze({ method: r.method, scheme: 'https', host: HOST, port: 443, path: r.path,
    kind: isMetadata ? 'metadata' : 'artifact', egressEnforced: false });
}
