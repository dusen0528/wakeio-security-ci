import { snapshotJsonData } from '../../json-snapshot.js';

const HOST = 'repo.maven.apache.org';
const SEGMENT = /^[A-Za-z0-9_][A-Za-z0-9_.+-]*$/;
const GROUP = /^[A-Za-z0-9_][A-Za-z0-9_-]*$/;
const FILE = /^(.*)\.(jar|pom|module|xml|zip|tar\.gz)(?:\.asc)?(?:\.(?:sha1|sha256|sha512|md5))?$/;
export interface MavenRepositoryRequest {
  method: 'GET' | 'HEAD'; scheme: 'https'; host: typeof HOST; port: 443; path: string;
  kind: 'artifact' | 'metadata'; egressEnforced: false;
}
function invalid(): never { throw new TypeError('invalid_maven_repository_request'); }
function metadata(parts: string[]): boolean {
  if (!/^maven-metadata\.xml(?:\.asc)?(?:\.(?:sha1|sha256|sha512|md5))?$/.test(parts.at(-1)!)) return false;
  const base = parts.slice(0, -1);
  const artifactLevel = base.length >= 2 && base.slice(0, -1).every(part => GROUP.test(part))
    && SEGMENT.test(base.at(-1)!);
  const versionLevel = base.length >= 3 && base.slice(0, -2).every(part => GROUP.test(part))
    && base.slice(-2).every(part => SEGMENT.test(part));
  return artifactLevel || versionLevel;
}
function artifact(parts: string[]): boolean {
  const file = parts.at(-1)!, version = parts.at(-2)!, name = parts.at(-3)!;
  if (parts.length < 4 || !parts.slice(0, -3).every(part => GROUP.test(part))
    || !SEGMENT.test(name) || !SEGMENT.test(version)) return false;
  const match = FILE.exec(file);
  if (!match) return false;
  const prefix = `${name}-${version}`, stem = match[1];
  if (stem === prefix || stem.startsWith(prefix + '-') && SEGMENT.test(stem.slice(prefix.length + 1))) return true;
  // Remote SNAPSHOT files use a timestamped version beneath the baseVersion directory.
  const snapshot = `${name}-${version.slice(0, -9)}-`;
  return version.endsWith('-SNAPSHOT') && stem.startsWith(snapshot)
    && /^\d{8}\.\d{6}-\d+(?:-[A-Za-z0-9_][A-Za-z0-9_.+-]*)?$/.test(stem.slice(snapshot.length));
}

/** Canonical upstream path/authority policy only; no server, DNS/redirect checks or enforced egress.
 * The HTTP adapter must separately bind its listener to the lease and reject duplicate Host headers.
 */
export function normaliseMavenRequest(input: unknown): MavenRepositoryRequest {
  const data = snapshotJsonData(input, invalid);
  if (!data || typeof data !== 'object' || Array.isArray(data)) invalid();
  const r = data as Record<string, unknown>;
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
  return { method: r.method, scheme: 'https', host: HOST, port: 443, path: r.path,
    kind: isMetadata ? 'metadata' : 'artifact', egressEnforced: false };
}
