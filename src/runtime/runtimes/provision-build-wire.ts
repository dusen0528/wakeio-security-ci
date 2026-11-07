import { snapshotJsonData } from '../../json-snapshot.js';
import { provisionRecord, requireProvision, unreachable } from './provision-types.js';

export type BuildReason = 'input_refused' | 'identity_changed' | 'phase_invalid' | 'operation_failed'
  | 'output_bound' | 'aborted' | 'deadline' | 'close_unconfirmed' | 'allocation_unknown';
type Receipt = Readonly<{ file: number; bytes: number; sha256: string }>;
type Ref = Readonly<{ build: string }>;
export type BuildRequest =
  | Readonly<{ operation: 'build-begin'; build: null; body: Readonly<{ profile: 'f01' | 'f02' | 'f03' | 'f04' }> }>
  | (Ref & Readonly<{ operation: 'build-input'; body: Readonly<{ file: number; offset: number; data: string }> }>)
  | (Ref & Readonly<{ operation: 'build-seal'; body: Readonly<{ files: readonly Receipt[] }> }>)
  | (Ref & Readonly<{ operation: 'build-prepare' | 'build-offline' | 'build-assemble' | 'build-close';
    body: Readonly<Record<string, never>> }>)
  | (Ref & Readonly<{ operation: 'build-stop';
    body: Readonly<{ reason: 'aborted' | 'deadline' | 'failure' | 'completed' }> }>);
type DigestSize = Readonly<{ sha256: string; bytes: number }>;
type Tree = DigestSize & Readonly<{ entries: number }>;
export type BuildResult =
  | Readonly<{ kind: 'allocated'; generation: number }>
  | Readonly<{ kind: 'input-accepted'; file: number; nextOffset: number }>
  | Readonly<{ kind: 'sealed'; manifestSha256: string }>
  | Readonly<{ kind: 'preparation-closed'; cache: Tree; closureSha256: string }>
  | Readonly<{ kind: 'offline-closed'; jar: Readonly<{ bytes: number; sha256: string }>; classes: Tree }>
  | Readonly<{ kind: 'assembled'; image: Readonly<{ id: string; configSha256: string; os: 'linux';
    architecture: 'arm64'; layersSha256: string }>; recipeSha256: string; gateSha256: string }>
  | Readonly<{ kind: 'stop-requested' }>
  | Readonly<{ kind: 'cleanup-state'; state: 'confirmed'; reason: null }>
  | Readonly<{ kind: 'cleanup-state'; state: 'unconfirmed'; reason: BuildReason }>
  | Readonly<{ kind: 'failed'; reason: BuildReason }>;
export type BuildReply = Readonly<{ build: string | null; result: BuildResult }>;

/** Ordered closed records; callers must snapshot own data before this internal parser. */
function record(raw: unknown, keys: string): Record<string, unknown> {
  const data = provisionRecord(raw);
  requireProvision(Object.keys(data).join(',') === keys, 'build_keys');
  return data;
}

export function buildInteger(raw: unknown, maximum: number): number {
  requireProvision(typeof raw === 'number' && Number.isSafeInteger(raw) && raw >= 0 && raw <= maximum,
    'build_integer');
  return raw;
}

export function buildDigest(raw: unknown): string {
  requireProvision(typeof raw === 'string' && /^[a-f0-9]{64}$/.test(raw), 'build_digest');
  return raw;
}

export function buildChunk(raw: unknown): string {
  requireProvision(typeof raw === 'string' && raw.length > 0 && raw.length <= 32768
    && Buffer.from(raw, 'base64').toString('base64') === raw, 'build_base64');
  return raw;
}

function reason(raw: unknown): BuildReason {
  switch (raw) {
    case 'input_refused': case 'identity_changed': case 'phase_invalid': case 'operation_failed':
    case 'output_bound': case 'aborted': case 'deadline': case 'close_unconfirmed': case 'allocation_unknown':
      return raw;
    default: requireProvision(false, 'build_reason');
  }
}

/** Own-data boundary: no getters, proxies, custom prototypes or caller-owned arrays survive. */
export function buildRequest(raw: unknown): BuildRequest {
  const data = record(snapshotJsonData(raw), 'operation,build,body');
  const { operation } = data;
  switch (operation) {
    case 'build-begin': {
      const body = record(data.body, 'profile'), profile = body.profile;
      requireProvision(data.build === null
        && (profile === 'f01' || profile === 'f02' || profile === 'f03' || profile === 'f04'), 'build_begin');
      return { operation, build: null, body: { profile } };
    }
    case 'build-input': {
      const body = record(data.body, 'file,offset,data');
      const file = buildInteger(body.file, 4), offset = buildInteger(body.offset, 1048576);
      const bytes = buildChunk(body.data);
      requireProvision(offset + Buffer.from(bytes, 'base64').length <= 1048576, 'build_file_bound');
      return { operation, build: buildDigest(data.build), body: { file, offset, data: bytes } };
    }
    case 'build-seal': {
      const body = record(data.body, 'files');
      requireProvision(Array.isArray(body.files) && body.files.length === 5, 'build_files');
      const files = body.files.map((rawFile: unknown, index: number) => {
        const row = record(rawFile, 'file,bytes,sha256'), file = buildInteger(row.file, 4);
        requireProvision(file === index, 'build_ordinal');
        return { file, bytes: buildInteger(row.bytes, 1048576), sha256: buildDigest(row.sha256) };
      });
      return { operation, build: buildDigest(data.build), body: { files } };
    }
    case 'build-stop': {
      const body = record(data.body, 'reason'), selected = body.reason;
      requireProvision(selected === 'aborted' || selected === 'deadline'
        || selected === 'failure' || selected === 'completed', 'build_stop');
      return { operation, build: buildDigest(data.build), body: { reason: selected } };
    }
    case 'build-prepare': case 'build-offline': case 'build-assemble': case 'build-close':
      record(data.body, '');
      return { operation, build: buildDigest(data.build), body: {} };
    default: requireProvision(false, 'build_operation');
  }
}

function tree(raw: unknown, bytes: number, entries: number): Tree {
  const data = record(raw, 'sha256,bytes,entries');
  return { sha256: buildDigest(data.sha256), bytes: buildInteger(data.bytes, bytes),
    entries: buildInteger(data.entries, entries) };
}

function image(raw: unknown): Extract<BuildResult, { kind: 'assembled' }>['image'] {
  const data = record(raw, 'id,configSha256,os,architecture,layersSha256');
  requireProvision(typeof data.id === 'string' && /^sha256:[a-f0-9]{64}$/.test(data.id)
    && data.os === 'linux' && data.architecture === 'arm64', 'build_image');
  return { id: data.id, configSha256: buildDigest(data.configSha256),
    os: 'linux', architecture: 'arm64', layersSha256: buildDigest(data.layersSha256) };
}

/** Phase-specific DATA, never an ownership or successful-build registration route. */
export function buildResult(raw: unknown, request: BuildRequest): BuildResult {
  const data = provisionRecord(snapshotJsonData(raw));
  if (data.kind === 'failed') {
    record(data, 'kind,reason');
    return { kind: 'failed', reason: reason(data.reason) };
  }
  switch (request.operation) {
    case 'build-begin':
      record(data, 'kind,generation');
      requireProvision(data.kind === 'allocated' && data.generation !== 0, 'build_result');
      return { kind: 'allocated', generation: buildInteger(data.generation, Number.MAX_SAFE_INTEGER) };
    case 'build-input':
      record(data, 'kind,file,nextOffset');
      requireProvision(data.kind === 'input-accepted' && data.file === request.body.file
        && data.nextOffset === request.body.offset + Buffer.from(request.body.data, 'base64').length,
      'build_input_result');
      return { kind: 'input-accepted', file: request.body.file,
        nextOffset: buildInteger(data.nextOffset, 1048576) };
    case 'build-seal':
      record(data, 'kind,manifestSha256');
      requireProvision(data.kind === 'sealed', 'build_result');
      return { kind: 'sealed', manifestSha256: buildDigest(data.manifestSha256) };
    case 'build-prepare':
      record(data, 'kind,cache,closureSha256');
      requireProvision(data.kind === 'preparation-closed', 'build_result');
      return { kind: 'preparation-closed', cache: tree(data.cache, 1073741824, 16384),
        closureSha256: buildDigest(data.closureSha256) };
    case 'build-offline': {
      record(data, 'kind,jar,classes');
      requireProvision(data.kind === 'offline-closed', 'build_result');
      const jar = record(data.jar, 'bytes,sha256');
      return { kind: 'offline-closed',
        jar: { bytes: buildInteger(jar.bytes, 67108864), sha256: buildDigest(jar.sha256) },
        classes: tree(data.classes, 134217728, 4096) };
    }
    case 'build-assemble': {
      record(data, 'kind,image,recipeSha256,gateSha256');
      requireProvision(data.kind === 'assembled', 'build_result');
      return { kind: 'assembled', image: image(data.image),
        recipeSha256: buildDigest(data.recipeSha256), gateSha256: buildDigest(data.gateSha256) };
    }
    case 'build-stop':
      record(data, 'kind');
      requireProvision(data.kind === 'stop-requested', 'build_result');
      return { kind: 'stop-requested' };
    case 'build-close':
      record(data, 'kind,state,reason');
      requireProvision(data.kind === 'cleanup-state', 'build_result');
      switch (data.state) {
        case 'confirmed':
          requireProvision(data.reason === null, 'build_cleanup');
          return { kind: 'cleanup-state', state: 'confirmed', reason: null };
        case 'unconfirmed':
          return { kind: 'cleanup-state', state: 'unconfirmed', reason: reason(data.reason) };
        default: requireProvision(false, 'build_cleanup');
      }
    default: return unreachable(request);
  }
}
