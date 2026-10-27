import { createHash } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { decodePgParserRequest, encodePgParserReply, pgParserBinding, pgParserFailure, projectPgParserFacts,
  PG_PARSER_LIMITS, PG_PARSER_PIN, PG_PARSER_PROTOCOL_REVISION, PgParserProtocolError } from './pg-parser-helper.js';
import type { PgParserReply, PgParserRequest } from './pg-parser-helper.js';

/** Separate CJS bundle entry only. Never import this file from CLI/main, Oracle or host-side tests. */
export const PG_PARSER_WORKER_PROTOCOL_REVISION = 'wakeio.pg-parser/v1';
const output = process.stdout.write.bind(process.stdout);
function silenceDiagnostics(): void {
  // Emscripten captures console methods during its import-time instantiate(). Suppress them first.
  process.stdout.write = (() => true) as typeof process.stdout.write;
  process.stderr.write = (() => true) as typeof process.stderr.write;
  for (const key of ['log', 'info', 'warn', 'error', 'debug'] as const) console[key] = () => undefined;
}
function assetHash(path: string, max: number): string {
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.size > max)
    throw new PgParserProtocolError('asset_mismatch');
  const bytes = readFileSync(path), after = lstatSync(path);
  if (bytes.length !== before.size || after.ino !== before.ino || after.dev !== before.dev
    || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs)
    throw new PgParserProtocolError('asset_mismatch');
  return createHash('sha256').update(bytes).digest('hex');
}
function verifyAssets(request: PgParserRequest): void {
  // R3 must supply an immutable, trusted installation directory; hashes alone do not authenticate it.
  if (typeof __dirname !== 'string' || typeof __filename !== 'string'
    || __filename !== join(__dirname, 'pg-parser-worker.cjs')
    || PG_PARSER_WORKER_PROTOCOL_REVISION !== PG_PARSER_PROTOCOL_REVISION)
    throw new PgParserProtocolError('parser_unavailable');
  if (assetHash(__filename, 16 * 1024 * 1024) !== request.assets.workerSha256
    || assetHash(join(__dirname, 'manifest.json'), 65536) !== request.assets.manifestSha256
    || assetHash(join(__dirname, 'libpg-query.wasm'), 16 * 1024 * 1024) !== PG_PARSER_PIN.wasmSha256)
    throw new PgParserProtocolError('asset_mismatch');
}
async function input(): Promise<Buffer> {
  const chunks: Buffer[] = []; let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > PG_PARSER_LIMITS.stdinBytes) { process.stdin.destroy(); throw new PgParserProtocolError('limit'); }
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks, bytes);
}
function emit(reply: PgParserReply, request?: PgParserRequest): void {
  let bytes: Buffer, ok = false;
  try {
    bytes = encodePgParserReply(reply, request ? pgParserBinding(request) : undefined); ok = reply.status === 'ok';
  }
  catch { bytes = encodePgParserReply(pgParserFailure('invalid_projection')); }
  output(bytes, () => process.exit(ok ? 0 : 2));
}
async function main(): Promise<void> {
  silenceDiagnostics(); let request: PgParserRequest | undefined;
  try {
    request = decodePgParserRequest(await input()); verifyAssets(request);
    // This is the ONLY execution entry importing the package. Its CJS import immediately instantiates WASM.
    const parser = await import('libpg-query'); await parser.loadModule();
    const parsed = parser.parseSync(request.sql), scanned = parser.scanSync(request.sql);
    emit(projectPgParserFacts(request, parsed, scanned), request);
  } catch (error) {
    // No excerpt, SqlError.message, stack or partially parsed tree may cross stdout/stderr.
    const reason = error instanceof PgParserProtocolError ? error.reason : 'parser_failure';
    emit(pgParserFailure(reason === 'none' ? 'parser_failure' : reason, request), request);
  }
}
// One job per process. A trap's asynchronous package reinitialization is never reused or retried.
// R3 MUST enforce network-none, 1s, 256MiB, UID/caps/readonly/CPU/PIDs and discard native stderr/core dumps.
void main();
