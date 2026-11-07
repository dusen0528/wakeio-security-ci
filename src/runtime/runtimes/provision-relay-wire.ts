import type { ChildProcessWithoutNullStreams } from 'node:child_process';
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { snapshotJsonData } from '../../json-snapshot.js';
import { buildRequest, buildResult, buildDigest, type BuildRequest, type BuildReply } from './provision-build-wire.js';
import { ProvisionError, provisionRecord, requireProvision, unreachable } from './provision-types.js';

export interface RelayRequest {
  readonly operation: 'identity' | 'qualify' | 'network-build' | 'network-runtime' | 'shutdown';
}

/** Serialized, bounded protocol. Request rejection is not transport drainage. */
export class ProvisionRelayWire {
  private sequence = 0;
  private buffer = Buffer.alloc(0);
  private active: Readonly<{
    sequence: number;
    challenge: string;
    build?: BuildRequest;
    resolve: (value: Record<string, unknown>) => void;
    reject: (error: ProvisionError) => void;
  }> | undefined;
  private failure: ProvisionError | undefined;
  private diagnosticBytes = 0;
  private buildStart: number | undefined;
  private buildRef: string | undefined;
  private phase = 0;
  private file = 0;
  private readonly offsets = [0, 0, 0, 0, 0];
  private readonly abort = () => this.fail('relay_aborted');

  constructor(private readonly child: ChildProcessWithoutNullStreams,
    private readonly binding: Readonly<{ nonce: string; run: string }>, private readonly signal: AbortSignal) {
    requireProvision(/^[a-f0-9]{64}$/.test(binding.nonce) && /^[a-f0-9]{32}$/.test(binding.run), 'relay_binding');
    child.stdout.on('data', this.output);
    child.stderr.on('data', (chunk: Buffer) => {
      this.diagnosticBytes += chunk.length;
      if (this.diagnosticBytes > 1024) this.fail('relay_diagnostic_bound');
    });
    child.once('close', () => this.fail('relay_closed'));
    child.once('error', () => this.fail('relay_transport_error'));
    child.stdin.on('error', () => this.fail('relay_input_closed'));
    signal.addEventListener('abort', this.abort, { once: true });
    if (signal.aborted) this.abort();
  }

  request(request: RelayRequest): Promise<Record<string, unknown>> {
    if (this.buildStart !== undefined && this.phase !== 7 && request.operation !== 'shutdown'
      && this.sequence - this.buildStart >= 254) return Promise.reject(new ProvisionError('build_budget'));
    return this.send(request);
  }

  async build(raw: BuildRequest): Promise<BuildReply> {
    const request = buildRequest(raw);
    if (this.failure) throw this.failure;
    const { operation } = request;
    if (operation === 'build-begin') {
      requireProvision(this.buildStart === undefined && this.sequence <= 736, 'build_reservation');
    } else {
      requireProvision(request.build === this.buildRef && this.phase !== 7, 'build_reference');
      const reserve = operation === 'build-close' ? 0 : operation === 'build-stop' ? 1 : 2;
      requireProvision(this.buildStart !== undefined
        && this.sequence - this.buildStart < 256 - reserve, 'build_budget');
      switch (operation) {
        case 'build-input':
          requireProvision(this.phase === 1 && request.body.file >= this.file
            && request.body.offset === this.offsets[request.body.file], 'build_input_order');
          break;
        case 'build-seal':
          requireProvision(this.phase === 1
            && request.body.files.every(row => row.bytes === this.offsets[row.file]), 'build_seal_order');
          break;
        case 'build-prepare': requireProvision(this.phase === 2, 'build_phase'); break;
        case 'build-offline': requireProvision(this.phase === 3, 'build_phase'); break;
        case 'build-assemble': requireProvision(this.phase === 4, 'build_phase'); break;
        case 'build-stop': requireProvision(this.phase !== 6, 'build_phase'); break;
        case 'build-close': break;
        default: return unreachable(request);
      }
    }
    // Consume the build slot before sending; an ambiguous reply never permits another begin.
    if (operation === 'build-begin') this.buildStart = this.sequence;
    const result = buildResult(await this.send(request, request), request);
    return { build: this.buildRef ?? null, result };
  }

  private send(request: RelayRequest | BuildRequest, build?: BuildRequest): Promise<Record<string, unknown>> {
    if (this.failure) return Promise.reject(this.failure);
    if (this.active || this.sequence >= 1024) {
      this.fail('relay_concurrent_or_exhausted');
      return Promise.reject(this.failure);
    }
    const sequence = ++this.sequence;
    const challenge = randomBytes(32).toString('hex');
    const payload = build
      ? { version: 2, sequence, challenge, run: this.binding.run,
        operation: build.operation, build: build.build, body: build.body }
      : { version: 1, sequence, run: this.binding.run, challenge, ...request };
    const mac = createHmac('sha256', Buffer.from(this.binding.nonce, 'hex'))
      .update((build ? 'build-request:' : 'request:') + JSON.stringify(payload)).digest('hex');
    const body = Buffer.from(JSON.stringify({ ...payload, mac }));
    requireProvision(body.length <= 65536, 'relay_request_bound');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(body.length);
    return new Promise((resolve, reject) => {
      this.active = { sequence, challenge, resolve, reject, ...(build ? { build } : {}) };
      this.child.stdin.write(Buffer.concat([header, body]));
    });
  }

  private readonly output = (chunk: Buffer) => {
    if (this.failure) return;
    if (this.buffer.length + chunk.length > 1024 * 1024 + 4) return this.fail('relay_frame_bound');
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (this.buffer.length >= 4) {
      const length = this.buffer.readUInt32BE(0);
      if (!length || length > 1024 * 1024) return this.fail('relay_frame_bound');
      if (this.buffer.length < length + 4) return;
      const bytes = this.buffer.subarray(4, length + 4);
      this.buffer = this.buffer.subarray(length + 4);
      try {
        const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
        const parsed = JSON.parse(text);
        requireProvision(JSON.stringify(parsed) === text, 'relay_noncanonical_frame');
        this.accept(provisionRecord(snapshotJsonData(parsed)));
      }
      catch (error) {
        if (!(error instanceof Error)) throw error;
        return this.fail('relay_frame_invalid');
      }
    }
  };

  private accept(data: Record<string, unknown>): void {
    if (this.active?.build) return this.acceptBuild(data, this.active.build);
    requireProvision(this.active && data.version === 1 && data.sequence === this.active.sequence
      && data.run === this.binding.run && data.challenge === this.active.challenge
      && Object.keys(data).sort().join(',') === 'challenge,mac,result,run,sequence,version', 'relay_response_binding');
    const result = provisionRecord(data.result);
    requireProvision(typeof data.mac === 'string' && /^[a-f0-9]{64}$/.test(data.mac), 'relay_response_mac');
    const payload = { version: 1, sequence: data.sequence, run: data.run, challenge: data.challenge, result };
    const expected = createHmac('sha256', Buffer.from(this.binding.nonce, 'hex'))
      .update('response:' + JSON.stringify(payload)).digest();
    requireProvision(timingSafeEqual(expected, Buffer.from(data.mac, 'hex')), 'relay_response_mac');
    const active = this.active;
    this.active = undefined;
    active.resolve(result);
  }

  private acceptBuild(data: Record<string, unknown>, request: BuildRequest): void {
    const active = this.active;
    requireProvision(active && Object.keys(data).join(',') ===
      'version,sequence,challenge,run,operation,build,result,mac'
      && data.version === 2 && data.sequence === active.sequence && data.challenge === active.challenge
      && data.run === this.binding.run && data.operation === request.operation, 'build_response_binding');
    const result = buildResult(data.result, request);
    if (request.operation === 'build-begin') {
      if (result.kind === 'allocated') buildDigest(data.build);
      else requireProvision(data.build === null, 'build_begin_reference');
    } else requireProvision(data.build === request.build, 'build_response_reference');
    requireProvision(typeof data.mac === 'string' && /^[a-f0-9]{64}$/.test(data.mac), 'build_response_mac');
    const payload = { version: 2, sequence: data.sequence, challenge: data.challenge, run: data.run,
      operation: data.operation, build: data.build, result };
    const expected = createHmac('sha256', Buffer.from(this.binding.nonce, 'hex'))
      .update('build-response:' + JSON.stringify(payload)).digest();
    requireProvision(timingSafeEqual(expected, Buffer.from(data.mac, 'hex')), 'build_response_mac');
    if (result.kind === 'allocated') this.buildRef = buildDigest(data.build);
    // Commit the observation before releasing the active slot, including to other data listeners.
    switch (result.kind) {
      case 'allocated': this.phase = 1; break;
      case 'input-accepted': this.file = result.file; this.offsets[result.file] = result.nextOffset; break;
      case 'sealed': this.phase = 2; break;
      case 'preparation-closed': this.phase = 3; break;
      case 'offline-closed': this.phase = 4; break;
      case 'assembled': this.phase = 5; break;
      case 'stop-requested': this.phase = 6; break;
      case 'cleanup-state': this.phase = 7; break;
      case 'failed': this.phase = 8; break;
      default: return unreachable(result);
    }
    this.active = undefined;
    active.resolve(provisionRecord(result));
  }

  private fail(code: string): void {
    this.failure ??= new ProvisionError(code);
    this.active?.reject(this.failure);
    this.active = undefined;
    this.child.stdin.destroy();
  }

  close(): void {
    this.signal.removeEventListener('abort', this.abort);
    this.fail('relay_closed');
  }
}
