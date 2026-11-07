import { randomBytes } from 'node:crypto';
import { ProvisionError, requireProvision, type ProvisionCleanup } from './provision-types.js';

export interface OwnedProvisionResource {
  readonly identity: string;
  /** Request termination only. This must never claim absence. */
  stop?(): void;
  /** Resolves only from a real transport/process close acknowledgement. */
  readonly drained: Promise<void>;
  /** Called only after every borrower drains; must refuse unknown ownership. */
  remove(): Promise<boolean>;
}

/** One live owner. Revocation, drainage and removal are three different transitions.
 * The owner retains every undrained resource, even when its bounded close call has returned.
 */
export class ProvisionOwner {
  readonly run = randomBytes(16).toString('hex');
  private readonly controller = new AbortController();
  readonly signal = this.controller.signal;
  private readonly resources: OwnedProvisionResource[] = [];
  private readonly borrowers = new Set<Promise<unknown>>();
  private failure: ProvisionError | undefined;
  private closing: Promise<ProvisionCleanup> | undefined;
  private completion: Promise<ProvisionCleanup> | undefined;
  private readonly timer: NodeJS.Timeout;
  private readonly abort = () => this.revoke('operation_aborted');

  constructor(readonly deadlineAt: number, private readonly external?: AbortSignal) {
    requireProvision(Number.isSafeInteger(deadlineAt) && deadlineAt > Date.now()
      && deadlineAt <= Date.now() + 900_000, 'deadline_invalid');
    external?.addEventListener('abort', this.abort, { once: true });
    this.timer = setTimeout(() => this.revoke('operation_deadline'), deadlineAt - Date.now());
    if (external?.aborted) this.abort();
  }

  check(): void {
    if (Date.now() >= this.deadlineAt) this.revoke('operation_deadline');
    if (this.failure) throw this.failure;
    requireProvision(!this.closing, 'owner_closed');
  }

  revoke(code: string): void {
    this.failure ??= new ProvisionError(code);
    this.controller.abort(this.failure);
  }

  own(resource: OwnedProvisionResource): void {
    requireProvision(!this.resources.some(item => item.identity === resource.identity), 'resource_replay');
    this.resources.push(resource);
    void resource.drained.catch(() => this.revoke('resource_drain_unconfirmed'));
    try { this.check(); }
    catch (error) {
      resource.stop?.();
      throw error;
    }
  }

  borrow<T>(use: () => Promise<T>): Promise<T> {
    this.check();
    const operation = Promise.resolve().then(() => { this.check(); return use(); });
    this.borrowers.add(operation);
    void operation.then(() => this.borrowers.delete(operation), () => {
      this.borrowers.delete(operation);
      this.revoke('borrower_failed');
    });
    return operation;
  }

  close(): Promise<ProvisionCleanup> {
    if (this.closing) return this.closing;
    this.revoke('owner_closed');
    clearTimeout(this.timer);
    this.external?.removeEventListener('abort', this.abort);
    // Retain the actual join after the bounded report expires. A timeout cannot
    // discard the only continuation capable of observing later real drainage.
    this.completion = this.drainAndRemove();
    this.closing = this.boundedClose(this.completion);
    return this.closing;
  }

  cleanupAfterDrain(): Promise<ProvisionCleanup> {
    requireProvision(this.completion, 'cleanup_not_started');
    return this.completion;
  }

  private async boundedClose(completion: Promise<ProvisionCleanup>): Promise<ProvisionCleanup> {
    let timer: NodeJS.Timeout | undefined;
    const expired = new Promise<ProvisionCleanup>(resolve => {
      timer = setTimeout(() => resolve(Object.freeze({ confirmed: false,
        retained: this.resources.map(resource => resource.identity), failures: ['drain_unconfirmed'] })), 120_000);
    });
    try { return await Promise.race([completion, expired]); }
    finally { clearTimeout(timer); }
  }

  private async drainAndRemove(): Promise<ProvisionCleanup> {
    const failures: string[] = [];
    for (const resource of [...this.resources].reverse()) {
      try { resource.stop?.(); }
      catch (error) {
        if (!(error instanceof Error)) throw error;
        failures.push('stop_failed');
      }
    }
    // In-flight allocation may register a stopped resource after revocation.
    // Capture resources only after every allocating borrower has settled.
    await Promise.allSettled([...this.borrowers]);
    const retained = this.resources.map(resource => resource.identity);
    const settled = await Promise.allSettled(this.resources.map(resource => resource.drained));
    if (!settled.every(result => result.status === 'fulfilled') || failures.length) {
      return Object.freeze({ confirmed: false, retained, failures: [...failures, 'drain_unconfirmed'] });
    }
    for (const resource of [...this.resources].reverse()) {
      let removed = false;
      try {
        removed = await resource.remove();
      } catch (error) {
        if (!(error instanceof Error)) throw error;
        failures.push('removal_failed');
      }
      if (!removed) {
        return Object.freeze({ confirmed: false, retained, failures: [...failures, 'removal_unconfirmed'] });
      }
      retained.splice(retained.indexOf(resource.identity), 1);
    }
    return Object.freeze({ confirmed: true, retained, failures });
  }
}
