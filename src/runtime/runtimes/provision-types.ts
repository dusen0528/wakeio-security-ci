import { types } from 'node:util';
import { snapshotJsonData } from '../../json-snapshot.js';

export class ProvisionError extends Error {
  constructor(readonly code: string, readonly retained: readonly string[] = [], options?: ErrorOptions) {
    super(code, options);
    this.name = 'ProvisionError';
  }
}

export function requireProvision(value: unknown, code: string): asserts value {
  if (!value) throw new ProvisionError(code);
}

export function provisionRecord(value: unknown): Record<string, unknown> {
  requireProvision(value !== null && typeof value === 'object' && !Array.isArray(value), 'invalid_record');
  return Object.fromEntries(Object.entries(value));
}

export interface ProvisionOptions {
  readonly executeTargetConsent: true;
  readonly deadlineAt: number;
  readonly acquisitionDeadlineAt: number;
  readonly requiredGrade: 'rootless-docker' | 'gvisor';
  readonly catalog: unknown;
}

/** Consent is checked without invoking an accessor or Proxy, before any product I/O. */
export function provisionOptions(raw: unknown): ProvisionOptions {
  requireProvision(raw !== null && typeof raw === 'object' && !types.isProxy(raw), 'consent_required');
  const consent = Object.getOwnPropertyDescriptor(raw, 'executeTargetConsent');
  requireProvision(consent?.enumerable && 'value' in consent && consent.value === true, 'consent_required');
  const invalid = (): never => { throw new ProvisionError('options_invalid'); };
  const data = provisionRecord(snapshotJsonData(raw, invalid, invalid));
  requireProvision(Object.keys(data).sort().join(',') ===
    'acquisitionDeadlineAt,catalog,deadlineAt,executeTargetConsent,requiredGrade', 'options_invalid');
  const { deadlineAt, acquisitionDeadlineAt, requiredGrade } = data;
  const now = Date.now();
  requireProvision(typeof deadlineAt === 'number' && Number.isSafeInteger(deadlineAt)
    && deadlineAt > now && deadlineAt <= now + 900_000, 'deadline_invalid');
  requireProvision(typeof acquisitionDeadlineAt === 'number' && Number.isSafeInteger(acquisitionDeadlineAt)
    && acquisitionDeadlineAt > now && acquisitionDeadlineAt <= Math.min(deadlineAt, now + 300_000),
  'deadline_invalid');
  requireProvision(requiredGrade === 'rootless-docker' || requiredGrade === 'gvisor', 'grade_invalid');
  return Object.freeze({ executeTargetConsent: true, deadlineAt, acquisitionDeadlineAt,
    requiredGrade, catalog: data.catalog });
}

export interface ProvisionCleanup {
  readonly confirmed: boolean;
  readonly retained: readonly string[];
  readonly failures: readonly string[];
}

export interface BackendIdentity {
  readonly run: string;
  readonly vm: string;
  readonly boot: string;
  readonly daemon: string;
  readonly helper: string;
}

export function sameBackendIdentity(expected: BackendIdentity, actual: BackendIdentity): void {
  requireProvision(expected.run === actual.run && expected.vm === actual.vm && expected.boot === actual.boot
    && expected.daemon === actual.daemon && expected.helper === actual.helper, 'backend_identity_changed');
}

export function unreachable(value: never): never {
  throw new ProvisionError('invalid_variant', [], { cause: value });
}
