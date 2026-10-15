/**
 * Label set for the fixed-plan (A) vs agent-selected (B) comparison.
 *
 * A label set is the ground truth for one target at one commit: the distinct
 * vulnerabilities that exist, and negative sites that must stay clean. Every
 * entry carries a `split`:
 *
 *   - `tuning`  — used while developing the agent's plan/selection prompts.
 *   - `final`   — used only to score a comparison run.
 *
 * The two never mix. The scorer (aggregate.ts) refuses a label set that still
 * contains any `tuning` entry, so final-evaluation truth can never reach the
 * agent's inputs or be scored alongside tuning material. The final split is
 * hashed and bound into the pass criteria, so criteria cannot be retrofitted
 * to a different truth set after seeing arm B.
 *
 * This module parses and normalizes labels only. It sends no requests and
 * imports no agent SDK. Site identity reuses the store's path normalization so
 * a labeled site and a run finding compare on the same terms.
 */
import { createHash } from 'node:crypto';
import { AUTH_STATES, PARAM_LOCATIONS, normalizePath, type AuthState, type ParamLocation } from '../store.js';

export const VULN_TYPES = ['sqli', 'xss', 'authz', 'ssrf', 'cmdi', 'path_traversal', 'open_redirect', 'api_contract', 'secret', 'misconfig', 'other'] as const;
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export const SPLITS = ['tuning', 'final'] as const;

export type VulnType = typeof VULN_TYPES[number];
export type Severity = typeof SEVERITIES[number];
export type Split = typeof SPLITS[number];

export const VULN_ID = /^v-[0-9a-z][0-9a-z-]{0,48}$/;
export const SITE_ID = /^n-[0-9a-z][0-9a-z-]{0,48}$/;

/** A request location, the unit both labels and findings are keyed on. */
export interface Site {
  method: string;
  path: string;
  param: string | null;
  location: ParamLocation | null;
  authState: AuthState;
}

export interface LabeledVuln {
  vulnId: string;
  type: VulnType;
  severity: Severity;
  site: Site;
  split: Split;
}

export interface NegativeSite {
  siteId: string;
  site: Site;
  split: Split;
  note?: string;
}

export interface LabelSet {
  version: 1;
  target: string;
  commit: string;
  vulnerabilities: LabeledVuln[];
  negatives: NegativeSite[];
}

export class LabelError extends Error {
  constructor(readonly path: string) { super(`label_invalid:${path}`); }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function oneOf<T extends string>(value: unknown, options: readonly T[], path: string): T {
  if (typeof value !== 'string' || !(options as readonly string[]).includes(value)) throw new LabelError(path);
  return value as T;
}

function parseSite(raw: unknown, path: string): Site {
  if (!record(raw)) throw new LabelError(path);
  const method = raw.method;
  if (typeof method !== 'string' || !/^[A-Z]{3,7}$/.test(method)) throw new LabelError(`${path}.method`);
  if (typeof raw.path !== 'string' || !raw.path.startsWith('/') || raw.path.length > 2048) throw new LabelError(`${path}.path`);
  if (raw.param !== null && (typeof raw.param !== 'string' || raw.param.length > 100)) throw new LabelError(`${path}.param`);
  const location = raw.location === null ? null : oneOf(raw.location, PARAM_LOCATIONS, `${path}.location`);
  const authState = oneOf(raw.authState, AUTH_STATES, `${path}.authState`);
  return { method, path: raw.path, param: (raw.param as string | null) ?? null, location, authState };
}

/**
 * Canonical identity of a site. Two sites with the same key are the same
 * place. Mirrors the store's dedupe fields minus the rule, so a label and a
 * finding at the same endpoint/parameter/auth role collapse together.
 */
export function siteKey(site: Site): string {
  return JSON.stringify([site.method.toUpperCase(), normalizePath(site.path), site.param, site.location, site.authState]);
}

export function parseLabelSet(raw: unknown): LabelSet {
  if (!record(raw) || raw.version !== 1) throw new LabelError('$');
  if (typeof raw.target !== 'string' || !raw.target) throw new LabelError('$.target');
  if (typeof raw.commit !== 'string' || !/^[0-9a-f]{7,64}$/.test(raw.commit)) throw new LabelError('$.commit');
  if (!Array.isArray(raw.vulnerabilities) || !Array.isArray(raw.negatives)) throw new LabelError('$');

  const seenIds = new Set<string>();
  const seenKeys = new Map<string, string>();
  const vulnerabilities = raw.vulnerabilities.map((v, i): LabeledVuln => {
    const p = `$.vulnerabilities[${i}]`;
    if (!record(v)) throw new LabelError(p);
    if (typeof v.vulnId !== 'string' || !VULN_ID.test(v.vulnId)) throw new LabelError(`${p}.vulnId`);
    if (seenIds.has(v.vulnId)) throw new LabelError(`${p}.vulnId`);
    seenIds.add(v.vulnId);
    const site = parseSite(v.site, `${p}.site`);
    // A site identifies at most one vulnerability, so counts stay by distinct problem.
    const key = `${oneOf(v.type, VULN_TYPES, `${p}.type`)}\u0000${siteKey(site)}`;
    if (seenKeys.has(key)) throw new LabelError(`${p}.site`);
    seenKeys.set(key, v.vulnId);
    return { vulnId: v.vulnId, type: v.type as VulnType, severity: oneOf(v.severity, SEVERITIES, `${p}.severity`), site, split: oneOf(v.split, SPLITS, `${p}.split`) };
  });

  const negatives = raw.negatives.map((n, i): NegativeSite => {
    const p = `$.negatives[${i}]`;
    if (!record(n)) throw new LabelError(p);
    if (typeof n.siteId !== 'string' || !SITE_ID.test(n.siteId)) throw new LabelError(`${p}.siteId`);
    if (seenIds.has(n.siteId)) throw new LabelError(`${p}.siteId`);
    seenIds.add(n.siteId);
    if (n.note !== undefined && (typeof n.note !== 'string' || n.note.length > 500)) throw new LabelError(`${p}.note`);
    return { siteId: n.siteId, site: parseSite(n.site, `${p}.site`), split: oneOf(n.split, SPLITS, `${p}.split`), note: n.note as string | undefined };
  });

  return { version: 1, target: raw.target, commit: raw.commit, vulnerabilities, negatives };
}

/** The final-split subset, with a hash the pass criteria binds to. */
export interface FinalLabels {
  target: string;
  commit: string;
  vulnerabilities: LabeledVuln[];
  negatives: NegativeSite[];
  hash: string;
}

/**
 * Keep only `final` entries and hash them canonically. The hash covers the
 * target, commit and every final site, so a criteria file bound to this hash
 * cannot silently apply to a different or edited truth set.
 */
export function finalLabels(set: LabelSet): FinalLabels {
  const vulnerabilities = set.vulnerabilities.filter(v => v.split === 'final').sort((a, b) => a.vulnId < b.vulnId ? -1 : 1);
  const negatives = set.negatives.filter(n => n.split === 'final').sort((a, b) => a.siteId < b.siteId ? -1 : 1);
  const canonical = JSON.stringify({
    target: set.target,
    commit: set.commit,
    vulnerabilities: vulnerabilities.map(v => [v.vulnId, v.type, v.severity, siteKey(v.site)]),
    negatives: negatives.map(n => [n.siteId, siteKey(n.site)]),
  });
  return { target: set.target, commit: set.commit, vulnerabilities, negatives, hash: createHash('sha256').update(canonical).digest('hex') };
}
