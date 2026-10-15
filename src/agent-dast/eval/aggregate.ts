/**
 * Offline aggregation for the A vs B comparison.
 *
 * Inputs are synthetic in this version: a list of findings and per-round
 * request counts that a comparison run would produce. Nothing here sends a
 * request, runs an engine or calls a model. It exists to prove the counting is
 * right before any live comparison:
 *
 *   - de-duplication: many findings for one problem count once;
 *   - TP / FP / FN by DISTINCT vulnerability, never by request count;
 *   - total-round budget: initial + verify + retry + expansion summed and
 *     checked against one shared cap, and against arm A's cap;
 *   - final / tuning separation: the scorer refuses tuning labels, and the
 *     pass criteria are bound to the final label hash and attested as fixed
 *     before arm B.
 */
import { createHash } from 'node:crypto';
import { SEVERITIES, VULN_TYPES, siteKey, type FinalLabels, type Severity, type VulnType } from './labels.js';
import { AUTH_STATES, PARAM_LOCATIONS, type AuthState, type ParamLocation } from '../store.js';
import { manifestDigest, verifyManifest, type Checklist, type RunManifest } from './manifest.js';

export type FindingBasis = 'candidate' | 'confirmed';

/** A finding as the harness consumes it (projected from a run, or synthetic). */
export interface EvalFinding {
  findingId: string;
  type: VulnType;
  severity: Severity;
  state: 'candidate' | 'confirmed' | 'rejected';
  method: string;
  path: string;
  param: string | null;
  location: ParamLocation | null;
  authState: AuthState;
  /** 1-based round the finding first appeared in. For reporting only; identity is the site. */
  round: number;
  /** run.db reference this finding came from. findingId is the observation ID (evidence filename), not the engine ID. Required when a run manifest is bound. */
  runRef?: { runId: string; taskId: string };
  /** `evidence/<findingId>.json` path recorded in run.db. Required when a manifest is bound. */
  evidenceRef?: string;
  /** SHA-256 of the evidence file's bytes, checked against the file when an evidence dir is given. */
  evidenceSha256?: string;
}

/** Expected evidence path for a finding, matching the store's recordFinding default. */
export function evidencePath(findingId: string): string { return `evidence/${findingId}.json`; }

export interface RoundBudget {
  /** 1 = initial plan, then verify, retry, expansion… in execution order. */
  round: number;
  kind: 'initial' | 'verify' | 'retry' | 'expansion';
  /** Admitted HTTP attempts in this round (controls included), from the run gate. */
  requestCount: number;
}

const matchKey = (type: VulnType, site: { method: string; path: string; param: string | null; location: ParamLocation | null; authState: AuthState }) =>
  `${type}\u0000${siteKey(site)}`;

export interface DistinctFinding { key: string; type: VulnType; severity: Severity; findingIds: string[]; firstRound: number }

/**
 * Collapse findings that name the same (type, site) into one. Keeps the worst
 * severity and the earliest round. `basis` filters by state first: confirmed
 * scoring drops unconfirmed candidates before counting.
 */
export function dedupeFindings(findings: readonly EvalFinding[], basis: FindingBasis): DistinctFinding[] {
  const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const distinct = new Map<string, DistinctFinding>();
  for (const f of findings) {
    if (f.state === 'rejected') continue;
    if (basis === 'confirmed' && f.state !== 'confirmed') continue;
    const key = matchKey(f.type, f);
    const existing = distinct.get(key);
    if (!existing) { distinct.set(key, { key, type: f.type, severity: f.severity, findingIds: [f.findingId], firstRound: f.round }); continue; }
    existing.findingIds.push(f.findingId);
    if (rank[f.severity] > rank[existing.severity]) existing.severity = f.severity;
    if (f.round < existing.firstRound) existing.firstRound = f.round;
  }
  return [...distinct.values()];
}

export interface ScoreResult {
  basis: FindingBasis;
  /** Distinct final vulnerabilities detected. */
  tp: number;
  /** Final vulnerabilities not detected. */
  fn: number;
  /** Distinct findings matching no final vulnerability (negative or unlabeled site). */
  fp: number;
  /** Final vulnerabilities present (tp + fn). */
  positives: number;
  /** tp / positives, or null when there are no positives. */
  recall: number | null;
  /** tp / (tp + fp), or null when nothing was flagged. */
  precision: number | null;
  detected: string[];
  missed: string[];
  falsePositiveKeys: string[];
}

export class EvalError extends Error {
  constructor(readonly code: 'tuning_label_in_scoring' | 'criteria_hash_mismatch' | 'criteria_not_fixed' | 'coverage_basis' | 'denominator_mismatch' | 'results_invalid', detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function intField(raw: Record<string, unknown>, key: string, path: string, min: number): number {
  const value = raw[key];
  if (!Number.isSafeInteger(value) || (value as number) < min) throw new EvalError('results_invalid', `${path}.${key}`);
  return value as number;
}

function strIn<T extends string>(raw: Record<string, unknown>, key: string, options: readonly T[], path: string): T {
  const value = raw[key];
  if (typeof value !== 'string' || !(options as readonly string[]).includes(value)) throw new EvalError('results_invalid', `${path}.${key}`);
  return value as T;
}

/** Validate one finding from an untrusted results bundle into the harness shape. */
export function parseEvalFinding(raw: unknown, path: string): EvalFinding {
  if (!record(raw)) throw new EvalError('results_invalid', path);
  if (typeof raw.findingId !== 'string' || !/^f-[0-9a-z-]{1,40}$/.test(raw.findingId)) throw new EvalError('results_invalid', `${path}.findingId`);
  if (typeof raw.method !== 'string' || !/^[A-Z]{3,7}$/.test(raw.method)) throw new EvalError('results_invalid', `${path}.method`);
  if (typeof raw.path !== 'string' || !raw.path.startsWith('/') || raw.path.length > 2048) throw new EvalError('results_invalid', `${path}.path`);
  if (raw.param !== null && (typeof raw.param !== 'string' || raw.param.length > 100)) throw new EvalError('results_invalid', `${path}.param`);
  const location = raw.location === null ? null : strIn(raw, 'location', PARAM_LOCATIONS, path);
  const finding: EvalFinding = {
    findingId: raw.findingId,
    type: strIn(raw, 'type', VULN_TYPES, path),
    severity: strIn(raw, 'severity', SEVERITIES, path),
    state: strIn(raw, 'state', ['candidate', 'confirmed', 'rejected'] as const, path),
    method: raw.method,
    path: raw.path,
    param: (raw.param as string | null) ?? null,
    location,
    authState: strIn(raw, 'authState', AUTH_STATES, path),
    round: intField(raw, 'round', path, 1),
  };
  if (raw.runRef !== undefined) {
    if (!record(raw.runRef) || typeof raw.runRef.runId !== 'string' || !/^r-[0-9a-z-]{1,40}$/.test(raw.runRef.runId)
      || typeof raw.runRef.taskId !== 'string' || !/^t-[0-9a-z-]{1,60}$/.test(raw.runRef.taskId)) throw new EvalError('results_invalid', `${path}.runRef`);
    finding.runRef = { runId: raw.runRef.runId, taskId: raw.runRef.taskId };
  }
  if (raw.evidenceRef !== undefined) {
    if (raw.evidenceRef !== evidencePath(finding.findingId)) throw new EvalError('results_invalid', `${path}.evidenceRef`);
    finding.evidenceRef = raw.evidenceRef;
  }
  if (raw.evidenceSha256 !== undefined) {
    if (typeof raw.evidenceSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(raw.evidenceSha256)) throw new EvalError('results_invalid', `${path}.evidenceSha256`);
    finding.evidenceSha256 = raw.evidenceSha256;
  }
  return finding;
}

const ROUND_KINDS = ['initial', 'verify', 'retry', 'expansion'] as const;

export function parseRoundBudget(raw: unknown, path: string): RoundBudget {
  if (!record(raw)) throw new EvalError('results_invalid', path);
  return { round: intField(raw, 'round', path, 1), kind: strIn(raw, 'kind', ROUND_KINDS, path), requestCount: intField(raw, 'requestCount', path, 0) };
}

/** Validate an arm (`armA`/`armB`) from an untrusted results bundle. */
export function parseArm(raw: unknown, name: 'A' | 'B'): Arm {
  const path = `arm${name}`;
  if (!record(raw)) throw new EvalError('results_invalid', path);
  if (raw.name !== name) throw new EvalError('results_invalid', `${path}.name`);
  if (!Array.isArray(raw.findings)) throw new EvalError('results_invalid', `${path}.findings`);
  if (!Array.isArray(raw.rounds) || raw.rounds.length === 0) throw new EvalError('results_invalid', `${path}.rounds`);
  if (!record(raw.coverage)) throw new EvalError('results_invalid', `${path}.coverage`);
  const findingIds = new Set<string>();
  const findings = raw.findings.map((f, i) => {
    const finding = parseEvalFinding(f, `${path}.findings[${i}]`);
    if (findingIds.has(finding.findingId)) throw new EvalError('results_invalid', `${path}.findings[${i}].findingId`);
    findingIds.add(finding.findingId);
    return finding;
  });
  const arm: Arm = {
    name,
    findings,
    rounds: raw.rounds.map((r, i) => parseRoundBudget(r, `${path}.rounds[${i}]`)),
    coverage: { plannedCells: intField(raw.coverage, 'plannedCells', `${path}.coverage`, 0), executedCells: intField(raw.coverage, 'executedCells', `${path}.coverage`, 0) },
    durationMs: intField(raw, 'durationMs', path, 0),
  };
  if (raw.tokens !== undefined) arm.tokens = intField(raw, 'tokens', path, 0);
  if (raw.producedValidPlanArmAMissed !== undefined) {
    if (typeof raw.producedValidPlanArmAMissed !== 'boolean') throw new EvalError('results_invalid', `${path}.producedValidPlanArmAMissed`);
    arm.producedValidPlanArmAMissed = raw.producedValidPlanArmAMissed;
  }
  return arm;
}

export interface ResultsBundle { manifestDigest?: string; armA: Arm; armB: Arm }

export function parseResultsBundle(raw: unknown): ResultsBundle {
  if (!record(raw)) throw new EvalError('results_invalid', '$');
  const bundle: ResultsBundle = { armA: parseArm(raw.armA, 'A'), armB: parseArm(raw.armB, 'B') };
  if (raw.manifestDigest !== undefined) {
    if (typeof raw.manifestDigest !== 'string' || !/^[0-9a-f]{64}$/.test(raw.manifestDigest)) throw new EvalError('results_invalid', 'manifestDigest');
    bundle.manifestDigest = raw.manifestDigest;
  }
  return bundle;
}

/**
 * Score findings against FINAL labels only. The caller passes `finalLabels()`
 * output; passing a set that still holds tuning entries is a programming error
 * the type does not prevent, so guard on it: every scored vuln must be final.
 */
export function scoreRun(findings: readonly EvalFinding[], labels: FinalLabels, basis: FindingBasis): ScoreResult {
  if (labels.vulnerabilities.some(v => v.split !== 'final') || labels.negatives.some(n => n.split !== 'final')) {
    throw new EvalError('tuning_label_in_scoring');
  }
  const distinct = dedupeFindings(findings, basis);
  const vulnByKey = new Map(labels.vulnerabilities.map(v => [matchKey(v.type, v.site), v]));
  const detected = new Set<string>();
  const falsePositiveKeys: string[] = [];
  for (const d of distinct) {
    const vuln = vulnByKey.get(d.key);
    if (vuln) detected.add(vuln.vulnId);
    else falsePositiveKeys.push(d.key);
  }
  const missed = labels.vulnerabilities.filter(v => !detected.has(v.vulnId)).map(v => v.vulnId);
  const tp = detected.size;
  const fn = missed.length;
  const fp = falsePositiveKeys.length;
  const positives = tp + fn;
  return {
    basis, tp, fn, fp, positives,
    recall: positives === 0 ? null : tp / positives,
    precision: tp + fp === 0 ? null : tp / (tp + fp),
    detected: [...detected].sort(),
    missed,
    falsePositiveKeys: falsePositiveKeys.sort(),
  };
}

export interface CoverageInput {
  /** Endpoint×parameter×check cells fixed BEFORE the run. This is the denominator. */
  plannedCells: number;
  /** Cells actually executed, from the run's coverage rows. */
  executedCells: number;
}

export interface CoverageResult { planned: number; executed: number; ratio: number | null }

/** Coverage is executed over a denominator fixed before the run — never the run's own audit count. */
export function coverage(input: CoverageInput): CoverageResult {
  if (!Number.isSafeInteger(input.plannedCells) || input.plannedCells < 0) throw new EvalError('coverage_basis', 'plannedCells');
  if (!Number.isSafeInteger(input.executedCells) || input.executedCells < 0) throw new EvalError('coverage_basis', 'executedCells');
  if (input.executedCells > input.plannedCells) throw new EvalError('coverage_basis', 'executed exceeds planned');
  return { planned: input.plannedCells, executed: input.executedCells, ratio: input.plannedCells === 0 ? null : input.executedCells / input.plannedCells };
}

export interface BudgetResult {
  rounds: number;
  total: number;
  cap: number;
  overBudget: boolean;
  perKind: Record<RoundBudget['kind'], number>;
}

/**
 * Sum admitted requests across EVERY round and compare to one shared cap.
 * Re-invoking run-plan does not grant a fresh cap: initial, verify, retry and
 * expansion all draw from the same total.
 */
export function sumRoundBudget(rounds: readonly RoundBudget[], sharedCap: number): BudgetResult {
  if (!Number.isSafeInteger(sharedCap) || sharedCap < 1) throw new EvalError('coverage_basis', 'sharedCap');
  const perKind: Record<RoundBudget['kind'], number> = { initial: 0, verify: 0, retry: 0, expansion: 0 };
  let total = 0;
  for (const r of rounds) {
    if (!Number.isSafeInteger(r.requestCount) || r.requestCount < 0) throw new EvalError('coverage_basis', 'requestCount');
    perKind[r.kind] += r.requestCount;
    total += r.requestCount;
  }
  return { rounds: rounds.length, total, cap: sharedCap, overBudget: total > sharedCap, perKind };
}

export interface Arm {
  name: 'A' | 'B';
  findings: readonly EvalFinding[];
  rounds: readonly RoundBudget[];
  coverage: CoverageInput;
  /** Wall time including model deliberation for B. Milliseconds. */
  durationMs: number;
  /** Model tokens, B only; A is 0. */
  tokens?: number;
  /** Recorded separately as a usability outcome, not a detection result. */
  producedValidPlanArmAMissed?: boolean;
}

export interface ArmResult {
  name: 'A' | 'B';
  score: ScoreResult;
  coverage: CoverageResult;
  budget: BudgetResult;
  durationMs: number;
  tokens: number;
}

export interface PassCriteria {
  version: 1;
  /** Must equal finalLabels().hash, or scoring refuses to issue a verdict. */
  labelSetHash: string;
  /** Attestation that criteria were fixed before arm B ran. */
  committedBeforeArmB: true;
  sharedRequestCap: number;
  basis: FindingBasis;
}

export function parsePassCriteria(raw: unknown): PassCriteria {
  const r = raw as Record<string, unknown>;
  if (!r || typeof r !== 'object' || r.version !== 1) throw new EvalError('criteria_not_fixed', 'version');
  if (typeof r.labelSetHash !== 'string' || !/^[0-9a-f]{64}$/.test(r.labelSetHash)) throw new EvalError('criteria_not_fixed', 'labelSetHash');
  if (r.committedBeforeArmB !== true) throw new EvalError('criteria_not_fixed', 'committedBeforeArmB');
  if (!Number.isSafeInteger(r.sharedRequestCap) || (r.sharedRequestCap as number) < 1) throw new EvalError('criteria_not_fixed', 'sharedRequestCap');
  if (r.basis !== 'candidate' && r.basis !== 'confirmed') throw new EvalError('criteria_not_fixed', 'basis');
  return { version: 1, labelSetHash: r.labelSetHash, committedBeforeArmB: true, sharedRequestCap: r.sharedRequestCap as number, basis: r.basis };
}

export interface Comparison {
  a: ArmResult;
  b: ArmResult;
  /** No-quality-loss gate: B detects every vulnerability A did (by identity, not count), adds no false positive, and holds coverage, within one shared budget. */
  qualityHeld: boolean;
  /** B detected exactly A's vulnerability set with no new false positive and fewer total requests. */
  fewerRequestsSameDetection: boolean;
  /** Usability outcome, recorded apart from detection. */
  producedValidPlanArmAMissed: boolean;
  /** Both arms stayed within the shared cap. */
  withinBudget: boolean;
  reasons: string[];
}

function subset(a: readonly string[], b: readonly string[]): boolean {
  const set = new Set(b);
  return a.every(x => set.has(x));
}

function sameSet(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && subset(a, b);
}

function armResult(arm: Arm, labels: FinalLabels, basis: FindingBasis, sharedCap: number): ArmResult {
  return {
    name: arm.name,
    score: scoreRun(arm.findings, labels, basis),
    coverage: coverage(arm.coverage),
    budget: sumRoundBudget(arm.rounds, sharedCap),
    durationMs: arm.durationMs,
    tokens: arm.tokens ?? 0,
  };
}

/**
 * Compare one run of each arm. Issues the comparison only when criteria are
 * bound to this exact final label set and attested as fixed beforehand. This
 * is a single-run comparison; the N-repeat majority is a preliminary step the
 * caller runs on top, deciding the final verdict before seeing arm B.
 */
export function compareArms(armA: Arm, armB: Arm, labels: FinalLabels, criteria: PassCriteria): Comparison {
  if (criteria.labelSetHash !== labels.hash) throw new EvalError('criteria_hash_mismatch', `criteria ${criteria.labelSetHash.slice(0, 12)} vs labels ${labels.hash.slice(0, 12)}`);
  // Coverage ratios compare only against one shared, pre-fixed denominator; a
  // per-arm denominator would make the ratio comparison meaningless.
  if (armA.coverage.plannedCells !== armB.coverage.plannedCells) {
    throw new EvalError('denominator_mismatch', `A planned ${armA.coverage.plannedCells}, B planned ${armB.coverage.plannedCells}`);
  }
  const a = armResult(armA, labels, criteria.basis, criteria.sharedRequestCap);
  const b = armResult(armB, labels, criteria.basis, criteria.sharedRequestCap);
  const reasons: string[] = [];
  const withinBudget = !a.budget.overBudget && !b.budget.overBudget;
  if (!withinBudget) reasons.push('a round budget exceeded the shared cap');

  // By identity, not count: B must detect every vulnerability A detected, so a
  // same-count run that swapped one detection for another does not pass.
  const keptAllOfA = subset(a.score.detected, b.score.detected);
  const noNewFalsePositive = subset(b.score.falsePositiveKeys, a.score.falsePositiveKeys);
  const coverageHeld = (b.coverage.ratio ?? 0) >= (a.coverage.ratio ?? 0);
  const qualityHeld = withinBudget && keptAllOfA && noNewFalsePositive && coverageHeld;
  if (!keptAllOfA) reasons.push(`detection not held: B missed ${a.score.detected.filter(v => !b.score.detected.includes(v)).join(', ') || '(none)'}`);
  if (!noNewFalsePositive) reasons.push('B introduced a false positive A did not have');
  if (!coverageHeld) reasons.push(`coverage not held: ${b.coverage.ratio} vs ${a.coverage.ratio}`);

  // "Same detection" is set equality on vulnerabilities plus no new false
  // positive — not an equal TP count, which can hide a swapped detection.
  const fewerRequestsSameDetection = withinBudget
    && sameSet(a.score.detected, b.score.detected)
    && noNewFalsePositive
    && b.budget.total < a.budget.total;

  return {
    a, b, qualityHeld, fewerRequestsSameDetection,
    producedValidPlanArmAMissed: armB.producedValidPlanArmAMissed === true,
    withinBudget, reasons,
  };
}

/** Hash of a synthetic-results bundle, so a stored comparison names its exact inputs. */
export function inputsDigest(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

// --- Evidence linking: bind results to a run-start record and finding evidence ---

export type ProvenanceStatus =
  | 'ok'                    // reference, hash AND evidence content all agree
  | 'missing_ref' | 'bad_ref' | 'missing_run_ref'
  | 'evidence_absent' | 'evidence_mismatch'   // file missing / byte hash wrong
  | 'evidence_unreadable'   // not the stored evidence JSON format
  | 'evidence_content_mismatch'  // JSON present and hash-correct, but names a different finding/run/task
  | 'hash_ok_unverified'    // byte hash/format matched; DB/report linkage was not checked
  | 'evidence_unchecked';   // reference present and well-formed; no evidence read at all

/** What was actually confirmed, so a hash-only check is never reported as provenance. */
export interface ProvenanceResult {
  findingId: string;
  status: ProvenanceStatus;
  refOk: boolean;
  hashChecked: boolean;
  hashOk: boolean;
  /** True only when stored DB observation, evidence and task report agree. */
  contentOk: boolean;
}

/** The minimal stored-evidence shape the harness cross-checks against a finding. */
export interface EvidenceDoc { version: 1; findingId: string; taskId: string; reportPath: string; ruleId: string; severity: Severity; kind: 'candidate' | 'observation' | 'advisory' }
export type VerifyStoredFinding = (finding: EvalFinding, evidence: EvidenceDoc) => boolean;

function parseEvidenceDoc(bytes: Buffer): EvidenceDoc | null {
  let value: unknown;
  try { value = JSON.parse(bytes.toString('utf8')); } catch { return null; }
  if (!record(value)) return null;
  if (value.version !== 1 || typeof value.findingId !== 'string' || !value.findingId
    || typeof value.taskId !== 'string' || !/^t-[0-9a-z-]{1,60}$/.test(value.taskId)
    || value.reportPath !== `tasks/${value.taskId}/report.json`
    || typeof value.ruleId !== 'string' || !value.ruleId
    || !SEVERITIES.includes(value.severity as Severity)
    || !['candidate', 'observation', 'advisory'].includes(value.kind as string)) return null;
  return value as unknown as EvidenceDoc;
}

/**
 * Check one finding's link to recorded evidence. A byte-hash match alone is not
 * provenance: when the evidence file is read it is also parsed as the stored
 * evidence JSON and its taskId and engine findingId are linked through run.db observations and the
 * referenced task report; the file itself contains no run ID. The result reports ref, hash and content separately so
 * a hash-only pass can never be read as a verified source.
 */
export function verifyFindingProvenance(finding: EvalFinding, readEvidence?: (relPath: string) => Buffer | null, verifyStoredFinding?: VerifyStoredFinding): ProvenanceResult {
  const id = finding.findingId;
  const base = { findingId: id, refOk: false, hashChecked: false, hashOk: false, contentOk: false };
  if (!finding.runRef) return { ...base, status: 'missing_run_ref' };
  if (!finding.evidenceRef) return { ...base, status: 'missing_ref' };
  if (finding.evidenceRef !== evidencePath(id)) return { ...base, status: 'bad_ref' };
  base.refOk = true;
  if (!readEvidence) return { ...base, status: 'evidence_unchecked' };
  const bytes = readEvidence(finding.evidenceRef);
  if (bytes === null) return { ...base, status: 'evidence_absent' };
  base.hashChecked = true;
  base.hashOk = !!finding.evidenceSha256 && createHash('sha256').update(bytes).digest('hex') === finding.evidenceSha256;
  if (!base.hashOk) return { ...base, status: 'evidence_mismatch' };
  const doc = parseEvidenceDoc(bytes);
  if (!doc) return { ...base, status: 'evidence_unreadable' };
  if (doc.taskId !== finding.runRef.taskId || doc.severity !== finding.severity) return { ...base, status: 'evidence_content_mismatch' };
  if (!verifyStoredFinding) return { ...base, status: 'hash_ok_unverified' };
  base.contentOk = verifyStoredFinding(finding, doc);
  if (!base.contentOk) return { ...base, status: 'evidence_content_mismatch' };
  return { ...base, status: 'ok' };
}

export interface ArmProvenance { name: 'A' | 'B'; findings: ProvenanceResult[]; allOk: boolean }

function armProvenance(arm: Arm, readEvidence?: (relPath: string, finding: EvalFinding) => Buffer | null, verifyStoredFinding?: VerifyStoredFinding): ArmProvenance {
  const findings = arm.findings.map(f => verifyFindingProvenance(f, readEvidence ? path => readEvidence(path, f) : undefined, verifyStoredFinding));
  return { name: arm.name, findings, allOk: findings.every(r => r.status === 'ok') };
}

export interface Evaluation {
  manifestDigest: string;
  manifestVerified: boolean;
  provenance: { a: ArmProvenance; b: ArmProvenance; allOk: boolean };
  comparison: Comparison;
}

/**
 * Full offline evaluation from stored results: confirm the run-start record is
 * untampered and matches the criteria, labels and check list; confirm the
 * results reference that record and every finding links to recorded evidence;
 * then score the comparison. No request, engine or model.
 *
 * `evidenceChecked` controls strictness: when false (no evidence directory
 * available), a present, well-formed reference is accepted as
 * `evidence_unchecked` and does not fail the evaluation; when true, every
 * finding's evidence file must exist and match its hash.
 */
export function evaluate(input: {
  manifest: RunManifest;
  bundle: ResultsBundle;
  labels: FinalLabels;
  criteria: PassCriteria;
  checklist: Checklist;
  readEvidence?: (relPath: string, finding: EvalFinding) => Buffer | null;
  verifyStoredFinding?: VerifyStoredFinding;
  evidenceChecked: boolean;
}): Evaluation {
  const digest = manifestDigest(input.manifest);
  // The record must be internally consistent with the three inputs it pins, and
  // its plain fields (target, commit, cap, basis, coverage cells) must agree…
  verifyManifest(input.manifest, digest, { labels: input.labels, criteria: input.criteria, checklist: input.checklist });
  // …and the results must reference exactly this record.
  if (input.bundle.manifestDigest !== digest) throw new EvalError('results_invalid', 'bundle.manifestDigest does not reference the run-start record');

  // The coverage denominator is the fixed cell count, not a free number per arm.
  const denominator = input.manifest.coverageCells.length;
  for (const arm of [input.bundle.armA, input.bundle.armB]) {
    if (arm.coverage.plannedCells !== denominator) {
      throw new EvalError('denominator_mismatch', `arm ${arm.name} planned ${arm.coverage.plannedCells}, run-start fixed ${denominator}`);
    }
  }

  const read = input.evidenceChecked ? input.readEvidence : undefined;
  const a = armProvenance(input.bundle.armA, read, input.verifyStoredFinding);
  const b = armProvenance(input.bundle.armB, read, input.verifyStoredFinding);
  // Without an evidence directory only the reference shape is confirmed; a
  // hash-only or unchecked state is not accepted as provenance when checking is on.
  const accept = (s: ProvenanceStatus) => s === 'ok' || (!input.evidenceChecked && s === 'evidence_unchecked');
  const allOk = [...a.findings, ...b.findings].every(r => accept(r.status));

  const comparison = compareArms(input.bundle.armA, input.bundle.armB, input.labels, input.criteria);
  return { manifestDigest: digest, manifestVerified: true, provenance: { a, b, allOk }, comparison };
}
