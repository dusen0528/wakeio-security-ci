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
import { siteKey, type FinalLabels, type Severity, type VulnType } from './labels.js';
import type { AuthState, ParamLocation } from '../store.js';

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
}

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
  constructor(readonly code: 'tuning_label_in_scoring' | 'criteria_hash_mismatch' | 'criteria_not_fixed' | 'coverage_basis', detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
  }
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
  /** No-quality-loss gate: B keeps detection and coverage at A's level within one shared budget. */
  qualityHeld: boolean;
  /** B reached the same detection with fewer requests. */
  fewerRequestsSameDetection: boolean;
  /** Usability outcome, recorded apart from detection. */
  producedValidPlanArmAMissed: boolean;
  /** Both arms stayed within the shared cap. */
  withinBudget: boolean;
  reasons: string[];
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
  const a = armResult(armA, labels, criteria.basis, criteria.sharedRequestCap);
  const b = armResult(armB, labels, criteria.basis, criteria.sharedRequestCap);
  const reasons: string[] = [];
  const withinBudget = !a.budget.overBudget && !b.budget.overBudget;
  if (!withinBudget) reasons.push('a round budget exceeded the shared cap');

  const detectionHeld = b.score.tp >= a.score.tp && b.score.fp <= a.score.fp;
  const coverageHeld = (b.coverage.ratio ?? 0) >= (a.coverage.ratio ?? 0);
  const qualityHeld = withinBudget && detectionHeld && coverageHeld;
  if (!detectionHeld) reasons.push(`detection not held: tp ${b.score.tp} vs ${a.score.tp}, fp ${b.score.fp} vs ${a.score.fp}`);
  if (!coverageHeld) reasons.push(`coverage not held: ${b.coverage.ratio} vs ${a.coverage.ratio}`);

  const fewerRequestsSameDetection = withinBudget && b.score.tp === a.score.tp && b.score.fp <= a.score.fp && b.budget.total < a.budget.total;

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
