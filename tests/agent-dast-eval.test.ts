import test from 'node:test';
import assert from 'node:assert/strict';
import { finalLabels, parseLabelSet, siteKey, type LabelSet } from '../src/agent-dast/eval/labels.js';
import {
  EvalError, compareArms, coverage, dedupeFindings, parseArm, parsePassCriteria, parseResultsBundle, scoreRun, sumRoundBudget,
  type Arm, type EvalFinding, type RoundBudget,
} from '../src/agent-dast/eval/aggregate.js';

function labelSet(): LabelSet {
  return parseLabelSet({
    version: 1, target: 'fixture', commit: 'abc1234',
    vulnerabilities: [
      { vulnId: 'v-sqli-login', type: 'sqli', severity: 'high', split: 'final',
        site: { method: 'POST', path: '/rest/user/login', param: 'email', location: 'body', authState: 'anonymous' } },
      { vulnId: 'v-idor-basket', type: 'authz', severity: 'high', split: 'final',
        site: { method: 'GET', path: '/rest/basket/1', param: null, location: null, authState: 'user' } },
      { vulnId: 'v-tuning-xss', type: 'xss', severity: 'medium', split: 'tuning',
        site: { method: 'GET', path: '/search', param: 'q', location: 'query', authState: 'anonymous' } },
    ],
    negatives: [
      { siteId: 'n-products', split: 'final', site: { method: 'GET', path: '/rest/products', param: null, location: null, authState: 'anonymous' } },
    ],
  });
}

function finding(over: Partial<EvalFinding>): EvalFinding {
  return {
    findingId: 'f-1', type: 'sqli', severity: 'high', state: 'confirmed',
    method: 'POST', path: '/rest/user/login', param: 'email', location: 'body', authState: 'anonymous', round: 1, ...over,
  };
}

test('a site maps to one labeled vulnerability and path ids are normalized for matching', () => {
  const labels = finalLabels(labelSet());
  // /rest/basket/1 (label) and /rest/basket/7 (finding) are the same site after normalization.
  assert.equal(siteKey({ method: 'GET', path: '/rest/basket/1', param: null, location: null, authState: 'user' }),
    siteKey({ method: 'GET', path: '/rest/basket/7', param: null, location: null, authState: 'user' }));
  assert.equal(labels.vulnerabilities.length, 2); // tuning filtered out
});

test('duplicate vulnId or duplicate (type, site) in a label set is rejected', () => {
  assert.throws(() => parseLabelSet({ version: 1, target: 't', commit: 'abc1234', negatives: [],
    vulnerabilities: [
      { vulnId: 'v-a', type: 'sqli', severity: 'high', split: 'final', site: { method: 'GET', path: '/x', param: 'a', location: 'query', authState: 'anonymous' } },
      { vulnId: 'v-a', type: 'xss', severity: 'low', split: 'final', site: { method: 'GET', path: '/y', param: 'b', location: 'query', authState: 'anonymous' } },
    ] }), /vulnId/);
  assert.throws(() => parseLabelSet({ version: 1, target: 't', commit: 'abc1234', negatives: [],
    vulnerabilities: [
      { vulnId: 'v-a', type: 'sqli', severity: 'high', split: 'final', site: { method: 'GET', path: '/x/1', param: 'a', location: 'query', authState: 'anonymous' } },
      { vulnId: 'v-b', type: 'sqli', severity: 'high', split: 'final', site: { method: 'GET', path: '/x/2', param: 'a', location: 'query', authState: 'anonymous' } },
    ] }), /site/);
});

test('TP/FP/FN count distinct vulnerabilities, not requests: repeated hits on one vuln are one TP', () => {
  const labels = finalLabels(labelSet());
  const findings: EvalFinding[] = [
    finding({ findingId: 'f-1', round: 1 }),
    finding({ findingId: 'f-2', round: 2 }),           // same vuln, re-hit across rounds
    finding({ findingId: 'f-3', path: '/rest/user/login', param: 'email', round: 3 }), // same site again
    finding({ findingId: 'f-4', type: 'authz', severity: 'high', method: 'GET', path: '/rest/basket/9', param: null, location: null, authState: 'user', round: 2 }),
  ];
  const score = scoreRun(findings, labels, 'confirmed');
  assert.equal(score.tp, 2);
  assert.equal(score.fn, 0);
  assert.equal(score.fp, 0);
  assert.equal(score.recall, 1);
  assert.deepEqual(score.detected, ['v-idor-basket', 'v-sqli-login']);
});

test('a finding at a negative or unlabeled site is one FP, deduped across repeats', () => {
  const labels = finalLabels(labelSet());
  const findings: EvalFinding[] = [
    finding({ findingId: 'f-1', type: 'sqli', method: 'GET', path: '/rest/products', param: 'sort', location: 'query', authState: 'anonymous', round: 1 }),
    finding({ findingId: 'f-2', type: 'sqli', method: 'GET', path: '/rest/products', param: 'sort', location: 'query', authState: 'anonymous', round: 3 }),
  ];
  const score = scoreRun(findings, labels, 'confirmed');
  assert.equal(score.tp, 0);
  assert.equal(score.fp, 1);
  assert.equal(score.fn, 2);
});

test('confirmed basis drops unconfirmed candidates; candidate basis keeps them', () => {
  const labels = finalLabels(labelSet());
  const findings: EvalFinding[] = [finding({ state: 'candidate' })];
  assert.equal(scoreRun(findings, labels, 'confirmed').tp, 0);
  assert.equal(scoreRun(findings, labels, 'candidate').tp, 1);
  assert.equal(dedupeFindings([finding({ state: 'rejected' })], 'candidate').length, 0);
});

test('a matching finding type is required: right site, wrong type is not a detection', () => {
  const labels = finalLabels(labelSet());
  const wrongType = finding({ type: 'xss' }); // login site is labeled sqli
  const score = scoreRun([wrongType], labels, 'confirmed');
  assert.equal(score.tp, 0);
  assert.equal(score.fp, 1);
});

test('scoring refuses a label set that still contains tuning entries', () => {
  const set = labelSet();
  const leaky = { ...finalLabels(set), vulnerabilities: set.vulnerabilities }; // includes the tuning entry
  assert.throws(() => scoreRun([], leaky, 'confirmed'), (e: unknown) => e instanceof EvalError && e.code === 'tuning_label_in_scoring');
});

test('round budgets sum across every round and compare to one shared cap', () => {
  const rounds: RoundBudget[] = [
    { round: 1, kind: 'initial', requestCount: 30 },
    { round: 2, kind: 'verify', requestCount: 12 },
    { round: 3, kind: 'retry', requestCount: 8 },
    { round: 4, kind: 'expansion', requestCount: 20 },
  ];
  const r = sumRoundBudget(rounds, 64);
  assert.equal(r.total, 70);
  assert.equal(r.overBudget, true); // 70 > 64: re-invocation does not grant a fresh cap
  assert.deepEqual(r.perKind, { initial: 30, verify: 12, retry: 8, expansion: 20 });
  assert.equal(sumRoundBudget(rounds.slice(0, 2), 64).overBudget, false);
});

test('coverage denominator must be fixed and cannot be exceeded by executed cells', () => {
  assert.deepEqual(coverage({ plannedCells: 40, executedCells: 38 }), { planned: 40, executed: 38, ratio: 38 / 40 });
  assert.throws(() => coverage({ plannedCells: 40, executedCells: 41 }), /coverage_basis/);
});

test('pass criteria must be bound to the final label hash and attested as fixed before arm B', () => {
  const labels = finalLabels(labelSet());
  const base = { version: 1, labelSetHash: labels.hash, committedBeforeArmB: true, sharedRequestCap: 64, basis: 'confirmed' };
  assert.doesNotThrow(() => parsePassCriteria(base));
  assert.throws(() => parsePassCriteria({ ...base, committedBeforeArmB: false }), /criteria_not_fixed/);
  const criteria = parsePassCriteria({ ...base, labelSetHash: 'f'.repeat(64) });
  const arm = (name: 'A' | 'B'): Arm => ({ name, findings: [], rounds: [{ round: 1, kind: 'initial', requestCount: 1 }], coverage: { plannedCells: 1, executedCells: 1 }, durationMs: 1 });
  assert.throws(() => compareArms(arm('A'), arm('B'), labels, criteria), (e: unknown) => e instanceof EvalError && e.code === 'criteria_hash_mismatch');
});

test('comparison holds quality and flags fewer-requests value, within one shared budget', () => {
  const labels = finalLabels(labelSet());
  const criteria = parsePassCriteria({ version: 1, labelSetHash: labels.hash, committedBeforeArmB: true, sharedRequestCap: 64, basis: 'confirmed' });
  const detect = (round: number): EvalFinding[] => [
    finding({ findingId: 'f-a', round }),
    finding({ findingId: 'f-b', type: 'authz', severity: 'high', method: 'GET', path: '/rest/basket/3', param: null, location: null, authState: 'user', round }),
  ];
  const armA: Arm = { name: 'A', findings: detect(1), rounds: [{ round: 1, kind: 'initial', requestCount: 60 }], coverage: { plannedCells: 40, executedCells: 40 }, durationMs: 5000 };
  const armB: Arm = { name: 'B', findings: detect(1), rounds: [{ round: 1, kind: 'initial', requestCount: 24 }, { round: 2, kind: 'verify', requestCount: 12 }], coverage: { plannedCells: 40, executedCells: 40 }, durationMs: 9000, tokens: 18000, producedValidPlanArmAMissed: true };
  const cmp = compareArms(armA, armB, labels, criteria);
  assert.equal(cmp.withinBudget, true);
  assert.equal(cmp.qualityHeld, true);
  assert.equal(cmp.fewerRequestsSameDetection, true); // 36 < 60 at equal detection
  assert.equal(cmp.producedValidPlanArmAMissed, true);
  assert.equal(cmp.b.tokens, 18000);
  // If B loses a detection, quality is not held.
  const worseB: Arm = { ...armB, findings: [finding({ findingId: 'f-a' })] };
  assert.equal(compareArms(armA, worseB, labels, criteria).qualityHeld, false);
});

// --- Regression: three issues raised in review of PR #60 ---

const idorFinding = (round: number): EvalFinding => finding({ findingId: 'f-idor', type: 'authz', severity: 'high', method: 'GET', path: '/rest/basket/3', param: null, location: null, authState: 'user', round });

test('regression: a per-arm coverage denominator is refused; ratios compare only against one shared denominator', () => {
  const labels = finalLabels(labelSet());
  const criteria = parsePassCriteria({ version: 1, labelSetHash: labels.hash, committedBeforeArmB: true, sharedRequestCap: 64, basis: 'confirmed' });
  const mk = (planned: number): Arm => ({ name: 'A', findings: [finding({})], rounds: [{ round: 1, kind: 'initial', requestCount: 10 }], coverage: { plannedCells: planned, executedCells: planned }, durationMs: 1 });
  const armA = mk(40);
  const armB: Arm = { ...mk(20), name: 'B' }; // B measured against a smaller denominator → 20/20 would falsely "hold"
  assert.throws(() => compareArms(armA, armB, labels, criteria), (e: unknown) => e instanceof EvalError && e.code === 'denominator_mismatch');
});

test('regression: equal TP count with a different detection set is not "same detection" and does not hold quality', () => {
  const labels = finalLabels(labelSet());
  const criteria = parsePassCriteria({ version: 1, labelSetHash: labels.hash, committedBeforeArmB: true, sharedRequestCap: 64, basis: 'confirmed' });
  const cov = { plannedCells: 40, executedCells: 40 };
  // A detects {sqli}; B detects {idor}. Same tp count (1), disjoint sets.
  const armA: Arm = { name: 'A', findings: [finding({})], rounds: [{ round: 1, kind: 'initial', requestCount: 50 }], coverage: cov, durationMs: 1 };
  const armB: Arm = { name: 'B', findings: [idorFinding(1)], rounds: [{ round: 1, kind: 'initial', requestCount: 20 }], coverage: cov, durationMs: 1 };
  const cmp = compareArms(armA, armB, labels, criteria);
  assert.equal(cmp.b.score.tp, cmp.a.score.tp); // equal count…
  assert.equal(cmp.qualityHeld, false);          // …but B dropped the vuln A found
  assert.equal(cmp.fewerRequestsSameDetection, false); // fewer requests, but NOT the same detection set
  assert.ok(cmp.reasons.some(r => r.includes('v-sqli-login')));
});

test('regression: fewer-requests value requires the exact same detection set, not just an equal count', () => {
  const labels = finalLabels(labelSet());
  const criteria = parsePassCriteria({ version: 1, labelSetHash: labels.hash, committedBeforeArmB: true, sharedRequestCap: 64, basis: 'confirmed' });
  const cov = { plannedCells: 40, executedCells: 40 };
  const both = (round: number): EvalFinding[] => [finding({ findingId: 'f-s', round }), idorFinding(round)];
  const armA: Arm = { name: 'A', findings: both(1), rounds: [{ round: 1, kind: 'initial', requestCount: 60 }], coverage: cov, durationMs: 1 };
  const armB: Arm = { name: 'B', findings: both(1), rounds: [{ round: 1, kind: 'initial', requestCount: 30 }], coverage: cov, durationMs: 1 };
  assert.equal(compareArms(armA, armB, labels, criteria).fewerRequestsSameDetection, true);
});

test('regression: a malformed results bundle is rejected before counting', () => {
  const good = { findingId: 'f-1', type: 'sqli', severity: 'high', state: 'confirmed', method: 'POST', path: '/x', param: 'e', location: 'body', authState: 'anonymous', round: 1 };
  const arm = (findings: unknown[]) => ({ name: 'A', findings, rounds: [{ round: 1, kind: 'initial', requestCount: 1 }], coverage: { plannedCells: 1, executedCells: 1 }, durationMs: 0 });
  assert.doesNotThrow(() => parseArm(arm([good]), 'A'));
  assert.throws(() => parseArm(arm([{ ...good, type: 'sqlinjection' }]), 'A'), /results_invalid.*type/);
  assert.throws(() => parseArm(arm([{ ...good, round: 0 }]), 'A'), /results_invalid.*round/);
  assert.throws(() => parseArm(arm([{ ...good, authState: 'root' }]), 'A'), /results_invalid.*authState/);
  assert.throws(() => parseArm(arm([good, good]), 'A'), /findings\[1\]\.findingId/); // duplicate id
  assert.throws(() => parseArm({ ...arm([]), rounds: [] }, 'A'), /results_invalid.*rounds/);
  assert.throws(() => parseArm(arm([good]), 'B'), /arm.*name/); // name must match the slot
  assert.throws(() => parseResultsBundle({ armA: arm([good]) }, ), /results_invalid/); // missing armB
});
