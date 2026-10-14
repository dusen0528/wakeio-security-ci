import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { finalLabels, parseLabelSet, type LabelSet } from '../src/agent-dast/eval/labels.js';
import {
  evaluate, parsePassCriteria, verifyFindingProvenance, type Arm, type EvalFinding, type PassCriteria, type ResultsBundle,
} from '../src/agent-dast/eval/aggregate.js';
import {
  ManifestError, buildRunManifest, checklistHash, manifestDigest, parseChecklist, parseRunManifest, verifyManifest, type Checklist,
} from '../src/agent-dast/eval/manifest.js';

function labelSet(): LabelSet {
  return parseLabelSet({
    version: 1, target: 'fixture', commit: 'abc1234',
    vulnerabilities: [
      { vulnId: 'v-sqli-login', type: 'sqli', severity: 'high', split: 'final',
        site: { method: 'POST', path: '/rest/user/login', param: 'email', location: 'body', authState: 'anonymous' } },
    ],
    negatives: [{ siteId: 'n-products', split: 'final', site: { method: 'GET', path: '/rest/products', param: null, location: null, authState: 'anonymous' } }],
  });
}
const checklist: Checklist = parseChecklist({ version: 1, entries: [{ checkId: 'c-sqli', engine: 'native-dast', check: 'sql_boolean_numeric_v1' }] });

function setup() {
  const labels = finalLabels(labelSet());
  const criteria: PassCriteria = parsePassCriteria({ version: 1, labelSetHash: labels.hash, committedBeforeArmB: true, sharedRequestCap: 64, basis: 'confirmed' });
  const manifest = buildRunManifest({ runId: 'run-01', createdAt: '2026-10-14T05:00:00Z', labels, criteria, checklist });
  return { labels, criteria, manifest, digest: manifestDigest(manifest) };
}

const evidence = Buffer.from('{"redacted":true}');
const evidenceSha = createHash('sha256').update(evidence).digest('hex');

function finding(over: Partial<EvalFinding> = {}): EvalFinding {
  return {
    findingId: 'f-1', type: 'sqli', severity: 'high', state: 'confirmed',
    method: 'POST', path: '/rest/user/login', param: 'email', location: 'body', authState: 'anonymous', round: 1,
    runRef: { runId: 'r-01', taskId: 't-injection' }, evidenceRef: 'evidence/f-1.json', evidenceSha256: evidenceSha, ...over,
  };
}
const arm = (name: 'A' | 'B', findings: EvalFinding[]): Arm => ({ name, findings, rounds: [{ round: 1, kind: 'initial', requestCount: 20 }], coverage: { plannedCells: 40, executedCells: 40 }, durationMs: 1 });

test('the run-start record pins and cross-checks the three input hashes', () => {
  const { labels, criteria, manifest } = setup();
  assert.equal(manifest.finalLabelHash, labels.hash);
  assert.equal(manifest.checklistHash, checklistHash(checklist));
  // Criteria that bind a different label set cannot build a manifest for these labels.
  const otherCriteria = parsePassCriteria({ version: 1, labelSetHash: 'f'.repeat(64), committedBeforeArmB: true, sharedRequestCap: 64, basis: 'confirmed' });
  assert.throws(() => buildRunManifest({ runId: 'run-01', createdAt: '2026-10-14T05:00:00Z', labels, criteria: otherCriteria, checklist }),
    (e: unknown) => e instanceof ManifestError && e.code === 'criteria_label_mismatch');
  void criteria;
});

test('any edit to criteria, labels or the check list breaks manifest verification', () => {
  const { labels, criteria, manifest, digest } = setup();
  assert.doesNotThrow(() => verifyManifest(manifest, digest, { labels, criteria, checklist }));
  // Edited check list → different hash → digest_mismatch.
  const editedChecklist = parseChecklist({ version: 1, entries: [{ checkId: 'c-sqli', engine: 'native-dast', check: 'sql_boolean_numeric_v2' }] });
  assert.throws(() => verifyManifest(manifest, digest, { labels, criteria, checklist: editedChecklist }),
    (e: unknown) => e instanceof ManifestError && e.code === 'digest_mismatch');
  // Tampered manifest field → digest no longer matches the referenced digest.
  assert.throws(() => verifyManifest({ ...manifest, sharedRequestCap: 128 }, digest, { labels, criteria, checklist }),
    (e: unknown) => e instanceof ManifestError && e.code === 'digest_mismatch');
});

test('checklist hashing is order-independent and rejects duplicate check ids', () => {
  const a = parseChecklist({ version: 1, entries: [{ checkId: 'c-a', engine: 'nuclei', check: 'x' }, { checkId: 'c-b', engine: 'native-dast', check: 'y' }] });
  const b = parseChecklist({ version: 1, entries: [{ checkId: 'c-b', engine: 'native-dast', check: 'y' }, { checkId: 'c-a', engine: 'nuclei', check: 'x' }] });
  assert.equal(checklistHash(a), checklistHash(b));
  assert.throws(() => parseChecklist({ version: 1, entries: [{ checkId: 'c-a', engine: 'nuclei', check: 'x' }, { checkId: 'c-a', engine: 'nuclei', check: 'z' }] }), /checkId/);
});

test('finding provenance requires a run ref and a correct evidence ref, and checks the file when given', () => {
  assert.equal(verifyFindingProvenance(finding()).status, 'evidence_unchecked');
  assert.equal(verifyFindingProvenance(finding({ runRef: undefined })).status, 'missing_run_ref');
  assert.equal(verifyFindingProvenance(finding({ evidenceRef: undefined })).status, 'missing_ref');
  const read = (rel: string) => rel === 'evidence/f-1.json' ? evidence : null;
  assert.equal(verifyFindingProvenance(finding(), read).status, 'ok');
  assert.equal(verifyFindingProvenance(finding(), () => null).status, 'evidence_absent');
  assert.equal(verifyFindingProvenance(finding({ evidenceSha256: 'a'.repeat(64) }), read).status, 'evidence_mismatch');
});

test('evaluate ties manifest, provenance and comparison; results must reference the record', () => {
  const { labels, criteria, manifest, digest } = setup();
  const bundle: ResultsBundle = { manifestDigest: digest, armA: arm('A', [finding({ findingId: 'f-a', evidenceRef: 'evidence/f-a.json' })]), armB: arm('B', [finding({ findingId: 'f-b', evidenceRef: 'evidence/f-b.json' })]) };
  const read = () => evidence;
  const ev = evaluate({ manifest, bundle, labels, criteria, checklist, readEvidence: read, evidenceChecked: true });
  assert.equal(ev.manifestVerified, true);
  assert.equal(ev.provenance.allOk, true);
  assert.equal(ev.comparison.qualityHeld, true);

  // A bundle that references a different record is refused.
  assert.throws(() => evaluate({ manifest, bundle: { ...bundle, manifestDigest: 'f'.repeat(64) }, labels, criteria, checklist, evidenceChecked: false }),
    /bundle.manifestDigest/);
  // With evidence checking on, a missing evidence file makes provenance fail.
  const ev2 = evaluate({ manifest, bundle, labels, criteria, checklist, readEvidence: () => null, evidenceChecked: true });
  assert.equal(ev2.provenance.allOk, false);
});

test('parseRunManifest round-trips a built record and rejects a malformed one', () => {
  const { manifest, digest } = setup();
  const parsed = parseRunManifest(JSON.parse(JSON.stringify(manifest)));
  assert.equal(manifestDigest(parsed), digest);
  assert.throws(() => parseRunManifest({ ...manifest, criteriaHash: 'short' }), /criteriaHash/);
  assert.throws(() => parseRunManifest({ ...manifest, runId: 'bad id' }), /runId/);
});
