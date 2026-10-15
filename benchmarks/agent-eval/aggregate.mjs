#!/usr/bin/env node
// Offline A-vs-B evaluation. Verifies the run-start record (criteria, final
// labels and shared check list hashes), confirms the results reference that
// record and each finding links to recorded evidence, then scores the
// comparison. Sends no request, runs no engine or model. Build first
// (npm run build); this imports the compiled modules.
import { readFileSync } from 'node:fs';
import { join, normalize } from 'node:path';
import { parseLabelSet, finalLabels } from '../../build/src/agent-dast/eval/labels.js';
import { parsePassCriteria, parseResultsBundle, evaluate, inputsDigest } from '../../build/src/agent-dast/eval/aggregate.js';
import { parseChecklist, parseRunManifest } from '../../build/src/agent-dast/eval/manifest.js';

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  if (i === -1) { if (fallback === undefined) throw new Error(`missing ${name}`); return fallback; }
  return process.argv[i + 1];
}
const readJson = p => JSON.parse(readFileSync(p, 'utf8'));

const labels = finalLabels(parseLabelSet(readJson(arg('--labels'))));
const criteria = parsePassCriteria(readJson(arg('--criteria')));
const checklist = parseChecklist(readJson(arg('--checklist')));
const manifest = parseRunManifest(readJson(arg('--manifest')));
const rawResults = readJson(arg('--results'));
const bundle = parseResultsBundle(rawResults);

// Optional: when an evidence directory is given, each finding's evidence file
// must exist and match its recorded hash. This alone does not verify the DB/report link.
const evidenceDir = arg('--evidence-dir', '');
const runA = arg('--run-a', ''), runB = arg('--run-b', '');
if (!!runA !== !!runB || (runA && evidenceDir)) throw new Error('provide both --run-a/--run-b, or --evidence-dir alone');
const stored = runA ? await import('../../build/src/agent-dast/eval/stored-results.js') : null;
const readers = stored ? { A: stored.storedRunReader(runA), B: stored.storedRunReader(runB) } : null;
const readerFor = finding => readers[bundle.armA.findings.includes(finding) ? 'A' : 'B'];
const evidenceChecked = evidenceDir !== '' || readers !== null;
const readEvidence = readers ? (relPath, finding) => readerFor(finding).readEvidence(relPath) : evidenceDir
  ? relPath => {
      const resolved = normalize(join(evidenceDir, relPath.replace(/^evidence\//, '')));
      try { return readFileSync(resolved); } catch { return null; }
    }
  : undefined;

const verifyStoredFinding = readers ? (finding, evidence) => readerFor(finding).verifyStoredFinding(finding, evidence) : undefined;
const result = evaluate({ manifest, bundle, labels, criteria, checklist, readEvidence, verifyStoredFinding, evidenceChecked });
console.log(JSON.stringify({
  target: manifest.target,
  commit: manifest.commit,
  runId: manifest.runId,
  manifestDigest: result.manifestDigest,
  evidenceChecked,
  // The manifest binds the three input hashes and is untampered, but it does
  // NOT prove when it was written; the execution layer binds that timestamp.
  criteriaAttestationUnverified: true,
  resultsDigest: inputsDigest(rawResults),
  provenanceAllOk: result.provenance.allOk,
  provenance: result.provenance,
  comparison: result.comparison,
}, null, 2));

// Exit 2 when a budget overran or provenance did not hold; the comparison is
// then not usable even if the scores look fine.
process.exit(result.comparison.withinBudget && result.provenance.allOk ? 0 : 2);
