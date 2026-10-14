#!/usr/bin/env node
// Offline A-vs-B aggregation. Reads a label set, a pass-criteria file and a
// synthetic/real results bundle, prints the per-arm scores, the total-round
// budget and the comparison verdict. Sends no request, runs no engine or
// model. Build first (npm run build); this imports the compiled modules.
import { readFileSync } from 'node:fs';
import { parseLabelSet, finalLabels } from '../../build/src/agent-dast/eval/labels.js';
import { parsePassCriteria, compareArms, inputsDigest } from '../../build/src/agent-dast/eval/aggregate.js';

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  if (i === -1) { if (fallback === undefined) throw new Error(`missing ${name}`); return fallback; }
  return process.argv[i + 1];
}
const readJson = p => JSON.parse(readFileSync(p, 'utf8'));

const labels = finalLabels(parseLabelSet(readJson(arg('--labels'))));
const criteria = parsePassCriteria(readJson(arg('--criteria')));
const results = readJson(arg('--results'));

const comparison = compareArms(results.armA, results.armB, labels, criteria);
console.log(JSON.stringify({
  target: labels.target,
  commit: labels.commit,
  labelSetHash: labels.hash,
  finalVulns: labels.vulnerabilities.length,
  resultsDigest: inputsDigest(results),
  comparison,
}, null, 2));

// Exit 2 when either arm overran the shared budget; the comparison is not usable then.
process.exit(comparison.withinBudget ? 0 : 2);
