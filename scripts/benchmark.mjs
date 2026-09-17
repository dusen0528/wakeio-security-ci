#!/usr/bin/env node

import { cp, lstat, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { tmpdir } from "node:os";
import { performance } from "node:perf_hooks";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");
const DEFAULT_CORPUS_PATH = join(REPO_ROOT, "benchmarks", "corpus.json");
const DEFAULT_OUT_DIR = join(REPO_ROOT, "benchmarks", "results");
const DEFAULT_ENGINE_MODULE = join(REPO_ROOT, "build", "src", "index.js");

/**
 * @typedef {{ ruleId: string, path: string, line: number, column?: number, support: "supported" | "known_miss", knownUnsupported?: string }} ExpectedFinding
 * @typedef {{ id: string, classification: "vulnerable" | "fixed", language: string, framework: string, fixture: string, whyVulnerable: string, whyFixed: string, expectedFindings: ExpectedFinding[] }} CorpusCase
 */

function usage() {
  return [
    "Usage: node scripts/benchmark.mjs [options]",
    "",
    "Runs the inspectable synthetic corpus through the built public runSource API.",
    "The target fixtures are read as data; they are never installed, built, or executed.",
    "",
    "Options:",
    "  --strict                 Exit 1 when a supported expectation has an FN or FP.",
    "  --engine-module PATH     Trusted local module exporting runSource (default: build/src/index.js).",
    "  --engine-label LABEL     Explicit label for the runtime under measurement.",
    "  --corpus PATH            Corpus JSON path (default: benchmarks/corpus.json).",
    "  --out-dir PATH           Directory for benchmark.json and benchmark.md (default: benchmarks/results).",
    "  --help                   Show this message.",
  ].join("\n");
}

function parseArgs(argv) {
  const options = {
    strict: false,
    engineModule: DEFAULT_ENGINE_MODULE,
    engineLabel: undefined,
    corpusPath: DEFAULT_CORPUS_PATH,
    outDir: DEFAULT_OUT_DIR,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--help" || argument === "-h") {
      options.help = true;
      continue;
    }
    if (argument === "--strict") {
      options.strict = true;
      continue;
    }
    const [name, inlineValue] = argument.split("=", 2);
    if (name === "--engine-module" || name === "--engine-label" || name === "--corpus" || name === "--out-dir") {
      const value = inlineValue ?? argv[++index];
      if (!value || value.startsWith("--")) throw new Error(`${name} requires a value`);
      if (name === "--engine-module") options.engineModule = value;
      else if (name === "--engine-label") options.engineLabel = value;
      else if (name === "--corpus") options.corpusPath = value;
      else options.outDir = value;
      continue;
    }
    throw new Error(`Unknown option: ${argument}`);
  }
  return options;
}

function asNonEmptyString(value, label) {
  if (typeof value !== "string" || value.trim().length === 0) throw new Error(`${label} must be a non-empty string`);
  return value;
}

function asPositiveInteger(value, label) {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error(`${label} must be a positive integer`);
  return value;
}

function normalizeExpected(value, caseId, index) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`Case ${caseId} expectedFindings[${index}] must be an object`);
  const finding = /** @type {Record<string, unknown>} */ (value);
  const ruleId = asNonEmptyString(finding.ruleId, `Case ${caseId} expectedFindings[${index}].ruleId`);
  const path = asNonEmptyString(finding.path, `Case ${caseId} expectedFindings[${index}].path`);
  const line = asPositiveInteger(finding.line, `Case ${caseId} expectedFindings[${index}].line`);
  const support = finding.support;
  if (support !== "supported" && support !== "known_miss") throw new Error(`Case ${caseId} expectedFindings[${index}].support must be supported or known_miss`);
  const knownUnsupported = finding.knownUnsupported;
  if (support === "known_miss" && typeof knownUnsupported !== "string") throw new Error(`Case ${caseId} known_miss must explain knownUnsupported scope`);
  const result = { ruleId, path, line, support, ...(typeof finding.column === "number" ? { column: asPositiveInteger(finding.column, `Case ${caseId} expectedFindings[${index}].column`) } : {}), ...(typeof knownUnsupported === "string" ? { knownUnsupported } : {}) };
  return /** @type {ExpectedFinding} */ (result);
}

/**
 * Load and validate the corpus before creating any temporary scan directory.
 * This prevents malformed expectations from being mistaken for scanner misses.
 */
export async function loadCorpus(corpusPath = DEFAULT_CORPUS_PATH) {
  const absolutePath = resolve(corpusPath);
  const raw = await readFile(absolutePath, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Corpus JSON is invalid: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Corpus must be a JSON object");
  const object = /** @type {Record<string, unknown>} */ (parsed);
  const corpusVersion = asNonEmptyString(object.corpusVersion, "corpusVersion");
  const scope = asNonEmptyString(object.scope, "scope");
  if (!Array.isArray(object.unsupportedScope) || object.unsupportedScope.length === 0 || !object.unsupportedScope.every((entry) => typeof entry === "string" && entry.length > 0)) throw new Error("unsupportedScope must contain at least one explanation");
  if (!Array.isArray(object.cases) || object.cases.length < 20) throw new Error("Corpus must contain at least 20 cases");
  /** @type {CorpusCase[]} */
  const cases = [];
  const ids = new Set();
  for (const [index, value] of object.cases.entries()) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error(`Corpus case ${index} must be an object`);
    const candidate = /** @type {Record<string, unknown>} */ (value);
    const id = asNonEmptyString(candidate.id, `Corpus case ${index}.id`);
    if (ids.has(id)) throw new Error(`Corpus case id is duplicated: ${id}`);
    ids.add(id);
    const classification = candidate.classification;
    if (classification !== "vulnerable" && classification !== "fixed") throw new Error(`Case ${id}.classification must be vulnerable or fixed`);
    const language = asNonEmptyString(candidate.language, `Case ${id}.language`);
    const framework = asNonEmptyString(candidate.framework, `Case ${id}.framework`);
    const fixture = asNonEmptyString(candidate.fixture, `Case ${id}.fixture`);
    if (!fixture.startsWith("fixtures/") || fixture.includes("\\")) throw new Error(`Case ${id}.fixture must stay under fixtures/`);
    const whyVulnerable = asNonEmptyString(candidate.whyVulnerable, `Case ${id}.whyVulnerable`);
    const whyFixed = asNonEmptyString(candidate.whyFixed, `Case ${id}.whyFixed`);
    if (!Array.isArray(candidate.expectedFindings)) throw new Error(`Case ${id}.expectedFindings must be an array`);
    const expectedFindings = candidate.expectedFindings.map((entry, expectedIndex) => normalizeExpected(entry, id, expectedIndex));
    if (classification === "vulnerable" && expectedFindings.length === 0) throw new Error(`Vulnerable case ${id} must map at least one expected finding`);
    if (classification === "fixed" && expectedFindings.some((entry) => entry.support === "known_miss")) throw new Error(`Fixed case ${id} cannot contain a known miss expectation`);
    cases.push({ id, classification, language, framework, fixture, whyVulnerable, whyFixed, expectedFindings });
  }
  const vulnerableCases = cases.filter((entry) => entry.classification === "vulnerable").length;
  const fixedCases = cases.filter((entry) => entry.classification === "fixed").length;
  if (vulnerableCases !== fixedCases) throw new Error(`Corpus must be balanced: vulnerable=${vulnerableCases}, fixed=${fixedCases}`);
  // Fixture paths in corpus.json are repository-relative (for example
  // fixtures/sql-direct), so the corpus directory is the containment root.
  const fixtureRoot = dirname(absolutePath);
  return { corpusVersion, scope, unsupportedScope: object.unsupportedScope, cases, corpusPath: absolutePath, fixtureRoot };
}

function signature(finding) {
  const location = finding?.location ?? {};
  return {
    ruleId: typeof finding?.ruleId === "string" ? finding.ruleId : "<missing-rule-id>",
    path: typeof location.path === "string" ? location.path : "<missing-path>",
    ...(typeof location.line === "number" ? { line: location.line } : { line: null }),
    ...(typeof location.column === "number" ? { column: location.column } : {}),
  };
}

function matches(expected, observed) {
  if (expected.ruleId !== observed.ruleId || expected.path !== observed.path || expected.line !== observed.line) return false;
  return expected.column === undefined || expected.column === observed.column;
}

function relativeFixturePath(fixtureRoot, fixture) {
  const absoluteFixture = resolve(fixtureRoot, fixture);
  const relativePath = relative(fixtureRoot, absoluteFixture);
  if (!relativePath || relativePath.startsWith("../") || isAbsolute(relativePath)) throw new Error(`Fixture escapes corpus fixtures directory: ${fixture}`);
  return absoluteFixture;
}

async function copyFixture(source, target) {
  const entries = await readdir(source, { withFileTypes: true });
  await mkdir(target, { recursive: true, mode: 0o700 });
  for (const entry of entries) {
    if (entry.name === "." || entry.name === "..") continue;
    const sourcePath = join(source, entry.name);
    const targetPath = join(target, entry.name);
    if (entry.isDirectory()) await copyFixture(sourcePath, targetPath);
    else if (entry.isFile()) await cp(sourcePath, targetPath, { force: true });
    else throw new Error(`Fixture contains unsupported entry: ${sourcePath}`);
  }
}

function checkStatus(checks, id) {
  const check = checks.find((entry) => entry && entry.id === id);
  if (!check || (check.status !== "completed" && check.status !== "not_applicable")) {
    throw new Error(`${id} did not complete for fixture (${check?.status ?? "missing"})`);
  }
  return check;
}

function analyzeCase(entry, checks, durationMs) {
  const inventory = checkStatus(checks, "source.inventory");
  const ast = checkStatus(checks, "source.builtin-ast");
  if (inventory.status !== "completed") throw new Error(`${entry.id}: source inventory is ${inventory.status}`);
  if (ast.status !== "completed") throw new Error(`${entry.id}: built-in AST check is ${ast.status}`);
  const observed = checks.flatMap((check) => Array.isArray(check?.findings) ? check.findings.map(signature) : []);
  const supportedExpected = entry.expectedFindings.filter((finding) => finding.support === "supported");
  const knownExpected = entry.expectedFindings.filter((finding) => finding.support === "known_miss");
  const unmatched = [...observed];
  let truePositives = 0;
  let falseNegatives = 0;
  let knownMisses = 0;
  let knownMissesResolved = 0;
  for (const expected of supportedExpected) {
    const index = unmatched.findIndex((candidate) => matches(expected, candidate));
    if (index < 0) falseNegatives += 1;
    else {
      truePositives += 1;
      unmatched.splice(index, 1);
    }
  }
  for (const expected of knownExpected) {
    const index = unmatched.findIndex((candidate) => matches(expected, candidate));
    if (index < 0) knownMisses += 1;
    else {
      knownMissesResolved += 1;
      unmatched.splice(index, 1);
    }
  }
  const falsePositives = unmatched.length;
  return {
    id: entry.id,
    classification: entry.classification,
    language: entry.language,
    framework: entry.framework,
    fixture: entry.fixture,
    whyVulnerable: entry.whyVulnerable,
    whyFixed: entry.whyFixed,
    expectedFindings: entry.expectedFindings,
    observedFindings: observed,
    durationMs,
    counts: { truePositives, falsePositives, falseNegatives, knownMisses, knownMissesResolved },
  };
}

function percentage(numerator, denominator) {
  return denominator === 0 ? null : Number((numerator / denominator).toFixed(4));
}

function addRuleCount(map, ruleId) {
  if (!map.has(ruleId)) map.set(ruleId, { ruleId, truePositives: 0, falsePositives: 0, falseNegatives: 0, knownMisses: 0, knownMissesResolved: 0 });
  return map.get(ruleId);
}

function aggregate(corpus, caseResults, engine, startedAt, durationMs) {
  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let knownMisses = 0;
  let knownMissesResolved = 0;
  let supportedExpectedFindings = 0;
  let knownUnsupportedExpectedFindings = 0;
  let falsePositiveCases = 0;
  let fixedFalsePositiveCases = 0;
  let falseNegativeCases = 0;
  const ruleMap = new Map();
  const coveredRuleIds = new Set();
  for (const entry of corpus.cases) {
    for (const finding of entry.expectedFindings) {
      coveredRuleIds.add(finding.ruleId);
      if (finding.support === "supported") supportedExpectedFindings += 1;
      else knownUnsupportedExpectedFindings += 1;
      addRuleCount(ruleMap, finding.ruleId);
    }
  }
  for (const result of caseResults) {
    for (const finding of result.observedFindings) coveredRuleIds.add(finding.ruleId);
    const unmatched = [...result.observedFindings];
    for (const expected of result.expectedFindings) {
      const rule = addRuleCount(ruleMap, expected.ruleId);
      const index = unmatched.findIndex((candidate) => matches(expected, candidate));
      if (index >= 0) {
        unmatched.splice(index, 1);
        if (expected.support === "supported") {
          truePositives += 1;
          rule.truePositives += 1;
        } else {
          knownMissesResolved += 1;
          rule.knownMissesResolved += 1;
        }
      } else if (expected.support === "supported") {
        falseNegatives += 1;
        rule.falseNegatives += 1;
      } else {
        knownMisses += 1;
        rule.knownMisses += 1;
      }
    }
    falsePositives += unmatched.length;
    if (unmatched.length > 0) {
      falsePositiveCases += 1;
      if (result.classification === "fixed") fixedFalsePositiveCases += 1;
    }
    for (const finding of unmatched) addRuleCount(ruleMap, finding.ruleId).falsePositives += 1;
    if (result.counts.falseNegatives > 0) falseNegativeCases += 1;
  }
  const allExpectedFindings = supportedExpectedFindings + knownUnsupportedExpectedFindings;
  const allDetectedExpectedFindings = truePositives + knownMissesResolved;
  const allFalseNegatives = falseNegatives + knownMisses;
  const strictRegressions = falsePositives + falseNegatives;
  const ruleMetrics = [...ruleMap.values()].sort((left, right) => left.ruleId.localeCompare(right.ruleId));
  return {
    schemaVersion: "1.0.0",
    corpusVersion: corpus.corpusVersion,
    generatedAt: new Date().toISOString(),
    startedAt,
    measurementScope: corpus.scope,
    unsupportedScope: corpus.unsupportedScope,
    engine,
    success: true,
    durationMs,
    summary: {
      totalCases: corpus.cases.length,
      vulnerableCases: corpus.cases.filter((entry) => entry.classification === "vulnerable").length,
      fixedCases: corpus.cases.filter((entry) => entry.classification === "fixed").length,
      supportedExpectationCases: corpus.cases.filter((entry) => entry.expectedFindings.some((finding) => finding.support === "supported")).length,
      knownUnsupportedCases: corpus.cases.filter((entry) => entry.expectedFindings.some((finding) => finding.support === "known_miss")).length,
      supportedExpectedFindings,
      knownUnsupportedExpectedFindings,
      allExpectedFindings,
      allDetectedExpectedFindings,
      allFalseNegatives,
      truePositives,
      falsePositives,
      falseNegatives,
      precision: percentage(truePositives, truePositives + falsePositives),
      recall: percentage(truePositives, truePositives + falseNegatives),
      supportedPrecision: percentage(truePositives, truePositives + falsePositives),
      supportedRecall: percentage(truePositives, truePositives + falseNegatives),
      allCorpusRecall: percentage(allDetectedExpectedFindings, allExpectedFindings),
      falsePositiveCases,
      fixedFalsePositiveCases,
      falseNegativeCases,
      fixedCaseFalsePositiveRate: percentage(fixedFalsePositiveCases, corpus.cases.filter((entry) => entry.classification === "fixed").length),
      knownMisses,
      knownMissesResolved,
      strictRegressions,
      coveredRuleIds: [...coveredRuleIds].sort(),
    },
    ruleMetrics,
    knownUnsupportedScope: corpus.cases.flatMap((entry) => entry.expectedFindings.filter((finding) => finding.support === "known_miss").map((finding) => ({ caseId: entry.id, ruleId: finding.ruleId, path: finding.path, line: finding.line, reason: finding.knownUnsupported }))),
    cases: caseResults,
  };
}

function normalizeEngineInfo(options = {}) {
  const engine = options.engine ?? {};
  const label = typeof engine.label === "string" && engine.label.length > 0 ? engine.label : "unspecified-runtime";
  const version = typeof engine.version === "string" && engine.version.length > 0 ? engine.version : "unknown";
  const modulePath = typeof engine.modulePath === "string" && engine.modulePath.length > 0 ? engine.modulePath : "programmatic-runSource";
  return { label, version, versionSource: engine.versionSource ?? "caller-supplied", modulePath };
}

/**
 * Measure a caller-supplied public runSource function. This is intentionally
 * exported so a reviewer can run the same corpus against two trusted local
 * package builds without changing fixture expectations.
 *
 * @param {(options: {root: string, tools: []}) => Promise<unknown>} runSource
 * @param {{ corpusPath?: string, engine?: {label?: string, version?: string, versionSource?: string, modulePath?: string} }} [options]
 */
export async function runBenchmark(runSource, options = {}) {
  if (typeof runSource !== "function") throw new Error("A public runSource function is required");
  const corpus = await loadCorpus(options.corpusPath ?? DEFAULT_CORPUS_PATH);
  const startedAt = new Date().toISOString();
  const started = performance.now();
  /** @type {ReturnType<typeof analyzeCase>[]} */
  const caseResults = [];
  for (const entry of corpus.cases) {
    const fixture = relativeFixturePath(corpus.fixtureRoot, entry.fixture);
    const parent = await mkdtemp(join(tmpdir(), "wakeio-security-benchmark-"));
    const scanRoot = join(parent, "source");
    const caseStarted = performance.now();
    try {
      await copyFixture(fixture, scanRoot);
      // The only target operation is the existing public scan entry point. No
      // package manager, shell, test runner, or fixture module is invoked.
      const checks = await runSource({ root: scanRoot, tools: [] });
      const caseDuration = Number((performance.now() - caseStarted).toFixed(3));
      caseResults.push(analyzeCase(entry, checks, caseDuration));
    } finally {
      await rm(parent, { recursive: true, force: true });
    }
  }
  const durationMs = Number((performance.now() - started).toFixed(3));
  return aggregate(corpus, caseResults, normalizeEngineInfo(options), startedAt, durationMs);
}

function formatCount(value) {
  return value === null || value === undefined ? "n/a" : String(value);
}

function findingText(findings) {
  if (!findings.length) return "—";
  return findings.map((finding) => `${finding.ruleId} @ ${finding.path}:${finding.line ?? "?"}`).join("; ");
}

export function renderMarkdown(report) {
  const summary = report.summary;
  const lines = [
    "# Wakeio built-in source benchmark",
    "",
    "> Synthetic scoped metrics only. This corpus is a regression signal for the public `runSource({ root, tools: [] })` API; it is not a production accuracy estimate.",
    "",
    `- Corpus version: \`${report.corpusVersion}\``,
    `- Engine label: \`${report.engine.label}\``,
    `- Engine version: \`${report.engine.version}\` (source: ${report.engine.versionSource})`,
    `- Measurement duration: ${report.durationMs} ms`,
    `- Scope: ${report.measurementScope}`,
    "",
    "## Counts",
    "",
    "| Metric | Count |",
    "| --- | ---: |",
    `| Cases | ${summary.totalCases} (${summary.vulnerableCases} vulnerable / ${summary.fixedCases} fixed) |`,
    `| Supported expected findings | ${summary.supportedExpectedFindings} |`,
    `| All expected findings (including known unsupported) | ${summary.allExpectedFindings} |`,
    `| All expected findings detected | ${summary.allDetectedExpectedFindings} |`,
    `| True positives | ${summary.truePositives} |`,
    `| False positives | ${summary.falsePositives} |`,
    `| Supported false negatives | ${summary.falseNegatives} |`,
    `| All-corpus false negatives (including known misses) | ${summary.allFalseNegatives} |`,
    `| Supported precision | ${formatCount(summary.supportedPrecision)} |`,
    `| Supported recall (known misses excluded) | ${formatCount(summary.supportedRecall)} |`,
    `| All-corpus expected recall (known misses included) | ${formatCount(summary.allCorpusRecall)} |`,
    `| False-positive cases (all classifications) | ${summary.falsePositiveCases} |`,
    `| Fixed false-positive cases | ${summary.fixedFalsePositiveCases} |`,
    `| Fixed case FP rate (fixed cases only) | ${formatCount(summary.fixedCaseFalsePositiveRate)} |`,
    `| Known unsupported expected findings | ${summary.knownUnsupportedExpectedFindings} |`,
    `| Known misses (excluded from supported FN denominator) | ${summary.knownMisses} |`,
    `| Known misses resolved | ${summary.knownMissesResolved} |`,
    `| Strict regressions (FP + supported FN) | ${summary.strictRegressions} |`,
    "",
    `Covered rule IDs: ${summary.coveredRuleIds.map((ruleId) => `\`${ruleId}\``).join(", ")}.`,
    "",
    "## Bounded unsupported scope",
    "",
    ...report.unsupportedScope.map((entry) => `- ${entry}`),
    "",
    "## Per-rule counts",
    "",
    "| Rule ID | TP | FP | FN | Known miss | Known resolved |",
    "| --- | ---: | ---: | ---: | ---: | ---: |",
    ...report.ruleMetrics.map((metric) => `| \`${metric.ruleId}\` | ${metric.truePositives} | ${metric.falsePositives} | ${metric.falseNegatives} | ${metric.knownMisses} | ${metric.knownMissesResolved} |`),
    "",
    "## Known unsupported scope",
    "",
    ...(report.knownUnsupportedScope.length
      ? report.knownUnsupportedScope.map((entry) => `- \`${entry.caseId}\`: \`${entry.ruleId}\` at \`${entry.path}:${entry.line}\` — ${entry.reason}.`)
      : ["- None recorded."]),
    "",
    "## Case evidence",
    "",
    "Each case keeps a high-level explanation and mapped signatures. Source values are intentionally omitted from this report.",
    "",
    "| Case | Class | Framework | Expected | Observed | TP | FP | FN | Known miss | ms |",
    "| --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ...report.cases.map((entry) => `| \`${entry.id}\` | ${entry.classification} | ${entry.framework} | ${findingText(entry.expectedFindings)} | ${findingText(entry.observedFindings)} | ${entry.counts.truePositives} | ${entry.counts.falsePositives} | ${entry.counts.falseNegatives} | ${entry.counts.knownMisses} | ${entry.durationMs} |`),
    "",
    "## Interpretation",
    "",
    "Default benchmark execution is successful when all fixtures were measured, even when supported false positives or false negatives exist. `--strict` turns those supported regressions into exit code 1. Known cross-function and cross-file misses remain visible above and are excluded from the supported recall denominator.",
    "",
  ];
  return lines.join("\n");
}

async function rejectSymlinkChain(path) {
  let current = resolve(path);
  while (true) {
    try {
      const info = await lstat(current);
      // macOS commonly exposes /var and /tmp as stable system symlinks. They
      // are trusted mount aliases; a user supplied output link below them is
      // still rejected.
      if (info.isSymbolicLink()) {
        if (current !== "/var" && current !== "/tmp") throw new Error(`Refusing symlink output path: ${path}`);
      } else if (!info.isDirectory()) throw new Error(`Output path component is not a directory: ${current}`);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
        // A missing component will be created below; inspect its ancestors.
      } else {
        throw error;
      }
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
}

async function rejectSymlinkFile(path) {
  try {
    const info = await lstat(path);
    if (info.isSymbolicLink()) throw new Error(`Refusing symlink report target: ${path}`);
    if (!info.isFile()) throw new Error(`Report target is not a regular file: ${path}`);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") return;
    throw error;
  }
}

export async function writeBenchmarkReports(report, outDir) {
  const targetDir = resolve(outDir);
  await rejectSymlinkChain(targetDir);
  await mkdir(targetDir, { recursive: true, mode: 0o700 });
  const jsonPath = join(targetDir, "benchmark.json");
  const markdownPath = join(targetDir, "benchmark.md");
  await rejectSymlinkChain(targetDir);
  await rejectSymlinkFile(jsonPath);
  await rejectSymlinkFile(markdownPath);
  await writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
  await writeFile(markdownPath, renderMarkdown(report), { encoding: "utf8", mode: 0o600 });
  return { jsonPath, markdownPath };
}

function packageVersionCandidate(modulePath) {
  let current = dirname(modulePath);
  return (async () => {
    for (let depth = 0; depth < 8; depth += 1) {
      try {
        const parsed = JSON.parse(await readFile(join(current, "package.json"), "utf8"));
        if (typeof parsed?.version === "string" && parsed.version.length > 0) return { version: parsed.version, path: join(current, "package.json") };
      } catch {
        // Continue toward the filesystem root.
      }
      const next = dirname(current);
      if (next === current) break;
      current = next;
    }
    return { version: "unknown", path: undefined };
  })();
}

async function loadRunSource(modulePath) {
  const absolute = resolve(modulePath);
  const imported = await import(pathToFileURL(absolute).href);
  const runSource = imported.runSource ?? imported.default?.runSource ?? imported.default;
  if (typeof runSource !== "function") throw new Error(`Engine module does not export runSource: ${absolute}`);
  const packageInfo = await packageVersionCandidate(absolute);
  return { runSource, packageInfo, absolute };
}

export function benchmarkExitCode(report, strict = false) {
  if (!report || report.success !== true) return 2;
  return strict && report.summary.strictRegressions > 0 ? 1 : 0;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(`${usage()}\n`);
    return 0;
  }
  const engine = await loadRunSource(options.engineModule);
  const label = options.engineLabel ?? `package-${engine.packageInfo.version}`;
  const report = await runBenchmark(engine.runSource, {
    corpusPath: options.corpusPath,
    engine: {
      label,
      version: engine.packageInfo.version,
      versionSource: engine.packageInfo.path ? `nearest-package.json:${engine.packageInfo.path}` : "unavailable",
      modulePath: engine.absolute,
    },
  });
  const paths = await writeBenchmarkReports(report, options.outDir);
  process.stdout.write(`${JSON.stringify({ ...report.summary, engine: report.engine, reports: paths }, null, 2)}\n`);
  return benchmarkExitCode(report, options.strict);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  main().catch((error) => {
    process.stderr.write(`benchmark error: ${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 2;
  }).then((code) => {
    if (typeof code === "number") process.exitCode = code;
  });
}
