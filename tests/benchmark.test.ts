import test from "node:test";
import assert from "node:assert/strict";
import { access, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const exec = promisify(execFile);
const repoRoot = resolve(fileURLToPath(new URL("../..", import.meta.url)));
const benchmarkScript = join(repoRoot, "scripts", "benchmark.mjs");
const corpusPath = join(repoRoot, "benchmarks", "corpus.json");

async function temporaryDirectory(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

async function runBenchmark(args: string[], outDir: string): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const result = await exec(process.execPath, [benchmarkScript, ...args, "--out-dir", outDir], { cwd: repoRoot, maxBuffer: 2 * 1024 * 1024 });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    const failure = error as { code?: number | string; stdout?: string; stderr?: string };
    return { code: typeof failure.code === "number" ? failure.code : Number(failure.code ?? 2), stdout: failure.stdout ?? "", stderr: failure.stderr ?? "" };
  }
}

test("benchmark corpus is balanced and every expected finding has an inspectable mapping", async () => {
  const corpus = JSON.parse(await readFile(corpusPath, "utf8")) as {
    corpusVersion: string;
    unsupportedScope: string[];
    cases: Array<{
      id: string;
      classification: string;
      whyVulnerable: string;
      whyFixed: string;
      fixture: string;
      expectedFindings: Array<{ ruleId: string; path: string; line: number; support: string; knownUnsupported?: string }>;
    }>;
  };
  assert.match(corpus.corpusVersion, /^\d{4}-\d{2}-\d{2}\./);
  assert.ok(corpus.unsupportedScope.some((entry) => /Python/i.test(entry)));
  assert.equal(corpus.cases.length, 50);
  assert.equal(corpus.cases.filter((entry) => entry.classification === "vulnerable").length, corpus.cases.filter((entry) => entry.classification === "fixed").length);
  assert.ok(corpus.cases.every((entry) => entry.whyVulnerable.length > 0 && entry.whyFixed.length > 0 && entry.fixture.startsWith("fixtures/")));
  const expected = corpus.cases.flatMap((entry) => entry.expectedFindings);
  assert.ok(expected.length > 0);
  for (const id of ["sql-cross-function-known-miss", "sql-cross-file-known-miss"]) {
    const promoted = corpus.cases.find((entry) => entry.id === id);
    assert.ok(promoted);
    assert.ok(promoted.expectedFindings.every((finding) => finding.support === "supported" && finding.knownUnsupported === undefined));
  }
  assert.ok(expected.every((finding) => finding.ruleId.length > 0 && finding.path.length > 0 && Number.isSafeInteger(finding.line) && finding.line > 0));
  assert.ok(expected.filter((finding) => finding.support === "known_miss").every((finding) => (finding.knownUnsupported ?? "").length > 0));
  assert.deepEqual([...new Set(expected.map((finding) => finding.ruleId))].sort(), [
    "ast:html-input-sink",
    "ast:open-redirect",
    "ast:server-request",
    "ast:shell-input-sink",
    "ast:sql-input-sink",
  ]);
});

test("benchmark measures the public engine, writes JSON and Markdown, and keeps known misses separate", async () => {
  const outDir = await temporaryDirectory("wakeio-benchmark-report-");
  try {
    const result = await runBenchmark([], outDir);
    assert.equal(result.code, 0, result.stderr || result.stdout);
    const report = JSON.parse(await readFile(join(outDir, "benchmark.json"), "utf8")) as {
      success: boolean;
      corpusVersion: string;
      durationMs: number;
      engine: { label: string; version: string; versionSource: string };
      summary: {
        totalCases: number;
        vulnerableCases: number;
        fixedCases: number;
        supportedExpectedFindings: number;
        knownUnsupportedExpectedFindings: number;
        allExpectedFindings: number;
        allDetectedExpectedFindings: number;
        allFalseNegatives: number;
        truePositives: number;
        falsePositives: number;
        falseNegatives: number;
        supportedTruePositives: number;
        supportedFalseNegatives: number;
        knownMisses: number;
        knownMissesResolved: number;
        strictRegressions: number;
        coveredRuleIds: string[];
      };
      knownUnsupportedScope: unknown[];
      unsupportedScope: string[];
      cases: unknown[];
    };
    assert.equal(report.success, true);
    assert.ok(report.durationMs >= 0);
    assert.equal(report.engine.label.startsWith("package-"), true);
    assert.ok(report.engine.versionSource.length > 0);
    assert.equal(report.summary.totalCases, report.cases.length);
    assert.equal(report.summary.vulnerableCases, report.summary.fixedCases);
    assert.equal(report.summary.allExpectedFindings, report.summary.supportedExpectedFindings + report.summary.knownUnsupportedExpectedFindings);
    assert.equal(report.summary.allDetectedExpectedFindings, report.summary.truePositives);
    assert.equal(report.summary.truePositives, report.summary.supportedTruePositives + report.summary.knownMissesResolved);
    assert.equal(report.summary.allFalseNegatives, report.summary.falseNegatives);
    assert.equal(report.summary.falseNegatives, report.summary.supportedFalseNegatives + report.summary.knownMisses);
    assert.equal(report.summary.knownUnsupportedExpectedFindings, report.summary.knownMisses + report.summary.knownMissesResolved);
    assert.equal(report.knownUnsupportedScope.length, report.summary.knownUnsupportedExpectedFindings);
    assert.ok(report.unsupportedScope.some((entry) => /Python/i.test(entry)));
    assert.equal(report.summary.coveredRuleIds.length, 5);
    const markdown = await readFile(join(outDir, "benchmark.md"), "utf8");
    assert.match(markdown, /Synthetic scoped metrics only/);
    assert.match(markdown, /All-corpus expected recall/);
    assert.match(markdown, /Known unsupported scope/);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("strict mode gates supported FP/FN while still retaining a successful measured report", async () => {
  const defaultOut = await temporaryDirectory("wakeio-benchmark-default-");
  const strictOut = await temporaryDirectory("wakeio-benchmark-strict-");
  try {
    const baseline = await runBenchmark([], defaultOut);
    assert.equal(baseline.code, 0, baseline.stderr || baseline.stdout);
    const baselineReport = JSON.parse(await readFile(join(defaultOut, "benchmark.json"), "utf8")) as { summary: { strictRegressions: number } };
    const strict = await runBenchmark(["--strict"], strictOut);
    assert.equal(strict.code, baselineReport.summary.strictRegressions === 0 ? 0 : 1, strict.stderr || strict.stdout);
    assert.ok(strict.code === 0 || strict.code === 1);
    await access(join(strictOut, "benchmark.json"));
    await access(join(strictOut, "benchmark.md"));
    await access(join(strictOut, "benchmark-failures.json"));
  } finally {
    await rm(defaultOut, { recursive: true, force: true });
    await rm(strictOut, { recursive: true, force: true });
  }
});

test("engine-module selects a trusted alternate public build and records its explicit label", async () => {
  const outDir = await temporaryDirectory("wakeio-benchmark-engine-");
  try {
    const engineModule = join(repoRoot, "build", "src", "source.js");
    const result = await runBenchmark(["--engine-module", engineModule, "--engine-label", "test-public-source-module"], outDir);
    assert.equal(result.code, 0, result.stderr || result.stdout);
    const report = JSON.parse(await readFile(join(outDir, "benchmark.json"), "utf8")) as { engine: { label: string; modulePath: string } };
    assert.equal(report.engine.label, "test-public-source-module");
    assert.equal(report.engine.modulePath, engineModule);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});

test("programmatic runBenchmark accepts a caller-supplied public runSource", async () => {
  const benchmark = await import(pathToFileURL(benchmarkScript).href) as {
    runBenchmark: (runSource: (options: { root: string; tools: [] }) => Promise<unknown>, options: { engine: { label: string; version: string; versionSource: string } }) => Promise<{ success: boolean; engine: { label: string }; summary: { totalCases: number } }>;
  };
  const engine = await import(pathToFileURL(join(repoRoot, "build", "src", "source.js")).href) as {
    runSource: (options: { root: string; tools: [] }) => Promise<unknown>;
  };
  const report = await benchmark.runBenchmark(engine.runSource, { engine: { label: "programmatic-test", version: "test", versionSource: "test" } });
  assert.equal(report.success, true);
  assert.equal(report.engine.label, "programmatic-test");
  assert.equal(report.summary.totalCases, 50);
});

test("default exit semantics permit a measured FN while strict mode exposes the supported regression", async () => {
  const benchmark = await import(pathToFileURL(benchmarkScript).href) as {
    runBenchmark: (runSource: (options: { root: string; tools: [] }) => Promise<unknown>, options: { engine: { label: string; version: string; versionSource: string } }) => Promise<{ success: boolean; summary: { falseNegatives: number; strictRegressions: number } }>;
    benchmarkExitCode: (report: { success: boolean; summary: { strictRegressions: number } }, strict?: boolean) => number;
  };
  const report = await benchmark.runBenchmark(async () => [
    { id: "source.inventory", status: "completed", findings: [], notes: [] },
    { id: "source.builtin-ast", status: "completed", findings: [], notes: [] },
  ], { engine: { label: "empty-test-engine", version: "test", versionSource: "test" } });
  assert.equal(report.success, true);
  assert.equal(report.summary.falseNegatives, 25);
  assert.equal(report.summary.strictRegressions, 24);
  assert.equal(benchmark.benchmarkExitCode(report, false), 0);
  assert.equal(benchmark.benchmarkExitCode(report, true), 1);
});

test("false-positive case metrics use the fixed-case denominator and preserve duplicate findings", async () => {
  const benchmark = await import(pathToFileURL(benchmarkScript).href) as {
    runBenchmark: (runSource: (options: { root: string; tools: [] }) => Promise<unknown>, options: { engine: { label: string; version: string; versionSource: string } }) => Promise<{
      summary: { falsePositives: number; falsePositiveCases: number; fixedFalsePositiveCases: number; fixedCaseFalsePositiveRate: number | null };
      ruleMetrics: Array<{ falsePositives: number }>;
    }>;
  };
  const mockRunSource = async ({ root }: { root: string; tools: [] }) => {
    let source = "";
    try { source = await readFile(join(root, "app.ts"), "utf8"); } catch { /* cross-file fixture or no app.ts */ }
    const findings: Array<{ ruleId: string; location: { path: string; line: number; column: number } }> = [];
    if (source.includes("db.query(req.query.sql)") && !source.includes("// db.query(req.query.sql)")) {
      const finding = { ruleId: "ast:sql-input-sink", location: { path: "app.ts", line: 2, column: 10 } };
      findings.push(finding, finding);
    }
    if (source.includes("node.textContent = req.query.html")) {
      findings.push({ ruleId: "ast:html-input-sink", location: { path: "app.ts", line: 2, column: 3 } });
    }
    return [
      { id: "source.inventory", status: "completed", findings: [], notes: [] },
      { id: "source.builtin-ast", status: "completed", findings, notes: [] },
    ];
  };
  const report = await benchmark.runBenchmark(mockRunSource, { engine: { label: "duplicate-fp-test", version: "test", versionSource: "test" } });
  assert.equal(report.summary.falsePositives, 2);
  assert.equal(report.summary.falsePositiveCases, 2);
  assert.equal(report.summary.fixedFalsePositiveCases, 1);
  assert.equal(report.summary.fixedCaseFalsePositiveRate, 0.04);
  assert.equal(report.ruleMetrics.reduce((sum, metric) => sum + metric.falsePositives, 0), 2);
});

test("engine or corpus errors exit nonzero without creating a clean report", async () => {
  const outDir = await temporaryDirectory("wakeio-benchmark-error-");
  try {
    const result = await runBenchmark(["--engine-module", join(outDir, "missing-engine.mjs")], outDir);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /benchmark error/i);
    const files = await readdir(outDir);
    assert.deepEqual(files, []);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});


type MappedFinding = { ruleId: string; path: string; line: number; support: string };
type BenchmarkCase = { id: string; fixture: string; expectedFindings: MappedFinding[] };
type BenchmarkReport = {
  schemaVersion: string;
  success: boolean;
  summary: {
    totalCases: number;
    completedCases: number;
    incompleteCases: number;
    allExpectedFindings: number;
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    supportedTruePositives: number;
    supportedFalseNegatives: number;
    supportedExpectedFindings: number;
    knownUnsupportedExpectedFindings: number;
    knownMisses: number;
    knownMissesResolved: number;
    precision: number | null;
    recall: number | null;
    supportedPrecision: number | null;
    supportedRecall: number | null;
    strictRegressions: number;
  };
  ruleMetrics: Array<{ ruleId: string; truePositives: number; falsePositives: number; falseNegatives: number }>;
  cases: Array<BenchmarkCase & {
    complete: boolean;
    checkStatuses: Array<{ id: string; status: string }>;
    counts: { falseNegatives: number };
  }>;
};

async function benchmarkApi() {
  return await import(pathToFileURL(benchmarkScript).href) as {
    runBenchmark: (runSource: (options: { root: string; tools: [] }) => Promise<unknown>, options?: { engine?: { label: string } }) => Promise<BenchmarkReport>;
    benchmarkExitCode: (report: BenchmarkReport, strict?: boolean) => number;
    writeBenchmarkReports: (report: BenchmarkReport, outDir: string) => Promise<{ failuresPath: string }>;
  };
}

function completedChecks(expected: MappedFinding[]) {
  return [
    { id: "source.inventory", status: "completed", findings: [], notes: [] },
    { id: "source.builtin-ast", status: "completed", findings: expected.map(({ ruleId, path, line }) => ({ ruleId, location: { path, line } })), notes: [] as string[] },
  ];
}

test("primary metrics count known misses in every FN denominator while strict gates supported regressions", async () => {
  const benchmark = await benchmarkApi();
  const corpus = JSON.parse(await readFile(corpusPath, "utf8")) as { cases: BenchmarkCase[] };
  let index = 0;
  const report = await benchmark.runBenchmark(async () => completedChecks(corpus.cases[index++].expectedFindings.filter((finding) => finding.support === "supported")));
  assert.equal(report.schemaVersion, "2.0.0");
  assert.equal(report.summary.allExpectedFindings, 25);
  assert.equal(report.summary.supportedExpectedFindings, 24);
  assert.equal(report.summary.truePositives, 24);
  assert.equal(report.summary.falseNegatives, 1);
  assert.equal(report.summary.supportedFalseNegatives, 0);
  assert.equal(report.summary.knownMisses, 1);
  assert.equal(report.summary.precision, 1);
  assert.equal(report.summary.recall, 0.96);
  assert.equal(report.summary.supportedRecall, 1);
  assert.equal(report.ruleMetrics.reduce((sum, rule) => sum + rule.falseNegatives, 0), 1);
  assert.equal(report.cases.find((entry) => entry.id === "koa-query-sql-vulnerable")?.counts.falseNegatives, 1);
  assert.equal(benchmark.benchmarkExitCode(report, true), 0);
});

test("a resolved known miss contributes to primary TP and precision without becoming an FP", async () => {
  const benchmark = await benchmarkApi();
  const corpus = JSON.parse(await readFile(corpusPath, "utf8")) as { cases: BenchmarkCase[] };
  let index = 0;
  const report = await benchmark.runBenchmark(async () => {
    const checks = completedChecks(corpus.cases[index++].expectedFindings);
    if (index === 1) checks[1].findings.push({ ruleId: "ast:unexpected-test-only", location: { path: "app.ts", line: 1 } });
    return checks;
  });
  assert.equal(report.summary.truePositives, 25);
  assert.equal(report.summary.supportedTruePositives, 24);
  assert.equal(report.summary.knownMissesResolved, 1);
  assert.equal(report.summary.knownMisses, 0);
  assert.equal(report.summary.falsePositives, 1);
  assert.equal(report.summary.falseNegatives, 0);
  assert.equal(report.summary.precision, 0.9615);
  assert.equal(report.summary.supportedPrecision, 0.96);
  assert.equal(report.summary.recall, 1);
  assert.equal(report.ruleMetrics.reduce((sum, rule) => sum + rule.truePositives, 0), 25);
  assert.equal(benchmark.benchmarkExitCode(report, true), 1);
});

test("incomplete checks retain evidence and full denominators, never a successful clean result", async () => {
  const benchmark = await benchmarkApi();
  for (const status of ["partial", "error", "skipped", "not_applicable", "missing"]) {
    const report = await benchmark.runBenchmark(async () => [
      { id: "source.inventory", status: "completed", findings: [], notes: [] },
      ...(status === "missing" ? [] : [{ id: "source.builtin-ast", status, findings: [], notes: [] }]),
    ]);
    assert.equal(report.success, false, status);
    assert.equal(report.summary.completedCases, 0, status);
    assert.equal(report.summary.incompleteCases, 50, status);
    assert.equal(report.summary.falseNegatives, 25, status);
    assert.equal(report.summary.recall, 0, status);
    assert.equal(report.cases.every((entry) => !entry.complete), true, status);
    assert.equal(benchmark.benchmarkExitCode(report, false), 2, status);
    assert.equal(benchmark.benchmarkExitCode(report, true), 2, status);
  }
});

test("partial inventory cannot be hidden by a completed AST with matching findings", async () => {
  const benchmark = await benchmarkApi();
  const corpus = JSON.parse(await readFile(corpusPath, "utf8")) as { cases: BenchmarkCase[] };
  let index = 0;
  const report = await benchmark.runBenchmark(async () => {
    const checks = completedChecks(corpus.cases[index++].expectedFindings);
    checks[0].status = "partial";
    return checks;
  });
  assert.equal(report.success, false);
  assert.equal(report.summary.truePositives, 25);
  assert.equal(report.summary.recall, 1);
  assert.equal(report.summary.incompleteCases, 50);
  assert.equal(benchmark.benchmarkExitCode(report, true), 2);
});

test("scan exceptions preserve an incomplete case and signature-only failure artifacts", async () => {
  const benchmark = await benchmarkApi();
  const corpus = JSON.parse(await readFile(corpusPath, "utf8")) as { cases: BenchmarkCase[] };
  const outDir = await temporaryDirectory("wakeio-benchmark-failure-artifact-");
  const sourceCanary = "SYNTHETIC_ERROR_SOURCE_MUST_NOT_BE_EXPORTED";
  let index = 0;
  try {
    const report = await benchmark.runBenchmark(async () => {
      const entry = corpus.cases[index++];
      if (index === 1) throw new Error(sourceCanary);
      const checks = completedChecks(entry.expectedFindings);
      checks[1].notes.push(sourceCanary);
      return checks;
    });
    assert.equal(report.success, false);
    assert.equal(report.summary.completedCases, 49);
    assert.equal(report.summary.incompleteCases, 1);
    assert.equal(report.summary.truePositives, 24);
    assert.equal(report.summary.falseNegatives, 1);
    assert.equal(benchmark.benchmarkExitCode(report), 2);
    const paths = await benchmark.writeBenchmarkReports(report, outDir);
    const failureText = await readFile(paths.failuresPath, "utf8");
    const failures = JSON.parse(failureText) as { cases: Array<{ id: string; complete: boolean; missedFindings: MappedFinding[]; checkStatuses: Array<{ status: string }> }> };
    assert.equal(failures.cases.length, 1);
    assert.equal(failures.cases[0].id, "sql-direct");
    assert.equal(failures.cases[0].complete, false);
    assert.equal(failures.cases[0].missedFindings.length, 1);
    assert.equal(failures.cases[0].checkStatuses.some((check) => check.status === "error"), true);
    for (const file of await readdir(outDir)) {
      const text = await readFile(join(outDir, file), "utf8");
      assert.equal(text.includes(sourceCanary), false);
      assert.equal(text.includes("db.query(req.query.sql)"), false);
    }
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});


test("CLI writes an incomplete report and failure artifact before exiting 2", async () => {
  const outDir = await temporaryDirectory("wakeio-benchmark-partial-cli-");
  try {
    const enginePath = join(outDir, "partial-engine.mjs");
    await writeFile(enginePath, `export async function runSource() {
      return [
        { id: "source.inventory", status: "completed", findings: [] },
        { id: "source.builtin-ast", status: "partial", findings: [] }
      ];
    }`);
    const result = await runBenchmark(["--strict", "--engine-module", enginePath], outDir);
    assert.equal(result.code, 2, result.stderr || result.stdout);
    const report = JSON.parse(await readFile(join(outDir, "benchmark.json"), "utf8")) as BenchmarkReport;
    assert.equal(report.success, false);
    assert.equal(report.summary.incompleteCases, 50);
    assert.equal(report.summary.falseNegatives, 25);
    const failures = JSON.parse(await readFile(join(outDir, "benchmark-failures.json"), "utf8")) as { cases: unknown[] };
    assert.equal(failures.cases.length, 50);
    const markdown = await readFile(join(outDir, "benchmark.md"), "utf8");
    assert.match(markdown, /Completed \/ incomplete cases \| 0 \/ 50/);
    assert.match(markdown, /\| NO \|/);
  } finally {
    await rm(outDir, { recursive: true, force: true });
  }
});
