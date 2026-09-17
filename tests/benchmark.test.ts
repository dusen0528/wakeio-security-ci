import test from "node:test";
import assert from "node:assert/strict";
import { access, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
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
  assert.ok(corpus.cases.length >= 20);
  assert.equal(corpus.cases.filter((entry) => entry.classification === "vulnerable").length, corpus.cases.filter((entry) => entry.classification === "fixed").length);
  assert.ok(corpus.cases.every((entry) => entry.whyVulnerable.length > 0 && entry.whyFixed.length > 0 && entry.fixture.startsWith("fixtures/")));
  const expected = corpus.cases.flatMap((entry) => entry.expectedFindings);
  assert.ok(expected.length > 0);
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
    assert.equal(report.summary.allDetectedExpectedFindings, report.summary.truePositives + report.summary.knownMissesResolved);
    assert.equal(report.summary.allFalseNegatives, report.summary.falseNegatives + report.summary.knownMisses);
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
  assert.equal(report.summary.totalCases, 30);
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
  assert.equal(report.summary.falseNegatives, 13);
  assert.equal(report.summary.strictRegressions, 13);
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
  assert.equal(report.summary.fixedCaseFalsePositiveRate, 0.0667);
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
