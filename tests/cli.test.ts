import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, parseCliArgs } from "../src/cli.js";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

test("CLI parser keeps --tools none as built-in-only scope and rejects unknown flags", () => {
  const options = parseCliArgs(["scan", "--source", ".", "--tools", "none", "--fail-on", "none"]);
  assert.equal("help" in options, false);
  if (!("help" in options)) {
    assert.deepEqual(options.tools, []);
    assert.equal(options.failOn, "none");
  }
  assert.throws(() => parseCliArgs(["scan", "--source", ".", "--unknown"]));
  assert.throws(() => parseCliArgs(["scan", "--source", ".", "--timeout-ms", "0"]));
});

test("CLI writes the standard reports after a source scan starts", async () => {
  const root = await mkdtemp(join(tmpdir(), "wakeio-security-ci-cli-source-"));
  const out = join(root, "reports");
  try {
    await writeFile(join(root, "app.ts"), "export function run(input: string) { return eval(input); }\n");
    const code = await main(["scan", "--source", root, "--tools", "none", "--out", out, "--fail-on", "high"]);
    assert.equal(code, 1);
    for (const file of ["report.json", "report.sarif", "report.md"]) {
      assert.ok((await readFile(join(out, file), "utf8")).length > 0);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CLI keeps a Python-only built-in scan incomplete when external tools are disabled", async () => {
  const root = await mkdtemp(join(tmpdir(), "wakeio-security-ci-cli-python-"));
  const out = join(root, "reports");
  try {
    await writeFile(join(root, "app.py"), "print('ready')\n");
    const code = await main(["scan", "--source", root, "--tools", "none", "--out", out, "--fail-on", "none"]);
    assert.equal(code, 2);
    const report = JSON.parse(await readFile(join(out, "report.json"), "utf8")) as { checks: Array<{ id: string; status: string }> };
    assert.equal(report.checks.find((check) => check.id === "source.builtin-ast")?.status, "partial");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("installed-style CLI output distinguishes findings, completed scope, and incomplete scans without printing source", async () => {
  const root = await mkdtemp(join(tmpdir(), "wakeio-security-ci-summary-"));
  const launch = (source: string, out: string): Promise<{ code: number | null; stdout: string; stderr: string }> => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL("../src/cli.js", import.meta.url)), "scan", "--source", source, "--tools", "none", "--out", out]);
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (value: Buffer) => { stdout += value.toString(); });
    child.stderr.on("data", (value: Buffer) => { stderr += value.toString(); });
    child.on("error", reject);
    child.on("close", (code) => { resolve({ code, stdout, stderr }); });
  });
  try {
    const marker = "private_source_marker_48294";
    await writeFile(join(root, "app.ts"), `function handle(req: any) { const ${marker} = req.query.id; db.query("SELECT " + ${marker}); }`);
    const found = await launch(root, join(root, "reports"));
    assert.equal(found.code, 1);
    assert.match(found.stdout, /FINDINGS:/);
    assert.match(found.stdout, /Findings: 1 \(critical 0, high 1/);
    assert.match(found.stdout, /report.json, report.sarif, report.md/);
    assert.match(found.stderr, /scanning source scope/);
    assert.equal((found.stdout + found.stderr).includes(marker), false);
    await writeFile(join(root, "app.ts"), "export const fixed = 1;");
    const clean = await launch(root, join(root, "reports"));
    assert.equal(clean.code, 0);
    assert.match(clean.stdout, /COMPLETED:.*checked scope/);
    assert.match(clean.stdout, /Findings: 0/);
    const incomplete = await launch(join(root, "missing"), join(root, "failed-reports"));
    assert.equal(incomplete.code, 2);
    assert.match(incomplete.stdout, /INCOMPLETE:/);
    assert.doesNotMatch(incomplete.stdout, /COMPLETED:/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
