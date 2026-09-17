import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createReport, exitCode } from "../src/report.js";
import { runSource } from "../src/source.js";
import { parseTrivyOutput } from "../src/source/parsers.js";

async function scratch(): Promise<string> {
  return mkdtemp(join(tmpdir(), "wakeio-security-ci-source-"));
}

test("source mode runs built-in AST candidates without retaining source values", async () => {
  const root = await scratch();
  try {
    const secret = "ghp_SYNTHETIC_SOURCE_VALUE_SHOULD_NOT_APPEAR";
    await writeFile(join(root, "app.ts"), `export function render(req: any) { eval(req.query.name); document.body.innerHTML = req.query.name; }\nconst token = '${secret}';\n`);
    await writeFile(join(root, ".env"), `TOKEN=${secret}\n`);
    const checks = await runSource({ root, tools: [] });
    const data = JSON.stringify(checks);
    assert.equal(data.includes(secret), false);
    const ast = checks.find((check) => check.id === "source.builtin-ast");
    assert.ok(ast);
    assert.ok(ast.findings.some((finding) => finding.ruleId === "ast:dynamic-code"));
    assert.ok(ast.findings.some((finding) => finding.ruleId === "ast:html-input-sink"));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("source findings carry stable semantic keys while duplicate anchors remain visible", async () => {
  const top = await scratch();
  const beforeRoot = join(top, "before");
  const afterRoot = join(top, "after");
  try {
    await mkdir(beforeRoot);
    await mkdir(afterRoot);
    await writeFile(join(beforeRoot, "app.ts"), [
      "function load(req: any) {",
      "  const id = req.query.id;",
      "  db.query(\"select * from users where id = \" + id);",
      "}",
    ].join("\n"));
    await writeFile(join(afterRoot, "app.ts"), [
      "// a comment and import moved the display line",
      'import type { Marker } from "marker";',
      "function load(req: any) {",
      "  const id = req.query.id;",
      "  db . query ( \"select * from users where id = \" + id ); // same semantic call",
      "}",
    ].join("\n"));
    const beforeChecks = await runSource({ root: beforeRoot, tools: [] });
    const afterChecks = await runSource({ root: afterRoot, tools: [] });
    const beforeFinding = beforeChecks.find((check) => check.id === "source.builtin-ast")?.findings.find((finding) => finding.ruleId === "ast:sql-input-sink");
    const afterFinding = afterChecks.find((check) => check.id === "source.builtin-ast")?.findings.find((finding) => finding.ruleId === "ast:sql-input-sink");
    assert.match(beforeFinding?.comparisonKey ?? "", /^[a-f0-9]{64}$/);
    assert.equal(beforeFinding?.comparisonKey, afterFinding?.comparisonKey);
    assert.notEqual(beforeFinding?.location.line, afterFinding?.location.line);

    await writeFile(join(afterRoot, "app.ts"), [
      "function load(req: any) {",
      "  db.query(\"select \" + req.query.id);",
      "  db.query(\"select \" + req.query.id);",
      "}",
    ].join("\n"));
    const duplicateChecks = await runSource({ root: afterRoot, tools: [] });
    const duplicateFindings = duplicateChecks.find((check) => check.id === "source.builtin-ast")?.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink") ?? [];
    assert.equal(duplicateFindings.length, 2);
    assert.equal(duplicateFindings[0]?.comparisonKey, duplicateFindings[1]?.comparisonKey);
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});

test("source collector rejects symlinks and reports truncation as incomplete", async () => {
  const top = await scratch();
  const root = join(top, "source");
  try {
    await mkdir(root);
    await writeFile(join(top, "outside.env"), "TOKEN=synthetic-outside-value\n");
    await symlink(join(top, "outside.env"), join(root, "linked.env"));
    await writeFile(join(root, "one.ts"), "export const one = 1;\n");
    await writeFile(join(root, "two.ts"), "export const two = 2;\n");
    const checks = await runSource({ root, tools: [], maxFiles: 1 });
    const data = JSON.stringify(checks);
    assert.equal(data.includes("synthetic-outside-value"), false);
    assert.ok(checks.some((check) => check.status === "partial" || check.status === "error"));
    assert.ok(checks.some((check) => check.notes.some((note) => /symlink|file_limit|coverage/i.test(note))));
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});

test("source mode never executes target npm scripts", async () => {
  const root = await scratch();
  try {
    await writeFile(join(root, "package.json"), JSON.stringify({ scripts: { postinstall: "touch SHOULD_NOT_EXIST" } }));
    await writeFile(join(root, "app.js"), "export const ready = true;\n");
    const checks = await runSource({ root, tools: [] });
    assert.ok(checks.length > 0);
    await assert.rejects(readFile(join(root, "SHOULD_NOT_EXIST")));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Trivy is not invoked for Terraform that can resolve modules or file functions", async () => {
  const root = await scratch();
  const marker = join(root, "trivy-invoked");
  const fake = join(root, "trivy");
  try {
    await writeFile(join(root, "remote.tf"), 'module "remote" { source = "registry.example/example/module" }\n');
    await writeFile(join(root, "escaped.tf.json"), '{"mo\\u0064ule":{"remote":{"source":"https://example.invalid/module"}}}\n');
    await writeFile(fake, `#!/bin/sh\ntouch '${marker}'\nprintf '%s\\n' '{"SchemaVersion":2,"Results":[]}'\n`);
    await chmod(fake, 0o700);
    const checks = await runSource({ root, tools: ["trivy"], toolPaths: { trivy: fake }, timeoutMs: 1000 });
    assert.ok(checks.some((check) => check.id === "source.trivy" && check.status === "partial"));
    await assert.rejects(readFile(marker));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Trivy's valid no-target envelope is not applicable while an empty object is rejected", () => {
  const result = parseTrivyOutput(JSON.stringify({
    SchemaVersion: 2,
    Trivy: { Version: "0.74.0" },
    ReportID: "01a0a548-8eff-7674-bd09-8ad18846fb62",
    CreatedAt: "2026-09-15T22:36:30.975425+09:00",
    ArtifactName: "/private/tmp/wakeio-ci-verification/plain-config",
    ArtifactType: "filesystem",
  }), "/scan", []);
  assert.equal(result.status, "not_applicable");
  assert.throws(() => parseTrivyOutput("{}", "/scan", []));
});

test("OSV is not applicable without dependency input and AST keeps the scan incomplete", async () => {
  const root = await scratch();
  try {
    await writeFile(join(root, "app.py"), "print('ready')\n");
    const checks = await runSource({ root, tools: ["osv"], toolPaths: { osv: join(root, "missing-osv") }, timeoutMs: 1000 });
    const ast = checks.find((check) => check.id === "source.builtin-ast");
    const osv = checks.find((check) => check.id === "source.osv");
    assert.equal(ast?.status, "partial");
    assert.equal(osv?.status, "not_applicable");
    assert.equal(exitCode(createReport(checks, "source", new Date()), "none"), 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("OSV remains partial when a dependency manifest declares packages without a supported lockfile", async () => {
  const root = await scratch();
  try {
    await writeFile(join(root, "app.py"), "print('ready')\n");
    await writeFile(join(root, "pyproject.toml"), "[project]\ndependencies = [\"requests>=2\"]\n");
    const checks = await runSource({ root, tools: ["osv"], toolPaths: { osv: join(root, "missing-osv") }, timeoutMs: 1000 });
    const ast = checks.find((check) => check.id === "source.builtin-ast");
    const osv = checks.find((check) => check.id === "source.osv");
    assert.equal(ast?.status, "not_applicable");
    assert.equal(osv?.status, "partial");
    assert.equal(exitCode(createReport(checks, "source", new Date()), "none"), 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Python with a supported lockfile can complete OSV while AST is not applicable", async () => {
  const root = await scratch();
  const fakeOsv = join(root, "osv-scanner");
  try {
    await writeFile(join(root, "app.py"), "print('ready')\n");
    await writeFile(join(root, "poetry.lock"), "[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n");
    await writeFile(fakeOsv, `#!/usr/bin/env node
const output = { results: [{ source: { path: "poetry.lock", type: "lockfile" }, packages: [{ package: { name: "requests", ecosystem: "PyPI", version: "2.31.0" }, vulnerabilities: [] }] }] };
process.stdout.write(JSON.stringify(output));
`);
    await chmod(fakeOsv, 0o700);
    // The fake scanner is a child Node process; allow hosted runners' process
    // startup variance while keeping scanner timeout-specific tests strict.
    const checks = await runSource({ root, tools: ["osv", "trivy"], toolPaths: { osv: fakeOsv, trivy: join(root, "missing-trivy") }, timeoutMs: 5000 });
    const ast = checks.find((check) => check.id === "source.builtin-ast");
    const osv = checks.find((check) => check.id === "source.osv");
    const trivy = checks.find((check) => check.id === "source.trivy");
    assert.equal(ast?.status, "not_applicable");
    assert.equal(osv?.status, "completed");
    assert.equal(trivy?.status, "not_applicable");
    assert.equal(exitCode(createReport(checks, "source", new Date()), "none"), 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("JavaScript with a supported lockfile can complete OSV while Trivy stays not applicable without IaC", async () => {
  const root = await scratch();
  const fakeOsv = join(root, "osv-scanner");
  try {
    await writeFile(join(root, "app.js"), "export const ready = true;\n");
    await writeFile(join(root, "package-lock.json"), "{}\n");
    await writeFile(fakeOsv, `#!/usr/bin/env node
const output = { results: [{ source: { path: "package-lock.json", type: "lockfile" }, packages: [{ package: { name: "demo", ecosystem: "npm", version: "1.0.0" }, vulnerabilities: [] }] }] };
process.stdout.write(JSON.stringify(output));
`);
    await chmod(fakeOsv, 0o700);
    // The fake scanner is a child Node process; allow hosted runners' process
    // startup variance while keeping scanner timeout-specific tests strict.
    const checks = await runSource({ root, tools: ["osv", "trivy"], toolPaths: { osv: fakeOsv, trivy: join(root, "missing-trivy") }, timeoutMs: 5000 });
    const ast = checks.find((check) => check.id === "source.builtin-ast");
    const osv = checks.find((check) => check.id === "source.osv");
    const trivy = checks.find((check) => check.id === "source.trivy");
    assert.equal(ast?.status, "completed");
    assert.equal(osv?.status, "completed");
    assert.equal(trivy?.status, "not_applicable");
    assert.equal(exitCode(createReport(checks, "source", new Date()), "none"), 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Bandit is not resolved for a source snapshot without Python files", async () => {
  const root = await scratch();
  try {
    await writeFile(join(root, "app.ts"), "export const ready = true;\n");
    const checks = await runSource({ root, tools: ["bandit"], toolPaths: { bandit: join(root, "missing-bandit") }, timeoutMs: 1000 });
    const bandit = checks.find((check) => check.id === "source.bandit");
    const framework = checks.find((check) => check.id === "source.framework");
    assert.equal(bandit?.status, "not_applicable");
    assert.equal(framework?.status, "not_applicable");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Python-only tools none remains incomplete when no built-in framework input is present", async () => {
  const root = await scratch();
  try {
    await writeFile(join(root, "app.py"), "print('ready')\n");
    const checks = await runSource({ root, tools: [] });
    const ast = checks.find((check) => check.id === "source.builtin-ast");
    const framework = checks.find((check) => check.id === "source.framework");
    assert.equal(ast?.status, "partial");
    assert.equal(framework?.status, "not_applicable");
    assert.equal(exitCode(createReport(checks, "source", new Date()), "none"), 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("OSV passes fully pinned requirements and uv.lock inputs while keeping unresolved files partial", async () => {
  const top = await scratch();
  const root = join(top, "source");
  const fakeOsv = join(top, "osv-scanner");
  const marker = join(top, "osv-lockfiles.json");
  try {
    await mkdir(root);
    await writeFile(join(root, "requirements.txt"), "requests==2.31.0\n");
    await writeFile(join(root, "requirements-dev.txt"), "requests>=2.0\n");
    await writeFile(join(root, "requirements-prod.txt"), "-r requirements.txt\n");
    await writeFile(join(root, "uv.lock"), [
      "version = 1",
      "revision = 1",
      "requires-python = \">=3.11\"",
      "",
      "[[package]]",
      "name = \"requests\"",
      "version = \"2.31.0\"",
      "source = { registry = \"https://pypi.org/simple\" }",
    ].join("\n"));
    const script = [
      "#!/usr/bin/env node",
      "const fs = require(\"node:fs\");",
      "const args = process.argv.slice(2);",
      "const lockfiles = [];",
      "for (let index = 0; index < args.length; index += 1) if (args[index] === \"--lockfile\") lockfiles.push(args[index + 1]);",
      `fs.writeFileSync(${JSON.stringify(marker)}, JSON.stringify(lockfiles));`,
      "const target = lockfiles[0];",
      "process.stdout.write(JSON.stringify({ results: [{ source: { path: target, type: \"lockfile\" }, packages: [{ package: { name: \"requests\", ecosystem: \"PyPI\", version: \"2.31.0\" }, vulnerabilities: [] }] }] }));",
    ].join("\n");
    await writeFile(fakeOsv, script);
    await chmod(fakeOsv, 0o700);
    const checks = await runSource({ root, tools: ["osv"], toolPaths: { osv: fakeOsv }, timeoutMs: 3000 });
    const osv = checks.find((check) => check.id === "source.osv");
    assert.equal(osv?.status, "partial");
    assert.equal(osv?.metrics?.packageCount, 1);
    const passed = JSON.parse(await readFile(marker, "utf8")) as string[];
    assert.ok(passed.some((path) => path.endsWith("/requirements.txt")));
    assert.ok(passed.some((path) => path.endsWith("/uv.lock")));
    assert.equal(passed.some((path) => path.endsWith("/requirements-dev.txt")), false);
    assert.equal(passed.some((path) => path.endsWith("/requirements-prod.txt")), false);
    assert.match(osv?.notes.join(" ") ?? "", /requirements file was excluded|partial/i);
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});

test("OSV does not invoke a scanner or report clean for only range/include requirements", async () => {
  const top = await scratch();
  const root = join(top, "source");
  const marker = join(top, "osv-invoked");
  const fakeOsv = join(top, "osv-scanner");
  try {
    await mkdir(root);
    await writeFile(join(root, "requirements.txt"), "requests>=2.0\n");
    await writeFile(join(root, "requirements-dev.txt"), "-r requirements.txt\n");
    const script = [
      "#!/usr/bin/env node",
      `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "invoked");`,
      "process.stdout.write(JSON.stringify({ results: [] }));",
    ].join("\n");
    await writeFile(fakeOsv, script);
    await chmod(fakeOsv, 0o700);
    const checks = await runSource({ root, tools: ["osv"], toolPaths: { osv: fakeOsv }, timeoutMs: 3000 });
    const osv = checks.find((check) => check.id === "source.osv");
    assert.equal(osv?.status, "partial");
    assert.equal(osv?.metrics?.lockfiles, 0);
    await assert.rejects(readFile(marker));
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});
