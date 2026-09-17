import test from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSource } from "../src/source.js";

async function scratch(): Promise<string> {
  return mkdtemp(join(tmpdir(), "wakeio-security-ci-python-"));
}

test("Bandit receives only the staged Python allowlist and its raw output never reaches findings", async () => {
  const top = await scratch();
  const root = join(top, "source");
  const marker = join(top, "bandit-boundary-marker");
  const secret = "synthetic-bandit-source-value-should-not-appear";
  const fake = join(top, "bandit");
  try {
    await mkdir(root);
    await writeFile(join(root, "app.py"), "# nosec\nimport subprocess\nsubprocess.run(['echo', 'ok'])\n");
    await writeFile(join(root, "notes.txt"), "this must not be staged for Bandit\n");
    await writeFile(join(root, ".bandit"), "[bandit]\ntests = B602\n");
    await writeFile(join(root, "bandit.yaml"), "tests: [B602]\n");
    const markerLiteral = JSON.stringify(marker);
    const secretLiteral = JSON.stringify(secret);
    const script = [
      "#!/usr/bin/env node",
      "const fs = require(\"node:fs\");",
      "const path = require(\"node:path\");",
      "const marker = " + markerLiteral + ";",
      "const walk = (directory) => fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {",
      "  const child = path.join(directory, entry.name);",
      "  return entry.isDirectory() ? walk(child) : [child];",
      "});",
      "const args = process.argv.slice(2);",
      "const stagedFiles = walk(process.cwd());",
      "if (!args.includes(\"-f\") || args[args.indexOf(\"-f\") + 1] !== \"json\" || !args.includes(\"--ignore-nosec\") || args.includes(\"-r\") || args.includes(\"-c\") || args.includes(\"--ini\") || stagedFiles.some((entry) => !entry.endsWith(\".py\"))) {",
      "  fs.writeFileSync(marker, \"unsafe Bandit argv or non-Python staged file\");",
      "}",
      "const targets = args.filter((entry) => entry.endsWith(\".py\"));",
      "const target = targets[0];",
      "const metrics = { _totals: { loc: 3, nosec: 0, skipped_tests: 0 } };",
      "metrics[target] = { loc: 3, nosec: 0, skipped_tests: 0 };",
      "process.stdout.write(JSON.stringify({",
      "  errors: [],",
      "  generated_at: \"2026-09-16T00:00:00Z\",",
      "  metrics,",
      "  results: [{",
      "    code: " + secretLiteral + ",",
      "    filename: target,",
      "    issue_confidence: \"HIGH\",",
      "    issue_severity: \"HIGH\",",
      "    issue_text: " + secretLiteral + ",",
      "    line_number: 3,",
      "    line_range: [3],",
      "    test_name: \"subprocess_popen_with_shell_equals_true\",",
      "    test_id: \"B602\"",
      "  }]",
      "}));",
    ].join("\n");
    await writeFile(fake, script);
    await chmod(fake, 0o700);
    const checks = await runSource({ root, tools: ["bandit"], toolPaths: { bandit: fake }, timeoutMs: 3000 });
    const bandit = checks.find((check) => check.id === "source.bandit");
    assert.equal(bandit?.status, "completed");
    assert.equal(bandit?.findings.length, 1);
    assert.equal(bandit?.findings[0]?.ruleId, "bandit:B602");
    assert.equal(JSON.stringify(checks).includes(secret), false);
    await assert.rejects(readFile(marker));
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});

test("Bandit rejects malformed or incomplete JSON rather than reporting a clean Python scan", async () => {
  const top = await scratch();
  const root = join(top, "source");
  const fake = join(top, "bandit");
  try {
    await mkdir(root);
    await writeFile(join(root, "app.py"), "print('ready')\n");
    await writeFile(fake, "#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({ errors: [], results: [] }));\n");
    await chmod(fake, 0o700);
    const checks = await runSource({ root, tools: ["bandit"], toolPaths: { bandit: fake }, timeoutMs: 3000 });
    const bandit = checks.find((check) => check.id === "source.bandit");
    assert.equal(bandit?.status, "error");
    assert.match(bandit?.notes[0] ?? "", /invalid|incomplete/i);
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});

test("Bandit scanner errors are incomplete and do not expose the scanner reason", async () => {
  const top = await scratch();
  const root = join(top, "source");
  const fake = join(top, "bandit");
  const secret = "synthetic-bandit-error-secret";
  try {
    await mkdir(root);
    await writeFile(join(root, "app.py"), "print('ready')\n");
    const secretLiteral = JSON.stringify(secret);
    const script = [
      "#!/usr/bin/env node",
      "const target = process.argv.find((value) => value.endsWith(\".py\"));",
      "const metrics = { _totals: { loc: 1, nosec: 0, skipped_tests: 0 } };",
      "metrics[target] = { loc: 1, nosec: 0, skipped_tests: 0 };",
      "process.stdout.write(JSON.stringify({ errors: [{ filename: target, reason: " + secretLiteral + " }], generated_at: \"2026-09-16T00:00:00Z\", metrics, results: [] }));",
    ].join("\n");
    await writeFile(fake, script);
    await chmod(fake, 0o700);
    const checks = await runSource({ root, tools: ["bandit"], toolPaths: { bandit: fake }, timeoutMs: 3000 });
    const bandit = checks.find((check) => check.id === "source.bandit");
    assert.equal(bandit?.status, "partial");
    assert.equal(JSON.stringify(checks).includes(secret), false);
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});

test("Bandit rejects a finding line outside the selected Python file bounds", async () => {
  const top = await scratch();
  const root = join(top, "source");
  const fake = join(top, "bandit");
  try {
    await mkdir(root);
    await writeFile(join(root, "app.py"), "print('ready')\n");
    const script = [
      "#!/usr/bin/env node",
      "const target = process.argv.find((value) => value.endsWith(\".py\"));",
      "const metrics = { _totals: { loc: 1 } };",
      "metrics[target] = { loc: 1 };",
      "process.stdout.write(JSON.stringify({ errors: [], generated_at: \"2026-09-16T00:00:00Z\", metrics, results: [{ code: \"x\", filename: target, issue_confidence: \"HIGH\", issue_severity: \"HIGH\", issue_text: \"x\", line_number: 2, line_range: [2], test_name: \"x\", test_id: \"B603\" }] }));",
    ].join("\n");
    await writeFile(fake, script);
    await chmod(fake, 0o700);
    const checks = await runSource({ root, tools: ["bandit"], toolPaths: { bandit: fake }, timeoutMs: 3000 });
    const bandit = checks.find((check) => check.id === "source.bandit");
    assert.equal(bandit?.status, "error");
    assert.match(bandit?.notes[0] ?? "", /invalid|incomplete/i);
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});

test("Bandit B603 findings use the rule-specific documentation link", async () => {
  const top = await scratch();
  const root = join(top, "source");
  const fake = join(top, "bandit");
  try {
    await mkdir(root);
    await writeFile(join(root, "app.py"), "import subprocess\n");
    const script = [
      "#!/usr/bin/env node",
      "const target = process.argv.find((value) => value.endsWith(\".py\"));",
      "const metrics = { _totals: { loc: 1 } };",
      "metrics[target] = { loc: 1 };",
      "process.stdout.write(JSON.stringify({ errors: [], generated_at: \"2026-09-16T00:00:00Z\", metrics, results: [{ code: \"subprocess.run(x)\", filename: target, issue_confidence: \"HIGH\", issue_severity: \"MEDIUM\", issue_text: \"subprocess\", line_number: 1, line_range: [1], test_name: \"subprocess_without_shell_equals_true\", test_id: \"B603\" }] }));",
    ].join("\n");
    await writeFile(fake, script);
    await chmod(fake, 0o700);
    const checks = await runSource({ root, tools: ["bandit"], toolPaths: { bandit: fake }, timeoutMs: 3000 });
    const bandit = checks.find((check) => check.id === "source.bandit");
    assert.equal(bandit?.status, "completed");
    assert.equal(bandit?.findings[0]?.references?.[0], "https://bandit.readthedocs.io/en/latest/plugins/b603_subprocess_without_shell_equals_true.html");
  } finally {
    await rm(top, { recursive: true, force: true });
  }
});
