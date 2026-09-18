import test from "node:test";
import assert from "node:assert/strict";
import { parseOsvOutput } from "../src/source/parsers.js";
import type { CollectedFile } from "../src/source/types.js";

const files: CollectedFile[] = [{
  path: "package-lock.json",
  bytes: 2,
  text: "{}",
  category: "dependency",
  sensitive: false,
}];

function report(packageResult: Record<string, unknown>): string {
  return JSON.stringify({
    results: [{
      source: { path: "/scan/package-lock.json", type: "lockfile" },
      packages: [packageResult],
    }],
  });
}

test("OSV 2.6 clean package records may omit vulnerabilities", () => {
  const parsed = parseOsvOutput(report({
    package: { name: "@emnapi/runtime", version: "1.11.3", ecosystem: "npm" },
    dependency_groups: ["optional"],
  }), "/scan", files);

  assert.equal(parsed.findings.length, 0);
  assert.equal(parsed.metrics?.packageCount, 1);
  assert.match(parsed.notes.join(" "), /1 package record/);
});

test("OSV vulnerability arrays still produce advisory findings", () => {
  const parsed = parseOsvOutput(report({
    package: { name: "demo-package", version: "1.0.0", ecosystem: "npm" },
    vulnerabilities: [{
      id: "GHSA-test-example-demo",
      database_specific: { severity: "HIGH" },
      references: [{ type: "ADVISORY", url: "https://osv.dev/vulnerability/GHSA-test-example-demo" }],
    }],
  }), "/scan", files);

  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0]?.severity, "high");
  assert.match(parsed.findings[0]?.ruleId ?? "", /GHSA-test-example-demo/);
});

test("OSV malformed vulnerability fields remain rejected", () => {
  for (const vulnerabilities of [null, {}, "clean"]) {
    assert.throws(() => parseOsvOutput(report({
      package: { name: "demo-package", version: "1.0.0", ecosystem: "npm" },
      vulnerabilities,
    }), "/scan", files));
  }
});
