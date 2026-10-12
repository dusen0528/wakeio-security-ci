import test from "node:test";
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DAST_CHECK_ID, parseDastPolicy, runDast, type DastPolicy } from "../src/dast.js";
import { sanitizeDastExecution } from "../src/dast-execution.js";

const fixtureModule = new URL("../../examples/native-dast-sqlite.mjs", import.meta.url).href;
type Fixture = { origin: string; url: string; requests: Array<{ method: string; path: string; id: string | null }>; firstRequest: Promise<void>; close(): Promise<void> };
async function fixture(mode: string): Promise<Fixture> {
  return (await import(fixtureModule)).startNativeDastSqlite(mode) as Promise<Fixture>;
}
function policy(target: Fixture): DastPolicy {
  return { version: 1, kind: "sql-boolean-differential", baseUrl: `${target.origin}/`, url: target.url,
    parameter: "id", profile: "numeric", oracle: { jsonPointer: "/count", expectedBaseline: 1, expectedTrue: 1, expectedFalse: 0 } };
}

test("owned SQLite vulnerable and bound controls run exactly eight GETs with redacted evidence", async () => {
  for (const [mode, expectedOutcome, expectedFindings] of [["vulnerable", "observed", 1], ["bound", "not_observed", 0], ["ignored", "not_observed", 0]] as const) {
    const target = await fixture(mode);
    try {
      const [check] = await runDast({ policy: policy(target), consent: true, allowPrivate: true });
      assert.equal(check?.id, DAST_CHECK_ID);
      assert.equal(check?.status, "completed", mode);
      assert.equal(check?.findings.length, expectedFindings, mode);
      assert.equal(check?.metrics?.requestCount, 8);
      assert.equal(check?.dastExecution?.counts.httpAttempts, 8);
      assert.equal(check?.dastExecution?.outcome, expectedOutcome);
      assert.deepEqual(target.requests.map((request) => request.id),
        ["1", "1 AND 1=1", "1 AND 1=2", "1", "1", "1 AND 1=1", "1 AND 1=2", "1"]);
      assert.ok(target.requests.every((request) => request.method === "GET" && request.path === "/items"));
      if (expectedFindings) {
        assert.equal(check?.findings[0]?.kind, "candidate");
        assert.equal(check?.findings[0]?.confidence, "medium");
      }
      const serialized = JSON.stringify(check);
      for (const forbidden of ["1 AND 1=1", "1 AND 1=2", "id=1", "\"expectedBaseline\":1", "\"count\":1"]) {
        assert.equal(serialized.includes(forbidden), false, `leaked ${forbidden}`);
      }
    } finally { await target.close(); }
  }
});

test("strict policy, consent and options preflight prevent traffic", async () => {
  const target = await fixture("vulnerable");
  try {
    const accepted = policy(target);
    const cases: unknown[] = [
      { ...accepted, url: `${target.origin}/items?id=1&id=2` },
      { ...accepted, url: `${target.origin}/items?other=1` },
      { ...accepted, url: "http://example.test/items?id=1" },
      { ...accepted, url: `${target.origin}/items?id=abc` },
      { ...accepted, oracle: { ...accepted.oracle, expectedTrue: 0 } },
      { ...accepted, profile: "single-quoted" },
    ];
    for (const input of cases) assert.throws(() => parseDastPolicy(input));
    let read = 0;
    const getterPolicy = { ...accepted, get parameter() { read++; return "id"; } };
    assert.throws(() => parseDastPolicy(getterPolicy));
    assert.equal(read, 0, "policy accessors are never invoked");
    const [noConsent] = await runDast({ policy: accepted, consent: false, allowPrivate: true });
    assert.equal(noConsent?.metrics?.errorCode, "consent_required");
    const [invalid] = await runDast({ policy: cases[0] as DastPolicy, consent: true, allowPrivate: true });
    assert.equal(invalid?.metrics?.errorCode, "invalid_policy");
    const [blocked] = await runDast({ policy: accepted, consent: true });
    assert.equal(blocked?.status, "partial");
    assert.equal(blocked?.metrics?.requestCount, 0);
    assert.equal(target.requests.length, 0);
  } finally { await target.close(); }
});

test("request budget is a wire count: seven is incomplete, eight and nine send eight", async () => {
  for (const [budget, expectedHits, expectedStatus] of [[7, 7, "partial"], [8, 8, "completed"], [9, 8, "completed"]] as const) {
    const target = await fixture("vulnerable");
    try {
      const [check] = await runDast({ policy: policy(target), consent: true, allowPrivate: true, maxRequests: budget });
      assert.equal(check?.status, expectedStatus);
      assert.equal(check?.metrics?.requestCount, expectedHits);
      assert.equal(target.requests.length, expectedHits);
      assert.equal(check?.dastExecution?.counts.httpAttempts, expectedHits);
      assert.equal(check?.findings.length, budget >= 8 ? 1 : 0);
      if (budget === 7) assert.equal(check?.dastExecution?.stopReason, "request_budget");
    } finally { await target.close(); }
  }
});

test("response byte budgets stop before a fifth request and reject oversized bodies", async () => {
  for (const [mode, expectedHits, expectedEvaluated] of [["large-exact", 4, 4], ["large-over", 1, 0], ["large-compressed", 1, 0]] as const) {
    const target = await fixture(mode);
    try {
      const [check] = await runDast({ policy: policy(target), consent: true, allowPrivate: true });
      assert.equal(check?.status, "partial", mode);
      assert.deepEqual(check?.findings, [], mode);
      assert.equal(check?.dastExecution?.stopReason, "body_budget", mode);
      assert.equal(check?.metrics?.requestCount, expectedHits, mode);
      assert.equal(target.requests.length, expectedHits, mode);
      assert.equal(check?.dastExecution?.counts.evaluated, expectedEvaluated, mode);
      assert.equal(check?.dastExecution?.steps[expectedEvaluated]?.outcome, "inconclusive", mode);
      assert.equal(check?.dastExecution?.steps[expectedEvaluated]?.httpAttempts, mode === "large-exact" ? 0 : 1, mode);
      assert.ok(check?.dastExecution?.steps.slice(expectedEvaluated + 1).every(step => step.outcome === "not_attempted"), mode);
    } finally { await target.close(); }
  }
});

test("drift, malformed output, server errors, redirects and echo never become findings", async () => {
  for (const mode of ["drift", "malformed", "server-error", "redirect", "echo"] as const) {
    const target = await fixture(mode);
    try {
      const [check] = await runDast({ policy: policy(target), consent: true, allowPrivate: true });
      assert.equal(check?.status, "partial", mode);
      assert.deepEqual(check?.findings, [], mode);
      assert.equal(check?.dastExecution?.outcome, "inconclusive");
      assert.ok(Number(check?.metrics?.requestCount) >= 1 && Number(check?.metrics?.requestCount) <= 8);
    } finally { await target.close(); }
  }
});

test("deadline and in-flight cancellation preserve an incomplete ledger", async () => {
  const target = await fixture("slow");
  try {
    const [timed] = await runDast({ policy: policy(target), consent: true, allowPrivate: true, timeoutMs: 20 });
    assert.equal(timed?.status, "partial");
    assert.equal(timed?.findings.length, 0);
    assert.equal(timed?.dastExecution?.stopReason, "deadline");
    assert.ok(Number(timed?.metrics?.requestCount) <= 1);
  } finally { await target.close(); }
  const cancelling = await fixture("slow");
  try {
    const controller = new AbortController();
    const pending = runDast({ policy: policy(cancelling), consent: true, allowPrivate: true, signal: controller.signal });
    await cancelling.firstRequest;
    controller.abort();
    const [cancelled] = await pending;
    assert.equal(cancelled?.status, "partial");
    assert.equal(cancelled?.findings.length, 0);
    assert.equal(cancelled?.dastExecution?.stopReason, "cancelled");
    assert.equal(cancelled?.metrics?.requestCount, 1);
    assert.equal(cancelling.requests.length, 1);
    assert.equal(cancelled?.dastExecution?.steps[0]?.outcome, "inconclusive");
    assert.ok(cancelled?.dastExecution?.steps.slice(1).every(step => step.outcome === "not_attempted"));
  } finally { await cancelling.close(); }
});

test("deadline abort keeps its cause when the wall clock has not reached the deadline", async (t) => {
  const target = await fixture("slow");
  const now = Date.now();
  const clock = t.mock.method(Date, "now", () => now);
  try {
    const [check] = await runDast({ policy: policy(target), consent: true, allowPrivate: true, timeoutMs: 20 });
    assert.equal(check?.status, "partial");
    assert.deepEqual(check?.findings, []);
    assert.equal(check?.dastExecution?.stopReason, "deadline");
    assert.equal(check?.dastExecution?.steps[0]?.reason, "deadline");
    assert.ok(Number(check?.metrics?.requestCount) <= 1);
    assert.ok(check?.dastExecution?.steps.slice(1).every(step => step.outcome === "not_attempted"));
  } finally { clock.mock.restore(); await target.close(); }
});

test("caller cancellation keeps its cause when the wall clock passes the deadline before handling", async (t) => {
  const target = await fixture("slow");
  let now = Date.now();
  const clock = t.mock.method(Date, "now", () => now);
  const controller = new AbortController();
  try {
    const pending = runDast({ policy: policy(target), consent: true, allowPrivate: true, timeoutMs: 30_000, signal: controller.signal });
    await target.firstRequest;
    controller.abort();
    now += 60_000;
    const [check] = await pending;
    assert.equal(check?.status, "partial");
    assert.deepEqual(check?.findings, []);
    assert.equal(check?.dastExecution?.stopReason, "cancelled");
    assert.equal(check?.dastExecution?.steps[0]?.reason, "cancelled");
    assert.equal(check?.metrics?.requestCount, 1);
    assert.equal(target.requests.length, 1);
    assert.ok(check?.dastExecution?.steps.slice(1).every(step => step.outcome === "not_attempted"));
  } finally { clock.mock.restore(); await target.close(); }
});

test("ledger sanitizer rejects forged completion, accidental values and accessor objects", async () => {
  const target = await fixture("vulnerable");
  try {
    const [check] = await runDast({ policy: policy(target), consent: true, allowPrivate: true });
    const ledger = check!.dastExecution!;
    assert.ok(sanitizeDastExecution(ledger));
    assert.equal(sanitizeDastExecution({ ...ledger, steps: ledger.steps.map((step, i) => i === 0 ? { ...step, oracleMatch: "other" } : step) }), null);
    let read = 0;
    const hostile = { ...ledger, get policySha256() { read++; return ledger.policySha256; } };
    assert.equal(sanitizeDastExecution(hostile), null);
    assert.equal(read, 0);
    assert.equal(sanitizeDastExecution({ ...ledger, status: "partial", outcome: "inconclusive", stopReason: "cancelled" }), null);
    assert.equal(sanitizeDastExecution({ ...ledger, maxRequests: 7 }), null);
  } finally { await target.close(); }
});

test("local CA HTTPS counts real requests; untrusted and wrong-host certificates fail", { timeout: 30_000 }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "wakeio-native-dast-tls-"));
  const caKey = join(directory, "ca.key"), ca = join(directory, "ca.crt");
  const serverKey = join(directory, "server.key"), csr = join(directory, "server.csr"), serverCert = join(directory, "server.crt");
  const ext = join(directory, "server.ext");
  let target: Fixture | undefined;
  const openssl = (...args: string[]) => execFileSync("openssl", args, { stdio: "ignore" });
  try {
    openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", caKey, "-out", ca,
      "-subj", "/CN=Wakeio Owned Test CA", "-days", "1", "-addext", "basicConstraints=critical,CA:TRUE");
    openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", serverKey, "-out", csr,
      "-subj", "/CN=127.0.0.1");
    await writeFile(ext, "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n");
    openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", caKey, "-CAcreateserial", "-out", serverCert,
      "-days", "1", "-extfile", ext);
    target = (await (await import(fixtureModule)).startNativeDastSqlite("vulnerable", {
      key: await readFile(serverKey), cert: await readFile(serverCert),
    })) as Fixture;
    const clientPath = join(process.cwd(), "tests/fixtures/native-dast-https-client.mjs");
    const runClient = async (url: string, trust: boolean): Promise<{ status: string; findings: number; attempts: number; stopReason: string }> => {
      const child = spawn(process.execPath, [clientPath, url], { cwd: process.cwd(),
        env: { PATH: process.env.PATH ?? "", ...(trust ? { NODE_EXTRA_CA_CERTS: ca } : {}) }, stdio: ["ignore", "pipe", "pipe"] });
      const stdout: Buffer[] = [], stderr: Buffer[] = [];
      child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
      child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
      const code = await new Promise<number | null>((resolve, reject) => {
        child.once("error", reject); child.once("close", resolve);
      });
      assert.equal(code, 0, Buffer.concat(stderr).toString("utf8"));
      return JSON.parse(Buffer.concat(stdout).toString("utf8")) as { status: string; findings: number; attempts: number; stopReason: string };
    };
    const trusted = await runClient(target.url, true);
    assert.deepEqual({ status: trusted.status, findings: trusted.findings, attempts: trusted.attempts },
      { status: "completed", findings: 1, attempts: 8 });
    assert.equal(target.requests.length, 8);
    const untrusted = await runClient(target.url, false);
    assert.equal(untrusted.status, "partial");
    assert.equal(untrusted.findings, 0);
    assert.equal(target.requests.length, 8, "untrusted TLS never reaches the HTTP fixture");
    const wrongHost = await runClient(target.url.replace("127.0.0.1", "localhost"), true);
    assert.equal(wrongHost.status, "partial");
    assert.equal(wrongHost.findings, 0);
    assert.equal(target.requests.length, 8, "hostname mismatch never reaches the HTTP fixture");
  } finally {
    await target?.close();
    await rm(directory, { recursive: true, force: true });
  }
});
