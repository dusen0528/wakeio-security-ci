import test from "node:test";
import assert from "node:assert/strict";
import { runApiPolicy } from "../src/api.js";
import { createReport } from "../src/report.js";
import { replayApiFinding, replayExitCode } from "../src/replay.js";
import { parseReplayArgs } from "../src/cli.js";
import { PROOF_ENV, proofPolicy, startProofFixture, type ProofFixture } from "./proof-fixture.js";

async function scanned(fixture: ProofFixture) {
  const policy = proofPolicy(fixture.baseUrl);
  const [check] = await runApiPolicy({ policy, env: PROOF_ENV, allowPrivate: true, timeoutMs: 5000 });
  // Round-trip through JSON as `replay --report report.json` does.
  const report = JSON.parse(JSON.stringify(createReport([check], "api", new Date())));
  const findingId: string = report.checks[0].findings[0].id;
  fixture.requests.length = 0;
  return { policy, report, findingId };
}

const replayOptions = { env: PROOF_ENV, allowPrivate: true, timeoutMs: 5000 };

test("replay re-executes only the finding's case, owner and probe actor and reproduces the leak", async () => {
  const fixture = await startProofFixture();
  try {
    const { policy, report, findingId } = await scanned(fixture);
    const result = await replayApiFinding({ report, policy, findingId, ...replayOptions });
    assert.equal(result.outcome, "reproduced");
    assert.equal(replayExitCode(result), 1);
    assert.deepEqual(result.replay && [result.replay.caseId, result.replay.actor], ["owner-document", "other"]);
    // owner + other identity before/after, owner-before, the single probe, owner-after.
    assert.deepEqual(fixture.requests.map((request) => `${request.actor} ${request.path}`), [
      "owner /whoami", "other /whoami", "owner /documents/doc-1", "other /documents/doc-1", "owner /documents/doc-1", "owner /whoami", "other /whoami"]);
  } finally { await fixture.close(); }
});

test("replay after the target is fixed is not_reproduced and exits 0", async () => {
  const fixture = await startProofFixture();
  try {
    const { policy, report, findingId } = await scanned(fixture);
    fixture.behaviour.leakOther = false;
    const result = await replayApiFinding({ report, policy, findingId, ...replayOptions });
    assert.equal(result.outcome, "not_reproduced");
    assert.equal(replayExitCode(result), 0);
    assert.equal(result.check?.status, "completed");
  } finally { await fixture.close(); }
});

test("a broken owner control during replay is inconclusive, never a fix", async () => {
  const fixture = await startProofFixture();
  try {
    const { policy, report, findingId } = await scanned(fixture);
    fixture.behaviour.leakOther = false;
    fixture.behaviour.ownerFailsAfter = 0;
    const result = await replayApiFinding({ report, policy, findingId, ...replayOptions });
    assert.equal(result.outcome, "inconclusive");
    assert.equal(replayExitCode(result), 2);
  } finally { await fixture.close(); }
});

test("replay refuses a changed policy, unknown finding or invalid report before any request", async () => {
  const fixture = await startProofFixture();
  try {
    const { policy, report, findingId } = await scanned(fixture);
    const changed = structuredClone(policy); changed.cases[0].deny[0].statuses = [403, 404];
    assert.deepEqual([(await replayApiFinding({ report, policy: changed, findingId, ...replayOptions })).reason,
      (await replayApiFinding({ report, policy, findingId: "f".repeat(64), ...replayOptions })).reason,
      (await replayApiFinding({ report: { ...report, schemaVersion: "9" }, policy, findingId, ...replayOptions })).reason],
    ["policy_mismatch", "finding_not_found", "invalid_report"]);
    const stripped = structuredClone(report); delete stripped.checks[0].findings[0].replay;
    const notReplayable = await replayApiFinding({ report: stripped, policy, findingId, ...replayOptions });
    assert.equal(notReplayable.reason, "not_replayable");
    assert.equal(replayExitCode(notReplayable), 2);
    assert.equal(fixture.requests.length, 0);
  } finally { await fixture.close(); }
});

test("replay CLI arguments are bounded like the API runner", () => {
  const id = "a".repeat(64);
  assert.deepEqual(parseReplayArgs(["replay", "--report", "r.json", "--api-policy", "p.json", "--finding", id, "--out", "o", "--allow-private", "--timeout-ms", "5000"]),
    { report: "r.json", apiPolicy: "p.json", findingId: id, outDir: "o", allowPrivate: true, timeoutMs: 5000 });
  assert.throws(() => parseReplayArgs(["replay", "--report", "r.json", "--api-policy", "p.json", "--finding", "not-an-id", "--out", "o"]), /finding/);
  assert.throws(() => parseReplayArgs(["replay", "--report", "r.json", "--api-policy", "p.json", "--finding", id, "--out", "o", "--timeout-ms", "300000"]), /timeout/);
  assert.throws(() => parseReplayArgs(["replay", "--report", "r.json", "--finding", id, "--out", "o"]), /requires/);
});
