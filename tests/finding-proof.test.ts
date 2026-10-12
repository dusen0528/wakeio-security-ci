import test from "node:test";
import assert from "node:assert/strict";
import { apiPolicyDigest, runApiPolicy } from "../src/api.js";
import { createReport, toAgentReport, toMarkdown, toSarif } from "../src/report.js";
import type { CheckResult, Finding } from "../src/contracts.js";
import { PROOF_CANARY, PROOF_ENV, proofPolicy, startProofFixture } from "./proof-fixture.js";

async function scan(configure: (behaviour: Awaited<ReturnType<typeof startProofFixture>>["behaviour"]) => void = () => {}) {
  const fixture = await startProofFixture();
  configure(fixture.behaviour);
  const policy = proofPolicy(fixture.baseUrl);
  try {
    const [check] = await runApiPolicy({ policy, env: PROOF_ENV, allowPrivate: true, timeoutMs: 5000 });
    return { check, policy, report: createReport([check], "api", new Date()) };
  } finally { await fixture.close(); }
}

function only(check: CheckResult): Finding {
  assert.equal(check.findings.length, 1);
  return check.findings[0];
}

test("a leak with every control passing carries controls_passed, ledger evidence and replay inputs", async () => {
  const { check, policy } = await scan();
  assert.equal(check.status, "completed");
  const finding = only(check);
  assert.equal(finding.kind, "candidate");
  assert.deepEqual(finding.controlVerification, { state: "controls_passed", method: "api-differential-canary", controls: {
    identityBefore: "passed", ownerBefore: "passed", probe: "canary_exposed", probeCompleted: true, ownerAfter: "passed", identityAfter: "passed" } });
  assert.deepEqual(finding.replay, { kind: "api-policy-case", policySha256: apiPolicyDigest(policy), caseId: "owner-document", actor: "other" });
  const evidence = finding.evidence!;
  assert.equal(evidence.planSha256, check.apiExecution!.planSha256);
  assert.deepEqual(evidence.steps.map((step) => [step.phase, step.actor, step.outcome, step.httpStatus]), [
    ["identity-before", "other", "evaluated", 200], ["owner-before", "owner", "evaluated", 200], ["deny", "other", "evaluated", 200],
    ["owner-after", "owner", "evaluated", 200], ["identity-after", "other", "evaluated", 200]]);
  for (const step of evidence.steps) {
    const recorded = check.apiExecution!.steps[step.ordinal];
    assert.equal(recorded.httpStatus, step.httpStatus); assert.equal(recorded.outcome, step.outcome);
  }
});

test("control evidence survives every public projection without changing the agent verification contract or leaking values", async () => {
  const { report } = await scan();
  const finding = only(report.checks[0]);
  assert.equal(finding.controlVerification?.state, "controls_passed");
  assert.equal(finding.evidence?.steps.length, 5);
  const agent = toAgentReport(report).findings[0];
  assert.deepEqual(agent.verification, { state: "not_run", vulnerabilityConfirmed: false, remediationVerified: false });
  assert.equal(agent.evidence.controlVerification?.state, "controls_passed");
  assert.deepEqual(agent.evidence.replay, finding.replay);
  const sarif = toSarif(report).runs[0].results[0].properties as Record<string, any>;
  assert.equal(sarif.controlVerification.state, "controls_passed");
  assert.match(toMarkdown(report), /In-run controls: controls_passed .*not exploit or fix verification/);
  for (const text of [JSON.stringify(report), JSON.stringify(toAgentReport(report)), JSON.stringify(toSarif(report)), toMarkdown(report)]) {
    for (const secret of [PROOF_CANARY, ...Object.values(PROOF_ENV)]) assert.equal(text.includes(secret), false, secret);
  }
});

test("an anonymous leak has no identity controls to run and still passes", async () => {
  const { check } = await scan((behaviour) => { behaviour.leakOther = false; behaviour.leakAnonymous = true; });
  const finding = only(check);
  assert.equal(finding.replay?.actor, "anonymous");
  assert.equal(finding.controlVerification?.state, "controls_passed");
  assert.equal(finding.controlVerification?.controls.identityBefore, "not_applicable");
  assert.equal(finding.controlVerification?.controls.identityAfter, "not_applicable");
  assert.deepEqual(finding.evidence?.steps.map((step) => step.phase), ["owner-before", "deny", "owner-after"]);
});

test("a failed owner control after the probe keeps the exposure but leaves it inconclusive", async () => {
  const { check, report } = await scan((behaviour) => { behaviour.ownerFailsAfter = 1; });
  assert.equal(check.status, "partial");
  const finding = only(check);
  assert.equal(finding.controlVerification?.state, "inconclusive");
  assert.equal(finding.controlVerification?.controls.ownerAfter, "failed");
  assert.equal(only(report.checks[0]).controlVerification?.state, "inconclusive");
});

test("no exposure means no control evidence", async () => {
  const { check } = await scan((behaviour) => { behaviour.leakOther = false; });
  assert.equal(check.status, "completed");
  assert.equal(check.findings.length, 0);
});

test("the sanitiser demotes or drops claims its own ledger does not support", async () => {
  const { check } = await scan();
  const finding = only(check);
  const sanitised = (changed: Partial<Finding>, id = check.id) => only(createReport([{ ...check, id, findings: [{ ...finding, ...changed }] }], "api", new Date()).checks[0]);

  const noEvidence = sanitised({ evidence: undefined });
  assert.equal(noEvidence.controlVerification?.state, "inconclusive");
  assert.equal(noEvidence.evidence, undefined);

  const noReplay = sanitised({ replay: undefined });
  assert.equal(noReplay.controlVerification?.state, "inconclusive");

  const forgedStatus = sanitised({ evidence: { ...finding.evidence!, steps: finding.evidence!.steps.map((step) => step.phase === "deny" ? { ...step, httpStatus: 403 } : step) } });
  assert.equal(forgedStatus.evidence, undefined);
  assert.equal(forgedStatus.controlVerification?.state, "inconclusive");

  const foreignPlan = sanitised({ evidence: { ...finding.evidence!, planSha256: "0".repeat(64) } });
  assert.equal(foreignPlan.evidence, undefined);

  const failedControl = sanitised({ controlVerification: { ...finding.controlVerification!, controls: { ...finding.controlVerification!.controls, ownerAfter: "failed" } } });
  assert.equal(failedControl.controlVerification?.state, "inconclusive");

  const otherCheck = sanitised({}, "url.scan");
  assert.equal(otherCheck.controlVerification, undefined);
  assert.equal(otherCheck.evidence, undefined);
  assert.equal(otherCheck.replay, undefined);

  assert.equal(sanitised({}).controlVerification?.state, "controls_passed");
});

test("the policy digest ignores key order and formatting but not policy content", async () => {
  const policy = proofPolicy("http://127.0.0.1:9");
  const reordered = JSON.parse(JSON.stringify({ cases: policy.cases, actors: policy.actors, baseUrl: policy.baseUrl, version: policy.version }, null, 4));
  assert.equal(apiPolicyDigest(reordered), apiPolicyDigest(policy));
  const changed = structuredClone(policy); changed.cases[0].deny[0].statuses = [404];
  assert.notEqual(apiPolicyDigest(changed), apiPolicyDigest(policy));
});
