import { apiPolicyDigest, parseApiPolicy, runApiPolicy, type ApiPolicyV2 } from "./api.js";
import { parseScanReport } from "./compare.js";
import type { CheckResult, FindingReplay } from "./contracts.js";

export type ApiReplayOutcome = 'reproduced' | 'not_reproduced' | 'inconclusive' | 'refused';
export type ApiReplayRefusal = 'invalid_report' | 'finding_not_found' | 'not_replayable' | 'invalid_policy' | 'legacy_policy' | 'policy_mismatch';

export interface ApiReplayOptions {
  /** A report.json document produced by `scan --api-policy`. */
  report: unknown;
  /** The same policy document that produced the report. */
  policy: unknown;
  findingId: string;
  env?: NodeJS.ProcessEnv;
  allowPrivate?: boolean;
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface ApiReplayResult {
  version: 1;
  kind: 'api-finding-replay';
  outcome: ApiReplayOutcome;
  findingId: string;
  reason?: ApiReplayRefusal;
  replay?: FindingReplay;
  /** The reduced re-execution: one case, its owner and the original probe actor. */
  check?: CheckResult;
}

function refused(findingId: string, reason: ApiReplayRefusal, replay?: FindingReplay): ApiReplayResult {
  return { version: 1, kind: 'api-finding-replay', outcome: 'refused', findingId, reason, ...(replay ? { replay } : {}) };
}

/** One case, its owner and the probe actor; every other actor and case is dropped. */
function reducedPolicy(policy: ApiPolicyV2, replay: FindingReplay): ApiPolicyV2 | undefined {
  const entry = policy.cases.find((item) => item.id === replay.caseId);
  const deny = entry?.deny.find((item) => item.actor === replay.actor);
  if (!entry || !deny) return undefined;
  return {
    version: 2,
    baseUrl: policy.baseUrl,
    actors: policy.actors.filter((actor) => actor.id === entry.allow.actor || actor.id === replay.actor),
    cases: [{ ...entry, deny: [deny] }],
  };
}

/**
 * Re-execute only the controls behind one `api.authorization` exposure finding.
 * The policy must match the digest recorded in the report. `reproduced` needs
 * the same exposure with every control passing again; `not_reproduced` needs a
 * completed run with an accepted denial. Anything else is `inconclusive`.
 */
export async function replayApiFinding(options: ApiReplayOptions): Promise<ApiReplayResult> {
  const findingId = typeof options?.findingId === 'string' ? options.findingId : '';
  let replay: FindingReplay | undefined;
  try {
    const report = parseScanReport(options.report);
    const finding = report.checks.find((check) => check.id === 'api.authorization')?.findings.find((item) => item.id === findingId);
    if (!finding) return refused(findingId, 'finding_not_found');
    replay = finding.replay;
  } catch {
    return refused(findingId, 'invalid_report');
  }
  if (!replay) return refused(findingId, 'not_replayable');
  let policy;
  try { policy = parseApiPolicy(options.policy).policy; }
  catch { return refused(findingId, 'invalid_policy', replay); }
  if (policy.version !== 2) return refused(findingId, 'legacy_policy', replay);
  if (apiPolicyDigest(options.policy) !== replay.policySha256) return refused(findingId, 'policy_mismatch', replay);
  const reduced = reducedPolicy(policy, replay);
  if (!reduced) return refused(findingId, 'policy_mismatch', replay);

  const [check] = await runApiPolicy({
    policy: reduced,
    ...(options.env === undefined ? {} : { env: options.env }),
    ...(options.allowPrivate === undefined ? {} : { allowPrivate: options.allowPrivate }),
    ...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  const exposure = check.findings.find((item) => item.replay?.caseId === replay.caseId && item.replay.actor === replay.actor);
  const outcome: ApiReplayOutcome = exposure
    ? exposure.controlVerification?.state === 'controls_passed' ? 'reproduced' : 'inconclusive'
    : check.status === 'completed' ? 'not_reproduced' : 'inconclusive';
  return { version: 1, kind: 'api-finding-replay', outcome, findingId, replay, check };
}

/** Exit codes follow the scan gate: 1 reproduced, 0 not reproduced, 2 otherwise. */
export function replayExitCode(result: ApiReplayResult): number {
  return result.outcome === 'reproduced' ? 1 : result.outcome === 'not_reproduced' ? 0 : 2;
}
