# Property-write DAST contract

2026-10-15. Design baseline `536d968`. This note records the implementation contract
for a bounded API experiment. External staging execution and general authorization
coverage are not established. The [usage contract](../api-property-write.md) is the
operator-facing reference; this feature grants no automatic replay permission.

## Why this experiment

[OWASP API3:2023](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/)
distinguishes property-level read/write authorization from object access. The existing
[owned PATCH pilot](../api-write-state.md) measures fixed synthetic resources with an
independent storage observer. This feature instead accepts one operator-declared
resource and two credential references. Its oracle is privileged HTTP readback;
independent storage observation is confined to the test target's ground truth.

Required declarations are a disposable staging resource, one exact GET/PATCH URI,
shared strong ETag validator semantics across owner/verifier representations, fixed
resource/owner/run-marker guards, one normal string field accepting generated nonces,
and one protected non-null scalar field. No organization/tenant marker is modeled:
resource-owner checks do not establish generic tenant coverage or uninterrupted
session continuity. There is no endpoint/property discovery or arbitrary payload hook.

[RFC 7396 §2](https://www.rfc-editor.org/rfc/rfc7396.html#section-2) defines merge-patch
null deletion and array replacement; v1 rejects null, containers, nested write fields,
duplicate JSON keys and prototype keys. [RFC 5789 §2](https://www.rfc-editor.org/rfc/rfc5789.html#section-2)
explains that PATCH is not generally safe or idempotent. Every write has one attempt;
no retry, redirect, address fallback, DELETE or automatic resource creation is allowed.
[RFC 9110 §13.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#name-if-match)
specifies strong comparison for If-Match. This engine's required 412 negative controls
are a deliberately narrower server contract than all lawful HTTP behaviors.

## Frozen plan: 22 HTTP requests, eight PATCHes

| Ordinals | Actor / request | Required observation |
| --- | --- | --- |
| 0–1 | Owner/verifier identity GET | Distinct configured principals |
| 2 | Owner resource GET | Resource, owner, run marker and normal value; protected visibility optional |
| 3 | Verifier baseline GET | Complete normal/protected initial values and strong ETag |
| 4–5 | Owner wrong-ETag normal PATCH / verifier GET | 412 and unchanged view |
| 6–7 | Verifier wrong-ETag protected PATCH / verifier GET | 412 and unchanged view |
| 8–9 | Owner normal nonce PATCH / verifier GET | Normal capability, protected unchanged |
| 10–11 | Verifier normal nonce + protected control PATCH / GET | Privileged positive control |
| 12–13 | Verifier normal nonce + protected initial PATCH / GET | Restore prerequisite |
| 14–15 | Owner protected probe PATCH / verifier GET | Provisional effect only |
| 16–17 | Owner fresh normal-only nonce PATCH / verifier GET | Fresh nonce and same provisional protected value; only now adjudicate |
| 18–19 | Verifier initial-values cleanup PATCH / GET | Exact baseline view restored |
| 20–21 | Owner/verifier identity GET | Both configured identities still observed |

All writes use the latest verifier strong ETag, except the two deliberately unequal
random tags. Every changed JSON representation must change its immediately preceding
ETag. Unrelated visible fields must remain identical; no automatic `updatedAt` ignore
list exists. GET requires 200, ordinary PATCH 200/204, negative PATCH 412, and the
owner probe 200/204/403. A 403 can still yield an observed effect; 200 alone cannot.

A stale privileged-positive response could otherwise mimic the protected probe.
The fresh owner-normal nonce barrier checks that the provisional view is still the
basis for an observable new write. A stale ETag, missing nonce or changed protected
value stops the run as partial. This does not defeat an API fabricating a mutually
consistent body and validator; HTTP readback is not independent database or exclusive
causality proof.

## Ambiguity, cleanup and evidence

An ambiguous PATCH stops writes. One reserved ordinal-22 verifier GET may reconcile
while the same run deadline and request budget remain live: maximum 23 HTTP/eight
PATCH. It never establishes an effect or resumes writes. Already established effect
survives ambiguous cleanup and later identity failure. Cancellation/deadline permits
no subsequent HTTP, including cleanup. Failure may leave the resource changed and
requires operator review. Restoring two fields cannot undo business side effects.

The typed `propertyWriteEvidence` version 1 has scope `policy-resource-property-write`,
basis `authenticated-http-readback`, fixed indexed ledger, controls, effect/provisional,
cleanup, first stop reason, policy digest and effective numeric budgets. Defaults and
bounds are documented in the operator guide. Path, field/env names, credentials,
identity/scalar values, bodies, nonces and ETags are omitted from public evidence.
A strict data-only parser rejects accessors, proxies, extra keys, inconsistent counts,
missing controls and invalid progression. Missing or inconsistent evidence cannot
produce a completed clean check.

The four report formats retain this evidence. Findings remain high-severity,
low-confidence candidates with verification false. Incomplete work has exit 2 priority;
a completed observed effect meets the default high threshold (1), and a completed
not-observed result is scoped 0. Comparison binds the policy and effective budget;
`not_observed` is not an authoritative fixed state. Advice policy remains 13 with no
new agent replay permission or automatic active run.

## Effectiveness acceptance and limits

Independent owned-target tests must cover writable versus allowlisted protected
fields while normal writes work, 403 with mutation, 200 without mutation, deny-all,
ignored preconditions, weak/missing/stale validators, wrong identity/resource/run
marker, protected-hidden owner view, conflicts, ambiguous writes, cleanup failures,
identity drift, hard request/body limits and cancellation with no subsequent request.
Renamed resources/fields exercise configuration rather than a hardcoded toy path.
Test storage is inspected independently of the runner's readback oracle. Forged ledger
and four-format privacy tests exercise the artifact boundary separately.

These are predefined synthetic controls. They do not establish production detection
rates, vulnerability confirmation, safe remediation or general BOPLA/BOLA coverage.
No live external application, third-party runtime or provider is part of this work.


## Measured owned-target acceptance

The independent owned-target matrix completed all 21 predefined scenarios:

| Final CLI exit | Scenarios | Meaning in this experiment |
| --- | ---: | --- |
| 1 | 3 | Protected effect candidate, default high threshold |
| 0 | 2 | Completed scoped not-observed controls and cleanup |
| 2 | 16 | Incomplete/failed delivery, never a clean result |

Twenty scenarios delivered all four report formats with privacy checks; one tested
intentional delivery failure. All 21 owned TCP connection lifecycles closed. The
[evidence suite](../../tests/api-property-evidence.test.ts) passed ten groups and the
combined initial owner/evidence run passed 23/23. The independent target's storage
checks are test ground truth, not a new production observer available to the runner.

Policy/budget matching is a necessary comparison condition. The current CLI does not
populate a declared `ScanReport.scope`; its report pairs therefore remain unverified
under the existing missing-scope rule. SDK comparison with an explicitly reviewed
scope does not confer CLI patch verification. No external staging run, independent
production storage observation, live provider call or production efficacy metric is
claimed by these measurements.
