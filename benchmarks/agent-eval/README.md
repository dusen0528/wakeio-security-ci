# Agent-DAST evaluation: fixed plan (A) vs agent selection (B)

This directory holds the **offline** comparison harness for the next validation
question: does letting an agent choose the plan and the follow-up checks add
anything over a well-built fixed plan, at the same target, engines and request
budget?

Scope of this harness: label format, a pass-criteria format, and an aggregator
that scores synthetic (or, later, real) results. It **sends no request, runs no
engine, and calls no model.** Real target traffic and agent-SDK wiring are out
of scope here. The harness exists to prove the counting is correct before any
live comparison runs.

## The two arms

- **A — fixed plan.** A human-written `plan.json` run through `run-plan`. Not a
  deliberately weak plan: a competent combination of the existing engines. Both
  arms receive the same follow-up execution results; A decides the next check by
  fixed rules.
- **B — agent selection.** An agent builds the plan from recon output and, from
  each round's summary, chooses verify / retry / scope expansion. Execution uses
  the **same `run-plan` executor and the same engines** as A.

### Fixed controls (identical for both arms)

- Same target (a local instance at one commit), same engine set, same recon
  input (same OpenAPI / surface list). B's advantage must come from *selection
  over the same input*, not from more input.
- Same oracle and adjudication. The label set is pinned to a known
  vulnerable/fixed pair.
- **One shared request budget for the whole of B.** Re-invoking `run-plan` does
  not grant a fresh budget: initial + verify + retry + expansion are summed and
  held to the same cap as A (`sumRoundBudget`). Scope expansion is allowed only
  within the approved target and a check scope fixed in advance.
- Each condition is repeated N times (preliminary N = 5) to see run-to-run
  variance.

## Measurement order: detection first, cost second

1. **Detection accuracy** — TP / FP against the pre-fixed labels, on a
   `confirmed` basis by default.
2. **Misses (FN)** — labeled vulnerabilities not detected.
3. **Coverage** — executed cells over a denominator **fixed before the run**
   (endpoint × parameter × check). The run's own `run.db` audit count is never
   used as a "whole-scan rate"; `coverage()` refuses an executed count above the
   planned denominator.
4. **Then** tokens, cost and time (time includes model deliberation for B;
   A's tokens are 0). "Produced a valid plan A missed" is recorded as a
   **usability** outcome, separately — it is not by itself detection value.

### Units

TP / FP / FN are counted by **distinct vulnerability**, never by request count.
Many findings for one problem collapse to one via `dedupeFindings` before
scoring, so repeated detection is not rewarded. A finding at a negative or
unlabeled site is one FP after the same de-duplication. A finding must match the
labeled **type** as well as the site.

## Labels: tuning and final splits

`labels/*.labels.json` ([format](../../src/agent-dast/eval/labels.ts)) lists
distinct vulnerabilities and negative sites, each with a `split`:

- `tuning` — used while developing the agent's prompts and selection logic.
- `final` — used only to score a comparison run.

What this code guarantees: the scorer (`scoreRun`) takes `finalLabels()` output
and **refuses** any set that still contains a tuning entry
(`tuning_label_in_scoring`), so tuning labels can never be *scored* alongside
final ones. What it does **not** guarantee: it cannot stop the final labels from
being handed to an agent as input — this harness only scores results; it does
not provision the agent's inputs. Keeping final labels out of the agent's view
is the job of the follow-up execution layer (see "Evidence the execution layer
must add"). In a final run the target should contain only final + negative
sites; tuning sites live in a separate development corpus.

## Pass criteria binding (and what is not yet verified)

`criteria.example.json` ([format](../../src/agent-dast/eval/aggregate.ts)) is
bound to the final label set:

- `labelSetHash` must equal `finalLabels().hash`, or `compareArms` throws
  `criteria_hash_mismatch` — criteria cannot be retrofitted to an edited truth
  set. **This is enforced by code.**
- `committedBeforeArmB: true` is only a **self-declared attestation**. It does
  not prove the criteria predate arm B; nothing in this harness checks when the
  file was written. The CLI output flags this as
  `criteriaAttestationUnverified: true`. Real pre-registration must be enforced
  by the execution layer below.

## Evidence the execution layer must add

This offline harness scores numbers; it does not observe the run that produced
them. Before a real-target comparison can be trusted, the follow-up execution
layer must bind:

- **Pre-registration of criteria** — a timestamp or signature (e.g. a committed
  criteria file hashed into a dated ledger, or a signed commit) proving the
  criteria and the final label hash existed before arm B ran. `committedBeforeArmB`
  is a placeholder for that proof, not the proof.
- **Label non-disclosure** — the input-provisioning step that builds the agent's
  recon/plan inputs must be shown never to include final labels (a separate
  corpus, a redaction check on the agent's inputs).
- **Finding provenance** — each `EvalFinding` the harness scores must link back
  to a run.db row and its evidence file, so a scored detection is traceable to
  an actual admitted request, not a hand-written number.

### Gates (draft, finalize with the real label set)

- **No quality loss (required):** within one shared budget, B's TP ≥ A's TP,
  B's FP ≤ A's FP, and B's coverage ≥ A's coverage (`qualityHeld`).
- **Value (one of, in a majority of repeats):** B produces a valid plan A
  missed, or B reaches the same detection with fewer requests
  (`fewerRequestsSameDetection`).
- **Otherwise:** hold the agent loop; keep the fixed plan plus code rules.

The exact numeric thresholds are set once the real label set exists; the example
criteria file is a shape placeholder, not the committed bar.

## Run the aggregator

```sh
npm run build
node benchmarks/agent-eval/aggregate.mjs \
  --labels   benchmarks/agent-eval/labels/example.labels.json \
  --criteria benchmarks/agent-eval/criteria.example.json \
  --results  benchmarks/agent-eval/results.example.json
```

The example bundle is synthetic and exercises the counting only: B detects both
final vulnerabilities (A detects one) within the shared 64-request cap across
three rounds (26 + 10 + 18 = 54), so `qualityHeld` is true. Exit code is 2 if
either arm overran the shared cap. `tests/agent-dast-eval.test.ts` checks the
distinct-vulnerability counting, de-duplication, round-budget summation, the
coverage denominator rule, and the tuning / final and criteria-binding guards.
