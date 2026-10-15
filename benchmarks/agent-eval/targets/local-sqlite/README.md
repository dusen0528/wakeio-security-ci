# Owned local SQLite pilot

Approval: `approval.json` records the user's 2026-10-14 consent in this chat. Only the generated 127.0.0.1 origin and GET paths listed there are authorized. No public/staging origin, real account, credential or destructive check is used. Codex may add these target-specific files; common evaluator code stays unchanged.

The fixture uses an in-memory SQLite database and resets its single synthetic row before every arm. `/items` and `/lookup` are final sites; `/catalog` and `/inventory` are tuning-only sites. Ground truth comes from SQL concatenation versus parameter binding in the fixture source, not scanner output. The one-positive/one-negative final set and five repeats are an integration pilot, not evidence of broad detection performance.

Build with `npm run build`. Install the optional `@openai/codex-sdk` separately and authenticate with `codex login`. The provider uses that login with tools and user/project configuration disabled. Never put login tokens or keys in this directory.

Run `WAKEIO_AGENT_LIVE=1 node benchmarks/agent-eval/targets/local-sqlite/evaluate.mjs --active-consent --evaluator-root <built PR60 checkout> --criteria-commit <published commit> --out <new private directory>`.

The evaluator checkout is an explicit dependency because PR #60 remains unmerged. Its CLI and evaluation modules are read/imported without editing. The command starts the loopback fixture, runs A five times then B five times, and always closes the server/database in `finally`; Ctrl-C terminates the process and its in-memory fixture. No background service or cleanup of unrelated processes is required.

Before any B call, the command verifies committed criteria/labels/checklist/acceptance bytes and the published GitHub commit, writes and signs the manifests using an ephemeral Ed25519 key, and saves the public key and signature. The local timestamp/signature plus published commit establish recorded ordering; this is not an external trusted timestamp service.

The model-input module `run.mjs` imports no labels or evaluation module. It receives the same owner catalog and empty RunStore reconnaissance counters available to A; later selections receive only the sanitized round counters. Prompt/tool configuration stays fixed after tuning. Model time includes plan and follow-up calls; usage is read from the provider ledger. Subscription tokens are not converted to a guessed monetary price.

For this pilot the unchanged PR60 CLI can verify a one-round B bundle. If B produces multiple rounds, the experiment preserves them and reports `multi_round_cli_support_required`; it never rewrites evidence IDs or presents a controller DB as a finding bundle. The B loop retains its default eight-round limit. Failed or incomplete runs remain in the report and cannot count as successful pairs.

The CLI does not print its internal `manifestVerified` value. The target scorer additionally calls the unchanged `evaluate()` API with the same stored readers and reports that verified value. Original CLI output is preserved beside it.

Coverage counts the two predeclared native policy tasks only when their stored group-completion rows report execution. Finding-observation rows are not used as a coverage denominator. Candidate-state findings are evaluated against source-grounded labels; no synthetic confirmation is added to run.db.

## Recorded pilot result (2026-10-14)

`pilot-result.json` preserves both attempts and hashes of the private raw artifacts. Initial execution was interrupted during B3 by aborting an SDK child after its iterator had removed listeners. Commit 9e0d278 removes that redundant abort; a regression test reproduces the event-lifecycle failure offline. Criteria, labels, prompts and engine configuration were unchanged for the second complete attempt.

The second attempt executed all five A and five B arms. A completed 5/5; B completed 4/5. B5 sent 16 admitted requests, then both selection attempts failed validation/provider completion and the loop safely returned `invalid_agent_output`, exit 2. The deliberately sanitized provider record cannot distinguish a transport failure from an invalid model result; no more specific cause is claimed.

The four completed pairs each scored candidate TP=1, FP=0, FN=0 and coverage=2/2, with CLI provenance and API manifest verification passing. Every arm used 16/64 requests. Mean total elapsed time across all five arms was A=1.5742 seconds, B=18.3502 seconds (including the failed B arm); population variance was A=10.16 ms², B=34,005,356.56 ms². Token usage is incomplete for failed calls and is reported as a lower bound, not zero or a price estimate.

Verdict: defer. G3's all-arms-complete condition is unmet; G4 has not started. No repeated campaign was run merely to obtain five favorable results. All bundles, rejected-attempt records and attestation remain in private local storage; only aggregate metrics and content hashes are committed. The public criteria commit predates both campaigns. This pilot does not establish a detection or efficiency advantage for the agent.

### Diagnostic follow-up (2026-10-15)

Commit 36bc596 separates bounded transport/authentication/rate/schema/event diagnostics from JSON and decision validation, without recording SDK messages. The exact historical B5 cause cannot be reconstructed. Six model-only calls using the original B5 summary all succeeded; no target requests were sent during those diagnostic calls.

A separately retained third campaign, with unchanged criteria, prompt, catalog and budgets, completed A=5/5 and B=5/5. All five pairs passed stored provenance and manifest verification, TP=1/FP=0/FN=0, coverage=2/2, requests=16/64. Mean time was A=1.573s and B=11.9228s; B mean tokens=25,309.4. Full population variance and artifact hashes are in `pilot-result.json.followup`. G3 evaluation execution is complete; adoption verdict remains **defer** because no detection/request/time benefit was demonstrated. The two earlier failures remain part of the reliability evidence, not replaced by this successful campaign. G4 may proceed using the fixed-plan runner; agent superiority is not claimed.
