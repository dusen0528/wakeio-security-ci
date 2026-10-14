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
