# Optional Codex advice for a scan report

`advise` is an explicit follow-up to a completed `scan`. It sends a capped projection of the redacted `agent-report.json` to a user-selected Codex CLI and writes a private `agent-advice.json`. It does not scan again, inspect source files, run target code, apply a patch, or change `report.json`, `agent-report.json`, the scan gate, or the original process/CI result. Its exit `0` means advice was produced; exit `2` means advice was incomplete or rejected. Neither exit verifies a vulnerability or fix.

The command checks that the adjacent `report.json` has the digest named by `agent-report.json`, and that the latter matches the report's sanitised projection. That validates the artifact pair, not final CI delivery. Keep the scan process receipt separately. Projection policy 11 is the source-preview contract and uploads gate state, declared scope, up to 24 coherently selected checks and 24 linked findings, and counted omissions under a 32 KiB cap. Incomplete and blocking checks are selected first. It includes typed native differential phases/outcomes and request budgets, plus authenticated native identity-control and probe-outcome enums without identity values, bounded API phase/outcome/control metadata, static-flow roles without positions, AST budget/gap accounting, and strictly validated `source.inventory` collection bounds with aggregate enumerated issue counts. Conditional static context contributes only its conditional authority, enumerated kinds, item count and truncation flag; context positions and observed target positions remain in local reports. It uses the existing nonexecuting `review_static_flow_or_budget` route and grants no replay authority. Missing or malformed collection metadata remains unknown; it does not receive guessed defaults. Collection cards use the existing nonexecuting `review_static_flow_or_budget` route and exclude notes, file paths and source content. The projection excludes source code, source paths/coordinates, report locations/URLs, target endpoints, request/response values, actor/case labels, credentials, logs, and arbitrary notes. Short titles remain untrusted data; automated redaction cannot recognise every private sentence, so review the report before opting in.

```sh
# Use the signed-in Codex CLI on this trusted local machine.
wakeio-security-ci advise --report /absolute/reports \
  --agent codex --auth cli-login --allow-report-upload \
  --out /absolute/private/advice-run

# For isolated CI, expose CODEX_API_KEY only to the trusted advice invocation step.
wakeio-security-ci advise --report /absolute/reports/agent-report.json \
  --agent codex --auth api-key --allow-report-upload \
  --out /absolute/private/advice-run
```

`--report` accepts the report directory or its `agent-report.json`. `--out` must be a new directory whose parent exists; it is created mode `0700`, and the advice file is mode `0600`. `--agent-path` selects a reviewed Codex executable. `--timeout-ms` is a positive value up to 120000 (default 120000). There is no automatic model/provider fallback. `scan` never invokes this command automatically. The current 0.5.0 source preview must be built locally; the last published npm package remains 0.4.0.

Both modes use a private working directory, minimal child environment, `codex exec --ignore-user-config --ignore-rules --strict-config --ephemeral --sandbox read-only`, disabled tools/features, schema-constrained output, a bounded JSONL parser, and a process deadline. API-key mode passes only `CODEX_API_KEY` into the child and uses a private home. CLI-login mode passes the selected Codex state-directory **path** to the native CLI so it can use its existing login; Wakeio does not open, copy, print, or store the credential file. The CLI itself owns authentication and may read/write its state. The two auth modes are mutually exclusive and explicitly selected; neither silently falls back to the other. The command does not perform a login or ask for a password. The supervisor confirms termination of the owned process group before accepting advice; processes that deliberately leave that group are not contained by this supervisor. This is a lifecycle check, not a filesystem or network isolation guarantee.

The installed Codex 0.162.0-alpha.17.2 needs its internal `code_mode_host` capability during startup even when agent-facing `code_mode` is disabled. The advisor therefore leaves `code_mode_host` at the CLI default while disabling `code_mode`, shell/unified execution, shell snapshots, browser/computer tools, plugins, hooks, and other listed capabilities. Every JSONL tool event still fails closed. This precise compatibility rule is checked by the fake CLI fixture and the live synthetic run; future CLI versions still require review.

`agent-advice.json` records input hashes, the original scan gate, auth mode, provider version and executable hash, projection policy version 11, `verified: false`, and validated prioritised recommendations linked only to supplied finding/check references or `scope`. Each recommendation must carry the exact locally derived `recheckRoute` for its reference. `replay_native_finding_same_policy` and `replay_api_finding_same_policy` indicate a separate human-initiated replay that requires the original policy and explicit active-scan consent; they do not run it. The native route appears only when the report also meets the replay parser's bounded input and report-only candidate prerequisites. The replay command still checks the supplied policy, target URL and consent before any request, and may refuse. `repeat_native_same_policy` marks check-level review, while static, diagnostic and scope routes name their bounded human review. A completed pass with no findings may return zero recommendations. Model and cost are `unknown` unless separately observed. Model prose is advisory; the underlying finding verification remains `not_run` and remediation remains `not_verified`. Unknown/malformed model references or mismatched routes, any tool event, failed turn, timeout, output overflow, or unsupported CLI option yield an incomplete advice receipt without model prose. Do not publish this private artifact automatically.

OpenAI documents [`codex exec` non-interactive mode](https://learn.chatgpt.com/docs/non-interactive-mode), its [flags](https://learn.chatgpt.com/docs/developer-commands?surface=cli), and the [`CODEX_API_KEY` and `CODEX_HOME` environments](https://learn.chatgpt.com/docs/config-file/environment-variables). Its documentation notes that `--ignore-user-config` leaves authentication attached to `CODEX_HOME`; account login therefore needs an explicit trust boundary. On 2026-10-13, a signed-in Codex 0.162.0-alpha.17.2 produced advice from the owned native SQLite demonstration report under both projection policies 1 and 2. The local private policy-2 receipt records `status: advice_produced`, `authMode: cli-login`, `policyVersion: 2`, `verified: false`, and one recommendation with the locally required native replay route. Its input hashes match the owned report pair; the provider parser rejects every tool event before a successful receipt, so this accepted turn had no tool event. Model and cost remain `unknown`. API-key mode passed fake-CLI contract tests only; `CODEX_API_KEY` was absent, so its live call remains untested. These synthetic runs do not establish a billing limit, real-target efficacy, or hard filesystem/network isolation.

Policy 3 added collection evidence to the bounded projection. Policy 4 preserves it and adds the enum-only conditional-context card, sharing one version constant with the advice receipt. Its test coverage consists of deterministic projection and fake-CLI contract fixtures; no live policy-4 model call has been performed. The historical real policy-2 call above does not establish a live policy-3 or policy-4 call. Selection limits, omission accounting, report-pair digest checks and authentication boundaries are unchanged.

Policy 5 introduced authenticated native v2 `identityControls.before/after` and `probeOutcome` enums. It sent no Authorization value, environment name, identity path, JSON pointer or expected principal. Its deterministic fake-CLI tests covered both `cli-login` and `api-key` modes; no live policy-5 provider call was performed.

Policy 6 preserves those boundaries and admits the explicit `single-quoted` v3 execution revisions. Unauthenticated v3 has eight phases and does not invent identity controls; authenticated v3 has ten phases and the same bounded control enums. A retained positive SQL probe with failed trailing identity stays low-confidence/partial and receives `review_check_diagnostics`, never native replay. Native replay advice requires the strong bounded original report prerequisites plus a complete, matched-control execution; replay still resolves fresh credentials and checks the supplied policy and consent later. No seed, SQL probe or target endpoint is added to the upload. Deterministic fake-CLI tests exercise both authentication modes and optional identity branches; no live policy-6 provider call is claimed. The historical policy-2 live call above remains a separate receipt.


Policy 7 implements the bounded filesystem flow projection contract. It preserves the existing cap, selection/omission accounting, digest pairing and authentication boundaries while admitting only `sourceKind: filesystem_filename` and the four enumerated conditional kinds `declared_filesystem_stream_origin`, `declared_stream_callback_schedule`, `conditional_array_accumulator`, and `declared_process_wrapper`. Structural roles, authority, counts and truncation are bounded metadata; source paths/positions/content, concrete filenames/target values, dependency-version-specific target data and commands are not added to the upload. Filename evidence uses the existing nonexecuting `review_static_flow_or_budget` route and gains no execution/replay authority. Consumer-specific filesystem fake-CLI/projection verification receives a separate private receipt after packaging; the linked validation record distinguishes it from source-suite evidence. No policy-7 live provider call is claimed. The historical policy-2 live receipt and older fake-CLI results do not verify policy 7. See the [filesystem flow contract](source-filesystem-flow.md).


Policy 8 preserves those upload limits and adds the strictly validated
collected-code coverage diagnostic: fixed language/provider/status enums, explicit
require and collection-complete flags, exact/unknown accounting, bounded counts or
null. It carries no source paths, filenames, code, target strings, tool messages or
credentials. A coverage check uses `review_check_diagnostics`; neither a diagnostic
card nor the strict gate authorizes installation, scanning, target execution or
replay. Missing/malformed evidence remains unknown. This slice includes no live
policy-8 provider call; any deterministic/fake-CLI verification belongs to its
separate receipt, and the historical live policy-2 run does not verify policy 8.
See [collected-code coverage](source-code-coverage.md).


Policy 9 preserves those limits and adds the v4 `method: POST` and round1/round2
normal-control enums to the existing native differential card. It uploads no body,
parameter name, original/alternate/probe value, oracle value, identity value or
Authorization header. A complete candidate still needs the same report-only
replay prerequisites; actual replay separately checks the original policy and
explicit consent. Partial controls grant diagnostic review only. No live policy-9
provider call is claimed; the historical policy-2 live receipt does not verify
policy 9. See [POST JSON numeric differential](native-dast-post-json.md).


Policy 10 preserves the bounded projection and adds only the archive-origin enum
`sourceKind: archive_entry_path` and conditional context kind
`declared_package_api`. Source text, paths, positions and concrete archive entry
values remain local. These cards use the existing nonexecuting static-review
route and grant no extraction, target execution, patch or replay authority.
No live policy-10 provider call is claimed; the historical live policy-2 receipt
does not verify policy 10. See [archive path source review](archive-path-sast.md).


Policy 11 preserves the existing bounded upload and admits the authenticated
Schemathesis GET diagnostic card: fixed profile/status/stop/control enums,
operation indices, counts, bounded limits and provenance-presence flags. It does
not upload concrete operation labels, policy/schema/worker digests, generated
fingerprints, credentials, environment names, oracle values, normal query values
or response bodies. Authenticated Schemathesis checks and findings use
`review_check_diagnostics` and never receive replay authority. The canonical
report pair and original scan gate remain authoritative; advice cannot turn
missing or incomplete controls into a pass. No live policy-11 Codex call is
claimed; earlier provider receipts do not verify this policy. See the
[authenticated Schemathesis controls](schemathesis-auth-controls.md).
