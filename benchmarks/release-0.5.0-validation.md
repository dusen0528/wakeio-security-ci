# 0.5.0 pre-tag validation — 2026-10-15

Engine and reviewed Action: `642fedf8c39b2a7fba7d7d446fe2675a4dc586eb` (integrated PRs #72 and #73). This record does not claim npm publication, a tag, or a GitHub Release. Paths below are relative to the repository; raw local logs remain ignored.

## Release scope

The primary path is bounded source analysis, fixed-plan `run-plan` execution, and CLI/CI reports. `scan` and `run-plan` do not call models. Agent loop/providers and the owned-target dashboard are present in the npm candidate as separate experimental features. Package inclusion does not establish general autonomous agent DAST, model routing, hosted history, or general remediation support.

## Accuracy, including external limitations

The synthetic corpus has 56 completed cases: 28 positives (TP 27 / FN 1) and 28 negatives (TN 28 / FP 0). TN is a negative-case count. The known FN, `koa-query-sql-vulnerable`, uses an unregistered `ctx.request.query` input reaching SQL, outside the bounded input model. These are author-maintained regression labels, not a blind holdout. The [P0 performance baseline](perf-baseline.md) retains its original measurement SHA and timing boundaries.

The existing OSS harness was also run against the whole pinned source checkouts with `tools: []`, `analysisProfile: 'extended'`, `maxFiles: 10000`, and `maxBytes: 134217728`. Neither target's dependencies, build, server, nor application code were executed. These settings differ from P0 performance tier M's defaults.

| External source | Declared positive flows | Candidate at declared sink locations | Strict source-to-sink matches | Remaining outcomes |
| --- | ---: | ---: | ---: | --- |
| [Juice Shop](https://github.com/juice-shop/juice-shop/tree/e39a3bdb8c61295c31fa4e0a03485e68a8ca12a4) | 4 | 4 | 0 | 4 unevaluable scope |
| [NodeGoat](https://github.com/OWASP/NodeGoat/tree/c5cb68a7084e4ae7dcc60e6a98768720a81841e8) | 3 | 2 | 1 | 1 unevaluable scope, 1 known unsupported |

Collection completed for both, but AST analysis was partial; the OSS gate exited **2**. Five conditional/truncated traces fail the harness's complete source-to-sink oracle even though sink candidates exist. NodeGoat's matched evaluation flow requires all three declared `eval` sinks; its missing NoSQL `$where` flow remains unsupported. Six candidate-bearing flow locations therefore do not mean six validated matches or runtime exploits. The five reviewed negative sites had no unexpected finding, but four were unevaluable and one unsupported; this does not establish TN 5. In total, 56 unmatched candidates remain unadjudicated, including the five conditional candidates at declared sites; precision, false-positive count and supported recall are unavailable. External source labels are also reviewed development examples, not a blind generalization test.

Manifest: [`oss-corpus.json`](oss-corpus.json), SHA-256 `eadd5883b9f7a92b455d42af66947418bb2dfed4b5b7ea5d34bc823796a84e94`. Local evidence: `artifacts/oss-release-evidence/results/oss-benchmark.json` and `oss-benchmark.md`. To reproduce after building WakeIO, prepare clean source-only checkouts at the pinned commits and run:

```sh
node scripts/benchmark-oss.mjs \
  --checkout "juice-shop=$(cd artifacts/juice-shop && pwd -P)" \
  --checkout "nodegoat=$(cd artifacts/nodegoat && pwd -P)" \
  --out artifacts/oss-release-evidence/results
```

An exit 2 is an incomplete result to retain, not a pass to relabel. This external evidence does not justify production-wide accuracy claims.

## Generated workflow on GitHub

The installed candidate's CLI generated the workflow with `init --mode action --action-ref 642fedf8c39b2a7fba7d7d446fe2675a4dc586eb --code-scanning`. Its bytes were unchanged. A separate, unmerged validation branch, `codex/rc050-onboarding-fixture`, contains only this generated workflow and an owned three-line SQL fixture. No repository settings or target dependencies were changed.

| GitHub run | Fixture commit | Expected and observed result |
| --- | --- | --- |
| [Vulnerable input](https://github.com/dusen0528/wakeio-security-ci/actions/runs/38708348918) | `13847300e22928dcb6083db6793f54bb11c93b4b` | One SQL candidate; scan exit 1 keeps the job failed; fresh SARIF validation, code-scanning upload and report artifact upload succeed |
| [Parameterized input](https://github.com/dusen0528/wakeio-security-ci/actions/runs/38708603149) | `ee6791080568854aa209ead88dcbd909e1df36f9` | Scan and workflow succeed; the same upload path processes the new reports |

The first upload produced code-scanning alert #2 at `app.ts:2`, tied to the workflow and fixture commit. After parameterization the reports recorded zero findings, zero incomplete checks and exit 0; the alert instance on the validation branch became `fixed`. This validates the generated push workflow, permission scope, finding gate, upload, and artifact path on GitHub. It does not validate a fork PR or changed-line PR annotation, or prove a runtime exploit was fixed. Local evidence is under `artifacts/onboarding/`.

The earlier REST-upload fixture [alert #1](https://github.com/dusen0528/wakeio-security-ci/security/code-scanning/1) was dismissed as **Used in tests**. Its original SARIF, API responses, screenshot and dismissal receipt remain in `artifacts/github-sarif/`; dismissal does not remove the verification record.

## Other release checks

The [integrated SHA release-check](https://github.com/dusen0528/wakeio-security-ci/actions/runs/38703232112) passed. Local required-engine validation passed 1,536 tests with zero failures or skips, plus the owned loopback corpus, package installation, exact-SHA Action smoke and installed Schemathesis checks. Those results belong to `642fedf`; subsequent documentation changes do not become new engine test measurements.

After the README scope clarification, `npm run package:release -- --out-dir artifacts/pretag` completed and `npm publish --dry-run --ignore-scripts ./artifacts/pretag/wakeio-security-ci-0.5.0.tgz --json` exited 0: version 0.5.0, 377 files, 1,065,008 bytes packed / 3,734,137 bytes unpacked. The README edits change the npm tarball checksum; the earlier candidate's checksum must not be reused. Evidence is `artifacts/rc-evidence/npm-publish-dry-run.json` and `npm-publish-dry-run.stderr`. Dry-run does not publish or prove registry authentication, ownership, or post-publication installation.

Registry installation after publication, fork/changed-line PR verification, ja/zh onboarding and the pilot remain outside this record.
