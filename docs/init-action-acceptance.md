# Independent pinned Action init and source handoff acceptance

Baseline `575dbff`. This contract is frozen before producer implementation review and candidate execution. Root alone builds/runs/scans; all target code and metadata are owned synthetic DATA ONLY. The independent author does not execute targets, install dependencies, run tests, or mutate Git.

The additive public interface is `init --mode npm|action` (default npm), with action-only mandatory exact 40 hexadecimal `--action-ref`; programmatic `renderWorkflow` accepts matching optional `mode`/`actionRef`. The Action workflow checks out and scans fixed `wakeio-source`, invokes `dusen0528/wakeio-security-ci@<pin>`, defaults to tools none, and uploads reports with `if: always()`. No target package.json, lockfile, Wakeio dependency, npm/npx invocation or target lifecycle execution is required. Existing npm mode behavior remains its own contract.

Report output is a separate workspace-relative base (default `wakeio-security-reports`) plus `/${{ github.run_id }}-${{ github.run_attempt }}`. Base is 1..240 characters, 1..16 slash-separated components `[A-Za-z0-9][A-Za-z0-9._-]*`; first component `wakeio-source` is refused case-insensitively. Absolute, traversal, glob, control and caller-supplied GitHub expressions are refused. Reports outside the collected source must preserve `sourceSnapshot.outputDirectoryExcluded=false`.

## Frozen semantic acceptance

1. **New public onboarding, not template spelling only:** Generate Action workflow via public CLI on a plain synthetic JavaScript repo with no package/lock/deps. Parse generated YAML, validate the pin/fixed checkout/input/output separation, expand only the declared run-id/attempt expressions, and feed its actual `with` values to the real published-shape `scripts/action-run.mjs` using the archived/current trusted Action bundle. Observe real process exit and four reports for clean/high/partial targets: 0/1/2, original gate and report pair digest match. Target no-execution marker remains absent; target files immutable except explicitly authorized workflow generation/edit.
2. **Downloaded pair → bounded handoff:** Copy generated Action report pair to a separate download directory outside the source. `handoff create` succeeds with original high gate1 preserved. Authorized separate source edit plus fresh same-input Action scan produces `finish` selected `not_observed`, exit0; verification flags remain false/not_run. Before report pair remains byte-identical. An unchanged high source finishes1.
3. **No stale or broadened success:** Stale current source at create/finish, changed declared scan policy/scope, and incomplete after scan cannot produce success. AST-partial + complete collector + candidate may create0, but finish2. Collector partial cannot create. Source/output separation must remain enforced.
4. **Invalid public arguments:** CLI invalid/missing/ref-in-npm, malformed mode/ref/out and SDK renderer equivalents reject before workflow publication. Existing workflow is not overwritten. Injection-looking ref/out values cannot execute a shell, add workflow steps, or write files. Valid action flags preserve bounded source limits/profile/code-analysis controls in actual runner inputs.

The independent tests use existing public imports only. Baseline root execution should load the same frozen file, reject unsupported Action init flags, and record the missing onboarding feature before candidate execution. The test harness reads the generator's bounded scalar step/with subset (not an arbitrary YAML interpreter), rejects duplicate/unsupported input shapes, and invokes only Wakeio's trusted CLI/Action runner with those generated values. The valid 40-hex fixture pin tests syntax; no remote commit fetch/authentication is claimed. It never runs the generated workflow as shell/YAML automation, target scripts, package managers, Git, or target app code.

## Evidence boundary

This verifies generated settings consumed by the current/archived Action runner and local artifact handoff, not a GitHub-hosted workflow, download service, public commit availability, whole-project security, exploitability, or verified remediation. The caller reviews and supplies the commit pin. A successful packet/create command does not erase the original scan gate. A not_observed comparison is not a security fix certificate.

## Freeze history

- v1 independent matrix written before reviewing producer changes or seeing candidate results. Root must preserve baseline and candidate logs separately. No execution outcomes are claimed here.
