# Experimental agent-dast SDK

`wakeio-security-ci/agent-dast` exposes the bounded worker-result validator,
local task store and the experimental [built-in plan runner](agent-dast-runner.md).
The validator/store alone do not execute a target or model. `runExecutionPlan`
and `run-plan` connect explicit consented plans to existing DAST adapters; agents
do not receive database authority. Store use supports Node 22.13+ within
22.x, Node 23.4+ within 23.x, and Node 24 or newer, with `node:sqlite` available;
unsupported runtimes fail with `node_sqlite_unavailable`.
The ordinary package entrypoint and CLI do not import SQLite eagerly.
Use a reviewed package build containing these experimental exports.

The module's introduction in Node 22.5 is not sufficient for the store's
read-only preflight: that version ignores `readOnly` and opens a database with
read/write/create flags. The supported range uses the documented read-only
option and unflagged module availability. See the [Node 22.5 implementation](https://github.com/nodejs/node/blob/v22.5.0/src/node_sqlite.cc),
[Node 22 SQLite API](https://nodejs.org/download/release/v22.22.1/docs/api/sqlite.html)
and [Node 23.4 SQLite API](https://nodejs.org/download/release/v23.4.0/docs/api/sqlite.html).

```ts
import { openRunStore, parseWorkerResult, type NewTask } from 'wakeio-security-ci/agent-dast';

const store = await openRunStore(':memory:'); // Local metadata only; no target request.
store.createRun({ runId: 'r-owned', targetOrigin: 'http://127.0.0.1:3000',
  scopeHash: 'a'.repeat(64), provider: 'fixed', startedAt: new Date().toISOString() });
store.addSurfaces('r-owned', [{ surfaceId: 's-items', method: 'GET',
  path: '/items', authState: 'anonymous' }]);
const task: NewTask = { taskId: 't-owned', runId: 'r-owned', category: 'config',
  surfaceIds: ['s-items'], coveragePlan: [{ surfaceId: 's-items', check: 'status' }],
  provider: 'fixed', scriptRef: 'owned/status' };
store.createTask(task);
store.startTask(task.taskId);
// Your trusted executor must perform the check and record its observed
// coverage/findings before closing this task. This example performs no scan.
store.close();
```

Parse the executor's single stdout JSON object with
`parseWorkerResult(workerStdout, { runId: task.runId, taskId: task.taskId,
category: task.category })`. A rejection has a fixed reason/schema location,
without echoing unknown keys or worker output. Raw SDK inputs and expected
identity must be bounded own JSON data; getters, proxies and inherited
structural fields are rejected without invocation.

A `completed` result requires positive `planned`, `executed === planned`,
`skipped === 0`, no gaps and no truncation. For the example plan this means
`{ planned: 1, executed: 1, skipped: 0 }`. `partial`, `error` and `skipped`
require an explicit gap; a skipped result cannot claim execution or findings.
The result must fit 2048 serialized UTF-8 bytes, with safe integer totals.
`failedWorkerResult` produces an error with zero placeholder counts, not a
completed result or a copy of unusable worker claims.

`completeTask(result, runnerLedger)` validates again and reconciles the full
assigned coverage plan, persisted task-local canonical findings/severities and
runner ledger. Completed work requires a successful, non-truncated ledger;
missing rows or contradictory counts cannot close the task. Persisting a row
is a caller observation, not independent evidence that a request occurred.
Populated legacy v1 databases are refused as `legacy_evidence_untrusted` rather
than upgraded into trusted v2 evidence.

Retrieve the reference schema without importing the store:

```js
import { createRequire } from 'node:module';
const schema = createRequire(import.meta.url)('wakeio-security-ci/schemas/worker-result.v1.json');
```

The disk factory is POSIX-only: its existing parent must belong to the current
UID with mode `0700`, and an existing database must belong to that UID with
mode `0600`. It creates a new database privately. Windows supports `:memory:`
only. These filesystem requirements apply to `openRunStore`; a caller supplying
a native connection owns its storage policy.

Read-only preflight preserves legacy database schema/data; it is not a promise
of zero filesystem writes. SQLite can create `-wal`/`-shm` sidecars while reading
a WAL database when its directory permits this. The WAL is part of persistent
database state, so copying only `run.db` can omit committed changes. See the
[SQLite WAL documentation](https://sqlite.org/wal.html#read_only_databases).

`run.db` stores redacted metadata and bounded relative `evidence/...json`
references; the SDK does not write those evidence files. Never store raw
requests, responses, source or credentials there. `roundSummary(runId)` is a
bounded aggregate, not a security report. This SDK does not emit the CLI's
`report.json`, `agent-report.json`, Markdown or SARIF bundle; existing scan
delivery still uses its separately selected `--out` directory.

The factory requires an existing owned 0700 parent and a 0600 single-link
regular DB file. It refuses WAL header mode or `-wal`/`-shm` sidecars before
opening SQLite; current factory storage uses rollback journals. Read-only
SQLite alone does not guarantee unchanged filesystem sidecars. Preserve old
WAL evidence and start a separate file; this SDK does not recover/checkpoint
that evidence. Direct caller-owned `DatabaseSync` injection leaves file
management with that caller. A worker with direct DB/file access can bypass
the SDK checks; no OS sandbox or independent execution attestation is supplied.
See the [RunStore evidence, migration and limits contract](agent-dast-store.md).

Private file modes, read-only preflight and transactional consistency do not
provide an OS sandbox, authenticate worker code, or attest that its claimed
requests occurred. They protect the declared local storage contract.
