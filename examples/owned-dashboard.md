# Owned local dashboard

Use after the G3 evaluation has been completed. This thin local dashboard uses `runExecutionPlan` directly; it adds no detection logic or model calls. Agent superiority was not established in the G3 pilot, so fixed plans are used here.

Build: `npm run build`.

Start: `node examples/owned-dashboard.mjs --active-consent --out /tmp/wakeio-dashboard-new` (the directory must not exist).

The command creates two ephemeral loopback-only SQLite fixtures, operator grants and a private `token.txt`, then prints the local dashboard URL and token file path. Open the URL, paste the token, and explicitly confirm ownership/permission and active consent for each target. Choose **지금 검사** or **1분마다 반복**. Results show DB-admitted request counts, candidate counts and the existing stored runner report. **반복 중지** prevents the next execution; an in-flight scan may finish. Ctrl-C stops scheduling, aborts active runs and closes both fixtures.

Only the startup-approved origin/catalog is accessible; HTTP clients cannot submit file paths, engine plans or an arbitrary scan target. Each fixture gets a separate runner admission cap of eight and rate of ten requests/second. Two targets may execute concurrently; one target cannot overlap itself. An authenticated out-of-scope registration returns 403 and appears as `out_of_scope` in the event panel. Token/Host/Origin checks and a same-origin CSP protect the local API; the token is held only in browser memory. No remote deployment or multi-user authentication is provided.

Operator grants and consent are persisted per session. Runner bundles and run.db remain on disk. This version does not resume schedules or load historical sessions after a restart; use a new output directory and explicitly register again. There is no total lifetime schedule budget: every scheduled execution has its own gate cap. Keep repeat mode enabled only while the fixture remains approved. Event panel keeps the most recent 100 events in memory; persistent evidence is the consent record and execution bundles.

Tests: `node --test build/tests/agent-dast-dashboard.test.js`. Real local fixture requests verify repeated scans, two concurrent target caps against their SQLite ledgers and observed fixture counts, unauthenticated access, cross-origin/Host requests and out-of-scope registration. The tests do not call a model or any public target.

## Verification recorded 2026-10-15

Real browser flow: token login → two ownership/consent registrations → scan both → repeat first → pause → inspect stored report and out-of-scope rejection. The first target produced three separate ledgers of eight requests each; the second produced one of eight. Authenticated registration of a different origin returned403 and visibly appeared in the event panel. Demo servers were closed after verification.

Automated dashboard tests: three pass (two real loopback integration scenarios, one offline delayed-response/logout regression). Full suite before the final UI-only regression addition:1408 pass/26 fail/10 skip; a clean archive of the parent commit had1406 pass/26 fail/10 skip with exactly the same failure-name set. No new full-suite failures; this environment does not provide a green full-suite baseline. Build and final dashboard tests pass.
