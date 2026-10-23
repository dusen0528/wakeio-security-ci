# Frozen 0.5 compatibility evidence

Captured with the unchanged main CLI at 536d968357c31a7c681164ef7afa6307b138d1a7, Node 22.23.1. Do not regenerate from the candidate implementation to update an expected result.

The states/ report is separately captured from the unchanged 0.5 serializer using synthetic checks for completed/partial/error/skipped/not_applicable; it is not an executed target scan.

The source inputs copy the existing sql-parameterized/sql-direct fixtures. Reports are outside their source directories and use stable project IDs. The partial case adds a second source file and uses --source-max-files 1. No fixture module or project script was executed.

manifest.json binds all four original artifact byte streams. Expected scan exits are pass=0, findings=1, incomplete=2. Original comparison exits are recorded separately: an unchanged existing finding does not block a comparison, while an incomplete comparison remains exit2. Remediation/verification remains unverified.

compat-0.5.test.ts reads these historical artifacts, verifies raw digests and projections, exercises existing CLI flags/exit semantics, and keeps execution-plan v1 strict. Source analysis success is not HTTP, exploit or fix verification.
