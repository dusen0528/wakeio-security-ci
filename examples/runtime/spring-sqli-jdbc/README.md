# Independent Spring SQL fixture: direct JDBC pair

R8 owns this second microservice and its expectations. It uses the same Spring Pack and SQL Oracle
as the primary JdbcTemplate pair; no fixture-specific scanner rule or engine exception is requested.
Each variant is a complete Maven application with its own source, configuration and three-row seed.
POM, datasource startup path, routes, seed and response types match between variants.
GET query `name` and POST JSON `/name` flow directly into the SQL call in each handler.
Only the search SQL changes: Statement string assembly versus PreparedStatement plus setString.
Safe-search always uses PreparedStatement; ping only reflects JSON; untouched receives no attack task.
ResultSets, Statements and Connections close through try-with-resources. SQL errors return a fixed
HTTP 500 error code without SQL, bound values, credentials or driver diagnostics.

`pins.json` and `cases.json` are byte copies of the independently frozen primary metadata/expectations.
Version candidates are identical; real JDK patch, platform and OCI digests remain null/unmeasured.
Maven's fixed output timestamp and debug/parameter information are preserved in both POMs.
`compose.draft.json` has a null DB image and missing Dockerfile.pending, so it cannot launch.
No host bind/socket/ports, privileged capability or administrator credential is requested.
R3 must supply pinned trusted build/lifecycle, rootless limits, default-deny network, logging/JaCoCo,
synthetic least-privilege datasource credentials and snapshot restoration before each control/probe.

Expected cases remain V1/V2/V3 confirmed 1; F1/F2/N4 confirmed 0 and strong 0 as recorded.
Default fail-on-grade strong expects vulnerable 1, fixed 0, safe 0, failure-only 2, finding+failure 1.
Preserve the N4 boundary in `tests/fixtures/runtime-m1/README.md`: ping has no SQL task; assigning a
SQL task without corresponding PG control observation must remain unknown/exit 2, never clean.
These are authored source/count expectations, not measured bytecode, Pack trace or runtime results.
No target build/run, PostgreSQL, Docker, WASM or Opengrep was executed. R9 owns actual verification.
