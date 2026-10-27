# Independent Spring SQL fixture: primary JdbcTemplate pair

R8 owns these sources, input cases and expected verdicts. SQL Oracle implementers may read them.
`cases.json` transcribes CP1-r2 expectations without importing or running product verdict code.
Both variants have identical POM, configuration, seed, methods and response types.
Only the two lines in `ItemController.search` differ: string assembly versus placeholder binding.
GET query `name` and POST JSON `/name` have separate handlers. Safe-search always binds.
Ping only reflects a JSON string; untouched is discovered but excluded from attack allocation.
The exception handler returns a fixed error code without returning SQL, input or DB diagnostics.

The seed contains exactly apple/banana/carrot. R3 restores it before EACH control and probe.
R3 must inject generated, in-memory synthetic datasource credentials; no credential is committed.
App role: NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS, schema USAGE/table SELECT only.
Separate trusted administrator/seed roles own server logging, restore, ACL and settings verification.
Server logging: log_statement=all plus log_min_error_statement=ERROR; Bind detail stays data.

Versions and official sources are in `pins.json`. Maven Central POM metadata for Boot parent/webmvc,
springdoc API and pgJDBC returned HTTP 200; this does not prove resolution or runtime compatibility.
The official Boot Java range and springdoc compatibility matrix include the selected versions.
PostgreSQL 18.6 is selected from official release metadata; its OCI platform digest remains unmeasured.
`compose.draft.json` intentionally has null DB image/missing Dockerfile and cannot launch.
Target drafts grant no execution permission. R3/R9 must supply measured immutable tool/image pins,
trusted build/lifecycle, rootless/cgroup limits, default-deny egress, logging and JaCoCo instrumentation.
No host sockets/binds/ports, privileged mode or source-controlled administrator setup are requested.

No Maven/JDK target build, Docker, HTTP target traffic or runtime verification was performed.
Bytecode/JAR/image hashes, effective dependency lock and LICENSE/NOTICE inspection remain pending R3/R9.
R9 must run the consent-gated verify path twice and verify real handler lines, verdicts and resource absence.
Default fail-on-grade strong expects vulnerable=1, fixed=0, safe-only=0; failure-only=2, finding+failure=1.
Missing/failed control or observation is unknown; HTTP success/reflection/row counts cannot confirm SQLi.
