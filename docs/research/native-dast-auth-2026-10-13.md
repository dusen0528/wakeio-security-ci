# Native authenticated SQL policy design (2026-10-13)

This increment extends the existing owned numeric differential probe to endpoints protected by a preexisting Authorization credential. It is not automatic login, crawling, credential discovery, broad fuzzing or a general authenticated DAST engine. No upstream code or templates are copied.

Primary design references:

- [ZAP authentication configuration](https://www.zaproxy.org/docs/desktop/ui/dialogs/session/context-auth/) separates authentication setup from verification and describes polling a configured URL to observe whether a user remains authenticated. Wakeio adopts a narrower before/after identity check rather than ZAP's login or polling machinery.
- [ProjectDiscovery's authenticated Nuclei design](https://projectdiscovery.io/blog/scanning-login-protected-targets-with-nuclei) scopes secrets to configured domains and describes static and dynamic authentication. Wakeio uses one exact validated origin and a selected environment Authorization value; it does not adopt Nuclei's secrets files, login templates or dynamic authentication implementation.

The policy-v2 contract supplies `authorizationEnv` and an identity `{path,status,jsonPointer,equals}` in addition to the original numeric target/oracle. Credential resolution uses a selected own data property, rejects accessors/proxies and invalid header values, and captures one value before execution awaits. Credential data never enters the returned prepared policy, plan, ledger, scope fingerprint or model projection. HTTPS is mandatory except explicitly permitted literal loopback for owned fixtures; redirects are refused by the existing transport.

Identity-before plus eight unchanged SQL phases plus identity-after consume one shared default-ten/max-64 HTTP attempt budget, including retries. A failed before-control stops SQL probing. An observed SQL differential survives a failed after-control as low-confidence evidence with partial status; it cannot authorize finding replay. Overall result and SQL probe outcome are separate enum fields. V1 remains unchanged.

The caller chooses the identity endpoint and expected principal. Matching that response at two boundaries does not prove the SQL endpoint's authorization logic, a stable principal during every intermediate request, or actual exploitability. Replay requires complete original controls, the same policy/effective limits and freshly resolved credentials. Advice policy 5 transfers enum outcomes only and never runs replay.

Validation is limited to independently owned authenticated SQLite fixtures, labeled synthetic HTTP protocol fixtures, offline-plan/refusal tests, report/CLI/Action contracts and fake provider executables. Live authenticated staging, production detection rate and a real policy-5 model call remain unverified. Counts and release receipts are recorded separately after the root agent's coordinated gates.
