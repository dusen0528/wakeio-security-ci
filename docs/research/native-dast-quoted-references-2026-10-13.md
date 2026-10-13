# Native single-quoted SQL differential: primary references

Reviewed 2026-10-13. This note records official documentation and source review only. No upstream engine, target application, database fixture, model, build or test was executed for this research. It is not an efficacy receipt. The new implementation is original, bounded code; no upstream payload corpus, matcher list or scanner implementation is copied.

## MIT engine references and attribution

Nuclei is an actual maintained HTTP vulnerability scanner. Its pinned [v3.11.1 license](https://github.com/projectdiscovery/nuclei/blob/v3.11.1/LICENSE.md) is MIT; the separately pinned [templates license](https://github.com/projectdiscovery/nuclei-templates/blob/f8b8b8dcd70d93826c3767e1829ef8243af9f03b/LICENSE.md) is also MIT. These are distinct artifacts, not a claim that every dependency or unrelated scanner is MIT.

The pinned [Nuclei SQL error template](https://github.com/projectdiscovery/nuclei-templates/blob/f8b8b8dcd70d93826c3767e1829ef8243af9f03b/dast/vulnerabilities/sqli/sqli-error-based.yaml) perturbs one request value at a time with quote/delimiter characters and matches database error patterns with an exclusion. This establishes that quote-context testing exists in a real engine. It does not implement Wakeio's exact JSON baseline/true/false oracle and does not establish that a quote error proves injection. No character list or error regex set is imported into Wakeio.

Nuclei's official [HTTP fuzzing documentation](https://docs.projectdiscovery.io/templates/protocols/http/fuzzing-overview) separates request part, replacement strategy and parameter selection. Its time-delay analyzer uses extra alternating verification requests to distinguish response-time control from noise. Wakeio adopts neither timing inference nor that algorithm; the relevant design lesson is that a changed response needs explicit controls rather than one perturbation being enough.

## Boolean response comparison is a separate detection strategy

The official [ZAP SQL injection rule source](https://github.com/zaproxy/zap-extensions/blob/main/addOns/ascanrules/src/main/java/org/zaproxy/zap/extension/ascanrules/SqlInjectionScanRule.java) describes refreshing the baseline, applying true/false conditions and comparing behavior. The same source identifies its license as Apache-2.0, so it is not counted as MIT. Its comments also warn that prior probes can change database state. This supports fresh controls and scoped uncertainty, not copying its payloads or claiming side-effect-free GET execution.

The official [sqlmap technique description](https://github.com/sqlmapproject/sqlmap/wiki/Techniques/df3882c51861bef399fb4582912c4f052c352dd1) distinguishes boolean response comparisons from error, timing, UNION and stacked-query strategies. Its [license documentation](https://github.com/sqlmapproject/sqlmap/wiki/License) identifies GPL terms, not MIT. Wakeio's selected increment does not import sqlmap code, payload XML, inference/extraction logic or automatic context discovery.

## SQLite string context and bound-value control

[SQLite expression syntax](https://sqlite.org/lang_expr.html#literal_values_constants) specifies single-quoted string literals and doubled single quotes for an embedded quote; backslash escaping is not its standard string-literal mechanism. Therefore numeric-only suffix tests cannot establish coverage of a value interpolated inside a string literal. This is a context limitation, not a general database claim.

[SQLite binding documentation](https://sqlite.org/c3ref/bind_blob.html) distinguishes statement placeholders from runtime values supplied through bind routines. The owned fixed control should keep SQL structure constant and bind the complete query value; it must not emulate a fix by manually recognizing the scanner's input strings.

[Node 22 StatementSync documentation](https://nodejs.org/docs/latest-v22.x/api/sqlite.html#class-statementsync) exposes prepared statements with bound parameter values and recommends parameterized statements for user input. This is the appropriate implementation primitive for the independently owned real-SQLite fixture. A synthetic HTTP fixture can validate CLI/report plumbing but cannot independently establish SQLite behavior.

## Adopted bounded implementation contract

The product adds only policy v3/profile `single-quoted`, with revisions `sql-boolean-single-quoted-v3` and `sql-boolean-single-quoted-auth-v3`. Authentication is absent or a strict paired Authorization-environment/identity declaration. It retains two baseline/true/false/baseline rounds and the explicit scalar JSON oracle, with eight unauthenticated or ten authenticated logical requests and one shared attempt/body/deadline budget.

There is no automatic profile selection, crawling, arbitrary user payload, DBMS fingerprinting, quote/comment boundary search, stacked query, timing, UNION or extraction feature. The original bounded string predicate is chosen from SQL semantics for the declared context, not an upstream payload collection. Numeric v1/v2 policy normalization, hashes, profiles, request counts and finding IDs remain unchanged. Single-quoted finding IDs add only the sanitized execution revision as a namespace; policy/scope comparison and replay remain bound to the exact declared profile.

Unknown oracle values, drift, malformed responses, server errors, failed identity controls, cancellation and insufficient budget remain incomplete. Failed trailing identity after positive SQL observations preserves a low candidate but grants no replay authority. A completed negative means the declared differential was not observed; it is not a verified fix or general SQL coverage. Fresh package/Action and owned vulnerable/bound controls must provide separate execution receipts before any validation claim.
