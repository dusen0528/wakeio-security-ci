# Bounded Koa request-context source contract

This source-preview extension connects a declared Koa middleware context to
existing SQL, outbound-request and evaluation-shaped candidate rules. It reads
the target as data. It does not import/install Koa, execute middleware, contact
a target, prove framework runtime identity or verify exploitability. Independent
tests and fixtures were authored before candidate execution; root alone built
and ran the Wakeio checks. The local candidate results below demonstrate this
declared static subset, without claiming installed or published support.

## Official semantic reference

The reference is official Koa `v3.1.1`, commit
`2e52fb589c29c9aa6f0915515263372c3a2ce4bf`. Read-only GitHub API inspection
resolved the [tag reference](https://api.github.com/repos/koajs/koa/git/ref/tags/v3.1.1)
to annotated tag `c7611ad6d39758bdba28365c9353c39eb9b67837`, whose
[tag object](https://api.github.com/repos/koajs/koa/git/tags/c7611ad6d39758bdba28365c9353c39eb9b67837)
names that commit. No package was installed or executed. This is a source
semantic reference, not evidence of the target's installed dependency version.

The [official application API](https://koajs.com/#app-use-function) registers one
middleware function through `app.use(fn)`. Its
[pinned implementation](https://github.com/koajs/koa/blob/2e52fb589c29c9aa6f0915515263372c3a2ce4bf/lib/application.js#L141-L146)
checks that operand and appends it to middleware. The middleware's first argument
is context; its second is downstream continuation, as shown in the
[official cascade documentation](https://koajs.com/#cascading). Pinned
[request handling](https://github.com/koajs/koa/blob/2e52fb589c29c9aa6f0915515263372c3a2ce4bf/lib/application.js#L187-L193)
passes context to composed middleware.

The [context documentation](https://koajs.com/#context) distinguishes request
and response delegates. The
[pinned delegation lists](https://github.com/koajs/koa/blob/2e52fb589c29c9aa6f0915515263372c3a2ce4bf/lib/context.js#L195-L248)
confirm the sides below. [Context creation](https://github.com/koajs/koa/blob/2e52fb589c29c9aa6f0915515263372c3a2ce4bf/lib/application.js#L202-L217)
creates separate request/response objects, initializes both original URL fields
from the incoming URL and initializes `state` to an empty object.

| Read at a declared middleware context | Core meaning | First source-model slice |
| --- | --- | --- |
| `context.query`, `context.request.query` | Parsed request query; [query getter](https://github.com/koajs/koa/blob/2e52fb589c29c9aa6f0915515263372c3a2ce4bf/lib/request.js#L172-L186) reads the query string | Request source, including scalar property/literal-computed access |
| `context.querystring`, `context.request.querystring` | Request query string | Request source |
| `context.url`, `context.request.url` | Incoming URL; [URL getter](https://github.com/koajs/koa/blob/2e52fb589c29c9aa6f0915515263372c3a2ce4bf/lib/request.js#L77-L79) reads Node request URL | Request source |
| `context.originalUrl`, `context.request.originalUrl` | Original incoming URL assigned during context creation | Request source |
| `context.path`, `context.request.path` | Request pathname | Request source |
| `context.header(s)`, `context.request.header(s)` | Incoming headers; [header getters](https://github.com/koajs/koa/blob/2e52fb589c29c9aa6f0915515263372c3a2ce4bf/lib/request.js#L35-L67) read Node request headers | Request source |
| `context.body`, `context.response.body` | Response body | No automatic request source; response-sink modeling is separate |
| `context.response.header(s)` | Outgoing response side | No automatic request source |
| `context.state` | Application/middleware state | No automatic request source |
| `context.request.body`, `context.params` | Parsed body/router data requires additional middleware contracts; core [bundles no middleware](https://koajs.com/#introduction) | Not inferred from Koa core |
| `next`/second middleware argument | Continuation | Not a request/context source, even if named `request` |

Other documented fields/methods, body parsers, routers, raw Node request objects,
cookies, proxy-derived identity, async-local context and cross-middleware state
are outside this first slice. Unsupported data is unknown, not certified safe.

## Declared lexical support and safeguards

The agreed first implementation recognizes exact same-file ESM default import
or default-as import from `koa`, an immutable `new Application()` binding and
its direct `.use(handler)` registration. Same-file immutable application aliases
and a direct inline function/arrow or immutable named callback/alias may connect
that registration. The callback has one or two parameters; only the first
receives context authority, regardless of its spelling. No bare `ctx/context`
name heuristic is introduced. CommonJS, namespace/default dispatch, arbitrary
factory wrappers and router registrations are not positive requirements.

Approved query/request aliases, literal-computed property reads and local or
first-parameter destructuring reuse bounded value transfer. A request-source
trace starts at the actual approved read/binding, then follows the existing
helper/alias/sink model. The existing HTTP convention leaves `sourceKind`
absent; it does not invent filesystem-origin types. Kind remains candidate and
runtime binding/execution remains unverified.

Observed factory/application/handler reassignment, shadowing, prototype/use
replacement, request/context accessor replacement, opaque escape or incomplete
indexing cannot retain stale registration proof. Response/body/state/unknown
properties do not fall through to a generic request-root taint. Genuine missing
modules and exhausted analysis budgets retain partial/gap/exit-2 semantics.
Recognized Koa registration alone must not create an unresolved `app.use` gap.

This is a fixed-read subset of a registered middleware, not complete Koa
application or middleware-chain analysis. Calling `next()` can execute unknown
downstream code that changes context/request accessors and values. Such a
continuation or unknown context mutation retains gap/partial uncertainty;
registration identity must not certify the later context as pristine. Router,
body-parser and opaque middleware effects are not inferred from Koa core.

`StaticModules` already supplies symbols, imports, new expressions, references,
mutation sets, same-file ownership, index completion and external-entry tracking.
The narrow Koa model can reuse those charged passes and existing value/trace
transfer, without importing target dependencies or copying Express route,
router, array-handler and response-MIME behavior. Context and request require
separate value roles so their response/unknown fields cannot become inputs.

## Independent acceptance frozen before candidate execution

`tests/source-koa.test.ts` contains twelve groups:

1. Exact default/default-as import, construction and `.use` bind renamed first
   parameters to actual SQL source evidence and a completed threshold gate.
2. Query input reaches existing outbound `fetch` candidate with source evidence.
3. Query input reaches `eval` with actual source evidence; a generic unresolved
   evaluation-shaped candidate is not substitute detection.
4. Approved context/request/query/URL/header aliases and literal-computed reads
   preserve source authority.
5. Local and middleware-parameter nested destructuring retain approved inputs.
6. Bound SQL values, fixed URL/text and explicit input overwrites remain narrow
   negative controls.
7. Plain context objects, unrelated `.use` methods and unbound functions do not
   acquire Koa authority.
8. Type-only/wrong imports, constructor/application shadowing and reassignment
   revoke registration evidence.
9. `.use`/prototype/request-context mutation and opaque escapes cannot preserve
   stale proof through aliases.
10. Immutable named callbacks and helper transfer retain actual input; second
    `next`, named `request`, unrelated callbacks and changed handlers do not.
11. Response body/outgoing headers/state/params/unmodeled parsed body do not
    become automatic request sources. Existing unresolved eval candidates may
    remain, without invented Koa/HTTP source traces.
12. Public source-only scan of owned V/F fixtures retains 1/0 and four redacted
    formats; incomplete indexing, cross-file names and real missing modules
    do not borrow/erase proof or gaps.

Owned paired source files are
`tests/fixtures/source-koa/{vulnerable,fixed}/app.js`. They are read-only scanner
inputs, never imported or executed. The existing unbound
`benchmarks/fixtures/koa-query-sql-vulnerable/app.ts` and corpus v3 remain unchanged
and `known_miss`; this slice must not satisfy them by adding a spelling heuristic.
All twelve groups were frozen before root execution. Their expectations
are semantic observations/guards, not a population recall or production claim.

## Observed local baseline and candidate comparison

Root's local `artifacts/koa-context-2026-10-14/baseline-v3/receipt.json` records
five separately owned source cases scanned by the previous archive. SQL-only
and HTTP-only cases were completed/exit 0 with no findings. Combined SQL/HTTP/
eval was exit 2 with only a generic evaluation candidate. The paired bound-SQL,
fixed-URL/JSON-parse source was exit 0; malformed source was exit 2. The receipt
records unchanged input bytes and per-format hashes. These are root execution
results, not author execution or runtime Koa behavior.

Those baseline case bytes differ from the new independent fixture pair above.
They must not be conflated. The final candidate scanned the same five root
case inputs, and both receipts record unchanged source bytes. Observed CLI
results were:

| Same input case | Previous archive | Final local candidate |
| --- | --- | --- |
| SQL-only registered middleware | Exit 0, no findings | Exit 1, SQL candidate with source trace |
| Outbound-request-only registered middleware | Exit 0, no findings | Exit 1, outbound-request candidate with source trace |
| Combined SQL/outbound/eval middleware | Exit 2, only unresolved eval candidate | Exit 1, three candidates with source traces |
| Bound SQL, fixed URL and JSON parse | Exit 0, no findings | Exit 0, no findings |
| Malformed source | Exit 2 | Exit 2 |

This demonstrates added detection for the declared binding and read patterns.
The malformed control still distinguishes incomplete analysis from a completed
scan without findings. SQL, HTTP and eval were not executed by these source scans.

Root also froze independent test SHA256
`dfec7fd31ca12ad62fb7080ea0d2e9fcd3c55e22a284a946af6953f5764ad504`
and ran it against the prior archive: **12 groups, 4 passed / 8 failed**,
retained in local `artifacts/koa-context-2026-10-14/baseline-independent.log`.
The positive registration/source groups fail on the missing capability. The
response/body negative group additionally exposes the old unbound parameter
destructuring heuristic, which a recognized Koa positional binding must not
inherit. Passing old negative groups alone does not prove the new provenance
guards; they must be evaluated alongside their working positive controls.
The final clean build passed all twelve independent groups, including their
positive controls, alongside the additional producer/reviewer guard tests.

Before any candidate execution, author source review corrected one expected
source coordinate in group 5: the two-step `{request: wire}` then
`{query: terms}` destructuring case must point to the second/query read at line
5, not the first/request-object alias at line 4. Root approved this correction
from the already agreed approved-read contract. Fixture inputs, sink/count/gate
assertions and the other source-coordinate expectations are unchanged. The
original test freeze and baseline failures remain retained; the corrected test
SHA256 is `47b48bf86bc550dea42684a383b4daad886d6c2c1cf93df94c926c913802b8fa`.
This is not an oracle adjustment to candidate output.

After the ruleset identity update, the final clean-build required engine suite
passed **1,210/1,210** tests with zero failures, skips, cancellations or todos.
Root separately reported
**18/18** CI-support checks passed. The required-suite receipt records the same
296-file source fingerprint before and after execution:
`75b731bc3394764b1b870685d9ba8e150b6d468bdc8887c41ac593d95c146f43`.
The earlier full pass remains retained under `required-final/` with fingerprint
`4a2b401e91649eea8648a0d1e340f06ccd3bdde51e15ddc6fa225c1c4c379b54`;
it precedes the ruleset update and is not the final build fingerprint.
Seven separately authored reviewer cases all matched their expected results,
including constructor escape, prototype customization, extra/computed
registration arguments, unregistered functions and unrelated constructors.

Public reports now declare ruleset `2026-10-14.1` so comparison/source-handoff
compatibility does not treat the previous detector and this Koa extension as
the same analyzer. The post-update CLI rerun retained all five table outcomes
and unchanged input SHA256 values. Comparing old/new fixed reports, each with
zero candidates, still returned `comparable: false` and CLI exit 2 with reason
`Declared target, options, or ruleset changed.` This deliberately prevents a
ruleset change from being reported as a comparable absence or security fix.

The unchanged original `2026-10-05.synthetic-js-ts.v3` corpus completed all
50 cases: **24 TP, 0 FP, 1 FN**, with that FN still the declared unbound Koa
`known_miss`. Supported FN and strict regressions remain zero. The new registered
middleware cases are additional evidence and do not replace that denominator.
These synthetic static results do not estimate production accuracy.

The following repository-relative local evidence records identify the measured
runs; they are not package contents or publication receipts. SHA256 values
fingerprint the exact records inspected for this document:

| Evidence under `artifacts/koa-context-2026-10-14/` | SHA256 |
| --- | --- |
| `baseline-v3/receipt.json` | `4b8ecadaa7bbdaae6a3751f61499697328be86509a46b83ffd891ae4eba858af` |
| `ruleset-final/receipt.json` | `2066545ad1055a1a05e74188f63490557791957e608e089056e1b934dc8cb1b2` |
| `ruleset-compare/comparison.json` | `7a80802266785bea11287d2365035f554d2cee21a06eb158a063097503e030d4` |
| `candidate-final-reviewer-receipt.json` | `09d6cf2f22b384f61c51b6f339a826a1b29e125a198e4e2c360714a2c6270210` |
| `candidate-benchmark/benchmark.json` | `2ffd3e4e32c23fe83dc14059fd4ea576458585f9a297c746684c088406b4edcf` |
| `required-ruleset-final/required-engine-FTbnLh/receipt.json` | `56085ad225e14816a0b6a367a74cae9ac9f03815238a9597fb96b40b4e655e83` |

At this documentation freeze, GitHub merge/publication and fresh compiled
package/source-archive verification remain pending. The published npm package
remains `0.4.0`; these local results do not imply an installed or deployed update.

## Existing scan workflow

For a reviewed source build, the normal workflow stays source-only:

```sh
node /absolute/path/wakeio-security-ci/build/src/cli.js scan \
  --source /absolute/path/koa-project \
  --tools none \
  --out /absolute/path/outside/koa-project/reports
```

The scanner reads source as data and writes `report.md`, `report.json`,
`report.sarif` and `agent-report.json`. It does not invoke the middleware's SQL,
fetch or eval, install its dependencies or issue DAST requests. Existing scan
exit 1 denotes threshold findings; incomplete analysis remains exit 2, including
`fail-on none`. Reports supply reviewable source evidence, not runtime proof.
