# T3-REDACTION-JSON repair

Repair base: a02ef2abd9d450cdb63eaaa0a9a7b58b9349204c.
The independent needs-fix verdict and earlier findings are retained unchanged.
This is one bounded verifier-classified harness repair, not a new roadmap task.

## Reproduction and causal chain

The exact independent api-probes.mjs was executed without modification, followed
by a real Node child that emits password JSON on stdout and token JSON on stderr.
Both canaries exist only in memory and the child environment, never argv.
Before the fix, stdout/stderr/serialized-artifact retention flags were true.
The pre-fix probe intentionally refused to persist the unsafe capture.

Competing hypotheses and evidence:

1. Fragmented byte capture: rejected. The unchanged split-write password/Bearer
   control passes; captureProcess collects buffers before decoding/redaction.
2. Source drift: rejected. Worktree HEAD is the verifier's exact a02ef2a commit;
   the independent verdict binds its ff001264... source digest.
3. Canonical matcher excludes quoted keys: confirmed. Both captureProcess and
   writeArtifact delegate complete strings to redactSecrets. Its quoted-value
   regex requires the key name immediately followed by whitespace and colon or
   equals. A JSON key's closing quote breaks that match; a repeated pass cannot
   change it.

Fix the canonical quoted-value matcher to accept the closing key quote.
Do not add a JSON parser, QA-private redactor, dependency, or altered credential
catalogue. Existing case-insensitive key matching and escaped quoted values are
reused, with plain assignments and Bearer controls retained.

## Regression ownership

The report-projection regression owns canonical credential privacy across JSON,
Markdown, SARIF and agent output, using the existing report test boundary.
Rows cover literal JSON password/token keys, mixed case, nesting/arrays,
escaped quoted values, single-quoted text and original assignment/Bearer forms.

The T3 regression owns the distinct real process/serialization boundary: actual
Node stdout and stderr, a second artifact transformation, and persisted bytes.
It asserts boolean retention flags before writing, so its failing-before run
does not retain or print raw synthetic credentials. There are no test-only
exports, mocks, prose pins, fixed sleeps or new production seams.

## Scope and limits

The canonical contract is text redaction of literal credential names and quoted
values, not a general JSON decoder. Unicode-escaped key spellings, multiply
encoded JSON documents, non-string credential objects and arbitrary unlabelled
values are not newly claimed by this closing-quote repair. Casing, nesting and
JSON escapes inside quoted values are exercised independently.

The shared absent-ancestor mkdir race is unchanged and separately nonblocking:
the verifier proved parent-present concurrency; current acceptance does not
require racing creation of a shared missing ancestor. Repair scenario output
parents are established before launching independent commands. No unrelated
concurrency implementation change is included.

RUN_TMP=.omo/tmp/t03-json-repair-01 in this task worktree. Dependencies and build
were absent before preparation. All caches are scoped there. Generated Action
bundle changes from npm run build are owned generated output to restore, not
an authorized product bundle update; lead integration owns the eventual rebuild.
Only src/report-path.ts, its two covering test files and this owned evidence root
are staged. Independent verifier files and sibling lanes remain untouched.
