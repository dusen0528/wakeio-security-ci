# Independent process-role review additions

Status: extra adversarial oracle authored after the frozen 25-group acceptance
baseline and before engine validation. No implementation-pass or exploit claim.
The frozen spec and test file remain untouched. Root alone executes tests.

`tests/source-process-review.test.ts` exercises ten bounded review groups:
charged native-alias inventory; alias/reflection/native-family mutation;
captured options-property evaluation; a later unrelated property input;
duplicate shell fields; null/undefined argv overload; callback-overload ignored
options; unknown argv/options role; completed local throw bodies; and interrupted
local wrappers with a nested native sink. Reports remain redacted in all four
public projections. These cases do not claim complete JavaScript semantics.

The overload/property expectations come from the official pinned
[Node.js v22.22.0 child_process implementation](https://raw.githubusercontent.com/nodejs/node/v22.22.0/lib/child_process.js):
`normalizeExecFileArgs` preserves explicit later options for null/undefined argv
but resets options when the second argument is a callback. Spawn also accepts
null/undefined argv with explicit later options. Ordinary JavaScript object
property evaluation captures each initializer before evaluating the next; later
binding writes must not retroactively change an earlier property's value.

When the model cannot establish a captured field because of effects, low
truncated input evidence or partial coverage is accepted. Completed clean is
not acceptable when the captured shell-field source is known. A later unrelated
input must never become medium-confidence evidence of an earlier fixed shell
field. Concrete alias/reflection writes veto pristine binding exclusions; this
does not assume runtime call reachability or prove replacement behavior.

Review must distinguish required corrections within this scope from documented
limitations. Do not expand into command-specific flags, runtime target commands,
arbitrary dynamic imports, interpreter execution or general prototype modeling.
