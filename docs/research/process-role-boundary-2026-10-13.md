# Process-role reflection boundary correction

Independent source review found the first `ProcessRoleModel` constructor marked
every native process role unresolved after any global `Object.assign`,
`defineProperty`, `Reflect.set`, or even an `Object.prototype` read. This would
create candidates for unrelated ordinary record operations preceding a fixed
executable, tainted argv, and explicit false shell option. This is a concrete
classification path identified from source; no execution result is claimed.

The official pinned
[Node.js v22.22.0 implementation](https://raw.githubusercontent.com/nodejs/node/v22.22.0/lib/child_process.js)
clones options into `{__proto__:null,...options}` in `normalizeSpawnArguments`
(line 555), `normalizeExecArgs` (line 187), and `execFile` (lines 308–317).
Inherited `Object.prototype.shell` alone therefore does not enable shell
execution for the supported plain/options-absent direct API calls. Read-only
prototype access and unrelated record reflection are not native binding writes.

The minimal correction removes this unrelated global veto and retains the
existing native-family escape/write checks and own-options shape/mutation
uncertainty. Delete-before-inherited-method replacement is a real native binding
change; an opaque consumer receiving the namespace invalidates its pristine
identity regardless of which reflective target it returns. Own options getters
are separately unresolved. This does not certify argv flags, executable behavior,
global JavaScript runtime integrity, or general prototype safety.

`tests/source-process-boundary.test.ts` adds six narrow groups for this boundary.
The first two independent oracle files remain unchanged. Only the root agent
executes tests and records actual results. No upstream scanner rules are copied.
