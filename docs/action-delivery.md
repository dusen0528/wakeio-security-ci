# Action scan and delivery status

The composite Action keeps the scanner result separate from the final Action
result. `scan-exit-code` (and `scanExitCode` in `action-status.json`) records an
observed scanner child exit of 0, 1, or 2. It is unavailable when no accepted
child exit was observed. `scan-status` retains the observed scan state;
cancellation can still make that state incomplete.

`exit-code` (and `exitCode` in the status artifact) is the final Action gate.
Failure to write `action-status.json` or a configured `GITHUB_OUTPUT` makes that
gate 2, including when the scanner found threshold findings and exited 1.
`delivery-status` is `failed` after either write fails and `delivered` otherwise.
The artifact records `failurePhase: "delivery"` for a delivery error. `delivered`
covers these required receipt/output channels, not the completeness of every
report format. It does not imply that the scan passed: an incomplete scan may
have delivered its reports successfully.

After a delivery error, the wrapper makes one bounded corrective attempt to
publish the failure to both channels. A writable channel must reflect final
exit 2; a persistently unwritable channel cannot receive a receipt. A recovered
write does not change the failed Action gate back to 0 or 1. Cancellation retains
the existing rollback behavior. Job summary writes remain optional and do not
change the gate. These files acknowledge the wrapper's observed state; they do
not prove the subsequent final GitHub Action outcome.

`report-dir` always identifies the status-artifact destination. Report-specific
outputs identify only available current artifacts: JSON must be fresh and
readable, and SARIF, Markdown, and agent files must each be regular, bounded
files whose fingerprints changed from their own before-state. An unreadable
before-state is conservatively unavailable. Agent output additionally requires
the existing SHA256 binding to the current JSON. Freshness checks for SARIF and
Markdown do not claim a digest binding to JSON. Missing or unchanged files have
empty outputs; previous files remain untouched for diagnostics.
