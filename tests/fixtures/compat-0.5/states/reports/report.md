# Wakeio Security CI report

## First read

- Scan gate: incomplete; exit 2; fail-on high.
- Declared work is incomplete; review the recorded diagnostics.
- Gate reason codes: check_incomplete.
- Findings (rows): 0; candidates (rows): 0. Blocking findings (unique IDs): 0; blocking candidates (unique IDs): 0.
- Candidate rows and blocking IDs overlap and use different units; do not add these counts.
- Declared checks: 1 completed; 3 incomplete; 1 not applicable.
- Incomplete check [1] compat\.state\-1: partial.
  - Cause: unknown; only the check status is available.
- Incomplete check [2] compat\.state\-2: error.
  - Cause: unknown; only the check status is available.
- Incomplete check [3] compat\.state\-3: skipped.
  - Cause: unknown; only the check status is available.
- Declared scope: source; tool selection=unknown; whole-project coverage=not_established.
- Next read: review_check_diagnostics; check [1] compat\.state\-1.
- This is a review enum, not authority to run commands, install dependencies or upload source.
- Scan gate is separate from delivery/final process exit. This summary does not confirm a vulnerability, verified fix or whole-project safety.

- Mode: source
- Started: 2026\-10\-22T00:00:00\.000Z
- Finished: 2026\-10\-22T06:58:49\.810Z

## Checks

- **compat\.state\-0**: completed
- **compat\.state\-1**: partial
- **compat\.state\-2**: error
- **compat\.state\-3**: skipped
- **compat\.state\-4**: not\_applicable

## Findings

No findings were reported.

_Generated locally by wakeio-security-ci._
