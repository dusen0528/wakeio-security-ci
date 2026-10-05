# Scanner parser diagnostics

Ruleset `2026-10-05.17` adds an optional numeric `diagnosticCode` to `parse_error` gaps with `phase: parse`, `extent: site` and a safe collected relative location. A new parse site requires a positive safe-integer code; the field remains absent on legacy check-wide gaps. Each erroneous JS/TS file contributes one observation. The retained representative is the scanner TypeScript parser's smallest valid `(start, code)` diagnostic; UTF16 line/column positions are 1-based and EOF positions are allowed. Diagnostic messages, source excerpts and related information are not published.

This is a diagnostic from this scanner's parser, not proof that the target project's official build fails or its source needs a patch. `nextRead: review_parse_diagnostics` is a source-only review location, not permission or an instruction to install, execute or automatically modify the target.

`parseErrorCount` still counts files with syntax diagnostics, not diagnostic messages. Those files remain excluded from flow analysis and the check stays partial (CI2). Missing valid diagnostic metadata or unsafe/protected paths use a check-wide fallback. Legacy count-only callers retain that fallback. Inconsistent representative counts or malformed external metadata produce unknown accounting rather than invented exact coverage.

The existing 32 representative keys per check and 256 per report are unchanged; dropped observations count files, not unselected messages. JSON, agent JSON and SARIF check properties preserve coordinates and TS codes. Markdown labels each as a scanner parser representative per file. Parser gaps are not findings or SARIF results. Findings, identity, order, gate policy, source/flow model and analysis caps are unchanged.

When the first selected incomplete check starts with a parser fallback, agent `nextRead` may use the first located parse item within that check's existing three representative summary items. It does not search omitted/dropped evidence or change check priority.
