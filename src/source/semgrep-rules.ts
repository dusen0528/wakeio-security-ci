// SPDX-License-Identifier: Apache-2.0
// Original WakeIO rules; no registry rule content is bundled or downloaded.
export const SEMGREP_RULE_REVISION = 'wakeio-go-v1';
export const SEMGREP_RULES = `# SPDX-License-Identifier: Apache-2.0
rules:
  - id: wakeio.go.sql-request-input
    languages: [go]
    mode: taint
    message: Request input reaches a SQL query argument.
    severity: ERROR
    pattern-sources:
      - pattern-either:
          - pattern: $REQ.FormValue(...)
          - pattern: $REQ.PostFormValue(...)
          - pattern: $REQ.URL.Query().Get(...)
        exact: true
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: $DB.Query($SQL, ...)
              - pattern: $DB.QueryRow($SQL, ...)
              - pattern: $DB.Exec($SQL, ...)
              - pattern: $DB.QueryContext($CTX, $SQL, ...)
              - pattern: $DB.QueryRowContext($CTX, $SQL, ...)
              - pattern: $DB.ExecContext($CTX, $SQL, ...)
          - focus-metavariable: $SQL
  - id: wakeio.go.html-request-input
    languages: [go]
    mode: taint
    message: Request input is converted to trusted HTML.
    severity: ERROR
    pattern-sources:
      - pattern-either:
          - pattern: $REQ.FormValue(...)
          - pattern: $REQ.PostFormValue(...)
          - pattern: $REQ.URL.Query().Get(...)
        exact: true
    pattern-sinks:
      - patterns:
          - pattern: template.HTML($HTML)
          - focus-metavariable: $HTML
  - id: wakeio.go.insecure-tls
    languages: [go]
    message: TLS certificate verification is disabled.
    severity: ERROR
    pattern: 'tls.Config{..., InsecureSkipVerify: true, ...}'
`;
