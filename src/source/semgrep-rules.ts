// SPDX-License-Identifier: Apache-2.0
// Original WakeIO rules; no registry rule content is bundled or downloaded.
export const SEMGREP_RULE_REVISION = 'wakeio-go-v2';
const REQUEST_SOURCES = `    pattern-sources:
      - pattern-either:
          - pattern: $REQ.FormValue(...)
          - pattern: $REQ.PostFormValue(...)
          - pattern: $REQ.URL.Query().Get(...)
          - pattern: $REQ.PathValue(...)
          - pattern: $REQ.Header.Get(...)
          - pattern: $REQ.URL.Path
        exact: true`;
export const SEMGREP_RULES = `# SPDX-License-Identifier: Apache-2.0
rules:
  - id: wakeio.go.sql-request-input
    languages: [go]
    mode: taint
    message: Request input reaches a SQL query argument.
    severity: ERROR
${REQUEST_SOURCES}
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
${REQUEST_SOURCES}
    pattern-sinks:
      - patterns:
          - pattern: template.HTML($HTML)
          - focus-metavariable: $HTML
  - id: wakeio.go.insecure-tls
    languages: [go]
    message: TLS certificate verification is disabled.
    severity: ERROR
    pattern: 'tls.Config{..., InsecureSkipVerify: true, ...}'
  - id: wakeio.go.command-request-input
    languages: [go]
    mode: taint
    message: Request input selects an executable or shell command.
    severity: ERROR
${REQUEST_SOURCES}
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: exec.Command($COMMAND, ...)
              - pattern: exec.CommandContext($CTX, $COMMAND, ...)
          - focus-metavariable: $COMMAND
      - patterns:
          - pattern-either:
              - pattern: exec.Command($SHELL, "-c", $COMMAND, ...)
              - pattern: exec.CommandContext($CTX, $SHELL, "-c", $COMMAND, ...)
          - metavariable-regex:
              metavariable: $SHELL
              regex: '^"(?:/bin/)?(?:sh|bash|dash|zsh)"$'
          - focus-metavariable: $COMMAND
  - id: wakeio.go.ssrf-request-input
    languages: [go]
    mode: taint
    message: Request input controls an outbound HTTP destination.
    severity: ERROR
${REQUEST_SOURCES}
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: http.Get($URL)
              - pattern: http.Head($URL)
              - pattern: http.Post($URL, ...)
              - pattern: http.PostForm($URL, ...)
          - focus-metavariable: $URL
  - id: wakeio.go.path-request-input
    languages: [go]
    mode: taint
    message: Request input controls a filesystem path.
    severity: ERROR
${REQUEST_SOURCES}
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: os.Open($PATH)
              - pattern: os.OpenFile($PATH, ...)
              - pattern: os.ReadFile($PATH)
              - pattern: os.Create($PATH)
              - pattern: http.ServeFile($W, $REQ, $PATH)
          - focus-metavariable: $PATH
`;
