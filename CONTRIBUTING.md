# Contributing

Wakeio Security CI is a public Apache-2.0 project for bounded local source and
URL checks. It runs without a Wakeio account or hosted service, and its reports
describe the evidence available to the run. The GitHub Action is available as
the moving preview reference `dusen0528/wakeio-security-ci@main`; review and
pin a full commit SHA before production use. npm publication and Marketplace
release are still pending. A contribution should keep the evidence boundary
visible: a static candidate is not proof of exploitability, and a clean exit
code is not a whole-service security guarantee.

## Before opening a change

Use synthetic repositories, URLs, credentials, and personal data in tests and
examples. Do not commit real source, customer material, scanner output from a
real system, tokens, `.env` files, or private URLs. Reports can contain paths,
package identifiers, URLs, and tool messages even when finding values and
source snippets are redacted, so review fixtures and CI artifacts before
sharing them.

The report contract is part of the public interface:

- `candidate` means a pattern that needs human confirmation.
- `observation` means a property observed in the collected response or
  configuration.
- `advisory` means a scanner or public advisory database result.
- finding evidence must remain redacted; do not add raw secret values or
  source excerpts to JSON, SARIF, Markdown, logs, or snapshots.
- a partial, skipped, timed out, or failed check must remain distinguishable
  from a completed clean check.

If a change affects a finding, redaction, exit code, or report field, update
the relevant contract documentation and test the public output formats
together.

## Tests and reproducible cases

For a new detector or a detector fix, add a small vulnerable/fixed pair:

1. The vulnerable fixture contains one synthetic trigger and asserts the
   expected finding kind, rule ID, location, and severity.
2. The fixed fixture changes only the relevant safety property and asserts
   that the finding is absent or has the documented result.
3. Both fixtures assert that the serialized report contains no synthetic
   secret value or unredacted source excerpt.

Keep the pair minimal enough that a reviewer can identify why the result
changed. If a behavior is intentionally uncertain, assert the documented
`candidate`, `partial`, or `unknown` state instead of making the fixture look
clean.

Run the checks locally with Node.js 22 or newer:

```sh
npm ci --ignore-scripts
npm test
```

The release packaging check is local and does not publish anything:

```sh
npm run package:release
```

It writes versioned source and npm archives plus a versioned SHA-256 manifest
under `artifacts/`. Do not add those generated files to a pull request.

## Rules, data, and licensing

Give new rules stable IDs, a short rationale, a documented limitation, and a
test case. Prefer a narrow rule with an explicit uncertainty state over a
pattern that claims more than it can establish.

Do not copy a rule, pattern, allowlist, advisory dataset, test corpus, or
scanner configuration from an upstream project unless its license permits
redistribution in this repository. Preserve the required attribution and
record the source and license in `THIRD_PARTY_NOTICES.md`. If the license is
unclear, write an independent rule from the public behavior contract or ask
for clarification before contributing it.

## Pull requests

Describe the input boundary, the observable output, and the test evidence.
Call out changes to report fields, scanner versions, network behavior, or
redaction. Keep pull requests focused and do not include unrelated generated
reports or vendored dependencies.

For a suspected vulnerability in this project, follow
[SECURITY.md](SECURITY.md) and use the private GitHub Security Advisory form.
Public issues should contain only ordinary documentation, reproducible
non-sensitive bugs, or feature requests.
