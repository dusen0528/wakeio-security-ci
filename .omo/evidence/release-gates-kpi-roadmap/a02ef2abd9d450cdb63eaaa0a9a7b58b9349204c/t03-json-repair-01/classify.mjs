import { randomUUID } from 'node:crypto';
import { redactSecrets } from '../../../../../src/report-path.ts';
import { writeArtifact } from '../../../../../scripts/qa/roadmap-cases/artifacts.mjs';
import { resolve } from 'node:path';
const out = resolve(process.env.QA_REPAIR_OUT
  ?? '.omo/evidence/release-gates-kpi-roadmap/a02ef2abd9d450cdb63eaaa0a9a7b58b9349204c/t03-json-repair-01');
const secret = randomUUID();
const rows = [
  ['literal-json', JSON.stringify({ password: secret, token: secret })],
  ['mixed-case-json', JSON.stringify({ PaSsWoRd: secret, API_KEY: secret })],
  ['nested-json-arrays', JSON.stringify({ entries: [{ inner: { session: secret, 'client-secret': secret } }] })],
  ['escaped-value-quotes-backslashes-newline', JSON.stringify({ password: `${secret}"\\\n${secret}` })],
  ['json-log-fragment', 'prefix ' + JSON.stringify({ token: secret }) + ' suffix'],
  ['single-quoted-text', `{'password':'${secret}'}`],
  ['original-quoted-assignment', `password="${secret} with spaces"`],
  ['original-bare-assignment', `token=${secret}`],
  ['original-bearer', `Authorization: Bearer ${secret}`],
];
const results = rows.map(([format, text]) => ({ format, rawCanaryRetained: redactSecrets(text).includes(secret) }));
await writeArtifact(out, 'classification.json', { results,
  unclaimed: ['unicode-escaped credential key spellings', 'multiply JSON-encoded documents',
    'non-string credential objects', 'arbitrary unlabelled values'],
  scope: 'existing_literal_credential_names_and_quoted_value_escaping' });
const success = results.every(result => !result.rawCanaryRetained);
console.log(JSON.stringify({ formats: results.length, allSupportedFlagsFalse: success }));
process.exitCode = success ? 0 : 1;
