import { createHash } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { redactSecrets } from '../../../src/report-path.ts';

// Redact complete captures, not individual chunks: credentials can span chunks.
export function redactArtifact(value) {
  if (typeof value === 'string') return redactSecrets(value);
  if (Array.isArray(value)) return value.map(redactArtifact);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, redactArtifact(item)]));
  }
  return value;
}

export async function writeArtifact(out, name, value) {
  if (!/^[a-z][a-z0-9-]*\.json$/.test(name)) throw new TypeError('invalid_artifact_name');
  await writeFile(join(out, name), JSON.stringify(redactArtifact(value), null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return name;
}

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
