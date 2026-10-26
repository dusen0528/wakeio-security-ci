import { createHash } from 'node:crypto';

// Frozen from 7a4ada160963fd6e9e0b700bf4ed638a0043a1ac scripts/kpi.mjs.
// Original module SHA256: 3bd5279ac418a73c5ea6859cc32d5185186af8ea15e5a655c1bfccbc8335d514.
// Do not import the candidate engine's hash implementation for this comparison.
function stable(value: unknown): unknown {
  return Array.isArray(value) ? value.map(stable) : value && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(key =>
      [key, stable((value as Record<string, unknown>)[key])])) : value;
}

export function runtimeM0SemanticHash(report: unknown): string {
  const { startedAt, finishedAt, ...content } = report as Record<string, unknown>;
  return createHash('sha256').update(JSON.stringify(stable(content))).digest('hex');
}
