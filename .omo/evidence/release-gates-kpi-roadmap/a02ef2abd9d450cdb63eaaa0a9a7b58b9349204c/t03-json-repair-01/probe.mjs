import { randomUUID } from 'node:crypto';
import { resolve, join } from 'node:path';
import { readFile, mkdir } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
const { captureProcess } = await import(pathToFileURL(resolve('scripts/qa/roadmap-cases/process.mjs')).href);
const { redactArtifact, writeArtifact } = await import(pathToFileURL(resolve('scripts/qa/roadmap-cases/artifacts.mjs')).href);
const { sourceSnapshot } = await import(pathToFileURL(resolve('scripts/ci-process.mjs')).href);
const out = resolve(process.env.QA_REPAIR_OUT
  ?? '.omo/evidence/release-gates-kpi-roadmap/a02ef2abd9d450cdb63eaaa0a9a7b58b9349204c/t03-json-repair-01');
await mkdir(out, { recursive: true });
const phase = process.argv[2];
if (!['before', 'after'].includes(phase)) throw new TypeError('invalid_probe_phase');
const exact = await captureProcess(process.execPath, [
  '.omo/evidence/release-gates-kpi-roadmap/a02ef2abd9d450cdb63eaaa0a9a7b58b9349204c/t03-independent/api-probes.mjs', out,
]);
const exactResults = JSON.parse(exact.stdout);
await writeArtifact(out, phase + '-independent.json', { ...exact, parsed: exactResults });

// Canary values exist in memory and the child environment, never command argv.
const secret = randomUUID();
process.env.T3_JSON_CANARY = secret;
const script = 'console.log(JSON.stringify({password:process.env.T3_JSON_CANARY}));'
  + 'console.error(JSON.stringify({token:process.env.T3_JSON_CANARY}))';
let captured;
try { captured = await captureProcess(process.execPath, ['-e', script]); }
finally { delete process.env.T3_JSON_CANARY; }
const serialized = JSON.stringify(redactArtifact(captured));
const flags = {
  stdoutRawCanaryRetained: captured.stdout.includes(secret),
  stderrRawCanaryRetained: captured.stderr.includes(secret),
  serializedArtifactRawCanaryRetained: serialized.includes(secret),
};
// Never write an unsafe serialized capture, including on the failing base.
let persistedArtifactRawCanaryRetained = null;
if (!Object.values(flags).some(Boolean)) {
  const name = await writeArtifact(out, phase + '-safe-capture.json', captured);
  persistedArtifactRawCanaryRetained = (await readFile(join(out, name), 'utf8')).includes(secret);
}
await writeArtifact(out, phase + '-json-probe.json', { flags, persistedArtifactRawCanaryRetained,
  childExitCode: captured.exitCode, childCleanup: captured.cleanup, source: sourceSnapshot(process.cwd()),
  expected: 'all_retention_flags_false', unsafeCapturePersisted: false });
const independentStructured = exactResults.results.find(item => item.trigger === 'structured-stdout-stderr-redaction');
const success = captured.exitCode === 0 && captured.cleanup.confirmed && exact.exitCode === 0
  && !Object.values(flags).some(Boolean) && persistedArtifactRawCanaryRetained === false
  && independentStructured.stdoutRawCanaryRetained === false
  && independentStructured.stderrRawCanaryRetained === false
  && independentStructured.afterArtifactRedactionRawCanaryRetained === false;
console.log(JSON.stringify({ phase, ...flags, persistedArtifactRawCanaryRetained, success }));
process.exitCode = success ? 0 : 1;
