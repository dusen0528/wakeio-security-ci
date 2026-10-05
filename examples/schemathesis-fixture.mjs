// Synthetic only: no target URL, external schema or real credentials accepted.
import { localArtifactStorage, pythonFixtureWorker, runSchemathesisFixture } from '../build/src/index.js';
const controller = new AbortController();
process.once('SIGINT', () => controller.abort());
const result = await runSchemathesisFixture({
  environment: 'staging', fixture: process.argv[2] === 'fixed' ? 'fixed' : 'broken',
  operations: ['readItems'], maxRequests: 5, timeoutMs: 30000, seed: 1,
  signal: controller.signal,
  worker: pythonFixtureWorker(process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? 'python3'),
  storage: localArtifactStorage('artifacts/schemathesis'),
});
const failures = (result.artifact.records ?? []).filter(r => r.check !== 'passed').length;
console.log(JSON.stringify({ status: result.artifact.status, failures, artifactRef: result.artifactRef, sha256: result.sha256 }));
process.exitCode = result.artifact.status !== 'completed' ? 2 : failures ? 1 : 0;
