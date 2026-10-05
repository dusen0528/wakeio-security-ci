// Replay only safe synthetic quantity inputs; caller data cannot choose a URL or executable.
import { readFile } from 'node:fs/promises';
import { localArtifactStorage, pythonFixtureWorker, runSchemathesisFixture } from '../build/src/index.js';
const artifact = JSON.parse(await readFile(process.argv[2], 'utf8'));
if (artifact.scope !== 'synthetic-wsgi-only' || artifact.replay?.workerProtocol !== 1 ||
    !Array.isArray(artifact.records) || artifact.records.length < 1) throw Error('invalid fixture artifact');
const job = artifact.replay.job;
const result = await runSchemathesisFixture({
  environment: job.environment, fixture: job.fixture, operations: job.operations,
  timeoutMs: job.timeoutMs, seed: job.seed, maxBodyBytes: job.maxBodyBytes, maxTotalBytes: job.maxTotalBytes,
  maxRequests: artifact.records.length, replayQuantities: artifact.records.map(r => r.input.quantity),
  worker: pythonFixtureWorker(process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? 'python3'),
  storage: localArtifactStorage('artifacts/schemathesis'),
});
// Hashes are provenance hints, not attestations. Refuse to claim equivalent replay under changed fixture inputs.
const sameImplementation = ['schemaSha256', 'workerSha256', 'dependencyLockSha256', 'engineVersion']
  .every(k => result.artifact[k] === artifact[k]) &&
  JSON.stringify(result.artifact.runtime) === JSON.stringify(artifact.runtime);
const sameRecords = JSON.stringify(result.artifact.records) === JSON.stringify(artifact.records);
console.log(JSON.stringify({ status: result.artifact.status, sameImplementation, sameRecords, artifactRef: result.artifactRef }));
process.exitCode = result.artifact.status === 'completed' && sameImplementation && sameRecords ? 0 : 2;
