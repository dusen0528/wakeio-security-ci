import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { chmod, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { promisify } from 'node:util';

const exec = promisify(execFile);
const root = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const script = join(root, 'scripts', 'benchmark-oss.mjs');
const corpusPath = join(root, 'benchmarks', 'oss-corpus.json');
const benchmark = await import(pathToFileURL(script).href);

async function git(cwd: string, ...args: string[]): Promise<string> {
  const result = await exec('git', ['-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', ...args], { cwd, env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
  return result.stdout.trim();
}
function sha256(text: string): string { return createHash('sha256').update(text).digest('hex'); }
async function syntheticRepo() {
  const checkout = await realpath(await mkdtemp(join(tmpdir(), 'wakeio-oss-bench-')));
  await git(checkout, 'init', '-q');
  await writeFile(join(checkout, 'app.js'), 'alpha\nbeta\ngamma\n');
  await writeFile(join(checkout, 'safe.js'), 'safe\n');
  await git(checkout, 'add', '--all');
  await git(checkout, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'seed');
  const commit = await git(checkout, 'rev-parse', 'HEAD');
  const tree = await git(checkout, 'rev-parse', 'HEAD^{tree}');
  const repo = {
    id: 'synthetic', url: 'https://github.com/example/synthetic.git', license: 'test-only', commit, tree,
    fileSha256: { 'app.js': sha256('alpha\nbeta\ngamma\n'), 'safe.js': sha256('safe\n') },
    expectedFindings: [{ id: 'one-flow', ruleId: 'ast:dynamic-code', checkId: 'source.builtin-ast', path: 'app.js',
      requiredFindings: [1, 2, 3].map((line) => ({ line, column: 1, source: { path: 'app.js', line, column: 2 } })), support: 'supported',
      basis: 'Three fixed synthetic positions represent one complete flow.',
      sourceUrl: `https://github.com/example/synthetic/blob/${commit}/app.js#L1-L3` }],
    reviewedNegativeSites: [{ id: 'safe-site', path: 'safe.js', firstLine: 1, lastLine: 1,
      ruleIds: ['ast:dynamic-code'], support: 'supported', basis: 'Fixed safe control site for candidate overlap.',
      sourceUrl: `https://github.com/example/synthetic/blob/${commit}/safe.js#L1` }],
  };
  const corpus = { data: { schemaVersion: 'oss-corpus-v1', repositories: [repo] }, sha256: 'synthetic-test' };
  return { checkout, repo, corpus };
}
function candidate(path: string, line: number, column = 1, kind = 'candidate') {
  return { ruleId: 'ast:dynamic-code', kind, location: { path, line, column },
    staticFlow: { kind: 'static_flow', truncated: false, steps: [
      { role: 'source', location: { path, line, column: 2 } },
      { role: 'sink', location: { path, line, column } },
    ] } };
}
function checks(findings: object[] = [], astStatus = 'completed') {
  return [
    { id: 'source.inventory', status: 'completed', findings: [], notes: [], metrics: { complete: true } },
    { id: 'source.builtin-ast', status: astStatus, findings, notes: [], metrics: { indexComplete: astStatus === 'completed', parseErrorCount: 0 } },
    { id: 'source.framework', status: 'not_applicable', findings: [], notes: [] },
  ];
}
function snapshot(complete = true) {
  return { complete, files: [{ path: 'app.js' }, { path: 'safe.js' }], issues: complete ? [] : [{ code: 'file_limit', path: 'other.js' }], totalBytes: 23 };
}

test('locked corpus has seven whole-repository source flows and one grouped three-sink flow', async () => {
  const corpus = await benchmark.loadOssCorpus(corpusPath);
  assert.equal(corpus.data.repositories.length, 2);
  assert.equal(corpus.data.repositories.reduce((count: number, repo: { expectedFindings: unknown[] }) => count + repo.expectedFindings.length, 0), 7);
  const nodegoat = corpus.data.repositories.find((repo: { id: string }) => repo.id === 'nodegoat');
  assert.equal(nodegoat.expectedFindings.find((item: { id: string }) => item.id === 'nodegoat-contribution-eval').requiredFindings.length, 3);
  assert.equal(corpus.data.repositories.flatMap((repo: { expectedFindings: Array<{ support: string }> }) => repo.expectedFindings).filter((item: { support: string }) => item.support === 'known_unsupported').length, 2);
});

test('one-to-one grouped matching consumes all three sinks; unrelated candidate and observation stay unreviewed', async () => {
  const { checkout, repo, corpus } = await syntheticRepo();
  try {
    const observed = checks([candidate('app.js', 1), candidate('app.js', 2), candidate('app.js', 3), candidate('other.js', 4), candidate('app.js', 1, 1, 'observation')]);
    const result = await benchmark.measureOssCorpus(corpus, new Map([[repo.id, checkout]]), {
      runSource: async () => observed, collectSource: async () => snapshot(),
    });
    assert.equal(result.report.summary.declaredExpected, 1);
    assert.equal(result.report.summary.matched, 1);
    assert.equal(result.report.summary.partialMatch, 0);
    assert.equal(result.report.summary.unreviewedCandidates, 1);
    assert.equal(result.report.summary.unreviewedObservations, 1);
    assert.equal(result.report.summary.precision, null);
    assert.equal(result.report.summary.exitCode, 0);
  } finally { await rm(checkout, { recursive: true, force: true }); }
});

test('two of three grouped sinks are a partial match, not one detected flow or two extras', async () => {
  const { checkout, repo } = await syntheticRepo();
  try {
    const result = benchmark.evaluateOssRepository(repo, snapshot(), checks([candidate('app.js', 1), candidate('app.js', 3)]));
    assert.equal(result.counts.matched, 0);
    assert.equal(result.counts.partialMatch, 1);
    assert.equal(result.counts.unreviewedCandidates, 0);
    assert.deepEqual(result.expected[0].observed.map((site: { line: number }) => site.line), [1, 3]);
  } finally { await rm(checkout, { recursive: true, force: true }); }
});

test('sink-only candidate with a missing source trace remains unreviewed and is not a matched flow', async () => {
  const { checkout, repo } = await syntheticRepo();
  try {
    repo.expectedFindings[0].requiredFindings = [{ line: 1, column: 1, source: { path: 'app.js', line: 1, column: 2 } }];
    const sinkOnly = { ...candidate('app.js', 1), staticFlow: { kind: 'static_flow', truncated: true, steps: [] } };
    const result = benchmark.evaluateOssRepository(repo, snapshot(), checks([sinkOnly]));
    assert.equal(result.counts.matched, 0);
    assert.equal(result.counts.traceMismatch, 1);
    assert.equal(result.counts.unreviewedCandidates, 1);
    assert.equal(result.expected[0].scopeComplete, true);
  } finally { await rm(checkout, { recursive: true, force: true }); }
});

test('partial collector or AST preserves observed evidence but prevents complete recall or a clean gate', async () => {
  const { checkout, repo, corpus } = await syntheticRepo();
  try {
    const result = await benchmark.measureOssCorpus(corpus, new Map([[repo.id, checkout]]), {
      runSource: async () => checks([candidate('app.js', 1), candidate('app.js', 2), candidate('app.js', 3)], 'partial'),
      collectSource: async () => snapshot(false),
    });
    assert.equal(result.report.summary.matched, 1);
    assert.equal(result.report.summary.scanComplete, false);
    assert.equal(result.report.summary.supportedRecall, null);
    assert.equal(result.report.summary.exitCode, 2);
    assert.equal(result.report.repositories[0].negativeSites[0].status, 'unevaluable_scope');
  } finally { await rm(checkout, { recursive: true, force: true }); }
});

test('missing supported or known-unsupported expectation uses full declared denominator and exits one when scan complete', async () => {
  const { checkout, repo, corpus } = await syntheticRepo();
  try {
    let result = await benchmark.measureOssCorpus(corpus, new Map([[repo.id, checkout]]), {
      runSource: async () => checks(), collectSource: async () => snapshot(),
    });
    assert.equal(result.report.summary.missedEvaluable, 1);
    assert.equal(result.report.summary.declaredObservedFraction, 0);
    assert.equal(result.report.summary.exitCode, 1);
    repo.expectedFindings[0].support = 'known_unsupported';
    result = await benchmark.measureOssCorpus(corpus, new Map([[repo.id, checkout]]), {
      runSource: async () => checks([], 'partial'), collectSource: async () => snapshot(false),
    });
    assert.equal(result.report.summary.missingKnownUnsupported, 1);
    assert.equal(result.report.repositories[0].expected[0].coverageReason, 'collector_incomplete');
    assert.equal(result.report.summary.exitCode, 2);
    result = await benchmark.measureOssCorpus(corpus, new Map([[repo.id, checkout]]), {
      runSource: async () => checks(), collectSource: async () => snapshot(),
    });
    assert.equal(result.report.summary.missingKnownUnsupported, 1);
    assert.equal(result.report.summary.exitCode, 1);
  } finally { await rm(checkout, { recursive: true, force: true }); }
});

test('candidate on a reviewed negative site is not labelled a false positive without review', () => {
  const repo = { id: 'fake', commit: 'a'.repeat(40), tree: 'b'.repeat(40), expectedFindings: [],
    reviewedNegativeSites: [{ id: 'negative', path: 'safe.js', firstLine: 1, lastLine: 2, ruleIds: ['ast:dynamic-code'], support: 'supported' }] };
  const result = benchmark.evaluateOssRepository(repo, snapshot(), checks([candidate('safe.js', 1)]));
  assert.equal(result.counts.unreviewedCandidates, 1);
  assert.equal(result.counts.unexpectedAtReviewedSite, 1);
  assert.equal(result.negativeSites[0].status, 'unexpectedAtReviewedSite');
});

test('checkout verifier rejects tracked edits and ignored or untracked files, without running configured fsmonitor', async () => {
  const { checkout, repo } = await syntheticRepo();
  const marker = join(tmpdir(), `wakeio-oss-fsmonitor-${process.pid}-${Date.now()}`);
  const hook = join(tmpdir(), `wakeio-oss-fsmonitor-hook-${process.pid}-${Date.now()}.sh`);
  try {
    await writeFile(hook, `#!/bin/sh\nprintf touched > '${marker}'\n`);
    await chmod(hook, 0o755);
    await git(checkout, 'config', 'core.fsmonitor', hook);
    await benchmark.verifyCheckout(repo, checkout);
    await assert.rejects(readFile(marker), { code: 'ENOENT' });
    await writeFile(join(checkout, 'untracked.js'), 'extra\n');
    await assert.rejects(benchmark.verifyCheckout(repo, checkout), /checkout_dirty_or_sparse/);
    await rm(join(checkout, 'untracked.js'));
    await writeFile(join(checkout, 'app.js'), 'changed\n');
    await assert.rejects(benchmark.verifyCheckout(repo, checkout), /checkout_dirty_tracked_file/);
  } finally { await rm(checkout, { recursive: true, force: true }); await rm(hook, { force: true }); await rm(marker, { force: true }); }
});

test('missing promisor tree refuses locally without invoking a configured ext remote helper', async () => {
  const { checkout, repo } = await syntheticRepo();
  const marker = join(tmpdir(), `wakeio-oss-promisor-${process.pid}-${Date.now()}`);
  const helper = join(tmpdir(), `wakeio-oss-promisor-helper-${process.pid}-${Date.now()}.sh`);
  try {
    await writeFile(helper, `#!/bin/sh\nprintf touched > '${marker}'\nexit 1\n`);
    await chmod(helper, 0o755);
    await git(checkout, 'config', 'remote.origin.promisor', 'true');
    await git(checkout, 'config', 'extensions.partialClone', 'origin');
    await git(checkout, 'config', 'remote.origin.url', `ext::${helper}`);
    await git(checkout, 'config', 'protocol.ext.allow', 'always');
    await rm(join(checkout, '.git', 'objects', repo.tree.slice(0, 2), repo.tree.slice(2)));
    await assert.rejects(benchmark.verifyCheckout(repo, checkout), /checkout_git_probe_failed/);
    await assert.rejects(readFile(marker), { code: 'ENOENT' });
  } finally { await rm(checkout, { recursive: true, force: true }); await rm(helper, { force: true }); await rm(marker, { force: true }); }
});

test('real CLI exercises fresh output, standard reports, artifact digests and benchmark gate on an owned tiny checkout', async () => {
  const { checkout, repo, corpus } = await syntheticRepo();
  const parent = await realpath(await mkdtemp(join(tmpdir(), 'wakeio-oss-cli-')));
  try {
    repo.expectedFindings = [];
    const manifest = join(parent, 'manifest.json');
    const out = join(parent, 'result');
    await writeFile(manifest, JSON.stringify(corpus.data));
    const result = await exec(process.execPath, [script, '--manifest', manifest, '--checkout', `synthetic=${checkout}`, '--out', out], { cwd: root, maxBuffer: 2 * 1024 * 1024 });
    assert.match(result.stdout, /"exitCode": 0/);
    const report = JSON.parse(await readFile(join(out, 'oss-benchmark.json'), 'utf8'));
    assert.equal(report.summary.exitCode, 0);
    assert.equal(report.summary.scanComplete, true);
    assert.equal(report.repositories[0].scanExitCode, 0);
    assert.match(report.engineFingerprint.buildJsSha256, /^[0-9a-f]{64}$/);
    assert.match(report.engineFingerprint.typescriptEntrySha256, /^[0-9a-f]{64}$/);
    for (const [name, hash] of Object.entries(report.repositories[0].reportArtifacts)) {
      assert.equal(sha256(await readFile(join(out, 'synthetic', name), 'utf8')), hash);
    }
  } finally { await rm(checkout, { recursive: true, force: true }); await rm(parent, { recursive: true, force: true }); }
});

test('malformed finding location fails closed instead of silently disappearing from unmatched output', () => {
  const repo = { id: 'fake', commit: 'a'.repeat(40), tree: 'b'.repeat(40), expectedFindings: [], reviewedNegativeSites: [] };
  assert.throws(() => benchmark.evaluateOssRepository(repo, snapshot(), checks([{ ruleId: 'ast:dynamic-code', kind: 'candidate', location: {} }])), /scan_invalid_finding/);
});
