import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { readFile, mkdir } from 'node:fs/promises';
const { captureProcess } = await import(pathToFileURL(resolve('scripts/qa/roadmap-cases/process.mjs')).href);
const { writeArtifact } = await import(pathToFileURL(resolve('scripts/qa/roadmap-cases/artifacts.mjs')).href);
const out = resolve(process.env.QA_EVIDENCE_OUT
  ?? '.omo/evidence/release-gates-kpi-roadmap/a49da4ceebc2c7dd24020ecbce420f46d0ca7625/t03-20261103-0528/t03');
await mkdir(out, { recursive: true });

const mode = process.argv[2];
const commands = mode === 'build' ? [
  ['npm', ['run', 'build'], 0, 'final-build'],
  [process.execPath, ['--test', 'build/tests/roadmap-qa.test.js'], 0, 'final-qa-tests'],
  [process.execPath, ['--test', 'build/tests/process-supervision.test.js', 'build/tests/report.test.js'], 0, 'final-neighbor-tests'],
] : mode === 'restored' ? [
  [process.execPath, ['--test', 'build/tests/roadmap-qa.test.js'], 0, 'restored-qa-tests'],
] : mode === 'audit' ? [
  ['bun', ['run', '/Applications/OmO.app/Contents/Resources/omo-runtime/darwin-arm64/plugin/skills/programming/scripts/typescript/check-test-junk.ts',
    'tests/roadmap-qa.test.ts'], 0, 'test-junk-audit'],
  ['bun', ['run', '/Applications/OmO.app/Contents/Resources/omo-runtime/darwin-arm64/plugin/skills/programming/scripts/typescript/check-no-excuse-rules.ts',
    'scripts/qa/roadmap.mjs', 'scripts/qa/roadmap-cases/artifacts.mjs', 'scripts/qa/roadmap-cases/process.mjs',
    'scripts/qa/roadmap-cases/harness.mjs', 'tests/roadmap-qa.test.ts'], 0, 'source-style-audit'],
] : mode === 'syntax' ? [
  ...['scripts/qa/roadmap.mjs', 'scripts/qa/roadmap-cases/artifacts.mjs', 'scripts/qa/roadmap-cases/process.mjs',
    'scripts/qa/roadmap-cases/harness.mjs'].map((path, index) => [process.execPath, ['--check', path], 0, 'syntax-' + index]),
  ['bun', ['run', '/Applications/OmO.app/Contents/Resources/omo-runtime/darwin-arm64/plugin/skills/programming/scripts/typescript/check-test-junk.ts',
    'tests/roadmap-qa.test.ts'], 0, 'test-junk-audit'],
] : mode === 'mutation' ? [
  [process.execPath, ['--test', 'build/tests/roadmap-qa.test.js'], 1, process.argv[3]],
] : [
  ...[
    ['happy', null, 0], ['abort', 'child-abort', 2], ['truncated', 'truncated-output', 1],
    ['failed-child', 'child-fail', 1], ['output-limit', 'output-limit', 2],
    ['handler-error', 'handler-error', 2], ['long-child', 'long-child', 2],
    ['incomplete-cleanup', 'incomplete-cleanup', 2], ['unsupported-mutation', 'unknown', 2],
  ].map(([name, mutation, expected]) => [process.execPath, ['scripts/qa/roadmap.mjs', '--case', 'harness',
    '--out', join(out, name), ...(mutation ? ['--mutate', mutation] : [])], expected, 'command-' + name]),
  ...['unknown', 'policy', 'manifest'].map(name => [process.execPath,
    ['scripts/qa/roadmap.mjs', '--case', name, '--out', join(out, name)], 2, 'command-' + name]),
  [process.execPath, ['scripts/qa/roadmap.mjs', '--case', 'harness', '--out', join(out, 'malformed'),
    '--case', 'harness'], 2, 'command-malformed'],
  [process.execPath, ['scripts/qa/roadmap.mjs', '--case', 'harness', '--out', join(out, 'happy')], 2, 'command-stale-output'],
];
let failed = false;
for (const [command, args, expected, name] of commands) {
  const result = await captureProcess(command, args, { timeoutMs: 120000, maxOutputBytes: 2 * 1024 * 1024 });
  await writeArtifact(out, name + '.json', { ...result, expectedExitCode: expected });
  const matched = result.exitCode === expected && result.cleanup.confirmed && !result.reason && !result.truncated;
  console.log(JSON.stringify({ name, exitCode: result.exitCode, expected, cleanup: result.cleanup.confirmed, matched }));
  failed ||= !matched;
  if (mode === 'build' && !matched) break;
  if (mode === 'mutation') {
    console.log(result.stdout);
    console.log(result.stderr);
  }
}
if (mode === 'concurrency') {
  const results = await Promise.all(['parallel-a', 'parallel-b', 'parallel-c'].map(async name => {
    const result = await captureProcess(process.execPath, ['scripts/qa/roadmap.mjs', '--case', 'harness',
      '--out', join(out, name)], { timeoutMs: 15000 });
    await writeArtifact(out, 'command-' + name + '.json', result);
    return { name, exitCode: result.exitCode, cleanup: result.cleanup.confirmed };
  }));
  await writeArtifact(out, 'concurrency.json', { results });
  failed ||= results.some(result => result.exitCode !== 0 || !result.cleanup);
  console.log(JSON.stringify({ concurrent: results, matched: !failed }));
}
if (![ 'build', 'mutation', 'restored', 'audit', 'syntax' ].includes(mode)) {
  const before = await readFile(join(out, 'happy', 'result.json'));
  const receipt = JSON.parse(before);
  console.log(JSON.stringify({ happyRetained: receipt.status === 'pass', sourceSha256: receipt.source.sha256 }));
}
process.exitCode = failed ? 1 : 0;
