import { resolve } from 'node:path';
import { mkdir } from 'node:fs/promises';
import { captureProcess } from '../../../../../scripts/qa/roadmap-cases/process.mjs';
import { writeArtifact } from '../../../../../scripts/qa/roadmap-cases/artifacts.mjs';
const out = resolve(process.env.QA_REPAIR_OUT
  ?? '.omo/evidence/release-gates-kpi-roadmap/a02ef2abd9d450cdb63eaaa0a9a7b58b9349204c/t03-json-repair-01');
await mkdir(out, { recursive: true });
const mode = process.argv[2];
const steps = mode === 'before' ? [
  ['npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], 0, 'prepare'],
  ['npm', ['run', 'build'], 0, 'before-build'],
  [process.execPath, ['--test', '--test-name-pattern=JSON credential',
    'build/tests/report.test.js', 'build/tests/roadmap-qa.test.js'], 1, 'before-regressions'],
] : [
  ['npm', ['run', 'build'], 0, 'after-build'],
  [process.execPath, ['--test', 'build/tests/report.test.js', 'build/tests/agent-report.test.js',
    'build/tests/parser-boundaries.test.js', 'build/tests/roadmap-qa.test.js'], 0, 'after-covering-tests'],
  ['bun', ['run', '/Applications/OmO.app/Contents/Resources/omo-runtime/darwin-arm64/plugin/skills/programming/scripts/typescript/check-test-junk.ts',
    'tests/report.test.ts', 'tests/roadmap-qa.test.ts'], 0, 'test-junk'],
];
let failed = false;
for (const [command, args, expectedExitCode, name] of steps) {
  const result = await captureProcess(command, args, { timeoutMs: 180000, maxOutputBytes: 2 * 1024 * 1024 });
  await writeArtifact(out, name + '.json', { ...result, expectedExitCode });
  const matched = result.exitCode === expectedExitCode && !result.reason && !result.truncated && result.cleanup.confirmed;
  console.log(JSON.stringify({ name, exitCode: result.exitCode, expectedExitCode, matched }));
  if (name === 'before-regressions') console.log(result.stdout);
  if (!matched) { failed = true; break; }
}
process.exitCode = failed ? 1 : 0;
