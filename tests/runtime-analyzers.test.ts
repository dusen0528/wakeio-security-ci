import test from 'node:test';
import assert from 'node:assert/strict';
import { ANALYZERS, SYNC_ANALYZERS, CODE_ANALYZERS, codeAnalyzer, isSourceTool,
  sourceAnalyzer, toolAnalyzer } from '../src/runtime/analyzer-registry.js';
import { CODE_PROVIDERS_V1, LEGACY_CODE_PROVIDERS_V1 } from '../src/source/code-coverage.js';
import type { SourceSnapshot } from '../src/source/types.js';
import { runSource } from '../src/source.js';
import { resolve } from 'node:path';

test('code analyzer metadata matches the fixed v1 provider order, IDs and language support', () => {
  assert.deepEqual(LEGACY_CODE_PROVIDERS_V1, ['builtin_ast', 'bandit', 'opengrep_native']);
  assert.deepEqual(CODE_PROVIDERS_V1, ['builtin_ast', 'bandit', 'opengrep_native', 'semgrep']);
  assert.deepEqual(CODE_ANALYZERS.map(p => p.id), CODE_PROVIDERS_V1);
  assert.deepEqual(CODE_ANALYZERS.map(p => [p.checkId, p.codeCoverage.languages]), [
    ['source.builtin-ast', ['javascript', 'typescript']], ['source.bandit', ['python']],
    ['source.opengrep.preview', ['javascript', 'typescript', 'python']], ['source.semgrep', ['go']],
  ]);
  assert.equal(new Set(CODE_ANALYZERS.map(p => p.id)).size, CODE_ANALYZERS.length);
  assert.ok(Object.isFrozen(CODE_ANALYZERS));
  for (const provider of CODE_ANALYZERS) {
    assert.ok(Object.isFrozen(provider));
    assert.ok(Object.isFrozen(provider.codeCoverage));
    assert.ok(Object.isFrozen(provider.codeCoverage.languages));
  }
  assert.throws(() => codeAnalyzer('unregistered' as never), /invalid_code_provider/);
});

test('source analyzer registration fixes the trusted ten adapters and rejects unknown selections', () => {
  assert.deepEqual(ANALYZERS.map(p => p.id), ['builtin_ast', 'framework', 'opengrep_native',
    'gitleaks', 'osv', 'trivy', 'bandit', 'semgrep', 'govulncheck', 'trivy-vuln']);
  assert.deepEqual(SYNC_ANALYZERS.map(p => p.id), ['builtin_ast', 'framework']);
  assert.equal(new Set(ANALYZERS.map(p => p.id)).size, 10);
  assert.equal(isSourceTool('framework'), false);
  assert.equal(isSourceTool('unregistered'), false);
  assert.throws(() => sourceAnalyzer('unregistered'), /invalid_source_analyzer/);
  assert.throws(() => toolAnalyzer('framework' as never), /invalid_source_tool/);
  const snapshot: SourceSnapshot = { root: '/source', files: [], issues: [], ignoredFiles: 0,
    totalBytes: 0, complete: true };
  for (const analyzer of ANALYZERS.filter(p => isSourceTool(p.id))) {
    assert.ok(Object.isFrozen(analyzer));
    if (analyzer.stage && analyzer.stage !== 'shared') {
      assert.ok(analyzer.stageFailure?.trim());
      assert.ok(analyzer.failureMessage?.trim());
    }
    const result = toolAnalyzer(analyzer.id as never).notApplicable(snapshot);
    assert.equal(result.id, analyzer.checkId);
    assert.equal(result.status, 'not_applicable');
  }
});

test('source dispatch preserves synchronous phases, explicit native selection and requested tool order', async () => {
  const root = resolve('tests/fixtures/compat-0.5/pass/source');
  const missing = resolve('tests/fixtures/runtime-analyzers-intentionally-missing');
  const tools = ['semgrep', 'bandit', 'gitleaks'] as const;
  const checks = await runSource({ root, tools: [...tools], toolPaths: Object.fromEntries(
    tools.map(tool => [tool, `${missing}/${tool}`])), nativePreview: { executable: `${missing}/opengrep-core` } });
  assert.deepEqual(checks.map(check => check.id), ['source.inventory', 'source.builtin-ast', 'source.framework',
    'source.opengrep.preview', 'source.semgrep', 'source.bandit', 'source.gitleaks', 'source.code-coverage']);
  assert.equal(checks[0].metrics?.requestedTools, tools.join(','));
  const nativeOnly = await runSource({ root, tools: [], nativePreview: { executable: `${missing}/opengrep-core` } });
  assert.equal(nativeOnly[0].metrics?.requestedTools, 'none');
  assert.deepEqual(nativeOnly.map(check => check.id), ['source.inventory', 'source.builtin-ast', 'source.framework',
    'source.opengrep.preview', 'source.code-coverage']);
});

test('code analyzer selection and admitted inputs retain provider-specific boundaries', () => {
  const snapshot: SourceSnapshot = {
    root: '/source', files: ['app.ts', 'app.py', 'app.go', 'config.json'].map(path => ({
      path, category: path.endsWith('.json') ? 'config' : 'code', text: '', bytes: 0, sensitive: false,
    })), issues: [], ignoredFiles: 0, totalBytes: 0, complete: true,
  };
  assert.deepEqual(CODE_ANALYZERS.map(p => p.selected({ tools: [], nativePreview: false })),
    [true, false, false, false]);
  const options = { tools: ['bandit', 'semgrep'] as const, nativePreview: true };
  assert.deepEqual(CODE_ANALYZERS.map(p => p.selected({ ...options, tools: [...options.tools] })),
    [true, true, true, true]);
  assert.deepEqual(CODE_ANALYZERS.map(p => p.codeCoverage.inputs(snapshot).map(f => f.path)),
    [['app.ts'], ['app.py'], ['app.ts', 'app.py'], ['app.go']]);
  assert.deepEqual(CODE_ANALYZERS.map(p => p.applicable({ ...snapshot, files: [] })),
    [false, false, false, false]);
});
