import test from 'node:test';
import assert from 'node:assert/strict';
import { CODE_ANALYZERS, codeAnalyzer } from '../src/runtime/registry.js';
import { CODE_PROVIDERS_V1, LEGACY_CODE_PROVIDERS_V1 } from '../src/source/code-coverage.js';
import type { SourceSnapshot } from '../src/source/types.js';

test('code analyzer metadata matches the fixed v1 provider order, IDs and language support', () => {
  assert.deepEqual(LEGACY_CODE_PROVIDERS_V1, ['builtin_ast', 'bandit', 'opengrep_native']);
  assert.deepEqual(CODE_PROVIDERS_V1, ['builtin_ast', 'bandit', 'opengrep_native', 'semgrep']);
  assert.deepEqual(CODE_ANALYZERS.map(p => p.codeCoverage.publicId), CODE_PROVIDERS_V1);
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

test('code analyzer selection and admitted inputs retain provider-specific boundaries', () => {
  const snapshot: SourceSnapshot = {
    root: '/source', files: ['app.ts', 'app.py', 'app.go', 'config.json'].map(path => ({
      path, category: path.endsWith('.json') ? 'config' : 'code', text: '', bytes: 0, sensitive: false,
    })), issues: [], ignoredFiles: 0, totalBytes: 0, complete: true,
  };
  assert.deepEqual(CODE_ANALYZERS.map(p => p.selected({ root: snapshot.root, tools: [] })),
    [true, false, false, false]);
  const options = { root: snapshot.root, tools: ['bandit', 'semgrep'] as const,
    nativePreview: { executable: '/owned/core' } };
  assert.deepEqual(CODE_ANALYZERS.map(p => p.selected({ ...options, tools: [...options.tools] })),
    [true, true, true, true]);
  assert.deepEqual(CODE_ANALYZERS.map(p => p.codeCoverage.inputs(snapshot).map(f => f.path)),
    [['app.ts'], ['app.py'], ['app.ts', 'app.py'], ['app.go']]);
  assert.deepEqual(CODE_ANALYZERS.map(p => p.applicable({ ...snapshot, files: [] })),
    [false, false, false, false]);
});
