import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS } from '../src/source/modules.js';
import type { SourceSnapshot } from '../src/source/types.js';
import { createReport, evaluateGate } from '../src/report.js';

test('configured fallback independent: input beyond deferred snapshot cap remains unknown input in caller', () => {
  for (const traceSteps of [16, 24]) {
    const args = [...Array(traceSteps).fill('0'), 'req.query.code'].join(', ');
    const texts = {
      'app.ts': `import { search } from '@/search'; export function route(req) { const result = search(${args}); eval(result); }`,
      'src/search.ts': "export function search(...values) { return 'fixed'; }",
      'tsconfig.json': '{"compilerOptions":{"paths":{"@/*":["./src/*"]}}}',
    };
    const files = Object.entries(texts).map(([path, text]) => ({ path, text,
      bytes: Buffer.byteLength(text), sensitive: false,
      category: path.endsWith('.json') ? 'config' as const : 'code' as const }));
    const snapshot: SourceSnapshot = { root: '/owned-inert-configured-fallback', files, issues: [],
      complete: true, ignoredFiles: 0, totalBytes: files.reduce((n, f) => n + f.bytes, 0) };
    const check = runBuiltinAst(snapshot, false, { ...FLOW_LIMITS, traceSteps });
    const rows = check.findings.filter(f => f.ruleId === 'ast:dynamic-code' && f.location.path === 'app.ts');
    assert.equal(rows.length, 1, `input argument ${traceSteps + 1} cannot disappear behind a deferred body cap`);
    assert.equal(rows[0].kind, 'candidate');
    assert.equal(rows[0].confidence, 'low');
    assert.equal(rows[0].staticContext?.authority, 'conditional');
    assert.ok(rows[0].staticFlow?.steps.some(s => s.role === 'source' && s.location.path === 'app.ts'));
    assert.equal(evaluateGate(createReport([check], 'source', new Date(0)), 'none').exitCode, 2);
  }
});
