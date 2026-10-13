import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import type { SourceSnapshot } from '../src/source/types.js';
import { createReport, evaluateGate } from '../src/report.js';

function scan(texts: Record<string, string>) {
  const files = Object.entries(texts).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false }));
  const snapshot: SourceSnapshot = { root: '/never-execute-dispatch-source', files, issues: [], complete: true, ignoredFiles: 0, totalBytes: files.reduce((sum, file) => sum + file.bytes, 0) };
  return runBuiltinAst(snapshot, false);
}

test('erased type imports permit only a unique immutable actual local function', () => {
  const completed = scan({ 'app.ts': "import type {spawn} from 'child_process'; function spawn(value){return value;} export function route(req){spawn(req.query.argument);}" });
  assert.equal(completed.status, 'completed'); assert.equal(completed.findings.length, 0);
  for (const declarations of [
    "import {spawn} from 'unrelated'; function spawn(value){return value;}",
    "import type {spawn} from 'child_process'; function spawn(value){return value;} function spawn(other){return other;}",
    "import type {spawn} from 'child_process'; function spawn(value){return value;} spawn=replacement;",
  ]) {
    const result = scan({ 'app.ts': declarations + ' export function route(req){spawn(req.query.argument);}' });
    assert.ok(result.status === 'partial' || result.findings.some(finding => finding.ruleId === 'ast:shell-input-sink'), 'conflicting runtime binding was incorrectly certified as completed local dispatch');
  }
});

test('named canonical CommonJS function self declaration preserves actual inner sink evidence', () => {
  const check = scan({
    'app.ts': "const execute=require('./helper'); export function route(req){execute(req.query.command);}",
    'helper.js': "const {exec:launch}=require('node:child_process'); module.exports=function execute(value){launch(value);};",
  });
  assert.equal(check.status, 'completed');
  const process = check.findings.filter(finding => finding.ruleId === 'ast:shell-input-sink');
  assert.equal(process.length, 1); assert.equal(process[0].confidence, 'medium');
  assert.equal(check.findings.some(finding => finding.ruleId === 'ast:sql-input-sink'), false, 'canonical local execute name became a spurious SQL call');
  assert.equal(process[0].location.path, 'helper.js');
  assert.ok(process[0].staticFlow?.steps.some(step => step.role === 'source' && step.location.path === 'app.ts'));
});

test('named CommonJS self recursion remains incomplete rather than suppressing inner process coverage', () => {
  const check = scan({
    'app.ts': "const execute=require('./helper'); export function route(req){execute(req.query.command);}",
    'helper.js': "const {exec:launch}=require('node:child_process'); module.exports=function execute(value){execute(value);launch(value);};",
  });
  assert.equal(check.status, 'partial');
  assert.equal(evaluateGate(createReport([check], 'source', '2026-10-13T00:00:00.000Z'), 'none').exitCode, 2);
});
