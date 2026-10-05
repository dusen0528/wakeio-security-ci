import test from 'node:test';
import assert from 'node:assert/strict';
import * as ts from 'typescript';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runBuiltinAst } from '../src/source/ast.js';
import { findSnapshotInputFlows } from '../src/source/dataflow.js';
import { FLOW_LIMITS } from '../src/source/modules.js';
import { AnalysisGapRecorder, sanitiseAnalysisGaps } from '../src/analysis-gaps.js';
import { createReport, evaluateGate, sanitiseReport, toAgentReport, toMarkdown, toSarif, writeReports } from '../src/report.js';
import type { AnalysisGap, AnalysisGaps } from '../src/contracts.js';

const started = '2026-10-06T00:00:00.000Z';
const snapshot = (texts: Record<string, string>) => ({ root: '/never-read', files: Object.entries(texts).map(([path, text]) => ({ path, text, bytes: Buffer.byteLength(text), category: 'code' as const, sensitive: false })), issues: [], ignoredFiles: 0, totalBytes: Object.values(texts).reduce((n,t) => n + Buffer.byteLength(t),0), complete: true });
const gaps = (items: AnalysisGap[]): AnalysisGaps => ({ accounting: 'exact', items, eventsObserved: items.reduce((n,i) => n+i.observations,0), eventsDropped: 0, truncated: false });
const parse = (path: string, code=1003): AnalysisGap => ({ reason: 'parse_error', phase: 'parse', extent: 'site', observations: 1, location: { path, line: 1, column: 1 }, diagnosticCode: code, nextReview: 'review_parse_diagnostics' });

// Independent parser values establish coordinates, never target build/run semantics.
test('one representative per erroneous file uses minimum valid parser start/code and preserves valid membership', () => {
  const texts = { 'broken.ts': 'function {\nconst = ;\n}', 'unicode.ts': '// 😀\r\nconst x = ;', 'eof.ts': 'function end(', 'valid.ts': 'function route(req){db.query(req.query.sql)}' };
  const result = runBuiltinAst(snapshot(texts), false);
  assert.equal(result.metrics?.parseErrorCount, 3); assert.equal(result.metrics?.filesParsed, 4); assert.equal(result.metrics?.filesParseValid, 1); assert.equal(result.status, 'partial');
  assert.equal(result.findings.filter(f => f.ruleId === 'ast:sql-input-sink').length, 1);
  const items = result.analysisGaps!.items.filter(i => i.reason === 'parse_error');
  assert.equal(items.length,3); assert.equal(items.reduce((n,i)=>n+i.observations,0),3);
  for (const [path,text] of Object.entries(texts).slice(0,3)) {
    const file=ts.createSourceFile(path,text,ts.ScriptTarget.Latest,true);
    const diagnostics=(file as ts.SourceFile & {parseDiagnostics:readonly ts.Diagnostic[]}).parseDiagnostics;
    assert.ok(diagnostics.length>0);
    const expected=[...diagnostics].sort((a,b)=>a.start!-b.start! || a.code-b.code)[0];
    const pos=file.getLineAndCharacterOfPosition(expected.start!);
    const item=items.find(i=>i.location?.path===path)!;
    assert.deepEqual(item.location,{path,line:pos.line+1,column:pos.character+1}); assert.equal(item.diagnosticCode,expected.code);
    assert.equal(item.observations,1);
  }
  assert.ok((ts.createSourceFile('broken.ts',texts['broken.ts'],ts.ScriptTarget.Latest,true) as ts.SourceFile & {parseDiagnostics:ts.Diagnostic[]}).parseDiagnostics.length>1);
});

test('unsafe or protected producer paths remain exact check-wide observations without source/message disclosure', () => {
  const token='ghp_SYNTHETICPARSESECRET000000000';
  for (const path of ['/private/bad.ts','../bad.ts','a/../bad.ts','a\\bad.ts','file:bad.ts',`dir/${token}.ts`,'bad\u0001.ts']) {
    const result=runBuiltinAst(snapshot({[path]:'function { /* OWNED_RAW_PARSER_MARKER */'}),false);
    const gap=result.analysisGaps!.items.find(i=>i.reason==='parse_error')!;
    assert.equal(gap.extent,'check'); assert.equal(gap.location,undefined); assert.equal(gap.diagnosticCode,undefined); assert.equal(result.analysisGaps!.accounting,'exact'); assert.equal(result.analysisGaps!.eventsObserved,1);
    const report=createReport([result],'source',started);
    for(const value of [report,toAgentReport(report),toSarif(report),toMarkdown(report)]) {
      const out=typeof value==='string'?value:JSON.stringify(value);
      assert.equal(out.includes(path),false); assert.equal(out.includes(token),false); assert.equal(out.includes('OWNED_RAW_PARSER_MARKER'),false);
    }
  }
});

test('legacy count-only fallback and inconsistent representative inventory do not claim exact location accounting', () => {
  const legacy=findSnapshotInputFlows([],FLOW_LIMITS,2,false);
  assert.deepEqual(legacy.analysisGaps!.items,[{reason:'parse_error',phase:'parse',extent:'check',observations:2,nextReview:'review_parse_diagnostics'}]);
  for(const evidence of [[],[{},{}]]) {
    const result=findSnapshotInputFlows([],FLOW_LIMITS,1,false,evidence);
    assert.equal(result.analysisGaps!.accounting,'unknown'); assert.equal(result.analysisGaps!.eventsObserved,null);
  }
});

test('diagnosticCode is primitive positive integer only on parser sites and participates in dedup identity', () => {
  const good=parse('bad.ts');
  for(const diagnosticCode of [0,-1,1.5,Infinity,Number.MAX_SAFE_INTEGER+1,'1003',[1003]]) {
    const cleaned=sanitiseAnalysisGaps(gaps([{...good,diagnosticCode} as AnalysisGap]),p=>p)!;
    assert.equal(cleaned.accounting,'unknown'); assert.equal(cleaned.items.length,0);
  }
  for(const patch of [{phase:'flow'},{extent:'check',location:undefined},{reason:'module_missing',phase:'flow'}]) {
    assert.equal(sanitiseAnalysisGaps(gaps([{...good,...patch} as AnalysisGap]),p=>p)!.accounting,'unknown');
  }
  const recorder=new AnalysisGapRecorder(); recorder.record('parse_error','parse',good.location,1,1003); recorder.record('parse_error','parse',good.location,1,1005); recorder.record('parse_error','parse',good.location,1,1003);
  const out=recorder.result()!; assert.equal(out.items.length,2); assert.equal(out.items[0].observations,2);
  const sanitized=sanitiseAnalysisGaps(out,p=>p)!; out.items[0].location!.path='changed'; out.items[0].diagnosticCode=999;
  assert.equal(sanitized.items[0].location!.path,'bad.ts'); assert.equal(sanitized.items[0].diagnosticCode,1003); assert.deepEqual(sanitiseAnalysisGaps(sanitized,p=>p),sanitized);
});

test('new parser sites require a code; legacy check-wide count metadata remains exact', () => {
  const missing = { ...parse('missing.ts') }; delete missing.diagnosticCode;
  const cleaned = sanitiseAnalysisGaps(gaps([missing]), p => p)!;
  assert.equal(cleaned.accounting, 'unknown'); assert.equal(cleaned.items.length, 0);
  const recorder = new AnalysisGapRecorder(); recorder.record('parse_error', 'parse', missing.location);
  const recorded = recorder.result()!;
  assert.equal(recorded.accounting, 'unknown'); assert.equal(recorded.eventsObserved, null);
  assert.equal(recorded.items[0].extent, 'check'); assert.equal(recorded.items[0].location, undefined);
  assert.deepEqual(sanitiseAnalysisGaps(recorded, p => p), recorded);
  const legacy = new AnalysisGapRecorder(); legacy.record('parse_error', 'parse', undefined, 2);
  assert.equal(legacy.result()!.accounting, 'exact'); assert.equal(legacy.result()!.items[0].extent, 'check');
  assert.equal(legacy.result()!.eventsObserved, 2);
});

test('40 parser files retain 32 representatives and account eight dropped files; report cap remains idempotent', () => {
  const result=runBuiltinAst(snapshot(Object.fromEntries(Array.from({length:40},(_,i)=>[`bad-${i}.ts`,'function {\nconst = ;']))),false);
  assert.equal(result.metrics?.parseErrorCount,40); const gap=result.analysisGaps!;
  assert.equal(gap.accounting,'exact'); assert.equal(gap.eventsObserved,40); assert.equal(gap.eventsDropped,8); assert.equal(gap.items.length,32);
  assert.deepEqual(gap.reasonSummary?.rows,[{reason:'parse_error',eventsObserved:40,eventsDropped:8}]);
  const report=createReport(Array.from({length:9},(_,i)=>({...result,id:`parse-${i}`})),'source',started);
  assert.equal(report.checks.reduce((n,c)=>n+c.analysisGaps!.items.length,0),256); assert.equal(report.checks[8].analysisGaps!.eventsDropped,40);
  assert.deepEqual(sanitiseReport(sanitiseReport(report)),report); assert.equal(evaluateGate(report,'none').exitCode,2); assert.equal(toAgentReport(report).scanGate.exitCode,2);
});

test('nextRead selects an actual retained parse site after fallback, within the unchanged three-item summary bound', () => {
  const report=createReport([runBuiltinAst(snapshot({'../bad.ts':'function {','safe.ts':'function {'}),false)],'source',started);
  const agent=toAgentReport(report); assert.equal(agent.summary!.nextRead.kind,'review_parse_diagnostics'); assert.equal(agent.summary!.nextRead.location?.path,'safe.ts');
  const check={id:'owned',status:'partial' as const,findings:[],notes:[],analysisGaps:gaps([{reason:'parse_error' as const,phase:'parse' as const,extent:'check' as const,observations:1,nextReview:'review_parse_diagnostics' as const},parse('second.ts'),parse('third.ts'),parse('hidden.ts')])};
  const summary=toAgentReport(createReport([check],'source',started)).summary!;
  assert.equal(summary.incompleteChecks[0].analysisGaps!.representativeItems.length,3); assert.equal(summary.nextRead.location?.path,'second.ts');
});

test('four artifacts carry scanner parser coordinates/code, unchanged finding identity, and review-only guidance', async () => {
  const root=await mkdtemp(join(tmpdir(),'wakeio-parse-report-'));
  try {
    const text='function { /* OWNED_NEVER_OUTPUT */';
    const result=runBuiltinAst(snapshot({'dir/bad.ts':text,'safe.ts':'function route(req){db.query(req.query.sql)}'}),false);
    const report=createReport([result],'source',started); await writeReports(report,root,{failOn:'none'});
    const json=JSON.parse(await readFile(join(root,'report.json'),'utf8')); const agent=JSON.parse(await readFile(join(root,'agent-report.json'),'utf8')); const sarif=JSON.parse(await readFile(join(root,'report.sarif'),'utf8')); const md=await readFile(join(root,'report.md'),'utf8');
    const expected=json.checks[0].analysisGaps.items.find((i:AnalysisGap)=>i.reason==='parse_error');
    assert.deepEqual(agent.checks[0].analysisGaps.items.find((i:AnalysisGap)=>i.reason==='parse_error'),expected);
    assert.deepEqual(sarif.runs[0].properties.analysisGaps[0].analysisGaps.items.find((i:AnalysisGap)=>i.reason==='parse_error'),expected);
    assert.equal(agent.summary!.nextRead.location.path,'dir/bad.ts'); assert.ok(md.includes(`TS${expected.diagnosticCode}`)); assert.ok(md.includes('scanner parser representative per file'));
    assert.equal(json.checks[0].findings.length,1); assert.equal(sarif.runs[0].results.length,1); assert.equal(sarif.runs[0].results[0].ruleId,json.checks[0].findings[0].ruleId);
    for(const value of [json,agent,sarif,md]) assert.equal((typeof value==='string'?value:JSON.stringify(value)).includes('OWNED_NEVER_OUTPUT'),false);
  } finally {await rm(root,{recursive:true,force:true});}
});
