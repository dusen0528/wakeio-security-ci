import test from 'node:test';
import assert from 'node:assert/strict';
import { parseGitleaksOutput, parseOsvOutput, parseTrivyOutput } from '../src/source/parsers.js';
import { createReport, exitCode, toSarif } from '../src/report.js';
import type { CollectedFile } from '../src/source/types.js';

const files: CollectedFile[] = [{path:'package-lock.json',bytes:2,text:'{}',category:'dependency',sensitive:false},{path:'Dockerfile',bytes:10,text:'FROM base',category:'config',sensitive:false}];

test('review: malformed native scanner output is rejected, never normalized to zero findings', () => {
  for (const raw of ['{}', '{"unexpected":[]}', '[null]', '{"results":false}', 'null']) {
    for (const parser of [parseGitleaksOutput, parseOsvOutput, parseTrivyOutput]) {
      assert.throws(() => parser(raw, '/scan', files), `${parser.name} accepted ${raw}`);
    }
  }
});

test('review: OSV cannot mark an expected lockfile checked with no valid package inventory', () => {
  for (const raw of [
    '{"results":[]}',
    '{"results":[{"source":{"path":"package-lock.json","type":"lockfile"},"packages":[null]}]}',
    '{"results":[{"source":{"path":"package-lock.json","type":"lockfile"},"packages":[{}]}]}'
  ]) assert.throws(() => parseOsvOutput(raw, '/scan', files));
});

test('review: Trivy non-failures are not vulnerabilities and unsupported result states are rejected', () => {
  const row = { ID:'DS-0002',Title:'Container user',Severity:'HIGH',Resolution:'Set USER',CauseMetadata:{StartLine:2} };
  const envelope = (statuses:string[], version=2) => JSON.stringify({SchemaVersion:version,Results:[{Target:'Dockerfile',Class:'config',Type:'dockerfile',MisconfSummary:{Successes:1,Failures:1},Misconfigurations:statuses.map(Status=>({...row,Status}))}]});
  const result=parseTrivyOutput(envelope(['PASS','FAIL']), '/scan', files);
  assert.equal(result.findings.length,1);
  assert.throws(()=>parseTrivyOutput(envelope(['EXCEPTION']), '/scan', files));
  assert.throws(()=>parseTrivyOutput(envelope(['FAIL'],999), '/scan', files));
});

test('review: each affected dependency remains identifiable and gets a distinct SARIF fingerprint', () => {
  const packages = ['first-package', 'second-package'].map(name => ({
    package:{name,version:'1.0.0',ecosystem:'npm'},
    vulnerabilities:[{id:'GHSA-test-example-demo',database_specific:{severity:'HIGH'},references:[{type:'ADVISORY',url:'https://osv.dev/vulnerability/GHSA-test-example-demo'}]}],
    groups:[{ids:['GHSA-test-example-demo'],max_severity:'8.1'}]
  }));
  const parsed = parseOsvOutput(JSON.stringify({results:[{source:{path:'/scan/package-lock.json',type:'lockfile'},packages}]}), '/scan', files);
  assert.equal(parsed.findings.length, 2);
  assert.ok(parsed.findings.every(f=>f.severity==='high'));
  assert.ok(JSON.stringify(parsed.findings[0]).includes('first-package'));
  assert.ok(JSON.stringify(parsed.findings[1]).includes('second-package'));
  const sarif = toSarif(createReport([{id:'osv',status:'completed',...parsed}], 'source', new Date().toISOString()));
  const results = sarif.runs[0].results;
  assert.notDeepEqual(results[0].fingerprints, results[1].fingerprints);
});

test('review: no checks and all-not-applicable checks are not successful security scans', () => {
  assert.equal(exitCode(createReport([], 'source', new Date()), 'none'), 2);
  assert.equal(exitCode(createReport([{id:'none',status:'not_applicable',findings:[],notes:[]}], 'source', new Date()), 'none'), 2);
});

test('review: complete quoted credentials are removed and special filename characters survive SARIF URI encoding', () => {
  const report = createReport([{id:'fixture',status:'completed',notes:['password="multi word SYNTHETIC_VALUE_TO_REMOVE"'],findings:[{
    ruleId:'fixture.path',severity:'high',kind:'candidate',confidence:'low',title:'Path fixture',description:'A test observation',location:{path:'src/special # name%.ts',line:2},remediation:'Review'
  }]}], 'source', new Date());
  assert.ok(!JSON.stringify(report).includes('SYNTHETIC_VALUE_TO_REMOVE'));
  const sarif=toSarif(report);
  const uri=sarif.runs[0].results[0].locations?.[0].physicalLocation?.artifactLocation?.uri;
  assert.equal(decodeURIComponent(uri ?? ''), 'src/special # name%.ts');
  assert.ok(!uri?.includes('#'));
});
