import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';

// Root executes the CLI only. Independently authored target files are DATA ONLY.
// Relative entry also resolves to the preserved pre-collection-fix compiled tree.
const CLI = fileURLToPath(new URL('../src/cli.js', import.meta.url));
const RULE = 'ast:archive-path-write', PRIVATE = 'owned-cjs-collection-private-7d02';
const CJS = "const unzipper=require('unzipper');\nconst fs=require('node:fs');\nconst path=require('node:path');\n";
const ESM = "import unzipper from 'unzipper';\nimport fs from 'node:fs';\nimport path from 'node:path';\n";
const extract = (headers: string, statements: string) => headers + 'async function extract(buffer){\n' +
  'const directory=await unzipper.Open.buffer(buffer);\nfor(const entry of directory.files){\n' + statements + '\n}\n}\n';
const RISK = "const filename=entry.path;\nfs.createWriteStream('owned/output/'+filename);";
const GUARD = "const root=path.resolve('owned/output');\nconst dest=path.resolve(root,entry.path);\nconst rel=path.relative(root,dest);\n" +
  "if(rel==='..'||rel.startsWith('..'+path.sep)||path.isAbsolute(rel)){throw new Error('outside');}\nfs.createWriteStream(dest);";
async function child(args: string[]) {
  return await new Promise<{code: number|null; stdout: string; stderr: string}>((resolve, reject) => {
    const p=spawn(process.execPath,[CLI,...args],{stdio:['ignore','pipe','pipe']}); let stdout='',stderr='';
    const timeout=setTimeout(()=>{p.kill('SIGKILL');reject(new Error('Owned CLI timeout'));},30_000);
    p.stdout.on('data',data=>{stdout+=String(data);}); p.stderr.on('data',data=>{stderr+=String(data);});
    p.once('error',error=>{clearTimeout(timeout);reject(error);});
    p.once('close',code=>{clearTimeout(timeout);resolve({code,stdout,stderr});});
  });
}
async function scan(t: TestContext, inputs: Record<string,string>, expected: {javascript:number;typescript:number}) {
  const top=await mkdtemp(join(tmpdir(),'wakeio-cjs-collection-')); t.after(()=>rm(top,{recursive:true,force:true}));
  const source=join(top,'source'),out=join(top,'reports'),executionMarker=join(top,'TARGET_EXECUTED'); await mkdir(source);
  const files: Record<string,string>={'package.json':JSON.stringify({private:true,dependencies:{unzipper:'^0.12.3'}})};
  for(const [name,text] of Object.entries(inputs)) {
    // If a .cjs target is imported, this owned marker is written before any external require.
    files[name]=(name.endsWith('.cjs') ? `require('node:fs').writeFileSync(${JSON.stringify(executionMarker)},'${PRIVATE}');\n` : '') +
      text+'\n// '+PRIVATE+'\n';
  }
  for(const [name,text] of Object.entries(files)) await writeFile(join(source,name),text);
  const result=await child(['scan','--source',source,'--tools','none','--require-code-analysis','--fail-on','none','--out',out]);
  assert.equal(result.code,2,'conditional archive evidence must preserve the incomplete process gate');
  const formats: Record<string,string>={};
  for(const name of ['report.json','agent-report.json','report.md','report.sarif']) {
    formats[name]=await readFile(join(out,name),'utf8');
    assert.equal(formats[name].includes(PRIVATE),false,name+': raw target marker leaked');
    assert.equal(formats[name].includes(executionMarker),false,name+': target source value leaked');
    for(const text of Object.values(inputs)) for(const line of text.split('\n').filter(line=>line.length>24&&/entry\.path|createWriteStream|ownedReplacement/.test(line))) {
      assert.equal(formats[name].includes(line),false,name+': raw source leaked');
      assert.equal(formats[name].includes(JSON.stringify(line).slice(1,-1)),false,name+': escaped source leaked');
    }
  }
  assert.equal(result.stdout.includes(PRIVATE)||result.stderr.includes(PRIVATE),false,'CLI logs leaked source');
  await assert.rejects(access(executionMarker),'target .cjs code was executed');
  for(const [name,text] of Object.entries(files)) assert.equal(await readFile(join(source,name),'utf8'),text,'target changed');
  assert.equal((await readdir(source)).includes('node_modules'),false,'target dependency installation');
  const report=JSON.parse(formats['report.json']),agent=JSON.parse(formats['agent-report.json']),sarif=JSON.parse(formats['report.sarif']);
  assert.equal(agent.scanGate.exitCode,2); assert.equal(agent.scanGate.failOn,'none');
  assert.equal(agent.reportArtifact.digest,createHash('sha256').update(formats['report.json']).digest('hex'));
  const inventory=report.checks.find((c:any)=>c.id==='source.inventory'); assert.ok(inventory);
  const total=expected.javascript+expected.typescript;
  assert.equal(inventory.metrics.codeFilesSelected,total,'collector omitted code inputs');
  assert.equal(inventory.metrics.codeFiles_javascript,expected.javascript);
  assert.equal(inventory.metrics.codeFiles_typescript,expected.typescript);
  const coverage=report.checks.find((c:any)=>c.id==='source.code-coverage')?.codeCoverage; assert.ok(coverage);
  assert.equal(coverage.accounting,'exact'); assert.equal(coverage.collectionComplete,true);
  assert.equal(coverage.totals.collected,total); assert.equal(coverage.requireCodeAnalysis,true);
  for(const [language,count] of Object.entries(expected)) {
    const row=coverage.languages.find((r:any)=>r.language===language);
    if(count===0) assert.equal(row,undefined,'invented zero language row');
    else {assert.ok(row,language);assert.equal(row.collected,count);assert.equal(row.eligible,count);}
  }
  const ast=report.checks.find((c:any)=>c.id==='source.builtin-ast'); assert.ok(ast);
  assert.equal(ast.status,'partial');assert.equal(ast.metrics.filesParsed,total,'collected code missed AST admission');
  return {report,agent,sarif,formats,ast,findings:ast.findings.filter((f:any)=>f.ruleId===RULE)};
}
function positive(r:Awaited<ReturnType<typeof scan>>,file:string) {
  assert.equal(r.findings.length,1);const f=r.findings[0];
  assert.equal(f.location.path,file);assert.equal(f.kind,'candidate');assert.equal(f.confidence,'low');assert.equal(f.severity,'high');
  assert.equal(f.staticFlow.sourceKind,'archive_entry_path');assert.equal(f.staticContext.authority,'conditional');
  assert.ok(f.staticFlow.steps.some((s:any)=>s.role==='source'&&s.location.path===file));
  const af=r.agent.findings.find((x:any)=>x.findingId===f.id);assert.ok(af);
  assert.deepEqual(af.evidence.staticFlow,f.staticFlow);assert.equal(af.verification.vulnerabilityConfirmed,false);
  assert.equal(af.verification.remediationVerified,false);
  const sf=r.sarif.runs[0].results.find((x:any)=>x.fingerprints?.['wakeio-security-ci/v2']===f.id);assert.ok(sf);
  assert.deepEqual(sf.properties.staticFlow,f.staticFlow);
  for(const [name,text] of Object.entries(r.formats)) {
    const visible=name==='report.md'?text.replace(/\\([\\`*_{}\[\]()#+\-.!<>])/g,'$1'):text;
    assert.ok(visible.includes('archive_entry_path'),name+': origin lost');assert.ok(visible.includes(file),name+': .cjs coordinate lost');
  }
}

test('archive collection: actual CLI collects .cjs archive risk as JavaScript and emits four matching reports',async t=>{
  positive(await scan(t,{'app.cjs':extract(CJS,RISK)},{javascript:1,typescript:0}),'app.cjs');
});

test('archive collection: .cjs lexical guard and fixed-content destination are separate normal controls',async t=>{
  const guard=await scan(t,{'app.cjs':extract(CJS,GUARD)},{javascript:1,typescript:0});
  assert.equal(guard.findings.length,0);assert.ok(guard.ast.metrics.archiveLexicalExclusions>=1);
  const normal=await scan(t,{'app.cjs':extract(CJS,"entry.stream().pipe(fs.createWriteStream('owned/fixed')); ")},{javascript:1,typescript:0});
  assert.equal(normal.findings.length,0);assert.equal(normal.ast.metrics.archiveLexicalExclusions,0);
});

test('archive collection: mixed .mts/.cjs selected shared writer replacement vetoes risk and lexical exclusion',async t=>{
  const mutation="require('node:fs').createWriteStream=ownedReplacement;";
  for(const statements of [RISK,GUARD]) {
    const r=await scan(t,{'app.mts':extract(ESM,statements),'mutation.cjs':mutation},{javascript:1,typescript:1});
    assert.equal(r.findings.length,0,'ignored .cjs mutation left fabricated native writer candidate');
    assert.equal(r.ast.metrics.archiveLexicalExclusions,0,'known native replacement kept safe exclusion');
  }
  const unrelated=await scan(t,{'app.mts':extract(ESM,RISK),'mutation.cjs':"require('node:fs').readFileSync=ownedReplacement;"},{javascript:1,typescript:1});
  positive(unrelated,'app.mts');
});

test('archive collection: collected .cjs direct and destructured shared archive replacement revokes origin',async t=>{
  for(const mutation of ["require('unzipper').Open.buffer=ownedReplacement;",
    "const {Open}=require('unzipper'); Open.buffer=ownedReplacement;",
    "const Open=require('unzipper').Open; Open.buffer=ownedReplacement;"]) {
    const r=await scan(t,{'app.mts':extract(ESM,RISK),'mutation.cjs':mutation},{javascript:1,typescript:1});
    assert.equal(r.findings.length,0,'ignored .cjs mutation minted archive source');
    assert.equal(r.report.checks.flatMap((c:any)=>c.findings).some((f:any)=>f.staticFlow?.sourceKind==='archive_entry_path'),false);
    assert.ok(r.ast.metrics.archiveUnsupportedUses>=1,'rejected archive declaration lost incomplete gap');
  }
});
