import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { access, chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { renderWorkflow } from '../src/init.js';

// Existing public renderer and real CLI/Action surfaces only. No target execution.
// Synthetic pin syntax; the local trusted Action root is never fetched from this pin.
const PIN='1'.repeat(40), PRIVATE='owned-init-action-source-marker-74b1';
const CLI=fileURLToPath(new URL('../src/cli.js',import.meta.url));
const ACTION_ROOT=process.env.WAKEIO_INIT_TEST_ACTION_ROOT ?? fileURLToPath(new URL('../../',import.meta.url));
const RISK="export function route(req){db.query('SELECT '+req.query.sql)}\n";
const FIXED="export function route(req){db.query('SELECT id FROM owned_rows WHERE id=$1',[req.query.sql])}\n";
const CLEAN='export const ready=true;\n';
const POLICY=['--require-code-analysis','--analysis-profile','default','--source-max-files','12','--source-max-bytes','65536'];
const sha=(text:string)=>createHash('sha256').update(text).digest('hex');
async function child(entry:string,args:string[],cwd:string,env:NodeJS.ProcessEnv={}) {
  return await new Promise<{code:number|null;out:string;err:string}>((resolveResult,reject)=>{
    const p=spawn(process.execPath,[entry,...args],{cwd,env:{...process.env,...env},stdio:['ignore','pipe','pipe']});let out='',err='';
    const timer=setTimeout(()=>{p.kill('SIGKILL');reject(new Error('Owned init/Action CLI timeout'));},30_000);
    p.stdout.on('data',v=>{out+=String(v);});p.stderr.on('data',v=>{err+=String(v);});
    p.once('error',e=>{clearTimeout(timer);reject(e);});p.once('close',code=>{clearTimeout(timer);resolveResult({code,out,err});});
  });
}
async function exists(path:string){try{await access(path);return true;}catch{return false;}}
async function fixture(t:TestContext,text=RISK){
  const top=await mkdtemp(join(tmpdir(),'wakeio-init-action-owned-'));t.after(()=>rm(top,{recursive:true,force:true}));
  const workspace=join(top,'workspace'),source=join(workspace,'wakeio-source');await mkdir(source,{recursive:true});
  const targetMarker=join(top,'TARGET_EXECUTED'),packageMarker=join(top,'PACKAGE_MANAGER_EXECUTED'),bin=join(top,'bin');await mkdir(bin);
  for(const name of ['npm','npx']){
    const executable=join(bin,name);await writeFile(executable,`#!/bin/sh\nprintf '%s\\n' '${name}' >> '${packageMarker}'\nexit 79\n`);await chmod(executable,0o700);
  }
  const prefix=`import fs from 'node:fs';\nfs.writeFileSync(${JSON.stringify(targetMarker)},'${PRIVATE}');\n`;
  await writeFile(join(source,'app.js'),prefix+text+'// '+PRIVATE+'\n');
  return {top,workspace,source,targetMarker,packageMarker,bin,prefix,workflow:join(source,'.github','workflows','wakeio-security-ci.yml')};
}
type Workspace=Awaited<ReturnType<typeof fixture>>;
type Step={values:Record<string,string>;with:Record<string,string>};
function scalar(raw:string){
  const text=raw.trim();
  if(text.startsWith('"')) return String(JSON.parse(text));
  if(text.startsWith("'")){assert.ok(text.endsWith("'"));return text.slice(1,-1).replaceAll("''","'");}
  assert.ok(text.length>0&&!/[\r\n]/.test(text));return text;
}
// Bounded emitted scalar-step subset only. Never interpret run: scripts or YAML tags.
function settings(workflow:string){
  const steps:Step[]=[];let selected:Step|undefined,insideWith=false;
  for(const line of workflow.split('\n')){
    const start=/^      - ([A-Za-z][A-Za-z-]*): (.+)$/.exec(line);
    if(start){selected={values:{[start[1]]:scalar(start[2])},with:{}};steps.push(selected);insideWith=false;continue;}
    if(!selected) continue;
    if(/^        with:\s*$/.test(line)){insideWith=true;continue;}
    const input=/^          ([A-Za-z][A-Za-z-]*): (.+)$/.exec(line);
    if(input&&insideWith){assert.equal(Object.hasOwn(selected.with,input[1]),false,'duplicate emitted Action input');selected.with[input[1]]=scalar(input[2]);continue;}
    const property=/^        ([A-Za-z][A-Za-z-]*): (.+)$/.exec(line);
    if(property){insideWith=false;assert.equal(Object.hasOwn(selected.values,property[1]),false);selected.values[property[1]]=scalar(property[2]);}
  }
  const scan=steps.find(s=>s.values.uses===`dusen0528/wakeio-security-ci@${PIN}`);assert.ok(scan,'missing exact pinned Wakeio step');
  const checkout=steps.find(s=>s.values.uses?.startsWith('actions/checkout@'));assert.ok(checkout);
  assert.match(checkout.values.uses,/^actions\/checkout@[a-f0-9]{40}$/);assert.equal(checkout.with.path,'wakeio-source');assert.equal(checkout.with['persist-credentials'],'false');
  const upload=steps.find(s=>s.values.uses?.startsWith('actions/upload-artifact@'));assert.ok(upload);
  assert.match(upload.values.uses,/^actions\/upload-artifact@[a-f0-9]{40}$/);assert.equal(upload.values.if,'always()');
  assert.equal(scan.with.source,'wakeio-source');assert.equal(scan.with.tools,'none');assert.equal(upload.with.path,scan.with.out);
  assert.ok(scan.with.out.endsWith('/${{ github.run_id }}-${{ github.run_attempt }}'));
  assert.equal(steps.some(s=>Object.hasOwn(s.values,'run')),false,'Action workflow runs target package manager/shell');
  assert.equal(steps.some(s=>s.values.uses?.startsWith('actions/setup-node@')),false,'duplicate Node onboarding');
  const allowed=new Set(['source','tools','out','project-id','require-code-analysis','analysis-profile','source-max-files','source-max-bytes']);
  assert.ok(Object.keys(scan.with).every(key=>allowed.has(key)),'unexpected generated input');return scan.with;
}
async function generate(w:Workspace,out='reports'){
  const result=await child(CLI,['init','--source',w.source,'--mode','action','--action-ref',PIN,'--out',out,...POLICY],w.workspace);
  assert.equal(result.code,0,result.err);const workflow=await readFile(w.workflow,'utf8'),inputs=settings(workflow);
  assert.equal(inputs['require-code-analysis'],'true');assert.equal(inputs['analysis-profile'],'default');
  assert.equal(inputs['source-max-files'],'12');assert.equal(inputs['source-max-bytes'],'65536');return {workflow,inputs};
}
async function run(w:Workspace,inputs:Record<string,string>,attempt:number){
  const output=join(w.top,`github-output-${attempt}`),summary=join(w.top,`github-summary-${attempt}`);await writeFile(output,'');await writeFile(summary,'');
  const out=inputs.out.replace('${{ github.run_id }}','81234').replace('${{ github.run_attempt }}',String(attempt));
  assert.equal(out.includes('${{'),false);const resolvedOut=resolve(w.workspace,out),relativeOut=relative(w.source,resolvedOut);
  assert.ok(relativeOut==='..'||relativeOut.startsWith('..'+sep),'generated reports reside inside collected source');
  const projectId=(inputs['project-id']??'owned/action-init').replace('${{ github.repository }}','owned/action-init');
  const env:NodeJS.ProcessEnv={PATH:w.bin+delimiter+(process.env.PATH??''),GITHUB_WORKSPACE:w.workspace,GITHUB_REPOSITORY:'owned/action-init',
    GITHUB_OUTPUT:output,GITHUB_STEP_SUMMARY:summary,WAKEIO_ACTION_PATH:ACTION_ROOT,WAKEIO_SOURCE:inputs.source,WAKEIO_TOOLS:inputs.tools,WAKEIO_OUT:out,
    WAKEIO_PROJECT_ID:projectId,WAKEIO_REQUIRE_CODE_ANALYSIS:inputs['require-code-analysis']??'false',
    WAKEIO_ANALYSIS_PROFILE:inputs['analysis-profile']??'default',WAKEIO_SOURCE_MAX_FILES:inputs['source-max-files']??'',WAKEIO_SOURCE_MAX_BYTES:inputs['source-max-bytes']??'',
    WAKEIO_FAIL_ON:'high',WAKEIO_URL:'',WAKEIO_PAGES:'',WAKEIO_API_POLICY:'',WAKEIO_MODE:'',WAKEIO_TOOL_CACHE:join(w.top,'tool-cache'),XDG_CACHE_HOME:join(w.top,'xdg')};
  const result=await child(join(ACTION_ROOT,'scripts','action-run.mjs'),[],w.workspace,env);
  const formats:Record<string,string>={};for(const name of ['report.json','agent-report.json','report.md','report.sarif']){
    formats[name]=await readFile(join(resolvedOut,name),'utf8');assert.equal(formats[name].includes(PRIVATE),false);assert.equal(formats[name].includes(w.targetMarker),false);
  }
  const report=JSON.parse(formats['report.json']),agent=JSON.parse(formats['agent-report.json']),status=JSON.parse(await readFile(join(resolvedOut,'action-status.json'),'utf8'));
  const outputs=Object.fromEntries((await readFile(output,'utf8')).trim().split('\n').map(line=>{const i=line.indexOf('=');return [line.slice(0,i),line.slice(i+1)];}));
  assert.equal(Number(outputs['exit-code']),result.code);assert.equal(status.exitCode,result.code);assert.equal(agent.scanGate.exitCode,result.code);
  assert.equal(outputs['report-agent'],join(resolvedOut,'agent-report.json'));assert.equal(agent.reportArtifact.digest,sha(formats['report.json']));
  assert.equal(report.checks.find((c:any)=>c.id==='source.inventory').sourceSnapshot.outputDirectoryExcluded,false);
  assert.equal(await exists(w.targetMarker),false,'target source executed');assert.equal(await exists(w.packageMarker),false,'package manager executed');
  for(const name of ['package.json','package-lock.json','node_modules'])assert.equal(await exists(join(w.source,name)),false,'target dependency coupling: '+name);
  return {dir:resolvedOut,code:result.code,report,agent,formats,outputs,status};
}
type Pair=Awaited<ReturnType<typeof run>>;
async function download(w:Workspace,pair:Pair,name:string){
  const dir=join(w.top,name);await mkdir(dir);for(const file of ['report.json','agent-report.json'])await copyFile(join(pair.dir,file),join(dir,file));return dir;
}
async function create(w:Workspace,pair:Pair,reportDir:string,name:string){
  const selected=pair.agent.findings.find((f:any)=>f.ruleId==='ast:sql-input-sink');assert.ok(selected);
  const out=join(w.top,name),result=await child(CLI,['handoff','create','--report',reportDir,'--source',w.source,'--finding',selected.findingId,
    '--check-index',String(selected.checkIndex),'--out',out],w.workspace);
  return {out,code:result.code,receipt:JSON.parse(await readFile(join(out,'handoff.json'),'utf8'))};
}
async function finish(w:Workspace,packet:string,after:string,name:string){
  const out=join(w.top,name),result=await child(CLI,['handoff','finish','--handoff',packet,'--report',after,'--source',w.source,'--out',out],w.workspace);
  return {code:result.code,receipt:JSON.parse(await readFile(join(out,'handoff.json'),'utf8'))};
}

test('init Action handoff: generated settings run real bundle on dependency-free clean/high/partial source',async t=>{
  for(const [text,expected,broken] of [[CLEAN,0,false],[RISK,1,false],[RISK,2,true]] as const){
    const w=await fixture(t,text),g=await generate(w);if(broken)await writeFile(join(w.source,'broken.js'),'export const broken = ;\n');
    const original=await readFile(join(w.source,'app.js'),'utf8'),pair=await run(w,g.inputs,1);
    assert.equal(pair.code,expected);assert.equal(await readFile(join(w.source,'app.js'),'utf8'),original);assert.equal(await readFile(w.workflow,'utf8'),g.workflow);
    if(expected===1)assert.ok(pair.agent.findings.some((f:any)=>f.ruleId==='ast:sql-input-sink'));
    if(expected===2)assert.ok(pair.report.checks.some((c:any)=>c.id==='source.builtin-ast'&&c.status==='partial'));
  }
});

test('init Action handoff: downloaded pair creates packet, unchanged high blocks, matching edit rechecks not_observed',async t=>{
  const w=await fixture(t),g=await generate(w),before=await run(w,g.inputs,1);assert.equal(before.code,1);
  const downloaded=await download(w,before,'download-before'),packet=await create(w,before,downloaded,'packet');assert.equal(packet.code,0);
  assert.equal(packet.receipt.originalScanGate.exitCode,1);assert.equal(packet.receipt.sourceBinding.outputDirectoryExcluded,false);
  assert.equal(packet.receipt.verification.vulnerabilityConfirmed,false);assert.equal(packet.receipt.verification.remediationVerified,false);
  const unchanged=await run(w,g.inputs,2),same=await finish(w,packet.out,await download(w,unchanged,'download-unchanged'),'finish-unchanged');
  assert.equal(same.code,1);assert.equal(same.receipt.selectedState,'unchanged');
  await writeFile(join(w.source,'app.js'),w.prefix+FIXED+'// '+PRIVATE+'\n');
  const after=await run(w,g.inputs,3);assert.equal(after.code,0);
  const fixed=await finish(w,packet.out,await download(w,after,'download-after'),'finish-fixed');
  assert.equal(fixed.code,0);assert.equal(fixed.receipt.selectedState,'not_observed');assert.equal(fixed.receipt.originalScanGate.exitCode,1);
  assert.equal(fixed.receipt.verification.securityControl,'not_run');assert.equal(fixed.receipt.verification.normalControl,'not_run');
  for(const file of ['report.json','agent-report.json']){
    assert.equal(await readFile(join(before.dir,file),'utf8'),before.formats[file]);assert.equal(await readFile(join(downloaded,file),'utf8'),before.formats[file]);
    assert.equal(await readFile(join(packet.out,file),'utf8'),before.formats[file]);
  }
});

test('init Action handoff: stale source, changed policy and AST partial cannot masquerade as successful recheck',async t=>{
  const w=await fixture(t),g=await generate(w),before=await run(w,g.inputs,1),downloaded=await download(w,before,'download-before');
  await writeFile(join(w.source,'late.js'),'export const late=true;\n');const stale=await create(w,before,downloaded,'stale-create');assert.equal(stale.code,2);
  await rm(join(w.source,'late.js'));const packet=await create(w,before,downloaded,'packet');assert.equal(packet.code,0);
  const changed=await run(w,{...g.inputs,'analysis-profile':'extended'},2);
  assert.equal((await finish(w,packet.out,await download(w,changed,'download-policy'),'finish-policy')).code,2);
  await writeFile(join(w.source,'broken.js'),'export const broken = ;\n');const partial=await run(w,g.inputs,3);assert.equal(partial.code,2);
  const partialPacket=await create(w,partial,await download(w,partial,'download-partial'),'packet-partial');assert.equal(partialPacket.code,0);
  assert.equal(partialPacket.receipt.originalScanGate.exitCode,2);
  assert.equal((await finish(w,partialPacket.out,partial.dir,'finish-partial')).code,2);
  await writeFile(join(w.source,'late.js'),'export const late=true;\n');
  assert.equal((await finish(w,packet.out,partial.dir,'finish-stale')).code,2);
});

test('init Action handoff: invalid CLI/SDK pin and out values reject without publication or injection',async t=>{
  const w=await fixture(t,CLEAN),base={mode:'action',actionRef:PIN,out:'reports',tools:['none'],pythonFiles:0};
  const cases:Array<{flags:string[];sdk:Record<string,unknown>}>=[
    {flags:['--mode','action'],sdk:{actionRef:undefined}},
    {flags:['--mode','npm','--action-ref',PIN],sdk:{mode:'npm'}},
    {flags:['--mode','invalid','--action-ref',PIN],sdk:{mode:'invalid'}},
    ...['f'.repeat(39),'aa\nrun: touch owned-injection'].map(actionRef=>({flags:['--mode','action','--action-ref',actionRef],sdk:{actionRef}})),
    ...['/absolute','../escape','WAKEIO-SOURCE/reports','${{ secrets.TOKEN }}','a\nrun: touch owned-injection']
      .map(out=>({flags:['--mode','action','--action-ref',PIN,'--out',out],sdk:{out}})),
  ];
  for(const c of cases){const result=await child(CLI,['init','--source',w.source,...c.flags],w.workspace);assert.equal(result.code,2);
    assert.equal(await exists(w.workflow),false,'invalid input published workflow');assert.throws(()=>renderWorkflow({...base,...c.sdk} as any));}
  const g=await generate(w);assert.equal((await child(CLI,['init','--source',w.source,'--mode','action','--action-ref',PIN],w.workspace)).code,2);
  assert.equal(await readFile(w.workflow,'utf8'),g.workflow);assert.equal(await exists(join(w.source,'owned-injection')),false);
  assert.equal(await exists(w.targetMarker),false);assert.equal(await exists(w.packageMarker),false);
});
