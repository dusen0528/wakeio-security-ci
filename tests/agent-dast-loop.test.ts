import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

const script = `
import assert from 'node:assert/strict';
import { mock } from 'node:test';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import net from 'node:net';
let sockets=0; mock.method(net.Socket.prototype,'connect',()=>{sockets++;throw Error('network_forbidden')});
let engineCalls=0;
mock.module('./build/src/nuclei.js',{namedExports:{runNuclei:async (_options,runtime)=>{
  engineCalls++; for(let i=0;i<2;i++){const permit=await runtime.reserve({method:'GET',kind:'probe'});permit.finish('response')}
  return [{id:'nuclei',status:'completed',notes:['RAW_RESPONSE_CANARY'],metrics:{requestCount:2},findings:Array.from({length:process.argv[1]==='repeat'?1:engineCalls},(_,i)=>({ruleId:'synthetic.'+i,title:'EVIDENCE_CANARY',description:'RAW_RESPONSE_CANARY',severity:'high',confidence:'high',kind:'candidate',location:{url:'http://127.0.0.1/items'},remediation:'synthetic'}))}];
}}});
const storeModule=await import('./build/src/agent-dast/store.js');
if(process.argv[1]==='storage-failure')mock.module('./build/src/agent-dast/store.js',{namedExports:{...storeModule,openRunStore:async path=>{const store=await storeModule.openRunStore(path);return path.includes('round-')?new Proxy(store,{get(target,key){if(key==='completeTask')return ()=>{throw Error('disk_full')};const value=Reflect.get(target,key);return typeof value==='function'?value.bind(target):value}}):store}}});
const {runAgentLoop}=await import('./build/src/agent-dast/loop/loop.js');
const {FakeAgent}=await import('./build/src/agent-dast/loop/agent.js');
const {openRunStore}=await import('./build/src/agent-dast/store.js');
const scenario=process.argv[1], root=await mkdtemp(join(tmpdir(),'wakeio-loop-'));
try {
 const recon=await openRunStore(':memory:');recon.createRun({runId:'r-recon',targetOrigin:'http://127.0.0.1',scopeHash:'a'.repeat(64),provider:'fixed',startedAt:new Date().toISOString()});
 const task={id:'t-exposure',engine:'nuclei',scopes:['exposures'],maxRequests:8};
 const plan={version:1,kind:'wakeio.execution-plan',origin:'http://127.0.0.1',tasks:[task]};
 const choices=[{action:'verify',tasks:[task]},{action:'expand',tasks:[task]},{action:'stop',tasks:[]}];
 const fake=new FakeAgent(plan,choices);let plans=0;const seen=[];
 const agent={planTasks:async s=>{seen.push(s);plans++;return scenario==='invalid'?{bad:'PRIVATE_ERROR'}:scenario==='retry'&&plans===1?{bad:true}:fake.planTasks(s)},selectNext:async s=>{seen.push(s);if(scenario==='invalid-selection')return {action:'verify',tasks:[],raw:'PRIVATE_ERROR'};if(scenario==='scope')return {action:'expand',tasks:[{...task,id:'t-outside'}]};return fake.selectNext(s)}};
 const opts={agent,reconStore:recon,reconRunId:'r-recon',outDir:join(root,'loop'),origin:plan.origin,
  taskCatalog:[{checkId:'c-exposure',task}],coverageCells:[{surface:'GET /items',checkId:'c-exposure'}],
  sharedRequestCap:scenario==='budget'?4:20,maxRounds:scenario==='rounds'?2:8,
  execution:{inputs:{version:1,inputs:[]},consent:true,allowedOrigin:plan.origin,allowPrivate:true,nucleiTemplates:root,ratePerSecond:150}};

 const result=await runAgentLoop(opts);
 const db=new DatabaseSync(join(root,'loop/run.db'),{readOnly:true});
 const ledger=db.prepare('SELECT coalesce(sum(request_count),0) n FROM ledger').get().n;
 assert.equal(result.rounds.reduce((n,r)=>n+r.requestCount,0),ledger);
 for(const round of result.rounds){const child=new DatabaseSync(join(round.outDir,'run.db'),{readOnly:true});if(scenario!=='storage-failure')assert.equal(child.prepare('SELECT sum(request_count) n FROM ledger').get().n,round.requestCount);child.close()}
 assert.equal(result.requestCount,ledger);assert.ok(ledger<=opts.sharedRequestCap);
 assert.equal(sockets,0);assert.ok(!JSON.stringify(seen).includes('RAW_RESPONSE_CANARY'));assert.ok(!JSON.stringify(seen).includes('EVIDENCE_CANARY'));
 const report=JSON.parse(await readFile(join(root,'loop/loop-report.json'),'utf8'));assert.equal(report.status,result.status);
 if(scenario==='storage-failure'){assert.equal(engineCalls,1);assert.equal(result.requestCount,2);assert.equal(result.rounds.length,1);assert.equal(result.status,'error');assert.equal(result.reason,'ledger_mismatch');assert.equal(result.rounds[0].ledgerVerified,false);}
 else if(scenario==='invalid'){assert.equal(plans,2);assert.equal(engineCalls,0);assert.equal(result.status,'error');}
 else if(scenario==='repeat'){assert.equal(engineCalls,2);assert.equal(result.reason,'repeated_summary');}
 else if(scenario==='invalid-selection'){assert.equal(engineCalls,1);assert.equal(result.status,'error');assert.equal(seen.length,3);}
 else if(scenario==='scope'){assert.equal(engineCalls,1);assert.equal(result.reason,'out_of_scope');}
 else if(scenario==='budget'){assert.equal(engineCalls,2);assert.equal(result.status,'partial');assert.equal(result.reason,'budget_exhausted');assert.ok(db.prepare("SELECT * FROM task_gaps WHERE reason='budget_exhausted'").get());}
 else if(scenario==='rounds'){assert.equal(engineCalls,2);assert.equal(result.reason,'round_limit');}
 else {assert.equal(engineCalls,3);assert.equal(result.status,'completed');assert.equal(result.rounds.length,3);if(scenario==='retry')assert.equal(plans,2);}
 db.close();recon.close();
} finally {await rm(root,{recursive:true,force:true})}
`;
for (const scenario of ['three-rounds','budget','scope','invalid','retry','rounds','repeat','invalid-selection','storage-failure']) {
  test(`offline loop: ${scenario}`, () => {
    assert.doesNotThrow(() => execFileSync(process.execPath, ['--experimental-test-module-mocks','--input-type=module','-e',script,scenario], { stdio:'pipe' }));
  });
}
