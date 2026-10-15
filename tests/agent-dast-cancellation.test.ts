import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

const loopScript = `
import assert from 'node:assert/strict';import {mock} from 'node:test';
import {mkdtemp,rm,readFile} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';
import net from 'node:net';let sockets=0;mock.method(net.Socket.prototype,'connect',()=>{sockets++;throw Error('network_forbidden')});
let engines=0;mock.module('./build/src/nuclei.js',{namedExports:{runNuclei:async(_options,runtime)=>{
 engines++;const permit=await runtime.reserve({method:'GET',kind:'probe'});permit.finish('response');
 return [{id:'nuclei',status:'completed',notes:[],metrics:{requestCount:1},findings:[]}];
}}});
const {runAgentLoop}=await import('./build/src/agent-dast/loop/loop.js');
const {openRunStore}=await import('./build/src/agent-dast/store.js');
const root=await mkdtemp(join(tmpdir(),'wakeio-loop-cancel-')),abort=new AbortController(),scenario=process.argv[1];
const task={id:'t-owned',engine:'nuclei',scopes:['exposures'],maxRequests:8};
const plan={version:1,kind:'wakeio.execution-plan',origin:'http://127.0.0.1',tasks:[task]};
let plans=0,selections=0,contextSignal;const agent={
 planTasks:async(_summary,context)=>{plans++;contextSignal=context?.signal;
  if(scenario==='plan'){queueMicrotask(()=>abort.abort());await new Promise(resolve=>setTimeout(resolve,20));}return plan;},
 selectNext:async(_summary,context)=>{selections++;contextSignal=context?.signal;
  queueMicrotask(()=>abort.abort());await new Promise(resolve=>setTimeout(resolve,20));return {action:'expand',tasks:[task]};}
};
if(scenario==='pre')abort.abort();
const store=await openRunStore(':memory:');store.createRun({runId:'r-recon',targetOrigin:plan.origin,scopeHash:'a'.repeat(64),provider:'fixed',startedAt:new Date().toISOString()});
try{
 const result=await runAgentLoop({agent,reconStore:store,reconRunId:'r-recon',origin:plan.origin,outDir:join(root,'loop'),taskCatalog:[{checkId:'c-owned',task}],coverageCells:[{surface:'GET /',checkId:'c-owned'}],sharedRequestCap:8,
 execution:{consent:true,allowedOrigin:plan.origin,allowPrivate:true,inputs:{version:1,inputs:[]},nucleiTemplates:root,signal:abort.signal}});
 assert.equal(result.status,'partial');assert.equal(result.reason,'cancelled');
 assert.equal(plans,scenario==='pre'?0:1);assert.equal(selections,scenario==='select'?1:0);assert.equal(engines,scenario==='select'?1:0);
 assert.equal(result.rounds.length,scenario==='select'?1:0);assert.equal(result.requestCount,scenario==='select'?1:0);assert.equal(sockets,0);
 if(scenario!=='pre')assert.equal(contextSignal,abort.signal);
 const report=JSON.parse(await readFile(join(root,'loop/loop-report.json'),'utf8'));assert.equal(report.reason,'cancelled');
}finally{store.close();await rm(root,{recursive:true,force:true});}
`;
for (const scenario of ['pre', 'plan', 'select']) test(`loop cancellation ${scenario} prevents agent retry, next runner and network`, () => {
  execFileSync(process.execPath, ['--experimental-test-module-mocks', '--input-type=module', '-e', loopScript, scenario], { stdio: 'pipe', timeout: 10000 });
});

const providerScript = `
import assert from 'node:assert/strict';import {mock} from 'node:test';import {getEventListeners} from 'node:events';
import {mkdtemp,rm,readFile,lstat} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import {promisify} from 'node:util';
import net from 'node:net';let sockets=0;mock.method(net.Socket.prototype,'connect',()=>{sockets++;throw Error('network_forbidden')});
const provider=process.argv[1],phase=process.argv[2],caller=new AbortController();
const template={version:1,kind:'wakeio.execution-plan',origin:'http://127.0.0.1',tasks:[{id:'t-owned',engine:'nuclei',scopes:['exposures'],maxRequests:8}]};
const summary={run_id:'r-owned',tasks:{queued:0,running:0,completed:0,partial:0,error:0,skipped:0},findings:{candidate:0,confirmed:0,rejected:0},open_by_severity:{critical:0,high:0,medium:0,low:0,info:0},gaps:{},needs_verify:0,needs_retry:0};
process.env.WAKEIO_AGENT_LIVE='1';process.env.CODEX_API_KEY='OWNED_CODEX_CANARY';process.env.ANTHROPIC_API_KEY='OWNED_CLAUDE_CANARY';
const fakeExec=()=>{};fakeExec[promisify.custom]=async()=>({stdout:'--ignore-user-config --ignore-rules --strict-config --ephemeral --disable',stderr:''});
const processExports=Object.fromEntries(Object.entries(await import('node:child_process')).filter(([key])=>key!=='default'));let spawned=0;
mock.module('node:child_process',{namedExports:{...processExports,execFile:fakeExec,spawn:()=>{spawned++;throw Error('subprocess_forbidden')}}});
let calls=0,aborted=0,cleaned=0;const signals=[],directories=[];
async function* events(signal){
 try{calls++;signals.push(signal);const cancelNow=phase==='pre'||phase==='plan'||phase==='loop'||calls===2;
 if(cancelNow){signal.addEventListener('abort',()=>aborted++,{once:true});queueMicrotask(()=>caller.abort());await new Promise(resolve=>setTimeout(resolve,15));if(signal.aborted)throw Error('owned abort');}
 const reply=phase==='select'&&calls===2?{action:'expand',tasks:template.tasks}:template;
 yield {type:'item.completed',item:{type:'agent_message',text:JSON.stringify(reply)}};yield {type:'turn.completed',usage:{input_tokens:1,output_tokens:1}};
 }finally{cleaned++;}
}
const sdk={Codex:class{startThread(options){directories.push(options.workingDirectory);return{runStreamed:async(_prompt,options)=>({events:events(options.signal)})}}},query:options=>{
 directories.push(options.options.cwd);
 const iterator=(async function*(){for await(const event of events(options.options.abortController.signal))if(event.type==='item.completed')yield{type:'result',subtype:'success',is_error:false,result:event.item.text,usage:{input_tokens:1,output_tokens:1}};})();iterator.close=()=>{};return iterator;
}};
const record=await import('./build/src/agent-dast/providers/record.js');mock.module('./build/src/agent-dast/providers/record.js',{namedExports:{...record,optionalSdk:async()=>sdk}});
mock.module('./build/src/agent-dast/providers/codex-help.js',{namedExports:{codexHelp:async()=>({executable:'/owned/codex',stdout:'--ignore-user-config --ignore-rules --strict-config --ephemeral --disable'})}});
const {createAgent}=await import('./build/src/agent-dast/providers/'+provider+'.js');
const root=await mkdtemp(join(tmpdir(),'wakeio-provider-cancel-'));
try{
 const agent=await createAgent({template,recordDir:join(root,'record'),live:true});
 if(phase==='pre')caller.abort();
 if(phase==='select')assert.deepEqual(await agent.planTasks(summary),template);
 if(phase==='loop'){
  const {runAgentLoop}=await import('./build/src/agent-dast/loop/loop.js');const {openRunStore}=await import('./build/src/agent-dast/store.js');
  const store=await openRunStore(':memory:');store.createRun({runId:'r-owned',targetOrigin:template.origin,scopeHash:'a'.repeat(64),provider:'fixed',startedAt:new Date().toISOString()});
  try{const result=await runAgentLoop({agent,reconStore:store,reconRunId:'r-owned',origin:template.origin,outDir:join(root,'loop'),taskCatalog:[{checkId:'c-owned',task:template.tasks[0]}],coverageCells:[{surface:'GET /',checkId:'c-owned'}],sharedRequestCap:8,
   execution:{consent:true,allowedOrigin:template.origin,allowPrivate:true,inputs:{version:1,inputs:[]},signal:caller.signal}});
   assert.equal(result.reason,'cancelled');assert.equal(result.status,'partial');assert.equal(result.rounds.length,0);assert.equal(result.requestCount,0);
  }finally{store.close();}
 }else{const pending=phase==='select'?agent.selectNext(summary,{signal:caller.signal}):agent.planTasks(summary,{signal:caller.signal});await assert.rejects(pending,/agent_cancelled/);}
 assert.equal(calls,phase==='pre'?0:phase==='select'?2:1);assert.equal(aborted,phase==='pre'?0:1);assert.equal(sockets,0);
 assert.equal(spawned,0);
 if(phase!=='pre')assert.equal(signals.at(-1).aborted,true);
 assert.equal(cleaned,calls);for(const directory of directories)await assert.rejects(lstat(directory),{code:'ENOENT'});
 assert.equal(getEventListeners(caller.signal,'abort').length,0);
 const logs=(await readFile(join(root,'record/ledger.jsonl'),'utf8'))+(await readFile(join(root,'record/transcript.jsonl'),'utf8'));
 assert(!logs.includes('OWNED_CODEX_CANARY'));assert(!logs.includes('OWNED_CLAUDE_CANARY'));if(phase!=='pre')assert(logs.includes('cancelled'));
}finally{await rm(root,{recursive:true,force:true});}
`;
for (const provider of ['codex', 'claude']) for (const phase of ['pre', 'plan', 'select', 'loop']) {
  test(`${provider} ${phase} cancellation reaches only existing SDK controller and never retries`, () => {
    execFileSync(process.execPath, ['--experimental-test-module-mocks', '--input-type=module', '-e', providerScript, provider, phase], { stdio: 'pipe', timeout: 10000 });
  });
}
