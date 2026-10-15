import test from 'node:test';
import { execFileSync } from 'node:child_process';

const mockScript = `
import assert from 'node:assert/strict';import {mock} from 'node:test';import {promisify} from 'node:util';import {EventEmitter} from 'node:events';
import * as fs from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import net from 'node:net';
let sockets=0;mock.method(net.Socket.prototype,'connect',()=>{sockets++;throw Error('network_forbidden')});
const scenario=process.argv[1],root=await fs.mkdtemp(join(tmpdir(),'wakeio-help-close-')),bin=join(root,"bin with ' quote");
await fs.mkdir(bin);const real=join(bin,"real ' codex");await fs.writeFile(real,'owned mock binary',{mode:0o700});await fs.symlink(real,join(bin,'codex'));
process.env.PATH=bin;process.env.WAKEIO_AGENT_LIVE='1';process.env.CODEX_API_KEY='OWNED_KEY_CANARY';
const caller=new AbortController(),child=new EventEmitter();let sdkStarts=0,helpCalls=0,closed=false,settled=false,removedBeforeClose=false,directory,wrapper='';
let started;const ready=new Promise(resolve=>started=resolve);let release=()=>{};
const flags='--ignore-user-config --ignore-rules --strict-config --ephemeral --disable';
const fakeExec=()=>{};fakeExec[promisify.custom]=(_command,_args,options)=>{
 helpCalls++;directory=options.env.HOME;
 const pending=new Promise((resolve,reject)=>{options.signal.addEventListener('abort',()=>reject(Object.assign(Error('owned abort callback'),{name:'AbortError'})),{once:true});release=()=>{closed=true;child.emit('close',null,'SIGTERM');resolve({stdout:flags,stderr:''});};});
 pending.child=child;started();return pending;
};
const cp=Object.fromEntries(Object.entries(await import('node:child_process')).filter(([key])=>key!=='default'));
mock.module('node:child_process',{namedExports:{...cp,execFile:fakeExec,spawn:()=>{throw Error('subprocess_forbidden')}}});
mock.module('node:fs/promises',{namedExports:{...fs,rm:async(...args)=>{if(String(args[0])===directory&&!closed)removedBeforeClose=true;return fs.rm(...args);}}});
const processes=await import('./build/src/source/process.js');
mock.module('./build/src/source/process.js',{namedExports:{...processes,runProcess:async(_binary,args,options)=>{
 helpCalls++;directory=options.cwd;assert.deepEqual(args,['exec','--help']);assert.equal(options.supervision,'agent');assert.equal(options.timeoutMs,5000);assert.equal(options.maxOutputBytes,65536);assert.equal(options.authentication,undefined);
 if(scenario==='cleanup-error'){closed=true;started();return{exitCode:null,signal:null,stdout:'',stderr:'SECRET_ERROR',timedOut:false,outputLimitExceeded:false,closeConfirmed:false,cleanupConfirmed:false,cleanupState:'running'};}
 if(scenario==='not-started'){closed=true;caller.abort();started();return{exitCode:null,signal:null,stdout:'',stderr:'',timedOut:false,outputLimitExceeded:false,cancelled:true,cleanupState:'not_started',cleanupConfirmed:true,closeConfirmed:false};}
 if(scenario==='quoted'){closed=true;started();return{exitCode:0,signal:null,stdout:flags,stderr:'',timedOut:false,outputLimitExceeded:false,closeConfirmed:true,cleanupConfirmed:true,cleanupState:'terminated'};}
 return await new Promise(resolve=>{release=()=>{closed=true;resolve({exitCode:null,signal:'SIGTERM',stdout:'',stderr:'',timedOut:false,outputLimitExceeded:false,cancelled:true,closeConfirmed:true,cleanupConfirmed:true,cleanupState:'terminated'});};started();});
}}});
const template={version:1,kind:'wakeio.execution-plan',origin:'http://127.0.0.1',tasks:[{id:'t-owned',engine:'nuclei',scopes:['exposures'],maxRequests:8}]};
const summary={run_id:'r-owned',tasks:{queued:0,running:0,completed:0,partial:0,error:0,skipped:0},findings:{candidate:0,confirmed:0,rejected:0},open_by_severity:{critical:0,high:0,medium:0,low:0,info:0},gaps:{},needs_verify:0,needs_retry:0};
const record=await import('./build/src/agent-dast/providers/record.js');
mock.module('./build/src/agent-dast/providers/record.js',{namedExports:{...record,optionalSdk:async()=>({Codex:class{constructor(options){sdkStarts++;this.path=options.codexPathOverride;}startThread(){const path=this.path;return{runStreamed:async()=>{wrapper=await fs.readFile(path,'utf8');return{events:(async function*(){yield{type:'item.completed',item:{type:'agent_message',text:JSON.stringify(template)}};yield{type:'turn.completed',usage:{input_tokens:1,output_tokens:1}};})()};}};}}})}});
const {createAgent}=await import('./build/src/agent-dast/providers/codex.js');let pending;
try{
 const agent=await createAgent({template,recordDir:join(root,'record'),live:true});pending=agent.planTasks(summary,{signal:caller.signal});pending.then(()=>settled=true,()=>settled=true);await ready;
 if(scenario==='withheld'){
  caller.abort();await new Promise(resolve=>setImmediate(resolve));
  assert.equal(removedBeforeClose,false,'provider entered directory cleanup before the owned help child closed');assert.equal(settled,false);assert.equal(sdkStarts,0);assert((await fs.lstat(directory)).isDirectory());
  release();await assert.rejects(pending,/agent_cancelled/);await assert.rejects(fs.lstat(directory),{code:'ENOENT'});
 }else if(scenario==='quoted'){
  assert.deepEqual(await pending,template);const checked=await fs.realpath(real);const quoted="'"+checked.split("'").join("'"+String.fromCharCode(92)+"''")+"'";assert(wrapper.includes('exec '+quoted+' exec '));assert.equal(sdkStarts,1);
 }else{
  await assert.rejects(pending);assert.equal(sdkStarts,0);
  if(scenario==='cleanup-error'){await assert.rejects(agent.planTasks(summary));assert.equal(helpCalls,1);}
  const log=await fs.readFile(join(root,'record/ledger.jsonl'),'utf8');assert(log.includes(scenario==='cleanup-error'?'cleanup_error':'cancelled'));if(scenario==='not-started')assert(!log.includes('cleanup_error'));
 }
 assert.equal(helpCalls,1);assert.equal(sockets,0);const log=await fs.readFile(join(root,'record/ledger.jsonl'),'utf8');assert(!log.includes('SECRET_ERROR'));assert(!log.includes('OWNED_KEY_CANARY'));
}finally{release();if(pending)await pending.catch(()=>{});await fs.rm(root,{recursive:true,force:true});}
`;
for (const scenario of ['withheld', 'cleanup-error', 'not-started', 'quoted']) {
  test(`Codex help ${scenario} preserves close-confirmed cleanup and never starts an unauthorized SDK`, () => {
    execFileSync(process.execPath, ['--experimental-test-module-mocks', '--input-type=module', '-e', mockScript, scenario], { stdio: 'pipe', timeout: 10000 });
  });
}

const ownedScript = `
import assert from 'node:assert/strict';import {mock} from 'node:test';import * as fs from 'node:fs/promises';import {tmpdir} from 'node:os';import {join} from 'node:path';import net from 'node:net';
let sockets=0;mock.method(net.Socket.prototype,'connect',()=>{sockets++;throw Error('network_forbidden')});
const root=await fs.mkdtemp(join(tmpdir(),'wakeio-help-owned-')),bin=join(root,'bin'),ready=join(root,'ready.json'),term=join(root,'term');await fs.mkdir(bin);
const program='#!'+process.execPath+'\\n'+"const fs=require('node:fs');process.on('SIGTERM',()=>fs.writeFileSync("+JSON.stringify(term)+",'TERM'));fs.writeFileSync("+JSON.stringify(ready)+",JSON.stringify({pid:process.pid}));setInterval(()=>{},1000);\\n";
await fs.writeFile(join(bin,'codex'),program,{mode:0o700});process.env.PATH=bin;process.env.WAKEIO_AGENT_LIVE='1';process.env.CODEX_API_KEY='OWNED_KEY_CANARY';
let sdkStarts=0;const record=await import('./build/src/agent-dast/providers/record.js');mock.module('./build/src/agent-dast/providers/record.js',{namedExports:{...record,optionalSdk:async()=>({Codex:class{constructor(){sdkStarts++;throw Error('SDK forbidden')}}})}});
const {createAgent}=await import('./build/src/agent-dast/providers/codex.js');const caller=new AbortController();let pid,pending;
const template={version:1,kind:'wakeio.execution-plan',origin:'http://127.0.0.1',tasks:[{id:'t-owned',engine:'nuclei',scopes:['exposures'],maxRequests:8}]};
const summary={run_id:'r-owned',tasks:{queued:0,running:0,completed:0,partial:0,error:0,skipped:0},findings:{candidate:0,confirmed:0,rejected:0},open_by_severity:{critical:0,high:0,medium:0,low:0,info:0},gaps:{},needs_verify:0,needs_retry:0};
try{
 const agent=await createAgent({template,recordDir:join(root,'record'),live:true});pending=agent.planTasks(summary,{signal:caller.signal});pending.catch(()=>{});
 const deadline=Date.now()+3000;while(!pid){try{pid=JSON.parse(await fs.readFile(ready,'utf8')).pid;}catch{if(Date.now()>deadline)throw Error('owned help never ready');await new Promise(resolve=>setTimeout(resolve,10));}}
 assert(Number.isSafeInteger(pid));process.kill(pid,0);caller.abort();await assert.rejects(pending,/agent_cancelled/);
 assert.equal(await fs.readFile(term,'utf8'),'TERM');assert.throws(()=>process.kill(pid,0),{code:'ESRCH'});assert.throws(()=>process.kill(-pid,0),{code:'ESRCH'});assert.equal(sdkStarts,0);assert.equal(sockets,0);
 const ledger=(await fs.readFile(join(root,'record/ledger.jsonl'),'utf8')).trim().split('\\n').map(JSON.parse);assert.equal(ledger.length,1);assert.equal(ledger[0].diagnostic,'cancelled');
}finally{caller.abort();if(pid){try{process.kill(-pid,'SIGKILL');}catch{}}if(pending)await pending.catch(()=>{});await fs.rm(root,{recursive:true,force:true});}
`;
test('owned harmless help child ignoring TERM is killed and its actual close/group disappearance precedes cancellation return', () => {
  execFileSync(process.execPath, ['--experimental-test-module-mocks', '--input-type=module', '-e', ownedScript], { stdio: 'pipe', timeout: 10000 });
});
