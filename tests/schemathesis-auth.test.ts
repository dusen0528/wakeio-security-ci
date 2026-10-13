import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { join } from 'node:path';
import { runSchemathesisLive, type SchemathesisLiveOptions } from '../src/schemathesis-live.js';
import { createReport, evaluateGate } from '../src/report.js';
import { authScalarObservation, parseSchemathesisAuthPolicy, sanitiseSchemathesisAuth, type SchemathesisAuthEvidence } from '../src/schemathesis-auth.js';

const python=process.env.WAKEIO_SCHEMATHESIS_PYTHON??join(process.cwd(),'.venv-schemathesis/bin/python');
const token='Bearer owned-auth-producer-private';
const marker='owned-producer-private-marker';
const selection:SchemathesisLiveOptions['operations']=[{method:'GET',path:'/items/{id}'},{method:'GET',path:'/other/{id}'}];
const response={description:'owned response',content:{'application/json':{schema:{type:'object',required:['marker'],properties:{marker:{type:'string'}}}}}};
const document={openapi:'3.0.3',info:{title:'Owned auth controls',version:'1.0.0'},security:[{bearer:[]}],components:{securitySchemes:{bearer:{type:'http',scheme:'bearer'}}},
  paths:Object.fromEntries(selection.map(o=>[o.path,{get:{parameters:[{name:'id',in:'path',required:true,schema:{type:'integer',enum:[1,2]}}],responses:{'200':response,'401':response,'500':response}}}]))};

async function target(risk:boolean, mode:'normal'|'malformed-denial'|'ignored'='normal') {
  const seen:Array<{path:string;authorized:boolean;cookie:boolean}>=[];
  const server=createServer((req,res)=>{
    const authorized=req.headers.authorization===token;
    seen.push({path:req.url??'',authorized,cookie:req.headers.cookie!==undefined});
    res.setHeader('content-type','application/json');res.setHeader('set-cookie',`auth=${token}`);
    if (!authorized && mode!=='ignored') {res.statusCode=401;res.end(mode==='malformed-denial'?'not-json':JSON.stringify({marker:'denied'}));return;}
    if (req.url==='/who') {res.end(JSON.stringify({who:'owned-principal'}));return;}
    res.statusCode=risk && req.url?.endsWith('/2')?500:200;res.end(JSON.stringify({marker}));
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const address=server.address();assert.ok(address&&typeof address==='object');
  return {origin:`http://127.0.0.1:${address.port}/`,seen,close:()=>new Promise<void>(resolve=>server.close(()=>resolve()))};
}
function policy(baseUrl:string) {
  return {version:1,kind:'schemathesis-get-auth',baseUrl,authorizationEnv:'OWNED_AUTH',identity:{path:'/who',status:200,jsonPointer:'/who',equals:'owned-principal'},
    operations:selection.map(o=>({path:o.path,normal:{path:o.path.replace('{id}','1'),status:200,jsonPointer:'/marker',equals:marker}}))};
}
function live(origin:string, extra:Partial<SchemathesisLiveOptions>={}) {
  return runSchemathesisLive({document,baseUrl:origin,operations:selection,consent:true,allowPrivate:true,python,maxRequests:12,seed:7,
    authPolicy:policy(origin),env:{OWNED_AUTH:token},...extra});
}

test('schemathesis auth: real two-operation generated risk/normal pair preserves controls and denominator',async()=>{
  for (const risk of [true,false]) {
    const owned=await target(risk);
    try {
      const checks=await live(owned.origin), check=checks[0]!;
      assert.equal(check.status,'completed',check.notes.join(' | '));
      const e=check.schemathesisAuth!;
      assert.equal(e.controls.length,8);assert.equal(e.requests.attempted,12);assert.equal(e.requests.generated,4);
      assert.deepEqual(e.operations.map(o=>o.generatedRequests),[2,2]);
      assert.ok(e.records.every(r=>r.attempt>5 && r.attempt<10));
      assert.ok(e.controls.every(c=>c.outcome==='matched'));
      assert.equal(owned.seen.length,12);assert.equal(owned.seen.filter(r=>!r.authorized).length,2);
      assert.ok(owned.seen.every(r=>!r.cookie));
      assert.equal(evaluateGate(createReport(checks,'url',new Date()),'medium').exitCode,risk?1:0);
      const serialized=JSON.stringify(check);
      for (const privateValue of [token,marker,'owned-principal','OWNED_AUTH','wakeio:']) assert.ok(!serialized.includes(privateValue));
    } finally {await owned.close();}
  }
});

test('schemathesis auth: malformed anonymous denial and ignored credential never authorize generation',async()=>{
  for (const mode of ['malformed-denial','ignored'] as const) {
    const owned=await target(false,mode);
    try {
      const checks=await live(owned.origin),check=checks[0]!;
      assert.equal(check.status,'partial');assert.equal(check.schemathesisAuth!.stopReason,'anonymous_control_failed');
      assert.equal(check.schemathesisAuth!.requests.generated,0);assert.equal(owned.seen.length,2);
      assert.equal(evaluateGate(createReport(checks,'url',new Date()),'none').exitCode,2);
    } finally {await owned.close();}
  }
});

test('schemathesis auth: options, policy, selection and credential snapshots reject accessors without invocation',async()=>{
  const owned=await target(false);
  try {
    let invoked=false;
    const env=Object.defineProperty({},'OWNED_AUTH',{get(){invoked=true;return token;},enumerable:true});
    const ops=Object.defineProperty([],'0',{get(){invoked=true;return selection[0];},enumerable:true});
    const cases:Partial<SchemathesisLiveOptions>[]=[{env},{operations:ops},{maxRequests:9},{env:Object.create({OWNED_AUTH:token})}];
    for (const extra of cases) {
      const checks=await live(owned.origin,extra);assert.equal(checks[0]!.status,'partial');assert.equal(checks[0]!.schemathesisAuthRequired,true);
      assert.equal(evaluateGate(createReport(checks,'url',new Date()),'none').exitCode,2);
    }
    assert.equal(invoked,false);assert.equal(owned.seen.length,0);
    const prototype=new Proxy({}, {has(){invoked=true;return true;}});
    const proxyInherited=Object.assign(Object.create(prototype),{document,baseUrl:owned.origin,operations:selection,consent:true});
    const rejected=await runSchemathesisLive(proxyInherited);
    assert.equal(rejected[0]!.status,'partial');assert.equal(invoked,false);assert.equal(owned.seen.length,0);
    const accepted=policy(owned.origin);accepted.operations.reverse();
    const checks=await live(owned.origin,{authPolicy:accepted});assert.equal(checks[0]!.status,'completed');
  } finally {await owned.close();}
});

test('schemathesis auth: selected templates cannot reach another documented GET route',async()=>{
  const owned=await target(false);
  try {
    const collision={...document,paths:{...document.paths,'/items/admin':{get:{responses:{'200':response}}}}};
    const checks=await live(owned.origin,{document:collision});
    assert.equal(checks[0]!.status,'partial');assert.equal(checks[0]!.schemathesisAuthRequired,true);
    assert.equal(owned.seen.length,0);
  } finally {await owned.close();}
});

test('schemathesis auth: strict canonical evidence rejects moved, invented and inconsistent generated records',()=>{
  const d='a'.repeat(64);
  const e:SchemathesisAuthEvidence={version:1,profileRevision:'schemathesis-get-auth-v1',status:'completed',stopReason:'complete',policySha256:d,schemaSha256:d,workerSha256:d,
    limits:{maxRequests:6,timeoutMs:1000,maxBodyBytes:1024,maxTotalBytes:4096},seed:1,operations:[{operation:'GET /items/{id}',generatedRequests:1,deniedRequests:0}],
    controls:[{ordinal:1,phase:'identity-before',operationIndex:null,outcome:'matched',httpStatus:200,attempt:1},
      {ordinal:2,phase:'anonymous-normal',operationIndex:0,outcome:'matched',httpStatus:401,attempt:2},
      {ordinal:3,phase:'normal-before',operationIndex:0,outcome:'matched',httpStatus:200,attempt:3},
      {ordinal:4,phase:'normal-after',operationIndex:0,outcome:'matched',httpStatus:200,attempt:5},
      {ordinal:5,phase:'identity-after',operationIndex:null,outcome:'matched',httpStatus:200,attempt:6}],
    requests:{attempted:6,generated:1,completedGenerated:1,responseBytes:12},records:[{ordinal:1,operationIndex:0,attempt:4,status:200,check:'passed',inputFingerprint:d,failures:[]}],
    engineVersion:'4.2.0',runtime:{python:'3.12.3',hypothesis:'6.168.3',jsonschema:'4.26.0',requests:'2.34.2'}};
  assert.deepEqual(sanitiseSchemathesisAuth(e),e);
  const bad=(edit:(copy:SchemathesisAuthEvidence)=>void)=>{const copy=structuredClone(e);edit(copy);assert.equal(sanitiseSchemathesisAuth(copy),undefined);};
  bad(c=>{c.records[0]!.attempt=1;});bad(c=>{c.operations[0]!.generatedRequests=0;});
  bad(c=>{c.records[0]!.check='response_contract';c.records[0]!.failures=[{rule:'response_schema_conformance',kind:'schema_violation',keyword:'privateString'}];});
  bad(c=>{c.controls[2]!.attempt=4;c.records[0]!.attempt=3;});
  assert.throws(()=>parseSchemathesisAuthPolicy({...policy('http://127.0.0.1:1/'),privateToken:token}));
  assert.deepEqual(authScalarObservation(Buffer.from('bad-json'),{path:'/',status:200,jsonPointer:'/marker',equals:marker}),{validJson:false,matched:false});
});
