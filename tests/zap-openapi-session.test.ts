import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { runExecutionPlan } from '../src/agent-dast/runner.js';
import { request } from 'node:http';
import { resolveDastOrigin, startEgressGate } from '../src/dast-egress.js';
import { ZapSessionBridge } from '../src/zap-session.js';
import { zapPolicyEngine } from './fixtures/zap-policy-engine.js';
import { compileZapOpenApi, reconstructZapBody, projectedZapOpenApi } from '../src/zap-openapi.js';
import { parseZapPolicy, prepareZapPolicy } from '../src/zap-policy.js';
import { runZap } from '../src/zap.js';
import { zapPolicyTarget } from './fixtures/zap-policy-target.js';
import { zapSessionTarget } from './fixtures/zap-session-target.js';

test('ZAP OpenAPI compiler binds selected nested/array inputs, rejects remote refs and preserves other body fields', async () => {
  const target = await zapSessionTarget();
  try {
    const compiled = compileZapOpenApi(target.policy.openapi), post = compiled.requests[2]!;
    assert.deepEqual(post.fields?.map(f => f.pointer), ['/filter/name', '/tags/0', '/limit']);
    assert.deepEqual(reconstructZapBody(post, { p0: 'attack', p1: 'daily', p2: 5 }), { filter: { name: 'attack' }, tags: ['daily'], limit: 5, includeDeleted: false });
    const projection = JSON.stringify(projectedZapOpenApi(compiled.requests, 'http://wakeio-zap.invalid'));
    assert.equal(projection.includes('must-not-contact'), false); assert.equal(projection.includes('$ref'), false);
    assert.match(prepareZapPolicy(target.policy, true, target.env).sourceSha256!, /^[a-f0-9]{64}$/);
    for (const ref of ['https://evil.invalid/schema.json', 'file:///tmp/source', '#/components/schemas/Filter']) {
      const source: any = structuredClone(target.policy.openapi);
      source.document.components.schemas.Filter = { $ref: ref };
      assert.throws(() => compileZapOpenApi(source));
    }
    const unsupported: any = structuredClone(target.policy); unsupported.openapi.operations[0].method = 'DELETE'; assert.throws(() => parseZapPolicy(unsupported));
    assert.equal(target.seen.length, 0);
  } finally { await target.close(); }
});

test('real ZAP native OpenAPI and JSON authentication handle expiry/refresh and bind nested findings', { skip: !process.env.WAKEIO_ZAP_PATH, timeout: 180000 }, async context => {
  const target = await zapSessionTarget({ expire: true });
  try {
    const check = (await runZap({ url: target.origin, policy: target.policy, env: target.env, executable: process.env.WAKEIO_ZAP_PATH,
      consent: true, allowPrivate: true, maxRequests: 1000, rateLimit: 50, timeoutMs: 120000 }))[0]!;
    assert.equal(check.status, 'completed', JSON.stringify(check));
    assert.equal(check.metrics!.requestCount, target.seen.length);
    assert.equal(check.metrics!.loginRequests, 1); assert.ok(Number(check.metrics!.refreshRequests) >= 1);
    assert.equal(check.metrics!.identityBefore, true); assert.equal(check.metrics!.identityAfter, true); assert.equal(check.metrics!.anonymousDenied, true);
    assert.ok(check.findings.some(f => f.ruleId === 'zap.40012')); assert.ok(check.findings.some(f => f.ruleId === 'zap.40018'));
    const nested = check.findings.filter(f => new URL(f.location.url!).pathname === '/api/products/filter'); assert.ok(nested.length >= 2, JSON.stringify(check));
    assert.equal(new Set(nested.map(f => f.comparisonKey)).size, nested.length);
    for (const secret of target.privateValues) assert.equal(JSON.stringify(check).includes(secret), false);
    context.diagnostic(JSON.stringify({ metrics: check.metrics, findings: check.findings.map(f => ({rule:f.ruleId,key:f.comparisonKey,path:new URL(f.location.url!).pathname})) }));
  } finally { await target.close(); }
});

test('real ZAP native form/cookie session reauthenticates and leaves the fixed API without findings', { skip: !process.env.WAKEIO_ZAP_PATH, timeout: 180000 }, async context => {
  const target = await zapSessionTarget({ fixed: true, cookie: true, format: 'form', expire: true });
  try {
    const check = (await runZap({ url: target.origin, policy: target.policy, env: target.env, executable: process.env.WAKEIO_ZAP_PATH,
      consent: true, allowPrivate: true, maxRequests: 1000, rateLimit: 50, timeoutMs: 120000 }))[0]!;
    assert.equal(check.status, 'completed', JSON.stringify(check)); assert.equal(check.findings.length, 0);
    assert.equal(check.metrics!.requestCount, target.seen.length); assert.ok(Number(check.metrics!.loginRequests) >= 2);
    assert.equal(check.metrics!.refreshRequests, 0); assert.equal(check.metrics!.nativeAuthentication, 'form');
    for (const secret of target.privateValues) assert.equal(JSON.stringify(check).includes(secret), false);
    context.diagnostic(JSON.stringify({status:check.status,requests:target.seen.length,logins:check.metrics!.loginRequests,findings:0}));
  } finally { await target.close(); }
});

test('ZAP v2 login refusals and all global admission attempts include session controls and cancellation', { timeout: 15000 }, async () => {
  const top = await mkdtemp(join(tmpdir(), 'owned-zap-v2-control-'));
  try {
    const engine = await zapPolicyEngine(top, 40, 10), denied = await zapSessionTarget({ rejectLogin: true });
    try {
      const check = (await runZap({ url:denied.origin,policy:denied.policy,env:denied.env,executable:engine,consent:true,allowPrivate:true,rateLimit:50 }))[0]!;
      assert.equal(check.status,'partial'); assert.equal(check.metrics!.stopReason,'login_failed'); assert.equal(denied.seen.length,1);
      assert.equal(check.metrics!.requestCount,1); assert.ok(denied.seen.every(q=>q.path==='/sessions'));
    } finally { await denied.close(); }
    const target=await zapSessionTarget();
    try {
      const bytes=JSON.stringify(target.policy); await writeFile(join(top,'policy.json'),bytes);
      const options={plan:{version:1 as const,kind:'wakeio.execution-plan' as const,origin:target.origin,tasks:[{id:'t-zap',engine:'zap' as const,policy:'owner',maxRequests:200}]},
        inputs:{version:1 as const,inputs:[{id:'owner',path:'policy.json',sha256:createHash('sha256').update(bytes).digest('hex')}]},inputBaseDir:top,outDir:join(top,'capped'),
        consent:true,allowedOrigin:target.origin,allowPrivate:true,maxRequests:4,timeoutMs:5000,ratePerSecond:50,zapPath:engine,env:target.env};
      const capped=await runExecutionPlan(options); assert.equal(capped.exitCode,2); assert.equal(capped.requests.requestCount,4); assert.equal(target.seen.length,4);
      assert.equal(capped.tasks[0]!.requests.attempts[0]!.method,'POST'); assert.equal(capped.tasks[0]!.requests.attempts[0]!.kind,'control');
      assert.equal(capped.requests.pending,0); assert.ok(target.seen.some(q=>q.path==='/sessions'));
      const before=target.seen.length, controller=new AbortController();
      const pending=runExecutionPlan({...options,maxRequests:200,outDir:join(top,'cancelled'),signal:controller.signal});
      for(let i=0;i<200&&target.seen.length<before+5;i++) await new Promise(r=>setTimeout(r,10));
      assert.ok(target.seen.length>=before+5);controller.abort();const cancelled=await pending;
      assert.equal(cancelled.exitCode,2);const count=target.seen.length;await new Promise(r=>setTimeout(r,80));assert.equal(target.seen.length,count);
      for(const value of target.privateValues) assert.equal((await readFile(join(top,'cancelled/run-report.json'),'utf8')).includes(value),false);
    } finally {await target.close();}
  } finally {await rm(top,{recursive:true,force:true});}
});

test('ZAP session snapshots never expose credentials and reject malformed, cross-scope and exhausted renewal', async () => {
  const target=await zapSessionTarget();
  try {
    const prepared=prepareZapPolicy(target.policy,true,target.env),auth=prepared.policy.authentication!;
    assert.ok('login' in auth);
    const session=new ZapSessionBridge(auth,prepared.loginEnv!);
    const alias=Buffer.from(JSON.stringify({username:'wakeio-user',password:'wakeio-password'}));
    const login=session.prepare(alias);assert.ok(!('cached' in login));
    for(const value of target.privateValues) assert.equal(JSON.stringify({origin:session.virtualOrigin,engineCookie:session.engineCookie}).includes(value),false);
    assert.equal(await session.receive(200,{},Buffer.from('{"access":"owned-token","refresh":"owned-refresh"}')),true);
    assert.ok('cached' in session.prepare(alias)); session.observe(401);
    const refresh=session.prepare(alias);assert.ok(!('cached' in refresh));assert.equal(refresh.path,'/sessions/refresh');
    session.onRenewed=async()=>false;
    assert.equal(await session.receive(200,{},Buffer.from('{"access":"other-token","refresh":"other-refresh"}')),false);
    assert.equal(session.ready,false);assert.throws(()=>session.prepare(alias));
    for(const patch of [{maxAttempts:0},{maxAttempts:9},{login:{...auth.login,path:'//other.invalid/login'}},{session:{type:'bearer',tokenPointer:'__proto__'}},
      {refresh:{path:'/refresh',field:'constructor'}}]) assert.throws(()=>prepareZapPolicy({...target.policy,authentication:{...auth,...patch}},true,target.env));
    const env=Object.defineProperty({},'OWNED_ZAP_PASSWORD',{get(){throw Error('must-not-run')}});assert.throws(()=>prepareZapPolicy(target.policy,true,env));
    assert.equal(target.seen.length,0);
  }finally{await target.close();}
});


test('ZAP native session capability isolates the random virtual origin, controller and pending principal verification', async () => {
  const target = await zapSessionTarget(), abort = new AbortController();
  const prepared = prepareZapPolicy(target.policy, true, target.env), auth = prepared.policy.authentication!;
  assert.ok('login' in auth); const session = new ZapSessionBridge(auth, prepared.loginEnv!);
  const gate = await startEgressGate({ ...await resolveDastOrigin(target.origin, true, abort.signal), signal: abort.signal,
    methods: new Set(['GET','POST']), operations: ['/api/products/search'], maxRequests: 20,
    deadlineAt: Date.now()+10000, maxSingleBodyBytes: 16384, maxTotalBytes: 100000,
    relay: { virtualOrigin: session.virtualOrigin, session, controlPaths: ['/identity'], requests: [{method:'GET',path:'/api/products/search',query:['q']}] } });
  const proxy = new URL(gate.proxyUrl);
  const send = (url: string, cookie?: string, body?: string) => new Promise<{status:number;body:string;cookie:string|undefined}>((resolve,reject) => {
    const req = request({hostname:proxy.hostname,port:proxy.port,path:url,method:body===undefined?'GET':'POST',headers:{
      ...(cookie?{cookie}:{}), ...(body===undefined?{}:{'content-type':'application/json','content-length':Buffer.byteLength(body)})}}, res => {
      const chunks:Buffer[]=[];res.on('data',b=>chunks.push(b));res.on('error',reject);res.on('end',()=>resolve({status:res.statusCode!,body:Buffer.concat(chunks).toString(),cookie:res.headers['set-cookie']?.[0]}));
    });req.on('error',reject);req.end(body);
  });
  const alias = JSON.stringify({username:'wakeio-user',password:'wakeio-password'});
  try {
    for (const origin of ['http://wakeio-zap.invalid',target.origin]) assert.equal((await send(origin+'/api/products/search?q=apple')).status,407);
    assert.equal((await send(session.virtualOrigin+'/identity',session.engineCookie)).status,502);
    assert.equal((await send(session.virtualOrigin+'/api/products/search?q=apple')).status,502);
    assert.equal(target.seen.length,0);
    const login = await send(session.virtualOrigin+'/__wakeio_session',undefined,alias); assert.equal(login.status,200);assert.equal(login.body,'{"authenticated":true}');
    assert.ok(login.cookie?.startsWith(session.engineCookie));
    for (const secret of target.privateValues) assert.equal(JSON.stringify(login).includes(secret),false);
    assert.equal((await send(session.virtualOrigin+'/api/products/search?q=apple',session.engineCookie)).status,200);
    assert.equal((await send(session.virtualOrigin+'/api/products/search?q=apple&extra=1',session.engineCookie)).status,502);
    assert.equal((await send(session.virtualOrigin+'/identity',session.engineCookie)).status,502);
    session.observe(401); session.prepare(Buffer.from(alias));
    let release!:()=>void;const wait=new Promise<void>(resolve=>{release=resolve});
    session.onRenewed=async()=>{assert.equal(session.ready,false);assert.deepEqual(session.headers(),{});assert.ok(session.headers(true).authorization);await wait;return true;};
    const renewal=session.receive(200,{},Buffer.from('{"access":"renewed","refresh":"refresh"}'));
    assert.equal((await send(session.virtualOrigin+'/api/products/search?q=apple',session.engineCookie)).status,502);
    const before=target.seen.length;release();assert.equal(await renewal,true);assert.equal(target.seen.length,before);assert.equal(session.ready,true);
    assert.equal(gate.counters.forwarded,target.seen.length);
  } finally {await gate.close();await target.close();}
});

test('ZAP OpenAPI bounds reject duplicate operations, oversized arrays, mixed bodies and unknown fields before traffic', async () => {
 const target=await zapSessionTarget();
 try {
  const mutations=[
   (v:any)=>v.openapi.operations.push(v.openapi.operations[0]),
   (v:any)=>v.openapi.operations[0].query={undeclared:'x'},
   (v:any)=>v.openapi.operations[0].body={},
   (v:any)=>v.openapi.operations[2].body={filter:{name:'x'},tags:['a'],limit:5,includeDeleted:false,extra:'x'},
   (v:any)=>v.openapi.document.components.schemas.Filter.properties.tags.minItems=Number.MAX_SAFE_INTEGER,
   (v:any)=>v.openapi.document.components.schemas.Filter.properties.filter={oneOf:[{type:'string'}]},
   (v:any)=>v.openapi.operations[2].body={filter:{name:'x'},tags:['a'],limit:[],includeDeleted:false},
   (v:any)=>v.openapi.operations[0].extra=true,
  ];
  for(const mutate of mutations){const policy:any=structuredClone(target.policy);mutate(policy);assert.throws(()=>prepareZapPolicy(policy,true,target.env));}
  assert.equal(target.seen.length,0);
 } finally {await target.close();}
});


test('real ZAP refuses renewed principal drift before sending more authenticated probes', {skip:!process.env.WAKEIO_ZAP_PATH,timeout:180000}, async () => {
 const target=await zapSessionTarget({expire:true,wrongPrincipal:true});
 try {
  const check=(await runZap({url:target.origin,policy:target.policy,env:target.env,executable:process.env.WAKEIO_ZAP_PATH,consent:true,allowPrivate:true,maxRequests:200,rateLimit:50,timeoutMs:120000}))[0]!;
  assert.equal(check.status,'partial');assert.equal(check.metrics!.stopReason,'identity_control_failed');assert.equal(check.metrics!.refreshRequests,1);
  assert.equal(check.metrics!.requestCount,target.seen.length);assert.equal(target.seen.at(-1)!.path,'/identity');
  for(const secret of target.privateValues) assert.equal(JSON.stringify(check).includes(secret),false);
 }finally{await target.close();}
});


test('ZAP v2 native projection preserves unauthenticated and static Authorization policies', async () => {
 const top=await mkdtemp(join(tmpdir(),'owned-zap-v2-legacy-auth-'));
 try {
  const engine=await zapPolicyEngine(top,4);
  for(const authenticated of [false,true]){
   const target=await zapPolicyTarget({ignoreAuth:!authenticated});
   try {
    const policy={version:2 as const,kind:'zap-active' as const,origin:target.origin,openapi:{document:{openapi:'3.0.3',paths:{'/sql':{get:{parameters:[{name:'id',in:'query',schema:{type:'integer',default:1}}],responses:{'200':{description:'OK'}}}}}},operations:[{method:'GET' as const,path:'/sql'}]},...(authenticated?{authentication:target.policy.authentication}:{})};
    const result=(await runZap({url:target.origin,policy,env:target.env,executable:engine,consent:true,allowPrivate:true,maxRequests:20,rateLimit:50}))[0]!;
    assert.equal(result.status,'completed',JSON.stringify(result));assert.equal(result.metrics!.requestCount,target.seen.length);assert.equal(result.metrics!.authenticated,authenticated);
    assert.ok(target.seen.filter(q=>q.path==='/sql').every(q=>q.authenticated===authenticated));assert.equal(JSON.stringify(result).includes(target.authorization),false);
   }finally{await target.close();}
  }
 }finally{await rm(top,{recursive:true,force:true});}
});
