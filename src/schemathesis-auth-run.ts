import { createHash } from 'node:crypto';
import { lstat, readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { types } from 'node:util';
import type { CheckResult, Finding } from './contracts.js';
import { API_DEFAULT_TIMEOUT_MS, API_MAX_REQUESTS, API_MAX_SINGLE_BODY_BYTES, API_MAX_TIMEOUT_MS, API_MAX_TOTAL_BODY_BYTES, createApiRunControl } from './api.js';
import { resolveDastOrigin, startEgressGate, type EgressGate } from './dast-egress.js';
import { selectOpenApiLiveOperations, type OpenApiLiveSelection } from './openapi.js';
import { superviseWorker } from './schemathesis.js';
import { LIVE_CHECK_ID, projectLiveResult, type SchemathesisLiveOptions } from './schemathesis-live.js';
import { normalizeUrl } from './url-network.js';
import { snapshotJsonData } from './json-snapshot.js';
import { admissionSignal, type TaskAdmission } from './agent-dast/admission.js';
import { authScalarObservation, parseSchemathesisAuthPolicy, sanitiseSchemathesisAuth, snapshotSchemathesisCredential,
  operationPathMatches, SCHEMATHESIS_AUTH_REVISION, type SchemathesisAuthEvidence, type SchemathesisAuthPolicy, type SchemathesisAuthStop } from './schemathesis-auth.js';

const OUTPUT_CAP = 256 * 1024;
const NOTE = 'Authenticated Schemathesis generates bounded GET cases after declared principal and per-operation normal controls. Node injects one credential through a pinned HTTP(S) gate; redacted evidence is diagnostic, not proof of authentication, exploitability, whole-API coverage, or a replay artifact.';
function fail(): never { throw new TypeError('invalid_auth_live_input'); }
const object = (v:unknown): v is Record<string,any> => !!v && typeof v === 'object' && !Array.isArray(v);
const keys = (v:unknown, wanted:string[]): v is Record<string,any> => object(v) && Object.keys(v).length===wanted.length && wanted.every(k=>Object.hasOwn(v,k));
const hash = (bytes:string|Buffer) => createHash('sha256').update(bytes).digest('hex');
const budget = (v:unknown,fallback:number,max:number):number => { const x=v??fallback; if (!Number.isSafeInteger(x) || Number(x)<1 || Number(x)>max) fail(); return Number(x); };

/** Reject competing credential channels in the selected operations before any traffic. */
export function validateSchemathesisAuthSchema(selection: OpenApiLiveSelection): void {
  const doc = selection.document as Record<string,any>;
  const resolve = (input:unknown):Record<string,any> => {
    let v=input, count=0;
    while (object(v) && Object.hasOwn(v,'$ref')) {
      if (++count>40 || typeof v.$ref !== 'string' || !v.$ref.startsWith('#/')) fail();
      let target:unknown=doc;
      for (const token of v.$ref.slice(2).split('/')) {
        const key=token.replace(/~1/g,'/').replace(/~0/g,'~');
        if (!object(target) || !Object.hasOwn(target,key)) fail(); target=target[key];
      }
      v=target;
    }
    if (!object(v)) fail(); return v;
  };
  for (const item of selection.operations) {
    // A generated parameter must not address another documented GET route.
    // This conservative template-overlap rejection also covers two selected ambiguous operations.
    const parts=item.path.split('/');
    for (const other of Object.keys(doc.paths)) {
      if (other===item.path || other.startsWith('x-')) continue;
      const otherItem=resolve(doc.paths[other]);
      if (!Object.hasOwn(otherItem,'get')) continue;
      const segments=other.split('/');
      if (parts.length===segments.length && parts.every((part,i)=>part===segments[i] || /^\{[A-Za-z0-9_.-]+\}$/.test(part) || /^\{[A-Za-z0-9_.-]+\}$/.test(segments[i]))) fail();
      if (operationPathMatches(item.path,other)) fail();
    }
    const path=resolve(doc.paths[item.path]), op=resolve(path.get);
    for (const group of [path.parameters,op.parameters]) {
      if (group===undefined) continue;
      if (!Array.isArray(group)) fail();
      for (const raw of group) { const p=resolve(raw); if (p.in==='cookie' || p.in==='header' && typeof p.name==='string' && ['authorization','cookie','proxy-authorization'].includes(p.name.toLowerCase())) fail(); }
    }
    const security=op.security??doc.security;
    if (security===undefined) continue;
    if (!Array.isArray(security) || security.length>32) fail();
    for (const requirement of security) {
      if (!object(requirement)) fail();
      for (const name of Object.keys(requirement)) {
        const scheme=resolve(doc.components?.securitySchemes?.[name]);
        if (scheme.type!=='http' || typeof scheme.scheme!=='string' || !['bearer','basic'].includes(scheme.scheme.toLowerCase())) fail();
      }
    }
  }
}

interface Prepared {
  policy:SchemathesisAuthPolicy; policySha256:string; authorization:string; selection:OpenApiLiveSelection; schemaSha256:string;
  maxRequests:number; timeoutMs:number; maxBodyBytes:number; maxTotalBytes:number; seed:number; allowPrivate:boolean; python:string; signal?:AbortSignal;
}
/** Every policy, schema, selected credential and scalar option is captured before the first await. */
function prepare(input:SchemathesisLiveOptions):Prepared {
  if (!input || typeof input!=='object' || types.isProxy(input) || Array.isArray(input)) fail();
  const prototype=Object.getPrototypeOf(input);
  if (prototype!==Object.prototype && prototype!==null || Object.getOwnPropertySymbols(input).length) fail();
  const descriptors=Object.getOwnPropertyDescriptors(input);
  const allowed=['document','baseUrl','operations','consent','allowPrivate','python','timeoutMs','maxRequests','maxBodyBytes','maxTotalBytes','seed','signal','authPolicy','env'];
  if (Object.keys(descriptors).some(k=>!allowed.includes(k) || !('value' in descriptors[k]) || !descriptors[k].enumerable)
    || !['document','baseUrl','operations','consent','authPolicy'].every(k=>Object.hasOwn(descriptors,k))) fail();
  const options=Object.create(null,descriptors) as SchemathesisLiveOptions;
  if (options.consent!==true || options.allowPrivate!==undefined && typeof options.allowPrivate!=='boolean'
    || options.python!==undefined && (typeof options.python!=='string' || !options.python || options.python.length>4096 || /[\u0000-\u001f\u007f]/.test(options.python))) fail();
  const parsed=parseSchemathesisAuthPolicy(options.authPolicy);
  let policy=parsed.policy;
  const authorization=snapshotSchemathesisCredential(policy,options.env);
  const selection=selectOpenApiLiveOperations(options.document,snapshotJsonData(options.operations));
  validateSchemathesisAuthSchema(selection);
  if (typeof options.baseUrl!=='string' || normalizeUrl(options.baseUrl).href!==policy.baseUrl
    || selection.operations.length!==policy.operations.length || selection.operations.some(o=>!policy.operations.some(p=>p.path===o.path))) fail();
  // The configuration digest retains the original canonical policy. Execution indices follow the selected operation order.
  policy={...policy,operations:selection.operations.map(o=>policy.operations.find(p=>p.path===o.path)!)};
  const url=new URL(policy.baseUrl);
  if (url.protocol==='http:' && (options.allowPrivate!==true || !['127.0.0.1','[::1]'].includes(url.hostname))) fail();
  const maxRequests=budget(options.maxRequests,32,API_MAX_REQUESTS);
  if (maxRequests<2+4*selection.operations.length) fail();
  if (options.signal!==undefined && (types.isProxy(options.signal) || !(options.signal instanceof AbortSignal))) fail();
  return {policy,policySha256:parsed.policySha256,authorization,selection,schemaSha256:hash(JSON.stringify(selection.document)),maxRequests,
    timeoutMs:budget(options.timeoutMs,API_DEFAULT_TIMEOUT_MS*2,API_MAX_TIMEOUT_MS),maxBodyBytes:budget(options.maxBodyBytes,API_MAX_SINGLE_BODY_BYTES,API_MAX_SINGLE_BODY_BYTES),
    maxTotalBytes:budget(options.maxTotalBytes,API_MAX_TOTAL_BODY_BYTES,API_MAX_TOTAL_BODY_BYTES),seed:budget(options.seed,1,2147483647),
    allowPrivate:options.allowPrivate===true,python:options.python??'python3',signal:options.signal};
}

async function workerPath():Promise<string|undefined> {
  for (const relative of ['../../workers/schemathesis/worker.py','../workers/schemathesis/worker.py']) {
    const path=fileURLToPath(new URL(relative,import.meta.url)), stat=await lstat(path).catch(()=>undefined);
    if (stat?.isFile() && !stat.isSymbolicLink()) return path;
  }
  return undefined;
}

type LiveResult = ReturnType<typeof projectLiveResult>;
/** v3 bounded NDJSON: a validated record prefix remains useful if the worker is interrupted. */
function workerOutput(raw:string,labels:Set<string>,max:number,expectedHash:string):{result?:LiveResult; invalid:boolean; final:boolean} {
  if (Buffer.byteLength(raw)>OUTPUT_CAP) return {invalid:true,final:false};
  const lines=raw.split('\n'); if (lines.at(-1)==='') lines.pop();
  let metadata:Record<string,any>|undefined, finalResult:LiveResult|undefined, invalid=false;
  const records:unknown[]=[];
  for (let i=0;i<lines.length;i++) {
    let event:unknown;
    try { event=JSON.parse(lines[i]); } catch { invalid=true; break; }
    if (!object(event) || event.version!==3 || finalResult) { invalid=true; break; }
    if (event.event==='metadata' && !metadata && !records.length && keys(event,['version','event','workerSha256','engineVersion','runtime'])) metadata=event;
    else if (event.event==='record' && metadata && keys(event,['version','event','record'])) records.push(event.record);
    else if (event.event==='final' && metadata && keys(event,['version','event','result'])) {
      try { finalResult=projectLiveResult(JSON.stringify(event.result),labels,max); } catch { invalid=true; break; }
      if (JSON.stringify(finalResult.records)!==JSON.stringify(records)) { invalid=true; finalResult=undefined; break; }
    } else { invalid=true; break; }
  }
  if (!metadata) return {invalid:true,final:false};
  let prefix:LiveResult;
  try {
    const operations=[...labels].map(operation=>({operation,requests:records.filter((r:any)=>r?.operation===operation).length}));
    prefix=projectLiveResult(JSON.stringify({version:2,status:'partial',reason:'transport_error',requestCount:records.length,bytesInspected:0,transportErrors:0,
      operations,workerSha256:metadata.workerSha256,engineVersion:metadata.engineVersion,runtime:metadata.runtime,records}),labels,max);
    if (prefix.workerSha256!==expectedHash || finalResult && (finalResult.workerSha256!==expectedHash || JSON.stringify(finalResult.runtime)!==JSON.stringify(prefix.runtime))) return {invalid:true,final:false};
  } catch { return {invalid:true,final:false}; }
  return {result:finalResult??prefix,invalid,final:!!finalResult};
}

function observations(e:SchemathesisAuthEvidence, gate:EgressGate, origin:string):Finding[] {
  const findings:Finding[]=[];
  for (let index=0;index<e.operations.length;index++) {
    const operation=e.operations[index].operation;
    const server=gate.authenticated!.observations.filter(x=>x.operationIndex===index && x.status!==null && x.status>=500).length;
    const schema=e.records.filter(r=>r.operationIndex===index && r.failures.some(f=>f.rule==='response_schema_conformance')).length;
    for (const [kind,count] of [['server',server],['schema',schema]] as const) if (count) findings.push({
      ruleId:kind==='server'?'api.schemathesis.server_error':'api.schemathesis.response_schema',
      title:kind==='server'?'Authenticated generated GET returned a server error':'Authenticated response did not conform to the OpenAPI schema',
      description:`${operation}: ${count} observed ${kind==='server'?'5xx response(s)':'engine response-contract failure(s)'}. Raw inputs, credentials, response bodies and exception messages are not retained.`,
      severity:kind==='server'?'medium':'low',confidence:'high',kind:'observation',location:{url:`${origin}${operation.slice(4).replace(/^\//,'')}`},
      remediation:'Review the diagnostic operation and rerun with the same policy, schema, engine and seed; this artifact does not authorize or encode a replay.',references:['https://schemathesis.readthedocs.io/en/stable/'] });
  }
  return findings;
}

export async function runSchemathesisAuthenticated(options:SchemathesisLiveOptions,runtime?:TaskAdmission):Promise<CheckResult[]> {
  let p:Prepared;
  try { p=prepare(options); } catch { return [{id:LIVE_CHECK_ID,status:'partial',schemathesisAuthRequired:true,findings:[],notes:[NOTE,'Authentication policy, options, schema or credential was rejected before traffic.'],metrics:{requestCount:0,stopReason:'unknown'}}]; }
  const n=p.policy.operations.length;
  const controls:SchemathesisAuthEvidence['controls']=[{ordinal:1,phase:'identity-before',operationIndex:null,outcome:'not_attempted',httpStatus:null,attempt:null},
    ...p.policy.operations.flatMap((_,i)=>[{ordinal:2+2*i,phase:'anonymous-normal' as const,operationIndex:i,outcome:'not_attempted' as const,httpStatus:null,attempt:null},
      {ordinal:3+2*i,phase:'normal-before' as const,operationIndex:i,outcome:'not_attempted' as const,httpStatus:null,attempt:null}]),
    ...p.policy.operations.map((_,i)=>({ordinal:2+2*n+i,phase:'normal-after' as const,operationIndex:i,outcome:'not_attempted' as const,httpStatus:null,attempt:null})),
    {ordinal:2+3*n,phase:'identity-after',operationIndex:null,outcome:'not_attempted',httpStatus:null,attempt:null}];
  const evidence:SchemathesisAuthEvidence={version:1,profileRevision:SCHEMATHESIS_AUTH_REVISION,status:'partial',stopReason:'unknown',policySha256:p.policySha256,
    schemaSha256:p.schemaSha256,workerSha256:'',limits:{maxRequests:p.maxRequests,timeoutMs:p.timeoutMs,maxBodyBytes:p.maxBodyBytes,maxTotalBytes:p.maxTotalBytes},
    seed:p.seed,operations:p.selection.operations.map(o=>({operation:`GET ${o.path}`,generatedRequests:0,deniedRequests:0})),controls,
    requests:{attempted:0,generated:0,completedGenerated:0,responseBytes:0},records:[],engineVersion:'unknown',runtime:null};
  const control=createApiRunControl(p.timeoutMs,admissionSignal(runtime,p.signal)), engine=new AbortController();
  const stopEngine=()=>engine.abort(); control.signal.addEventListener('abort',stopEngine,{once:true});
  let gate:EgressGate|undefined, reason:SchemathesisAuthStop='complete', result:LiveResult|undefined;
  const interrupted=():SchemathesisAuthStop|undefined=>control.signal.aborted || Date.now()>=control.deadlineAt?(p.signal?.aborted?'cancelled':'timeout'):undefined;
  const runControl=async(index:number):Promise<boolean>=>{
    if (!gate?.authenticated || interrupted()) return false;
    const step=controls[index], assertion=step.operationIndex===null?p.policy.identity:p.policy.operations[step.operationIndex].normal;
    const before=gate.counters.forwarded;
    try {
      const reply=await gate.authenticated.control(assertion.path,step.phase==='anonymous-normal');
      step.attempt=reply.attempt; step.httpStatus=reply.status;
      const marker=authScalarObservation(reply.body,assertion);
      const matched=step.phase==='anonymous-normal'?[401,403].includes(reply.status)&&marker.validJson&&!marker.matched:reply.status===assertion.status&&marker.validJson&&marker.matched;
      step.outcome=matched?'matched':'not_matched';
      if (!matched) reason=step.phase.startsWith('identity')?'identity_mismatch':step.phase==='anonymous-normal'?'anonymous_control_failed':'normal_control_mismatch';
      return matched;
    } catch {
      if (gate.counters.forwarded>before) {step.attempt=before+1;step.outcome='transport_error';}
      reason=interrupted()??(gate.stopReason()==='body_limit'?'body_limit':'transport_error'); return false;
    }
  };
  try {
    const path=await workerPath(); if (!path) {reason='worker_failed';throw new Error('stop');}
    evidence.workerSha256=hash(await readFile(path));
    const resolved=await resolveDastOrigin(p.policy.baseUrl,p.allowPrivate,control.signal);
    if (interrupted()) {reason=interrupted()!;throw new Error('stop');}
    gate=await startEgressGate({origin:resolved.origin,address:resolved.address,methods:new Set(['GET']),maxRequests:p.maxRequests,maxSingleBodyBytes:p.maxBodyBytes,
      maxTotalBytes:p.maxTotalBytes,signal:control.signal,deadlineAt:control.deadlineAt,authentication:{authorization:p.authorization,operations:p.selection.operations.map(o=>o.path),
        controlPaths:[p.policy.identity.path,...p.policy.operations.map(o=>o.normal.path)],generatedMaxRequests:p.maxRequests-(2+3*n)}},runtime);
    gate.onStop(stopEngine);
    for (let i=0;i<1+2*n;i++) if (!await runControl(i)) throw new Error('stop');
    gate.authenticated!.beginGeneration();
    try {
      const job={version:3,mode:'live-auth',proxy:gate.proxyUrl,baseUrl:'http://wakeio-schemathesis.invalid/',schema:p.selection.document,operations:p.selection.operations,
        maxRequests:p.maxRequests-(2+3*n),timeoutMs:Math.max(1,control.deadlineAt-Date.now()),maxBodyBytes:p.maxBodyBytes,maxTotalBytes:p.maxTotalBytes,seed:p.seed};
      const output=await superviseWorker(p.python,['-I',path],JSON.stringify(job),engine.signal,OUTPUT_CAP,true);
      const parsed=workerOutput(output.stdout,new Set(evidence.operations.map(o=>o.operation)),job.maxRequests,evidence.workerSha256);
      result=parsed.result;
      if (parsed.invalid) reason='worker_invalid';
      else if (output.exitCode!==0 || !parsed.final) reason='worker_failed';
      else if (result?.reason!=='complete') reason=result?.reason??'worker_failed';
    } catch {reason='worker_failed';} finally {gate.authenticated!.finishGeneration();}
    if (!interrupted() && !gate.stopReason()) {
      for (let i=1+2*n;i<controls.length;i++) if (!await runControl(i)) break;
    }
  } catch { if (reason==='complete') reason=interrupted()??'transport_error'; }
  finally {control.signal.removeEventListener('abort',stopEngine);control.dispose();await gate?.close();}
  if (gate) {
    const wire=gate.authenticated!.observations;
    evidence.requests={attempted:gate.counters.forwarded,generated:wire.length,completedGenerated:wire.filter(w=>w.completed).length,responseBytes:gate.counters.responseBytes};
    for (let i=0;i<n;i++) { evidence.operations[i].generatedRequests=wire.filter(w=>w.operationIndex===i).length; evidence.operations[i].deniedRequests=wire.filter(w=>w.operationIndex===i&&[401,403].includes(w.status??0)).length; }
    if (result) {
      evidence.engineVersion=result.engineVersion; evidence.runtime=result.runtime;
      let coherent=true;
      for (let i=0;i<result.records.length;i++) {
        const r=result.records[i], w=wire[i], index=evidence.operations.findIndex(o=>o.operation===r.operation);
        if (!w || !w.completed || index!==w.operationIndex || r.status!==w.status) {coherent=false;break;}
        evidence.records.push({ordinal:i+1,operationIndex:index,attempt:w.attempt,status:r.status,check:r.check,inputFingerprint:r.inputFingerprint,failures:r.failures});
      }
      if (!coherent || result.status==='completed' && (result.requestCount!==wire.length || result.records.length!==wire.length
        || result.operations.length!==n || new Set(result.operations.map(o=>o.operation)).size!==n
        || result.operations.some(o=>o.requests!==evidence.operations.find(x=>x.operation===o.operation)?.generatedRequests))) reason='worker_invalid';
    }
    const stopped=gate.stopReason();
    reason=interrupted()??(stopped==='body_limit'?'body_limit':stopped==='request_limit'?'request_limit':stopped?'egress_refused':reason);
    if (reason==='complete' && (gate.counters.blockedOrigin+gate.counters.blockedMethod>0 || gate.counters.rejectedEncoding>0)) reason='egress_refused';
    if (reason==='complete' && gate.counters.upstreamErrors>0) reason='transport_error';
    if (wire.some(w=>w.status!==null && w.status>=300 && w.status<=399)) reason=interrupted()??'egress_refused';
    if (evidence.operations.some(o=>o.deniedRequests>0)) reason=interrupted()??'generated_auth_denied';
    if (reason==='complete' && evidence.operations.some(o=>o.generatedRequests===0)) reason='worker_invalid';
  }
  evidence.stopReason=reason; evidence.status=reason==='complete'?'completed':'partial';
  const canonical=sanitiseSchemathesisAuth(evidence);
  const findings=gate?observations(evidence,gate,p.policy.baseUrl):[];
  return [{id:LIVE_CHECK_ID,status:canonical?.status??'partial',schemathesisAuthRequired:true,...(canonical?{schemathesisAuth:canonical}:{}),findings,
    notes:[NOTE,reason==='complete'?'Declared principal and normal controls matched before and after generation.':`Incomplete authenticated diagnostic: ${reason}.`],
    metrics:{requestCount:evidence.requests.attempted,generatedRequests:evidence.requests.generated,responseBytes:evidence.requests.responseBytes,operationsSelected:n,
      stopReason:canonical?reason:'worker_invalid',schemaSha256:p.schemaSha256,...(evidence.workerSha256?{workerSha256:evidence.workerSha256}:{}),engine:'schemathesis',engineVersion:evidence.engineVersion}}];
}
