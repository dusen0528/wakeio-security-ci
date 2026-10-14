#!/usr/bin/env node
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdir, readFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startFixture } from './fixture.mjs';
import { prepare, runArm, save, sha } from './run.mjs';
import { projectArm } from './score.mjs';

const directory = dirname(fileURLToPath(import.meta.url)), root = resolve(directory, '../../../..');
const arg = name => { const i=process.argv.indexOf(name); if(i<0 || !process.argv[i+1]) throw Error('missing '+name); return process.argv[i+1]; };
if (!process.argv.includes('--active-consent') || process.env.WAKEIO_AGENT_LIVE !== '1') throw Error('explicit_consent_and_live_optin_required');
const out=resolve(arg('--out')), evaluator=resolve(arg('--evaluator-root')), commit=arg('--criteria-commit');
if(!/^[a-f0-9]{40}$/.test(commit)) throw Error('invalid_criteria_commit');
const readJson=async path=>JSON.parse(await readFile(path,'utf8'));
const frozen=['criteria.json','acceptance.json','checklist.json','approval.json'].map(name=>'benchmarks/agent-eval/targets/local-sqlite/'+name);
frozen.push('benchmarks/agent-eval/labels/local-sqlite.labels.json');
execFileSync('git',['merge-base','--is-ancestor',commit,'HEAD'],{cwd:root});
execFileSync('git',['diff','--exit-code','HEAD'],{cwd:root,stdio:'pipe'});
const published=execFileSync('gh',['api',`repos/dusen0528/wakeio-security-ci/commits/${commit}`,'--jq','.sha'],{encoding:'utf8'}).trim();
assert.equal(published,commit);
const hashes={};
for(const path of frozen){const bytes=await readFile(join(root,path));assert.equal(sha(bytes),sha(execFileSync('git',['show',`${commit}:${path}`],{cwd:root})));hashes[path]=sha(bytes);}
const load=name=>import(pathToFileURL(join(evaluator,'build/src/agent-dast/eval',name+'.js')).href);
const labelApi=await load('labels'),manifestApi=await load('manifest'),aggregateApi=await load('aggregate'),storedApi=await load('stored-results');
const labelPath=join(root,'benchmarks/agent-eval/labels/local-sqlite.labels.json');
const labels=labelApi.finalLabels(labelApi.parseLabelSet(await readJson(labelPath)));
const criteria=aggregateApi.parsePassCriteria(await readJson(join(directory,'criteria.json')));
const checklist=manifestApi.parseChecklist(await readJson(join(directory,'checklist.json')));
const acceptance=await readJson(join(directory,'acceptance.json'));
assert.equal(acceptance.repeats,5);assert.equal(criteria.sharedRequestCap,64);
assert.equal(sha(await readFile(join(directory,'fixture.mjs'))),sha(execFileSync('git',['show',`${labels.commit}:benchmarks/agent-eval/targets/local-sqlite/fixture.mjs`],{cwd:root})));
await mkdir(out,{mode:0o700});
const {publicKey,privateKey}=generateKeyPairSync('ed25519');
const fixture=await startFixture({activeConsent:true});
const results={A:[],B:[]},reports=[];
try{
 const prepared=await prepare(fixture,join(out,'inputs'),['/items','/lookup']);
 const manifests=Array.from({length:5},(_,i)=>manifestApi.buildRunManifest({runId:`run-local-sqlite-${i+1}`,createdAt:new Date().toISOString(),labels,criteria,checklist,coverageCells:prepared.coverageCells}));
 const declaration={version:1,createdAt:new Date().toISOString(),criteriaCommit:commit,codeCommit:execFileSync('git',['rev-parse','HEAD'],{cwd:root,encoding:'utf8'}).trim(),publishedCommitVerified:true,hashes,origin:fixture.origin,manifests:manifests.map(manifestApi.manifestDigest),scope:await readJson(join(directory,'approval.json'))};
 const message=JSON.stringify(declaration),signature=sign(null,Buffer.from(message),privateKey).toString('base64');
 assert.ok(verify(null,Buffer.from(message),publicKey,Buffer.from(signature,'base64')));
 await save(join(out,'precommit-attestation.json'),{declaration,signature,publicKey:publicKey.export({type:'spki',format:'pem'})});
 for(let i=0;i<5;i++)await save(join(out,`manifest-${i+1}.json`),manifests[i]);
 for(const arm of ['A','B'])for(let i=0;i<5;i++){
  const run=await runArm(arm,fixture,prepared,join(out,`${arm}-${i+1}`),criteria.sharedRequestCap);
  results[arm].push(run);await save(join(out,`${arm}-${i+1}.json`),run);
  console.log(JSON.stringify({arm,repeat:i+1,status:run.status,exitCode:run.exitCode,requests:run.actualRequests,rounds:run.rounds.length}));
 }
 for(let i=0;i<5;i++){
  const a=results.A[i],b=results.B[i];
  if(a.exitCode===2 || b.exitCode===2){reports.push({repeat:i+1,complete:false,reason:'incomplete_arm'});continue;}
  try{
   const bundle=aggregateApi.parseResultsBundle({manifestDigest:manifestApi.manifestDigest(manifests[i]),armA:await projectArm(a),armB:await projectArm(b)});
   const resultFile=join(out,`results-${i+1}.json`);await save(resultFile,bundle);
   const readers={A:storedApi.storedRunReader(a.rounds[0].outDir),B:storedApi.storedRunReader(b.rounds[0].outDir)};
   const reader=finding=>readers[bundle.armA.findings.includes(finding)?'A':'B'];
   const evaluated=aggregateApi.evaluate({manifest:manifests[i],bundle,labels,criteria,checklist,evidenceChecked:true,
    readEvidence:(path,finding)=>reader(finding).readEvidence(path),verifyStoredFinding:(finding,evidence)=>reader(finding).verifyStoredFinding(finding,evidence)});
   const cli=JSON.parse(execFileSync(process.execPath,[join(evaluator,'benchmarks/agent-eval/aggregate.mjs'),'--labels',labelPath,'--criteria',join(directory,'criteria.json'),'--checklist',join(directory,'checklist.json'),'--manifest',join(out,`manifest-${i+1}.json`),'--results',resultFile,'--run-a',a.rounds[0].outDir,'--run-b',b.rounds[0].outDir],{encoding:'utf8',maxBuffer:1024*1024,stdio:['ignore','pipe','pipe']}));
   assert.equal(cli.provenanceAllOk,true);assert.equal(evaluated.manifestVerified,true);assert.deepEqual(cli.comparison,evaluated.comparison);
   await save(join(out,`cli-${i+1}.json`),cli);
   reports.push({repeat:i+1,complete:true,...evaluated,provenanceAllOk:cli.provenanceAllOk});
  }catch(error){reports.push({repeat:i+1,complete:false,reason:error.message});}
 }
 const statistics=values=>{const mean=values.reduce((a,b)=>a+b,0)/values.length;return {mean,min:Math.min(...values),max:Math.max(...values),variance:values.reduce((s,x)=>s+(x-mean)**2,0)/values.length};};
 const complete=reports.every(r=>r.complete&&r.manifestVerified&&r.provenanceAllOk);
 const qualityHeld=complete&&reports.every(r=>r.comparison.qualityHeld&&r.comparison.a.score.tp===1&&r.comparison.a.score.fp===0&&r.comparison.a.score.fn===0);
 const stats=Object.fromEntries(['A','B'].map(arm=>[arm,{requests:statistics(results[arm].map(r=>r.actualRequests)),durationMs:statistics(results[arm].map(r=>r.durationMs)),tokens:complete?statistics(reports.map(r=>r.comparison[arm.toLowerCase()].tokens)):null}]));
 const valueProven=qualityHeld&&(stats.B.requests.mean<stats.A.requests.mean||stats.B.durationMs.mean<stats.A.durationMs.mean);
 await save(join(out,'evaluation.json'),{version:1,complete,qualityHeld,valueProven,verdict:valueProven?'pass':'defer',criteriaCommit:commit,attestation:'precommit-attestation.json',stats,pairs:reports,limitations:acceptance.limitations});
 console.log(JSON.stringify({complete,qualityHeld,valueProven,verdict:valueProven?'pass':'defer',stats}));
 if(!complete)process.exitCode=2;
}finally{await fixture.close();}
