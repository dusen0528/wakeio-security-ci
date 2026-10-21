import assert from 'node:assert/strict';
import { readFile, writeFile, appendFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { arch, platform } from 'node:os';
import { runZap, ZAP_VERSION, ZAP_OPENAPI_REVISION } from '../../build/src/zap.js';
import { zapSurfaceKey } from '../../build/src/zap-policy.js';
import { zapSessionTarget } from '../../build/tests/fixtures/zap-session-target.js';
import { startJuiceShop } from './juice-shop.mjs';
const repeats = Number(process.argv[2] ?? 5), output = process.argv[3], selection = process.argv[4] ?? 'all';
if (!Number.isInteger(repeats) || repeats < 1 || repeats > 5 || !output || !['all','reference','juiceShop'].includes(selection) || !process.env.WAKEIO_ZAP_PATH) throw Error('Usage: WAKEIO_ZAP_PATH=/prepared/zap.sh WAKEIO_OWNED_JUICE_SHOP=1 node benchmarks/dast-zap/measure-applications.mjs [1..5] OUTPUT.json [all|reference|juiceShop]');
const runtimeFiles = ['build/src/zap.js','build/src/zap-policy.js','build/src/zap-openapi.js','build/src/zap-session.js','build/src/dast-egress.js','build/tests/fixtures/zap-session-target.js','benchmarks/dast-zap/juice-shop.mjs','benchmarks/dast-zap/measure-applications.mjs'];
const fingerprint = async () => createHash('sha256').update(JSON.stringify(await Promise.all(runtimeFiles.map(async file => [file,createHash('sha256').update(await readFile(file)).digest('hex')])))).digest('hex');
const runtimeSha256 = await fingerprint();
const labelBytes = await readFile(new URL('./application-labels.json', import.meta.url)), truth = JSON.parse(labelBytes), rounds = [];
await writeFile(output + '.jsonl', '', { flag: 'wx' });
for (let round = 1; round <= repeats; round++) for (const application of selection === 'all' ? ['reference', 'juiceShop'] : [selection]) for (const fixed of [false, true]) {
  const provisionStart = performance.now(), target = application === 'reference' ? await zapSessionTarget({ fixed, expire: true }) : await startJuiceShop(fixed);
  const provisionMs = performance.now() - provisionStart, startCount = target.seen.length;
  try {
    const started = performance.now(), check = (await runZap({ url: target.origin, policy: target.policy, env: target.env,
      executable: process.env.WAKEIO_ZAP_PATH, consent: true, allowPrivate: true, maxRequests: 200, rateLimit: 50, timeoutMs: 120000 }))[0];
    const elapsedMs = Number((performance.now() - started).toFixed(2)), observations = target.seen.slice(startCount);
    assert.equal(check.metrics.requestCount, observations.length);
    assert.ok(observations.every(q => q.completed !== false), 'Every completed response must come from the actual application');
    const found = new Set(check.findings.map(f => f.comparisonKey)), known = new Set(); let TP=0,FP=0,FN=0,TN=0;
    for (const label of truth[application]) {
      const key=zapSurfaceKey(label.rule.slice(4),label,label.parameter);known.add(key);
      if (!fixed && label.vulnerable) found.has(key)?TP++:FN++; else found.has(key)?FP++:TN++;
    }
    FP += [...found].filter(key=>!known.has(key)).length;
    const row={round,application,mode:fixed?'fixed':'vulnerable',status:check.status,stopReason:check.metrics.stopReason,TP,FP,FN,TN,
      elapsedMs,provisionMs:Number(provisionMs.toFixed(2)),requests:observations.length,cap:200,loginRequests:check.metrics.loginRequests,
      refreshRequests:check.metrics.refreshRequests,authChallenges:check.metrics.authChallenges,sourceSha256:check.metrics.openapiSourceSha256,
      projectionSha256:check.metrics.openapiProjectionSha256,target:target.metadata??{implementation:'owned SQLite product API with login, refresh and nested filter',auth:'JSON/Bearer',expiry:'first token expires after six protected probes'},
      requestKinds:Object.fromEntries([...new Set(observations.map(q=>q.method+' '+q.path))].map(key=>[key,observations.filter(q=>q.method+' '+q.path===key).length]))};
    rounds.push(row);await appendFile(output+'.jsonl',JSON.stringify(row)+'\n');console.log(JSON.stringify(row));
  } finally { await target.close(); }
}
const summaries = [];
for (const application of [...new Set(rounds.map(r=>r.application))]) for (const mode of ['vulnerable','fixed']) {
 const rows=rounds.filter(r=>r.application===application&&r.mode===mode),times=rows.map(r=>r.elapsedMs).sort((a,b)=>a-b);
 summaries.push({application,mode,repeats:rows.length,completed:rows.filter(r=>r.status==='completed').length,
  TP:rows.map(r=>r.TP),FP:rows.map(r=>r.FP),FN:rows.map(r=>r.FN),TN:rows.map(r=>r.TN),p50Ms:times[Math.ceil(times.length*.5)-1],maxMs:times.at(-1),requests:rows.map(r=>r.requests)});
}
assert.equal(await fingerprint(), runtimeSha256, 'Runtime changed during official measurement');
await writeFile(output, JSON.stringify({version:1,measuredAt:new Date().toISOString(),engine:ZAP_VERSION,profile:ZAP_OPENAPI_REVISION,
 runtime:{node:process.version,platform:platform(),arch:arch()},runtimeSha256,labelsSha256:createHash('sha256').update(labelBytes).digest('hex'),rounds,summaries,
 limits:['Paired scope only, not whole-service security or production accuracy.','Same API profile, selected operations, caps and engine for vulnerable/fixed comparisons.','Timed scan includes startup, login, renewal, controls, import, attack, shutdown and cleanup; provisioning is separate.','Juice Shop uses network-disabled Docker plus private IPC/HTTP observation; its transport time differs from direct reference HTTP.','Unsupported/not-selected challenges are explicitly not tested, never counted as TN.','No hidden split, agent/model comparison or optimization percentage is claimed.']},null,2)+'\n',{flag:'wx'});
