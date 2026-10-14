import test from 'node:test';
import assert from 'node:assert/strict';
import { runBuiltinAst } from '../src/source/ast.js';
import { FLOW_LIMITS, type FlowLimits } from '../src/source/modules.js';
import { createReport, evaluateGate, toAgentReport, toMarkdown, toSarif } from '../src/report.js';
import type { SourceSnapshot } from '../src/source/types.js';
import type { CheckResult } from '../src/contracts.js';

const HTTP = 'ast:server-request', SQL = 'ast:sql-input-sink';
const SETUP = "import { Hono } from 'hono';\nconst app = new Hono();\n";
function scan(text: string, limits: FlowLimits = FLOW_LIMITS, complete = true): CheckResult {
  const snapshot: SourceSnapshot = { root: '/owned-inert-hono', files: [{ path: 'route.ts', text,
    bytes: Buffer.byteLength(text), category: 'code', sensitive: false }], issues: [], complete,
    ignoredFiles: 0, totalBytes: Buffer.byteLength(text) };
  return runBuiltinAst(snapshot, false, limits);
}
function position(text: string, needle: string) {
  const offset = text.indexOf(needle); assert.ok(offset >= 0);
  const lines = text.slice(0, offset).split('\n');
  return { path: 'route.ts', line: lines.length, column: lines.at(-1)!.length + 1 };
}
function observed(text: string, ruleId: string, source: string, sink: string) {
  const result = scan(text), matches = result.findings.filter(row => row.ruleId === ruleId);
  assert.equal(matches.length, 1, text);
  const finding = matches[0];
  assert.equal(result.status, 'completed', text);
  assert.equal(finding.kind, 'candidate'); assert.equal(finding.confidence, 'medium');
  assert.deepEqual(finding.location, position(text, sink));
  assert.ok(finding.staticFlow, 'Actual request-read source trace required');
  assert.equal(finding.staticFlow.truncated, false);
  assert.ok(finding.staticFlow.steps.some(step => step.role === 'source'
    && JSON.stringify(step.location) === JSON.stringify(position(text, source))), source);
  assert.deepEqual(finding.staticFlow.steps.at(-1), { role: 'sink', location: position(text, sink) });
  return result;
}
function noRequestFinding(text: string) {
  const result = scan(text);
  assert.equal(result.findings.filter(row => [HTTP, SQL].includes(row.ruleId)).length, 0, text);
  return result;
}

test('Hono request role: literal routes seed renamed Context query and param reads at actual source positions', () => {
  for (const name of ['c', 'incoming', 'arbitraryContextName']) for (const method of ['query', 'param']) {
    const source = `${name}.req.${method}('ownedMarker')`;
    const text = SETUP + `app.get('/item/:ownedMarker', ${name} => {\n  fetch(${source});\n});\nexport default app;`;
    const result = observed(text, HTTP, source, 'fetch(');
    assert.equal(result.metrics?.honoEntryModel, 'lexical-hono-literal-route-v1');
    assert.equal(evaluateGate(createReport([result], 'source', new Date(0)), 'high').exitCode, 1);
  }
  for (const method of ['query', 'param']) {
    const source = `c.req.${method}()`;
    observed(SETUP + `app.get('/item/:url',c=>{const {url}= ${source}; fetch(url)});`, HTTP, source, 'fetch(');
  }
});

test('Hono request role: constructor app request aliases named handlers chained routes and serving exports retain candidates', () => {
  const header = "import { Hono as Application } from 'hono';\nconst Factory=Application;\nconst original=new Factory();\nconst app=original;\n";
  const handler = "function route(incoming) { const requestAlias=incoming.req; fetch(requestAlias.query('ownedMarker')); }\nconst alias=route;\n";
  for (const end of ['export default app;', 'export const fetch=app.fetch;', 'serve({fetch:app.fetch});']) {
    observed(header + handler + "app.get('/x',alias).post('/y',c=>c.text('fixed'));\n" + end,
      HTTP, "requestAlias.query('ownedMarker')", 'fetch(');
  }
  const text = SETUP + "const route=c=>fetch(c.req.query('ownedMarker'));app.get('/x',route);";
  observed(text, HTTP, "c.req.query('ownedMarker')", 'fetch(');
});

test('Hono request role: awaited JSON reaches pg statement text and preserves existing bound-data proof boundaries', () => {
  const prefix = SETUP + "import {Pool} from 'pg';\nconst db=new Pool();\n";
  const unsafe = prefix + "app.post('/item',async c=>{\n const payload=await c.req.json<{term:string}>();\n db.query('SELECT '+payload.term);\n});export default app;";
  observed(unsafe, SQL, 'c.req.json<{term:string}>()', 'db.query(');
  const fixed = prefix + "app.post('/item',async c=>{const payload=await c.req.json();db.query('SELECT id FROM items WHERE name=$1',[payload.term]);return c.json({ok:true})});export default app;";
  const result = noRequestFinding(fixed);
  assert.equal(result.status, 'completed'); assert.equal(result.metrics?.sqlValuesOnlyExcluded,1);
  for (const method of ['query','param']) {
    const value = prefix + `app.get('/item/:term',c=>db.query('SELECT id FROM items WHERE name=$1',[c.req.${method}('term')]));`;
    const fixed = noRequestFinding(value); assert.equal(fixed.status,'completed');
    assert.equal(fixed.metrics?.sqlValuesOnlyExcluded,1);
  }
  const param = prefix + "app.get('/item/:term',c=>db.query('SELECT '+c.req.param('term')));";
  observed(param, SQL, "c.req.param('term')", 'db.query(');
});

test('Hono request role: fixed destinations bound query values and unawaited promises are negative controls', () => {
  const bodies = [
    "const term=c.req.query('term');fetch('https://owned.invalid/fixed',{body:term});return c.json({ok:true});",
    "db.query('SELECT id FROM items WHERE name=$1',[c.req.query('term')]);",
    "const pending=c.req.json();fetch(pending.url);",
    "let destination=c.req.query('url');destination='https://owned.invalid/fixed';fetch(destination);",
  ];
  for (const body of bodies) assert.equal(noRequestFinding(SETUP + `app.get('/item',async c=>{${body}});export default app;`).status, 'completed');
});

test('Hono request role: pg bound-data witness rejects mutated aliased hooked opaque and unknown JSON values', () => {
  const prefix=SETUP+"import {Pool} from 'pg';const db=new Pool();";
  for(const change of ["payload.other=custom;", "const alias=payload;", "opaque(payload);",
    "Object.defineProperty(payload,'name',{get(){return custom}});", "payload.toPostgres=custom;"]) {
    const text=prefix+`app.post('/item',async c=>{const payload=await c.req.json();${change}db.query('SELECT id FROM items WHERE name=$1',[payload.name])});`;
    const result=scan(text), rows=result.findings.filter(row=>row.ruleId===SQL);
    assert.equal(rows.length,1,change); assert.equal(rows[0].confidence,'low',change);
    assert.equal(result.metrics?.sqlValuesOnlyExcluded,0,change);
  }
  for(const read of ["await unknown(c.req.query('data'))", "JSON.parse(c.req.query('data'))",
    "flag ? await c.req.json() : await unknown(c.req.query('data'))"]) {
    const text=prefix+`app.post('/item',async c=>{const payload=${read};db.query('SELECT id FROM items WHERE name=$1',[payload.name])});`;
    const result=scan(text), rows=result.findings.filter(row=>row.ruleId===SQL);
    assert.equal(rows.length,1,read); assert.equal(rows[0].confidence,'low',read);
    assert.equal(result.metrics?.sqlValuesOnlyExcluded,0,read);
  }
});

test('Hono request role: registered and non-Hono actual contexts cannot share a globally cached SQL data witness', () => {
  const prefix=SETUP+"import {Pool} from 'pg';const db=new Pool();";
  const body="const handler=async c=>{const payload=await c.req.json();db.query('SELECT id FROM items WHERE name=$1',[payload.name])};";
  const registration="app.post('/item',handler);";
  const actual="export function wrapper(req){handler({req:{json:()=>req.body}})}";
  for(const text of [prefix+body+registration+actual,prefix+body+actual+registration]) {
    const result=scan(text), rows=result.findings.filter(row=>row.ruleId===SQL);
    assert.equal(rows.length,1,'The non-Hono request-shaped actual still has unresolved SQL data roles');
    assert.equal(rows[0].confidence,'low'); assert.equal(result.metrics?.sqlStatementInputUses,0);
  }
});

test('Hono request role: pristine const field aliases retain pg bound-data proof without accepting mutable aliases or hooks', () => {
  const prefix=SETUP+"import {Pool} from 'pg';const db=new Pool();";
  for(const capture of ["const term=payload.term;", "const term=payload['term'];", "const nested=payload.nested;const term=nested.term;"]) {
    const text=prefix+`app.post('/search',async context=>{const payload=await context.req.json();${capture}return db.query('SELECT id FROM items WHERE name=$1',[term])});export default app;`;
    const result=noRequestFinding(text); assert.equal(result.status,'completed');
    assert.equal(result.metrics?.sqlValuesOnlyExcluded,1,capture);
  }
  for(const change of ["opaque(term);", "term.toPostgres=custom;", "Object.defineProperty(term,'x',{get(){return custom}});",
    "const alias=term;", "payload.other=custom;", "Object.defineProperty(payload,'term',{get(){return custom}});"]) {
    const text=prefix+`app.post('/search',async context=>{const payload=await context.req.json();const term=payload.term;${change}return db.query('SELECT id FROM items WHERE name=$1',[term])});`;
    const result=scan(text), rows=result.findings.filter(row=>row.ruleId===SQL);
    assert.equal(rows.length,1,change); assert.equal(rows[0].confidence,'low',change);
    assert.equal(result.metrics?.sqlValuesOnlyExcluded,0,change);
  }
  for(const capture of ["let term=payload.term;", "const term=payload[field];", "const term=payload?.term;", "const term=payload.toPostgres;"]) {
    const result=scan(prefix+`app.post('/search',async context=>{const payload=await context.req.json();${capture}return db.query('SELECT id FROM items WHERE name=$1',[term])});`);
    assert.equal(result.metrics?.sqlValuesOnlyExcluded,0,capture);
  }
});

test('Hono request role: repeated or cached JSON return identity remains unknown without assuming newer Hono freshness', () => {
  const prefix=SETUP+"import {Pool} from 'pg';const db=new Pool();";
  for(const effect of [
    "const alias=await c.req.json();alias.toPostgres=custom;",
    "const r=c.req;const alias=await r.json();alias.toPostgres=custom;",
    "function change(context){const pending=context.req.json();opaque(pending)}change(c);",
    "const cache=c.req.bodyCache;opaque(cache);",
    "opaque(c);",
  ]) {
    const text=prefix+`app.post('/item',async c=>{const payload=await c.req.json();${effect}db.query('SELECT $1',[payload])});`;
    const result=scan(text), rows=result.findings.filter(row=>row.ruleId===SQL);
    assert.equal(rows.length,1,effect); assert.equal(rows[0].confidence,'low',effect);
    assert.equal(result.metrics?.sqlValuesOnlyExcluded,0,effect);
  }
  const captured=prefix+"app.post('/item',async c=>{const pending=c.req.json();c.req={};const payload=await pending;db.query('SELECT $1',[payload])});";
  const retained=scan(captured), rows=retained.findings.filter(row=>row.ruleId===SQL);
  assert.equal(rows.length,1); assert.equal(rows[0].confidence,'low');
  assert.equal(retained.metrics?.sqlValuesOnlyExcluded,0,
    'Captured input remains, but request mutation is outside the isolated JSON data proof');
  for(const effect of ["const alias=await c.req.json();alias.toPostgres=custom;",
    "const alias=await c.req.bodyCache.json;alias.toPostgres=custom;", "opaque(c.req);"]) {
    const text=prefix+`app.post('/item',async c=>{const payload=await c.req.json();const values=[payload];${effect}db.query('SELECT $1',values)});`;
    const result=scan(text), rows=result.findings.filter(row=>row.ruleId===SQL);
    assert.equal(rows.length,1,effect); assert.equal(rows[0].confidence,'low',effect);
    assert.equal(result.metrics?.sqlValuesOnlyExcluded,0,effect);
    const config=prefix+`app.post('/item',async c=>{const payload=await c.req.json();const values=[payload];const config={text:'SELECT $1',values};${effect}db.query(config)});`;
    const configured=scan(config), configRows=configured.findings.filter(row=>row.ruleId===SQL);
    assert.equal(configRows.length,1,effect); assert.equal(configRows[0].confidence,'low',effect);
    assert.equal(configured.metrics?.sqlValuesOnlyExcluded,0,effect);
  }
  const future=prefix+"app.post('/item',async c=>{const payload=await c.req.json();db.query('SELECT $1',[payload]);const alias=await c.req.bodyCache.json;alias.toPostgres=custom});";
  assert.equal(scan(future).metrics?.sqlValuesOnlyExcluded,0,
    'Whole-use prerequisites cover later cached-body effects and asynchronous pg preparation');
  const ordinary=prefix+"const marker=JSON.stringify({ok:true});const sample=new Request('https://owned.invalid/');app.post('/item',async c=>{const payload=await c.req.json();const term=payload.term;return db.query('SELECT $1',[term])});";
  assert.equal(noRequestFinding(ordinary).metrics?.sqlValuesOnlyExcluded,1,
    'Ordinary direct JSON serialization and fresh Request allocation are not parser modification');
});

test('Hono request role: JSON SQL exclusion requires isolated registration and no unknown continuation effects', () => {
  const prefix=SETUP+"import {Pool} from 'pg';const db=new Pool();";
  const reader="app.post('/item',async c=>{const payload=await c.req.json();db.query('SELECT $1',[payload])});";
  const changer="app.post('/item',async(c,next)=>{const alias=await c.req.json();alias.toPostgres=custom;await next()});";
  for(const text of [prefix+changer+reader,prefix+reader+changer,
    prefix+"app.get('/elsewhere',c=>c.text('fixed'));"+reader]) {
    const result=scan(text), rows=result.findings.filter(row=>row.ruleId===SQL);
    assert.equal(rows.length,1,'Multiple entries cannot prove independent JSON objects');
    assert.equal(rows[0].confidence,'low'); assert.equal(result.metrics?.sqlValuesOnlyExcluded,0);
  }
  const continuation=prefix+"app.post('/item',async(c,next)=>{const payload=await c.req.json();await next();db.query('SELECT $1',[payload])});";
  const result=scan(continuation), rows=result.findings.filter(row=>row.ruleId===SQL);
  assert.equal(result.status,'partial'); assert.equal(rows.length,1); assert.equal(rows[0].confidence,'low');
  assert.equal(result.metrics?.sqlValuesOnlyExcluded,0);
});

test('Hono request role: pruning escaped prior handler proof cannot erase an observed shared-context registration', () => {
  const prefix=SETUP+"import {Pool} from 'pg';const db=new Pool();";
  const prior="async function prior(c,next){c.req.bodyCache.json=Promise.resolve({toPostgres(){return 'owned'}});return next()}opaque(prior);";
  const reader="app.post('/item',async c=>{const payload=await c.req.json();db.query('SELECT $1',[payload])});";
  for(const registrations of ["app.post('/item',prior);"+reader,reader+"app.post('/item',prior);"]) {
    const result=scan(prefix+prior+registrations), rows=result.findings.filter(row=>row.ruleId===SQL);
    assert.equal(rows.length,1,'An escaped handler can still be registered and affect the cached body');
    assert.equal(rows[0].confidence,'low');
    assert.equal(rows[0].title,'Input-related SQL API argument roles are unresolved');
    assert.ok(rows[0].staticFlow?.steps.some(step=>step.role==='source'),'Captured request input must remain');
    assert.equal(result.metrics?.sqlValuesOnlyExcluded,0);
  }
});

test('Hono request role: captured scalar and JSON promise keep prior provenance after request replacement', () => {
  const query = SETUP + "app.get('/item',c=>{const target=c.req.query('url');c.req={query:()=> 'fixed'};fetch(target)});";
  observed(query, HTTP, "c.req.query('url')", 'fetch(');
  const pending = SETUP + "app.post('/item',async c=>{const pending=c.req.json();c.req={query:()=> 'fixed'};const body=await pending;fetch(body.url)});";
  observed(pending, HTTP, 'c.req.json()', 'fetch(');
  const opaque = SETUP + "app.post('/item',async c=>{const pending=c.req.json();opaque(pending);const body=await pending;fetch(body.url)});";
  assert.equal(noRequestFinding(opaque).status, 'partial', 'Opaque promise effects remain unresolved');
});

test('Hono request role: fake names local and type-only imports unrelated callbacks never become Hono request sources', () => {
  const handler = "c=>fetch(c.req.query('url'))";
  for (const text of [
    `const app={get(){}};app.get('/item',${handler});`,
    `import {Hono} from './local-hono';const app=new Hono();app.get('/item',${handler});`,
    `import type {Hono} from 'hono';const app=new Hono();app.get('/item',${handler});`,
    `import {type Hono} from 'hono';const app=new Hono();app.get('/item',${handler});`,
    `import * as packageAlias from 'hono';const app=new packageAlias.Hono();app.get('/item',${handler});`,
    `export function route(c){fetch(c.req.query('url'))}`,
    SETUP + `other.get('/item',${handler});`,
    SETUP + `app.onError(${handler});`,
    SETUP + `app.get('/item',(c,next)=>fetch(next.req.query('url')));`,
  ]) noRequestFinding(text);
  observed("import {Hono,type Context} from 'hono';const app=new Hono();app.get('/item',c=>fetch(c.req.query('url')));",
    HTTP, "c.req.query('url')", 'fetch(');
});

test('Hono request role: constructor application handler mutations and fluent result escapes revoke registration proof', () => {
  const handler = "c=>fetch(c.req.query('url'))";
  for (const change of ["Hono.prototype.get=custom;", "opaque(Hono);", "app.get=custom;", "opaque(app);", "const alias=app;alias.get=custom;",
    "Object.defineProperty(app,'get',{value:custom});"]) noRequestFinding(SETUP + change + `app.get('/item',${handler});`);
  for (const source of [
    SETUP + `const escaped=app.get('/item',${handler});escaped.get=custom;`,
    SETUP + `opaque(app.get('/item',${handler}));`,
    "import {Hono,Context} from 'hono';const app=new Hono();" + `app.get('/item',${handler});`,
    SETUP + `const handler=${handler};handler.length=0;app.get('/item',handler);`,
    SETUP + `let application=app;application.get('/item',${handler});`,
  ]) noRequestFinding(source);
});

test('Hono request role: unsupported registrations reads detached methods and request escapes never certify source authority', () => {
  const handler = "c=>fetch(c.req.query('url'))";
  for (const registration of [`app.get(dynamicPath,${handler});`, `app.get('/item',middleware,${handler});`,
    `app.use('/item',${handler});`, `app.route('/item',child);app.get('/other',${handler});`,
    `app['get']('/item',${handler});`, `app.get('/item',wrapper(${handler}));`]) noRequestFinding(SETUP + registration);
  for (const body of ["const read=c.req.query;fetch(read('url'));", "c.req.query=()=> 'fixed';fetch(c.req.query('url'));",
    "delete c.req.query;fetch(c.req.query('url'));", "opaque(c.req);fetch(c.req.query('url'));",
    "fetch(c.req.query('url','extra'));", "fetch(c.req.query(...args));", "fetch(c.req.query?.('url'));",
    "fetch(c.req[method]('url'));", "fetch(c.req.json({}));"]) noRequestFinding(SETUP + `app.get('/item',c=>{${body}});`);
});

test('Hono request role: low indexing and flow budgets preserve incomplete status and scope remains bounded', () => {
  const text = SETUP + "app.get('/item',c=>fetch(c.req.query('url')));export default app;";
  for (const limits of [{...FLOW_LIMITS,indexWork:1}, {...FLOW_LIMITS,flowWork:1}]) {
    const check = scan(text, limits); assert.equal(check.status, 'partial');
    assert.equal(evaluateGate(createReport([check], 'source', new Date(0)), 'none').exitCode, 2);
  }
  assert.equal(scan(text,FLOW_LIMITS,false).findings.filter(row=>row.ruleId===HTTP).length,0);
});

test('Hono request role: report projections retain trace and not_run without exposing source query markers', () => {
  const text = SETUP + "app.get('/item',c=>fetch(c.req.query('ownedHonoPrivateMarker')));export default app;";
  const check = observed(text,HTTP,"c.req.query('ownedHonoPrivateMarker')",'fetch(');
  const report = createReport([check],'source',new Date(0)), agent = toAgentReport(report);
  assert.equal(agent.findings[0].verification.state,'not_run');
  assert.equal(agent.findings[0].verification.vulnerabilityConfirmed,false);
  for (const output of [JSON.stringify(report),JSON.stringify(agent),toMarkdown(report),JSON.stringify(toSarif(report))]) {
    assert.equal(output.includes('ownedHonoPrivateMarker'),false);
    assert.equal(output.includes(text),false);
  }
});
