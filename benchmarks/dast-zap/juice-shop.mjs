// OWASP Juice Shop v19.0.0, MIT. Only owned Docker IDs and loopback HTTP are controlled.
import { spawn, execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createServer } from 'node:http';
import { createInterface } from 'node:readline';
import { mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
const exec = promisify(execFile);
export const JUICE_IMAGE = 'bkimminich/juice-shop@sha256:2765a26de7647609099a338d5b7f61085d95903c8703bb70f03fcc4b12f0818d';
export const JUICE_SOURCE = '36870cbbdfe7864698e1adf644c7bf772f67ebb7';
export const JUICE_ORIGINAL_SHA = '073059f1600484467f9039b3989314c7aacd6a806ec679d5afc4a8f91b6e9b3c';
export const JUICE_FIXED_SHA = 'a26713609ed5a6622af93ef6e56863f4396f0e7d99b36c65395e836fe9d738a7';
const sha = b => createHash('sha256').update(b).digest('hex');
const docker = async (...args) => (await exec('docker', args, { maxBuffer: 2 * 1024 * 1024, timeout: 30000 })).stdout.trim();
export function fixJuiceSearch(source) {
  if (sha(source) !== JUICE_ORIGINAL_SHA) throw Error('unexpected_juice_search_source');
  const before = "models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)";
  const after = "models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`, { replacements: { criteria: '%' + criteria + '%' } })";
  const fixed = source.toString().replace(before, after);
  if (sha(fixed) !== JUICE_FIXED_SHA) throw Error('unexpected_juice_fix'); return fixed;
}
// One persistent private IPC bridge keeps the container network disabled. Actual HTTP still reaches its real Express/Sequelize application.
const BRIDGE = `const http=require('http'),rl=require('readline').createInterface({input:process.stdin});
rl.on('line',line=>{const q=JSON.parse(line);const req=http.request({host:'127.0.0.1',port:3000,path:q.path,method:q.method,headers:q.headers,agent:false},res=>{
let size=0,chunks=[];res.on('data',b=>{size+=b.length;if(size>2097152)req.destroy();else chunks.push(b)});res.on('end',()=>process.stdout.write(JSON.stringify({id:q.id,status:res.statusCode,headers:res.headers,body:Buffer.concat(chunks).toString('base64')})+'\\n'));res.on('error',()=>process.stdout.write(JSON.stringify({id:q.id,error:true})+'\\n'));});
req.setTimeout(10000,()=>req.destroy());req.on('error',()=>process.stdout.write(JSON.stringify({id:q.id,error:true})+'\\n'));req.end(Buffer.from(q.body,'base64'));});`;

export async function startJuiceShop(fixed = false) {
  if (process.env.WAKEIO_OWNED_JUICE_SHOP !== '1') throw Error('explicit_owned_juice_shop_opt_in_required');
  const metadata = JSON.parse(await docker('image', 'inspect', JUICE_IMAGE));
  if (!metadata[0]?.Config?.Labels?.['org.opencontainers.image.revision']?.startsWith(JUICE_SOURCE.slice(0, 7))) throw Error('unexpected_juice_image_revision');
  const directory = await mkdtemp(join(tmpdir(), 'owned-wakeio-juice-')), pending = new Map(), seen = [];
  let id, inspectId, bridge, server, serial = 0;
  const close = async () => {
    if (id) await docker('rm', '-f', id).catch(() => {});
    if (inspectId) await docker('rm', '-f', inspectId).catch(() => {});
    bridge?.kill(); for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(Error('owned_target_closed')); } pending.clear();
    if (server) { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
    await rm(directory, { recursive: true, force: true });
  };
  try {
    const args = ['run', '-d', '--network', 'none', '--log-driver', 'none', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--memory', '768m', '--label', 'wakeio.benchmark=zap-openapi'];
    if (fixed) {
      inspectId = await docker('create', JUICE_IMAGE); const sourcePath = join(directory, 'original.js'), patchPath = join(directory, 'search.js');
      await docker('cp', `${inspectId}:/juice-shop/build/routes/search.js`, sourcePath); await writeFile(patchPath, fixJuiceSearch(await readFile(sourcePath)));
      await docker('rm', inspectId); inspectId = undefined;
      args.push('--mount', `type=bind,source=${patchPath},target=/juice-shop/build/routes/search.js,readonly`);
    }
    id = await docker(...args, JUICE_IMAGE);
    bridge = spawn('docker', ['exec', '-i', id, '/nodejs/bin/node', '-e', BRIDGE], { stdio: ['pipe', 'pipe', 'ignore'] });
    const failed = () => { for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(Error('owned_target_transport')); } pending.clear(); };
    bridge.on('error', failed); bridge.on('exit', failed); bridge.stdin.on('error', failed);
    const lines = createInterface({ input: bridge.stdout });
    lines.on('line', line => { try { const result = JSON.parse(line), p = pending.get(result.id); if (p) { pending.delete(result.id); clearTimeout(p.timer); result.error ? p.reject(Error('owned_target_transport')) : p.resolve(result); } } catch { failed(); } });
    server = createServer(async (req, res) => {
      try {
        const chunks = []; let size = 0; for await (const b of req) { size += b.length; if (size > 16384) throw Error('owned_body_limit'); chunks.push(b); }
        const path = new URL(req.url, 'http://owned').pathname;
        if (!['/api/Users', '/rest/user/login', '/rest/products/search'].includes(path) && !/^\/rest\/basket\/\d+$/.test(path)) { res.writeHead(404); res.end(); return; }
        const observation = { method: req.method, path, completed:false }; seen.push(observation);
        const requestId = ++serial;
        const result = await new Promise((resolve, reject) => { if (bridge.exitCode !== null || bridge.stdin.destroyed) { reject(Error('owned_target_transport')); return; } const timer=setTimeout(()=>{pending.delete(requestId);reject(Error('owned_target_timeout'));},12000);pending.set(requestId, {resolve,reject,timer}); bridge.stdin.write(JSON.stringify({ id: requestId, method: req.method, path: req.url,
          headers: req.headers, body: Buffer.concat(chunks).toString('base64') }) + '\n'); });
        observation.completed = true;
        res.writeHead(result.status, { ...result.headers, connection: 'close' }); res.end(Buffer.from(result.body, 'base64'));
      } catch { res.destroy(); }
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const origin = `http://127.0.0.1:${server.address().port}`, setup = async (path, options = {}) => fetch(origin + path, { ...options, redirect: 'error', signal: AbortSignal.timeout(15000) });
    let ready = false; const deadline=Date.now()+45000;
    for (let i = 0; i < 120 && Date.now()<deadline; i++) { try { if ((await setup('/rest/products/search?q=apple')).status === 200) { ready = true; break; } } catch {} await new Promise(r => setTimeout(r, 250)); }
    if (!ready) throw Error('owned_juice_not_ready');
    const email = `wakeio-${randomBytes(8).toString('hex')}@example.test`, password = randomBytes(24).toString('hex');
    const post = body => ({ method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(body) });
    const registration = await setup('/api/Users', post({email,password,passwordRepeat:password})); if (registration.status !== 201) throw Error('owned_registration_failed');
    const userId = (await registration.json()).data.id;
    const loggedIn = await setup('/rest/user/login', post({email,password})); if (loggedIn.status !== 200) throw Error('owned_login_failed');
    const authentication = (await loggedIn.json()).authentication, basketId = authentication.bid;
    if (!Number.isSafeInteger(userId) || !Number.isSafeInteger(basketId)) throw Error('owned_fixture_identity');
    const policy = { version:2, kind:'zap-active', origin, openapi:{ document:{openapi:'3.0.3',info:{title:'Pinned Juice Shop search scope',version:'19.0.0'},paths:{'/rest/products/search':{get:{parameters:[{name:'q',in:'query',required:true,schema:{type:'string',default:'apple'}}],responses:{'200':{description:'Search'}}}}}},operations:[{method:'GET',path:'/rest/products/search'}]},
      authentication:{login:{path:'/rest/user/login',format:'json',fields:{email:'OWNED_JUICE_EMAIL',password:'OWNED_JUICE_PASSWORD'}},session:{type:'bearer',tokenPointer:'/authentication/token'},identity:{path:`/rest/basket/${basketId}`,status:200,jsonPointer:'/data/UserId',equals:userId},maxAttempts:4} };
    return { origin, policy, env:{OWNED_JUICE_EMAIL:email,OWNED_JUICE_PASSWORD:password}, seen, setupRequests:seen.length,
      metadata:{image:JUICE_IMAGE,sourceCommit:JUICE_SOURCE,fix:fixed?'parameterized-search-only':'unmodified',routeSha256:fixed?JUICE_FIXED_SHA:JUICE_ORIGINAL_SHA,network:'none',transport:'owned loopback observer plus persistent Docker IPC to real container HTTP'},close };
  } catch (error) { await close(); throw error; }
}
