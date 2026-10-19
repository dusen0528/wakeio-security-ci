import { chmod, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
/** Protocol stand-in for transport/control failure tests, never detection claims. */
export async function zapPolicyEngine(directory: string, count = 2, delay = 0): Promise<string> {
  const file = join(directory, `zap-${count}-${delay}.mjs`);
  await writeFile(file, `#!/usr/bin/env node
import {request} from 'node:http'; import {readFileSync,writeFileSync} from 'node:fs'; import {join} from 'node:path';
if(process.argv.includes('-version')) {console.log('2.17.0');process.exit(0);}
const plan=JSON.parse(readFileSync(process.argv[process.argv.indexOf('-autorun')+1],'utf8')), proxy=plan.env.proxy;
const seeds=plan.jobs.find(j=>j.type==='requestor').requests;
for(let i=0;i<${count};i++) { const seed=seeds[i%seeds.length]; await new Promise(resolve=>{
const body=seed.data, req=request({hostname:proxy.hostname,port:proxy.port,path:seed.url,method:seed.method,headers:{'proxy-authorization':'Basic '+Buffer.from(proxy.username+':'+proxy.password).toString('base64'),...(body?{'content-type':'application/json','content-length':Buffer.byteLength(body)}:{})}},res=>{res.resume();res.on('end',resolve)});req.on('error',resolve);req.end(body); });
${delay ? `await new Promise(resolve=>setTimeout(resolve,${delay}));` : ''}}
writeFileSync(join(plan.jobs.find(j=>j.type==='report').parameters.reportDir,'report.json'),JSON.stringify({'@version':'2.17.0',site:[{'@name':new URL(seeds[0].url).origin,alerts:[]}]}));
`); await chmod(file, 0o700); return file;
}
