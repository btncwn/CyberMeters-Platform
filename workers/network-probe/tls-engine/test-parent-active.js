// Controlled loopback integration for the disabled Heartbleed adapter.
// Mutates an in-memory copy of the collector gate; production source remains off.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { projectTlsCollectorReceipt } from '../src/tls-contract.js';

const root=resolve(fileURLToPath(new URL('../../../',import.meta.url)));
const build=process.env.CM_TLS_TEST_BUILD_ROOT || join(root,'workers/network-probe/tls-engine/.build');
const active=process.env.CM_TLS_TEST_ACTIVE_BINARY || join(build,'bin/tls-active-legacy');
const directory=mkdtempSync(join(tmpdir(),'cybermeters-tls-active-parent-'));
const certificate=join(directory,'localhost.pem'),key=join(directory,'localhost.key');
const config=join(directory,'openssl.cnf');
writeFileSync(config,'[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=localhost\n');
function run(binary,args){
  const result=spawnSync(binary,args,{stdio:['ignore','ignore','pipe'],timeout:10000});
  assert.equal(result.status,0,String(result.stderr||result.error||'').slice(-500));
}
run(join(build,'install-modern/bin/openssl'),['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','2',
  '-config',config,'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-out',certificate,'-keyout',key]);
const prefix=join(build,'install-legacy');
const lib=join(prefix,existsSync(join(prefix,'lib64/libssl.a'))?'lib64':'lib');
const fixture=join(directory,'fixture-server');
run('cc',['-Wno-deprecated-declarations',`-I${join(prefix,'include')}`,
  join(root,'workers/network-probe/tls-engine/src/fixture-server.c'),join(lib,'libssl.a'),join(lib,'libcrypto.a'),
  '-lpthread','-lz',...(process.platform==='linux'?['-ldl']:[]),'-o',fixture]);
let source=readFileSync(join(root,'workers/network-probe/src/tls-collector-runtime.js'),'utf8');
assert(source.includes('const SPECIAL_CONTROLS_ENABLED = false;'));
source=source.replace('const SPECIAL_CONTROLS_ENABLED = false;','const SPECIAL_CONTROLS_ENABLED = true;');
for(const [from,to] of [
  ['/opt/cybermeters/tls-active-legacy',active],
  ['/opt/cybermeters/tls-baseline-legacy',join(build,'bin/tls-baseline-legacy')],
  ['/opt/cybermeters/trust/ca-bundle.pem',certificate],
])source=source.replaceAll(from,to);
source=source.replace('!publicAddress(endpoint.address)',"!(endpoint.address === '127.0.0.1' || endpoint.address === '127.0.0.2')");
source=source.replace('resolve4(endpoint.hostname), resolve6(endpoint.hostname)',"Promise.resolve(['127.0.0.1']), Promise.resolve([])");
const {__runTlsCollector}=await import('data:text/javascript,'+encodeURIComponent(source));
const reservation=createServer();
await new Promise((done,reject)=>reservation.once('error',reject).listen(0,'127.0.0.1',done));
const port=reservation.address().port;
await new Promise(done=>reservation.close(done));
const child=spawn(fixture,[String(port),certificate,key,'tls1_2_hb'],{stdio:['ignore','ignore','pipe']});
const ready=async()=>{
  for(let attempt=0;attempt<100;attempt++){
    if(child.exitCode!==null)throw new Error('active fixture exited');
    const connected=await new Promise(resolve=>{
      const socket=connect({host:'127.0.0.1',port});
      socket.once('connect',()=>{socket.destroy();resolve(true);});
      socket.once('error',()=>resolve(false));
    });
    if(connected)return;
    await new Promise(resolve=>setTimeout(resolve,20));
  }
  throw new Error('active fixture did not start');
};
try{
  await ready();
  const now=()=>new Date().toISOString();
  const request={schema_version:'tls-assessment-request-v1',request_id:'local_active_1',workspace_id:'local',scan_id:'local',
    domain_id:'local',domain:'localhost',endpoint:{hostname:'localhost',sni:'localhost',address:'127.0.0.1',port,
      transport:'tcp',application_protocol:'https',dns_addresses:['127.0.0.1'],dns_observed_at:now()},
    scope:{kind:'authorized_service',service_authorization_id:'local',generation:1,special_consent:true,
      consent_version:'tls-special-2026-10-13'},checks:[{control:'heartbleed',protocol:'tls1_2',cipher_id:null}],
    deadline_at:new Date(Date.now()+15000).toISOString(),max_connections:1,max_bytes:4096};
  const raw=await __runTlsCollector(request);
  assert.equal(raw.results[0].engine_result?.engine?.family,'active_legacy');
  assert.equal(raw.results[0].engine_result?.vulnerability?.status,'not_observed');
  assert.equal(raw.telemetry.connections,1);
  assert(raw.telemetry.bytes_sent+raw.telemetry.bytes_received<=request.max_bytes);
  const projected=projectTlsCollectorReceipt(request,raw,{requireSandbox:false});
  assert.equal(projected.results[0].state,'rejected');
  const noConsent={...request,request_id:'local_active_without_consent',
    scope:{...request.scope,special_consent:false,consent_version:null},deadline_at:new Date(Date.now()+15000).toISOString()};
  const blocked=await __runTlsCollector(noConsent);
  assert.equal(blocked.results[0].engine_result?.state,'unexecutable');
  assert.equal(blocked.telemetry.connections,0);
  const drifted={...request,request_id:'local_active_dns_drift',
    endpoint:{...request.endpoint,address:'127.0.0.2',dns_addresses:['127.0.0.2']},
    deadline_at:new Date(Date.now()+15000).toISOString()};
  const drift=await __runTlsCollector(drifted);
  assert.equal(drift.results[0].reason,'dns_authority_changed');
  assert.equal(drift.telemetry.connections,0);
  console.log('TLS active parent: one bounded Heartbleed connection; no-consent and DNS drift made zero connections');
}finally{
  child.kill('SIGTERM');
  if(child.exitCode===null)await new Promise(resolve=>child.once('exit',resolve));
  child.stderr.destroy();
  rmSync(directory,{recursive:true,force:true});
}
