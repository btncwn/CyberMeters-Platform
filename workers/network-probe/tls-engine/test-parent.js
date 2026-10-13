// Loopback-only parent/child integration. The production collector still rejects
// every private address; this fixture substitutes its own isolated source copy.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { createSecureContext, TLSSocket } from 'node:tls';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { projectTlsCollectorReceipt } from '../src/tls-contract.js';

const root=resolve(fileURLToPath(new URL('../../../',import.meta.url)));
const build=join(root,'workers/network-probe/tls-engine/.build');
const directory=mkdtempSync(join(tmpdir(),'cybermeters-tls-parent-'));
const certificate=join(directory,'localhost.pem'),key=join(directory,'localhost.key');
const config=join(directory,'openssl.cnf');
writeFileSync(config,'[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=localhost\n');
const openssl=join(build,'install-modern/bin/openssl');
const issue=spawnSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','2',
  '-config',config,'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-out',certificate,'-keyout',key],
  {stdio:['ignore','ignore','pipe'],timeout:5000});
if(issue.status!==0)throw new Error('local_fixture_certificate_failed: '+String(issue.stderr||issue.error||'').slice(-300));
let source=readFileSync(join(root,'workers/network-probe/src/tls-collector-runtime.js'),'utf8');
for(const [from,to] of [
  ['/opt/cybermeters/tls-baseline-legacy',join(build,'bin/tls-baseline-legacy')],
  ['/opt/cybermeters/tls-baseline-modern',join(build,'bin/tls-baseline-modern')],
  ['/opt/cybermeters/tls-active-legacy',join(build,'bin/tls-baseline-legacy')],
  ['/opt/cybermeters/trust/ca-bundle.pem',certificate],
])source=source.replaceAll(from,to);
source=source.replace('!publicAddress(endpoint.address)',"!(endpoint.address === '127.0.0.1' || endpoint.address === '127.0.0.2')");
source=source.replace('resolve4(endpoint.hostname), resolve6(endpoint.hostname)',"Promise.resolve(['127.0.0.1']), Promise.resolve([])");
const {__runTlsCollector}=await import('data:text/javascript,'+encodeURIComponent(source));

const context=createSecureContext({cert:readFileSync(certificate),key:readFileSync(key),minVersion:'TLSv1.2',maxVersion:'TLSv1.3'});
const sockets=new Set();
const server=createServer(socket=>{
  sockets.add(socket);socket.once('close',()=>sockets.delete(socket));
  socket.on('error',()=>{});
  socket.write('220 local fixture ready\r\n');
  let phase='ehlo';
  const onData=chunk=>{
    const line=chunk.toString('ascii');
    if(phase==='ehlo'&&line.startsWith('EHLO ')){
      phase='starttls';socket.write('250-localhost\r\n250 STARTTLS\r\n');
    }else if(phase==='starttls'&&line==='STARTTLS\r\n'){
      phase='tls';socket.off('data',onData);
      socket.write('220 Go ahead\r\n',()=>{
        const secure=new TLSSocket(socket,{isServer:true,secureContext:context});
        secure.on('error',()=>{});
      });
    }else socket.destroy();
  };
  socket.on('data',onData);
});
const close=()=>new Promise(resolve=>server.close(resolve));
try{
  await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'127.0.0.1',resolve));
  const port=server.address().port;
  const request={schema_version:'tls-assessment-request-v1',request_id:'local_parent_1',workspace_id:'local',scan_id:'local',
    domain_id:'local',domain:'localhost',endpoint:{hostname:'localhost',sni:'localhost',address:'127.0.0.1',port,
      transport:'tcp',application_protocol:'smtp',dns_addresses:['127.0.0.1'],dns_observed_at:new Date().toISOString()},
    scope:{kind:'authorized_service',service_authorization_id:'local',generation:0,special_consent:false,consent_version:null},
    checks:[{control:'protocol',protocol:'tls1_2',cipher_id:null}],deadline_at:new Date(Date.now()+20000).toISOString(),
    max_connections:4,max_bytes:20000};
  const raw=await __runTlsCollector(request);
  assert.equal(raw.results[0].engine_result?.state,'accepted',JSON.stringify(raw.results[0]));
  assert.equal(raw.results[0].engine_result?.authenticated_finished,true);
  assert.equal(raw.telemetry.connections,1);
  assert(raw.telemetry.bytes_sent>raw.results[0].engine_result.telemetry.bytes_sent,'SMTP bytes must be charged');
  const receipt=projectTlsCollectorReceipt(request,raw,{requireSandbox:false});
  assert.equal(receipt.results[0].state,'accepted');
  const tls13={...request,request_id:'local_parent_tls13',checks:[{control:'cipher',protocol:'tls1_3',cipher_id:'TLS_AES_128_GCM_SHA256'}],
    deadline_at:new Date(Date.now()+20000).toISOString()};
  const raw13=await __runTlsCollector(tls13);
  assert.equal(raw13.results[0].engine_result?.engine?.family,'modern');
  assert.equal(raw13.results[0].engine_result?.negotiated?.cipher,'TLS_AES_128_GCM_SHA256');
  assert.equal(projectTlsCollectorReceipt(tls13,raw13,{requireSandbox:false}).results[0].state,'accepted');
  const changed={...request,request_id:'local_parent_2',endpoint:{...request.endpoint,address:'127.0.0.2',dns_addresses:['127.0.0.2']},
    deadline_at:new Date(Date.now()+20000).toISOString()};
  const blocked=await __runTlsCollector(changed);
  assert.equal(blocked.results[0].reason,'dns_authority_changed');
  assert.equal(blocked.telemetry.connections,0);
  console.log('TLS parent: real SMTP STARTTLS, TLS 1.3 cipher routing, physical accounting and DNS escape block passed');
}finally{for(const socket of sockets)socket.destroy();await close();rmSync(directory,{recursive:true,force:true});}
