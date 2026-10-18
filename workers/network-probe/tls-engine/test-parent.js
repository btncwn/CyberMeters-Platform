// Loopback-only parent/child integration. The production collector still rejects
// every private address; this fixture substitutes its own isolated source copy.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { createSecureContext, TLSSocket } from 'node:tls';
import { spawn, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { projectTlsCollectorReceipt } from '../src/tls-contract.js';

const root=resolve(fileURLToPath(new URL('../../../',import.meta.url)));
const build=join(root,'workers/network-probe/tls-engine/.build');
const runtimeRoot=process.env.CM_TLS_TEST_RUNTIME_ROOT;
const directory=mkdtempSync(join(tmpdir(),'cybermeters-tls-parent-'));
const certificate=process.env.CM_TLS_TEST_CERTIFICATE || join(directory,'localhost.pem');
const key=process.env.CM_TLS_TEST_KEY || join(directory,'localhost.key');
const config=join(directory,'openssl.cnf');
if(!process.env.CM_TLS_TEST_CERTIFICATE || !process.env.CM_TLS_TEST_KEY){
  writeFileSync(config,'[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=localhost\n');
  const openssl=join(build,'install-modern/bin/openssl');
  const issue=spawnSync(openssl,['req','-x509','-newkey','rsa:2048','-nodes','-sha256','-days','2',
    '-config',config,'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-out',certificate,'-keyout',key],
    {stdio:['ignore','ignore','pipe'],timeout:5000});
  if(issue.status!==0)throw new Error('local_fixture_certificate_failed: '+String(issue.stderr||issue.error||'').slice(-300));
}
let source=readFileSync(join(root,'workers/network-probe/src/tls-collector-runtime.js'),'utf8');
for(const [from,to] of [
  ['/opt/cybermeters/tls-baseline-legacy',runtimeRoot?join(runtimeRoot,'tls-baseline-legacy'):join(build,'bin/tls-baseline-legacy')],
  ['/opt/cybermeters/tls-active-legacy',runtimeRoot?join(runtimeRoot,'tls-active-legacy'):join(build,'bin/tls-active-legacy')],
  ['/opt/cybermeters/tls-baseline-modern',runtimeRoot?join(runtimeRoot,'tls-baseline-modern'):join(build,'bin/tls-baseline-modern')],
  ['/opt/cybermeters/trust/ca-bundle.pem',certificate],
])source=source.replaceAll(from,to);
source=source.replace('!publicAddress(endpoint.address)',"!(endpoint.address === '127.0.0.1' || endpoint.address === '127.0.0.2' || endpoint.address === '::1')");
source=source.replace('resolve4(endpoint.hostname), resolve6(endpoint.hostname)',"Promise.resolve(['127.0.0.1']), Promise.resolve(['::1'])");
source=source.replace('resolveMx(input.domain)',"Promise.resolve([{exchange:'localhost'}])");
const {__runTlsCollector}=await import('data:text/javascript,'+encodeURIComponent(source));
const profile={requests:0,checks:0,connections:0,bytes_sent:0,bytes_received:0,states:{}};
async function measuredCollector(request){
  const receipt=await __runTlsCollector(request);
  profile.requests++;
  for(const key of ['connections','bytes_sent','bytes_received'])profile[key]+=receipt.telemetry?.[key]||0;
  for(const result of receipt.results||[]){
    profile.checks++;
    const state=result.engine_result?.state||result.state||'unknown';
    profile.states[state]=(profile.states[state]||0)+1;
  }
  return receipt;
}

const context=createSecureContext({cert:readFileSync(certificate),key:readFileSync(key),minVersion:'TLSv1.2',maxVersion:'TLSv1.3'});
const context6=createSecureContext({cert:readFileSync(certificate),key:readFileSync(key),minVersion:'TLSv1.2',maxVersion:'TLSv1.2'});
const sockets=new Set();
const extraServers=[];
function smtpSocket(socket,tlsContext) {
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
        const secure=new TLSSocket(socket,{isServer:true,secureContext:tlsContext});
        secure.on('error',()=>{});
      });
    }else socket.destroy();
  };
  socket.on('data',onData);
}
const server=createServer(socket=>smtpSocket(socket,context));
const close=()=>new Promise(resolve=>server.close(resolve));
async function pinnedSmtpReference(port) {
  const binary=join(build,'install-modern/bin/openssl');
  const args=['s_client','-brief','-starttls','smtp','-tls1_2','-connect',`127.0.0.1:${port}`,
    '-servername','localhost','-verify_hostname','localhost','-CAfile',certificate];
  const child=spawn(binary,args,{stdio:['pipe','pipe','pipe']});
  const output=[];
  child.stdout.on('data',chunk=>output.push(chunk));
  child.stderr.on('data',chunk=>output.push(chunk));
  child.stdin.end();
  const timer=setTimeout(()=>child.kill(),5000);
  const code=await new Promise((resolve,reject)=>{
    child.once('error',reject);child.once('close',resolve);
  }).finally(()=>clearTimeout(timer));
  const text=Buffer.concat(output).toString('utf8');
  assert.equal(code,0,text);
  return text;
}
async function checkMailUpgrade(request,application,variant='valid') {
  const mail=createServer(socket=>{
    sockets.add(socket);socket.once('close',()=>sockets.delete(socket));socket.on('error',()=>{});
    socket.write(application==='imap'?'* OK local fixture ready\r\n':'+OK local fixture ready\r\n');
    let phase='capability';
    const onData=chunk=>{
      const line=chunk.toString('ascii');
      if(application==='imap'&&phase==='capability'&&line==='a001 CAPABILITY\r\n'){
        phase='upgrade';socket.write(variant==='missing'?'* CAPABILITY IMAP4rev1\r\na001 OK ready\r\n':
          '* CAPABILITY IMAP4rev1 STARTTLS\r\na001 OK ready\r\n');
      }else if((application==='imap'&&line==='a002 STARTTLS\r\n')||(application==='pop3'&&line==='STLS\r\n')){
        socket.off('data',onData);
        if(variant==='rejected'){socket.end('-ERR STLS unavailable\r\n');return;}
        socket.write(application==='imap'?'a002 OK Go ahead\r\n':'+OK Go ahead\r\n',()=>{
          const secure=new TLSSocket(socket,{isServer:true,secureContext:context});
          secure.on('error',()=>{});
        });
      }else socket.destroy();
    };
    socket.on('data',onData);
  });
  extraServers.push(mail);
  await new Promise((resolve,reject)=>mail.once('error',reject).listen(0,'127.0.0.1',resolve));
  const input={...request,request_id:`local_parent_${application}_${variant}`,endpoint:{...request.endpoint,
    port:mail.address().port,application_protocol:application},deadline_at:new Date(Date.now()+20000).toISOString()};
  const raw=await measuredCollector(input);
  if(variant==='valid')assert.equal(raw.results[0].engine_result?.state,'accepted',JSON.stringify(raw.results[0]));
  else assert.notEqual(raw.results[0].engine_result?.state,'accepted',JSON.stringify(raw.results[0]));
  assert(raw.telemetry.bytes_sent>raw.results[0].engine_result.telemetry.bytes_sent,
    `${application} upgrade bytes must be charged`);
  const projected=projectTlsCollectorReceipt(input,raw,{requireSandbox:false});
  assert.equal(projected.results[0].state,variant==='valid'?'accepted':'uncertain');
}
async function checkMailMx(request,variant) {
  let connections=0, quit=0, unexpected=0;
  let quitResolve;
  const quitReceived=new Promise(resolve=>{quitResolve=resolve;});
  const fixture=createServer(socket=>{
    connections++;
    sockets.add(socket);socket.once('close',()=>sockets.delete(socket));socket.on('error',()=>{});
    socket.write('220 local mail fixture\r\n');
    let phase='ehlo';
    socket.on('data',function plaintext(chunk){
      const line=chunk.toString('ascii');
      if(phase==='ehlo'&&line.startsWith('EHLO ')){
        phase='upgrade';socket.write(variant==='absent'?'250 localhost\r\n':'250-localhost\r\n250 STARTTLS\r\n');
      }else if(variant==='absent'&&line==='QUIT\r\n'){
        quit++;quitResolve();socket.end('221 goodbye\r\n');
      }else if(phase==='upgrade'&&line==='STARTTLS\r\n'){
        phase='tls';socket.off('data',plaintext);
        socket.write('220 begin TLS\r\n',()=>{
          const secure=new TLSSocket(socket,{isServer:true,secureContext:context});
          secure.on('data',data=>{
            if(data.toString('ascii')==='QUIT\r\n'){quit++;quitResolve();}
            else unexpected++;
            secure.end('221 goodbye\r\n');
          });
          secure.on('error',()=>{});
        });
      }else{unexpected++;socket.destroy();}
    });
  });
  extraServers.push(fixture);
  await new Promise((resolve,reject)=>fixture.once('error',reject).listen(0,'127.0.0.1',resolve));
  const mail={...request,request_id:`local_mail_${variant}`,
    endpoint:{...request.endpoint,port:fixture.address().port},
    scope:{kind:'mail_mx',service_authorization_id:null,generation:0,special_consent:false,consent_version:null},
    checks:[{control:'certificate',protocol:'tls1_2',cipher_id:null}],
    deadline_at:new Date(Date.now()+10000).toISOString(),max_connections:1};
  const raw=await measuredCollector(mail);
  assert.equal(connections,1,'mail probe must use one TCP connection');
  assert.equal(raw.telemetry.connections,1);
  assert.equal(raw.results[0].reason,variant==='absent'?'starttls_unavailable':null,JSON.stringify(raw.results[0]));
  if(variant==='present'){
    assert.equal(raw.results[0].engine_result?.authenticated_finished,true);
    assert.equal(raw.results[0].engine_result?.negotiated?.version,'tls1_3');
  }
  assert.equal(projectTlsCollectorReceipt(mail,raw,{requireSandbox:false}).results[0].state,
    variant==='absent'?'rejected':'accepted');
  await Promise.race([quitReceived,new Promise(resolve=>setTimeout(resolve,1000))]);
  assert.equal(quit,1,'mail probe must send one QUIT');
  assert.equal(unexpected,0,'mail probe must not send message commands');
}
try{
  await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'127.0.0.1',resolve));
  const port=server.address().port;
  const request={schema_version:'tls-assessment-request-v1',request_id:'local_parent_1',workspace_id:'local',scan_id:'local',
    domain_id:'local',domain:'localhost',endpoint:{hostname:'localhost',sni:'localhost',address:'127.0.0.1',port,
      transport:'tcp',application_protocol:'smtp',dns_addresses:['127.0.0.1'],dns_observed_at:new Date().toISOString()},
    scope:{kind:'authorized_service',service_authorization_id:'local',generation:0,special_consent:false,consent_version:null},
    checks:[{control:'protocol',protocol:'tls1_2',cipher_id:null}],deadline_at:new Date(Date.now()+20000).toISOString(),
    max_connections:4,max_bytes:20000};
  const raw=await measuredCollector(request);
  assert.equal(raw.results[0].engine_result?.state,'accepted',JSON.stringify(raw.results[0]));
  assert.equal(raw.results[0].engine_result?.authenticated_finished,true);
  assert.equal(raw.telemetry.connections,1);
  assert(raw.telemetry.bytes_sent>raw.results[0].engine_result.telemetry.bytes_sent,'SMTP bytes must be charged');
  const receipt=projectTlsCollectorReceipt(request,raw,{requireSandbox:false});
  assert.equal(receipt.results[0].state,'accepted');
  if(!runtimeRoot){
    const reference=await pinnedSmtpReference(port);
    assert.match(reference,/Protocol version: TLSv1\.2/);
    assert.match(reference,/Verification: OK/);
  }
  const tls13={...request,request_id:'local_parent_tls13',checks:[{control:'cipher',protocol:'tls1_3',cipher_id:'TLS_AES_128_GCM_SHA256'}],
    deadline_at:new Date(Date.now()+20000).toISOString()};
  const raw13=await measuredCollector(tls13);
  assert.equal(raw13.results[0].engine_result?.engine?.family,'modern');
  assert.equal(raw13.results[0].engine_result?.negotiated?.cipher,'TLS_AES_128_GCM_SHA256');
  assert.equal(projectTlsCollectorReceipt(tls13,raw13,{requireSandbox:false}).results[0].state,'accepted');
  const compression={...request,request_id:'local_parent_compression',
    checks:[{control:'compression',protocol:'tls1_2',cipher_id:null}],
    deadline_at:new Date(Date.now()+20000).toISOString()};
  const rawCompression=await measuredCollector(compression);
  assert.equal(rawCompression.results[0].engine_result?.engine?.family,'legacy');
  const expectedCompression=process.env.CM_TLS_TEST_BASELINE_IMAGE==='1'?'unexecutable':'accepted';
  assert.equal(rawCompression.results[0].engine_result?.state,expectedCompression);
  if(expectedCompression==='accepted')assert.equal(rawCompression.results[0].engine_result?.extensions?.compression,false);
  assert.equal(projectTlsCollectorReceipt(compression,rawCompression,{requireSandbox:false}).results[0].state,expectedCompression);
  const ipv6=createServer(socket=>smtpSocket(socket,context6));
  extraServers.push(ipv6);
  await new Promise((resolve,reject)=>ipv6.once('error',reject).listen(0,'::1',resolve));
  const v6={...tls13,request_id:'local_parent_ipv6_difference',endpoint:{...tls13.endpoint,
    address:'::1',dns_addresses:['::1'],port:ipv6.address().port},
    checks:[{control:'protocol',protocol:'tls1_3',cipher_id:null}],
    deadline_at:new Date(Date.now()+20000).toISOString()};
  const raw6=await measuredCollector(v6);
  assert.equal(raw6.results[0].engine_result?.state,'rejected',JSON.stringify(raw6.results[0]));
  assert.equal(raw6.results[0].engine_result?.reason,'protocol_version_rejected');
  assert.equal(raw6.telemetry.connections,1);
  assert.equal(projectTlsCollectorReceipt(v6,raw6,{requireSandbox:false}).results[0].state,'rejected');
  const changed={...request,request_id:'local_parent_2',endpoint:{...request.endpoint,address:'127.0.0.2',dns_addresses:['127.0.0.2']},
    deadline_at:new Date(Date.now()+20000).toISOString()};
  const blocked=await measuredCollector(changed);
  assert.equal(blocked.results[0].reason,'dns_authority_changed');
  assert.equal(blocked.telemetry.connections,0);
  const unavailable={...request,request_id:'local_parent_special_without_consent',
    checks:[{control:'heartbleed',protocol:'tls1_2',cipher_id:null}],
    deadline_at:new Date(Date.now()+20000).toISOString()};
  const noActive=await measuredCollector(unavailable);
  assert.equal(noActive.results[0].engine_result?.state,'unexecutable');
  assert.equal(noActive.results[0].engine_result?.reason,'control_unavailable');
  assert.equal(noActive.telemetry.connections,0);
  const consentedUnavailable={...unavailable,request_id:'local_parent_special_consented_no_heartbeat',
    scope:{...unavailable.scope,special_consent:true,consent_version:'tls-special-2026-10-13'}};
  const activeWithoutHeartbeat=await measuredCollector(consentedUnavailable);
  assert.equal(activeWithoutHeartbeat.results[0].engine_result?.state,'unexecutable');
  assert.equal(activeWithoutHeartbeat.results[0].engine_result?.reason,'heartbeat_unavailable');
  assert.equal(activeWithoutHeartbeat.telemetry.connections,1);
  await checkMailUpgrade(request,'imap');
  await checkMailUpgrade(request,'pop3');
  await checkMailUpgrade(request,'imap','missing');
  await checkMailUpgrade(request,'pop3','rejected');
  await checkMailMx(request,'present');
  await checkMailMx(request,'absent');
  if(process.env.CM_TLS_TEST_PROFILE==='1')console.log('TLS parent profile: '+JSON.stringify(profile));
  console.log('TLS parent: SMTP/IMAP/POP3 STARTTLS refusal cases, IPv4/IPv6 TLS divergence, TLS 1.3 cipher routing, physical accounting and DNS escape block'+
    (runtimeRoot?'':', pinned OpenSSL SMTP STARTTLS parity')+' passed');
}finally{for(const socket of sockets)socket.destroy();await close();for(const mail of extraServers)await new Promise(resolve=>mail.close(resolve));rmSync(directory,{recursive:true,force:true});}
