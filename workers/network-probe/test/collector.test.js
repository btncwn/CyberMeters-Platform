import test, {after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import {spawnSync} from 'node:child_process';
import {runCollector,collectorProgram} from '../src/collector.js';
import {FREE_TOOL_TLS_LIMITS,isPublicProbeAddress,validateNetworkProbeRequest,readBoundedJson} from '../src/contract.js';
import {validateFreeToolTlsReceipt,validateNetworkProbeReceipt} from '../src/receipt.js';
import {attachLiveTlsToSsl,collectNetworkProbe,liveCertificateFindings} from '../../scan-api/src/engines/network-probe.js';
import {runCertificateIntelligenceModule} from '../../scan-api/src/engines/cert-intel.js';
import {createTlsFixtures} from './fixtures/create-tls-fixtures.js';
const fixtures=createTlsFixtures();
const read=fixtures.read;
after(fixtures.cleanup);
process.once('exit',fixtures.cleanup);
const request=(profile='live_tls')=>({schema_version:'network-probe-request-v1',request_id:'request_1',workspace_id:'workspace_1',scan_id:'scan_1',profile,deadline_at:new Date(Date.now()+20_000).toISOString(),targets:profile==='live_tls'?[{address:null,hostname:'owned.example.com'}]:[{address:'93.184.216.34',hostname:null}],ports:profile==='live_tls'?[443]:[22]});
const tlsFixture=async(name,{trusted=false}={})=>{
 const sockets=new Set();
 const server=tls.createServer({key:read(`${name}.key`),cert:read(`${name}.pem`)});
 server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});server.on('tlsClientError',()=>{});
 await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'127.0.0.1',resolve));
 const req=request();
 try{
  const receipt=await runCollector(req,{resolve:async(_,family)=>family===4?['93.184.216.34']:[],connect:opts=>net.connect({...opts,host:'127.0.0.1',port:server.address().port}),tlsConnect:opts=>tls.connect({...opts,host:'127.0.0.1',port:server.address().port}),...(trusted?{trustedRoots:[read('ca.pem')]}:{})});
  return {req,receipt};
 }finally{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}
};
test('public scope rejects loopback, private, reserved, mapped and transition addresses',()=>{
 for(const ip of ['127.0.0.1','10.1.2.3','169.254.169.254','100.64.1.1','192.0.2.1','198.18.0.1','224.1.1.1','010.1.2.3','::1','::ffff:127.0.0.1','64:ff9b::a00:1','2001:db8::1','2002:7f00:1::','fe80::1','fc00::1','2001:20::1'])assert.equal(isPublicProbeAddress(ip),false,ip);
 for(const ip of ['93.184.216.34','2606:4700::1111'])assert.equal(isPublicProbeAddress(ip),true,ip);
});
test('request rejects command input, excess scope and non-fixed ports',()=>{
 for(const delta of [{command:'echo bad'},{ports:[1234]},{deadline_at:new Date(Date.now()+120000).toISOString()},{targets:[{address:'127.0.0.1',hostname:null}]},{ports:[22,22]}])assert.equal(validateNetworkProbeRequest({...request('network_services'),...delta}).ok,false);
 assert.equal(validateNetworkProbeRequest(request()).ok,true);
});
test('mixed public/private DNS answers cause no connection and cannot be complete',async()=>{
 let connected=0;const req=request();const receipt=await runCollector(req,{resolve:async(_,family)=>family===4?['93.184.216.34','127.0.0.1']:[],connect:()=>{connected++;throw Error('unexpected');}});
 assert.equal(connected,0);assert.equal(receipt.quality,'partial');assert.equal(receipt.observations[0].reason,'dns_non_public_answer');assert.deepEqual(validateNetworkProbeReceipt(req,receipt),{ok:true});
});
test('a real local TLS certificate from an unknown CA is captured, not called trusted',async()=>{
 const {req,receipt}=await tlsFixture('valid');const live=receipt.observations[0].tls;
 assert.equal(live.leaf_collected,true);assert.equal(live.hostname_match.result,'matched');assert.equal(live.trust_store_validation.validation_result,'invalid');assert.equal(live.chain_collected,false);assert.equal(live.revocation_assurance.status,'unknown');assert.deepEqual(validateNetworkProbeReceipt(req,receipt),{ok:true});
 const ssl=attachLiveTlsToSsl({}, {receipt});assert.equal(liveCertificateFindings(ssl,'owned.example.com')[0].signal,'certificate_untrusted');
 for(const mutate of [r=>r.workspace_id='other',r=>r.observations.push(r.observations[0]),r=>r.coverage.completed=0,r=>r.observations[0].tls.hostname_match.certificate_identity='sha256:'+'0'.repeat(64),r=>r.observations[0].tls.trust_store_validation.validation_performed=false,r=>r.observations[0].tls.chain_collected=true]){const altered=structuredClone(receipt);mutate(altered);assert.equal(validateNetworkProbeReceipt(req,altered).ok,false);}
});
test('trusted local CA control proves real trust validation and named fixture roots',async()=>{
 const {receipt}=await tlsFixture('valid',{trusted:true});const live=receipt.observations[0].tls;
 assert.equal(live.trust_store_validation.validation_result,'valid');assert.equal(live.hostname_match.result,'matched');assert.equal(live.trust_store_context.name,'Local fixture CA roots');assert.equal(liveCertificateFindings(attachLiveTlsToSsl({}, {receipt}),'owned.example.com').length,0);
});
test('wrong hostname and expired certificate are distinct actual TLS failures',async()=>{
 const wrong=await tlsFixture('wrong',{trusted:true});const row=wrong.receipt.observations[0].tls;
 assert.equal(row.hostname_match.result,'mismatched');assert.equal(row.trust_store_validation.validation_result,'valid','hostname is separate from trust-chain validation');
 assert.deepEqual(liveCertificateFindings(attachLiveTlsToSsl({},wrong),'owned.example.com').map(x=>x.signal),['certificate_hostname_mismatch']);
 const expired=await tlsFixture('expired',{trusted:true});const findings=liveCertificateFindings(attachLiveTlsToSsl({},expired),'owned.example.com');assert.ok(findings.some(x=>x.signal==='certificate_expired'));assert.ok(findings.some(x=>x.signal==='certificate_untrusted'));
});
test('the live leaf is the only certificate source and keeps unrelated SSL fields',async()=>{
 const {receipt}=await tlsFixture('expired',{trusted:true});const ssl=attachLiveTlsToSsl({tls_state:'observed_present',redirect_ok:true}, {receipt});
 assert.equal(ssl.redirect_ok,true);
 const ci=runCertificateIntelligenceModule({ssl,subdomains:{wildcard_dns:false,items:[]}},'owned.example.com');
 assert.equal(ci.evidence_source,'live_tls');assert.equal(ci.expires_at,'2021-01-01T00:00:00.000Z');assert.equal(ci.certificate_status,'invalid');assert.ok(ci.suspicious_certificate_signals.some(x=>x.signal==='certificate_expired'));
 assert.equal(ci.signal_completeness.signals.hostname_match.provenance.method,'node_tls_check_server_identity');assert.equal(ci.signal_completeness.signals.expiry.observation_scope,'live_tls');assert.equal(ci.signal_completeness.signals.chain.observation,'unknown');
});
test('network receipt requires every exact tuple, never missing or extra ports',async()=>{
 const req=request('network_services');const receipt=await runCollector(req,{connect:()=>{throw Error('local test failure');}});
 assert.deepEqual(validateNetworkProbeReceipt(req,receipt),{ok:true});assert.equal(receipt.quality,'partial');
 const extra=structuredClone(receipt);extra.observations[0].port=443;assert.equal(validateNetworkProbeReceipt(req,extra).ok,false);
 const missing=structuredClone(receipt);missing.observations=[];assert.equal(validateNetworkProbeReceipt(req,missing).ok,false);
});
test('private binding timeout is bounded even if a mock ignores AbortSignal',async()=>{
 const req=request();req.deadline_at=new Date(Date.now()+25).toISOString();const started=Date.now();await assert.rejects(collectNetworkProbe({NETWORK_PROBE:{fetch:()=>new Promise(()=>{})}},req),/collector_aborted/);assert.ok(Date.now()-started<2000);
});
test('body parser rejects oversized data',async()=>{
 await assert.rejects(readBoundedJson(new Response('x'.repeat(40)).body,20),/body_limit/);
});
test('fixed Node exec source is executable and never interprets request commands',()=>{
 const source=collectorProgram();const result=spawnSync(process.execPath,['--input-type=module','-e',source],{input:'{"command":"echo bad"}',encoding:'utf8',timeout:5000});assert.equal(result.status,1);assert.match(result.stderr,/unknown_request_field/);
 // Exercise valid request path with a local dependency that refuses connections.
 const req=request('network_services');const local=source.slice(0,source.indexOf("let raw='';"))+`const result=await runCollector(${JSON.stringify(req)},{connect:()=>{throw Error('fixture');}});process.stdout.write(JSON.stringify(result));`;
 const executed=spawnSync(process.execPath,['--input-type=module','-e',local],{encoding:'utf8',timeout:5000});assert.equal(executed.status,0,executed.stderr);assert.equal(JSON.parse(executed.stdout).quality,'partial');
});

test('fresh TLS case verification needs every endpoint and cannot use HTTP success',async()=>{
 const {buildLiveTlsCaseVerificationEvidence}=await import('../../scan-api/src/engines/certificate-lifecycle.js');
 const {receipt}=await tlsFixture('valid',{trusted:true});
 const now=new Date().toISOString();const ssl=attachLiveTlsToSsl({}, {receipt});
 const ci=runCertificateIntelligenceModule({ssl},'owned.example.com',{observedAt:now,engineVersion:'local-fixture'});
 const current={id:'observation_1',last_seen:now,evidence_json:JSON.stringify({signal_completeness:ci.signal_completeness})};
 const context={current,after:new Date(Date.now()-60_000).toISOString(),hostname:'owned.example.com',now};
 assert.equal(buildLiveTlsCaseVerificationEvidence('certificate_untrusted',context).verification_result,'verified');
 for(const change of [v=>v.leaf.value.all_planned_endpoints_observed=false,v=>v.hostname_match.observation_scope='historical_observation',v=>v.trust_store_validation.publishable=false,v=>v.leaf.value.endpoint_checks.push({...v.leaf.value.endpoint_checks[0],hostname_match:'mismatched'})]){
  const bad=structuredClone(ci.signal_completeness);change(bad.signals);const altered={...current,evidence_json:JSON.stringify({signal_completeness:bad})};assert.notEqual(buildLiveTlsCaseVerificationEvidence('certificate_untrusted',{...context,current:altered}).verification_result,'verified');
 }
 assert.equal(buildLiveTlsCaseVerificationEvidence('certificate_untrusted',{...context,after:now}).verification_result,'inconclusive');
 assert.equal(buildLiveTlsCaseVerificationEvidence('certificate_untrusted',{...context,current:{...current,evidence_json:'{"https_available":true}'}}).verification_result,'inconclusive');
});

async function importWorkerForLocalTests(bundlePath,{module=false}={}){
 const url=bundlePath?new URL(`file://${bundlePath}`):new URL('../src/index.js',import.meta.url);
 let source=fs.readFileSync(url,'utf8');
 source=source.replace(/import\s*\{\s*DurableObject\s*\}\s*from\s*["']cloudflare:workers["'];?/,'class DurableObject { constructor(ctx,env){this.ctx=ctx;this.env=env;} }');
 source=source.replace(/from '([^']+)'/g,(match,path)=>path.startsWith('.')?`from '${new URL(path,url).href}'`:match);
 if(bundlePath&&!module)source+='\nexport { collectorProgram };';
 return import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
}

test('native DO destroys job container and does not signal an already exited process',async()=>{
 const {NetworkProbeContainer}=await importWorkerForLocalTests();const req=request('network_services');
 const receipt=await runCollector(req,{connect:()=>{throw Error('local fixture');}});const calls=[];
 const ctx={storage:{setAlarm:async()=>calls.push('alarm'),deleteAlarm:async()=>calls.push('deleteAlarm')},container:{running:false,start(options){calls.push(['start',options]);this.running=true;},setInactivityTimeout:async ms=>calls.push(['inactivity',ms]),destroy:async function(){calls.push('destroy');this.running=false;},exec:async(args,opts)=>{calls.push(['exec',args.slice(0,3)]);return {stdout:new Response(JSON.stringify(receipt)).body,exitCode:Promise.resolve(0)};}}};
 const controller=new AbortController();const worker=new NetworkProbeContainer(ctx,{});
 const result=await worker.fetch(new Request('http://container/collect',{method:'POST',body:JSON.stringify(req),signal:controller.signal}));
 assert.equal(result.status,200);assert.equal(ctx.container.running,false);assert.ok(calls.includes('destroy'));assert.equal(worker.busy,false);assert.deepEqual(calls.find(x=>Array.isArray(x)&&x[0]==='inactivity'),['inactivity',120000]);
 const before=calls.length;controller.abort();assert.equal(calls.length,before,'abort listener removed on exit');
 assert.deepEqual(calls.find(x=>Array.isArray(x)&&x[0]==='exec')[1],['node','--input-type=module','-e']);
});
test('native DO rejects oversized input before start and destroys failed execution',async()=>{
 const {NetworkProbeContainer}=await importWorkerForLocalTests();let starts=0,destroyed=0;
 const ctx={storage:{setAlarm:async()=>{},deleteAlarm:async()=>{}},container:{running:false,start(){starts++;this.running=true;},setInactivityTimeout:async()=>{},exec:async()=>{throw Error('startup failure');},destroy:async function(){destroyed++;this.running=false;}}};
 const worker=new NetworkProbeContainer(ctx,{});const call=body=>worker.fetch(new Request('http://container/collect',{method:'POST',body}));
 assert.equal((await call('x'.repeat(17000))).status,502);assert.equal(starts,0);
 assert.equal((await call(JSON.stringify(request()))).status,502);assert.equal(starts,1);assert.equal(destroyed,1);assert.equal(worker.busy,false);
});
test('private dispatcher can start only two fixed slots',async()=>{
 const {default:worker}=await importWorkerForLocalTests();const slots=[];const env={PROBE_CONTAINERS:{getByName:name=>{slots.push(name);return{fetch:async()=>new Response('',{status:503})};}}};
 const result=await worker.fetch(new Request('http://container/collect',{method:'POST',body:JSON.stringify(request())}),env);assert.equal(result.status,503);assert.deepEqual(slots,['probe-slot-0','probe-slot-1']);
});
if(process.env.NETWORK_PROBE_BUNDLE){
 test('actual pinned Wrangler bundle emits an executable Node collector',async()=>{
  const compiled=await importWorkerForLocalTests(process.env.NETWORK_PROBE_BUNDLE);const program=compiled.collectorProgram();const req=request('network_services');
  const local=program.slice(0,program.indexOf("let raw='';"))+`const result=await runCollector(${JSON.stringify(req)},{connect:()=>{throw Error('fixture');}});process.stdout.write(JSON.stringify(result));`;
  const result=spawnSync(process.execPath,['--input-type=module','-e',local],{encoding:'utf8',timeout:5000});assert.equal(result.status,0,result.stderr);assert.equal(JSON.parse(result.stdout).quality,'partial');
 });
}

test('live leaf fingerprint is the only persistent certificate identity',async()=>{
 const {certificateObservationKey}=await import('../../scan-api/src/engines/cert-events.js');
 const {hashToken}=await import('../../scan-api/src/lib/auth-crypto.js');
 const unobserved={issuer:'same issuer',subject:'same subject',expires_at:'2040-01-01T00:00:00.000Z',san_hostnames:['owned.example.com']};
 assert.equal(await certificateObservationKey(unobserved),null);
 const live={...unobserved,evidence_source:'live_tls',live_certificate_verified:true,live_tls:{leaf_certificate:{collection_complete:true,certificate_identity:'sha256:'+'a'.repeat(64)}}};
 assert.equal(await certificateObservationKey(live),await hashToken('live_tls|sha256:'+'a'.repeat(64)));
 const changed=structuredClone(live);changed.live_tls.leaf_certificate.certificate_identity='sha256:'+'b'.repeat(64);
 assert.notEqual(await certificateObservationKey(live),await certificateObservationKey(changed));
 const partial=structuredClone(live);partial.live_tls.leaf_certificate.collection_complete=false;
 assert.equal(await certificateObservationKey(partial),null);
});

test('configured collector failure leaves the certificate unknown, never valid',()=>{
 const ssl=attachLiveTlsToSsl({tls_state:'observed_present',https_available:true}, {error:'live_tls_unavailable',receipt:null});
 const ci=runCertificateIntelligenceModule({ssl,subdomains:{wildcard_dns:false,items:[]}},'owned.example.com');
 assert.equal(ci.evidence_source,'not_observed');assert.equal(ci.issuer,null);assert.equal(ci.certificate_status,'unknown');assert.equal(ci.incomplete,true);assert.equal(ci.live_certificate_verified,false);assert.equal(liveCertificateFindings(ssl,'owned.example.com').length,0);
});

// ── Anonymous free-tool TLS profile (F2 SSL/TLS checker) ──────────────────────
const freeToolRequest=(overrides={})=>({schema_version:'network-probe-request-v1',request_id:'ftls_1',workspace_id:null,scan_id:null,profile:'free_tool',deadline_at:new Date(Date.now()+7_000).toISOString(),targets:[{address:null,hostname:'owned.example.com'}],ports:[443],...overrides});
const freeToolBoundary={
 contract:validate=>{
  const ok=validate(freeToolRequest()).ok===true;
  const refused=[{workspace_id:'workspace_1'},{scan_id:'scan_1'},{ports:[8443]},{ports:[443,80]},{targets:[{address:'93.184.216.34',hostname:null}]},{targets:[{address:'10.0.0.1',hostname:null}]},{targets:[{address:null,hostname:'owned.example.com'},{address:null,hostname:'b.example.com'}]},{deadline_at:new Date(Date.now()+9_000).toISOString()},{extra:true}]
   .filter(delta=>validate(freeToolRequest(delta)).ok===false).length;
  return ok&&refused===9;
 },
};
const freeToolServer=async({trusted=false,raw=false}={})=>{
 const sockets=new Set();
 const server=raw?net.createServer(socket=>{sockets.add(socket);socket.on('error',()=>{});}):tls.createServer({key:read('valid.key'),cert:read('valid.pem')});
 server.on('connection',socket=>{sockets.add(socket);socket.on('close',()=>sockets.delete(socket));});server.on('tlsClientError',()=>{});
 await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'127.0.0.1',resolve));
 const port=server.address().port;
 return {deps:(extra={})=>({resolve:async(_,family)=>family===4?['93.184.216.34']:[],connect:opts=>net.connect({...opts,host:'127.0.0.1',port}),...(trusted?{trustedRoots:[read('ca.pem')]}:{}),...extra}),
  close:async()=>{for(const socket of sockets)socket.destroy();await new Promise(resolve=>server.close(resolve));}};
};
test('free_tool request is anonymous, one hostname, port 443 only, deadline at most 8 s',()=>{
 assert.equal(freeToolBoundary.contract(validateNetworkProbeRequest),true);
 assert.equal(validateNetworkProbeRequest({...request(),workspace_id:null}).ok,false,'only free_tool is anonymous');
});
test('free_tool returns certificate and protocol facts only, within the response cap',async()=>{
 const server=await freeToolServer({trusted:true});
 try{
  const req=freeToolRequest();const receipt=await runCollector(req,server.deps());
  assert.equal(receipt.outcome,'observed');assert.equal(receipt.trust.result,'valid');assert.equal(receipt.hostname_match,'matched');
  assert.ok(['TLSv1.2','TLSv1.3'].includes(receipt.protocol));assert.deepEqual(receipt.certificate.dns_names,['owned.example.com']);
  assert.match(receipt.certificate.issuer,/LOCAL TEST CA/);assert.equal(receipt.endpoint.address,'93.184.216.34');
  assert.deepEqual(validateFreeToolTlsReceipt(req,receipt),{ok:true});
  const json=JSON.stringify(receipt);assert.ok(Buffer.byteLength(json)<FREE_TOOL_TLS_LIMITS.responseBytes);assert.ok(!/der_base64|banner/.test(json));
  for(const mutate of [r=>r.certificate.der_base64='AA==',r=>r.endpoint.port=8443,r=>r.endpoint.address='10.0.0.1',r=>r.certificate.issuer='x'.repeat(300),r=>r.chain=Array(5).fill({subject:'a',issuer:'b',not_after:r.certificate.not_after}),r=>r.request_id='other',r=>r.trust.result='maybe']){
   const altered=structuredClone(receipt);mutate(altered);assert.equal(validateFreeToolTlsReceipt(req,altered).ok,false);
  }
 }finally{await server.close();}
});
const freeToolPrivateDnsMakesNoConnection=async collector=>{
 let connects=0;const receipt=await collector(freeToolRequest(),{resolve:async(_,family)=>family===4?['93.184.216.34','10.0.0.7']:[],connect:()=>{connects++;throw Error('unexpected');}});
 return connects===0&&receipt.outcome==='unavailable'&&receipt.reason==='dns_non_public_answer';
};
test('free_tool: a private or reserved DNS answer makes no connection',async()=>{
 assert.equal(await freeToolPrivateDnsMakesNoConnection(runCollector),true);
});
test('free_tool: one pinned address, one handshake, no retry',async()=>{
 const hosts=[];const req=freeToolRequest();
 const receipt=await runCollector(req,{resolve:async(_,family)=>family===4?['93.184.216.40','93.184.216.34']:['2606:4700::1111'],connect:opts=>{hosts.push(`${opts.host}:${opts.port}`);return net.connect({host:'127.0.0.1',port:1});}});
 assert.deepEqual(hosts,['93.184.216.34:443']);assert.ok(['tls_connection_failed','tls_handshake_failed'].includes(receipt.reason));assert.deepEqual(validateFreeToolTlsReceipt(req,receipt),{ok:true});
});
const freeToolHandshakeTimesOut=async collector=>{
 const server=await freeToolServer({raw:true});const started=Date.now();
 try{const receipt=await collector(freeToolRequest(),server.deps({freeToolLimits:{handshakeMs:200}}));return receipt.reason==='tls_timeout'&&Date.now()-started<1500;}
 finally{await server.close();}
};
test('free_tool: a handshake that never completes ends at the handshake cap',async()=>{
 assert.equal(await freeToolHandshakeTimesOut(runCollector),true);
});
const freeToolOversizeRefused=async collector=>{
 const server=await freeToolServer({trusted:true});
 try{
  const big=await collector(freeToolRequest(),server.deps({freeToolLimits:{certificateBytes:64}}));
  const flood=await collector(freeToolRequest(),server.deps({freeToolLimits:{handshakeBytes:64}}));
  return big.reason==='certificate_too_large'&&big.certificate===null&&flood.reason==='handshake_too_large';
 }finally{await server.close();}
};
test('free_tool: an oversize certificate or handshake returns no certificate data',async()=>{
 assert.equal(await freeToolOversizeRefused(runCollector),true);
});
const freeToolRoutesIsolated=async worker=>{
 const slots=[];const env={PROBE_CONTAINERS:{getByName:name=>{slots.push(name);return{fetch:async()=>new Response('',{status:503})};}}};
 const call=(path,body)=>worker.fetch(new Request(`http://container${path}`,{method:'POST',body:JSON.stringify(body)}),env);
 const onCollect=await call('/collect',freeToolRequest());const scanOnFree=await call('/free-tool-tls',request());
 const busy=await call('/free-tool-tls',freeToolRequest());
 return onCollect.status===400&&scanOnFree.status===400&&busy.status===503&&JSON.stringify(slots)==='["free-tool-slot-0"]';
};
test('free_tool runs only on /free-tool-tls, on its own slot, with no fallback',async()=>{
 const {default:worker}=await importWorkerForLocalTests();
 assert.equal(await freeToolRoutesIsolated(worker),true);
});
test('free_tool DO refuses an oversize collector response',async()=>{
 const {NetworkProbeContainer}=await importWorkerForLocalTests();
 const ctx={storage:{setAlarm:async()=>{},deleteAlarm:async()=>{}},container:{running:false,start(){this.running=true;},setInactivityTimeout:async()=>{},destroy:async function(){this.running=false;},exec:async()=>({stdout:new Response('{"x":"'+'a'.repeat(FREE_TOOL_TLS_LIMITS.responseBytes)+'"}').body,exitCode:Promise.resolve(0)})}};
 const response=await new NetworkProbeContainer(ctx,{}).fetch(new Request('http://container/free-tool-tls',{method:'POST',body:JSON.stringify(freeToolRequest())}));
 assert.equal(response.status,502);
});
test('scan-api free-tool client: busy, invalid receipts and the importer guard',async()=>{
 const {runFreeToolTlsCheck}=await import('../../scan-api/src/engines/free-tools/tls-certificate-check.js');
 assert.equal((await runFreeToolTlsCheck({NETWORK_PROBE:{fetch:async()=>new Response('',{status:503})}},'owned.example.com')).error,'collector_busy');
 assert.equal((await runFreeToolTlsCheck({NETWORK_PROBE:{fetch:async()=>Response.json({schema_version:'free-tool-tls-receipt-v1'})}},'owned.example.com')).error,'invalid_receipt');
 assert.equal((await runFreeToolTlsCheck({NETWORK_PROBE:{fetch:async()=>{throw Error('x');}}},'10.0.0.1')).error,'invalid_target');
 // Only the free-tools route (after Turnstile and the limiter) may call it.
 const src=new URL('../../scan-api/src/',import.meta.url);const importers=[];
 const walk=dir=>{for(const entry of fs.readdirSync(dir,{withFileTypes:true})){const full=new URL(entry.name+(entry.isDirectory()?'/':''),dir);if(entry.isDirectory())walk(full);else if(entry.name.endsWith('.js')&&/free-tools\/tls-certificate-check\.js/.test(fs.readFileSync(full,'utf8')))importers.push(full.pathname.slice(src.pathname.length));}};
 walk(src);
 assert.ok(importers.every(file=>file==='routes/free-tools.js'),JSON.stringify(importers));
});

// Mutants: each boundary above must fail against a deliberately broken copy.
test('free_tool boundary mutants are killed',async()=>{
 const os=await import('node:os');const path=await import('node:path');
 const repo=new URL('../../../',import.meta.url).pathname;
 const mutants=[
  ['contract deadline cap',          'workers/network-probe/src/contract.js',"(freeTool?FREE_TOOL_TLS_LIMITS.deadlineMs:90_000)","90_000",                         async m=>freeToolBoundary.contract(m.contract.validateNetworkProbeRequest)],
  ['contract anonymous identity',    'workspace_id','',''],
  ['contract port 443 only',         'workers/network-probe/src/contract.js',"input.ports.length!==1||input.ports[0]!==443||","input.ports.length!==1||",   async m=>freeToolBoundary.contract(m.contract.validateNetworkProbeRequest)],
  ['collector private DNS refusal',  'workers/network-probe/src/collector.js',"if(addresses.some(address=>!isPublicProbeAddress(address)))throw new Error('dns_non_public_answer');","", async m=>freeToolPrivateDnsMakesNoConnection(m.collector.runCollector)],
  ['collector handshake cap',        'workers/network-probe/src/collector.js',"Math.min(limits.handshakeMs,remaining)","remaining",                            async m=>freeToolHandshakeTimesOut(m.collector.runCollector)],
  ['collector certificate cap',      'workers/network-probe/src/collector.js',"if(peer.raw.byteLength>limits.certificateBytes)return finish({reason:'certificate_too_large'});","", async m=>freeToolOversizeRefused(m.collector.runCollector)],
  ['dispatcher free-tool slot',      'workers/network-probe/src/index.js',"path==='/free-tool-tls'?['free-tool-slot-0']:['probe-slot-0','probe-slot-1']","['probe-slot-0','probe-slot-1']", async m=>freeToolRoutesIsolated(m.index.default)],
 ];
 mutants[1]=['contract anonymous identity','workers/network-probe/src/contract.js',"freeTool&&key!=='request_id'?input[key]!==null:","false?null:",async m=>freeToolBoundary.contract(m.contract.validateNetworkProbeRequest)];
 for(const [name,file,from,to,check] of mutants){
  const dir=fs.mkdtempSync(path.join(process.env.NETWORK_PROBE_TEMP_ROOT||os.tmpdir(),'cm-free-tool-mutant-'));
  try{
   fs.cpSync(path.join(repo,'workers/network-probe/src'),path.join(dir,'workers/network-probe/src'),{recursive:true});
   fs.cpSync(path.join(repo,'shared'),path.join(dir,'shared'),{recursive:true});
   fs.cpSync(path.join(repo,'workers/scan-api/src'),path.join(dir,'workers/scan-api/src'),{recursive:true});
   fs.symlinkSync(path.join(repo,'workers/scan-api/node_modules'),path.join(dir,'workers/scan-api/node_modules'),'dir');
   const target=path.join(dir,file);const source=fs.readFileSync(target,'utf8');
   assert.equal(source.split(from).length,2,`${name}: anchor`);
   fs.writeFileSync(target,source.replace(from,to));
   const base=path.join(dir,'workers/network-probe/src/');
   const m={contract:await import(`file://${base}contract.js`),collector:await import(`file://${base}collector.js`),index:await importWorkerForLocalTests(`${base}index.js`,{module:true})};
   assert.equal(await check(m),false,`${name}: mutant survived`);
  }finally{fs.rmSync(dir,{recursive:true,force:true});}
 }
});

// ── Added ports (21 Oct 2026): Telnet 23, Docker API 2375, WinRM 5985/5986,
// memcached 11211. Open port and unsolicited banner only — nothing is ever sent.
const NEW_PORTS = [23, 2375, 5985, 5986, 11211];
const portRequest = (ports) => ({ ...request('network_services'), ports });
const silentOrBannerServer = async (banner = null) => {
  let received = 0; const sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket); socket.on('data', chunk => { received += chunk.length; }); socket.on('error', () => {});
    if (banner) socket.write(banner);
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  return { received: () => received, connect: opts => net.connect({ ...opts, host: '127.0.0.1', port }),
    close: async () => { for (const s of sockets) s.destroy(); await new Promise(r => server.close(r)); } };
};
test('new ports are accepted, unlisted ports and the per-run limits still refuse', () => {
  for (const port of NEW_PORTS) assert.equal(validateNetworkProbeRequest(portRequest([port])).ok, true, String(port));
  assert.equal(validateNetworkProbeRequest(portRequest(NEW_PORTS)).ok, true);
  assert.equal(validateNetworkProbeRequest(portRequest([1234])).reason, 'port_limit');
  assert.equal(validateNetworkProbeRequest(portRequest([2376])).reason, 'port_limit');
  assert.equal(validateNetworkProbeRequest(portRequest([...NEW_PORTS, 21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993])).reason, 'port_limit', 'more than 16 ports per run');
});
test('Telnet is identified from its own option negotiation, and nothing is sent to it', async () => {
  const srv = await silentOrBannerServer(Buffer.from([0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03]));
  try {
    const req = portRequest([23]);
    const receipt = await runCollector(req, { connect: srv.connect });
    const row = receipt.observations[0];
    assert.equal(row.state, 'open'); assert.equal(row.service?.name, 'telnet'); assert.equal(row.service?.basis, 'unsolicited_tcp_banner');
    assert.equal(row.tls, null, 'no TLS attempt on a banner port');
    assert.equal(srv.received(), 0, 'the collector wrote nothing to the service');
    assert.deepEqual(validateNetworkProbeReceipt(req, receipt), { ok: true });
  } finally { await srv.close(); }
});
test('Docker API, WinRM and memcached ports: open is reported without any request or claimed service', async () => {
  for (const port of [2375, 5985, 5986, 11211]) {
    const srv = await silentOrBannerServer(null);
    try {
      const req = portRequest([port]);
      const receipt = await runCollector(req, { connect: srv.connect });
      const row = receipt.observations[0];
      assert.equal(row.state, 'open', String(port)); assert.equal(row.service, null, `${port}: no service is claimed without a banner`);
      assert.equal(row.tls, null, `${port}: no TLS handshake`);
      assert.equal(srv.received(), 0, `${port}: the collector wrote nothing`);
      assert.deepEqual(validateNetworkProbeReceipt(req, receipt), { ok: true });
    } finally { await srv.close(); }
  }
});
test('the serialized container program accepts the new ports', () => {
  const source = collectorProgram(); const req = portRequest(NEW_PORTS);
  const local = source.slice(0, source.indexOf("let raw='';")) + `const result=await runCollector(${JSON.stringify(req)},{connect:()=>{throw Error('fixture');}});process.stdout.write(JSON.stringify(result));`;
  const run = spawnSync(process.execPath, ['--input-type=module', '-e', local], { encoding: 'utf8', timeout: 5000 });
  assert.equal(run.status, 0, run.stderr); assert.equal(JSON.parse(run.stdout).observations.length, NEW_PORTS.length);
});
