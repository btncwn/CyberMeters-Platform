import test, {after} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import tls from 'node:tls';
import {spawnSync} from 'node:child_process';
import {runCollector,collectorProgram} from '../src/collector.js';
import {isPublicProbeAddress,validateNetworkProbeRequest,readBoundedJson} from '../src/contract.js';
import {validateNetworkProbeReceipt} from '../src/receipt.js';
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
test('live leaf wins over a conflicting CT projection without deleting CT evidence',async()=>{
 const {receipt}=await tlsFixture('expired',{trusted:true});const ssl=attachLiveTlsToSsl({tls_state:'observed_present',cert_not_after:'2045-01-01T00:00:00.000Z',cert_expiry_days:7000,cert_issuer:'CT issuer'}, {receipt});
 assert.equal(ssl.cert_not_after,'2045-01-01T00:00:00.000Z');
 const ci=runCertificateIntelligenceModule({ssl,subdomains:{sources:{crt_sh:{count:1},certspotter:{count:1}}}},'owned.example.com');
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

test('fresh TLS case verification needs every endpoint and cannot use CT/HTTP success',async()=>{
 const {buildLiveTlsCaseVerificationEvidence}=await import('../../scan-api/src/engines/certificate-lifecycle.js');
 const {receipt}=await tlsFixture('valid',{trusted:true});
 const now=new Date().toISOString();const ssl=attachLiveTlsToSsl({}, {receipt});
 const ci=runCertificateIntelligenceModule({ssl},'owned.example.com',{observedAt:now,engineVersion:'local-fixture'});
 const current={id:'observation_1',last_seen:now,evidence_json:JSON.stringify({signal_completeness:ci.signal_completeness})};
 const context={current,after:new Date(Date.now()-60_000).toISOString(),hostname:'owned.example.com',now};
 assert.equal(buildLiveTlsCaseVerificationEvidence('certificate_untrusted',context).verification_result,'verified');
 for(const change of [v=>v.leaf.value.all_planned_endpoints_observed=false,v=>v.hostname_match.observation_scope='ct_issuance',v=>v.trust_store_validation.publishable=false,v=>v.leaf.value.endpoint_checks.push({...v.leaf.value.endpoint_checks[0],hostname_match:'mismatched'})]){
  const bad=structuredClone(ci.signal_completeness);change(bad.signals);const altered={...current,evidence_json:JSON.stringify({signal_completeness:bad})};assert.notEqual(buildLiveTlsCaseVerificationEvidence('certificate_untrusted',{...context,current:altered}).verification_result,'verified');
 }
 assert.equal(buildLiveTlsCaseVerificationEvidence('certificate_untrusted',{...context,after:now}).verification_result,'inconclusive');
 assert.equal(buildLiveTlsCaseVerificationEvidence('certificate_untrusted',{...context,current:{...current,evidence_json:'{"https_available":true}'}}).verification_result,'inconclusive');
});

async function importWorkerForLocalTests(bundlePath){
 const url=bundlePath?new URL(`file://${bundlePath}`):new URL('../src/index.js',import.meta.url);
 let source=fs.readFileSync(url,'utf8');
 source=source.replace(/import\s*\{\s*DurableObject\s*\}\s*from\s*["']cloudflare:workers["'];?/,'class DurableObject { constructor(ctx,env){this.ctx=ctx;this.env=env;} }');
 source=source.replace(/from '([^']+)'/g,(match,path)=>path.startsWith('.')?`from '${new URL(path,url).href}'`:match);
 if(bundlePath)source+='\nexport { collectorProgram };';
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

test('live leaf fingerprint changes persistent identity while historical CT keys stay exact',async()=>{
 const {certificateObservationKey}=await import('../../scan-api/src/engines/cert-events.js');
 const {hashToken}=await import('../../scan-api/src/lib/auth-crypto.js');
 const historic={issuer:'same issuer',subject:'same subject',expires_at:'2040-01-01T00:00:00.000Z',san_hostnames:['owned.example.com']};
 assert.equal(await certificateObservationKey(historic),await hashToken('same issuer|same subject|2040-01-01T00:00:00.000Z|owned.example.com'));
 const live={...historic,evidence_source:'live_tls',live_certificate_verified:true,live_tls:{leaf_certificate:{collection_complete:true,certificate_identity:'sha256:'+'a'.repeat(64)}}};
 const changed=structuredClone(live);changed.live_tls.leaf_certificate.certificate_identity='sha256:'+'b'.repeat(64);
 assert.notEqual(await certificateObservationKey(live),await certificateObservationKey(changed));
 assert.notEqual(await certificateObservationKey(live),await certificateObservationKey(historic));
});

test('configured collector failure preserves CT but cannot present a valid live certificate',()=>{
 const ssl=attachLiveTlsToSsl({tls_state:'observed_present',https_available:true,cert_not_after:'2040-01-01T00:00:00.000Z',cert_expiry_days:4800,cert_issuer:'CT issuer'}, {error:'live_tls_unavailable',receipt:null});
 const ci=runCertificateIntelligenceModule({ssl,subdomains:{sources:{crt_sh:{count:1},certspotter:{count:1}}}},'owned.example.com');
 assert.equal(ci.evidence_source,'certificate_transparency');assert.equal(ci.issuer,'CT issuer');assert.equal(ci.certificate_status,'unknown');assert.equal(ci.incomplete,true);assert.equal(ci.live_certificate_verified,false);assert.equal(liveCertificateFindings(ssl,'owned.example.com').length,0);
});
