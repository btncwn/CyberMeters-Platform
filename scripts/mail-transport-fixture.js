import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mailMxPlan, projectMailMxReceipt, runMailTransportModule } from '../workers/scan-api/src/engines/mail-transport.js';
import { validateTlsAssessmentRequest, projectTlsCollectorReceipt } from '../workers/network-probe/src/tls-contract.js';

const mx = { host: 'route1.mx.cybermeters.com', priority: 10 };
const evidence = (cipher = 'TLS_AES_128_GCM_SHA256') => ({ authenticated_finished: true,
  negotiated: { version: 'tls1_3', cipher },
  certificates: { hostname: true, trust: 'valid', offered_chain: [{ not_after: 1790000000 }] } });
const receipt = (reason = 'handshake_completed', cipher) => ({ results: [{ state: reason === 'handshake_completed' ? 'accepted' :
  reason === 'starttls_unavailable' ? 'rejected' : 'uncertain', reason,
  evidence: reason === 'handshake_completed' ? evidence(cipher) : null, observed_at: '2026-10-18T00:00:00.000Z' }] });
assert.equal(projectMailMxReceipt(mx,receipt()).state,'tested');
assert.equal(projectMailMxReceipt(mx,receipt()).tls_version,'tls1_3');
assert.equal(projectMailMxReceipt(mx,receipt('starttls_unavailable')).starttls_offered,false);
assert.equal(projectMailMxReceipt(mx,receipt('starttls_unavailable')).state,'not_offered');
assert.equal(projectMailMxReceipt(mx,receipt('probe_incomplete')).state,'not_tested');
assert.equal(projectMailMxReceipt(mx,receipt('handshake_completed','RC4-SHA')).cipher_class,'weak');
assert.equal(projectMailMxReceipt(mx,receipt()).cipher_class,'not_flagged_weak');

const dns = { mx_records: [
  {value:'20 route2.mx.cybermeters.com.'}, {value:'10 route1.mx.cybermeters.com.'},
  {value:'30 route3.mx.cybermeters.com.'}, {value:'40 route4.mx.cybermeters.com.'},
  {value:'50 route5.mx.cybermeters.com.'}, {value:'60 route6.mx.cybermeters.com.'},
  {value:'10 route1.mx.cybermeters.com.'},
] };
assert.deepEqual(mailMxPlan(dns).map(row=>row.host),[
  'route1.mx.cybermeters.com','route2.mx.cybermeters.com','route3.mx.cybermeters.com',
  'route4.mx.cybermeters.com','route5.mx.cybermeters.com',
]);
let allowed = false, calls = 0;
const env = { cybermeters_db: { prepare: () => ({bind: () => ({first: async () => allowed ? {allowed:1} : null})}) } };
const scan = { id:'scan_test',workspace_id:'ws_test',domain_id:'domain_test',domain:'cybermeters.com' };
const lookup = async (host,type) => ({Status:0,Answer:type==='A'?[{type:1,name:host+'.',data:'162.159.205.12'}]:[]});
const collect = async (_env,request) => { calls++; assert.equal(validateTlsAssessmentRequest(request).ok,true);
  assert.equal(request.max_connections,1); assert.equal(request.endpoint.port,25);
  return receipt(calls===1?'handshake_completed':'starttls_unavailable'); };
assert.equal((await runMailTransportModule(env,{...scan,workspace_id:null},dns,{lookup,collect})).state,'not_tested');
assert.equal((await runMailTransportModule(env,scan,dns,{lookup,collect})).reason,'verified_workspace_required');
assert.equal(calls,0,'unverified and anonymous scans must not connect');
allowed = true;
const observed = await runMailTransportModule(env,scan,dns,{lookup,collect});
assert.equal(calls,5);
assert.equal(observed.coverage.planned,5);
assert.equal(observed.state,'observed');
assert.equal(observed.hosts[0].state,'tested');
assert.equal(observed.hosts[1].state,'not_offered');
const foreignMx = {schema_version:'tls-assessment-request-v1',request_id:'mail_fixture',
  workspace_id:scan.workspace_id,scan_id:scan.id,domain_id:scan.domain_id,domain:scan.domain,
  endpoint:{hostname:'mx.other-domain.net',sni:'mx.other-domain.net',address:'1.1.1.1',
    port:25,transport:'tcp',application_protocol:'smtp',dns_addresses:['1.1.1.1'],dns_observed_at:new Date().toISOString()},
  scope:{kind:'mail_mx',service_authorization_id:null,generation:0,special_consent:false,consent_version:null},
  checks:[{control:'certificate',protocol:'tls1_2',cipher_id:null}],
  deadline_at:new Date(Date.now()+9000).toISOString(),max_connections:1,max_bytes:262144};
assert.equal(validateTlsAssessmentRequest(foreignMx).ok,true,'an external MX is permitted only within the bounded mail scope');
assert.equal(validateTlsAssessmentRequest({...foreignMx,scope:{...foreignMx.scope,kind:'authorized_service'}}).ok,false);
assert.equal(validateTlsAssessmentRequest({...foreignMx,endpoint:{...foreignMx.endpoint,port:587}}).ok,false);
assert.equal(validateTlsAssessmentRequest({...foreignMx,max_connections:2}).ok,false);
const finishedAt=new Date(), startedAt=new Date(finishedAt.getTime()-100);
const rawAbsent={schema_version:'tls-collector-raw-v1',request_id:foreignMx.request_id,
  started_at:startedAt.toISOString(),finished_at:finishedAt.toISOString(),
  results:[{check:foreignMx.checks[0],engine_result:null,reason:'starttls_unavailable',
    observed_at:finishedAt.toISOString(),physical_telemetry:{connections:1,bytes_sent:32,bytes_received:64,duration_ms:100}}],
  telemetry:{connections:1,bytes_sent:32,bytes_received:64,duration_ms:100}};
assert.equal(projectTlsCollectorReceipt(foreignMx,rawAbsent,{now:finishedAt.getTime(),requireSandbox:false}).quality,'complete');
assert.throws(() => projectTlsCollectorReceipt({...foreignMx,scope:{...foreignMx.scope,kind:'authorized_service'}},rawAbsent,
  {now:finishedAt.getTime(),requireSandbox:false}),/unrun_reason/);

// Mutation proof: force the compiled-catalog weak-cipher classification to
// return false in an isolated source copy. The RC4 fixture must then fail.
const sourcePath=fileURLToPath(new URL('../workers/scan-api/src/engines/mail-transport.js',import.meta.url));
const source=readFileSync(sourcePath,'utf8');
assert(source.includes('isWeakTlsCipher(cipher)'));
// A dead MX host (21 Oct 2026: a cancelled tenant's MX read only "not tested").
// NXDOMAIN on A and AAAA, confirmed by an independent resolver, is a definitive
// observation; one resolver alone, or any transient failure, never is.
{
  const deadDns = { mx_records: [{ value: '0 tenant-example.mail.protection.example.net.' }] };
  const nx = async (host,type) => ({Status:3,TC:false,Question:[{name:host,type:type==='A'?1:28}]});
  let probes = 0;
  const noProbe = async () => { probes++; return receipt(); };
  const dead = await runMailTransportModule(env,scan,deadDns,{lookup:nx,confirmLookup:host=>nx(host,'A'),collect:noProbe});
  assert.equal(dead.hosts[0].state,'no_address');
  assert.equal(dead.hosts[0].reason,'mx_host_does_not_exist');
  assert.equal(dead.state,'observed','a definitively absent MX host is an observation, not a gap');
  assert.equal(probes,0,'no connection is attempted to a host that does not exist');
  const disagreed = await runMailTransportModule(env,scan,deadDns,{lookup:nx,
    confirmLookup:async host=>({Status:0,Question:[{name:host,type:1}],Answer:[{type:1,name:host,data:'192.0.2.9'}]}),collect:noProbe});
  assert.equal(disagreed.hosts[0].reason,'probe_unavailable','the second resolver disagreeing keeps it unproven');
  const flaky = await runMailTransportModule(env,scan,deadDns,{lookup:async()=>{throw new Error('timeout');},
    confirmLookup:host=>nx(host,'A'),collect:noProbe});
  assert.equal(flaky.hosts[0].reason,'probe_unavailable','a failed lookup is never a dead MX');
}
const directory=mkdtempSync(join(tmpdir(),'cm-mail-mutation-'));
try {
  const imports=source.replaceAll("from '../../../network-probe/src/contract.js'",`from '${new URL('../workers/network-probe/src/contract.js',import.meta.url)}'`)
    .replaceAll("from './exposure-jobs.js'",`from '${new URL('../workers/scan-api/src/engines/exposure-jobs.js',import.meta.url)}'`)
    .replaceAll("from './dns.js'",`from '${new URL('../workers/scan-api/src/engines/dns.js',import.meta.url)}'`)
    .replaceAll("from './tls-planner.js'",`from '${new URL('../workers/scan-api/src/engines/tls-planner.js',import.meta.url)}'`)
    .replaceAll("from '../../../../shared/tls/catalog.js'",`from '${new URL('../shared/tls/catalog.js',import.meta.url)}'`)
    .replaceAll("from '../lib/util.js'",`from '${new URL('../workers/scan-api/src/lib/util.js',import.meta.url)}'`)
    .replaceAll("from '../lib/ssrf.js'",`from '${new URL('../workers/scan-api/src/lib/ssrf.js',import.meta.url)}'`);
  const target=join(directory,'mail-transport-mutant.mjs');
  writeFileSync(target,imports.replace('isWeakTlsCipher(cipher) ?','false ?'));
  const mutant=await import(`file://${target}`);
  assert.throws(() => assert.equal(mutant.projectMailMxReceipt(mx,receipt('handshake_completed','RC4-SHA')).cipher_class,'weak'));
  // Mutant: a dead MX proven by ONE resolver (no independent confirmation).
  const anchor='primaryPackets.every(packet=>nxdomainFor(packet,name))&&nxdomainFor(confirmPacket,name)';
  assert.equal(imports.split(anchor).length,2,'dead-MX mutation anchor present once');
  const target2=join(directory,'mail-transport-mutant-2.mjs');
  writeFileSync(target2,imports.replace(anchor,'primaryPackets.every(packet=>nxdomainFor(packet,name))'));
  const mutant2=await import(`file://${target2}`);
  const host='tenant-example.mail.protection.example.net';
  const nxPacket={Status:3,TC:false,Question:[{name:host,type:1}]};
  assert.equal(mutant2.provesNxdomain([nxPacket,nxPacket],{Status:0,Question:[{name:host,type:1}],Answer:[{type:1,data:'192.0.2.9'}]},host),true,
    'mutant without independent confirmation wrongly proves a dead MX (caught)');
} finally { rmSync(directory,{recursive:true,force:true}); }
console.log('mail transport: present, absent, weak, verified gate, five-MX cap and mutation passed');
