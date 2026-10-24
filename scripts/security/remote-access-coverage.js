// Independent advisory-boundary and product-replacement witnesses. Imported by
// the existing catalogue gate; all requests and database rows here are fixtures.
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { remoteAccessFingerprint, assessRemoteAccess, validRemoteAccessEvidence,
  REMOTE_ACCESS_ADVISORIES, REMOTE_ACCESS_CONDITIONAL_ADVISORIES, REMOTE_ACCESS_PATHS } from '../../shared/exposure/remote-access.js';
import { exposureEvaluatorProgramSource } from '../../shared/exposure/evaluate.js';
import { exposureIdentity } from '../../shared/exposure/redaction.js';
import { externalExposureModule, evaluateExposureCondition } from '../../workers/scan-api/src/engines/exposure-findings.js';
import { refreshRemoteAccessCatalogue } from '../../workers/scan-api/src/engines/remote-access-catalogue.js';
import { evaluateWebsiteSecurityForScan } from '../../workers/scan-api/src/engines/website-security-lifecycle.js';
import { canTransitionCase } from '../../workers/scan-api/src/engines/managed-case-model.js';
import { buildDb, makeEnv } from './lib/worker-harness.js';

const now = Date.parse('2026-10-24T02:00:00Z'), root = 'https://vpn.example.test/';
const profiles = {
  panos_globalprotect: ['GlobalProtect Portal','/global-protect/login.esp','user','PAN-OS',''],
  fortios_sslvpn: ['SSL VPN Service','/remote/logincheck','username','FortiOS','FortiGate'],
  fortiproxy_sslvpn: ['SSL VPN Service','/remote/logincheck','username','FortiProxy','FortiProxy'],
  netscaler_gateway: ['NetScaler Gateway','/cgi/login','login','NetScaler Gateway',''],
  ivanti_connect_secure: ['Ivanti Connect Secure','/dana-na/auth/url_default/login.cgi','username','Ivanti Connect Secure',''],
};
const html = (id, version = null) => {
  const [title, action, user, label, marker] = profiles[id];
  return `<html><title>${title}</title><body><div>${marker}</div><form action="${action}"><input name="${user}"><input type="password" name="password"></form><footer>${version === null ? '' : `${label} version: ${version}`}</footer></body></html>`;
};
const catalogue = {fetched_at:new Date(now).toISOString(),released_at:new Date(now).toISOString(),
  catalogue_version:'2026.10.23',cves:[...new Set(REMOTE_ACCESS_ADVISORIES.map(r=>r.cve))]};
const portal = (product,version) => remoteAccessFingerprint(html(product,version),root);
const state = (product,version,cache=catalogue) => assessRemoteAccess(portal(product,version),cache,now).state;

// Golden expectations are explicit advisory examples, not computed from the
// implementation's table. In particular the two SSL-VPN products differ.
const goldens = [
  ['panos_globalprotect','10.2.0-h2','present'],['panos_globalprotect','10.2.0-h3','clear'],
  ['panos_globalprotect','10.2.4-h15','present'],['panos_globalprotect','10.2.4-h16','clear'],
  ['panos_globalprotect','10.2.8-h2','present'],['panos_globalprotect','10.2.8-h3','clear'],
  ['panos_globalprotect','10.2.10','clear'],['panos_globalprotect','11.0.3-h9','present'],
  ['panos_globalprotect','11.0.3-h10','clear'],['panos_globalprotect','11.1.3','clear'],
  ['fortios_sslvpn','7.4.2','present'],['fortios_sslvpn','7.4.3','clear'],
  ['fortios_sslvpn','7.2.5','present'],['fortios_sslvpn','7.2.6','present'],['fortios_sslvpn','7.2.7','clear'],
  ['fortios_sslvpn','7.0.13','present'],['fortios_sslvpn','7.0.14','clear'],
  ['fortios_sslvpn','6.0.16','present'],['fortios_sslvpn','6.0.17','present'],['fortios_sslvpn','6.0.18','present'],
  ['fortios_sslvpn','6.0.19','deferred'],['fortios_sslvpn','7.6.1','deferred'],
  ['fortiproxy_sslvpn','7.2.7','present'],['fortiproxy_sslvpn','7.2.8','present'],['fortiproxy_sslvpn','7.2.9','clear'],
  ['fortiproxy_sslvpn','7.0.14','present'],['fortiproxy_sslvpn','7.0.15','clear'],
  ['fortiproxy_sslvpn','2.0.13','present'],['fortiproxy_sslvpn','2.0.14','clear'],['fortiproxy_sslvpn','7.4.3','clear'],
  ['netscaler_gateway','13.1-58.32','present'],['netscaler_gateway','13.1-64.22','present'],
  ['netscaler_gateway','13.1-64.23','clear'],['netscaler_gateway','14.1-73.36','present'],
  ['netscaler_gateway','14.1-73.37','clear'],['netscaler_gateway','13.0-91.12','present'],
  ['netscaler_gateway','13.0-92.21','deferred'],
  ['ivanti_connect_secure','22.7R2.4','present'],['ivanti_connect_secure','22.7R2.5','present'],
  ['ivanti_connect_secure','22.7R2.6','clear'],['ivanti_connect_secure','22.7R2','present'],
  ['ivanti_connect_secure','9.1R18.9','present'],['ivanti_connect_secure','9.1R17.5','present'],
  ['ivanti_connect_secure','22.7R3.1','deferred'],['ivanti_connect_secure','22.8R2.6','deferred'],
];
const truth={tp:0,fp:0,tn:0,fn:0,unknown:0};
for(const [id,version,expected] of goldens){
  const actual=state(id,version);
  if(actual==='deferred')truth.unknown++;
  else if(actual==='present')truth[expected==='present'?'tp':'fp']++;
  else truth[expected==='present'?'fn':'tn']++;
  assert.equal(actual,expected,`${id} ${version}`);
}
assert.equal(truth.fp,0);assert.equal(truth.fn,0);
// Isolate each advisory in the catalogue so another overlapping CVE cannot
// mask an incorrect boundary. At its fixed release it must never emit that CVE;
// other affected advisories missing from this fixture catalogue stay deferred.
for(const [id,cve,before,fixed] of [
  ['fortios_sslvpn','CVE-2023-27997','7.2.4','7.2.5'],
  ['fortios_sslvpn','CVE-2024-21762','7.2.6','7.2.7'],
  ['fortiproxy_sslvpn','CVE-2023-27997','7.2.3','7.2.4'],
  ['fortiproxy_sslvpn','CVE-2024-21762','7.2.8','7.2.9'],
  ['netscaler_gateway','CVE-2023-3519','13.1-49.12','13.1-49.13'],
  ['netscaler_gateway','CVE-2023-4966','13.1-49.14','13.1-49.15'],
  ['netscaler_gateway','CVE-2023-6549','14.1-12.34','14.1-12.35'],
  ['netscaler_gateway','CVE-2025-5777','14.1-43.55','14.1-43.56'],
  ['netscaler_gateway','CVE-2025-6543','14.1-47.45','14.1-47.46'],
  ['netscaler_gateway','CVE-2025-7775','14.1-47.47','14.1-47.48'],
  ['netscaler_gateway','CVE-2026-8452','14.1-72.60','14.1-72.61'],
  ['netscaler_gateway','CVE-2026-88771','13.1-64.22','13.1-64.23'],
  ['ivanti_connect_secure','CVE-2025-0282','22.7R2.4','22.7R2.5'],
  ['ivanti_connect_secure','CVE-2025-22457','22.7R2.5','22.7R2.6'],
]){
  const cache={...catalogue,cves:[cve]};
  assert.equal(assessRemoteAccess(portal(id,before),cache,now).cve,cve,`${cve} lower boundary`);
  const patched=assessRemoteAccess(portal(id,fixed),cache,now);
  assert.notEqual(patched.cve,cve,`${cve} fixed boundary`);
  assert.ok(['clear','deferred'].includes(patched.state));
}
assert.equal(assessRemoteAccess(portal('ivanti_connect_secure','22.7R2.5'),catalogue,now).cve,'CVE-2025-22457',
  'fixing an earlier advisory cannot clear a later applicable advisory');
assert.equal(state('netscaler_gateway','13.1-64.22',{...catalogue,cves:['CVE-2026-88772']}),'deferred',
  'DTLS default is not evidence that this individual appliance has enabled it');
assert.equal(REMOTE_ACCESS_CONDITIONAL_ADVISORIES.length,2);
assert.ok(REMOTE_ACCESS_CONDITIONAL_ADVISORIES.every(r=>r.cve==='CVE-2026-88772'&&r.requires==='dtls_enabled'&&r.advisory.endsWith('CTX697096')));
assert.equal(new Set(REMOTE_ACCESS_ADVISORIES.map(r=>r.product_id)).size,5);
assert.equal(new Set(REMOTE_ACCESS_ADVISORIES.map(r=>r.cve)).size,13);
assert.deepEqual(REMOTE_ACCESS_PATHS,['/','/global-protect/login.esp','/remote/login','/vpn/index.html','/dana-na/auth/url_default/welcome.cgi']);

const controls=[{status:404,body:'Missing one'},{status:404,body:'Missing two'}];
const generated=vm.runInNewContext(exposureEvaluatorProgramSource()+';evaluateExposure',{URL,TextEncoder,TextDecoder,Uint8Array,DataView,Set,Map});
for(const [id,version] of goldens){
  const p=portal(id,version);assert.ok(p);assert.ok(validRemoteAccessEvidence(p));
  assert.equal(generated({rule:'remote-access-portal',response:{url:root,status:200,body:html(id,version)},controls}).portal.product_id,id);
  const hidden=portal(id,null);assert.equal(hidden.version_state,'absent');
  assert.equal(assessRemoteAccess(hidden,catalogue,now).reason,'version_not_visible');
  assert.equal(remoteAccessFingerprint(html(id,version).replace('type="password"','type="text"'),root),null);
  const action=profiles[id][1];
  assert.equal(remoteAccessFingerprint(html(id,version).replace(`action="${action}"`,`action="https://foreign.example.test${action}"`),root),null);
  assert.equal(remoteAccessFingerprint(`<article>${html(id,version)}</article>`,root),null);
  assert.equal(remoteAccessFingerprint(html(id,version),root+'?token=fixture'),null);
}
for(const [id,version] of [['panos_globalprotect','11.1.203'],['panos_globalprotect','11.01.2'],
  ['netscaler_gateway','13.1-37.279'],['netscaler_gateway','14.1-73.37 FIPS'],
  ['fortios_sslvpn','7.4.x'],['fortiproxy_sslvpn','7.2.7-build123'],['ivanti_connect_secure','22.7r2.6']]){
  assert.equal(portal(id,version).version_state,'unreadable');
  assert.equal(state(id,version),'deferred');
}
assert.equal(remoteAccessFingerprint(html('fortios_sslvpn','7.4.2').replace('FortiGate</div>','FortiGate FortiProxy</div>'),root),null,
  'ambiguous product markers cannot select the first matching product');
for(const id of Object.keys(profiles)){
  for(const field of ['Version: 13.1-64.23','Server version: v12R1','Release: 7_4_2']){
    const body=html(id).replace('</footer>',field+'</footer>');
    assert.equal(remoteAccessFingerprint(body,root).version_state,'unreadable','unattributed version-like text is not hidden');
    assert.equal(generated({rule:'remote-access-portal',response:{url:root,status:200,body},controls}).portal.version_state,'unreadable');
  }
  const client=html(id).replace('</footer>','Client version: v12R1</footer>');
  assert.equal(remoteAccessFingerprint(client,root).version_state,'absent','a clearly identified client version does not establish a server version');
}
for(const released_at of [undefined,new Date(now-14*86400000-1).toISOString(),new Date(now+60001).toISOString()])
  assert.equal(state('fortios_sslvpn','7.4.2',{...catalogue,released_at}),'deferred');
assert.equal(state('fortios_sslvpn','7.4.2',{...catalogue,released_at:new Date(now-14*86400000).toISOString()}),'present');
let writes=0;
await assert.rejects(()=>refreshRemoteAccessCatalogue({cybermeters_reports:{put:async()=>{writes++;}}},
  {now,fetchImpl:async()=>Response.json({catalogVersion:'2026.10.01',dateReleased:new Date(now-15*86400000).toISOString(),count:1,vulnerabilities:[{cveID:'CVE-2024-21762'}]})}));
assert.equal(writes,0,'a frozen mirror never refreshes the cache timestamp');

const wire=(id,version,url=root)=>({rule_id:'remote-access-portal',url,identity:exposureIdentity('remote-access-portal',url),
  state:'observed',comparable:true,portal:portal(id,version),observed_at:new Date(now).toISOString(),finding:null,
  observation:{rule_id:'remote-access-portal',severity:'info',indicators:['known_remote_access_login'],safe_url:url,identity:exposureIdentity('remote-access-portal',url)}});
const moduleFor=rows=>externalExposureModule({source:'external_exposure',quality:'complete',checks:rows,
  coverage:{completed:rows.length,pending:0,blocked:0,not_applicable:0,budget_exhausted:0,uncertain:0},observed_at:new Date(now).toISOString()},{catalogue,now});
const gpOld=moduleFor([wire('panos_globalprotect','11.1.2-h2')]),gpFixed=moduleFor([wire('panos_globalprotect','11.1.2-h3')]);
const osOld=moduleFor([wire('fortios_sslvpn','7.4.2')]),osFixed=moduleFor([wire('fortios_sslvpn','7.4.3')]);
const proxyFixed=moduleFor([wire('fortiproxy_sslvpn','7.4.3')]);
const gpKey=gpOld.findings[0].id,osKey=osOld.findings[0].id;
assert.equal(gpKey,'external_exposure_remote-access-portal__0dec19badbad6baf71bc53af2d07f213b7fa366f345f8a22d2b6c9932bd52234','shipped condition identity unchanged');
assert.notEqual(gpKey,osKey);
assert.equal(evaluateExposureCondition(gpKey,osFixed).state,'deferred');
assert.equal(evaluateExposureCondition(gpKey,{...osFixed,checks:osFixed.checks.map(row=>({...row,condition_key:gpKey}))}).state,'deferred',
  'a supplied condition key cannot override the product-bound identity');
assert.equal(evaluateExposureCondition(osKey,gpFixed).state,'deferred');
assert.equal(evaluateExposureCondition(osKey,proxyFixed).state,'deferred');
assert.equal(evaluateExposureCondition(osKey,osFixed).state,'clear');
assert.equal(evaluateExposureCondition(osKey,moduleFor([wire('fortios_sslvpn','7.4.3',root+'remote/login')])).state,'deferred');

// Real SQLite lifecycle: replacement products hold the original case/condition
// byte-for-byte; exact same-product retests verify through the shared factory.
const db=buildDb(),env=makeEnv(db);
db.exec("INSERT INTO users(id,email) VALUES('u','owner@example.test'); INSERT INTO workspaces(id,owner_user_id,name) VALUES('ws','u','Fixture'); INSERT INTO domains(id,user_id,domain) VALUES('d','u','example.test'); INSERT INTO workspace_domains(workspace_id,domain_id,verification_status) VALUES('ws','d','verified');");
const base={ssl:{https_available:true,https_probe_executed:true},headers:{accessible:true,headers_assessed:true},dns:{resolves:true}};
const run=(scan_id,mod)=>evaluateWebsiteSecurityForScan(env,{workspace_id:'ws',domain_id:'d',domain:'example.test',scan_id,findings:mod.findings,
  modules:{...base,external_exposure:mod},scanQuality:{status:'complete',modules_skipped:[],modules_incomplete:[]}});
const bytes=id=>JSON.stringify(db.prepare('SELECT * FROM managed_cases WHERE id=?').get(id));
async function submit(kase){
  for(const target of ['triaged','assigned','approved','action_in_progress','awaiting_verification']){
    const t=canTransitionCase({case:kase,target_status:target,actor:{actor_type:'customer',actor_id:'u'},owner_ref:'u'});
    assert.equal(t.ok,true,t.reason);db.prepare('UPDATE managed_cases SET status=? WHERE id=?').run(t.case.status,kase.id);kase={...kase,status:t.case.status};
  }
}
await run('baseline',gpFixed);await run('gp-detected',gpOld);
let kase=db.prepare('SELECT * FROM managed_cases').get();await submit(kase);
let before=bytes(kase.id),condition=JSON.stringify(db.prepare('SELECT * FROM website_security_conditions WHERE condition_key=?').get(gpKey));
await run('replacement-fixed',osFixed);assert.equal(bytes(kase.id),before);
assert.equal(JSON.stringify(db.prepare('SELECT * FROM website_security_conditions WHERE condition_key=?').get(gpKey)),condition);
await run('gp-fixed',gpFixed);assert.equal(db.prepare('SELECT status FROM managed_cases WHERE id=?').get(kase.id).status,'verified');
await run('os-detected',osOld);kase=db.prepare("SELECT * FROM managed_cases WHERE status='detected'").get();assert.ok(kase);await submit(kase);
before=bytes(kase.id);await run('other-profile-fixed',proxyFixed);assert.equal(bytes(kase.id),before);
await run('os-fixed',osFixed);assert.equal(db.prepare('SELECT status FROM managed_cases WHERE id=?').get(kase.id).status,'verified');
db.close();
console.log('Remote-access expanded advisory truth: '+JSON.stringify(truth));
console.log('Remote-access product isolation, embedded signatures, freshness and canonical lifecycle: PASS');
