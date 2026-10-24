// Imported by the existing CI-blocking exposure-catalog validator.
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { remoteAccessFingerprint, assessRemoteAccess, REMOTE_ACCESS_SENTENCES, REMOTE_ACCESS_ADVISORIES } from '../../shared/exposure/remote-access.js';
import { exposureEvaluatorProgramSource, evaluateExposure } from '../../shared/exposure/evaluate.js';
import { exposureIdentity } from '../../shared/exposure/redaction.js';
import { planExposureChecks } from '../../shared/exposure/discovery.js';
import { externalExposureModule, evaluateExposureCondition } from '../../workers/scan-api/src/engines/exposure-findings.js';
import { unresolvedExposureChecks, readExposureForScan } from '../../workers/scan-api/src/engines/exposure-jobs.js';
import { refreshRemoteAccessCatalogue, readRemoteAccessCatalogue, REMOTE_ACCESS_CATALOGUE_KEY, REMOTE_ACCESS_FEED_URLS } from '../../workers/scan-api/src/engines/remote-access-catalogue.js';
import { evaluateWebsiteSecurityForScan } from '../../workers/scan-api/src/engines/website-security-lifecycle.js';
import { canTransitionCase } from '../../workers/scan-api/src/engines/managed-case-model.js';
import { buildDb, makeEnv } from './lib/worker-harness.js';

const url = 'https://vpn.example.test/global-protect/login.esp', rule_id = 'remote-access-portal';
const now = Date.parse('2026-10-24T02:00:00Z');
const cache = { fetched_at:new Date(now).toISOString(),catalogue_version:'2026.10.23',cves:['CVE-2024-3400'] };
const page = (label='') => `<html><head><title>GlobalProtect Portal</title></head><body><form action="/global-protect/login.esp" method="post"><input name="user"><input type="password" name="passwd"></form><footer>${label}</footer></body></html>`;
const stated = 'PAN-OS version: 11.1.2-h2';
const positive = remoteAccessFingerprint(page(stated),url);
assert.equal(remoteAccessFingerprint(page(stated).replace('<title>GlobalProtect Portal</title>','<title>Palo Alto Networks - GlobalProtect Portal</title>'),url)?.version,positive.version,'primary documented factory title is supported');
assert.deepEqual(positive,{product_id:'panos_globalprotect',version:'11.1.2-h2',version_state:'explicit'});
assert.equal(assessRemoteAccess(positive,cache,now).sentence,REMOTE_ACCESS_SENTENCES.listed);
assert.equal(assessRemoteAccess(remoteAccessFingerprint(page(),url),cache,now).sentence,REMOTE_ACCESS_SENTENCES.hidden);
for (const body of [page(stated).replace('GlobalProtect Portal','Welcome'), page(stated).replace('type="password"','type="text"'),page(stated).replace('action="/global-protect/login.esp"','action="https://foreign.example.test/global-protect/login.esp"'),`<article>${page(stated)}</article>`, '<h1>GlobalProtect PAN-OS version: 11.1.2-h2</h1>']) assert.equal(remoteAccessFingerprint(body,url),null);
assert.equal(remoteAccessFingerprint(page(stated),url.replace('https:','http:')),null);
assert.equal(remoteAccessFingerprint(page(stated),url+'?token=sensitive'),null);
assert.equal(remoteAccessFingerprint(page(stated),url.replace('login.esp','logout.esp')),null);
assert.equal(remoteAccessFingerprint(page('<script>const version="11.1.2-h2"</script>'),url).version_state,'absent');
assert.equal(remoteAccessFingerprint(page('Client version: 11.1.2-h2'),url).version_state,'absent');
assert.equal(assessRemoteAccess(remoteAccessFingerprint(page('PAN-OS version: unknown'),url),cache,now).state,'deferred');
for(const prose of ['Supported PAN-OS version: 11.1.2-h2','PAN-OS version: 11.1.2-h2 is required by the client'])
  assert.equal(assessRemoteAccess(remoteAccessFingerprint(page(prose),url),cache,now).state,'deferred','a version mentioned in compatibility prose is not the running server version');
assert.equal(assessRemoteAccess(remoteAccessFingerprint(page(stated+' PAN-OS version: 11.1.2-h3'),url),cache,now).state,'deferred');
for(const row of REMOTE_ACCESS_ADVISORIES){
  const portal={...positive,version:row.affectedFrom};
  assert.equal(assessRemoteAccess(portal,cache,now).state,'present');
  assert.equal(assessRemoteAccess({...portal,version:row.fixed},cache,now).state,'clear');
  assert.ok(row.advisory.startsWith('https://'));
}
for(const catalogue of [null,{...cache,fetched_at:new Date(now-7*86400000-1).toISOString()},{...cache,fetched_at:new Date(now+60001).toISOString()},{...cache,cves:[]}]) assert.equal(assessRemoteAccess(positive,catalogue,now).state,'deferred');
assert.equal(assessRemoteAccess({...positive,version:'11.1.203'},cache,now).state,'deferred','no guessed hotfix/marketplace interpretation');
assert.equal(assessRemoteAccess(positive,{...cache,fetched_at:new Date(now-7*86400000).toISOString()},now).state,'present');
const controls=[{status:404,body:'Missing'},{status:404,body:'Missing again'}];
const detection=evaluateExposure({rule:rule_id,response:{url,status:200,body:page(stated)},controls});
assert.equal(detection.state,'observed');assert.deepEqual(detection.portal,positive);
assert.equal(evaluateExposure({rule:rule_id,response:{url,status:200,body:page(),truncated:true},controls}).comparable,false);
assert.equal(evaluateExposure({rule:rule_id,response:{url,status:403,body:page(stated)},controls}).comparable,false);
const generated=vm.runInNewContext(exposureEvaluatorProgramSource()+';evaluateExposure',{URL,TextEncoder,TextDecoder,Uint8Array,DataView,Set,Map});
assert.equal(generated({rule:rule_id,response:{url,status:200,body:page(stated)},controls}).portal.version,positive.version,'the shipped collector program carries the fingerprint');
const portalChecks=planExposureChecks({origin:new URL(url).origin}).checks.filter(r=>r.ruleId===rule_id);
assert.equal(portalChecks.length,2);assert.ok(portalChecks.every(r=>r.url.startsWith('https://vpn.example.test/')));
function wire(portal=positive, target=url){
  return {rule_id,url:target,identity:exposureIdentity(rule_id,target),state:'observed',comparable:true,portal,
    finding:null,observation:{rule_id,severity:'info',indicators:['known_remote_access_login'],identity:exposureIdentity(rule_id,target),safe_url:target},observed_at:new Date(now).toISOString()};
}
const coverage={completed:1,pending:0,blocked:0,not_applicable:0,budget_exhausted:0,uncertain:0,pending_assets:0};
const moduleFor=(checks,catalogue=cache)=>externalExposureModule({source:'external_exposure',quality:'complete',checks,coverage,observed_at:new Date(now).toISOString()},{catalogue,now});
const finding=moduleFor([wire()]).findings[0];
const retained=unresolvedExposureChecks([], [wire()]);
assert.deepEqual(retained,[{rule_id,url}]);
assert.deepEqual(unresolvedExposureChecks(retained,[{...wire(),state:'uncertain',comparable:false}]),retained);
assert.equal(planExposureChecks({origin:new URL(url).origin,previousFindings:retained}).checks[0].url,url,'observed portals retain exact-path retest priority across an inconclusive scan');
assert.deepEqual(unresolvedExposureChecks(retained,[{...wire(),state:'not_found',comparable:true}]),retained,'a hidden browser page cannot discard a known portal retest');
const gone={...wire(),portal:undefined,state:'not_found',comparable:true,observation:null};
const stored={state:'complete',cursor:1,domain:'example.test',updated_at:new Date(now).toISOString(),costs_json:'{}',results_json:JSON.stringify([gone])};
async function readGone(prior){
  const row={...stored,plan_json:JSON.stringify({content_state:'complete',checks:[{rule_id,url}],retest_checks:prior,hosts_total:1,host_coverage:[{hostname:'vpn.example.test'}]})};
  return readExposureForScan({cybermeters_db:{prepare:()=>({bind:()=>({first:async()=>row})})}},{workspaceId:'ws',scanId:'hidden'});
}
const hiddenReceipt=await readGone(retained),hiddenModule=externalExposureModule(hiddenReceipt,{catalogue:cache,now});
assert.equal((await readGone([])).checks[0].state,'not_found','a never-observed portal path is an ordinary negative, not a blanket coverage gap');
assert.equal(hiddenReceipt.checks[0].comparable,false);
assert.equal(hiddenModule.quality,'partial');assert.equal(hiddenModule.incomplete_reason,'checks_inconclusive');
assert.equal(evaluateExposureCondition(finding.id,hiddenModule).state,'deferred','disabling a browser login does not prove the service was patched');
assert.ok(finding);assert.equal(finding.finding_type,'finding');assert.equal(finding.description,REMOTE_ACCESS_SENTENCES.listed);
assert.match(finding.exposure.retest_requirement,/server version in the curated fixed range/);
assert.match(finding.recommendation,/browser login page/);
assert.equal(moduleFor([wire({...positive,version:null,version_state:'absent'})]).findings[0].description,REMOTE_ACCESS_SENTENCES.hidden);
const fixed=moduleFor([wire({...positive,version:'11.1.2-h3'})]);
assert.equal(fixed.findings.length,0);assert.equal(evaluateExposureCondition(finding.id,fixed).state,'clear');
assert.equal(evaluateExposureCondition(finding.id,moduleFor([wire()],null)).state,'deferred','stale feed never verifies a listed condition');
assert.equal(moduleFor([wire()],null).quality,'partial','stale feed never becomes a healthy coverage claim');
assert.equal(moduleFor([wire()],null).incomplete_reason,'checks_inconclusive');
assert.equal(evaluateExposureCondition(finding.id,moduleFor([wire({...positive,version:'11.1.2-h3'},'https://vpn.example.test/')])).state,'deferred','a different path cannot verify');
assert.equal(evaluateExposureCondition(finding.id,moduleFor([{...wire(),state:'blocked',comparable:false}])).state,'deferred');
assert.equal(evaluateExposure({rule:rule_id,response:{url,status:404,body:'Missing'},controls:controls.map(c=>({...c,status:200,body:page()}))}).comparable,false,'a portal login wall on controls cannot verify absence');
assert.equal(remoteAccessFingerprint(page(stated+' Portal does not exist'),url),null);
// Separate product-truth calibration: positive, negative and deliberately
// unassessable shapes. These counts are not public-corpus or live-target claims.
const calibration={tp:0,fp:0,tn:0,fn:0,unknown:0};
const examples=[
  ...REMOTE_ACCESS_ADVISORIES.map(r=>({body:page(`PAN-OS version: ${r.affectedFrom}`),expected:'present'})),
  ...REMOTE_ACCESS_ADVISORIES.map(r=>({body:page(`PAN-OS version: ${r.fixed}`),expected:'clear'})),
  {body:page(),expected:'present'}, {body:page('Client version: 11.1.2-h2'),expected:'present'},
  {body:'<html><title>Welcome</title>Ordinary page</html>',expected:'none'},
  {body:`<article>${page(stated)}</article>`,expected:'none'},
  {body:page('PAN-OS version: unknown'),expected:'deferred'},
  {body:page('PAN-OS version: 11.1.203'),expected:'deferred'},
  {body:page('Server version: 11.1.2-h2'),expected:'deferred'},
  {body:page('Version: 11.1.2-h2'),expected:'deferred'},
  {body:page(stated),catalogue:null,expected:'deferred'},
];
for(const example of examples){
  const portal=remoteAccessFingerprint(example.body,url);
  const actual=portal?assessRemoteAccess(portal,'catalogue' in example?example.catalogue:cache,now).state:'none';
  if(actual==='deferred')calibration.unknown++;
  else if(actual==='present')calibration[example.expected==='present'?'tp':'fp']++;
  else calibration[example.expected==='present'?'fn':'tn']++;
  assert.equal(actual,example.expected,'curated product-truth calibration');
}
assert.equal(calibration.fp,0);assert.equal(calibration.fn,0);
console.log('Remote-access controlled product truth: '+JSON.stringify(calibration));
// Public feed: strict size/schema, official mirror fallback, no scan-time fetch.
let persisted=null,reads=0,calls=[];
assert.equal(REMOTE_ACCESS_CATALOGUE_KEY,'public-feeds/remote-access-kev-v1.json');
const storage={put:async(key,text)=>{assert.equal(key,REMOTE_ACCESS_CATALOGUE_KEY);persisted=text;},get:async key=>{assert.equal(key,REMOTE_ACCESS_CATALOGUE_KEY);reads++;return persisted?{size:persisted.length,body:new Response(persisted).body}:null;}};
const feed={catalogVersion:'2026.10.23',dateReleased:'2026-10-23T12:00:00Z',count:1,workspace_private:'synthetic-private-metadata',vulnerabilities:[{cveID:'CVE-2024-3400',customer_private:'synthetic-private-metadata'}]};
await refreshRemoteAccessCatalogue({cybermeters_reports:storage},{now,fetchImpl:async(u,opts)=>{calls.push(u);assert.equal(opts.method,'GET');assert.equal(opts.redirect,'error');return calls.length===1?new Response('denied',{status:403}):Response.json(feed);}});
assert.equal(calls.length,2);assert.equal((await readRemoteAccessCatalogue({cybermeters_reports:storage})).cves[0],feed.vulnerabilities[0].cveID);
assert.deepEqual(calls,[...REMOTE_ACCESS_FEED_URLS]);
assert.deepEqual(Object.keys(JSON.parse(persisted)).sort(),['schema','source','fetched_at','catalogue_version','released_at','cves'].sort());
assert.ok(!persisted.includes('synthetic-private-metadata'),'the shared public object cannot retain arbitrary feed metadata');
const saved=persisted;
await assert.rejects(()=>refreshRemoteAccessCatalogue({cybermeters_reports:storage},{now,fetchImpl:async()=>Response.json({...feed,count:2})}));
assert.equal(persisted,saved,'malformed refresh never replaces the last validated cache');
// Canonical case lifecycle: baseline -> observation -> submission -> exact retest.
const db=buildDb(),env=makeEnv(db);
db.exec("INSERT INTO users(id,email) VALUES('u','owner@example.test'); INSERT INTO workspaces(id,owner_user_id,name) VALUES('ws','u','Fixture'),('foreign','u','Foreign'); INSERT INTO domains(id,user_id,domain) VALUES('d','u','example.test'); INSERT INTO workspace_domains(workspace_id,domain_id,verification_status) VALUES('ws','d','verified');");
const base={ssl:{https_available:true,https_probe_executed:true},headers:{accessible:true,headers_assessed:true},dns:{resolves:true}};
const quality={status:'complete',modules_skipped:[],modules_incomplete:[]};
const run=async(id,mod)=>evaluateWebsiteSecurityForScan(env,{workspace_id:'ws',domain_id:'d',domain:'example.test',scan_id:id,findings:mod.findings,modules:{...base,external_exposure:mod},scanQuality:quality});
await run('baseline',fixed);await run('detected',moduleFor([wire()]));
let kase=db.prepare("SELECT * FROM managed_cases WHERE workspace_id='ws'").get();assert.ok(kase);
assert.equal(kase.asset_ref,url);
for(const target of ['triaged','assigned','approved','action_in_progress','awaiting_verification']){
  const result=canTransitionCase({case:kase,target_status:target,actor:{actor_type:'customer',actor_id:'u'},owner_ref:'u'});
  assert.equal(result.ok,true,result.reason);db.prepare('UPDATE managed_cases SET status=? WHERE id=?').run(result.case.status,kase.id);kase={...kase,status:result.case.status};
}
await run('unavailable',moduleFor([wire()],null));assert.equal(db.prepare('SELECT status FROM managed_cases WHERE id=?').get(kase.id).status,'awaiting_verification');
await run('login-hidden',hiddenModule);assert.equal(db.prepare('SELECT status FROM managed_cases WHERE id=?').get(kase.id).status,'awaiting_verification');
await run('fixed',fixed);assert.equal(db.prepare('SELECT status FROM managed_cases WHERE id=?').get(kase.id).status,'verified');
assert.equal(db.prepare("SELECT COUNT(*) n FROM managed_cases WHERE workspace_id='foreign'").get().n,0);
db.close();
console.log('Remote-access portal fingerprint/advisory/freshness/exact-retest/lifecycle contracts: PASS (local only)');
