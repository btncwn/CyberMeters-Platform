import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, rmSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { validateTlsAssessmentRequest, projectTlsCollectorReceipt, validateTlsAssessmentReceipt, validateTlsEngineResult } from '../workers/network-probe/src/tls-contract.js';
import { parseTlsDnsAnswers, buildTlsCheckPlan, buildBudgetedTlsCheckPlan } from '../workers/scan-api/src/engines/tls-planner.js';
import { TLS_SPECIAL_CONTROLS_AVAILABLE } from '../shared/tls/catalog.js';
import { collectTlsAssessment } from '../workers/scan-api/src/engines/exposure-jobs.js';
import { buildScanQuality } from '../workers/scan-api/src/engines/scan-engine.js';
import { resolveAssessmentPresentation } from '../workers/scan-api/src/engines/assessment-presentation.js';
import { projectPhase5SnapshotForCustomer, resolvePhase5HistoricalCustomerProjection, resolvePhase5CustomerAggregate } from '../workers/scan-api/src/engines/phase5-evidence.js';
import { blockingTlsUnexecutable, classifyTlsRefusals, projectTlsScanQualityForCustomer, tlsSupportedCoverageGapReason } from '../workers/scan-api/src/engines/tls-quality.js';

const now = Date.now();
const iso = offset => new Date(now + offset).toISOString();
const request = {
  schema_version:'tls-assessment-request-v1',request_id:'r1',workspace_id:'w1',scan_id:'s1',domain_id:'d1',domain:'acme.org',
  endpoint:{hostname:'mail.acme.org',sni:'mail.acme.org',address:'8.8.8.8',port:587,transport:'tcp',application_protocol:'smtp',
    dns_addresses:['8.8.8.8'],dns_observed_at:iso(-1000)},
  scope:{kind:'authorized_service',service_authorization_id:'svc1',generation:2,special_consent:false,consent_version:null},
  checks:[{control:'protocol',protocol:'tls1_2',cipher_id:null}],deadline_at:iso(15000),max_connections:4,max_bytes:20000,
};
assert.equal(validateTlsAssessmentRequest(request,now).ok,true);
for(const [name,mutation] of [
  ['cross-domain',x=>{x.endpoint.hostname='other.org';x.endpoint.sni='other.org';}],
  ['wrong-port',x=>{x.endpoint.port=445;}],
  ['private-address',x=>{x.endpoint.address='127.0.0.1';x.endpoint.dns_addresses=['127.0.0.1'];}],
  ['dns-mismatch',x=>{x.endpoint.address='1.1.1.1';}],
  ['sni-mismatch',x=>{x.endpoint.sni='other.org';}],
  ['standard-https-scope',x=>{x.scope.kind='standard_https';x.scope.service_authorization_id=null;}],
  ['unexpected-field',x=>{x.endpoint.command='curl';}],
  ['active-without-consent',x=>{x.checks=[{control:'heartbleed',protocol:'tls1_2',cipher_id:null}];}],
]) {
  const x=structuredClone(request);mutation(x);
  assert.equal(validateTlsAssessmentRequest(x,now).ok,false,name);
}
const engine = {
  schema:'tls-engine-result-v1',engine:{family:'modern',version:'3.5.9',build_id:'a'.repeat(64),sandboxed:true},
  control:'handshake',protocol:'tls1_2',state:'accepted',reason:'handshake_completed',authenticated_finished:true,vulnerability:null,
  negotiated:{version:'tls1_2',cipher:'ECDHE-RSA-AES256-GCM-SHA384',cipher_bits:256,group:'X25519',group_bits:255,pfs:true,alpn:null,sni_sent:true},
  certificates:null,ocsp:null,extensions:null,telemetry:{connections:1,bytes_sent:120,bytes_received:300,duration_ms:20},
  limitations:[],catalog:null,
};
assert.equal(validateTlsEngineResult(engine,request.checks[0]).ok,true);
const injected=structuredClone(engine);injected.raw_certificate=['-----BEGIN','PRIVATE KEY-----'].join(' ');
assert.equal(validateTlsEngineResult(injected,request.checks[0]).ok,false,'raw secret rejected');
const noSandbox=structuredClone(engine);noSandbox.engine.sandboxed=false;
assert.equal(validateTlsEngineResult(noSandbox,request.checks[0]).ok,false,'unsandboxed production result rejected');
assert.equal(validateTlsEngineResult(noSandbox,request.checks[0],{requireSandbox:false}).ok,true,'local fixture can test native binary');
const falseAccepted=structuredClone(engine);falseAccepted.authenticated_finished=false;
assert.equal(validateTlsEngineResult(falseAccepted,request.checks[0]).ok,false,'no Finished is not accepted');
const heartbleedCheck={control:'heartbleed',protocol:'tls1_2',cipher_id:null};
const heartbleed={...structuredClone(engine),engine:{...engine.engine,family:'active_legacy',version:'1.0.2u'},
  control:'heartbleed',reason:'active_confirmed',vulnerability:{status:'confirmed',profile:'heartbleed-minimal-v1',completed_vectors:3,planned_vectors:3}};
assert.equal(validateTlsEngineResult(heartbleed,heartbleedCheck).ok,true,'bounded positive evidence accepted');
for(const [control,profile,vectors,connections] of [
  ['ccs','ccs-early-record-v1',4,5],['robot','robot-finite-v1',10,11],['robot','robot-finite-v1',20,21],
]){
  const row=structuredClone(heartbleed),check={control,protocol:'tls1_2',cipher_id:null};
  row.control=control;row.vulnerability={status:'confirmed',profile,completed_vectors:vectors,planned_vectors:vectors};
  row.telemetry.connections=connections;
  assert.equal(validateTlsEngineResult(row,check).ok,true,`${control} complete profile`);
  row.vulnerability.completed_vectors--;
  assert.equal(validateTlsEngineResult(row,check).ok,false,`${control} partial profile cannot confirm`);
}
const interrupted={...structuredClone(heartbleed),state:'uncertain',reason:'aborted',authenticated_finished:false,
  negotiated:null,vulnerability:{...heartbleed.vulnerability,status:'unknown',completed_vectors:0},
  telemetry:{connections:1,bytes_sent:0,bytes_received:0,duration_ms:2}};
assert.equal(validateTlsEngineResult(interrupted,heartbleedCheck).ok,true,'aborted special check stays unknown');
for(const mutation of [
  row=>{row.authenticated_finished=false;row.negotiated=null;},
  row=>{row.vulnerability.profile='ccs-finished-v1';},
  row=>{row.vulnerability.completed_vectors=2;},
  row=>{row.vulnerability.status='not_observed';},
]) {
  const row=structuredClone(heartbleed);mutation(row);
  assert.equal(validateTlsEngineResult(row,heartbleedCheck).ok,false,'unproved special verdict rejected');
}
const raw={schema_version:'tls-collector-raw-v1',request_id:'r1',started_at:iso(0),finished_at:iso(100),
  results:[{check:request.checks[0],engine_result:engine,reason:null,observed_at:iso(99),
    physical_telemetry:{connections:1,bytes_sent:150,bytes_received:350,duration_ms:30}}],
  telemetry:{connections:1,bytes_sent:150,bytes_received:350,duration_ms:100}};
const receipt=projectTlsCollectorReceipt(request,raw,{now:now+100});
assert.equal(receipt.quality,'complete');
assert.equal(validateTlsAssessmentReceipt(request,receipt,{now:now+100}).ok,true);
const fakeNetwork=structuredClone(raw);fakeNetwork.results[0].physical_telemetry.connections=0;fakeNetwork.telemetry.connections=0;
assert.throws(()=>projectTlsCollectorReceipt(request,fakeNetwork,{now:now+100}),/engine_cost_conflict|unproved_network_verdict/);
const secret=structuredClone(receipt);secret.results[0].evidence.raw_server_text='password';
assert.equal(validateTlsAssessmentReceipt(request,secret,{now:now+100}).ok,false,'receipt must reject extra server text');
const authorizedSpecial={...request,checks:[{control:'heartbleed',protocol:'tls1_2',cipher_id:null}],max_connections:1,
  scope:{...request.scope,special_consent:true,consent_version:'tls-special-2026-10-13'}};
// Containment (21 Oct 2026): special controls are unavailable until the
// per-domain, owned-address consent gate exists. Even a consented request is
// refused by the probe contract.
assert.equal(TLS_SPECIAL_CONTROLS_AVAILABLE,false,'intrusive TLS controls stay contained');
assert.equal(validateTlsAssessmentRequest(authorizedSpecial,now).reason,'control_unavailable');
assert.deepEqual(parseTlsDnsAnswers([
  ['A',{Status:0,Answer:[{type:5,name:'mail.acme.org.',data:'edge.provider.net.'},{type:1,name:'edge.provider.net.',data:'8.8.8.8'},
    {type:1,name:'evilmail.acme.org.',data:'1.1.1.1'},{type:1,name:'mail.acme.org.',data:'127.0.0.1'}]}],
  ['AAAA',{Status:0,Answer:[{type:28,name:'mail.acme.org.',data:'2606:4700:4700::1111'}]}],
],'mail.acme.org'),['8.8.8.8','2606:4700:4700::1111']);
const endpoint={endpoint:request.endpoint,endpoint_identity:'mail.acme.org|mail.acme.org|8.8.8.8|587|tcp|smtp',scope:request.scope};
const plan=buildTlsCheckPlan({endpoints:[endpoint],cipherCatalog:[{protocol:'tls1_2',name:'ECDHE-RSA-AES256-GCM-SHA384',executable:true},
  {protocol:'ssl2',name:'EXP-RC4-MD5',executable:false,reason:'engine_unsupported'}],maxChecks:100});
const thirteen=Array.from({length:13},(_,index)=>({endpoint:{hostname:`host${index}.example.org`,port:443,application_protocol:'https',address:`8.8.8.${index+1}`},
  endpoint_identity:`host${index}.example.org|host${index}.example.org|8.8.8.${index+1}|443|tcp|https`,scope:{special_consent:false}}));
const budgetedEndpoints=[...thirteen,...thirteen.map((entry,index)=>({...entry,
  endpoint:{...entry.endpoint,address:`1.1.1.${index+1}`},endpoint_identity:entry.endpoint_identity.replace('8.8.8.','1.1.1.')}))];
const budgeted=buildBudgetedTlsCheckPlan({endpoints:budgetedEndpoints,
  cipherCatalog:[{protocol:'tls1_2',name:'AES128-GCM-SHA256',executable:true},
    {protocol:'tls1_2',name:'AES128-SHA',executable:true}],
  observedHttpsHosts:thirteen.map(entry=>entry.endpoint.hostname),scanId:'scan-budgeted',maxChecks:512});
assert(budgeted.selected.length>0&&budgeted.selected.length<=512,'13 observed HTTPS assets fit the TLS cap');
assert.equal(budgeted.omitted_checks,0,'no pending control is silently left beyond the cap');
assert.equal(budgeted.deferred_endpoints.length,13,'other DNS addresses are explicitly deferred');
assert.equal(budgeted.deferred_hosts.length,0,'all 13 observed HTTPS hosts fit the plan');
assert.equal(new Set(budgeted.selected.map(row=>`${budgetedEndpoints[row.endpoint_index].endpoint.hostname}|${row.check.protocol}|${row.check.control}|${row.check.cipher_id||''}`)).size,budgeted.selected.length);
const plannerPath=fileURLToPath(new URL('../workers/scan-api/src/engines/tls-planner.js',import.meta.url));
const mutantPath=plannerPath.replace(/\.js$/,`.p1b-mutant-${process.pid}.js`);
const plannerSource=readFileSync(plannerPath,'utf8');
const mutatedSource=plannerSource.replace('const key=`${host}|${port}`;', 'const key=`${host}|${port}|${entry.endpoint.address}`;');
assert.notEqual(mutatedSource,plannerSource,'TLS dedupe mutation must apply');
try{
  writeFileSync(mutantPath,mutatedSource);
  const mutant=await import(pathToFileURL(mutantPath).href);
  const wrong=mutant.buildBudgetedTlsCheckPlan({endpoints:budgetedEndpoints,cipherCatalog:[
    {protocol:'tls1_2',name:'AES128-GCM-SHA256',executable:true},{protocol:'tls1_2',name:'AES128-SHA',executable:true}],
    observedHttpsHosts:thirteen.map(entry=>entry.endpoint.hostname),scanId:'scan-budgeted',maxChecks:512});
  assert.notEqual(wrong.deferred_endpoints.length,13,'removing host/port dedupe must fail the exact deferral proof');
  assert(wrong.deferred_hosts.some(row=>row.reason==='tls_plan_budget'),'mutation exhausts the bounded plan');
}finally{rmSync(mutantPath,{force:true});}
const tiny=buildBudgetedTlsCheckPlan({endpoints:thirteen,cipherCatalog:[],observedHttpsHosts:thirteen.map(entry=>entry.endpoint.hostname),maxChecks:20});
assert(tiny.deferred_hosts.some(row=>row.reason==='tls_plan_budget'),'over-cap hosts are deferred with a reason');
assert(plan.selected.some(row=>row.check.control==='cipher'&&row.check.protocol==='tls1_2'));
// Contained: availability is checked before consent, so an unconsented endpoint
// also records the special controls as unexecutable (never run, never passed).
assert(plan.static_results.some(row=>row.check.control==='heartbleed'&&row.state==='unexecutable'));
const consentedPlan=buildTlsCheckPlan({endpoints:[{...endpoint,scope:{...endpoint.scope,special_consent:true,
  consent_version:'tls-special-2026-10-13'}}],maxChecks:512});
// Contained: even with workspace consent, no special control is selected; each
// is recorded unexecutable, never as a passed check.
assert.equal(consentedPlan.selected.filter(row=>['heartbleed','robot','ccs'].includes(row.check.control)).length,0);
assert(consentedPlan.static_results.filter(row=>['heartbleed','robot','ccs'].includes(row.check.control)).every(row=>['unexecutable','not_applicable'].includes(row.state)));
assert(consentedPlan.static_results.some(row=>row.check.control==='heartbleed'));
assert(plan.static_results.some(row=>row.check.control==='early_data'&&row.check.protocol==='tls1_2'&&row.state==='not_applicable'));
assert(plan.static_results.some(row=>row.check.control==='cipher'&&row.check.protocol==='ssl2'&&row.state==='unexecutable'));
const tlsPartial={source:'tls_assessment',quality:'partial',coverage:{omitted_checks:1176,uncertain:395,
  unexecutable:336,omitted_services:0,endpoint_gaps:0},endpoints:[{hostname:'acme.org',checks:[{control:'certificate',protocol:'tls1_3',state:'accepted'}]}]};
const tlsStaticOnly={...tlsPartial,coverage:{...tlsPartial.coverage,omitted_checks:0,uncertain:0}};
assert.equal(tlsSupportedCoverageGapReason(tlsPartial),'tls_checks_outside_scan_budget');
assert.equal(tlsSupportedCoverageGapReason(tlsStaticOnly),null,'unavailable special controls alone do not degrade supported coverage');
assert.equal(buildScanQuality({tls_assessment:tlsPartial}).status,'partial');
assert.equal(buildScanQuality({tls_assessment:tlsStaticOnly}).status,'complete');
const oldQuality={status:'complete',warnings:[],modules_incomplete:[],modules_skipped:[]};
const correctedQuality=projectTlsScanQualityForCustomer(oldQuality,tlsPartial);
assert.equal(correctedQuality.status,'partial','stored complete quality is customer-projected as partial');
assert.equal(correctedQuality.modules_incomplete[0].incomplete_reason,'tls_checks_outside_scan_budget');
assert.deepEqual(correctedQuality.modules_skipped,[], 'an attempted TLS assessment is incomplete, not skipped');
assert.equal(oldQuality.status,'complete','stored quality remains immutable');
assert.equal(projectTlsScanQualityForCustomer({...oldQuality,status:'degraded'},tlsPartial).status,'degraded',
  'TLS gaps do not upgrade an already degraded scan');
const completeModules={
  technology_detection:{technologies:['nginx'],technology_fingerprints:[{technology:'nginx',source:'server',confidence:90}],
    serviceability_contract:{serviceable:true,conclusion_class:'conclusive',reason:'origin_response_serviceable'}},
  cve_intelligence:{technologies_checked:['nginx'],lookup_statuses:{nginx:{status:'complete'}},results:{},total_cves:0,
    critical_count:0,high_count:0,cve_coverage:'complete',source:'nvd_api'},
  known_exploited_vulnerabilities:{matches:[]},email_security_intelligence:{email_security_score:100},
};
const historical=resolvePhase5HistoricalCustomerProjection({score:100,riskLevel:'excellent',
  assessment:resolveAssessmentPresentation({score:100,scanQuality:'complete',status:'completed'}),
  scanQuality:'complete',modules:{...completeModules,tls_assessment:tlsPartial}});
assert.equal(historical.score,100,'persisted score remains numeric for the measured scoring scope');
assert.equal(historical.risk_level,null,'stored final band is withheld');
assert.equal(historical.scan_quality,'partial');
assert.equal(historical.assessment.provisional,true);
assert.equal(historical.assessment.display_rating,null);
const alreadyDegraded=resolvePhase5HistoricalCustomerProjection({score:80,riskLevel:'good',
  scanQuality:'degraded',modules:{...completeModules,tls_assessment:tlsPartial}});
assert.equal(alreadyDegraded.scan_quality,'degraded','historical projection preserves worse evidence quality');
const portfolioAggregate=resolvePhase5CustomerAggregate([
  {status:'completed',score:100,scan_quality:historical.scan_quality,assessment:historical.assessment,
    phase5_evidence:{complete:true},phase5_evidence_read:{state:'verified'}},
  {status:'completed',score:80,scan_quality:'complete',
    assessment:resolveAssessmentPresentation({score:80,scanQuality:'complete',status:'completed'}),
    phase5_evidence:{complete:true},phase5_evidence_read:{state:'verified'}},
]);
assert.deepEqual(portfolioAggregate.scores,[80],'provisional TLS score is excluded from complete-scan averages');
assert.equal(portfolioAggregate.evidence_coverage.assessed_row_count,1);
assert.equal(portfolioAggregate.evidence_coverage.incomplete_row_count,1);
const storedSnapshot={domains:[{domain_key:'certificates_trust',trend:{scan_quality:'complete',comparable_basis:true}}],
  overall:{cyber_metrics_score:100,score_band:'excellent',summary:'Excellent',
    assessment:resolveAssessmentPresentation({score:100,scanQuality:'complete',status:'completed'}),
    business_risk_indicator:{band:'low',provisional:false,internal_metrics:{score:95}},
    evidence_completeness:{scan_quality:'complete',assessment_quality:'complete'},not_fully_assessed:[]}};
const customerSnapshot=projectPhase5SnapshotForCustomer(storedSnapshot,{...completeModules,tls_assessment:tlsPartial});
assert.equal(customerSnapshot.overall.cyber_metrics_score,100);
assert.equal(customerSnapshot.overall.score_band,null);
assert.equal(customerSnapshot.overall.assessment.provisional,true);
assert.equal(customerSnapshot.overall.business_risk_indicator.band,null);
assert.equal(customerSnapshot.domains[0].trend.comparable_basis,false);
assert.equal(customerSnapshot.overall.not_fully_assessed.find(row=>row.domain_key==='tls_assessment')?.reason,
  'tls_checks_outside_scan_budget');
assert.equal(storedSnapshot.overall.score_band,'excellent','immutable snapshot facts are untouched');
const stop=new AbortController();
const hung=collectTlsAssessment({NETWORK_PROBE:{fetch:()=>new Promise(()=>{})}},request,{signal:stop.signal});
const abortTimer=setTimeout(()=>stop.abort(),5);
let guardTimer;
try {
  await assert.rejects(Promise.race([hung,new Promise((_,reject)=>{guardTimer=setTimeout(()=>reject(new Error('abort_not_bounded')),1000);})]),/collector_aborted/);
} finally {clearTimeout(abortTimer);clearTimeout(guardTimer);}
// ── Refusal without a version alert (decision 20 Oct 2026) ──────────────────
// A legacy-protocol, cipher or renegotiation probe that ends in transport_eof,
// handshake_failed or a non-version alert is "not accepted" only when the same
// endpoint completed a handshake in the same run; the basis stays visible.
const refusalCases = classify => {
  const row = (endpoint_index, control, protocol, state, reason) => ({ endpoint_index, control, protocol, cipher_id: control === 'cipher' ? 'TLS_RSA_WITH_RC4_128_SHA' : null, state, reason });
  const reachable = classify([
    row(0, 'certificate', 'tls1_3', 'accepted', 'handshake_completed'),
    row(0, 'protocol', 'ssl2', 'uncertain', 'transport_eof'),
    row(0, 'protocol', 'tls1_1', 'uncertain', 'handshake_failed'),
    row(0, 'cipher', 'tls1_2', 'uncertain', 'peer_alert'),
    row(0, 'secure_renegotiation', 'tls1_2', 'uncertain', 'handshake_failed'),
    row(0, 'protocol', 'tls1', 'rejected', 'protocol_version_rejected'),
  ]);
  const unreachable = classify([
    row(1, 'protocol', 'ssl2', 'uncertain', 'transport_eof'),
    row(1, 'cipher', 'tls1_2', 'uncertain', 'peer_alert'),
  ]);
  const excluded = classify([
    row(2, 'certificate', 'tls1_2', 'accepted', 'handshake_completed'),
    row(2, 'protocol', 'ssl3', 'uncertain', 'transport_timeout'),
    row(2, 'cipher', 'tls1_2', 'uncertain', 'budget_exhausted'),
    row(2, 'protocol', 'tls1_1', 'uncertain', 'aborted'),
    row(2, 'cipher', 'tls1_2', 'uncertain', 'pending'),
    row(2, 'robot', 'tls1_2', 'uncertain', 'handshake_failed'),
    row(2, 'protocol', 'tls1_3', 'uncertain', 'handshake_failed'),
  ]);
  return {
    reachableRefused: reachable.slice(1, 5).every(c => c.state === 'rejected' && c.engine_state === 'uncertain' && c.rejection_basis === 'refused_without_version_alert')
      && reachable[1].reason === 'transport_eof' && reachable[5].rejection_basis === 'engine_alert' && reachable[5].reason === 'protocol_version_rejected',
    unreachableStaysInconclusive: unreachable.every(c => c.state === 'uncertain' && !c.rejection_basis),
    timeoutStaysInconclusive: excluded[1].state === 'uncertain' && !excluded[1].rejection_basis,
    otherExclusionsStayInconclusive: excluded.slice(2).every(c => c.state === 'uncertain' && !c.rejection_basis),
  };
};
{
  const result = refusalCases(classifyTlsRefusals);
  for (const [name, ok] of Object.entries(result)) assert.equal(ok, true, `TLS refusal: ${name}`);
  // The stored Cloudflare-edge run: every inconclusive check is a refusal on the
  // reachable endpoint, so supported coverage has no gap and nothing else moves.
  const fixture = JSON.parse(readFileSync(new URL('./fixtures/tls-refusal-cloudflare-edge-2026-10-18.json', import.meta.url), 'utf8'));
  const classified = classifyTlsRefusals(fixture.checks);
  assert.equal(fixture.checks.filter(c => c.state === 'uncertain').length, 7);
  assert.equal(classified.filter(c => c.state === 'uncertain').length, 0);
  assert.equal(classified.filter(c => c.rejection_basis === 'refused_without_version_alert').length, 7);
  assert.deepEqual(classified.filter(c => c.state === 'accepted'), fixture.checks.filter(c => c.state === 'accepted'), 'accepted checks unchanged');
  const coverage = { completed: classified.filter(c => ['accepted', 'rejected'].includes(c.state)).length, uncertain: 0, omitted_checks: 0, omitted_services: 0, endpoint_gaps: 0 };
  assert.equal(tlsSupportedCoverageGapReason({ source: 'tls_assessment', coverage, endpoints: [{ checks: classified }], quality: 'complete' }), null);
  // Mutants: the reachability condition and the timeout exclusion are load-bearing.
  const source = readFileSync(new URL('../workers/scan-api/src/engines/tls-quality.js', import.meta.url), 'utf8');
  for (const [name, from, to, expectFalse] of [
    ['reachability condition removed', "row?.state === 'uncertain' && reachable.has(row.endpoint_index)", "row?.state === 'uncertain'", 'unreachableStaysInconclusive'],
    ['timeout counted as a refusal', "['transport_eof', 'handshake_failed', 'peer_alert']", "['transport_eof', 'handshake_failed', 'peer_alert', 'transport_timeout']", 'timeoutStaysInconclusive'],
  ]) {
    assert.equal(source.split(from).length, 2, `TLS refusal mutant anchor: ${name}`);
    const mutantUrl = new URL(`../workers/scan-api/src/engines/.tls-quality.refusal-mutant.${process.pid}.${expectFalse}.js`, import.meta.url);
    writeFileSync(mutantUrl, source.replace(from, to));
    try {
      const mutant = await import(mutantUrl.href);
      assert.equal(refusalCases(mutant.classifyTlsRefusals)[expectFalse], false, `TLS refusal mutant survived: ${name}`);
    } finally { rmSync(mutantUrl, { force: true }); }
  }
}
// Capability-limited unexecutable controls do not keep the TLS module partial;
// checks CyberMeters did not run on its own side still do.
{
  const unexecutableCases = count => count([
    { state: 'unexecutable', reason: 'heartbeat_unavailable' }, { state: 'unexecutable', reason: 'cipher_unavailable' },
    { state: 'accepted', reason: 'handshake_completed' },
  ]) === 0 && count([{ state: 'unexecutable', reason: 'feature_disabled' }, { state: 'unexecutable', reason: 'heartbeat_unavailable' }]) === 1;
  assert.equal(unexecutableCases(blockingTlsUnexecutable), true, 'TLS unexecutable: capability limits only');
  const source = readFileSync(new URL('../workers/scan-api/src/engines/tls-quality.js', import.meta.url), 'utf8');
  const from = "&& !TLS_CAPABILITY_UNEXECUTABLE_REASONS.includes(row.reason)";
  assert.equal(source.split(from).length, 2, 'TLS unexecutable mutant anchor');
  const mutantUrl = new URL(`../workers/scan-api/src/engines/.tls-quality.unexecutable-mutant.${process.pid}.js`, import.meta.url);
  writeFileSync(mutantUrl, source.replace(from, ''));
  try {
    assert.equal(unexecutableCases((await import(mutantUrl.href)).blockingTlsUnexecutable), false, 'TLS unexecutable mutant survived: reason filter removed');
  } finally { rmSync(mutantUrl, { force: true }); }
}
console.log('Deep TLS contract: endpoint scope, consent, physical proof and redaction passed');
await import('./p1b-single-domain-engine-fixture.js');
await import('./mail-transport-fixture.js');
