import assert from 'node:assert/strict';
import { validateTlsAssessmentRequest, projectTlsCollectorReceipt, validateTlsAssessmentReceipt, validateTlsEngineResult } from '../workers/network-probe/src/tls-contract.js';
import { parseTlsDnsAnswers, buildTlsCheckPlan } from '../workers/scan-api/src/engines/tls-planner.js';
import { collectTlsAssessment } from '../workers/scan-api/src/engines/exposure-jobs.js';
import { buildScanQuality } from '../workers/scan-api/src/engines/scan-engine.js';
import { resolveAssessmentPresentation } from '../workers/scan-api/src/engines/assessment-presentation.js';
import { projectPhase5SnapshotForCustomer, resolvePhase5HistoricalCustomerProjection, resolvePhase5CustomerAggregate } from '../workers/scan-api/src/engines/phase5-evidence.js';
import { projectTlsScanQualityForCustomer, tlsSupportedCoverageGapReason } from '../workers/scan-api/src/engines/tls-quality.js';

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
const unknown={...request,checks:[{control:'heartbleed',protocol:'tls1_2',cipher_id:null}],scope:{...request.scope,special_consent:true,consent_version:'tls-special-2026-10-13'}};
assert.deepEqual(validateTlsAssessmentRequest(unknown,now),{ok:false,reason:'control_unavailable'});
assert.deepEqual(parseTlsDnsAnswers([
  ['A',{Status:0,Answer:[{type:5,name:'mail.acme.org.',data:'edge.provider.net.'},{type:1,name:'edge.provider.net.',data:'8.8.8.8'},
    {type:1,name:'evilmail.acme.org.',data:'1.1.1.1'},{type:1,name:'mail.acme.org.',data:'127.0.0.1'}]}],
  ['AAAA',{Status:0,Answer:[{type:28,name:'mail.acme.org.',data:'2606:4700:4700::1111'}]}],
],'mail.acme.org'),['8.8.8.8','2606:4700:4700::1111']);
const endpoint={endpoint:request.endpoint,endpoint_identity:'mail.acme.org|mail.acme.org|8.8.8.8|587|tcp|smtp',scope:request.scope};
const plan=buildTlsCheckPlan({endpoints:[endpoint],cipherCatalog:[{protocol:'tls1_2',name:'ECDHE-RSA-AES256-GCM-SHA384',executable:true},
  {protocol:'ssl2',name:'EXP-RC4-MD5',executable:false,reason:'engine_unsupported'}],maxChecks:100});
assert(plan.selected.some(row=>row.check.control==='cipher'&&row.check.protocol==='tls1_2'));
assert(plan.static_results.some(row=>row.check.control==='heartbleed'&&row.state==='unexecutable'
  &&row.reason==='engine_capability_limit'));
const consentedPlan=buildTlsCheckPlan({endpoints:[{...endpoint,scope:{...endpoint.scope,special_consent:true,
  consent_version:'tls-special-2026-10-13'}}],maxChecks:100});
assert(consentedPlan.static_results.some(row=>row.check.control==='heartbleed'&&row.state==='unexecutable'
  &&row.reason==='engine_capability_limit'));
assert(!consentedPlan.selected.some(row=>['heartbleed','robot','ccs'].includes(row.check.control)));
assert(plan.static_results.some(row=>row.check.control==='early_data'&&row.check.protocol==='tls1_2'&&row.state==='not_applicable'));
assert(plan.static_results.some(row=>row.check.control==='cipher'&&row.check.protocol==='ssl2'&&row.state==='unexecutable'));
const tlsPartial={source:'tls_assessment',quality:'partial',coverage:{omitted_checks:1176,uncertain:395,
  unexecutable:336,omitted_services:0,endpoint_gaps:0},endpoints:[{hostname:'acme.org',checks:[]}]};
const tlsStaticOnly={...tlsPartial,coverage:{...tlsPartial.coverage,omitted_checks:0,uncertain:0}};
assert.equal(tlsSupportedCoverageGapReason(tlsPartial),'tls_checks_outside_scan_budget');
assert.equal(tlsSupportedCoverageGapReason(tlsStaticOnly),null,'unavailable special controls alone do not degrade supported coverage');
assert.equal(buildScanQuality({tls_assessment:tlsPartial}).status,'partial');
assert.equal(buildScanQuality({tls_assessment:tlsStaticOnly}).status,'complete');
const oldQuality={status:'complete',warnings:[],modules_incomplete:[],modules_skipped:[]};
const correctedQuality=projectTlsScanQualityForCustomer(oldQuality,tlsPartial);
assert.equal(correctedQuality.status,'partial','stored complete quality is customer-projected as partial');
assert.equal(correctedQuality.modules_incomplete[0].incomplete_reason,'tls_checks_outside_scan_budget');
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
assert.equal(storedSnapshot.overall.score_band,'excellent','immutable snapshot facts are untouched');
const stop=new AbortController();
const hung=collectTlsAssessment({NETWORK_PROBE:{fetch:()=>new Promise(()=>{})}},request,{signal:stop.signal});
const abortTimer=setTimeout(()=>stop.abort(),5);
let guardTimer;
try {
  await assert.rejects(Promise.race([hung,new Promise((_,reject)=>{guardTimer=setTimeout(()=>reject(new Error('abort_not_bounded')),1000);})]),/collector_aborted/);
} finally {clearTimeout(abortTimer);clearTimeout(guardTimer);}
console.log('Deep TLS contract: endpoint scope, consent, physical proof and redaction passed');
