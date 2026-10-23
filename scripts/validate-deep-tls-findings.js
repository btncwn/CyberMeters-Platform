import assert from 'node:assert/strict';
import { tlsAssessmentFindings, evaluateTlsCondition } from '../workers/scan-api/src/engines/tls-findings.js';
import { resolveRemediation } from '../workers/scan-api/src/engines/remediation-registry.js';
import { buildTlsCheckPlan } from '../workers/scan-api/src/engines/tls-planner.js';
import { resolveSecurityCheckDomainStates } from '../workers/scan-api/src/engines/security-check-domains.js';

const identity='mail.example.org|mail.example.org|8.8.8.8|587|tcp|smtp';
const engine={family:'legacy',version:'1.0.2u',build_id:'a'.repeat(64),sandboxed:true};
const good={connections:1,bytes_sent:120,bytes_received:300,duration_ms:10};
const observed='2026-10-13T12:00:00.000Z';
const protocol=(version,state='accepted')=>({control:'protocol',protocol:version,cipher_id:null,state,reason:state==='accepted'?'handshake_completed':state==='rejected'?'protocol_version_rejected':'peer_alert',
  observed_at:observed,engine,evidence:{authenticated_finished:state==='accepted',negotiated:state==='accepted'?{version,cipher:'AES256-SHA'}:null,
    certificates:null,ocsp:null,extensions:null,vulnerability:null,limitations:[]},physical_telemetry:good});
const endpoint=(checks,address='8.8.8.8')=>({endpoint_identity:identity.replace('8.8.8.8',address),hostname:'mail.example.org',sni:'mail.example.org',
  address,port:587,application_protocol:'smtp',checks});
const module=checks=>({source:'tls_assessment',quality:'complete',endpoints:[endpoint(checks)]});
const baseline=module([protocol('tls1'),protocol('tls1_3')]);
const [finding]=tlsAssessmentFindings(baseline);
assert(finding?.id.startsWith('tls_legacy_protocol__'));
const domainState = report => resolveSecurityCheckDomainStates(report).find(row=>row.domain_key==='certificates_trust');
const report = (assessment,findings=[]) => ({scan_quality:{status:'complete',modules_skipped:[]},
  modules:{certificate_intelligence:{},tls_assessment:assessment},findings});
assert.equal(domainState(report({...baseline,coverage:{completed:2}},[finding])).state,'issue_detected');
assert.deepEqual(domainState(report({...baseline,coverage:{completed:2}},[finding])).finding_ids,[finding.id]);
assert.notEqual(domainState(report({...baseline,quality:'partial',coverage:{completed:1,unexecutable:1}})).state,'assessed_healthy');
assert.equal(domainState(report({...baseline,quality:'partial',coverage:{completed:1,unexecutable:1}},[finding])).coverage,'partial');
assert.equal(resolveRemediation({finding_type:finding.id}).status,'resolved');
assert.equal(evaluateTlsCondition(finding.id,module([protocol('tls1','rejected'),protocol('tls1_3')])).state,'clear');
assert.notEqual(evaluateTlsCondition(finding.id,module([protocol('tls1','uncertain'),protocol('tls1_3')])).state,'clear');
assert.equal(evaluateTlsCondition(finding.id,module([{...protocol('tls1','rejected'),reason:'peer_alert'},protocol('tls1_3')])).state,'deferred');
assert.notEqual(evaluateTlsCondition(finding.id,{source:'tls_assessment',endpoints:[endpoint([protocol('tls1','rejected'),protocol('tls1_3')],'1.1.1.1')]}).state,'clear');
assert.notEqual(evaluateTlsCondition(finding.id,module([{...protocol('tls1','rejected'),engine:{...engine,build_id:'b'.repeat(64)}},protocol('tls1_3')])).state,'clear');
const cipher={...protocol('tls1_2'),control:'cipher',cipher_id:'RC4-MD5',evidence:{...protocol('tls1_2').evidence,negotiated:{version:'tls1_2',cipher:'RC4-MD5'}}};
const cipherFinding=tlsAssessmentFindings(module([protocol('tls1_2'),cipher])).find(row=>row.id.startsWith('tls_weak_cipher__'));
assert(cipherFinding);
// A weak cipher clears only on an exact negative (23 Oct 2026): the server answered
// the cipher-only offer with a TLS alert while the same endpoint still serves tls1_2.
assert.equal(evaluateTlsCondition(cipherFinding.id,module([protocol('tls1_2'),{...cipher,state:'uncertain',reason:'peer_alert'}])).state,'clear','weak cipher refused by alert on a served protocol clears');
assert.equal(evaluateTlsCondition(cipherFinding.id,module([protocol('tls1_2'),cipher])).state,'present','weak cipher still negotiated is present');
assert.equal(evaluateTlsCondition(cipherFinding.id,module([protocol('tls1_2'),{...cipher,state:'uncertain',reason:'transport_timeout'}])).state,'deferred','a timeout is not a refusal');
assert.equal(evaluateTlsCondition(cipherFinding.id,module([protocol('tls1_3'),protocol('tls1_2','uncertain'),{...cipher,state:'uncertain',reason:'peer_alert'}])).state,'deferred','an alert while tls1_2 itself is not served proves nothing about the cipher');
assert.equal(evaluateTlsCondition(cipherFinding.id,module([protocol('tls1_2'),{...cipher,state:'uncertain',reason:'peer_alert',physical_telemetry:{...good,bytes_received:0}}])).state,'deferred','no reply bytes is not a server alert');
// Case keys: a profile bump keeps the case; a weak cipher key names its cipher.
{
  const { tlsCaseKey } = await import('../workers/scan-api/src/engines/tls-findings.js');
  const base={type:'tls_robot_confirmed',endpoint_identity:identity,control:'robot',protocol:'tls1_2',cipher_id:null};
  assert.equal(tlsCaseKey({...base,detail:'robot-finite-v1'}),tlsCaseKey({...base,detail:'robot-finite-v2'}),'a _confirmed profile bump (v1 → v2) keeps the same case');
  const wc={type:'tls_weak_cipher',endpoint_identity:identity,control:'cipher',protocol:'tls1_2'};
  assert.notEqual(tlsCaseKey({...wc,cipher_id:'RC4-MD5',detail:'RC4-MD5'}),tlsCaseKey({...wc,cipher_id:'DES-CBC3-SHA',detail:'DES-CBC3-SHA'}),'a weak-cipher case key includes its cipher id');
}
const leaf={key_type:'RSA',key_bits:1024,signature_algorithm:'rsa_sha1',sha256:'b'.repeat(64)};
const certRow=certificate=>({...protocol('tls1_2'),control:'certificate',evidence:{...protocol('tls1_2').evidence,
  certificates:{offered_chain:[certificate],trust:'valid',hostname:true}}});
const certFindings=tlsAssessmentFindings(module([protocol('tls1_2'),certRow(leaf)]));
const weakKeyFinding=certFindings.find(row=>row.id.startsWith('tls_weak_certificate_key__'));
const weakSignatureFinding=certFindings.find(row=>row.id.startsWith('tls_weak_certificate_signature__'));
assert(weakKeyFinding&&weakSignatureFinding);
const unknown=module([protocol('tls1_2'),certRow({...leaf,key_type:'UNKNOWN',key_bits:0,signature_algorithm:'unknown'})]);
assert.equal(evaluateTlsCondition(weakKeyFinding.id,unknown).state,'deferred');
assert.equal(evaluateTlsCondition(weakSignatureFinding.id,unknown).state,'deferred');
const strong=module([protocol('tls1_2'),certRow({...leaf,key_bits:3072,signature_algorithm:'rsa_sha256'})]);
assert.equal(evaluateTlsCondition(weakKeyFinding.id,strong).state,'clear');
assert.equal(evaluateTlsCondition(weakSignatureFinding.id,strong).state,'clear');
const robot={...protocol('tls1_2'),control:'robot',reason:'active_confirmed',engine:{...engine,family:'active_legacy'},
  evidence:{...protocol('tls1_2').evidence,vulnerability:{status:'confirmed',profile:'robot-finite-v1',completed_vectors:10,planned_vectors:10}},
  physical_telemetry:{...good,connections:11}};
const robotFinding=tlsAssessmentFindings(module([protocol('tls1_2'),robot])).find(row=>row.id.startsWith('tls_robot_confirmed__'));
assert(robotFinding);
assert.equal(robotFinding.confidence,80);
assert.match(robotFinding.description,/CDN edge result does not establish an origin vulnerability/);
assert.equal(evaluateTlsCondition(robotFinding.id,module([protocol('tls1_2'),robot])).state,'present');
const robotClear={...robot,state:'rejected',reason:'active_not_observed',evidence:{...robot.evidence,
  vulnerability:{...robot.evidence.vulnerability,status:'not_observed'}}};
assert.equal(evaluateTlsCondition(robotFinding.id,module([protocol('tls1_2'),robotClear])).state,'clear');
assert.equal(evaluateTlsCondition(robotFinding.id,module([protocol('tls1_2'),{...robotClear,state:'uncertain'}])).state,'deferred');
const plan=buildTlsCheckPlan({endpoints:[{endpoint_identity:identity,scope:{special_consent:false}}],cipherCatalog:[
  ...Array.from({length:160},(_,index)=>({protocol:'tls1_2',name:`CIPHER_${index}`,executable:true}))],scanId:'scanA',maxChecks:60});
const next=buildTlsCheckPlan({endpoints:[{endpoint_identity:identity,scope:{special_consent:false}}],cipherCatalog:[
  ...Array.from({length:160},(_,index)=>({protocol:'tls1_2',name:`CIPHER_${index}`,executable:true}))],scanId:'scanB',maxChecks:60});
assert(plan.selected.some(row=>row.check.control==='cipher'));
assert(next.selected.some(row=>row.check.control==='cipher'));
assert.notDeepEqual(plan.selected.filter(row=>row.check.control==='cipher').map(row=>row.check.cipher_id),
  next.selected.filter(row=>row.check.control==='cipher').map(row=>row.check.cipher_id));

// ── TLS endpoint conditions as Certificates & Trust cases (23 Oct 2026) ──────
// Real SQLite (schema + migrations), the real case model and alert pipeline.
{
  // The shared harness DB: schema + migrations applied statement by statement,
  // a schema error terminal (F-025/F-035), never a blanket catch here.
  const { buildDb } = await import('./security/lib/worker-harness.js');
  const db = buildDb();
  db.exec('PRAGMA foreign_keys=OFF');
  const wrap=(sql,args=[])=>({bind:(...a)=>wrap(sql,a),first:async()=>db.prepare(sql).get(...args)||null,
    all:async()=>({results:db.prepare(sql).all(...args)}),run:async()=>{const r=db.prepare(sql).run(...args);return {meta:{changes:r.changes}};}});
  const env={cybermeters_db:{prepare:sql=>wrap(sql),batch:async st=>Promise.all(st.map(x=>x.run()))},RESEND_API_KEY:'',FRONTEND_URL:'https://app.cybermeters.com'};
  db.prepare("INSERT INTO users (id,email,email_verified) VALUES ('u1','owner@example.org',1)").run();
  db.prepare("INSERT INTO workspaces (id,name,owner_user_id) VALUES ('ws1','Example','u1')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('d1','u1','example.org')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id,verification_status) VALUES ('ws1','d1','verified')").run();
  const { reconcileTlsEndpointCases } = await import('../workers/scan-api/src/engines/tls-endpoint-cases.js');
  const run = assessment => reconcileTlsEndpointCases(env,{workspace_id:'ws1',domain:'example.org',scan_id:'scan_t',tls_assessment:assessment});
  const { tlsCaseKey } = await import('../workers/scan-api/src/engines/tls-findings.js');
  const caseKey = tlsCaseKey(finding.tls_condition);
  assert.match(caseKey,/^tlscase:tls_legacy_protocol:[a-f0-9]{64}$/,'the case key is build-less');
  const kase = () => db.prepare("SELECT * FROM managed_cases WHERE workspace_id='ws1' AND finding_id=?").get(caseKey);
  const events = () => db.prepare("SELECT action,from_status,to_status,actor_type FROM managed_case_events WHERE case_id=? ORDER BY rowid").all(kase()?.id).map(e=>({...e}));
  const transitions = () => db.prepare("SELECT detail_json FROM certificate_lifecycle_events WHERE lifecycle_id=? AND event_type='monitoring_changed' ORDER BY rowid").all(kase()?.id).map(r=>JSON.parse(r.detail_json).to_recurrence_type);

  assert.deepEqual(await run(baseline), {opened:1,reopened:0,verified:0}, 'a measured legacy protocol opens one case');
  const c1=kase();
  assert.deepEqual([c1.case_type,c1.domain_key,c1.status,c1.source_finding_type,c1.severity,c1.remediation_id],
    ['certificate_case','certificates_trust','detected','tls_legacy_protocol','high','tls.endpoint.legacy_protocol'], 'the case is a Certificates & Trust case with the canonical remediation');
  assert.deepEqual(transitions(),['tls_condition_observed'],'the opening is recorded as an alert occurrence');
  const { certificateCaseDisplay } = await import('../workers/scan-api/src/engines/certificate-lifecycle.js');
  assert.equal(certificateCaseDisplay(c1).display_title,'TLS endpoint mail.example.org — legacy TLS version accepted','a TLS case names the endpoint condition, never "Certificate follow-up"');
  assert.deepEqual(await run(baseline), {opened:0,reopened:0,verified:0}, 'the same measurement again opens nothing new');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM managed_cases WHERE workspace_id='ws1'").get().n,1,'one case per exact condition');
  const fixed=module([protocol('tls1','rejected'),protocol('tls1_3')]);
  assert.deepEqual(await run(fixed), {opened:0,reopened:0,verified:0}, 'a fix on a case nobody submitted verifies nothing');
  assert.equal(kase().status,'detected');
  db.prepare("UPDATE managed_cases SET status='awaiting_verification' WHERE id=?").run(c1.id);
  assert.deepEqual(await run(module([protocol('tls1','uncertain'),protocol('tls1_3')])), {opened:0,reopened:0,verified:0}, 'an inconclusive retest never verifies');
  // A new probe build (Executive, 23 Oct 13:45): the same weakness on the same
  // endpoint reaches the SAME case, never a duplicate; the build is evidence.
  const newBuild={...engine,build_id:'c'.repeat(64)};
  const stillThereNewBuild=module([{...protocol('tls1'),engine:newBuild},{...protocol('tls1_3'),engine:newBuild}]);
  assert.deepEqual(await run(stillThereNewBuild), {opened:0,reopened:0,verified:0}, 'a new engine build measuring the same condition opens no duplicate');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM managed_cases WHERE workspace_id='ws1'").get().n,1,'still one case after the build changed');
  assert.notEqual(tlsAssessmentFindings(stillThereNewBuild)[0].id, finding.id, 'the finding id does change with the build (it is evidence)');
  assert.deepEqual(await run(module([{...protocol('tls1','rejected'),engine:newBuild},{...protocol('tls1','accepted')},protocol('tls1_3')])), {opened:0,reopened:0,verified:0}, 'one build clear while another still measures it present never verifies');
  assert.deepEqual(await run({source:'tls_assessment',quality:'complete',endpoints:[endpoint([protocol('tls1','rejected'),protocol('tls1_3')],'1.1.1.1')]}), {opened:0,reopened:0,verified:0}, 'a scan that never re-measured this endpoint never verifies it');
  const fixedNewBuild=module([{...protocol('tls1','rejected'),engine:newBuild},{...protocol('tls1_3'),engine:newBuild}]);
  assert.deepEqual(await run(fixedNewBuild), {opened:0,reopened:0,verified:1}, 'an exact-retest clear from the new build verifies the submitted case');
  const v=kase(); assert.equal(v.status,'verified');
  assert.deepEqual(events().at(-1),{action:'transition_verified',from_status:'awaiting_verification',to_status:'verified',actor_type:'system'},'verified by the system');
  const verifiedEvidence=JSON.parse(db.prepare("SELECT detail_json FROM managed_case_events WHERE case_id=? AND action='transition_verified'").get(c1.id).detail_json);
  assert.deepEqual(verifiedEvidence.observation.engine_build_ids,['c'.repeat(64)],'the verifying engine build is recorded on the evidence');
  assert.deepEqual(await run(baseline), {opened:0,reopened:1,verified:0}, 'the condition measured again after verification reopens the same case');
  const r=kase(); assert.deepEqual([r.id,r.status,r.reopened_count],[c1.id,'reopened',1]);
  assert.deepEqual(transitions(),['tls_condition_observed','tls_condition_returned'],'the reopen is its own alert occurrence');
  assert.deepEqual(await run({source:'not_tls'}), {opened:0,reopened:0,verified:0,skipped:'no_tls_assessment'});
  db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='ws1'").run();
  db.prepare("DELETE FROM managed_cases").run();
  assert.equal((await run(baseline)).opened,0,'a soft-deleted workspace gets no new case');
}
console.log('Deep TLS findings: physical proof, exact retest, endpoint/tool isolation and catalogue rotation passed');
