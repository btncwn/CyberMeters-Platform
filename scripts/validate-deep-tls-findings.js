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
// Must-Staple (RFC 7633, S3-MODERN 1): a finding only for a definite Must-Staple
// leaf with no stapled OCSP response; null/missing is not assessed.
{
  const good={key_type:'RSA',key_bits:2048,signature_algorithm:'rsa_sha256',sha256:'e'.repeat(64)};
  const stapleRow=(must_staple,ocsp)=>{const row=certRow({...good,must_staple});row.evidence.ocsp=ocsp;return row;};
  const absent={state:'absent',signature_valid:null,cert_id_match:null,fresh:null,this_update:null,next_update:null};
  const stapled={state:'good',signature_valid:true,cert_id_match:true,fresh:true,this_update:1,next_update:2};
  const ids=(row)=>tlsAssessmentFindings(module([protocol('tls1_2'),row])).map(f=>f.id.split('__')[0]).filter(id=>id==='tls_must_staple_not_stapled');
  assert.deepEqual(ids(stapleRow(true,absent)),['tls_must_staple_not_stapled'],'Must-Staple leaf without a staple is a finding');
  assert.deepEqual(ids(stapleRow(true,stapled)),[],'Must-Staple leaf with a stapled response is fine');
  assert.deepEqual(ids(stapleRow(false,absent)),[],'no Must-Staple, no staple: not a finding');
  assert.deepEqual(ids(stapleRow(null,absent)),[],'unknown Must-Staple (legacy engine) is not assessed');
  assert.deepEqual(ids(stapleRow(true,null)),[],'no OCSP observation is not assessed');
  const finding=tlsAssessmentFindings(module([protocol('tls1_2'),stapleRow(true,absent)])).find(f=>f.id.startsWith('tls_must_staple_not_stapled__'));
  assert.equal(finding.severity,'high');
  assert.equal(evaluateTlsCondition(finding.id,module([protocol('tls1_2'),stapleRow(true,stapled)])).state,'clear','stapling enabled clears');
  assert.equal(evaluateTlsCondition(finding.id,module([protocol('tls1_2'),stapleRow(true,absent)])).state,'present','still unstapled stays present');
  assert.equal(evaluateTlsCondition(finding.id,module([protocol('tls1_2'),stapleRow(null,absent)])).state,'deferred','unknown is inconclusive');
  // R1: an invalid staple fails Must-Staple; it never reads stapled or clears.
  const invalidStaple={...stapled,state:'invalid',signature_valid:false};
  assert.deepEqual(ids(stapleRow(true,invalidStaple)),['tls_must_staple_not_stapled'],'an invalid staple is a finding');
  assert.equal(evaluateTlsCondition(finding.id,module([protocol('tls1_2'),stapleRow(true,invalidStaple)])).state,'present','an invalid staple never clears');
  assert.deepEqual(ids(stapleRow(true,{...stapled,state:'revoked'})),[],'a revoked staple is the tls_ocsp_revoked finding, not a duplicate');
  const { mustStapleState } = await import('../workers/scan-api/src/engines/tls-findings.js');
  const st=(row)=>mustStapleState(module([protocol('tls1_2'),row]))[0]?.state;
  assert.deepEqual([st(stapleRow(true,absent)),st(stapleRow(true,stapled)),st(stapleRow(false,absent)),st(stapleRow(null,absent)),st(stapleRow(true,null))],
    ['required_not_stapled','required_stapled','not_required','not_assessed','not_assessed'],'card states are backend-owned');
  assert.equal(st(stapleRow(true,invalidStaple)),'required_staple_invalid','an invalid staple reads invalid, never stapled');
}
const strong=module([protocol('tls1_2'),certRow({...leaf,key_bits:3072,signature_algorithm:'rsa_sha256'})]);
assert.equal(evaluateTlsCondition(weakKeyFinding.id,strong).state,'clear');
assert.equal(evaluateTlsCondition(weakSignatureFinding.id,strong).state,'clear');
const robot={...protocol('tls1_2'),control:'robot',reason:'active_confirmed',engine:{...engine,family:'active_legacy'},
  evidence:{...protocol('tls1_2').evidence,vulnerability:{status:'confirmed',profile:'robot-finite-v1',completed_vectors:10,planned_vectors:10}},
  physical_telemetry:{...good,connections:11}};
const robotFinding=tlsAssessmentFindings(module([protocol('tls1_2'),robot])).find(row=>row.id.startsWith('tls_robot_confirmed__'));
// C-45: no internal identifier (snake_case enum or profile id) in customer prose.
{
  const prose=/[a-z]+_[a-z_]+|-v\d/;
  const active=(control,profile,planned)=>({...robot,control,evidence:{...robot.evidence,vulnerability:{status:'confirmed',profile,completed_vectors:planned,planned_vectors:planned}}});
  const rows=[...['ssl2','ssl3','tls1','tls1_1'].map(v=>protocol(v)),cipher,robot,active('heartbleed','heartbleed-minimal-v1',1),active('ccs','ccs-early-record-v1',4),
    ...['rsa_md5','rsa_sha1','ecdsa_sha1','dsa_sha1'].map(sig=>certRow({...leaf,signature_algorithm:sig})),
    ...['issuer_missing','self_signed','expired','not_yet_valid','signature_invalid','invalid_purpose','trust_unknown','something_new'].map(reason=>{
      const row=certRow({...leaf,key_bits:3072,signature_algorithm:'rsa_sha256'});row.evidence.certificates={...row.evidence.certificates,trust:'invalid',reason};return row;})];
  let checked=0;
  for(const row of rows)for(const f of tlsAssessmentFindings(module([protocol('tls1_2'),row]))){
    for(const field of ['title','description','recommendation'])assert.doesNotMatch(f[field],prose,`${f.id.split('__')[0]} ${field}: ${f[field]}`);
    checked++;
  }
  assert.ok(checked>=20,`prose scan covered ${checked} findings`);
  const tls10=tlsAssessmentFindings(module([protocol('tls1_2'),protocol('tls1')]))[0];
  assert.match(tls10.title,/^TLS 1\.0 accepted/);assert.equal(tls10.evidence[0].value.startsWith('tls1 '),true,'evidence keeps the raw value');
  const expired=certRow({...leaf,key_bits:3072,signature_algorithm:'rsa_sha256'});expired.evidence.certificates={...expired.evidence.certificates,trust:'invalid',reason:'expired'};
  assert.match(tlsAssessmentFindings(module([protocol('tls1_2'),expired])).find(f=>f.id.startsWith('tls_certificate_trust__')).description,/certificate chain: the certificate has expired\./);
}
// Heartbeat not offered (Executive, 24 Oct 2026): Heartbleed reads "not
// applicable", never "Could not execute"; no finding; an open case stays inconclusive.
{
  const { classifyTlsRefusals } = await import('../workers/scan-api/src/engines/tls-quality.js');
  const noHeartbeat={...protocol('tls1_2'),control:'heartbleed',state:'unexecutable',reason:'heartbeat_unavailable',engine:{...engine,family:'active_legacy'},
    evidence:{...protocol('tls1_2').evidence,vulnerability:null}};
  const [mapped]=classifyTlsRefusals([noHeartbeat]);
  assert.deepEqual([mapped.state,mapped.reason,mapped.engine_state],['not_applicable','heartbeat_unavailable','unexecutable'],'heartbeat not offered is not applicable');
  assert.equal(classifyTlsRefusals([{...noHeartbeat,reason:'engine_capability_limit'}])[0].state,'unexecutable','another reason is unchanged');
  assert.equal(classifyTlsRefusals([{...noHeartbeat,control:'robot'}])[0].state,'unexecutable','only Heartbleed relies on the heartbeat extension');
  assert.equal(tlsAssessmentFindings(module([protocol('tls1_2'),mapped])).length,0,'not applicable is never a finding');
  const hbOpen={...noHeartbeat,state:'accepted',reason:'active_confirmed',evidence:{...noHeartbeat.evidence,vulnerability:{status:'confirmed',profile:'heartbleed-minimal-v1',completed_vectors:1,planned_vectors:1}}};
  const hbFinding=tlsAssessmentFindings(module([protocol('tls1_2'),hbOpen])).find(f=>f.id.startsWith('tls_heartbleed_confirmed__'));
  assert.equal(evaluateTlsCondition(hbFinding.id,module([protocol('tls1_2'),{...mapped,evidence:{...mapped.evidence,vulnerability:{status:'unknown',profile:'heartbleed-minimal-v1',completed_vectors:0,planned_vectors:0}}}])).state,'deferred','an open case is never cleared by a server that stopped offering the heartbeat');
}
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
  // Alerting is active for this domain (so the pipeline writes the alert, not baseline-only).
  db.prepare("INSERT INTO alert_activation (id,workspace_id,domain_key,activated_at,baseline_count,created_at) VALUES ('aa1','ws1','certificates_trust','2026-01-01T00:00:00Z',0,'2026-01-01T00:00:00Z')").run();
  const certAlerts = () => db.prepare("SELECT type, message FROM notification_events WHERE workspace_id='ws1' AND domain_key='certificates_trust' ORDER BY rowid").all().map(r=>({...r}));
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
  assert.equal(certificateCaseDisplay(c1).display_title,'TLS endpoint mail.example.org — TLS 1.0 accepted','a TLS case names its protocol, never "Certificate follow-up" or a shared phrase');
  // Two cases on one endpoint never read the same (Executive, 23 Oct 19:42).
  {
    const notifMark = db.prepare("SELECT COALESCE(MAX(rowid),0) m FROM notification_events").get().m;
    const both = module([protocol('tls1'),protocol('tls1_1'),protocol('tls1_3')]);
    await run(both);
    const titles = db.prepare("SELECT * FROM managed_cases WHERE workspace_id='ws1' AND source_finding_type='tls_legacy_protocol'").all().map(r=>certificateCaseDisplay({...r}).display_title).sort();
    assert.deepEqual(titles,['TLS endpoint mail.example.org — TLS 1.0 accepted','TLS endpoint mail.example.org — TLS 1.1 accepted'],'TLS 1.0 and TLS 1.1 cases are told apart');
    // An older case without the recorded condition gets it on the next re-measure, once, no duplicate.
    const t11 = db.prepare("SELECT id FROM managed_cases WHERE workspace_id='ws1' AND title LIKE 'TLS 1.1%'").get().id;
    db.prepare("UPDATE managed_cases SET evidence_json=NULL WHERE id=?").run(t11);
    assert.equal(certificateCaseDisplay({...db.prepare("SELECT * FROM managed_cases WHERE id=?").get(t11)}).display_title,'TLS endpoint mail.example.org — legacy TLS version accepted');
    const before = db.prepare("SELECT COUNT(*) n FROM managed_cases WHERE workspace_id='ws1'").get().n;
    await run(both);
    assert.equal(certificateCaseDisplay({...db.prepare("SELECT * FROM managed_cases WHERE id=?").get(t11)}).display_title,'TLS endpoint mail.example.org — TLS 1.1 accepted','an older case is retitled on the next re-measure');
    assert.equal(db.prepare("SELECT COUNT(*) n FROM managed_cases WHERE workspace_id='ws1'").get().n,before,'no duplicate case');
    assert.equal(certificateCaseDisplay({case_type:'certificate_case',source_finding_type:'tls_weak_cipher',asset_ref:'mail.example.org',evidence_json:JSON.stringify({tls_condition:{protocol:'tls1_2',cipher_id:'RC4-MD5'}})}).display_title,'TLS endpoint mail.example.org — weak cipher RC4-MD5 accepted','a weak cipher case names its cipher');
    assert.equal(certificateCaseDisplay({case_type:'certificate_case',source_finding_type:'tls_robot_confirmed',asset_ref:'mail.example.org'}).display_title,'TLS endpoint mail.example.org — ROBOT (RSA padding oracle) signal','a _confirmed case names its vulnerability');
    db.prepare("DELETE FROM managed_cases WHERE workspace_id='ws1' AND id<>?").run(c1.id);
    // This block's own side effects stay inside it (the alert assertions below count from the open).
    db.prepare("DELETE FROM notification_events WHERE rowid > ?").run(notifMark);
  }
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
  const sent = certAlerts();
  assert.deepEqual(sent.map(a=>a.type),['certificates_trust.tls_condition_observed','certificates_trust.tls_condition_returned'],'one alert on open, one on reopen');
  assert.match(sent[0].message,/A TLS measurement of mail\.example\.org observed: TLS 1\.0 accepted on this endpoint\./,'the open alert names the endpoint and the observed condition in plain words');
  assert.match(sent[1].message,/CyberMeters verified this fixed on \d{1,2} [A-Z][a-z]{2} \d{4}; it has been observed again, so the case is reopened\./,'the reopen alert says it was verified, and when');
  assert(!sent.some(a=>/tls_|tlscase:|condition "/.test(a.message)),'no internal key in alert prose');
  // F1 end to end (23 Oct 2026): an Active Checks grant -> a scan a person
  // started plans Heartbleed for the owned address -> the finite profile result
  // -> tls_heartbleed_confirmed -> a Certificates & Trust case -> one alert.
  // A scheduled scan with the same grant plans nothing intrusive.
  {
    const { loadTlsEndpoints, buildBudgetedTlsCheckPlan } = await import('../workers/scan-api/src/engines/tls-planner.js');
    const { isAuthorised } = await import('../workers/scan-api/src/engines/active-check-consent.js');
    db.prepare(`INSERT INTO active_check_consents(id,workspace_id,kind,domain_id,domain,hosts_json,checks_json,actor_user_id,actor_workspace_role,
        signer_name,signer_title,authority_text,authority_version,created_at) VALUES('acc_f1','ws1','grant','d1','example.org','[]',?,'u1','owner','Pat','IT','text','v',?)`)
      .run(JSON.stringify(['tls_intrusive_heartbleed']),new Date().toISOString());
    // The owned-address gate is the real one; only the DNS ownership read is fixed.
    const owned = async()=>({roots:['example.org'],owned:new Map([['8.8.8.8',{domain:'example.org'}]]),shared:new Set(),lookups_failed:0});
    const authorise = (e,q)=>isAuthorised(e,q,{observedNetworkAddresses:owned});
    const lookup = async(host,type)=>type==='A'?{Status:0,Answer:[{type:1,name:`${host}.`,data:'8.8.8.8'}]}:{Status:0,Answer:[]};
    const scan={id:'scan_f1',workspace_id:'ws1',domain_id:'d1',domain:'example.org'};
    const plan = async trigger => {
      const loaded=await loadTlsEndpoints(env,scan,{lookup,authorise,trigger});
      return {loaded,planned:buildBudgetedTlsCheckPlan({endpoints:loaded.endpoints,cipherCatalog:[],observedHttpsHosts:['example.org'],scanId:'scan_f1'})};
    };
    const scheduled=await plan('scheduled');
    assert.ok(!scheduled.planned.selected.some(r=>r.check.control==='heartbleed'),'F1: a scheduled scan never plans Heartbleed');
    const started=await plan('manual');
    assert.equal(started.loaded.endpoints[0].scope.special_checks.heartbleed,'acc_f1','F1: the started scan carries the grant for the owned address');
    const selected=started.planned.selected.find(r=>r.check.control==='heartbleed');
    assert.deepEqual(selected?.check,{control:'heartbleed',protocol:'tls1_2',cipher_id:null},'F1: the started scan plans Heartbleed on TLS 1.2');
    // The probe's finite profile result for exactly that check.
    const hb={...protocol('tls1_2'),control:'heartbleed',reason:'active_confirmed',engine:{...engine,family:'active_legacy'},
      evidence:{...protocol('tls1_2').evidence,vulnerability:{status:'confirmed',profile:'heartbleed-minimal-v1',completed_vectors:1,planned_vectors:1}}};
    const measured={source:'tls_assessment',quality:'complete',endpoints:[{...endpoint([protocol('tls1_2'),hb]),
      endpoint_identity:started.loaded.endpoints[0].endpoint_identity,hostname:'example.org',sni:'example.org',port:443,application_protocol:'https'}]};
    const confirmed=tlsAssessmentFindings(measured).find(f=>f.id.startsWith('tls_heartbleed_confirmed__'));
    assert.ok(confirmed,'F1: the confirmed profile result is a finding');
    const alertsBefore=certAlerts().length;
    assert.deepEqual(await run(measured),{opened:1,reopened:0,verified:0},'F1: it opens one case');
    const hbCase=db.prepare("SELECT * FROM managed_cases WHERE workspace_id='ws1' AND source_finding_type='tls_heartbleed_confirmed'").get();
    assert.deepEqual([hbCase.case_type,hbCase.domain_key,hbCase.severity],['certificate_case','certificates_trust','high'],'F1: a Certificates & Trust case');
    const hbAlerts=certAlerts().slice(alertsBefore);
    assert.deepEqual(hbAlerts.map(a=>a.type),['certificates_trust.tls_condition_observed'],'F1: one alert');
    assert.match(hbAlerts[0].message,/HEARTBLEED behaviour confirmed|Heartbleed behaviour confirmed/,'F1: the alert names the observed behaviour');
    // A clean profile result is no finding and opens nothing.
    const clean={...hb,state:'rejected',reason:'active_not_observed',evidence:{...hb.evidence,vulnerability:{...hb.evidence.vulnerability,status:'not_observed'}}};
    assert.ok(!tlsAssessmentFindings({...measured,endpoints:[{...measured.endpoints[0],checks:[protocol('tls1_2'),clean]}]}).some(f=>f.id.startsWith('tls_heartbleed_confirmed__')),'F1: a clean result is not a finding');
  }
  assert.deepEqual(await run({source:'not_tls'}), {opened:0,reopened:0,verified:0,skipped:'no_tls_assessment'});
  db.prepare("UPDATE workspaces SET deleted_at=datetime('now') WHERE id='ws1'").run();
  db.prepare("DELETE FROM managed_cases").run();
  assert.equal((await run(baseline)).opened,0,'a soft-deleted workspace gets no new case');
}
console.log('Deep TLS findings: physical proof, exact retest, endpoint/tool isolation and catalogue rotation passed');
