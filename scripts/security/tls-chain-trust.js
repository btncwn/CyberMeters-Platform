import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { buildDb, makeEnv } from './lib/worker-harness.js';
import { tlsAssessmentFindings, tlsCaseKey, evaluateTlsCase, evaluateTlsCondition } from '../../workers/scan-api/src/engines/tls-findings.js';
import { reconcileTlsEndpointCases } from '../../workers/scan-api/src/engines/tls-endpoint-cases.js';
import { createManagedCase, canTransitionCase } from '../../workers/scan-api/src/engines/managed-case-model.js';

const identity='mail.example.org|mail.example.org|8.8.8.8|587|tcp|smtp';
const stamp='2026-10-24T12:00:00.000Z',leaf='b'.repeat(64),build='a'.repeat(64);
const protocol=p=>({control:'protocol',protocol:p,cipher_id:null,state:'accepted',reason:'handshake_completed',observed_at:stamp,
  engine:{family:'legacy',version:'1.0.2u',build_id:build,sandboxed:true},
  physical_telemetry:{connections:1,bytes_sent:120,bytes_received:300,duration_ms:10},
  evidence:{authenticated_finished:true,negotiated:{version:p,cipher:'AES256-SHA'}}});
const cert=(p,trust='invalid',fingerprint=leaf)=>({...protocol(p),control:'certificate',
  evidence:{...protocol(p).evidence,certificates:{trust,reason:'issuer_missing',hostname:true,
    offered_chain:[{sha256:fingerprint,key_type:'RSA',key_bits:3072,signature_algorithm:'rsa_sha256'}]}}});
const endpoint=checks=>({endpoint_identity:identity,hostname:'mail.example.org',sni:'mail.example.org',address:'8.8.8.8',port:587,application_protocol:'smtp',checks});
const assessment=(a=cert('tls1_2'),b=cert('tls1_3'))=>({source:'tls_assessment',quality:'complete',endpoints:[endpoint([protocol('tls1_2'),protocol('tls1_3'),a,b])]});
const findings=a=>tlsAssessmentFindings(a).filter(f=>f.tls_condition.type==='tls_certificate_trust');
const old=assessment(),[finding]=findings(old),key=tlsCaseKey(finding.tls_condition);
assert.equal(findings(old).length,1,'two protocol rows for one endpoint/leaf emit one finding');
assert.equal(finding.evidence.length,2,'both protocol measurements remain evidence');
assert.equal(finding.tls_condition.protocol,null);
assert.equal(finding.tls_condition.leaf_sha256,leaf);
assert.equal(finding.score_impact,0);
assert.equal(finding.severity,'high');
const expired=cert('tls1_3');expired.evidence.certificates.reason='expired';
const differentReasons=findings(assessment(cert('tls1_2'),expired))[0];
assert.match(differentReasons.description,/the issuing certificate could not be found/);
assert.match(differentReasons.description,/the certificate has expired/);
assert.equal(differentReasons.description,findings(assessment(expired,cert('tls1_2')))[0].description,'different trust reasons are all listed, independent of row order');
assert.equal((finding.description.match(/the issuing certificate could not be found/g)||[]).length,1,'identical trust reasons are not repeated');
assert.equal(findings(assessment(cert('tls1_3'),cert('tls1_2')))[0].id,finding.id,'row order does not change identity');
const otherBuild=cert('tls1_3');otherBuild.engine={...otherBuild.engine,family:'modern',build_id:'c'.repeat(64)};
assert.equal(findings(assessment(cert('tls1_2'),otherBuild)).length,1,'two engines still measure one endpoint/leaf issue');
assert.equal(findings(assessment(cert('tls1_2'),cert('tls1_3','invalid','c'.repeat(64)))).length,2,'different leaves remain different findings');
assert.equal(findings(assessment(cert('tls1_2','invalid',null),cert('tls1_3','invalid',null))).length,0,'missing leaf identity is not guessed');
const untrusted={...cert('tls1_3'),engine:{...cert('tls1_3').engine,sandboxed:false}};
assert.equal(evaluateTlsCondition(finding.id,assessment(cert('tls1_2','valid'),untrusted)).state,'deferred','untrusted provenance cannot verify a protocol variant');
const other=endpoint([protocol('tls1_2'),cert('tls1_2')]);other.endpoint_identity=identity.replace('|587|','|465|');other.port=465;
assert.equal(findings({...old,endpoints:[old.endpoints[0],other]}).length,2,'different endpoints remain different findings');
assert.equal(evaluateTlsCondition(finding.id,assessment(cert('tls1_2','valid'),cert('tls1_3'))).state,'present','one valid row cannot hide an invalid row');
const split={...old,endpoints:[endpoint([protocol('tls1_2'),cert('tls1_2','valid')]),endpoint([protocol('tls1_3'),cert('tls1_3')])]};
assert.equal(findings(split).length,1);
assert.equal(evaluateTlsCondition(finding.id,split).state,'present','repeated endpoint entries are aggregated too');
const good=assessment(cert('tls1_2','valid'),cert('tls1_3','valid'));
assert.equal(evaluateTlsCondition(finding.id,good).state,'clear');
const rebuilt={...good,endpoints:good.endpoints.map(e=>({...e,checks:e.checks.map(r=>({...r,engine:{...r.engine,build_id:'f'.repeat(64)}}))}))};
assert.equal(evaluateTlsCase(key,rebuilt).state,'clear','a new tool build still verifies the same endpoint/leaf case');
assert.deepEqual(evaluateTlsCase(key,rebuilt).engine_build_ids,['f'.repeat(64)]);
const uncertain={...cert('tls1_3'),state:'uncertain',evidence:{authenticated_finished:false,certificates:null}};
assert.equal(evaluateTlsCondition(finding.id,assessment(cert('tls1_2','valid'),uncertain)).state,'deferred');
assert.equal(evaluateTlsCase(key,assessment(cert('tls1_2','valid','d'.repeat(64)),cert('tls1_3','valid','d'.repeat(64))),finding.tls_condition).state,'clear','a fully validated replacement fixes the same endpoint');
assert.equal(evaluateTlsCase(key,assessment(cert('tls1_2','invalid','d'.repeat(64)),cert('tls1_3','invalid','d'.repeat(64))),finding.tls_condition).state,'deferred','an invalid replacement never verifies the prior leaf');

// Frozen predecessor recipe, independent of the new compatibility helper.
const legacy=p=>'tlscase:tls_certificate_trust:'+createHash('sha256').update(
  ['tls-case-v1','tls_certificate_trust',identity,'certificate',p,'',''].join('\n')).digest('hex');

async function fixture({history=true,original=old}={}){
  const db=buildDb(),env=makeEnv(db);env.RESEND_API_KEY='';
  // Model D1's atomic, serial batch semantics using real local SQLite.
  let tail=Promise.resolve();
  env.cybermeters_db.batch=statements=>{
    const result=tail.then(async()=>{db.exec('BEGIN');try{const out=[];for(const s of statements)out.push(await s.run());db.exec('COMMIT');return out;}catch(e){db.exec('ROLLBACK');throw e;}});
    tail=result.catch(()=>{});return result;
  };
  db.exec("INSERT INTO users(id,email,email_verified) VALUES('u','owner@example.org',1); INSERT INTO workspaces(id,owner_user_id,name) VALUES('ws','u','Fixture'),('foreign','u','Foreign'); INSERT INTO domains(id,user_id,domain) VALUES('d','u','example.org'); INSERT INTO workspace_domains(workspace_id,domain_id,verification_status) VALUES('ws','d','verified'),('foreign','d','verified');");
  db.exec("INSERT INTO alert_activation(id,workspace_id,domain_key,activated_at,baseline_count,created_at) VALUES('activation','ws','certificates_trust','2026-01-01T00:00:00Z',0,'2026-01-01T00:00:00Z')");
  const saveHistory=()=>{
    const tls={endpoints:[{endpoint_identity:identity,endpoint:{hostname:'mail.example.org',sni:'mail.example.org',address:'8.8.8.8',port:587,application_protocol:'smtp'},scope:{}}],
      static_results:[],results:original.endpoints[0].checks.map(r=>({...r,endpoint_index:0})),selected:[],cursor:0,gaps:[],profile_version:'fixture',policy_version:'fixture'};
    db.prepare("INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,state,plan_json,created_ms,deadline_ms,updated_at) VALUES('original','ws','d','example.org','complete',?,0,1,?)").run(JSON.stringify({tls}),stamp);
  };
  if(history)saveHistory();
  const cases=[];
  for(const p of ['tls1_2','tls1_3']){
    const r=await createManagedCase(env,{workspace_id:'ws',domain_key:'certificates_trust',case_type:'certificate_case',
      source_finding_type:'tls_certificate_trust',source_finding_id:legacy(p),source_scan_id:'original',domain:'example.org',asset_ref:'mail.example.org',
      title:'Certificate chain did not validate',severity:'high',evidence:{marker:p,tls_condition:{type:'tls_certificate_trust',control:'certificate',protocol:p,cipher_id:null}},actor:{actor_type:'system'}});
    assert(r.ok&&r.created);cases.push(r.case);
  }
  db.prepare("UPDATE managed_cases SET status='awaiting_verification',owner_ref='owner-kept',due_at='2026-11-01',reopened_count=2 WHERE id=?").run(cases[0].id);
  db.prepare("UPDATE managed_cases SET status='approved',owner_ref='other-owner-kept' WHERE id=?").run(cases[1].id);
  const run=a=>reconcileTlsEndpointCases(env,{workspace_id:'ws',domain:'example.org',scan_id:'current',tls_assessment:a,now:stamp});
  const rows=()=>db.prepare("SELECT * FROM managed_cases WHERE workspace_id='ws' ORDER BY id").all();
  return {db,env,cases,run,rows,saveHistory};
}
{
  const {db,cases,run,rows}=await fixture();
  const created=db.prepare('SELECT * FROM managed_case_events WHERE action=\'case_created\' ORDER BY id').all();
  assert.deepEqual(await run(old),{opened:0,reopened:0,verified:0});
  const survivor=rows().find(r=>r.finding_id===key),alias=rows().find(r=>r.id!==survivor.id);
  assert.equal(survivor.id,cases[0].id,'the advanced existing case survives; no new case ID');
  assert.deepEqual([survivor.status,survivor.owner_ref,survivor.due_at,survivor.reopened_count],['awaiting_verification','owner-kept','2026-11-01',2]);
  assert.equal(JSON.parse(survivor.evidence_json).marker,'tls1_2');
  assert.equal(alias.status,'superseded','duplicate advanced workflow is retired, never marked verified');
  assert.equal(alias.owner_ref,'other-owner-kept');
  assert.equal(JSON.parse(alias.evidence_json).tls_identity_alias.canonical_case_id,survivor.id);
  assert.equal(rows().length,2,'both original histories remain stored');
  assert.deepEqual(db.prepare('SELECT * FROM managed_case_events WHERE action=\'case_created\' ORDER BY id').all(),created,'no history rewritten or new creation');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM certificate_lifecycle_events').get().n,0,'identity migration produces no alert occurrence');
  const before=JSON.stringify(rows()),events=db.prepare('SELECT COUNT(*) n FROM managed_case_events').get().n;
  assert.deepEqual(await run(old),{opened:0,reopened:0,verified:0});
  assert.equal(JSON.stringify(rows()),before,'repeat reconciliation is idempotent');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM managed_case_events').get().n,events);
  assert.deepEqual(await run(assessment(cert('tls1_2','valid'),uncertain)),{opened:0,reopened:0,verified:0});
  assert.deepEqual(await run(good),{opened:0,reopened:0,verified:1},'exact valid retest verifies just the surviving submitted case');
  assert.deepEqual(await run(old),{opened:0,reopened:1,verified:0},'a genuine recurrence reopens the same case once');
  assert.equal(rows().find(r=>r.id===survivor.id).reopened_count,3);
  assert.equal(rows().find(r=>r.id===alias.id).status,'superseded');
  assert.equal(db.prepare("SELECT COUNT(*) n FROM certificate_lifecycle_events WHERE event_type='monitoring_changed'").get().n,1,'one recurrence occurrence');
  const advanced={...survivor,status:'approved'};
  const opts={case:advanced,target_status:'superseded',actor:{actor_type:'system'},reason:'duplicate',identity_merge:{canonical_case:{...survivor,id:'another'},condition:finding.tls_condition}};
  assert.equal(canTransitionCase(opts).ok,true);
  assert.equal(canTransitionCase({...opts,actor:{actor_type:'customer',actor_id:'u'}}).ok,false,'customers cannot use the internal compatibility edge');
  assert.equal(canTransitionCase({...opts,identity_merge:{...opts.identity_merge,canonical_case:{...opts.identity_merge.canonical_case,workspace_id:'foreign'}}}).ok,false);
  assert.equal(canTransitionCase({...opts,identity_merge:{...opts.identity_merge,condition:{...finding.tls_condition,leaf_sha256:null,detail:null}}}).ok,false);
  assert.equal(canTransitionCase({...opts,case:{...advanced,source_finding_type:'tls_weak_cipher'}}).ok,false);
  db.close();
}
{
  const {db,run,rows,saveHistory}=await fixture({history:false});
  const before=JSON.stringify(rows());
  assert.deepEqual(await run(old),{opened:0,reopened:0,verified:0,identity_deferred:1});
  assert.equal(JSON.stringify(rows()),before,'missing original leaf proof neither guesses a merge nor creates a duplicate');
  saveHistory();assert.deepEqual(await run(old),{opened:0,reopened:0,verified:0});
  assert.equal(rows().filter(r=>r.status!=='superseded').length,1,'restored original evidence reconciles both original cases');
  db.close();
}
{
  const distinct=assessment(cert('tls1_2'),cert('tls1_3','invalid','c'.repeat(64)));
  const {db,run,rows}=await fixture({original:distinct});
  assert.equal((await run(distinct)).opened,0);
  assert.equal(rows().filter(r=>r.status!=='superseded').length,2,'different original leaves are never merged');
  db.close();
}
// R1: unreadable historical proof cannot suppress a real returning failure.
for(const status of ['verified','monitoring']){
  const {db,cases,run,rows}=await fixture({history:false});
  db.prepare('UPDATE managed_cases SET status=? WHERE id=?').run(status,cases[0].id);
  db.prepare("UPDATE managed_cases SET status='closed_no_action' WHERE id=?").run(cases[1].id);
  const historicalBefore=JSON.stringify(rows().find(r=>r.id===cases[0].id));
  assert.deepEqual(await run(old),{opened:1,reopened:0,verified:0},`${status} old case with unreadable source allows one current endpoint/leaf case`);
  const active=rows().filter(r=>['detected','triaged','assigned','approved','action_in_progress','awaiting_verification','reopened'].includes(r.status));
  assert.equal(active.length,1,'exactly one active case despite two protocol measurements');
  assert.equal(active[0].finding_id,key);
  assert.equal(JSON.stringify(rows().find(r=>r.id===cases[0].id)),historicalBefore,'unproven historical identity is not guessed or rewritten');
  assert.deepEqual(await run(old),{opened:0,reopened:0,verified:0},'a repeat does not duplicate the current case');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM certificate_lifecycle_events').get().n,1,'the returning failure produces one occurrence');
  db.close();
}
{
  const {db,cases,run,rows}=await fixture({history:false});
  db.prepare("UPDATE managed_cases SET status='closed_no_action' WHERE id=?").run(cases[1].id);
  const differentLeaf='c'.repeat(64),distinct=assessment(cert('tls1_2'),cert('tls1_3','invalid',differentLeaf));
  const secondKey=tlsCaseKey(findings(distinct).find(f=>f.tls_condition.leaf_sha256===differentLeaf).tls_condition);
  assert.deepEqual(await run(distinct),{opened:1,reopened:0,verified:0,identity_deferred:1},'unreadable open protocol case holds its own leaf only');
  assert.equal(rows().filter(r=>r.finding_id===secondKey&&r.status==='detected').length,1,'a different second leaf is not suppressed');
  assert.equal(rows().find(r=>r.id===cases[0].id).finding_id,legacy('tls1_2'),'the unknown open case retains its old identity');
  assert.deepEqual(await run(distinct),{opened:0,reopened:0,verified:0,identity_deferred:1});
  db.close();
}
for(const acceptedIndex of [0,1]){
  const {db,cases,run,rows}=await fixture();
  db.prepare("UPDATE managed_cases SET status='detected',reason=NULL WHERE workspace_id='ws'").run();
  db.prepare("UPDATE managed_cases SET status='accepted_risk',reason='Protocol-specific acceptance',risk_accepted_until='2026-11-01T00:00:00Z' WHERE id=?").run(cases[acceptedIndex].id);
  assert.deepEqual(await run(old),{opened:0,reopened:0,verified:0});
  const survivor=rows().find(r=>r.finding_id===key);
  assert.equal(survivor.id,cases[1-acceptedIndex].id,'the still-failing detected workflow outranks a sibling risk acceptance');
  assert.equal(survivor.status,'detected');
  const migration=db.prepare("SELECT detail_json FROM managed_case_events WHERE action='evidence_added' AND json_extract(detail_json,'$.evidence_type')='tls_trust_identity_compatibility'").get();
  assert.ok(JSON.parse(migration.detail_json).sources.some(s=>s.case_id===cases[acceptedIndex].id&&s.status==='accepted_risk'&&s.reason==='Protocol-specific acceptance'),'acceptance remains in append-only history');
  assert.equal(rows().find(r=>r.id===cases[acceptedIndex].id).status,'superseded');
  db.close();
}
// Legacy raw case keys can still re-test before original evidence is available.
assert.equal(evaluateTlsCase(legacy('tls1_2'),good).state,'clear');
assert.equal(evaluateTlsCase(legacy('tls1_2'),old).state,'present');
{
  const {db,env,cases,run,rows}=await fixture();
  db.prepare("UPDATE managed_cases SET status='verified',verified_at=? WHERE id=?").run(stamp,cases[1].id);
  const foreign=await createManagedCase(env,{workspace_id:'foreign',domain_key:'certificates_trust',case_type:'certificate_case',source_finding_type:'tls_certificate_trust',source_finding_id:legacy('tls1_2'),source_scan_id:'original',domain:'example.org',asset_ref:'mail.example.org',severity:'high',actor:{actor_type:'system'}});
  const foreignBefore=JSON.stringify(db.prepare('SELECT * FROM managed_cases WHERE id=?').get(foreign.case.id));
  assert.deepEqual(await run(old),{opened:0,reopened:0,verified:0},'an existing open sibling prevents reopening a historical verified duplicate');
  assert.equal(rows().find(r=>r.id===cases[1].id).status,'verified','historical verification is not rewritten as an active failure');
  assert.equal(JSON.parse(rows().find(r=>r.id===cases[1].id).evidence_json).tls_identity_alias.canonical_case_id,cases[0].id);
  assert.equal(JSON.stringify(db.prepare('SELECT * FROM managed_cases WHERE id=?').get(foreign.case.id)),foreignBefore,'another workspace is byte-identical');
  db.close();
}
{
  const {db,run,rows}=await fixture();
  const results=await Promise.all([run(old),run(old)]);
  assert.equal(results.reduce((n,r)=>n+r.opened+r.reopened,0),0,'concurrent migration never opens or reopens a case');
  assert.equal(rows().filter(r=>r.status!=='superseded').length,1);
  assert.equal(db.prepare("SELECT COUNT(*) n FROM managed_case_events WHERE action='evidence_added' AND json_extract(detail_json,'$.evidence_type')='tls_trust_identity_compatibility'").get().n,1,'one atomic identity migration');
  db.close();
}
{
  const {db,run,rows}=await fixture();
  db.prepare("UPDATE workspaces SET deleted_at=? WHERE id='ws'").run(stamp);
  const before=JSON.stringify(rows());await run(old);
  assert.equal(JSON.stringify(rows()),before,'an inactive workspace receives no identity mutation');
  db.close();
}
{
  const {db,run,rows}=await fixture({history:false});
  db.prepare("INSERT INTO external_exposure_jobs(scan_id,workspace_id,domain_id,domain,state,plan_json,created_ms,deadline_ms,updated_at) VALUES('foreign-source','foreign','d','example.org','complete','{}',0,1,?)").run(stamp);
  db.prepare("UPDATE managed_cases SET source_scan_id='foreign-source' WHERE workspace_id='ws'").run();
  const before=JSON.stringify(rows());assert.equal((await run(old)).identity_deferred,1);
  assert.equal(JSON.stringify(rows()),before,'another workspace source cannot establish the original leaf');
  db.close();
}
{
  const {db,env,run,rows}=await fixture();
  const prior=await createManagedCase(env,{workspace_id:'ws',domain_key:'certificates_trust',case_type:'certificate_case',source_finding_type:'tls_certificate_trust',source_finding_id:key,source_scan_id:'original',domain:'example.org',asset_ref:'mail.example.org',severity:'high',evidence:{tls_condition:finding.tls_condition},actor:{actor_type:'system'}});
  assert(prior.ok&&prior.created);
  assert.deepEqual(await run(old),{opened:0,reopened:0,verified:0});
  assert.equal(rows().filter(r=>r.status!=='superseded').length,1,'an existing new-key row cannot displace a more advanced old workflow');
  const alias=rows().find(r=>r.id===prior.case.id);
  assert.equal(alias.status,'superseded');assert.match(alias.finding_id,/:alias:/,'the old unique index cannot collide with a historical canonical alias');
  db.close();
}
{
  const {db,env,run,rows}=await fixture();
  const before=JSON.stringify(rows()),events=db.prepare('SELECT COUNT(*) n FROM managed_case_events').get().n;
  const batch=env.cybermeters_db.batch;
  env.cybermeters_db.batch=statements=>batch([...statements,env.cybermeters_db.prepare('INSERT INTO missing_c57_fixture_table VALUES (1)')]);
  const oldError=console.error;console.error=()=>{};
  try { assert.equal((await run(old)).skipped,'reconcile_failed'); } finally { console.error=oldError; }
  assert.equal(JSON.stringify(rows()),before,'a batch failure restores every old case byte-for-byte');
  assert.equal(db.prepare('SELECT COUNT(*) n FROM managed_case_events').get().n,events,'a failed migration leaves no claimed audit event');
  db.close();
}
console.log('C-57 chain trust: one endpoint/leaf finding, legacy-case consolidation, exact retest, recurrence and fail-closed identity proof PASS');
