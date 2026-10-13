import assert from 'node:assert/strict';
import { tlsAssessmentFindings, evaluateTlsCondition } from '../workers/scan-api/src/engines/tls-findings.js';
import { resolveRemediation } from '../workers/scan-api/src/engines/remediation-registry.js';
import { buildTlsCheckPlan } from '../workers/scan-api/src/engines/tls-planner.js';

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
assert.equal(resolveRemediation({finding_type:finding.id}).status,'resolved');
assert.equal(evaluateTlsCondition(finding.id,module([protocol('tls1','rejected'),protocol('tls1_3')])).state,'clear');
assert.notEqual(evaluateTlsCondition(finding.id,module([protocol('tls1','uncertain'),protocol('tls1_3')])).state,'clear');
assert.equal(evaluateTlsCondition(finding.id,module([{...protocol('tls1','rejected'),reason:'peer_alert'},protocol('tls1_3')])).state,'deferred');
assert.notEqual(evaluateTlsCondition(finding.id,{source:'tls_assessment',endpoints:[endpoint([protocol('tls1','rejected'),protocol('tls1_3')],'1.1.1.1')]}).state,'clear');
assert.notEqual(evaluateTlsCondition(finding.id,module([{...protocol('tls1','rejected'),engine:{...engine,build_id:'b'.repeat(64)}},protocol('tls1_3')])).state,'clear');
const cipher={...protocol('tls1_2'),control:'cipher',cipher_id:'RC4-MD5',evidence:{...protocol('tls1_2').evidence,negotiated:{version:'tls1_2',cipher:'RC4-MD5'}}};
const cipherFinding=tlsAssessmentFindings(module([protocol('tls1_2'),cipher])).find(row=>row.id.startsWith('tls_weak_cipher__'));
assert(cipherFinding);
assert.equal(evaluateTlsCondition(cipherFinding.id,module([protocol('tls1_2'),{...cipher,state:'uncertain',reason:'peer_alert'}])).state,'deferred');
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
const plan=buildTlsCheckPlan({endpoints:[{endpoint_identity:identity,scope:{special_consent:false}}],cipherCatalog:[
  ...Array.from({length:160},(_,index)=>({protocol:'tls1_2',name:`CIPHER_${index}`,executable:true}))],scanId:'scanA',maxChecks:60});
const next=buildTlsCheckPlan({endpoints:[{endpoint_identity:identity,scope:{special_consent:false}}],cipherCatalog:[
  ...Array.from({length:160},(_,index)=>({protocol:'tls1_2',name:`CIPHER_${index}`,executable:true}))],scanId:'scanB',maxChecks:60});
assert(plan.selected.some(row=>row.check.control==='cipher'));
assert(next.selected.some(row=>row.check.control==='cipher'));
assert.notDeepEqual(plan.selected.filter(row=>row.check.control==='cipher').map(row=>row.check.cipher_id),
  next.selected.filter(row=>row.check.control==='cipher').map(row=>row.check.cipher_id));
console.log('Deep TLS findings: physical proof, exact retest, endpoint/tool isolation and catalogue rotation passed');
