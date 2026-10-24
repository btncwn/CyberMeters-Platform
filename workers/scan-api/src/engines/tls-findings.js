import { sha256Text } from '../../../../shared/exposure/redaction.js';
import { TLS_POLICY_VERSION, TLS_PROFILE_VERSION, isWeakTlsCipher, tlsProtocolRisk } from '../../../../shared/tls/catalog.js';

const positive = row => row.state === 'accepted' && row.evidence?.authenticated_finished === true &&
  row.physical_telemetry?.connections > 0 && row.physical_telemetry?.bytes_sent > 0 && row.physical_telemetry?.bytes_received > 0;
const endpointReachable = endpoint => endpoint.checks?.some(row => positive(row) && row.control === 'protocol');
const weakKeyExchange = negotiated => {
  const bits=negotiated?.group_bits,group=negotiated?.group||'';
  if(!Number.isInteger(bits)||bits<1||!group)return false;
  return /^(?:x25519|x448|secp|prime|p-\d)/i.test(group) ? bits<224 : bits<2048;
};
const strongCertificateKey = leaf => (leaf.key_type==='RSA'&&leaf.key_bits>=2048)
  || (leaf.key_type==='EC'&&leaf.key_bits>=224)
  || (leaf.key_type==='ED25519'&&leaf.key_bits>=256)
  || (leaf.key_type==='ED448'&&leaf.key_bits>=456);
const strongCertificateSignature = leaf => ['rsa_sha256','rsa_sha384','rsa_sha512',
  'ecdsa_sha256','ecdsa_sha384','ecdsa_sha512','ed25519','ed448'].includes(leaf.signature_algorithm);
const conditionKey = (type,endpoint,row,detail='') => {
  const engine=row.engine;
  if(!engine?.build_id)return null;
  return `${type}__${sha256Text([TLS_PROFILE_VERSION,TLS_POLICY_VERSION,endpoint.endpoint_identity,row.control,row.protocol,
    row.cipher_id||'',detail,engine.family,engine.version,engine.build_id].join('\n'))}`;
};
const evidence = (endpoint,row,value) => ({type:'tls_endpoint_measurement',label:'Pinned TCP TLS endpoint',value,
  source:'tls_assessment',checked_at:row.observed_at,endpoint:{hostname:endpoint.hostname,sni:endpoint.sni,address:endpoint.address,
    port:endpoint.port,transport:'tcp',application_protocol:endpoint.application_protocol},
  endpoint_identity:endpoint.endpoint_identity,control:row.control,protocol:row.protocol,cipher:row.evidence?.negotiated?.cipher||null,
  engine:{family:row.engine.family,version:row.engine.version,build_id:row.engine.build_id},
  profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION});
// Customer prose names things in words (C-45, 23 Oct 2026): protocol enums,
// trust reasons, signature enums and active-profile ids stay in evidence
// fields only, never in a title or description.
const PROTOCOL_WORDS={ssl2:'SSL 2.0',ssl3:'SSL 3.0',tls1:'TLS 1.0',tls1_1:'TLS 1.1',tls1_2:'TLS 1.2',tls1_3:'TLS 1.3'};
export const tlsProtocolWords=protocol=>PROTOCOL_WORDS[protocol]||'an unrecognised TLS version';
const TRUST_REASON_WORDS={issuer_missing:'the issuing certificate could not be found',self_signed:'the certificate is self-signed',
  expired:'the certificate has expired',not_yet_valid:'the certificate is not yet valid',signature_invalid:'a certificate signature is invalid',
  invalid_purpose:'the certificate is not valid for this purpose',trust_unknown:'the chain could not be validated'};
const trustReasonWords=reason=>TRUST_REASON_WORDS[reason]||'the chain could not be validated';
const SIGNATURE_WORDS={rsa_md5:'RSA with MD5',rsa_sha1:'RSA with SHA-1',ecdsa_sha1:'ECDSA with SHA-1',dsa_sha1:'DSA with SHA-1'};
const ACTIVE_CONTROL_WORDS={heartbleed:'Heartbleed',ccs:'CCS injection',robot:'ROBOT'};

const make = (type,endpoint,row,{title,description,severity,recommendation,value,detail='',confidence=95}) => {
  const id=conditionKey(type,endpoint,row,detail);
  if(!id)return null;
  return {id,module:'tls_assessment',finding_type:'finding',severity,confidence,score_impact:0,title,description,recommendation,
    evidence:[evidence(endpoint,row,value)],tls_condition:{type,endpoint_identity:endpoint.endpoint_identity,
      control:row.control,protocol:row.protocol,cipher_id:row.cipher_id||null,detail,
      engine_build_id:row.engine.build_id,profile_version:TLS_PROFILE_VERSION,policy_version:TLS_POLICY_VERSION,
      retest_requirement:'Repeat this control on the same reachable endpoint with the same engine build and profile. Missing, blocked, partial or changed-tool results cannot verify remediation.'}};
};

export function tlsAssessmentFindings(assessment) {
  if(assessment?.source!=='tls_assessment')return [];
  const output=new Map();
  const add = finding => {if(finding)output.set(finding.id,finding);};
  for(const endpoint of assessment.endpoints||[])for(const row of endpoint.checks||[]){
    if(!row.engine?.sandboxed || !row.observed_at)continue;
    if(row.control==='protocol'&&positive(row)&&row.evidence.negotiated?.version===row.protocol&&tlsProtocolRisk(row.protocol))
      add(make('tls_legacy_protocol',endpoint,row,{title:`${tlsProtocolWords(row.protocol)} accepted on this endpoint`,
        description:`The measured endpoint completed a ${tlsProtocolWords(row.protocol)} handshake. Certificate validity does not remove the risk of accepting this legacy protocol.`,
        severity:'high',recommendation:'Disable the observed legacy TLS version on this specific service after checking client compatibility, then repeat the same endpoint test.',
        value:`${row.protocol} authenticated Finished`}));
    if(row.control==='cipher'&&positive(row)&&row.evidence.negotiated?.cipher===row.cipher_id&&isWeakTlsCipher(row.cipher_id))
      add(make('tls_weak_cipher',endpoint,row,{title:'Weak TLS cipher accepted on this endpoint',
        description:`The endpoint completed a handshake with ${row.cipher_id}. This proves cipher acceptance, not exploitation of another weakness.`,
        severity:'high',recommendation:'Remove the observed weak cipher from this service and retest the same endpoint and protocol.',
        value:row.cipher_id,detail:row.cipher_id}));
    if(row.control==='key_exchange'&&positive(row)&&weakKeyExchange(row.evidence.negotiated))
      add(make('tls_weak_key_exchange',endpoint,row,{title:'Weak TLS key exchange accepted',
        description:`The measured key exchange used ${row.evidence.negotiated.group} with ${row.evidence.negotiated.group_bits} bits.`,
        severity:'high',recommendation:'Configure a current key exchange group on this service and retest the same endpoint.',
        value:`${row.evidence.negotiated.group} ${row.evidence.negotiated.group_bits}`}));
    if(row.control==='key_exchange'&&positive(row)&&row.evidence.negotiated?.pfs===false)
      add(make('tls_no_forward_secrecy',endpoint,row,{title:'Key exchange did not provide forward secrecy',
        description:'The completed handshake did not negotiate a forward-secret key exchange on this endpoint.',
        severity:'medium',recommendation:'Offer and prefer a forward-secret key exchange on this service, then repeat this control.',
        value:'forward secrecy false'}));
    if(['heartbleed','robot','ccs'].includes(row.control)&&row.evidence?.vulnerability?.status==='confirmed'&&
      row.evidence.vulnerability.completed_vectors===row.evidence.vulnerability.planned_vectors&&
      row.evidence.vulnerability.completed_vectors>0&&row.physical_telemetry?.connections>0)
      add(make(`tls_${row.control}_confirmed`,endpoint,row,{title:row.control==='robot'?'RSA padding oracle signal observed':`${ACTIVE_CONTROL_WORDS[row.control]} behaviour confirmed`,
        description:row.control==='robot'
          ? `The bounded ROBOT test observed repeatable different TLS alerts for RSA padding classes on this measured endpoint. No decryption was attempted. A CDN edge result does not establish an origin vulnerability; confirm the edge behaviour with its operator.`
          : `The bounded ${ACTIVE_CONTROL_WORDS[row.control]} test confirmed the behaviour on this measured endpoint. No memory collection or decryption was performed.`,
        severity:'high',confidence:row.control==='robot'?80:95,
        recommendation:row.control==='robot'
          ? 'Ask the measured edge or service operator to investigate the RSA padding oracle signal, update or reconfigure its TLS implementation where confirmed, then repeat this bounded control.'
          : 'Update or reconfigure the affected TLS implementation for this service, then repeat the same bounded control.',
        value:`${row.evidence.vulnerability.completed_vectors}/${row.evidence.vulnerability.planned_vectors} bounded vectors`,
        detail:row.evidence.vulnerability.profile}));
    if(row.control==='certificate'&&positive(row)){
      const cert=row.evidence.certificates,leaf=cert?.offered_chain?.[0];
      if(cert?.hostname===false)add(make('tls_certificate_hostname',endpoint,row,{title:'Certificate does not cover this hostname',
        description:'The offered certificate did not match the SNI hostname tested on this endpoint.',severity:'high',
        recommendation:'Deploy a certificate covering this hostname on this exact service and retest the endpoint.',
        value:leaf?.sha256||'hostname mismatch'}));
      if(cert?.trust==='invalid')add(make('tls_certificate_trust',endpoint,row,{title:'Certificate chain did not validate',
        description:`The local trust snapshot rejected the offered certificate chain: ${trustReasonWords(cert.reason)}. Revocation status is separate.`,severity:'high',
        recommendation:'Correct the certificate chain or trust configuration for this endpoint and retest against the recorded trust snapshot.',
        value:cert.reason}));
      if(leaf && ((leaf.key_type==='RSA'||leaf.key_type==='DSA')&&leaf.key_bits>0&&leaf.key_bits<2048 ||
        leaf.key_type==='EC'&&leaf.key_bits>0&&leaf.key_bits<224))
        add(make('tls_weak_certificate_key',endpoint,row,{title:'Certificate public key is below the policy minimum',
          description:`The offered leaf certificate uses ${leaf.key_type} ${leaf.key_bits}-bit key material.`,severity:'high',
          recommendation:'Replace the endpoint certificate with a suitable key and chain, then verify the live deployment.',
          value:`${leaf.key_type} ${leaf.key_bits}`}));
      if(leaf&&['rsa_md5','rsa_sha1','ecdsa_sha1','dsa_sha1'].includes(leaf.signature_algorithm))
        add(make('tls_weak_certificate_signature',endpoint,row,{title:'Certificate uses a legacy signature algorithm',
          description:`The offered leaf certificate is signed with ${SIGNATURE_WORDS[leaf.signature_algorithm]}.`,severity:'medium',
          recommendation:'Replace the certificate with one signed using a current algorithm and verify the live chain.',
          value:leaf.signature_algorithm}));
      const ocsp=row.evidence.ocsp;
      if(ocsp?.state==='revoked'&&ocsp.signature_valid&&ocsp.cert_id_match&&ocsp.fresh)
        add(make('tls_ocsp_revoked',endpoint,row,{title:'Stapled OCSP response reports revocation',
          description:'A valid, fresh stapled response for the offered certificate reports revoked status.',severity:'high',
          recommendation:'Replace the revoked certificate and correct the stapled response on this endpoint, then retest.',
          value:'verified stapled OCSP: revoked'}));
      // Must-Staple (RFC 7633, S3-MODERN 1): the leaf requires a stapled OCSP
      // response and none was stapled; browsers that enforce it refuse the
      // connection. Only a definite must_staple=true AND an observed 'absent'
      // staple count; null/unknown is not assessed, never a finding.
      // An invalid or unknown-status staple fails Must-Staple too (R1, 23 Oct
      // 2026); a revoked staple is already its own finding (tls_ocsp_revoked).
      if(leaf?.must_staple===true&&['absent','invalid','unknown'].includes(ocsp?.state))
        add(make('tls_must_staple_not_stapled',endpoint,row,{title:ocsp.state==='absent'
            ?'Certificate requires OCSP stapling, but none was stapled'
            :'Certificate requires OCSP stapling, but the stapled response is not usable',
          description:ocsp.state==='absent'
            ?'The offered leaf certificate carries the TLS Feature (Must-Staple) extension, but this endpoint did not staple an OCSP response, so browsers that enforce Must-Staple refuse the connection.'
            :`The offered leaf certificate carries the TLS Feature (Must-Staple) extension, and this endpoint stapled an OCSP response that is ${ocsp.state==='invalid'?'invalid':'of unknown status'}, so browsers that enforce Must-Staple refuse the connection.`,
          severity:'high',
          recommendation:'Enable OCSP stapling on this endpoint, or reissue the certificate without Must-Staple, then retest.',
          value:ocsp.state==='absent'?'Must-Staple required; no stapled OCSP response':`Must-Staple required; stapled OCSP response ${ocsp.state}`}));
    }
    if(row.control==='compression'&&positive(row)&&row.evidence.extensions?.compression===true)
      add(make('tls_compression_enabled',endpoint,row,{title:'TLS compression accepted',
        description:'The measured TLS connection negotiated compression on this endpoint.',severity:'medium',
        recommendation:'Disable TLS-level compression on the affected service and repeat this control.',value:'compression negotiated'}));
  }
  return [...output.values()];
}

// The CASE identity of a TLS condition: the endpoint, the control and the
// protocol/cipher, WITHOUT the engine build or profile versions (Executive,
// 23 Oct 2026). A new probe build measures the same weakness on the same
// endpoint; it must reach the same case, not orphan it and open a duplicate.
// The build stays on the finding, the occurrence and the verification evidence.
export function tlsCaseKey(condition) {
  const c=condition||{};
  if(!/^tls_[a-z_]+$/.test(String(c.type||''))||!c.endpoint_identity||!c.control)return null;
  // A _confirmed type's detail is the VERSIONED probe profile (heartbleed-minimal-v1,
  // robot-finite-v1, ccs-early-record-v1): a profile bump must not change the case,
  // so it is left out — type + control + endpoint already name the condition. The
  // weak-cipher detail is the cipher id, which IS the condition, and stays.
  const detail=c.type.endsWith('_confirmed')?'':(c.detail||'');
  return `tlscase:${c.type}:${sha256Text(['tls-case-v1',c.type,c.endpoint_identity,c.control,c.protocol||'',c.cipher_id||'',detail].join('\n'))}`;
}

// Re-test a case on THIS assessment, whatever engine build produced it: find
// the current measurement(s) of the same build-less condition and evaluate each
// exactly. 'clear' only when every match clears; any 'present' wins; nothing
// measured is deferred.
export function evaluateTlsCase(caseKey,assessment) {
  if(!/^tlscase:tls_[a-z_]+:[a-f0-9]{64}$/.test(String(caseKey||''))||assessment?.source!=='tls_assessment')return {state:'deferred',reason:'tls_not_recorded',condition_ids:[]};
  const type=String(caseKey).split(':')[1];
  const ids=new Set(),builds=new Set();
  for(const endpoint of assessment.endpoints||[])for(const row of endpoint.checks||[]){
    if(!row.engine?.sandboxed||!row.observed_at)continue;
    const detail=type==='tls_weak_cipher'?row.cipher_id||'':type.endsWith('_confirmed')?row.evidence?.vulnerability?.profile||'':'';
    if(tlsCaseKey({type,endpoint_identity:endpoint.endpoint_identity,control:row.control,protocol:row.protocol,cipher_id:row.cipher_id||null,detail})!==caseKey)continue;
    const id=conditionKey(type,endpoint,row,detail);
    if(id){ids.add(id);builds.add(row.engine.build_id);}
  }
  if(!ids.size)return {state:'deferred',reason:'tls_condition_not_measured',condition_ids:[],engine_build_ids:[]};
  const measured={condition_ids:[...ids],engine_build_ids:[...builds]};
  const results=[...ids].map(id=>({id,...evaluateTlsCondition(id,assessment)}));
  const present=results.find(r=>r.state==='present');
  if(present)return {state:'present',reason:present.reason,...measured};
  if(results.every(r=>r.state==='clear'))return {state:'clear',reason:results[0].reason,...measured};
  return {state:'deferred',reason:results.find(r=>r.state!=='clear')?.reason||'tls_retest_inconclusive',...measured};
}

// PQC readiness per endpoint for the Certificates & Trust card (S3-MODERN 2):
// what the server chose when offered the hybrid X25519MLKEM768 group beside
// classical groups. A readiness signal, not a weakness: no finding, no score.
// Wording on the card is "Post-quantum key exchange: negotiated <group> / not
// offered by the server / not assessed" - never "quantum safe/ready".
export function pqcKeyExchangeState(assessment) {
  const out=[];
  for(const endpoint of assessment?.endpoints||[]){
    const rows=(endpoint.checks||[]).filter(r=>r.control==='pqc_key_exchange'&&r.engine?.sandboxed);
    const row=rows.find(positive);
    const group=row?.evidence?.negotiated?.group||null;
    const state=!row||!group?'not_assessed'
      :/MLKEM|KYBER/i.test(group)?'hybrid_pqc_negotiated':'classical_only';
    if(rows.length||row)out.push({endpoint_identity:endpoint.endpoint_identity||null,hostname:endpoint.endpoint?.hostname||null,state,
      group:state==='not_assessed'?null:group});
  }
  return out;
}
// Must-Staple state per endpoint for the Certificates & Trust card (S3-MODERN 1),
// from the latest positive certificate observation: required_stapled /
// required_not_stapled / not_required / not_assessed. Backend-owned; the card
// never derives it.
export function mustStapleState(assessment) {
  const out=[];
  for(const endpoint of assessment?.endpoints||[]){
    const row=(endpoint.checks||[]).find(r=>r.control==='certificate'&&r.engine?.sandboxed&&positive(r));
    const leaf=row?.evidence?.certificates?.offered_chain?.[0],ocsp=row?.evidence?.ocsp;
    const state=!leaf||typeof leaf.must_staple!=='boolean'?'not_assessed'
      :leaf.must_staple===false?'not_required'
      :!ocsp?'not_assessed'
      :ocsp.state==='absent'?'required_not_stapled'
      :ocsp.state==='good'?'required_stapled'
      :'required_staple_invalid';
    out.push({endpoint_identity:endpoint.endpoint_identity||null,hostname:endpoint.endpoint?.hostname||null,state});
  }
  return out;
}
export function evaluateTlsCondition(id,assessment) {
  if(!/^tls_[a-z_]+__[a-f0-9]{64}$/.test(String(id||''))||assessment?.source!=='tls_assessment')return {state:'deferred',reason:'tls_not_recorded'};
  for(const endpoint of assessment.endpoints||[]){
    const reachable=endpointReachable(endpoint);
    for(const row of endpoint.checks||[]){
      if(!row.engine?.sandboxed||!row.observed_at)continue;
      const types=['tls_legacy_protocol','tls_weak_cipher','tls_weak_key_exchange','tls_no_forward_secrecy','tls_heartbleed_confirmed','tls_robot_confirmed','tls_ccs_confirmed',
        'tls_certificate_hostname','tls_certificate_trust','tls_weak_certificate_key','tls_weak_certificate_signature','tls_ocsp_revoked','tls_compression_enabled',
        'tls_must_staple_not_stapled'];
      for(const type of types){
        const detail=type==='tls_weak_cipher'?row.cipher_id||'':
          type.startsWith('tls_')&&type.endsWith('_confirmed')?row.evidence?.vulnerability?.profile||'':
          '';
        if(conditionKey(type,endpoint,row,detail)!==id)continue;
        if(!reachable)return {state:'deferred',reason:'endpoint_not_reachable'};
        // A weak cipher no longer negotiates (23 Oct 2026). The engine offers ONLY
        // this cipher; it reports no explicit cipher refusal, so the exact negative
        // is: the server answered that offer with a TLS alert (bytes came back, not a
        // timeout or EOF), while the SAME endpoint still completes a handshake on the
        // SAME protocol version in this assessment. Anything less stays deferred.
        if(type==='tls_weak_cipher'){
          if(positive(row)&&row.evidence?.negotiated?.cipher===row.cipher_id)return {state:'present',reason:'tls_condition_still_observed'};
          const alerted=row.state==='uncertain'&&row.reason==='peer_alert'&&row.physical_telemetry?.connections>0&&row.physical_telemetry?.bytes_received>0;
          const protocolServed=(endpoint.checks||[]).some(o=>o.control==='protocol'&&o.protocol===row.protocol&&positive(o)&&o.evidence?.negotiated?.version===row.protocol);
          return alerted&&protocolServed?{state:'clear',reason:'cipher_refused_on_exact_retest'}:{state:'deferred',reason:'cipher_retest_inconclusive'};
        }
        if(row.state==='uncertain'||row.state==='unexecutable'||row.state==='not_authorized'||row.state==='not_applicable')return {state:'deferred',reason:'exact_tls_check_inconclusive'};
        if(type==='tls_legacy_protocol')
          return row.control==='protocol'&&row.state==='rejected'&&row.reason==='protocol_version_rejected'
            ? {state:'clear',reason:'exact_tls_condition_retested'}
            : positive(row)?{state:'present',reason:'tls_condition_still_observed'}:{state:'deferred',reason:'protocol_retest_inconclusive'};
        if(type==='tls_weak_key_exchange')return positive(row) && row.evidence?.negotiated?.group &&
          Number.isInteger(row.evidence.negotiated.group_bits) && !weakKeyExchange(row.evidence.negotiated)
          ? {state:'clear',reason:'key_exchange_retested'} : {state:'deferred',reason:'key_exchange_retest_inconclusive'};
        if(type==='tls_no_forward_secrecy')return positive(row) && row.evidence?.negotiated?.pfs===true
          ? {state:'clear',reason:'forward_secrecy_retested'} : {state:'deferred',reason:'forward_secrecy_retest_inconclusive'};
        if(type==='tls_compression_enabled')return positive(row) && row.evidence?.extensions?.compression===false
          ? {state:'clear',reason:'compression_retested'} : {state:'deferred',reason:'compression_retest_inconclusive'};
        if(type.endsWith('_confirmed')){
          const v=row.evidence?.vulnerability;
          if(v?.completed_vectors!==v?.planned_vectors)return {state:'deferred',reason:'active_retest_inconclusive'};
          if(v.status==='confirmed'&&row.state==='accepted')return {state:'present',reason:'tls_condition_still_observed'};
          if(v.status==='not_observed'&&row.state==='rejected')return {state:'clear',reason:'exact_active_profile_retested'};
          return {state:'deferred',reason:'active_retest_inconclusive'};
        }
        if(['tls_certificate_hostname','tls_certificate_trust','tls_ocsp_revoked','tls_weak_certificate_key','tls_weak_certificate_signature','tls_must_staple_not_stapled'].includes(type)
          && !positive(row))return {state:'deferred',reason:'certificate_retest_inconclusive'};
        if(type==='tls_certificate_hostname')return row.evidence?.certificates?.hostname===true?{state:'clear',reason:'hostname_retested'}:{state:'deferred',reason:'hostname_retest_inconclusive'};
        if(type==='tls_certificate_trust')return row.evidence?.certificates?.trust==='valid'?{state:'clear',reason:'trust_retested'}:{state:'deferred',reason:'trust_retest_inconclusive'};
        if(type==='tls_ocsp_revoked')return row.evidence?.ocsp?.state==='good'&&row.evidence.ocsp.signature_valid&&row.evidence.ocsp.cert_id_match&&row.evidence.ocsp.fresh
          ?{state:'clear',reason:'stapled_ocsp_retested'}:{state:'deferred',reason:'ocsp_retest_inconclusive'};
        const leaf=row.evidence?.certificates?.offered_chain?.[0];
        if(!leaf)return {state:'deferred',reason:'certificate_not_observed'};
        if(type==='tls_must_staple_not_stapled'){
          const ocsp=row.evidence?.ocsp;
          if(leaf.must_staple===true&&['absent','invalid','unknown'].includes(ocsp?.state))return {state:'present',reason:'must_staple_still_unstapled'};
          // Only a good staple (or the extension gone) clears; never an invalid one.
          if(leaf.must_staple===false||(leaf.must_staple===true&&ocsp?.state==='good'))return {state:'clear',reason:'must_staple_retested'};
          return {state:'deferred',reason:'must_staple_retest_inconclusive'};
        }
        if(type==='tls_weak_certificate_key'){
          const weak=((leaf.key_type==='RSA'||leaf.key_type==='DSA')&&leaf.key_bits>0&&leaf.key_bits<2048)||
            (leaf.key_type==='EC'&&leaf.key_bits>0&&leaf.key_bits<224);
          return weak?{state:'present',reason:'weak_key_still_observed'}
            : strongCertificateKey(leaf)?{state:'clear',reason:'certificate_key_retested'}
            : {state:'deferred',reason:'certificate_key_unknown'};
        }
        if(type==='tls_weak_certificate_signature')return ['rsa_md5','rsa_sha1','ecdsa_sha1','dsa_sha1'].includes(leaf.signature_algorithm)
          ?{state:'present',reason:'weak_signature_still_observed'}
          :strongCertificateSignature(leaf)?{state:'clear',reason:'certificate_signature_retested'}
          :{state:'deferred',reason:'certificate_signature_unknown'};
        return {state:'deferred',reason:'exact_tls_check_inconclusive'};
      }
    }
  }
  return {state:'deferred',reason:'exact_tls_check_not_run'};
}
