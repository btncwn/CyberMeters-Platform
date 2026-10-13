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
const make = (type,endpoint,row,{title,description,severity,recommendation,value,detail=''}) => {
  const id=conditionKey(type,endpoint,row,detail);
  if(!id)return null;
  return {id,module:'tls_assessment',finding_type:'finding',severity,confidence:95,score_impact:0,title,description,recommendation,
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
      add(make('tls_legacy_protocol',endpoint,row,{title:`${row.protocol.toUpperCase().replace('_','.') } accepted on this endpoint`,
        description:`The measured endpoint completed a ${row.protocol} TLS handshake. Certificate validity does not remove the risk of accepting this legacy protocol.`,
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
      add(make(`tls_${row.control}_confirmed`,endpoint,row,{title:`${row.control.toUpperCase()} behaviour confirmed`,
        description:`The bounded ${row.evidence.vulnerability.profile} profile confirmed the behaviour on this measured endpoint. No memory collection or decryption was performed.`,
        severity:'high',recommendation:'Update or reconfigure the affected TLS implementation for this service, then repeat the same bounded control.',
        value:`${row.evidence.vulnerability.completed_vectors}/${row.evidence.vulnerability.planned_vectors} bounded vectors`,
        detail:row.evidence.vulnerability.profile}));
    if(row.control==='certificate'&&positive(row)){
      const cert=row.evidence.certificates,leaf=cert?.offered_chain?.[0];
      if(cert?.hostname===false)add(make('tls_certificate_hostname',endpoint,row,{title:'Certificate does not cover this hostname',
        description:'The offered certificate did not match the SNI hostname tested on this endpoint.',severity:'high',
        recommendation:'Deploy a certificate covering this hostname on this exact service and retest the endpoint.',
        value:leaf?.sha256||'hostname mismatch'}));
      if(cert?.trust==='invalid')add(make('tls_certificate_trust',endpoint,row,{title:'Certificate chain did not validate',
        description:`The local trust snapshot rejected the offered certificate chain (${cert.reason}). Revocation status is separate.`,severity:'high',
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
          description:`The offered leaf certificate uses ${leaf.signature_algorithm}.`,severity:'medium',
          recommendation:'Replace the certificate with one signed using a current algorithm and verify the live chain.',
          value:leaf.signature_algorithm}));
      const ocsp=row.evidence.ocsp;
      if(ocsp?.state==='revoked'&&ocsp.signature_valid&&ocsp.cert_id_match&&ocsp.fresh)
        add(make('tls_ocsp_revoked',endpoint,row,{title:'Stapled OCSP response reports revocation',
          description:'A valid, fresh stapled response for the offered certificate reports revoked status.',severity:'high',
          recommendation:'Replace the revoked certificate and correct the stapled response on this endpoint, then retest.',
          value:'verified stapled OCSP: revoked'}));
    }
    if(row.control==='compression'&&positive(row)&&row.evidence.extensions?.compression===true)
      add(make('tls_compression_enabled',endpoint,row,{title:'TLS compression accepted',
        description:'The measured TLS connection negotiated compression on this endpoint.',severity:'medium',
        recommendation:'Disable TLS-level compression on the affected service and repeat this control.',value:'compression negotiated'}));
  }
  return [...output.values()];
}

export function evaluateTlsCondition(id,assessment) {
  if(!/^tls_[a-z_]+__[a-f0-9]{64}$/.test(String(id||''))||assessment?.source!=='tls_assessment')return {state:'deferred',reason:'tls_not_recorded'};
  for(const endpoint of assessment.endpoints||[]){
    const reachable=endpointReachable(endpoint);
    for(const row of endpoint.checks||[]){
      if(!row.engine?.sandboxed||!row.observed_at)continue;
      const types=['tls_legacy_protocol','tls_weak_cipher','tls_weak_key_exchange','tls_no_forward_secrecy','tls_heartbleed_confirmed','tls_robot_confirmed','tls_ccs_confirmed',
        'tls_certificate_hostname','tls_certificate_trust','tls_weak_certificate_key','tls_weak_certificate_signature','tls_ocsp_revoked','tls_compression_enabled'];
      for(const type of types){
        const detail=type==='tls_weak_cipher'?row.cipher_id||'':
          type.startsWith('tls_')&&type.endsWith('_confirmed')?row.evidence?.vulnerability?.profile||'':
          '';
        if(conditionKey(type,endpoint,row,detail)!==id)continue;
        if(!reachable)return {state:'deferred',reason:'endpoint_not_reachable'};
        if(row.state==='uncertain'||row.state==='unexecutable'||row.state==='not_authorized'||row.state==='not_applicable')return {state:'deferred',reason:'exact_tls_check_inconclusive'};
        if(type==='tls_legacy_protocol'||type==='tls_weak_cipher')
          return row.state==='rejected' ? {state:'clear',reason:'exact_tls_condition_retested'} : {state:'present',reason:'tls_condition_still_observed'};
        if(type==='tls_weak_key_exchange')return positive(row) && row.evidence?.negotiated?.group &&
          Number.isInteger(row.evidence.negotiated.group_bits) && !weakKeyExchange(row.evidence.negotiated)
          ? {state:'clear',reason:'key_exchange_retested'} : {state:'deferred',reason:'key_exchange_retest_inconclusive'};
        if(type==='tls_no_forward_secrecy')return positive(row) && row.evidence?.negotiated?.pfs===true
          ? {state:'clear',reason:'forward_secrecy_retested'} : {state:'deferred',reason:'forward_secrecy_retest_inconclusive'};
        if(type==='tls_compression_enabled')return positive(row) && row.evidence?.extensions?.compression===false
          ? {state:'clear',reason:'compression_retested'} : {state:'deferred',reason:'compression_retest_inconclusive'};
        if(type.endsWith('_confirmed')){
          const v=row.evidence?.vulnerability;
          return v?.status==='not_observed'&&v.completed_vectors===v.planned_vectors
            ? {state:'clear',reason:'exact_active_profile_retested'} : {state:'deferred',reason:'active_retest_inconclusive'};
        }
        if(type==='tls_certificate_hostname')return row.evidence?.certificates?.hostname===true?{state:'clear',reason:'hostname_retested'}:{state:'deferred',reason:'hostname_retest_inconclusive'};
        if(type==='tls_certificate_trust')return row.evidence?.certificates?.trust==='valid'?{state:'clear',reason:'trust_retested'}:{state:'deferred',reason:'trust_retest_inconclusive'};
        if(type==='tls_ocsp_revoked')return row.evidence?.ocsp?.state==='good'&&row.evidence.ocsp.signature_valid&&row.evidence.ocsp.cert_id_match&&row.evidence.ocsp.fresh
          ?{state:'clear',reason:'stapled_ocsp_retested'}:{state:'deferred',reason:'ocsp_retest_inconclusive'};
        const leaf=row.evidence?.certificates?.offered_chain?.[0];
        if(!leaf)return {state:'deferred',reason:'certificate_not_observed'};
        if(type==='tls_weak_certificate_key'){
          const weak=((leaf.key_type==='RSA'||leaf.key_type==='DSA')&&leaf.key_bits>0&&leaf.key_bits<2048)||
            (leaf.key_type==='EC'&&leaf.key_bits>0&&leaf.key_bits<224);
          return weak?{state:'present',reason:'weak_key_still_observed'}:{state:'clear',reason:'certificate_key_retested'};
        }
        if(type==='tls_weak_certificate_signature')return ['rsa_md5','rsa_sha1','ecdsa_sha1','dsa_sha1'].includes(leaf.signature_algorithm)
          ?{state:'present',reason:'weak_signature_still_observed'}:{state:'clear',reason:'certificate_signature_retested'};
        return {state:'deferred',reason:'exact_tls_check_inconclusive'};
      }
    }
  }
  return {state:'deferred',reason:'exact_tls_check_not_run'};
}
