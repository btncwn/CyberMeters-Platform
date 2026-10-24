import { isProbeHostname, isPublicProbeAddress } from './contract.js';
import { TLS_CONTROLS, TLS_PROTOCOLS, TLS_SLICE_LIMITS, TLS_SPECIAL_CONNECTION_LIMITS, tlsSliceDurationMs, TLS_SPECIAL_CONTROLS, TLS_SPECIAL_CONTROLS_AVAILABLE, TLS_SPECIAL_CONSENT_VERSION, TLS_TRUST_BUNDLE, applicableTlsControl, isTlsService, tlsEndpointIdentity, tlsEngineControl } from '../../../shared/tls/catalog.js';

const id = value => typeof value === 'string' && /^[A-Za-z0-9_-]{1,100}$/.test(value);
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(key => keys.includes(key));
const isoTime = value => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value) && Number.isFinite(Date.parse(value));

// Only the authenticated scan queue may create this private-service request.
// The collector separately re-resolves DNS and connects by this single pinned
// public address; the C engine receives no address or socket capability.
export function validateTlsAssessmentRequest(input, now = Date.now()) {
  const fail = reason => ({ ok: false, reason });
  if (!exact(input, ['schema_version','request_id','workspace_id','scan_id','domain_id','domain','endpoint','scope','checks','deadline_at','max_connections','max_bytes'])) return fail('invalid_request');
  if (input.schema_version !== 'tls-assessment-request-v1') return fail('unknown_schema');
  for (const key of ['request_id','workspace_id','scan_id','domain_id']) if (!id(input[key])) return fail('invalid_identity');
  const mailMx = input.scope?.kind === 'mail_mx';
  if (!isProbeHostname(input.domain) || !isProbeHostname(input.endpoint?.hostname) ||
      (!mailMx && !(input.endpoint.hostname === input.domain || input.endpoint.hostname.endsWith('.' + input.domain)))) return fail('invalid_domain');
  const e = input.endpoint;
  if (!exact(e, ['hostname','sni','address','port','transport','application_protocol','dns_addresses','dns_observed_at']) ||
      e.transport !== 'tcp' || e.sni !== e.hostname || !isPublicProbeAddress(e.address) ||
      !isTlsService(e.port, e.application_protocol) || !isoTime(e.dns_observed_at) ||
      Math.abs(now - Date.parse(e.dns_observed_at)) > 60_000 || !Array.isArray(e.dns_addresses) ||
      e.dns_addresses.length < 1 || e.dns_addresses.length > 16 ||
      new Set(e.dns_addresses).size !== e.dns_addresses.length ||
      e.dns_addresses.some(address => !isPublicProbeAddress(address)) ||
      !e.dns_addresses.includes(e.address)) return fail('invalid_endpoint');
  if (!exact(input.scope, ['kind','service_authorization_id','generation','special_consent','consent_version']) ||
      !['standard_https','authorized_service','mail_mx'].includes(input.scope.kind) ||
      !Number.isSafeInteger(input.scope.generation) || input.scope.generation < 0 ||
      typeof input.scope.special_consent !== 'boolean' ||
      (input.scope.special_consent ? input.scope.consent_version !== TLS_SPECIAL_CONSENT_VERSION : input.scope.consent_version !== null) ||
      (input.scope.kind === 'standard_https'
        ? (e.application_protocol !== 'https' || e.port !== 443 || input.scope.service_authorization_id !== null)
        : mailMx ? (e.application_protocol !== 'smtp' || e.port !== 25 || input.scope.service_authorization_id !== null ||
          input.scope.special_consent || input.scope.generation !== 0)
        : !id(input.scope.service_authorization_id))) return fail('invalid_scope');
  if (!isoTime(input.deadline_at) || Date.parse(input.deadline_at) <= now ||
      Date.parse(input.deadline_at) > now + tlsSliceDurationMs(input.checks)) return fail('invalid_deadline');
  const specialControl=input.checks?.length===1?input.checks[0]?.control:null;
  const connectionLimit=TLS_SPECIAL_CONNECTION_LIMITS[specialControl]||TLS_SLICE_LIMITS.connections;
  if (!Number.isSafeInteger(input.max_connections) || input.max_connections < 1 || input.max_connections > connectionLimit ||
      !Number.isSafeInteger(input.max_bytes) || input.max_bytes < 4096 || input.max_bytes > TLS_SLICE_LIMITS.bytes) return fail('invalid_budget');
  if (!Array.isArray(input.checks) || input.checks.length < 1 || input.checks.length > TLS_SLICE_LIMITS.checks) return fail('invalid_checks');
  if (mailMx && (input.checks.length !== 1 || input.checks[0]?.control !== 'certificate' ||
      input.checks[0]?.protocol !== 'tls1_2' || input.checks[0]?.cipher_id !== null ||
      input.max_connections !== 1 || Date.parse(input.deadline_at) > now + 10_000)) return fail('invalid_mail_mx');
  const seen = new Set();
  for (const check of input.checks) {
    if (!exact(check, ['control','protocol','cipher_id']) || !TLS_CONTROLS.includes(check.control) || !TLS_PROTOCOLS.includes(check.protocol) ||
        (check.cipher_id !== null && (check.control !== 'cipher' || typeof check.cipher_id !== 'string' || !/^[A-Za-z0-9_-]{1,96}$/.test(check.cipher_id))) ||
        (check.control === 'cipher' && check.cipher_id === null)) return fail('invalid_check');
    // Inapplicable controls are represented as explicit not_applicable rows in
    // the job plan. They never cause network traffic.
    if (!applicableTlsControl(check.control, check.protocol)) return fail('inapplicable_check');
    const key = [check.control, check.protocol, check.cipher_id].join('|');
    if (seen.has(key)) return fail('duplicate_check');
    seen.add(key);
  }
  if (input.checks.some(check => TLS_SPECIAL_CONTROLS.includes(check.control)) && !input.scope.special_consent) return fail('special_consent_required');
  if (input.checks.some(check => TLS_SPECIAL_CONTROLS.includes(check.control)) && input.checks.length !== 1) return fail('special_slice_required');
  if (input.checks.some(check => TLS_SPECIAL_CONTROLS.includes(check.control)) && !TLS_SPECIAL_CONTROLS_AVAILABLE) return fail('control_unavailable');
  return { ok: true, endpoint_identity: tlsEndpointIdentity(e) };
}

export function tlsAssessmentLimitations(input) {
  return [
    'tcp_tls_only_quic_not_assessed',
    'observed_endpoint_not_origin_inference',
    'no_external_revocation_fetch',
    'mozilla_name_constraints_not_preserved',
    ...(input.endpoint.application_protocol !== 'https' ? ['authorized_service_only'] : []),
  ];
}

const enums = Object.freeze({
  state: ['accepted','rejected','uncertain','not_applicable','unexecutable'],
  reason: ['catalog_ready','handshake_completed','peer_alert','protocol_version_rejected','fallback_rejected','transport_eof','transport_timeout','budget_exhausted','aborted','malformed_ipc','handshake_failed','certificate_limit','engine_error','cipher_unavailable','protocol_unavailable','requires_credentials','control_unavailable','group_unavailable','renegotiation_completed','renegotiation_refused','resumption_completed','resumption_declined','ticket_not_received','heartbeat_unavailable','active_confirmed','active_not_observed','active_inconclusive','protocol_not_applicable'],
  trust: ['valid','invalid','unknown'],
  trust_reason: ['trusted','issuer_missing','self_signed','expired','not_yet_valid','signature_invalid','invalid_purpose','unsupported_algorithm','trust_unknown','chain_limit'],
  ocsp: ['absent','good','revoked','unknown','invalid'],
  key: ['RSA','EC','DSA','DH','ED25519','ED448','UNKNOWN'],
  signature: ['rsa_md5','rsa_sha1','rsa_sha256','rsa_sha384','rsa_sha512','rsa_pss','ecdsa_sha1','ecdsa_sha256','ecdsa_sha384','ecdsa_sha512','dsa_sha1','dsa_sha256','ed25519','ed448','unknown'],
  limitation: ['os_sandbox_unavailable','ssl2_export_unavailable','ssl2_single_des_unavailable','ssl2_single_certificate','compression_not_offered','no_trust_snapshot','no_stapled_ocsp','bounded_vector_profile','certificate_chain_limit','ticket_wait_limit','credential_suites_unexecutable','engine_capability_limit'],
});
const choice = (value, list) => list.includes(value);
const integer = (value, max, min = 0) => Number.isSafeInteger(value) && value >= min && value <= max;
const optional = (value, test) => value === null || test(value);
const hash = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const token = (value, max = 96) => typeof value === 'string' && value.length <= max && /^[A-Za-z0-9_-]+$/.test(value);
const keys = (value, expected) => exact(value, expected) && Object.keys(value).length === expected.length;
// must_staple (RFC 7633 TLS Feature) is optional so an older engine image still validates.
const certificate = value => (keys(value, ['sha256','spki_sha256','not_before','not_after','key_type','key_bits','signature_algorithm','self_signed','ca'])
  || (keys(value, ['sha256','spki_sha256','not_before','not_after','key_type','key_bits','signature_algorithm','self_signed','ca','must_staple'])
    && [true,false,null].includes(value.must_staple))) &&
  hash(value.sha256) && hash(value.spki_sha256) && optional(value.not_before, x => integer(x,253402300799,-62167219200)) &&
  optional(value.not_after, x => integer(x,253402300799,-62167219200)) && choice(value.key_type,enums.key) &&
  integer(value.key_bits,16384) && choice(value.signature_algorithm,enums.signature) &&
  typeof value.self_signed === 'boolean' && typeof value.ca === 'boolean';

// Validate the C engine's *entire* bounded output before a single field can
// cross the private-service boundary. No arbitrary X.509 subject, URI, raw
// certificate, alert text, banner or memory fragment is persisted.
export function validateTlsEngineResult(value, check, { requireSandbox = true } = {}) {
  const fail = reason => ({ ok: false, reason });
  if (!keys(value,['schema','engine','control','protocol','state','reason','authenticated_finished','vulnerability','negotiated','certificates','ocsp','extensions','telemetry','limitations','catalog']) ||
      value.schema !== 'tls-engine-result-v1' || value.control !== tlsEngineControl(check.control) ||
      value.protocol !== check.protocol || !choice(value.state,enums.state) || !choice(value.reason,enums.reason) ||
      typeof value.authenticated_finished !== 'boolean') return fail('engine_shape');
  const e = value.engine;
  if (!keys(e,['family','version','build_id','sandboxed']) || !choice(e.family,['legacy','modern','active_legacy']) ||
      !choice(e.version,['1.0.2u','3.5.9']) || !hash(e.build_id) || typeof e.sandboxed !== 'boolean' ||
      (requireSandbox && !e.sandboxed) || (e.family === 'modern' ? e.version !== '3.5.9' : e.version !== '1.0.2u')) return fail('engine_identity');
  if (TLS_SPECIAL_CONTROLS.includes(check.control) !== (e.family === 'active_legacy')) return fail('engine_family');
  if (check.control === 'cipher' && e.family !== (check.protocol === 'tls1_3' ? 'modern' : 'legacy')) return fail('cipher_engine');
  if (value.state === 'accepted' && !value.authenticated_finished && !TLS_SPECIAL_CONTROLS.includes(check.control)) return fail('unproved_acceptance');
  if (value.state === 'rejected' && !['protocol_version_rejected','fallback_rejected','renegotiation_refused','resumption_declined','active_not_observed'].includes(value.reason)) return fail('unproved_rejection');
  const v = value.vulnerability;
  if (v !== null && (!keys(v,['status','profile','completed_vectors','planned_vectors']) ||
      !choice(v.status,['confirmed','not_observed','unknown']) || !choice(v.profile,['heartbleed-minimal-v1','robot-finite-v1','ccs-early-record-v1']) ||
      !integer(v.completed_vectors,64) || !integer(v.planned_vectors,64,1) || v.completed_vectors > v.planned_vectors ||
      !TLS_SPECIAL_CONTROLS.includes(check.control))) return fail('vulnerability_shape');
  if (TLS_SPECIAL_CONTROLS.includes(check.control) && v === null && !['not_applicable','unexecutable'].includes(value.state)) return fail('vulnerability_missing');
  if (v && (v.profile !== ({heartbleed:'heartbleed-minimal-v1',robot:'robot-finite-v1',ccs:'ccs-early-record-v1'})[check.control] ||
      (check.control === 'heartbleed' && v.planned_vectors !== 3) ||
      (check.control === 'ccs' && v.planned_vectors !== 4) ||
      (check.control === 'robot' && ![10,20].includes(v.planned_vectors)) ||
      (v.status === 'confirmed' && (value.state !== 'accepted' || value.reason !== 'active_confirmed')) ||
      (v.status === 'not_observed' && (value.state !== 'rejected' || value.reason !== 'active_not_observed')) ||
      (v.status === 'unknown' && (value.state !== 'uncertain' || !['active_inconclusive','aborted','budget_exhausted',
        'transport_timeout','transport_eof','malformed_ipc','peer_alert','handshake_failed'].includes(value.reason))) ||
      (v.status !== 'unknown' && (!value.authenticated_finished || v.completed_vectors !== v.planned_vectors)))) return fail('vulnerability_unproved');
  const n = value.negotiated;
  if (n !== null && (!keys(n,['version','cipher','cipher_bits','group','group_bits','pfs','alpn','sni_sent']) ||
      !choice(n.version,TLS_PROTOCOLS) || !token(n.cipher) || !integer(n.cipher_bits,512) ||
      !optional(n.group,x => token(x,64)) || !optional(n.group_bits,x => integer(x,16384)) ||
      !optional(n.pfs,x => typeof x === 'boolean') || !choice(n.alpn,[null,'h2','http/1.1']) || typeof n.sni_sent !== 'boolean')) return fail('negotiated_shape');
  if (value.authenticated_finished && n === null) return fail('negotiated_missing');
  if (check.control === 'cipher' && value.state === 'accepted' && n?.cipher !== check.cipher_id) return fail('cipher_identity');
  const c = value.certificates;
  if (c !== null && (!keys(c,['offered_chain','trusted_chain','trust','hostname','dates','reason','evaluation_at','trust_bundle_sha256']) ||
      !Array.isArray(c.offered_chain) || c.offered_chain.length > 8 || !c.offered_chain.every(certificate) ||
      !Array.isArray(c.trusted_chain) || c.trusted_chain.length > 8 || !c.trusted_chain.every(hash) ||
      !choice(c.trust,enums.trust) || !optional(c.hostname,x => typeof x === 'boolean') ||
      !optional(c.dates,x => typeof x === 'boolean') || !choice(c.reason,enums.trust_reason) ||
      !integer(c.evaluation_at,253402300799) || !optional(c.trust_bundle_sha256,hash))) return fail('certificate_shape');
  const o = value.ocsp;
  if (o !== null && (!keys(o,['state','signature_valid','cert_id_match','fresh','this_update','next_update']) || !choice(o.state,enums.ocsp) ||
      !['signature_valid','cert_id_match','fresh'].every(key => optional(o[key],x => typeof x === 'boolean')) ||
      !optional(o.this_update,x => integer(x,253402300799,-62167219200)) ||
      !optional(o.next_update,x => integer(x,253402300799,-62167219200)) ||
      (o.state === 'good' && !(o.signature_valid && o.cert_id_match && o.fresh)))) return fail('ocsp_shape');
  const x = value.extensions;
  if (x !== null && (!keys(x,['ems','compression','secure_renegotiation','fallback_scsv','session_reused','early_data_max','renegotiation_completed']) ||
      !['ems','compression','secure_renegotiation','fallback_scsv','session_reused','renegotiation_completed'].every(key => optional(x[key],v => typeof v === 'boolean')) ||
      !optional(x.early_data_max,v => integer(v,4294967295)))) return fail('extensions_shape');
  const t = value.telemetry;
  if (!keys(t,['connections','bytes_sent','bytes_received','duration_ms']) || !integer(t.connections,64) ||
      !integer(t.bytes_sent,16777216) || !integer(t.bytes_received,16777216) || !integer(t.duration_ms,30000)) return fail('telemetry_shape');
  if (v && v.status !== 'unknown' && (!t.connections || !t.bytes_sent || !t.bytes_received)) return fail('vulnerability_unproved');
  if (!Array.isArray(value.limitations) || value.limitations.length > 12 ||
      new Set(value.limitations).size !== value.limitations.length ||
      !value.limitations.every(x => choice(x,enums.limitation)) || value.catalog !== null) return fail('unsafe_output');
  return { ok: true };
}

function projectTlsResult(check, raw, { requireSandbox, mailMx }) {
  const observed = isoTime(raw?.observed_at);
  const pt = raw?.physical_telemetry;
  if (!keys(raw,['check','engine_result','reason','observed_at','physical_telemetry']) ||
      !observed || JSON.stringify(raw.check) !== JSON.stringify(check) ||
      !keys(pt,['connections','bytes_sent','bytes_received','duration_ms']) ||
      !integer(pt.connections,TLS_SPECIAL_CONNECTION_LIMITS[check.control]||TLS_SLICE_LIMITS.connections) ||
      !integer(pt.bytes_sent,TLS_SLICE_LIMITS.bytes + TLS_SLICE_LIMITS.overreadBytes) ||
      !integer(pt.bytes_received,TLS_SLICE_LIMITS.bytes + TLS_SLICE_LIMITS.overreadBytes) ||
      !integer(pt.duration_ms,tlsSliceDurationMs([check]) + 1000)) throw new Error('result_shape');
  if (raw.engine_result === null) {
    if (!choice(raw.reason,['budget_exhausted','deadline_exhausted','engine_unavailable','dns_authority_changed',
      ...(mailMx ? ['starttls_unavailable','starttls_rejected','starttls_greeting'] : [])])) throw new Error('unrun_reason');
    return { ...check, state: raw.reason === 'starttls_unavailable' ? 'rejected' : raw.reason === 'engine_unavailable' ? 'unexecutable' : 'uncertain', reason: raw.reason,
      observed_at: raw.observed_at, engine: null, evidence: null, physical_telemetry: pt };
  }
  if (raw.reason !== null) throw new Error('unexpected_reason');
  const engine = raw.engine_result;
  const checked = validateTlsEngineResult(engine,check,{requireSandbox});
  if (!checked.ok) throw new Error(checked.reason);
  if (requireSandbox && engine.certificates &&
      engine.certificates.trust_bundle_sha256 !== TLS_TRUST_BUNDLE.sha256)
    throw new Error('trust_snapshot_mismatch');
  if (engine.telemetry.connections > pt.connections || engine.telemetry.bytes_sent > pt.bytes_sent ||
      engine.telemetry.bytes_received > pt.bytes_received) throw new Error('engine_cost_conflict');
  if (['accepted','rejected'].includes(engine.state) &&
      (pt.connections < 1 || engine.telemetry.connections < 1 || pt.bytes_sent < 1 || pt.bytes_received < 1))
    throw new Error('unproved_network_verdict');
  return { ...check, state: engine.state, reason: engine.reason, observed_at: raw.observed_at,
    engine: engine.engine,
    evidence: { authenticated_finished: engine.authenticated_finished, negotiated: engine.negotiated,
      certificates: engine.certificates, ocsp: engine.ocsp, extensions: engine.extensions,
      vulnerability: engine.vulnerability, limitations: engine.limitations },
    physical_telemetry: pt };
}

// This is the only path by which a C result becomes a customer-facing receipt.
// It does not preserve the raw JSON when validation fails.
export function projectTlsCollectorReceipt(request, raw, { now = Date.now(), requireSandbox = true } = {}) {
  if (!keys(raw,['schema_version','request_id','started_at','finished_at','results','telemetry']) ||
      raw.schema_version !== 'tls-collector-raw-v1' || raw.request_id !== request.request_id ||
      !isoTime(raw.started_at) || !isoTime(raw.finished_at) ||
      Date.parse(raw.started_at) > Date.parse(raw.finished_at) ||
      Date.parse(raw.started_at) < Date.parse(request.deadline_at) - tlsSliceDurationMs(request.checks) - 1000 ||
      Date.parse(raw.finished_at) > Date.parse(request.deadline_at) + 1000 ||
      Date.parse(raw.finished_at) > now + 1000 || !Array.isArray(raw.results) || raw.results.length !== request.checks.length)
    throw new Error('collector_shape');
  const telemetry = raw.telemetry;
  if (!keys(telemetry,['connections','bytes_sent','bytes_received','duration_ms']) ||
      !integer(telemetry.connections,request.max_connections) ||
      !integer(telemetry.bytes_sent,request.max_bytes + TLS_SLICE_LIMITS.overreadBytes) ||
      !integer(telemetry.bytes_received,request.max_bytes + TLS_SLICE_LIMITS.overreadBytes) ||
      !integer(telemetry.duration_ms,tlsSliceDurationMs(request.checks) + 1000) ||
      Math.abs(telemetry.duration_ms - (Date.parse(raw.finished_at) - Date.parse(raw.started_at))) > 1000 ||
      telemetry.bytes_sent + telemetry.bytes_received > request.max_bytes + TLS_SLICE_LIMITS.overreadBytes)
    throw new Error('collector_cost');
  const results = raw.results.map((row,index) => projectTlsResult(request.checks[index],row,
    {requireSandbox,mailMx:request.scope.kind==='mail_mx'}));
  for (const key of ['connections','bytes_sent','bytes_received']) {
    if (results.reduce((sum,row) => sum + row.physical_telemetry[key],0) !== telemetry[key]) throw new Error('collector_cost_conflict');
  }
  const quality = results.every(row => ['accepted','rejected','not_applicable'].includes(row.state)) ? 'complete' : 'partial';
  return { schema_version: 'tls-assessment-receipt-v1', request_id: request.request_id,
    workspace_id: request.workspace_id, scan_id: request.scan_id, domain_id: request.domain_id,
    domain: request.domain, endpoint: request.endpoint, endpoint_identity: tlsEndpointIdentity(request.endpoint),
    scope: request.scope, started_at: raw.started_at, finished_at: raw.finished_at, quality, results,
    telemetry, limitations: tlsAssessmentLimitations(request) };
}

export function validateTlsAssessmentReceipt(request, receipt, options = {}) {
  try {
    if (!keys(receipt,['schema_version','request_id','workspace_id','scan_id','domain_id','domain','endpoint','endpoint_identity','scope','started_at','finished_at','quality','results','telemetry','limitations']) ||
        receipt.schema_version !== 'tls-assessment-receipt-v1' ||
        ['request_id','workspace_id','scan_id','domain_id','domain'].some(key => receipt[key] !== request[key]) ||
        JSON.stringify(receipt.endpoint) !== JSON.stringify(request.endpoint) ||
        JSON.stringify(receipt.scope) !== JSON.stringify(request.scope) ||
        receipt.endpoint_identity !== tlsEndpointIdentity(request.endpoint) ||
        JSON.stringify(receipt.limitations) !== JSON.stringify(tlsAssessmentLimitations(request))) return { ok:false, reason:'receipt_identity' };
    const synthetic = { schema_version:'tls-collector-raw-v1', request_id:receipt.request_id,started_at:receipt.started_at,
      finished_at:receipt.finished_at,results:receipt.results.map((row,index) => ({
        check:request.checks[index],reason:row.evidence === null ? row.reason : null,observed_at:row.observed_at,
        physical_telemetry:row.physical_telemetry,engine_result:row.evidence === null ? null : {
          schema:'tls-engine-result-v1',engine:row.engine,control:tlsEngineControl(row.control),protocol:row.protocol,
          state:row.state,reason:row.reason,authenticated_finished:row.evidence.authenticated_finished,
          vulnerability:row.evidence.vulnerability,negotiated:row.evidence.negotiated,
          certificates:row.evidence.certificates,ocsp:row.evidence.ocsp,extensions:row.evidence.extensions,
          telemetry:row.physical_telemetry,limitations:row.evidence.limitations,catalog:null,
        },
      })),telemetry:receipt.telemetry };
    const expected = projectTlsCollectorReceipt(request,synthetic,options);
    return JSON.stringify(receipt) === JSON.stringify(expected) ? {ok:true} : {ok:false,reason:'receipt_mismatch'};
  } catch { return {ok:false,reason:'invalid_receipt'}; }
}
