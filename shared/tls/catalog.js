// Every assessment result is scoped to the endpoint and the exact local engine
// catalogue. The catalogue is populated from the pinned compiled binaries;
// names offered by a server never become new instructions to the engine.
export const TLS_PROFILE_VERSION = 'cybermeters-tls-profile/2';
export const TLS_POLICY_VERSION = 'rfc9325-2022/1';
export const TLS_SPECIAL_CONSENT_VERSION = 'tls-special-2026-10-13';
export const TLS_TRUST_BUNDLE = Object.freeze({name:'curl Mozilla CA Extract',version:'2026-09-25',
  sha256:'a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505'});

export const TLS_PROTOCOLS = Object.freeze(['ssl2','ssl3','tls1','tls1_1','tls1_2','tls1_3']);
export const TLS_STATES = Object.freeze(['accepted','rejected','uncertain','not_applicable','not_authorized','unexecutable']);
export const TLS_APPLICATIONS = Object.freeze({
  https:Object.freeze([443,8443]),
  smtp:Object.freeze([25,587]),
  smtps:Object.freeze([465]),
  imap:Object.freeze([143]),
  imaps:Object.freeze([993]),
  pop3:Object.freeze([110]),
  pop3s:Object.freeze([995]),
});
export const TLS_SPECIAL_CONTROLS = Object.freeze(['heartbleed','robot','ccs']);
// Containment (21 Oct 2026): OFF. The only consent model is workspace-wide and
// does not exclude shared provider infrastructure, so Heartbleed/ROBOT/CCS were
// sent to a CDN's shared edge (a cybermeters.com scan at 17:35 UTC probed
// 104.21.84.8). The founder's design requires per-domain consent AND customer-
// owned addresses only (S3-CONSENT). With this off the planner records these
// controls as unexecutable, the probe contract refuses them and the consent
// route will not enable them. Re-enable only with the per-domain, owned-address
// gate in place.
// Founder decision (23 Oct 2026): available at launch. The per-domain grant
// AND the customer-owned-address gate (isAuthorised -> evaluateTargetScope;
// provider/CDN edges are 'provider_infrastructure' and refused) now hold, which
// was the condition for lifting the 21 Oct containment above.
export const TLS_SPECIAL_CONTROLS_AVAILABLE = true;
export const TLS_CONTROLS = Object.freeze([
  'protocol','cipher','key_exchange','certificate','ocsp','compression',
  'secure_renegotiation','fallback_scsv','extended_master_secret',
  'session_resumption','early_data','sni_alpn',
  // PQC readiness (S3-MODERN 2): one TLS 1.3 handshake offering the hybrid
  // X25519MLKEM768 group beside classical groups; records what was chosen.
  'pqc_key_exchange',...TLS_SPECIAL_CONTROLS,
]);
// S3-B (22 Oct 2026): the two classes of TLS control. SAFE-ACTIVE controls are
// ordinary handshakes a client would make (protocol, cipher, forward secrecy,
// fallback, compression, renegotiation, ...) and run in normal scans under the
// owned-endpoint rules. INTRUSIVE controls send deliberately malformed or
// out-of-sequence messages and run only with an Active Checks grant for that
// exact address (engines/active-check-consent.js) once the engine is released.
export const TLS_INTRUSIVE_CONTROLS = TLS_SPECIAL_CONTROLS;
export const TLS_SAFE_ACTIVE_CONTROLS = Object.freeze(TLS_CONTROLS.filter(control => !TLS_SPECIAL_CONTROLS.includes(control)));
// The reason an intrusive control was not run because the customer has not
// authorised it: stated, never a gap in CyberMeters' own assessment.
export const TLS_AUTHORISATION_REQUIRED_REASON = 'requires_customer_authorisation';
// The customer authorised an intrusive control, but the engine is not released.
export const TLS_AUTHORISED_NOT_RELEASED_REASON = 'authorised_engine_not_released';
// Authorised, but this scan was not started by a person, or its origin is not
// known: the signed consent is "on demand", so only a scan whose trigger is
// exactly 'manual' runs an intrusive control (F1; C-52 N02).
export const TLS_AUTHORISED_ON_DEMAND_REASON = 'scheduled_or_unknown_origin';
// Authorised for the host, but this address is shared provider infrastructure
// (a CDN or hosting edge): never tested, whatever the grant says (F1).
export const TLS_PROVIDER_EDGE_REASON = 'provider_infrastructure_not_tested';
// Authorised for the host, but this address is not observed in the DNS of a
// verified domain: never tested (F1).
export const TLS_ADDRESS_NOT_OWNED_REASON = 'address_not_verified_not_tested';
export const TLS_SLICE_LIMITS = Object.freeze({
  checks:8, connections:16, bytes:1048576, overreadBytes:65536,
  durationMs:25000, requestBytes:16384, responseBytes:524288,
  engineBytes:262144, engineResultBytes:262144,
});
// Special checks always occupy their own slice. The ROBOT profile needs a
// verified baseline plus two rounds of five vectors in two message flows.
export const TLS_SPECIAL_CONNECTION_LIMITS = Object.freeze({heartbleed:1,robot:21,ccs:5});

const tls13Only = new Set(['early_data','pqc_key_exchange']);
const legacyOnly = new Set(['compression','secure_renegotiation','fallback_scsv','extended_master_secret']);
export function applicableTlsControl(control, protocol) {
  if(!TLS_CONTROLS.includes(control)||!TLS_PROTOCOLS.includes(protocol))return false;
  if(tls13Only.has(control))return protocol==='tls1_3';
  if(legacyOnly.has(control))return !['ssl2','tls1_3'].includes(protocol);
  if(control==='heartbleed'||control==='ccs')return ['tls1','tls1_1','tls1_2'].includes(protocol);
  if(control==='robot')return ['ssl3','tls1','tls1_1','tls1_2'].includes(protocol);
  if(control==='ocsp')return protocol!=='ssl2';
  return true;
}

export function isTlsService(port, application) {
  return Number.isInteger(port)&&TLS_APPLICATIONS[application]?.includes(port)===true;
}

export function tlsEndpointIdentity({hostname,sni,address,port,transport,application_protocol}) {
  // Every address has its own verdict. A CDN edge cannot stand for another IP.
  return [hostname,sni,address,port,transport,application_protocol].join('|');
}

export function isWeakTlsCipher(name) {
  // A selected cipher is classified only after an authenticated handshake.
  // Names are looked up in the compiled catalogue, never parsed from banners.
  return /(?:^|[_-])(NULL|ANON|ADH|AECDH|EXPORT|EXP(?:40|56)?|RC4|DES(?:40)?)(?:[_-]|$)/i.test(name)
    || /(?:^|[_-])3DES(?:[_-]|$)/i.test(name);
}

export function tlsEngineControl(control) {
  if (['protocol','cipher','key_exchange','extended_master_secret','sni_alpn','pqc_key_exchange'].includes(control)) return 'handshake';
  if (['certificate','ocsp'].includes(control)) return 'certificate';
  if (control === 'secure_renegotiation') return 'renegotiation';
  if (control === 'fallback_scsv') return 'fallback';
  if (['session_resumption','early_data'].includes(control)) return 'resumption';
  return control;
}

export function tlsProtocolRisk(protocol) {
  if(['ssl2','ssl3','tls1','tls1_1'].includes(protocol))return 'high';
  return null;
}
