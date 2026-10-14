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
// Keep special checks visible in coverage until all three implementations and
// their independent acceptance pass; customer scans spend no slice on them.
export const TLS_SPECIAL_CONTROLS_AVAILABLE = false;
export const TLS_CONTROLS = Object.freeze([
  'protocol','cipher','key_exchange','certificate','ocsp','compression',
  'secure_renegotiation','fallback_scsv','extended_master_secret',
  'session_resumption','early_data','sni_alpn',...TLS_SPECIAL_CONTROLS,
]);
export const TLS_SLICE_LIMITS = Object.freeze({
  checks:8, connections:16, bytes:1048576, overreadBytes:65536,
  durationMs:25000, requestBytes:16384, responseBytes:524288,
  engineBytes:262144, engineResultBytes:262144,
});

const tls13Only = new Set(['early_data']);
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
  if (['protocol','cipher','key_exchange','extended_master_secret','sni_alpn'].includes(control)) return 'handshake';
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
