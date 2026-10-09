// Dedicated provider-token encryption. The binding is a versioned AES key ring,
// never an MFA/session key. Ciphertexts cannot move between tenants or zones.
const encoder = new TextEncoder();
const fail = () => Object.assign(new Error('DNS provider encryption is unavailable.'), { code: 'key_unavailable', status: 503 });
const encode = bytes => btoa(String.fromCharCode(...bytes));
function decode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length > 16384) throw fail();
  try { return Uint8Array.from(atob(value), char => char.charCodeAt(0)); } catch { throw fail(); }
}
function ring(binding) {
  try {
    const value = JSON.parse(binding);
    if (value.v !== 1 || !/^[a-zA-Z0-9_-]{1,32}$/.test(value.active) || !value.keys || Object.keys(value.keys).length > 5) throw fail();
    if (decode(value.keys[value.active]).length !== 32) throw fail();
    return value;
  } catch { throw fail(); }
}
function aad(scope) {
  const fields = ['workspace_id', 'domain_id', 'zone_id', 'connection_id'];
  if (fields.some(key => typeof scope?.[key] !== 'string' || !scope[key] || scope[key].length > 128)) throw fail();
  return encoder.encode(JSON.stringify(['cybermeters:cloudflare-dns-token:v1', ...fields.map(key => scope[key])]));
}
export function providerKeyAvailable(binding) { try { ring(binding); return true; } catch { return false; } }
export async function encryptProviderToken(token, scope, binding) {
  if (typeof token !== 'string' || !/^[a-zA-Z0-9_-]{20,256}$/.test(token)) throw Object.assign(new Error('Enter a Cloudflare API token.'), { code: 'invalid_token', status: 400 });
  const keys = ring(binding), iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', decode(keys.keys[keys.active]), 'AES-GCM', false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(scope) }, key, encoder.encode(token));
  return JSON.stringify({ v: 1, kid: keys.active, iv: encode(iv), ct: encode(new Uint8Array(ciphertext)) });
}
export async function decryptProviderToken(envelope, scope, binding) {
  try {
    const keys = ring(binding), value = JSON.parse(envelope);
    if (value.v !== 1 || !Object.hasOwn(keys.keys, value.kid)) throw fail();
    const raw = decode(keys.keys[value.kid]), iv = decode(value.iv), ct = decode(value.ct);
    if (raw.length !== 32 || iv.length !== 12 || ct.length < 16) throw fail();
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(scope) }, key, ct);
    const token = new TextDecoder('utf-8', { fatal: true }).decode(clear);
    if (!/^[a-zA-Z0-9_-]{20,256}$/.test(token)) throw fail();
    return token;
  } catch { throw fail(); }
}
