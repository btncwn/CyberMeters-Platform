// Website sign-in credential encryption (signed-in scanning, migration 116).
//
// A DEDICATED versioned AES-256-GCM key ring in the Worker secret
// WEBSITE_AUTH_KEY — never the DNS provider key, never an auth/session key:
//   {"v":1,"active":"k1","keys":{"k1":"<base64 32 bytes>"}}
// Rotation: add a new key id, make it active, keep the old id until every
// profile has been re-saved. Without a valid ring the feature is unavailable
// (fail closed) — nothing is stored in clear, ever.
//
// The ciphertext is bound (AES-GCM additional data) to the workspace, domain,
// profile id and method, so it cannot be moved to another tenant, domain or
// profile, nor replayed under another sign-in method.
const encoder = new TextEncoder();
const fail = () => Object.assign(new Error('Signed-in scanning is temporarily unavailable.'), { code: 'vault_unavailable', status: 503 });
const encode = (bytes) => btoa(String.fromCharCode(...bytes));
function decode(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value) || value.length > 16384) throw fail();
  try { return Uint8Array.from(atob(value), (char) => char.charCodeAt(0)); } catch { throw fail(); }
}
function ring(binding) {
  try {
    const value = JSON.parse(binding);
    if (value.v !== 1 || !/^[a-zA-Z0-9_-]{1,32}$/.test(value.active) || !value.keys || typeof value.keys !== 'object' || Object.keys(value.keys).length > 5) throw fail();
    if (decode(value.keys[value.active]).length !== 32) throw fail();
    return value;
  } catch { throw fail(); }
}
const METHODS = ['form', 'header', 'cookie'];
function aad(scope) {
  const fields = ['workspace_id', 'domain_id', 'profile_id', 'method'];
  if (fields.some((key) => typeof scope?.[key] !== 'string' || !scope[key] || scope[key].length > 128)) throw fail();
  if (!METHODS.includes(scope.method)) throw fail();
  return encoder.encode(JSON.stringify(['cybermeters:website-sign-in:v1', ...fields.map((key) => scope[key])]));
}

/** Shape of the secret per method. Values are validated again before use. */
export function validSecret(method, secret) {
  if (!secret || typeof secret !== 'object' || Array.isArray(secret)) return false;
  const str = (v, max) => typeof v === 'string' && v.length > 0 && v.length <= max && !/[\r\n\0]/.test(v);
  if (method === 'form') return Object.keys(secret).length === 2 && str(secret.username, 256) && str(secret.password, 512);
  if (method === 'header') return Object.keys(secret).length === 2 && str(secret.header_name, 64) && str(secret.header_value, 4096);
  if (method === 'cookie') return Object.keys(secret).length === 2 && str(secret.cookie_name, 128) && str(secret.cookie_value, 4096);
  return false;
}

export function websiteAuthKeyAvailable(binding) { try { ring(binding); return true; } catch { return false; } }

export async function encryptWebsiteSecret(secret, scope, binding) {
  if (!validSecret(scope?.method, secret)) throw Object.assign(new Error('Check the sign-in details.'), { code: 'invalid_secret', status: 400 });
  const keys = ring(binding), iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey('raw', decode(keys.keys[keys.active]), 'AES-GCM', false, ['encrypt']);
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(scope) }, key, encoder.encode(JSON.stringify(secret)));
  return JSON.stringify({ v: 1, kid: keys.active, iv: encode(iv), ct: encode(new Uint8Array(ciphertext)) });
}

export async function decryptWebsiteSecret(envelope, scope, binding) {
  try {
    const keys = ring(binding), value = JSON.parse(envelope);
    if (value.v !== 1 || typeof value.kid !== 'string' || !Object.hasOwn(keys.keys, value.kid)) throw fail();
    const raw = decode(keys.keys[value.kid]), iv = decode(value.iv), ct = decode(value.ct);
    if (raw.length !== 32 || iv.length !== 12 || ct.length < 16) throw fail();
    const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
    const clear = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(scope) }, key, ct);
    const secret = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(clear));
    if (!validSecret(scope.method, secret)) throw fail();
    return secret;
  } catch { throw fail(); }
}
