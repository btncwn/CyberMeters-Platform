// ── Shareable free-tool results ─────────────────────────────────────────────
//
// A shared result travels in the link itself: the public result (DNS facts and
// our wording, nothing secret) is compressed, signed and given an expiry. The
// page puts it after the # so it never reaches a server log; the page sends it
// back here only to check the signature and the expiry before showing it, so a
// link cannot be edited to show a result CyberMeters never produced. Nothing is
// stored. Without FREE_TOOLS_SHARE_KEY no link is offered.
export const SHARE_TTL_SECONDS = 7 * 24 * 3600;
export const MAX_SHARE_TOKEN_CHARS = 16_000;
const MAX_SHARE_JSON_BYTES = 64 * 1024;
const VERSION = "v1";

function shareKey(env) {
  const key = typeof env?.FREE_TOOLS_SHARE_KEY === "string" ? env.FREE_TOOLS_SHARE_KEY.trim() : "";
  return key.length >= 32 ? key : null;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("invalid base64url");
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  return Uint8Array.from(atob(padded), (char) => char.charCodeAt(0));
}

async function transform(bytes, stream, limit = Infinity) {
  const reader = new Blob([bytes]).stream().pipeThrough(stream).getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > limit) { await reader.cancel(); throw new Error("share payload too large"); }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { out.set(chunk, offset); offset += chunk.byteLength; }
  return out;
}

async function hmac(key, message) {
  const cryptoKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(message)));
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Sign a result for sharing. Returns { token, expires_at } or null. */
export async function signShareToken(env, result, { now = Date.now() } = {}) {
  const key = shareKey(env);
  if (!key || !result) return null;
  const expiresAt = new Date(now + SHARE_TTL_SECONDS * 1000).toISOString();
  const json = new TextEncoder().encode(JSON.stringify({ exp: expiresAt, result }));
  const body = toBase64Url(await transform(json, new CompressionStream("deflate-raw")));
  const token = `${VERSION}.${body}.${toBase64Url(await hmac(key, `${VERSION}.${body}`))}`;
  if (token.length > MAX_SHARE_TOKEN_CHARS) return null;
  return { token, expires_at: expiresAt };
}

/** Check a shared link. Returns { ok: true, result, expires_at } or { ok: false, code }. */
export async function verifyShareToken(env, token, { now = Date.now() } = {}) {
  const key = shareKey(env);
  if (!key) return { ok: false, code: "sharing_unavailable" };
  if (typeof token !== "string" || token.length > MAX_SHARE_TOKEN_CHARS) return { ok: false, code: "invalid_link" };
  const [version, body, signature, extra] = token.split(".");
  if (version !== VERSION || !body || !signature || extra !== undefined) return { ok: false, code: "invalid_link" };
  try {
    if (!sameBytes(fromBase64Url(signature), await hmac(key, `${VERSION}.${body}`))) return { ok: false, code: "invalid_link" };
    const json = await transform(fromBase64Url(body), new DecompressionStream("deflate-raw"), MAX_SHARE_JSON_BYTES);
    const payload = JSON.parse(new TextDecoder().decode(json));
    const expires = Date.parse(payload?.exp ?? "");
    if (!Number.isFinite(expires)) return { ok: false, code: "invalid_link" };
    if (expires <= now) return { ok: false, code: "expired_link" };
    return { ok: true, result: payload.result, expires_at: payload.exp };
  } catch {
    return { ok: false, code: "invalid_link" };
  }
}
