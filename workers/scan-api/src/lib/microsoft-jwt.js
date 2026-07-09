// Microsoft Entra OAuth / id_token (RS256 JWT) validation. Extracted verbatim from
// index.js (monolith decomposition, Phase 1b). Behavior-preserving — no logic change.

// ── Microsoft Entra OAuth helpers ────────────────────────────────────────────

/** Decode a base64url string to a UTF-8 string (safe for JWT header/payload). */
function b64urlDecode(str) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded  = base64 + "==".slice(0, (4 - (base64.length % 4)) % 4);
  return atob(padded);
}

/** Decode a base64url string to an ArrayBuffer (used for JWT signature). */
function b64urlToBuffer(str) {
  const binary = b64urlDecode(str);
  const buf    = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) buf[i] = binary.charCodeAt(i);
  return buf.buffer;
}

/**
 * Validate a Microsoft Entra id_token (RS256 JWT).
 * Fetches the tenant JWKS, verifies the signature, and validates core claims.
 * Returns the decoded payload on success; throws on any validation failure.
 */
export function validateMicrosoftIdTokenClaims(header, payload, clientId, tenantId, expectedNonce = null, nowSeconds = Date.now() / 1000) {
  if (header.alg !== "RS256") throw new Error("id_token: unsupported signing algorithm");
  if (!header.kid) throw new Error("id_token: missing kid");
  if (payload.aud !== clientId) throw new Error("id_token: aud mismatch");
  if (!Number.isFinite(payload.exp) || nowSeconds > payload.exp + 60) throw new Error("id_token: expired");
  if (Number.isFinite(payload.nbf) && nowSeconds + 60 < payload.nbf) throw new Error("id_token: not active");
  if (!payload.oid) throw new Error("id_token: missing oid claim");
  if (!payload.tid) throw new Error("id_token: missing tid claim");

  const multiTenantAliases = new Set(["common", "organizations", "consumers"]);
  if (!multiTenantAliases.has(tenantId) && payload.tid !== tenantId) {
    throw new Error("id_token: tenant mismatch");
  }
  const expectedIssuer = `https://login.microsoftonline.com/${payload.tid}/v2.0`;
  if (payload.iss !== expectedIssuer) throw new Error("id_token: issuer mismatch");
  if (expectedNonce && payload.nonce !== expectedNonce) throw new Error("id_token: nonce mismatch");
}

export async function validateMicrosoftIdToken(idToken, clientId, tenantId, expectedNonce = null) {
  const parts = idToken.split(".");
  if (parts.length !== 3) throw new Error("id_token: invalid format");

  const header  = JSON.parse(b64urlDecode(parts[0]));
  const payload = JSON.parse(b64urlDecode(parts[1]));

  validateMicrosoftIdTokenClaims(header, payload, clientId, tenantId, expectedNonce);

  // Fetch signing keys from Microsoft's tenant JWKS endpoint
  const jwksUrl = `https://login.microsoftonline.com/${tenantId}/discovery/v2.0/keys`;
  const jwksRes = await fetch(jwksUrl, { headers: { "User-Agent": "CyberMeters/1.0" } });
  if (!jwksRes.ok) throw new Error(`id_token: JWKS fetch failed (${jwksRes.status})`);
  const { keys } = await jwksRes.json();

  const key = keys.find(k => k.kid === header.kid && (!k.alg || k.alg === "RS256") && (!k.use || k.use === "sig"));
  if (!key) throw new Error("id_token: no matching JWKS key for kid=" + header.kid);

  // Import the RSA public key and verify the RS256 signature
  const cryptoKey = await crypto.subtle.importKey(
    "jwk", key,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signingInput = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
  const signature    = b64urlToBuffer(parts[2]);

  const valid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, signingInput);
  if (!valid) throw new Error("id_token: signature invalid");

  return payload; // { oid, email, name, tid, sub, ... }
}
