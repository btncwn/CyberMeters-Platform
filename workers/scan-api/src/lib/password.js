// ── Password hashing ──
// PBKDF2-SHA256 hash + constant-time verify. Extracted verbatim from index.js
// (monolith decomposition, Phase 1b). Behavior-preserving — no logic change.

/**
 * Hash a password using PBKDF2-SHA256 (100,000 iterations).
 * Returns a storable string: "pbkdf2:sha256:100000:<salt_hex>:<hash_hex>"
 */
export async function hashPassword(password) {
  const encoder     = new TextEncoder();
  const salt        = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const hashBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 100_000 },
    keyMaterial, 256
  );
  const toHex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  return `pbkdf2:sha256:100000:${toHex(salt.buffer)}:${toHex(hashBits)}`;
}

/**
 * Verify a password against a stored PBKDF2 hash.
 * Uses constant-time XOR comparison to prevent timing attacks.
 */
export async function verifyPassword(password, stored) {
  const parts = stored.split(":");
  if (parts.length !== 5 || parts[0] !== "pbkdf2" || parts[1] !== "sha256") return false;
  const iterations  = parseInt(parts[2], 10);
  const saltBytes   = new Uint8Array(parts[3].match(/../g).map(h => parseInt(h, 16)));
  const storedHash  = parts[4];
  const encoder     = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const hashBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    keyMaterial, 256
  );
  const computed = Array.from(new Uint8Array(hashBits)).map(b => b.toString(16).padStart(2, "0")).join("");
  // Constant-time string comparison
  if (computed.length !== storedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) {
    diff |= computed.charCodeAt(i) ^ storedHash.charCodeAt(i);
  }
  return diff === 0;
}
