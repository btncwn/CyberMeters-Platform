// RFC 6238 TOTP — extracted verbatim from index.js (monolith decomposition, Phase 1b).
// Behavior-preserving — no logic change. Uses the base32 codec.
import { base32Decode, base32Encode } from "./base32.js";

// ── TOTP Engine (RFC 6238) ────────────────────────────────────────────────────
// Pure WebCrypto — no third-party libraries.
// TOTP = HOTP(key, T) where T = floor(unix_seconds / 30)
// HOTP uses HMAC-SHA1 per RFC 4226.

export function generateTotpSecret() {
  // 20 bytes = 160-bit secret (RFC 4226 recommended minimum)
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

async function computeTotp(base32Secret, timeStep = null) {
  const keyBytes = base32Decode(base32Secret);
  const t = timeStep ?? Math.floor(Date.now() / 1000 / 30);

  // 8-byte big-endian counter
  const msg = new DataView(new ArrayBuffer(8));
  const high = Math.floor(t / 0x100000000);
  const low  = t >>> 0;
  msg.setUint32(0, high, false);
  msg.setUint32(4, low,  false);

  const key = await crypto.subtle.importKey(
    "raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, msg.buffer));

  // Dynamic truncation (RFC 4226 §5.4)
  const offset = sig[sig.length - 1] & 0x0f;
  const code = (
    ((sig[offset]     & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) <<  8) |
     (sig[offset + 3] & 0xff)
  ) % 1_000_000;

  return code.toString().padStart(6, "0");
}

export async function verifyTotp(base32Secret, code) {
  if (!code || !/^\d{6}$/.test(code.trim())) return false;
  const t = Math.floor(Date.now() / 1000 / 30);
  // Allow ±1 window (30 seconds each side) for clock drift
  for (const delta of [0, -1, 1]) {
    if (await computeTotp(base32Secret, t + delta) === code.trim()) return true;
  }
  return false;
}
