// ── Auth crypto ──
// Token generation (session/API/invite/verification/reset/MFA-challenge), MFA secret
// encryption (AES-256-GCM), recovery codes, token hashing. Extracted verbatim from
// index.js (monolith decomposition, Phase 1b). Behavior-preserving. Recovery codes are
// hashed/verified with the password hasher.
import { hashPassword, verifyPassword } from "./password.js";

// ── Auth Crypto Helpers ────────────────────────────────────────────────────────

/**
 * Generate a 64-char hex bearer token and return both the raw token (for client)
 * and its SHA-256 hash (for D1 storage — raw token never persisted).
 */
export async function generateSessionToken() {
  const raw     = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, "0")).join("");
  const hashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  const hash    = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
  return { raw, hash };
}

export async function generateApiToken() {
  const secret = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, "0")).join("");
  const raw    = `cm_${secret}`;
  const hash   = await hashToken(raw);
  return { raw, hash };
}

export async function generateInviteToken() {
  const secret = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, "0")).join("");
  const raw    = `cmi_${secret}`;
  const hash   = await hashToken(raw);
  return { raw, hash };
}

/**
 * generateVerificationToken — creates a 64-char hex token for email verification.
 * The raw token is only sent by email. D1 stores its SHA-256 hash.
 */
export function generateVerificationToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function generateEmailVerificationToken() {
  const raw = generateVerificationToken();
  const hash = await hashToken(raw);
  return { raw, hash };
}

export function getEmailVerificationTokenStatus(userRow, nowMs = Date.now()) {
  if (!userRow) return "invalid";
  if (userRow.email_verified) return "already_verified";
  const expiresAt = Date.parse(userRow.verification_token_expires_at || "");
  if (!Number.isFinite(expiresAt) || expiresAt <= nowMs) return "expired";
  return "valid";
}

export function isEmailVerificationResendCoolingDown(expiresAt, nowMs = Date.now()) {
  const expiresAtMs = Date.parse(expiresAt || "");
  const cooldownThreshold = nowMs + (24 * 60 * 60 * 1000) - (60 * 1000);
  return Number.isFinite(expiresAtMs) && expiresAtMs > cooldownThreshold;
}

export async function generatePasswordResetToken() {
  const secret = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, "0")).join("");
  const raw    = `cmreset_${secret}`;
  const hash   = await hashToken(raw);
  return { raw, hash };
}

export async function generateMfaChallengeToken() {
  const secret = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, "0")).join("");
  const raw    = `cmfa_${secret}`;
  const hash   = await hashToken(raw);
  return { raw, hash };
}

// ── MFA secret encryption (AES-256-GCM) ──────────────────────────────────────
// TOTP secrets must be reversible — encrypted with env.MFA_ENCRYPTION_KEY.
// Key derivation: PBKDF2-SHA256, 100k iterations, static purpose-salt.

export async function getMfaEncryptionKey(env) {
  if (!env.MFA_ENCRYPTION_KEY) throw new Error("MFA_ENCRYPTION_KEY is not configured");
  const raw     = new TextEncoder().encode(env.MFA_ENCRYPTION_KEY);
  const baseKey = await crypto.subtle.importKey("raw", raw, "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256",
      salt: new TextEncoder().encode("cybermeters-mfa-v1"), iterations: 100_000 },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

export async function encryptTotpSecret(base32Secret, env) {
  const key = await getMfaEncryptionKey(env);
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(base32Secret));
  const toHex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  return JSON.stringify({ iv: toHex(iv.buffer), ct: toHex(ct) });
}

export async function decryptTotpSecret(stored, env) {
  const key = await getMfaEncryptionKey(env);
  const { iv: ivHex, ct: ctHex } = JSON.parse(stored);
  const fromHex = (hex) => new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16)));
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromHex(ivHex) }, key, fromHex(ctHex));
  return new TextDecoder().decode(plain);
}

// ── Recovery codes ────────────────────────────────────────────────────────────
// 8 codes, format: XXXX-XXXX-XXXX (uppercase alphanumeric).
// Raw codes are shown to user once; PBKDF2 hashes stored in JSON array.

export function generateRawRecoveryCode() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  const parts = [];
  for (let i = 0; i < 3; i++) {
    let seg = "";
    for (let j = 0; j < 4; j++) seg += chars[bytes[i * 4 + j] % chars.length];
    parts.push(seg);
  }
  return parts.join("-");
}

export function normalizeRecoveryCode(code) {
  return code.replace(/-/g, "").toUpperCase().trim();
}

export async function generateRecoveryCodes() {
  const codes  = Array.from({ length: 8 }, generateRawRecoveryCode);
  const hashes = await Promise.all(codes.map(c => hashPassword(normalizeRecoveryCode(c))));
  return { codes, hashes };
}

export async function verifyRecoveryCode(submittedCode, hashesJson) {
  if (!hashesJson) return { valid: false, remainingHashes: null };
  const hashes     = JSON.parse(hashesJson);
  const normalized = normalizeRecoveryCode(submittedCode);
  for (let i = 0; i < hashes.length; i++) {
    if (await verifyPassword(normalized, hashes[i])) {
      const remaining = hashes.filter((_, idx) => idx !== i);
      return { valid: true, remainingHashes: remaining };
    }
  }
  return { valid: false, remainingHashes: null };
}

/**
 * Hash a bearer token string for D1 lookup (same as above but for incoming tokens).
 */
export async function hashToken(raw) {
  const hashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
}
