// ── Central log redaction ─────────────────────────────────────────────────────
// Defence-in-depth for logs: never rely on each call site to remember to hide a
// secret. Pass anything you're about to log through redact() and secret-shaped
// keys and values are replaced with "[redacted]". Pure, no I/O, never throws.

// Object KEYS whose value is always secret regardless of shape.
const SECRET_KEY = /(pass(word)?|secret|token|authorization|cookie|api[_-]?key|key[_-]?material|bearer|mfa|totp|recovery|otc|credential|session|priv|signature)/i;

// String VALUES that look like a secret even under an innocent key.
const SECRET_VALUE = [
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/,      // JWT
  /\b(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}\b/,                          // Stripe keys
  /\bwhsec_[A-Za-z0-9]{8,}\b/,                                           // Stripe webhook secret
  /\bcm(rua)?_[A-Za-z0-9]{16,}\b/,                                       // CyberMeters tokens
  /\bBearer\s+[A-Za-z0-9._-]{12,}\b/i,                                   // Authorization header value
  /\b[A-Fa-f0-9]{40,}\b/,                                                // long hex (hashes/keys)
];

const REDACTED = "[redacted]";

function redactString(s) {
  let out = String(s);
  for (const re of SECRET_VALUE) out = out.replace(new RegExp(re, "g"), REDACTED);
  return out;
}

// Recursively redact. Depth-capped and cycle-safe so a hostile/huge object can
// never hang or blow the stack.
export function redact(value, _depth = 0, _seen = new WeakSet()) {
  if (value == null) return value;
  if (typeof value === "string") return redactString(value);
  if (typeof value === "number" || typeof value === "boolean" || typeof value === "bigint") return value;
  if (_depth > 6) return "[…]";
  if (typeof value === "object") {
    if (_seen.has(value)) return "[circular]";
    _seen.add(value);
    if (Array.isArray(value)) return value.slice(0, 200).map((v) => redact(v, _depth + 1, _seen));
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = SECRET_KEY.test(k) ? REDACTED : redact(v, _depth + 1, _seen);
    }
    return out;
  }
  return REDACTED; // functions, symbols, etc.
}

// Convenience: build a safe JSON string for a log line.
export function redactedJson(value) {
  try { return JSON.stringify(redact(value)); } catch { return '"[unserialisable]"'; }
}
