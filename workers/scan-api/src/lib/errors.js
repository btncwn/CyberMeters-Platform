// ── Customer-safe error helpers ──
// Logs the internal error server-side and returns a safe, generic customer-facing
// message (never leaks Worker/D1/stack internals — CLAUDE.md trust rule). Extracted
// verbatim from index.js (monolith decomposition, Phase 1c). Behavior-preserving.

// The identity lookup could not run, which says nothing about the credential.
// Optional-auth callers rethrow it rather than falling back to anonymous.
export class AuthUnavailableError extends Error {}

export function customerSafeFailure(context, error, message) {
  console.error(`[${context}]`, error);
  return message;
}
