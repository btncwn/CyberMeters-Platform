// ── Normalized delivery outcomes + cooldown policy (canonical) ──────────────
// Two decisions that were previously implicit, made explicit and testable in one
// place, because both govern whether a customer is contacted.

// ─────────────────────────────────────────────────────────────────────────────
// 1. PROVIDER OUTCOME NORMALIZATION
// ─────────────────────────────────────────────────────────────────────────────
// The transport returns a coarse `provider_rejected` for every non-2xx, which
// lumps a 429 (retry in a minute) together with a 403 (never going to work). The
// retry sweep cannot tell them apart, so it either retries what can never succeed
// or abandons what would.
//
// This maps the transport's (reason, status) onto a closed, deterministic
// vocabulary with an explicit terminal flag. Unknown combinations FAIL CLOSED:
// an unrecognised provider outcome is treated as permanent, because a wrong "stop"
// is visible in the ledger while a wrong "retry forever" is a silent outbound loop
// against someone else's mail server.
//
// PRIVACY: this never returns a raw provider body or any recipient address. Only
// three safe, normalized diagnostics are persisted — a status code, an error class
// and a message code. The ledger is an audit trail, not a second copy of customer
// PII or of the provider's prose.

export const PROVIDER_OUTCOMES = Object.freeze({
  provider_rate_limited:          { terminal: false, error_class: "rate_limited" },
  provider_unavailable:           { terminal: false, error_class: "unavailable" },
  provider_temporary_rejection:   { terminal: false, error_class: "temporary_rejection" },
  provider_permanent_rejection:   { terminal: true,  error_class: "permanent_rejection" },
  provider_authentication_failed: { terminal: true,  error_class: "authentication" },
  recipient_invalid:              { terminal: true,  error_class: "recipient" },
});

// Resend returns 422 for an unroutable/invalid recipient payload; 401/403 for a bad
// key or an unverified sender domain. Both are configuration/recipient facts, not
// weather.
export function normalizeProviderOutcome({ reason = null, status = null } = {}) {
  const code = Number(status) || null;
  const mk = (r, message_code) => ({
    reason: r,
    terminal: PROVIDER_OUTCOMES[r].terminal,
    provider_status_code: code,
    provider_error_class: PROVIDER_OUTCOMES[r].error_class,
    provider_message_code: message_code,
  });

  // Transport-level failures never reached the provider.
  if (reason === "timeout") return mk("provider_unavailable", "timeout");
  if (reason === "network_error") return mk("provider_unavailable", "network_error");

  if (reason === "provider_rejected" && code) {
    if (code === 429) return mk("provider_rate_limited", "http_429");
    if (code >= 500) return mk("provider_unavailable", `http_${code}`);
    if (code === 408) return mk("provider_temporary_rejection", "http_408");
    if (code === 401 || code === 403) return mk("provider_authentication_failed", `http_${code}`);
    if (code === 422) return mk("recipient_invalid", "http_422");
    if (code >= 400) return mk("provider_permanent_rejection", `http_${code}`);
  }

  // Anything unrecognised — including provider_rejected with no status — is
  // permanent by default. Fail closed.
  return {
    reason: reason || "provider_permanent_rejection",
    terminal: true,
    provider_status_code: code,
    provider_error_class: "unknown",
    provider_message_code: reason ? String(reason).slice(0, 64) : "unclassified",
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. COOLDOWN POLICY
// ─────────────────────────────────────────────────────────────────────────────
// ONE canonical policy and source. Previously `cooldownActive` was a boolean the
// caller passed in, which meant the real policy lived wherever each caller decided
// — i.e. nowhere and everywhere.
//
// WHAT COOLDOWN IS FOR: damping repetition of the SAME kind of noise on the SAME
// entity. It is not deduplication (that is exact-occurrence identity) and it is not
// entitlement.
//
//   key        : workspace | domain_key | kind | entity
//                Per-entity so a noisy certificate cannot silence a different one,
//                and per-kind so a renewal alert cannot silence an expiry alert.
//   duration   : by severity (below). Critical is NOT exempt — it is merely shorter.
//   scope      : OUTBOUND ONLY. The canonical in-app event is always written, so the
//                bell and history stay complete even while email/channels are damped.
//   new occurrence : a genuinely new occurrence has a new occurrence_id and therefore
//                a different dedupe_key, but the SAME cooldown key — so it is damped
//                if it lands inside the window. That is intentional: five recurrences
//                of one condition in an hour is the exact noise cooldown exists for.
//   failure    : a cooldown lookup failure returns NOT in cooldown (fail OPEN).
//                Cooldown is a comfort feature; failing closed would silently
//                suppress a real security alert on a transient database error.
//                This is the one place fail-open is correct, and it is deliberate.
export const COOLDOWN_HOURS_BY_SEVERITY = Object.freeze({
  critical: 1,
  high: 4,
  medium: 12,
  low: 24,
  info: 24,
});

export function cooldownHoursFor(severity) {
  return COOLDOWN_HOURS_BY_SEVERITY[String(severity || "").toLowerCase()] ?? COOLDOWN_HOURS_BY_SEVERITY.medium;
}

// Deterministic, and deliberately NOT including occurrence_id: cooldown damps
// repetition of a kind on an entity, so every occurrence of that pair shares a key.
export function buildCooldownKey({ workspace_id, domain_key, kind, entity }) {
  return [workspace_id, domain_key, kind, String(entity || "").trim().toLowerCase()].join("|");
}

// Is this alert inside the cooldown window of a previously DELIVERED alert of the
// same kind on the same entity? Only a delivered outbound alert starts a window —
// a suppressed or failed one never reached the customer, so it cannot be "too soon".
export async function isInCooldown(env, { workspace_id, domain_key, kind, entity, severity, now = new Date().toISOString() } = {}) {
  const hours = cooldownHoursFor(severity);
  try {
    const row = await env.cybermeters_db
      .prepare(`SELECT d.created_at
                FROM alert_deliveries d
                JOIN notification_events n ON n.id = d.notification_id
                WHERE d.workspace_id = ? AND d.domain_key = ? AND d.alert_kind = ?
                  AND d.outcome = 'delivered' AND d.channel != 'in_app'
                  AND json_extract(n.metadata_json, '$.cooldown_entity') = ?
                  AND d.created_at > datetime(?, ?)
                ORDER BY d.created_at DESC LIMIT 1`)
      .bind(workspace_id, domain_key, kind, String(entity || "").trim().toLowerCase(), now, `-${hours} hours`)
      .first();
    return Boolean(row);
  } catch (err) {
    // Fail OPEN — see the note above. A damping feature must not be able to
    // silence a real alert because a query failed.
    console.error("[alert-cooldown] lookup failed", JSON.stringify({ workspace_id, domain_key, kind, reason: err?.message }));
    return false;
  }
}
