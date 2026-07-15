// ── Certificate renewal policy — ONE canonical threshold source ─────────────
// Every certificate expiry / renewal-readiness decision in the managed lifecycle
// derives from THIS module. Historically the same "days until expiry" bands were
// re-derived in ssl-scan, cert-intel, cert-trust-l2 and alerts with slightly
// different cut-offs; the managed lifecycle centralises them here so the customer
// sees ONE consistent renewal story. Deterministic, pure, side-effect free.
//
// Honesty: `days_remaining` is computed from the externally-OBSERVED expiry
// (crt.sh / CT `not_after`). It says nothing about chain, root, OCSP, revocation
// or private-key state — those remain unknown without live TLS.

// Canonical renewal bands, widest-remaining first. A certificate falls in the
// FIRST band whose `min_days` it meets (expired is the floor).
export const CERT_RENEWAL_BANDS = Object.freeze([
  { readiness: "monitoring",  risk_status: "ok",        min_days: 90,  label: "Monitoring" },
  { readiness: "planning",    risk_status: "ok",        min_days: 60,  label: "Plan renewal" },
  { readiness: "preparation", risk_status: "attention", min_days: 30,  label: "Prepare renewal" },
  { readiness: "high",        risk_status: "urgent",    min_days: 14,  label: "Renew soon" },
  { readiness: "critical",    risk_status: "critical",  min_days: 1,   label: "Renew now" },
  { readiness: "expired",     risk_status: "expired",   min_days: -Infinity, label: "Expired" },
]);

// Latest safe point (days before expiry) by which renewal work should START.
// A certificate whose renewal has not started by this point is renewal-overdue.
export const RENEWAL_START_BY_DAYS = 30;

// ── How loudly a renewal-overdue certificate alerts (PR-B2) ──────────────────
// Founder-specified: 30–8 days => high, 7–1 days => critical, 0 or below is the
// `expired` recurrence (critical) and is NOT this function's business.
//
// Deliberately NOT reusing CERT_RENEWAL_BANDS.readiness, whose boundary is 14/13.
// Those bands drive the customer-facing renewal GUIDANCE ladder ("Renew soon" /
// "Renew now"); this drives ALERT severity. They are different questions with
// different thresholds, and folding them together would mean re-tuning one by
// editing the other — silently, since nothing would fail.
//
// The band doubles as the severity: both values are already valid severities, so
// there is no second mapping to drift.
//
// Returns null when the certificate is not renewal-overdue (>30 days) or is
// expired/unknown (<=0 / unparseable) — the caller must not alert `renewal_overdue`
// in either case.
export const RENEWAL_ALERT_CRITICAL_DAYS = 7;

export function renewalAlertBand(daysRemaining) {
  if (daysRemaining === null || daysRemaining === undefined) return null;
  const d = Number(daysRemaining);
  if (!Number.isFinite(d)) return null;
  if (d <= 0) return null;                                  // expired owns this
  if (d <= RENEWAL_ALERT_CRITICAL_DAYS) return "critical";  // 7..1
  if (d <= RENEWAL_START_BY_DAYS) return "high";            // 30..8
  return null;                                              // not overdue yet
}
// A domain with no observed certificate evidence at all cannot be assessed.
export const RENEWAL_READINESS_UNKNOWN = "unknown";

const MS_PER_DAY = 86_400_000;

// Whole days from `now` until `not_after` (floored). null when not_after is
// absent/unparseable — the caller must treat that as "unknown", never as safe.
export function daysUntil(notAfter, now = new Date().toISOString()) {
  if (!notAfter) return null;
  const exp = Date.parse(notAfter);
  const ref = Date.parse(now);
  if (!Number.isFinite(exp) || !Number.isFinite(ref)) return null;
  return Math.floor((exp - ref) / MS_PER_DAY);
}

// Canonical renewal assessment for an observed expiry.
//   { days_remaining, readiness, risk_status, band_label, expired,
//     start_by_days, renewal_start_by, overdue_start }
// `days_remaining === null` (no observed expiry) → readiness "unknown": the
// product does not claim safety it cannot see.
export function assessRenewal(notAfter, now = new Date().toISOString()) {
  const days_remaining = daysUntil(notAfter, now);
  if (days_remaining === null) {
    return {
      days_remaining: null, readiness: RENEWAL_READINESS_UNKNOWN, risk_status: "unknown",
      band_label: "Expiry unknown", expired: false,
      start_by_days: RENEWAL_START_BY_DAYS, renewal_start_by: null, overdue_start: false,
    };
  }
  const band = CERT_RENEWAL_BANDS.find((b) => days_remaining >= b.min_days) ||
    CERT_RENEWAL_BANDS[CERT_RENEWAL_BANDS.length - 1];
  const expired = days_remaining <= 0;
  // Latest safe start = not_after − RENEWAL_START_BY_DAYS.
  let renewal_start_by = null;
  const exp = Date.parse(notAfter);
  if (Number.isFinite(exp)) renewal_start_by = new Date(exp - RENEWAL_START_BY_DAYS * MS_PER_DAY).toISOString();
  const overdue_start = days_remaining <= RENEWAL_START_BY_DAYS && !expired;
  return {
    days_remaining, readiness: band.readiness, risk_status: band.risk_status,
    band_label: band.label, expired, start_by_days: RENEWAL_START_BY_DAYS,
    renewal_start_by, overdue_start,
  };
}

// Should a renewal case be opened purely on expiry pressure? Reserved for the
// critical / expired bands — earlier bands are informational planning states,
// not managed-case triggers (avoids crying wolf at 89 days out).
export function renewalRequiresCase(readiness) {
  return readiness === "critical" || readiness === "expired";
}
