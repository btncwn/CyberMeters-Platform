// ── Atomic active-scan admission guard (PR-2, 22 Jul 2026) ───────────────────
// The DATABASE is the admission authority: migration 099's partial unique
// indexes allow at most ONE active scan per (workspace_id, domain) — and per
// (domain) for the defensive NULL-workspace case. Application code never
// decides admission by reading first (a read-then-write check loses the race
// between two concurrent Worker invocations); it attempts the INSERT and
// converts the constraint rejection into an honest customer outcome:
//   - manual POST /api/scan  → json(activeScanConflictBody(), 409) — the
//     stable customer-safe contract { error, code }, never internal ids
//   - scheduled cron runner  → skip with a stable reason; the schedule stays
//     due and retries next tick, exactly like an eligibility skip.
//
// SCAN_ACTIVE_STATUSES must stay in lockstep with the WHERE clause of BOTH
// indexes in database/migrations/099-active-scan-admission-guard.sql —
// scripts/validate-scan-admission-guard.js fails CI on any drift. 'queued' and
// 'retrying' are reserved for PR-3 (durable Queue dispatch); only 'running' is
// written today. RECOVERY_ACTIVE_STATUSES (engines/scan-recovery.js) is a
// DIFFERENT, narrower set: the statuses recovery knows how to repair — PR-3
// widens it deliberately, never by importing this one.

export const SCAN_ACTIVE_STATUSES = ["queued", "running", "retrying"];

export const ACTIVE_SCAN_CONFLICT_CODE = "active_scan_exists";
export const ACTIVE_SCAN_CONFLICT_MESSAGE =
  "A scan is already active for this domain.";

// The canonical customer-safe conflict body — a frozen CONSTANT by design.
// It carries no scan id, workspace id, domain id, timestamp or database
// detail, and is byte-identical regardless of WHICH active row caused the
// conflict, so the response can never become a cross-tenant or internal-state
// oracle. The route returns exactly this with status 409; anything richer
// (polling hints, active status) needs a founder-approved UI contract first.
const ACTIVE_SCAN_CONFLICT_BODY = Object.freeze({
  error: ACTIVE_SCAN_CONFLICT_MESSAGE,
  code: ACTIVE_SCAN_CONFLICT_CODE,
});
export function activeScanConflictBody() {
  return ACTIVE_SCAN_CONFLICT_BODY;
}

// D1 surfaces SQLite constraint rejections as an Error whose message contains
// the SQLite wording (typically prefixed "D1_ERROR:"), e.g.
//   "UNIQUE constraint failed: scans.workspace_id, scans.domain".
// Matching the stable SQLite substring covers both the D1 client and the local
// SQLite used by CI. Anything else (D1 outage, syntax, other constraints) is
// NOT an admission conflict and must keep propagating to the safe 500 path.
export function isUniqueConstraintError(err) {
  return /UNIQUE constraint failed/i.test(String(err?.message ?? err ?? ""));
}
