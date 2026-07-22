// ── Atomic active-scan admission guard (PR-2, 22 Jul 2026) ───────────────────
// The DATABASE is the admission authority: migration 099's partial unique
// indexes allow at most ONE active scan per (workspace_id, domain) — and per
// (domain) for the defensive NULL-workspace case. Application code never
// decides admission by reading first (a read-then-write check loses the race
// between two concurrent Worker invocations); it attempts the INSERT and
// converts the constraint rejection into an honest customer outcome:
//   - manual POST /api/scan  → json({ error, active_scan_* }, 409)
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

export const ACTIVE_SCAN_CONFLICT_MESSAGE =
  "A scan for this domain is already in progress in this workspace. " +
  "Wait for it to finish, then start a new scan.";

// D1 surfaces SQLite constraint rejections as an Error whose message contains
// the SQLite wording (typically prefixed "D1_ERROR:"), e.g.
//   "UNIQUE constraint failed: scans.workspace_id, scans.domain".
// Matching the stable SQLite substring covers both the D1 client and the local
// SQLite used by CI. Anything else (D1 outage, syntax, other constraints) is
// NOT an admission conflict and must keep propagating to the safe 500 path.
export function isUniqueConstraintError(err) {
  return /UNIQUE constraint failed/i.test(String(err?.message ?? err ?? ""));
}

// Read-only lookup of the blocking active scan, for the honest 409 payload.
// Both ids returned are the caller's own already-authorised workspace context
// (scan:create was verified before admission), so this is not an enumeration
// oracle. Best-effort: a read failure degrades to a payload without the
// active_scan_* fields, never to a different admission decision.
export async function findActiveScan(env, workspaceId, domain) {
  try {
    const placeholders = SCAN_ACTIVE_STATUSES.map(() => "?").join(",");
    const row = await env.cybermeters_db
      .prepare(
        `SELECT id, status, created_at FROM scans
          WHERE workspace_id = ? AND domain = ? AND status IN (${placeholders})
          ORDER BY created_at DESC LIMIT 1`
      )
      .bind(workspaceId, domain, ...SCAN_ACTIVE_STATUSES)
      .first();
    return row ?? null;
  } catch {
    return null;
  }
}
