// ── Canonical current-posture selector ────────────────────────────────────────
// The SINGLE source of "what is this scope's authoritative current posture?". Every
// customer-facing "latest posture / current score" consumer MUST delegate here
// instead of running its own `status='completed' ORDER BY created_at DESC LIMIT 1`.
//
// Rules (partial-scan honesty, strict model):
//   1. Authoritative current posture = latest COMPLETE assessment
//      (scan_quality='complete'), deterministic tie-break created_at DESC, id DESC.
//   2. A newer partial/degraded/unknown assessment is returned SEPARATELY as the
//      latest provisional assessment — it never replaces the authoritative posture.
//   3. If no complete assessment exists → posture 'not_established' (a provisional
//      latest may still be shown separately).
//   4. Legacy NULL/unknown quality NEVER outranks a known complete assessment
//      (the authoritative query matches scan_quality='complete' only).

import { normalizeQuality, resolveAssessmentPresentation, POSTURE_NOT_ESTABLISHED_MESSAGE } from "./assessment-presentation.js";

// scope: { workspaceId } (latest across the workspace's linked domains) or
// { domainId } (a single domain). Returns:
//   { state: 'established'|'not_established',
//     authoritative: {scan_id, score, rating, scan_quality, created_at} | null,
//     latest_provisional: {scan_id, score, scan_quality, created_at} | null }
export async function getAuthoritativeCurrentPosture(env, { workspaceId = null, domainId = null } = {}) {
  const from = workspaceId
    ? "FROM scans s JOIN workspace_domains wd ON wd.domain_id = s.domain_id WHERE wd.workspace_id = ?"
    : "FROM scans s WHERE s.domain_id = ?";
  const bind = workspaceId || domainId;
  if (!bind) return { state: "not_established", authoritative: null, latest_provisional: null };

  const cols = "s.id AS scan_id, s.score, s.rating, s.scan_quality, s.created_at";
  const order = "ORDER BY s.created_at DESC, s.id DESC LIMIT 1";

  let authoritative = null, latest = null;
  try {
    authoritative = await env.cybermeters_db
      .prepare(`SELECT ${cols} ${from} AND s.status='completed' AND s.scan_quality='complete' ${order}`)
      .bind(bind).first();
    latest = await env.cybermeters_db
      .prepare(`SELECT ${cols} ${from} AND s.status='completed' ${order}`)
      .bind(bind).first();
  } catch {
    return { state: "not_established", authoritative: null, latest_provisional: null };
  }

  // The latest completed scan is "provisional to show separately" only when it is
  // NOT the authoritative complete row and is not itself complete quality.
  let latest_provisional = null;
  if (latest && (!authoritative || latest.scan_id !== authoritative.scan_id) && normalizeQuality(latest.scan_quality) !== "complete") {
    latest_provisional = latest;
  }

  return {
    state: authoritative ? "established" : "not_established",
    authoritative,
    latest_provisional,
  };
}

// True only when the given scan is comparable for trend deltas (complete only).
export function isComparableAssessment(scanQuality) {
  return normalizeQuality(scanQuality) === "complete";
}

// One-call canonical decision for every score/rating/posture API consumer: resolves
// the authoritative posture AND wraps it in the canonical presentation, plus the
// latest provisional assessment (if any) and a not-established message. Consumers
// MUST use this (or getAuthoritativeCurrentPosture) rather than their own
// latest-completed-scan query + riskLevelForScore, so the whole product renders one
// completeness-aware decision. Fields carried: raw_score/display_score/display_rating/
// quality/provisional/authoritative/comparable/message.
export async function getCurrentPosturePresentation(env, scope) {
  const posture = await getAuthoritativeCurrentPosture(env, scope);
  const present = (row) => row
    ? resolveAssessmentPresentation({ score: row.score, scanQuality: row.scan_quality, status: "completed" })
    : null;
  return {
    state:               posture.state,                    // 'established' | 'not_established'
    authoritative:       present(posture.authoritative),   // canonical fields or null
    authoritative_scan_id: posture.authoritative?.scan_id ?? null,
    latest_provisional:  present(posture.latest_provisional),
    latest_provisional_scan_id: posture.latest_provisional?.scan_id ?? null,
    posture_message:     posture.state === "not_established" ? POSTURE_NOT_ESTABLISHED_MESSAGE : null,
  };
}
