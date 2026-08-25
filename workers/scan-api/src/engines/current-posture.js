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

import { normalizeQuality, POSTURE_NOT_ESTABLISHED_MESSAGE } from "./assessment-presentation.js";
import {
  resolvePhase5HistoricalCustomerProjection,
  websiteRedirectConclusionWithheld,
  WEBSITE_REDIRECT_WITHHELD_MESSAGE,
} from "./phase5-evidence.js";

// scope: { workspaceId } (latest across the workspace's linked domains) or
// { domainId } (a single domain). Returns:
//   { state: 'established'|'not_established',
//     authoritative: {scan_id, score, rating, scan_quality, created_at} | null,
//     latest_provisional: {scan_id, score, scan_quality, created_at} | null }
export async function getAuthoritativeCurrentPosture(env, { workspaceId = null, domainId = null } = {}) {
  const from = workspaceId
    // A linked domain may belong to several workspaces. Only the scan's explicit
    // workspace attribution may grant this read; joining through
    // workspace_domains would let one tenant's posture request fetch another
    // tenant's immutable report now that monitoring provenance is R2-backed.
    ? "FROM scans s WHERE s.workspace_id = ?"
    : "FROM scans s WHERE s.domain_id = ?";
  const bind = workspaceId || domainId;
  if (!bind) return { state: "not_established", authoritative: null, latest_provisional: null };

  const cols = "s.id AS scan_id, s.score, s.rating, s.scan_quality, s.created_at";
  const order = "ORDER BY s.created_at DESC, s.id DESC LIMIT 1";

  let authoritative = null, latest = null, authoritativeCandidates = [];
  try {
    const candidateStatement = env.cybermeters_db
      .prepare(`SELECT ${cols} ${from} AND s.status='completed' AND s.scan_quality='complete' ORDER BY s.created_at DESC, s.id DESC LIMIT 100`)
      .bind(bind);
    if (typeof candidateStatement.all === "function") {
      const rows = await candidateStatement.all();
      authoritativeCandidates = rows?.results ?? [];
      authoritative = authoritativeCandidates[0] ?? null;
    } else {
      authoritative = await candidateStatement.first();
      authoritativeCandidates = authoritative ? [authoritative] : [];
    }
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
    authoritative_candidates: authoritativeCandidates,
    latest_completed: latest,
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
  const presentations = new Map();
  const present = async (row) => {
    if (!row) return null;
    if (presentations.has(row.scan_id)) return presentations.get(row.scan_id);

    let monitoringStates;
    let phase5Modules = {};
    let reportFindings = null;
    // A raw "complete" scan row is only a candidate for authority. The immutable
    // report carries provider/signal provenance; missing R2, malformed JSON, or
    // absent provenance fails toward provisional. Non-complete rows are already
    // provisional and do not need an R2 read to prove it again.
    if (normalizeQuality(row.scan_quality) === "complete") {
      try {
        const object = await env.cybermeters_reports.get(`reports/${row.scan_id}.json`);
        const report = object ? await object.json() : null;
        monitoringStates = report?.monitoring_states ?? null;
        phase5Modules = report?.modules ?? {};
        reportFindings = report?.findings ?? null;
      } catch {
        monitoringStates = null;
        phase5Modules = {};
        reportFindings = null;
      }
    }
    const phase5 = resolvePhase5HistoricalCustomerProjection({
      score: row.score,
      riskLevel: row.rating,
      scanQuality: row.scan_quality,
      modules: phase5Modules,
      monitoringStates,
    });
    // Phase-5 owns the complete customer decision, including the distinct case
    // where its own intelligence evidence is complete but a score-bearing
    // module was skipped. Re-branching on evidence.complete here used to revive
    // the stored numeric score for precisely that suppressed case.
    //
    // P1-2: the SAME historical invalidation the snapshot projector applies
    // must reach authority selection. A persisted 85/good that rests on the
    // withdrawn non-serviceable redirect conclusion cannot become the
    // authoritative posture just because this reader looked at raw modules
    // instead of the projected snapshot.
    const websiteWithheld = websiteRedirectConclusionWithheld(phase5Modules, reportFindings);
    const value = websiteWithheld
      ? {
          ...phase5.assessment,
          display_score: null,
          display_rating: null,
          authoritative: false,
          comparable: false,
          provisional: true,
          message: WEBSITE_REDIRECT_WITHHELD_MESSAGE,
        }
      : phase5.assessment;
    presentations.set(row.scan_id, value);
    return value;
  };

  let authoritative = null;
  let authoritativeRaw = null;
  const candidates = posture.authoritative_candidates?.length
    ? posture.authoritative_candidates
    : (posture.authoritative ? [posture.authoritative] : []);
  for (const candidate of candidates) {
    const presentation = await present(candidate);
    if (presentation?.authoritative) {
      authoritativeRaw = candidate;
      authoritative = presentation;
      break;
    }
  }
  const latestRaw = posture.latest_completed ?? posture.latest_provisional ?? posture.authoritative;
  const latestPresentation = await present(latestRaw);
  const latestProvisional =
    latestPresentation && !latestPresentation.authoritative &&
      latestRaw?.scan_id !== authoritativeRaw?.scan_id
      ? latestPresentation
      : null;
  const established = authoritative != null;
  const labelledAuthoritative = established
    ? {
        ...authoritative,
        label: latestProvisional ? "Last authoritative posture" : null,
        assessed_at: authoritativeRaw?.created_at ?? null,
      }
    : null;
  return {
    state: established ? "established" : "not_established",
    authoritative: labelledAuthoritative,
    authoritative_scan_id: established ? (authoritativeRaw?.scan_id ?? null) : null,
    latest_provisional: latestProvisional,
    latest_provisional_scan_id: latestProvisional ? (latestRaw?.scan_id ?? null) : null,
    posture_message: established ? null : POSTURE_NOT_ESTABLISHED_MESSAGE,
  };
}
