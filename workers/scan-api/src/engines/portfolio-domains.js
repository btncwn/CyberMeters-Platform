// ── MSP Portfolio — per-domain state and trend ────────────────────────────────
// "For every customer domain I manage: what state is each of the eight Cyber MOT
// domains in, what changed, and who needs me first?"
//
// The unit here is the DOMAIN RECORD — (workspace_id, domain_id) — not the customer and
// not the hostname. The existing portfolio (portfolio-customers.js) answers the same
// question one level up, per workspace, and collapses the domain dimension away with a
// GROUP BY. This does not collapse it, and it never averages the eight domains into a
// number: a customer at 86 with one critical domain and nine healthy ones is not "Low
// risk", and a mean is exactly how that gets said out loud.
//
// Reads D1 only — four queries for the WHOLE portfolio, independent of domain count.
// Zero R2. Zero writes. See cyber-mot-state-history.js for why that is possible.

import { CANONICAL_TERMINAL_STATES } from "./managed-case-model.js";
import { resolveAssessmentPresentation } from "./assessment-presentation.js";
import { CYBER_MOT_STATES } from "./cyber-mot-domains.js";
import {
  phase5EvidenceReadCoverage,
  projectPhase5ScanRowsForCustomer,
} from "./phase5-evidence.js";
import {
  buildDomainMatrix, CYBER_MOT_DOMAIN_KEYS, DOMAIN_TREND, EVIDENCE_FRESHNESS,
  evidenceFreshness, readPortfolioDomainStates,
} from "./cyber-mot-state-history.js";

// Open = not terminal. Reuses the canonical model's terminal list rather than declaring
// a fourth one — the repo already carries three that disagree (the partial unique index
// on managed_cases, the factory's dedupe filter, and CANONICAL_TERMINAL_STATES). This
// is the canonical one. `closed` is included because the legacy ASM/Brand machines emit
// it and it is terminal in both other lists; leaving it out would count closed cases as
// open on exactly the two most mature domains.
const TERMINAL_CASE_STATES = Object.freeze([...CANONICAL_TERMINAL_STATES, "closed"]);

// States that mean "we have a verdict and it is bad". Used ONLY to decide whether a
// domain contributes an attention reason — never to rank, colour or score.
const ATTENTION_STATES = new Set([CYBER_MOT_STATES.ISSUE_DETECTED]);
// States that mean "we do not know". These are attention-worthy for an MSP too: an
// unassessed customer is not a safe customer, they are an unlooked-at one.
const UNKNOWN_STATES = new Set([
  CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT,
  CYBER_MOT_STATES.NOT_YET_ASSESSED,
  CYBER_MOT_STATES.UNAVAILABLE,
]);

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const sevRank = (s) => SEV_RANK[String(s || "").toLowerCase()] ?? -1;

// Priority bands, published as a word plus the reasons behind it. This is NOT a score
// and deliberately not a 0-100 anything — it is an ordering with its evidence attached,
// so the MSP reads WHY a customer is first, not just that they are.
export const DOMAIN_PRIORITY = Object.freeze({
  CRITICAL: "critical", HIGH: "high", MEDIUM: "medium", LOW: "low", UNKNOWN: "unknown",
});
const PRIORITY_RANK = { critical: 0, high: 1, medium: 2, unknown: 3, low: 4 };

/**
 * summariseDomainRow(matrix, freshness) → { priority, attention_required, reasons[], counts }
 *
 * Derives the row's headline from the EIGHT domain entries — by worst-case and by
 * naming, never by averaging. Every reason is attributable to a specific domain.
 */
function summariseDomainRow(matrix, rowFreshness) {
  const reasons = [];
  let worstSeverity = null;

  const issues    = matrix.filter((d) => ATTENTION_STATES.has(d.state));
  const unknowns  = matrix.filter((d) => UNKNOWN_STATES.has(d.state));
  const worsening = matrix.filter((d) => d.trend === DOMAIN_TREND.WORSENING || d.trend === DOMAIN_TREND.NEW_RISK);
  const awaiting  = matrix.filter((d) => d.state === CYBER_MOT_STATES.CUSTOMER_INPUT_REQUIRED);
  const staleDoms = matrix.filter((d) => d.evidence_freshness === EVIDENCE_FRESHNESS.STALE);

  for (const d of issues) if (sevRank(d.highest_severity) > sevRank(worstSeverity)) worstSeverity = d.highest_severity;

  for (const d of issues) {
    reasons.push({
      domain_key: d.domain_key, kind: "issue_detected", severity: d.highest_severity,
      detail: `${d.display_name}: ${d.summary}`,
    });
  }
  for (const d of worsening) {
    reasons.push({
      domain_key: d.domain_key, kind: d.trend, severity: d.highest_severity,
      detail: `${d.display_name}: ${d.trend_reason}`,
    });
  }
  for (const d of staleDoms) {
    reasons.push({ domain_key: d.domain_key, kind: "evidence_stale", severity: null, detail: `${d.display_name}: ${d.freshness_reason}` });
  }
  for (const d of unknowns) {
    reasons.push({ domain_key: d.domain_key, kind: "evidence_unknown", severity: null, detail: `${d.display_name}: ${d.summary}` });
  }
  for (const d of awaiting) {
    reasons.push({ domain_key: d.domain_key, kind: "customer_input_required", severity: null, detail: `${d.display_name}: ${d.summary}` });
  }

  // Priority. Note what is deliberately absent: there is no path from "everything is
  // unknown" to LOW. A domain nobody has assessed cannot earn a low priority by being
  // quiet — that is green-by-absence with an ordering attached.
  let priority;
  if (sevRank(worstSeverity) >= 4)                                priority = DOMAIN_PRIORITY.CRITICAL;
  else if (sevRank(worstSeverity) === 3 || worsening.length)      priority = DOMAIN_PRIORITY.HIGH;
  else if (issues.length)                                          priority = DOMAIN_PRIORITY.MEDIUM;
  else if (unknowns.length === CYBER_MOT_DOMAIN_KEYS.length)       priority = DOMAIN_PRIORITY.UNKNOWN;
  else if (unknowns.length || staleDoms.length || rowFreshness.freshness === EVIDENCE_FRESHNESS.STALE)
                                                                   priority = DOMAIN_PRIORITY.UNKNOWN;
  else                                                             priority = DOMAIN_PRIORITY.LOW;

  return {
    priority,
    attention_required: priority !== DOMAIN_PRIORITY.LOW,
    highest_severity: worstSeverity,
    reasons,
    counts: {
      issue_detected: issues.length,
      worsening: worsening.length,
      unknown: unknowns.length,
      stale: staleDoms.length,
      customer_input_required: awaiting.length,
      assessed_healthy: matrix.filter((d) => d.state === CYBER_MOT_STATES.ASSESSED_HEALTHY).length,
    },
  };
}

/**
 * computePortfolioDomainRows(db, workspaceIds, { now })
 *
 * Returns ONE row per authorised (workspace, domain) with its full eight-domain matrix.
 * Every query is bound to `workspaceIds`, which the route has already resolved through
 * getAccessibleWorkspaceIds() — that is the tenant boundary, and it is the only one this
 * engine needs. Pure read.
 */
export async function computePortfolioDomainRows(db, workspaceIds, opts = {}) {
  if (!workspaceIds || workspaceIds.length === 0) return [];
  const now = opts.now ?? Date.now();
  const wsIn = workspaceIds.map(() => "?").join(",");

  const caseIn = TERMINAL_CASE_STATES.map(() => "?").join(",");

  const [domRes, stateSeries, caseRes, scanRes] = await Promise.all([
    // 1. The authorised domain records. Soft-deleted workspaces are excluded here too,
    //    belt-and-braces: getAccessibleWorkspaceIds already filters them, but that is an
    //    implicit contract and this row is the thing the customer sees.
    db.prepare(
      `SELECT wd.workspace_id, wd.domain_id, d.domain AS hostname,
              w.name AS workspace_name,
              wd.verification_status, wd.verified_at
       FROM workspace_domains wd
       JOIN workspaces w ON w.id = wd.workspace_id AND w.deleted_at IS NULL
       JOIN domains d ON d.id = wd.domain_id
       WHERE wd.workspace_id IN (${wsIn})`
    ).bind(...workspaceIds).all(),

    // 2. The eight states + their comparable predecessors. Two queries, whole portfolio.
    readPortfolioDomainStates(db, workspaceIds),

    // 3. Open managed cases per (workspace, domain_key, hostname). Workspace-scoped, so
    //    a hostname match can never reach another tenant's case. managed_cases carries a
    //    hostname (`domain`) and a `domain_key`, but no domain_id — matching on the
    //    hostname WITHIN the tenant is the only link available, and it is safe because
    //    the workspace filter is applied first.
    db.prepare(
      `SELECT workspace_id, domain_key, domain AS hostname, COUNT(*) AS n
       FROM managed_cases
       WHERE workspace_id IN (${wsIn})
         AND status NOT IN (${caseIn})
       GROUP BY workspace_id, domain_key, domain`
    ).bind(...workspaceIds, ...TERMINAL_CASE_STATES).all(),

    // 4. The overall score/rating of the latest COMPLETE scan per (workspace, domain).
    //    scan_quality='complete' only — a partial scan never establishes a rating
    //    (partial-scan honesty); the row still renders, with no score and a reason.
    db.prepare(
      `SELECT workspace_id, domain_id, scan_id, score, rating, scan_quality, created_at
       FROM (
         SELECT wd.workspace_id, s.domain_id, s.id AS scan_id, s.score, s.rating,
                s.scan_quality, s.created_at,
                ROW_NUMBER() OVER (
                  PARTITION BY wd.workspace_id, s.domain_id
                  ORDER BY s.created_at DESC, s.id DESC
                ) AS rn
         FROM scans s
         JOIN workspace_domains wd ON wd.domain_id = s.domain_id
         WHERE wd.workspace_id IN (${wsIn})
           AND s.status = 'completed' AND s.scan_quality = 'complete'
       ) WHERE rn = 1`
    ).bind(...workspaceIds).all(),
  ]);

  const caseMap = new Map();   // ws::hostname::domain_key → n
  for (const c of (caseRes.results || [])) {
    caseMap.set(`${c.workspace_id}::${c.hostname ?? ""}::${c.domain_key ?? ""}`, Number(c.n) || 0);
  }
  const customerScanRows = await projectPhase5ScanRowsForCustomer(
    opts.env,
    (scanRes.results || []).map((row) => ({
      ...row,
      id: row.scan_id,
      status: "completed",
    })),
  );
  const scanMap = new Map();
  for (const s of customerScanRows) scanMap.set(`${s.workspace_id}::${s.domain_id}`, s);

  const rows = (domRes.results || []).map((d) => {
    const key = `${d.workspace_id}::${d.domain_id}`;
    const matrix = buildDomainMatrix(stateSeries.get(key), now);
    const scan = scanMap.get(key) || null;

    // Row-level freshness = the most recent assessment behind ANY of the eight. The
    // eight always come from one scan today, but the row must not assume that.
    const lastAssessed = matrix.reduce((acc, m) => {
      if (!m.last_assessed_at) return acc;
      return !acc || m.last_assessed_at > acc ? m.last_assessed_at : acc;
    }, null);
    const fresh = evidenceFreshness(lastAssessed, now);

    // Per-domain open-case counts, attributed to this hostname within this tenant.
    let openCases = 0;
    const matrixWithCases = matrix.map((m) => {
      const n = caseMap.get(`${d.workspace_id}::${d.hostname}::${m.domain_key}`) ?? 0;
      openCases += n;
      return { ...m, open_case_count: n };
    });

    const summary = summariseDomainRow(matrixWithCases, fresh);

    // Overall score/rating comes from the canonical presentation resolver — the same
    // decision the Dashboard, Scorecard and PDF render. This engine does not own a band
    // ladder and must never grow one.
    const domainCoverageLimited = matrixWithCases.some((entry) =>
      ["partial", "degraded", "unknown"].includes(String(entry.coverage || "").toLowerCase())
    );
    const presentation = resolveAssessmentPresentation({
      score: scan?.score ?? null,
      scanQuality:
        scan?.scan_quality === "complete" && domainCoverageLimited
          ? "degraded"
          : (scan?.scan_quality ?? null),
      status: scan ? "completed" : null,
    });

    return {
      workspace_id: d.workspace_id,
      workspace_name: d.workspace_name,
      domain_id: d.domain_id,
      hostname: d.hostname,
      domain_verification_status: d.verification_status ?? "unverified",
      domain_verified_at: d.verified_at ?? null,

      // Overall posture — sayable only from a complete assessment.
      overall_score: presentation.display_score,
      overall_rating: presentation.display_rating,
      overall_state: scan ? (presentation.authoritative ? "established" : "provisional") : "not_established",
      overall_reason: scan ? presentation.message : "No completed assessment has established a posture for this domain yet.",

      // Evidence quality, as its own dimension — never folded into the state.
      last_assessed_at: lastAssessed,
      evidence_freshness: fresh.freshness,
      evidence_age_days: fresh.age_days,
      freshness_reason: fresh.reason,
      evidence_completeness: matrix.filter((m) => m.state !== CYBER_MOT_STATES.NOT_YET_ASSESSED).length,
      latest_scan_id: scan?.scan_id ?? matrix.find((m) => m.source_scan_id)?.source_scan_id ?? null,
      latest_scan_quality: scan?.scan_quality ?? null,
      phase5_evidence_read: scan?.phase5_evidence_read ?? null,
      phase5_assessment: scan?.assessment ?? null,

      priority: summary.priority,
      attention_required: summary.attention_required,
      highest_severity: summary.highest_severity,
      attention_reasons: summary.reasons,
      domain_state_counts: summary.counts,
      open_case_count: openCases,

      // Always exactly eight, in canonical order.
      cyber_mot_domains: matrixWithCases,

      // Drill-down. Ids the caller has already proved access to — never a hostname
      // lookup, which would reintroduce the existence oracle the domain routes close.
      drill_down: {
        workspace_id: d.workspace_id,
        domain_id: d.domain_id,
        scan_id: scan?.scan_id ?? null,
      },
    };
  });

  Object.defineProperty(rows, "phase5_evidence_coverage", {
    value: phase5EvidenceReadCoverage(customerScanRows),
    enumerable: false,
  });
  return rows;
}

// ── Deterministic ordering ───────────────────────────────────────────────────
// Every comparator ends in a total tie-break on (workspace_id, domain_id), so the same
// portfolio always paginates the same way. Without it, page 2 can repeat or skip a row
// that page 1 already showed.
const tieBreak = (a, b) =>
  a.workspace_id.localeCompare(b.workspace_id) || a.domain_id.localeCompare(b.domain_id);

const SORTERS = {
  priority: (a, b) =>
    (PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority]) ||
    (sevRank(b.highest_severity) - sevRank(a.highest_severity)) ||
    (b.domain_state_counts.issue_detected - a.domain_state_counts.issue_detected) ||
    tieBreak(a, b),
  worsening: (a, b) =>
    (b.domain_state_counts.worsening - a.domain_state_counts.worsening) ||
    (PRIORITY_RANK[a.priority] - PRIORITY_RANK[b.priority]) || tieBreak(a, b),
  severity: (a, b) => (sevRank(b.highest_severity) - sevRank(a.highest_severity)) || tieBreak(a, b),
  // Lowest score first (worst customer first). A null score sorts AFTER every real one
  // rather than being treated as 0 (which would fake a crisis) or 100 (which would fake
  // an all-clear) — it is simply not a score, and it lands with the other unknowns.
  score: (a, b) => {
    const an = a.overall_score == null, bn = b.overall_score == null;
    if (an && bn) return tieBreak(a, b);
    if (an) return 1;
    if (bn) return -1;
    return (a.overall_score - b.overall_score) || tieBreak(a, b);
  },
  // Stalest first; "never assessed" (null age) is the stalest thing there is.
  freshness: (a, b) => {
    const an = a.evidence_age_days == null, bn = b.evidence_age_days == null;
    if (an && bn) return tieBreak(a, b);
    if (an) return -1;
    if (bn) return 1;
    return (b.evidence_age_days - a.evidence_age_days) || tieBreak(a, b);
  },
  cases: (a, b) => (b.open_case_count - a.open_case_count) || tieBreak(a, b),
  customer: (a, b) => (a.workspace_name || "").localeCompare(b.workspace_name || "") || tieBreak(a, b),
  domain: (a, b) => (a.hostname || "").localeCompare(b.hostname || "") || tieBreak(a, b),
};
export const PORTFOLIO_SORTS = Object.freeze(Object.keys(SORTERS));

const FILTERS = {
  attention:  (r) => r.attention_required,
  worsening:  (r) => r.domain_state_counts.worsening > 0,
  stale:      (r) => r.evidence_freshness === EVIDENCE_FRESHNESS.STALE,
  unknown:    (r) => r.domain_state_counts.unknown > 0,
  incomplete: (r) => r.latest_scan_quality !== "complete",
  cases:      (r) => r.open_case_count > 0,
};
export const PORTFOLIO_FILTERS = Object.freeze(Object.keys(FILTERS));

/**
 * applyPortfolioView(rows, { filter, domainKey, state, sort, limit, offset })
 * Pure. Filter → sort → page, in that order, so `total` is the count of the FILTERED
 * set and paginating never changes it.
 */
export function applyPortfolioView(rows, opts = {}) {
  let out = rows;
  if (opts.filter && FILTERS[opts.filter]) out = out.filter(FILTERS[opts.filter]);
  if (opts.domainKey && CYBER_MOT_DOMAIN_KEYS.includes(opts.domainKey)) {
    const st = opts.state;
    out = out.filter((r) => {
      const d = r.cyber_mot_domains.find((x) => x.domain_key === opts.domainKey);
      return d && (!st || d.state === st);
    });
  }
  const sorter = SORTERS[opts.sort] || SORTERS.priority;
  out = [...out].sort(sorter);
  const total = out.length;
  const limit = opts.limit ?? 25, offset = opts.offset ?? 0;
  return { rows: out.slice(offset, offset + limit), total };
}

/**
 * buildPortfolioDomainSummary(rows)
 *
 * Portfolio headline. Counts, never a mean: there is deliberately no portfolio-wide
 * score here. `total_domains` and the band counts reconcile EXACTLY with the authorised
 * rows the caller can page through — the summary is a fold of the same array, not a
 * separate query that could disagree with it.
 */
export function buildPortfolioDomainSummary(rows) {
  const byPriority = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const r of rows) byPriority[r.priority]++;

  // Per-domain-key rollup across the portfolio — all eight, always.
  const by_domain = CYBER_MOT_DOMAIN_KEYS.map((key) => {
    const cells = rows.map((r) => r.cyber_mot_domains.find((d) => d.domain_key === key)).filter(Boolean);
    const count = (fn) => cells.filter(fn).length;
    return {
      domain_key: key,
      display_name: cells[0]?.display_name ?? key,
      issue_detected:  count((d) => d.state === CYBER_MOT_STATES.ISSUE_DETECTED),
      assessed_healthy: count((d) => d.state === CYBER_MOT_STATES.ASSESSED_HEALTHY),
      unknown:         count((d) => UNKNOWN_STATES.has(d.state)),
      customer_input_required: count((d) => d.state === CYBER_MOT_STATES.CUSTOMER_INPUT_REQUIRED),
      worsening: count((d) => d.trend === DOMAIN_TREND.WORSENING || d.trend === DOMAIN_TREND.NEW_RISK),
      improving: count((d) => d.trend === DOMAIN_TREND.IMPROVING || d.trend === DOMAIN_TREND.RECOVERED),
      stale:     count((d) => d.evidence_freshness === EVIDENCE_FRESHNESS.STALE),
      open_cases: cells.reduce((s, d) => s + (d.open_case_count || 0), 0),
    };
  });

  const assessed = rows.filter((r) => r.last_assessed_at != null).length;

  return {
    total_domains: rows.length,
    total_customers: new Set(rows.map((r) => r.workspace_id)).size,
    assessed_domains: assessed,
    unassessed_domains: rows.length - assessed,
    attention_required: rows.filter((r) => r.attention_required).length,
    stale_domains: rows.filter((r) => r.evidence_freshness === EVIDENCE_FRESHNESS.STALE).length,
    worsening_domains: rows.filter((r) => r.domain_state_counts.worsening > 0).length,
    open_cases: rows.reduce((s, r) => s + r.open_case_count, 0),
    priority_distribution: byPriority,
    by_domain,
    // No portfolio-wide score. Eight domains across N customers do not have a mean that
    // means anything, and the one thing a blended number reliably does is hide the one
    // customer who needs you. The counts above are the headline.
    coverage_note: assessed === rows.length
      ? null
      : `${rows.length - assessed} of ${rows.length} monitored domain${rows.length === 1 ? " has" : "s have"} no completed assessment and ${rows.length - assessed === 1 ? "is" : "are"} not represented in the state counts above.`,
  };
}
