// ── Canonical per-domain Cyber MOT state history: writer, reader, trend ───────
// The persistence layer for engines/cyber-mot-domains.js. It adds NO state semantics
// of its own — resolveCyberMotDomainStates() decides what state a domain is in, this
// module records what it decided and, later, compares two recordings.
//
// Three jobs, deliberately in one file because they share one contract:
//   1. persistCyberMotDomainStates() — write, at scan finalize, from the report in hand.
//   2. readPortfolioDomainStates()   — read the current eight per domain, D1 only.
//   3. resolveDomainTrend()          — compare two recordings, honestly.
//
// What this module must never become: a second opinion about domain state. If you find
// yourself writing `if (state === ...)` to DERIVE a state here, it belongs in the
// resolver instead. The only classification this file owns is TREND (a fact about two
// states over time, which the resolver cannot see) and FRESHNESS (a fact about the
// clock, which the resolver deliberately does not consult).

import {
  CYBER_MOT_DOMAINS,
  CYBER_MOT_RESOLVER_VERSION,
  CYBER_MOT_STATES,
  resolveCyberMotDomainStates,
} from "./cyber-mot-domains.js";
import { createId } from "../lib/util.js";

// ── Trend vocabulary ─────────────────────────────────────────────────────────
// Separate from CYBER_MOT_STATES on purpose. "Current critical, improving" and "current
// good, worsening" are both real and both sayable; collapsing state and trend into one
// word is how a portfolio starts lying. A domain always has both, and they never
// substitute for each other.
export const DOMAIN_TREND = Object.freeze({
  IMPROVING:            "improving",
  STABLE:               "stable",
  WORSENING:            "worsening",
  NEW_RISK:             "new_risk",
  RECOVERED:            "recovered",
  INSUFFICIENT_HISTORY: "insufficient_history",
  NOT_COMPARABLE:       "not_comparable",
});

// ── Evidence freshness ───────────────────────────────────────────────────────
// The resolver has no clock — a `complete` scan from 2019 resolves to assessed_healthy
// with full confidence, because coverage and age are different questions and it only
// answers the first. That is defensible for a Dashboard the customer opens right after
// scanning. It is not defensible for a portfolio, where the whole job is "which of my
// 40 customers has nobody looked at lately".
//
// So freshness is computed HERE, at read time, against assessed_at — an orthogonal
// dimension published ALONGSIDE the resolver's state, never folded into it. The state
// stays the resolver's word; the age stays a fact about the clock; the UI shows both,
// and a stale healthy can never read as a current all-clear.
//
// 45 days matches the three existing lifecycle staleness constants
// (STALE_EVIDENCE_DAYS, IDENTITY_STALE_EVIDENCE_DAYS, CERT_STALE_EVIDENCE_DAYS), which
// are three copies of 45 in three engines. This is a fourth, and it is named and
// exported so the eventual unification has something to unify.
export const FRESHNESS_AGING_DAYS = 14;
export const FRESHNESS_STALE_DAYS = 45;

export const EVIDENCE_FRESHNESS = Object.freeze({
  CURRENT: "current",
  AGING:   "aging",
  STALE:   "stale",
  NONE:    "none",
});

const DAY_MS = 24 * 60 * 60 * 1000;

const parseTs = (t) => {
  if (!t) return null;
  const s = String(t);
  const ms = Date.parse(s.includes("T") ? s : s.replace(" ", "T") + "Z");
  return Number.isFinite(ms) ? ms : null;
};

/**
 * evidenceFreshness(assessedAt, now) → { freshness, age_days, reason }
 * No evidence is `none`, never `current`. An unparseable timestamp is `none` too —
 * a date we cannot read is not a date we may call fresh.
 */
export function evidenceFreshness(assessedAt, now = Date.now()) {
  const ts = parseTs(assessedAt);
  if (ts == null) {
    return { freshness: EVIDENCE_FRESHNESS.NONE, age_days: null, reason: "No assessment has been recorded for this domain yet." };
  }
  const age = Math.max(0, Math.floor((now - ts) / DAY_MS));
  if (age > FRESHNESS_STALE_DAYS) {
    return { freshness: EVIDENCE_FRESHNESS.STALE, age_days: age, reason: `Last assessed ${age} days ago — this evidence is stale and may no longer reflect the current posture.` };
  }
  if (age > FRESHNESS_AGING_DAYS) {
    return { freshness: EVIDENCE_FRESHNESS.AGING, age_days: age, reason: `Last assessed ${age} days ago.` };
  }
  return { freshness: EVIDENCE_FRESHNESS.CURRENT, age_days: age, reason: `Last assessed ${age === 0 ? "today" : age === 1 ? "yesterday" : `${age} days ago`}.` };
}

// ── State severity ordering, for trend direction only ────────────────────────
// This is NOT a risk ladder and must never be shown to a customer as one. It answers
// exactly one internal question: "is B a worse ANSWER than A?" — and only for the two
// states that carry a verdict. Every non-verdict state (unknown, insufficient, awaiting
// input, monitoring) is deliberately OUTSIDE the ordering, because moving between
// "we found a problem" and "we could not look" is not an improvement or a regression in
// the customer's posture. It is a change in OUR evidence, and the trend says so by name
// rather than by direction.
const VERDICT_RANK = {
  [CYBER_MOT_STATES.ASSESSED_HEALTHY]: 0,
  [CYBER_MOT_STATES.ISSUE_DETECTED]:   1,
};
const isVerdict = (s) => Object.prototype.hasOwnProperty.call(VERDICT_RANK, s);

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const sevRank = (s) => SEV_RANK[String(s || "").toLowerCase()] ?? -1;

const parseIds = (json) => {
  try {
    const v = JSON.parse(json || "[]");
    return Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
  } catch { return []; }
};

/**
 * resolveDomainTrend(current, previous) → { trend, trend_reason, ... }
 *
 * The contract, stated as refusals — every one of these is a way a trend lies:
 *   • No previous comparable row        → insufficient_history. NEVER stable.
 *   • Either side not scan_quality complete → not_comparable. A partial scan is not an
 *     improvement, and a failed one is not a recovery.
 *   • resolver_version differs          → not_comparable. WE changed, they did not.
 *   • Evidence disappeared (verdict → unknown/insufficient) → not_comparable, NEVER
 *     recovered. A rule that stopped running is not a problem that got fixed.
 *   • Both sides identical              → stable, and only then.
 *
 * `current` and `previous` are rows from cyber_mot_domain_states (previous may be null).
 */
export function resolveDomainTrend(current, previous) {
  const none = (trend, reason) => ({
    trend, trend_reason: reason, trend_window_days: null,
    compared_scan_id: null, previous_state: null, previous_assessed_at: null,
    new_finding_ids: [], resolved_finding_ids: [],
  });

  if (!current) return none(DOMAIN_TREND.INSUFFICIENT_HISTORY, "No assessment has been recorded for this domain yet.");
  if (!previous) return none(DOMAIN_TREND.INSUFFICIENT_HISTORY, "Only one assessment has been recorded — a trend needs at least two comparable assessments.");

  // Comparability, before any comparison. Both sides must be authoritative.
  if (current.scan_quality !== "complete" || previous.scan_quality !== "complete") {
    return none(DOMAIN_TREND.NOT_COMPARABLE, "The most recent assessments did not both complete, so no trend can be established from them.");
  }
  // The version gate. This is the whole reason resolver_version exists: without it, a
  // change to a match() regex or a required[] list reads as every customer's domain
  // deteriorating on the day we deployed.
  if (current.resolver_version !== previous.resolver_version) {
    return none(DOMAIN_TREND.NOT_COMPARABLE, "The way this domain is assessed changed between these two assessments, so the difference would not describe a change in your security posture.");
  }

  const windowDays = (() => {
    const a = parseTs(current.assessed_at), b = parseTs(previous.assessed_at);
    return a != null && b != null ? Math.max(0, Math.round((a - b) / DAY_MS)) : null;
  })();

  const curIds = parseIds(current.finding_ids_json);
  const prevIds = parseIds(previous.finding_ids_json);
  const prevSet = new Set(prevIds), curSet = new Set(curIds);
  const newIds = curIds.filter((i) => !prevSet.has(i));
  const goneIds = prevIds.filter((i) => !curSet.has(i));

  const base = {
    trend_window_days: windowDays,
    compared_scan_id: previous.scan_id,
    previous_state: previous.state,
    previous_assessed_at: previous.assessed_at,
    new_finding_ids: newIds,
    resolved_finding_ids: goneIds,
  };
  const out = (trend, reason) => ({ trend, trend_reason: reason, ...base });

  const curVerdict = isVerdict(current.state), prevVerdict = isVerdict(previous.state);

  // Evidence appeared or disappeared. Either direction is a change in what WE could
  // see, not in what THEY did — so it is named, never pointed up or down.
  if (!curVerdict || !prevVerdict) {
    if (curVerdict && !prevVerdict) {
      return out(DOMAIN_TREND.NOT_COMPARABLE, `This domain could not be assessed previously (${previous.state}), so there is nothing to compare this assessment against.`);
    }
    if (!curVerdict && prevVerdict) {
      // The important one. previous=issue_detected, current=evidence_insufficient must
      // NEVER read as recovered — the issue may be sitting there unobserved.
      return out(DOMAIN_TREND.NOT_COMPARABLE, `This domain could not be assessed in the latest scan (${current.state}); the previous result is not evidence that it has been resolved.`);
    }
    // Neither side carried a verdict (e.g. monitoring_only → monitoring_only).
    return current.state === previous.state
      ? out(DOMAIN_TREND.STABLE, `Unchanged since the previous assessment (${current.state}).`)
      : out(DOMAIN_TREND.NOT_COMPARABLE, `This domain moved between two states that carry no verdict (${previous.state} → ${current.state}).`);
  }

  // Both sides carry a verdict — a real comparison is possible.
  const curRank = VERDICT_RANK[current.state], prevRank = VERDICT_RANK[previous.state];

  if (prevRank === 0 && curRank === 1) {
    return out(DOMAIN_TREND.NEW_RISK, newIds.length
      ? `A new issue was detected that was not present in the previous assessment (${newIds.join(", ")}).`
      : "An issue was detected that was not present in the previous assessment.");
  }
  if (prevRank === 1 && curRank === 0) {
    return out(DOMAIN_TREND.RECOVERED, goneIds.length
      ? `Previously detected issues are no longer observed (${goneIds.join(", ")}).`
      : "The previously detected issue is no longer observed.");
  }
  if (prevRank === 0 && curRank === 0) {
    return out(DOMAIN_TREND.STABLE, "No material issue observed in either assessment.");
  }

  // Both issue_detected — the interesting case. Direction comes from the evidence SET
  // and the severity, never from a count alone.
  const sevNow = sevRank(current.highest_severity), sevPrev = sevRank(previous.highest_severity);
  if (sevNow > sevPrev) {
    return out(DOMAIN_TREND.WORSENING, `The most severe outstanding issue is now ${current.highest_severity} (previously ${previous.highest_severity || "unknown"}).`);
  }
  if (sevNow < sevPrev) {
    return out(DOMAIN_TREND.IMPROVING, `The most severe outstanding issue is now ${current.highest_severity} (previously ${previous.highest_severity || "unknown"}).`);
  }
  if (newIds.length && !goneIds.length) {
    return out(DOMAIN_TREND.WORSENING, `${newIds.length} additional issue${newIds.length === 1 ? "" : "s"} detected since the previous assessment (${newIds.join(", ")}).`);
  }
  if (goneIds.length && !newIds.length) {
    return out(DOMAIN_TREND.IMPROVING, `${goneIds.length} issue${goneIds.length === 1 ? "" : "s"} resolved since the previous assessment (${goneIds.join(", ")}).`);
  }
  if (newIds.length && goneIds.length) {
    return out(DOMAIN_TREND.WORSENING, `The outstanding issues changed since the previous assessment (${newIds.length} new, ${goneIds.length} resolved) at the same severity.`);
  }
  return out(DOMAIN_TREND.STABLE, "The same issues are outstanding as in the previous assessment.");
}

/**
 * persistCyberMotDomainStates(env, { workspaceId, domainId, scanId, report, cyberEssentials, assessedAt })
 *
 * Writes the eight resolved states for one completed scan. Called ONCE, from the scan
 * finalize path, with the report already in memory — so it costs zero R2 reads and the
 * portfolio costs zero R2 reads forever after.
 *
 * Never throws: the caller is the scan-completion path, and a state-history failure
 * must never turn a completed scan into a failed one. A missing row is honest
 * (not_yet_assessed); a scan that dies at the last step to record a cache is not.
 *
 * Idempotent: INSERT OR IGNORE against UNIQUE(workspace_id, domain_id, scan_id,
 * domain_key), so a re-finalize or a reconciler re-run adds nothing.
 *
 * @returns {Promise<{written:number, skipped:string|null}>}
 */
export async function persistCyberMotDomainStates(env, opts = {}) {
  const { workspaceId, domainId, scanId, report, cyberEssentials = null, assessedAt = null } = opts;

  // Fail closed, quietly. Without a tenant + domain-record + scan identity the row
  // could not be scoped, compared or purged — so it is not written at all.
  if (!workspaceId || !domainId || !scanId) return { written: 0, skipped: "missing_identity" };
  if (!report) return { written: 0, skipped: "no_report" };

  try {
    const states = resolveCyberMotDomainStates(report, { scanId, cyberEssentials });
    const quality = report?.scan_quality?.status ?? null;
    const at = assessedAt || report?.completed_at || report?.created_at || new Date().toISOString();

    const stmt = env.cybermeters_db.prepare(
      `INSERT OR IGNORE INTO cyber_mot_domain_states
         (id, workspace_id, domain_id, scan_id, domain_key, state, coverage, summary,
          highest_severity, finding_count, evidence_count, finding_ids_json,
          scan_quality, resolver_version, assessed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const rows = states.map((d) => stmt.bind(
      createId("cmds"), workspaceId, domainId, scanId, d.domain_key,
      d.state, d.coverage ?? null, d.summary ?? null,
      d.highest_severity ?? null, d.finding_count ?? 0, d.evidence_count ?? 0,
      JSON.stringify(d.finding_ids ?? []),
      quality, CYBER_MOT_RESOLVER_VERSION, at,
    ));

    // One batch: eight rows land together or not at all. Falls back to sequential
    // inserts where batch() is unavailable.
    if (typeof env.cybermeters_db.batch === "function") {
      await env.cybermeters_db.batch(rows);
    } else {
      for (const r of rows) await r.run();
    }
    return { written: states.length, skipped: null };
  } catch {
    return { written: 0, skipped: "write_failed" };
  }
}

// The canonical eight, in fixed order, for callers that must render all of them.
export const CYBER_MOT_DOMAIN_KEYS = Object.freeze(CYBER_MOT_DOMAINS.map((d) => d.domain_key));
const DOMAIN_META = Object.freeze(Object.fromEntries(
  CYBER_MOT_DOMAINS.map((d) => [d.domain_key, { display_name: d.display_name, description: d.description, maturity: d.maturity, managed_status: d.managed_status, limitations: d.limitations }]),
));

/**
 * readPortfolioDomainStates(db, workspaceIds) → Map<`${ws}::${domainId}`, {current, previous}>
 *
 * TWO D1 queries for the WHOLE portfolio, regardless of domain count — the property
 * this table exists for. No R2. No per-domain query. No N+1.
 *
 * Returns the latest row per (workspace, domain, domain_key) and the latest COMPARABLE
 * predecessor for the trend. Scoped by workspace_id IN (...) — the caller has already
 * resolved that list through getAccessibleWorkspaceIds(), which is the tenant boundary.
 */
export async function readPortfolioDomainStates(db, workspaceIds) {
  const out = new Map();
  if (!workspaceIds || workspaceIds.length === 0) return out;
  const wsIn = workspaceIds.map(() => "?").join(",");

  // rn=1 → current (any quality: a provisional latest must show AS provisional, not be
  // hidden behind an older complete one).
  const currentRes = await db.prepare(
    `SELECT * FROM (
       SELECT *, ROW_NUMBER() OVER (
         PARTITION BY workspace_id, domain_id, domain_key
         ORDER BY assessed_at DESC, created_at DESC, id DESC
       ) AS rn
       FROM cyber_mot_domain_states
       WHERE workspace_id IN (${wsIn})
     ) WHERE rn = 1`
  ).bind(...workspaceIds).all();

  // The trend baseline: the two most recent COMPLETE rows per series. Restricting to
  // complete here is the same rule every other baseline in the codebase uses
  // (historical-scan.js, posture-events.js, current-posture.js, portfolio-customers.js)
  // — a partial/degraded/unknown predecessor is never a comparable baseline.
  const compRes = await db.prepare(
    `SELECT * FROM (
       SELECT *, ROW_NUMBER() OVER (
         PARTITION BY workspace_id, domain_id, domain_key
         ORDER BY assessed_at DESC, created_at DESC, id DESC
       ) AS rn
       FROM cyber_mot_domain_states
       WHERE workspace_id IN (${wsIn}) AND scan_quality = 'complete'
     ) WHERE rn <= 2`
  ).bind(...workspaceIds).all();

  const comparable = new Map(); // series → [newest, previous]
  for (const r of (compRes.results || [])) {
    const k = `${r.workspace_id}::${r.domain_id}::${r.domain_key}`;
    (comparable.get(k) ?? comparable.set(k, []).get(k)).push(r);
  }
  for (const list of comparable.values()) list.sort((a, b) => a.rn - b.rn);

  for (const cur of (currentRes.results || [])) {
    const seriesKey = `${cur.workspace_id}::${cur.domain_id}::${cur.domain_key}`;
    const comp = comparable.get(seriesKey) || [];
    // The predecessor is the newest COMPLETE row that is not the current row itself.
    // When the current row is provisional, comp[0] is an older complete row — and it is
    // not a predecessor of anything, so there is no trend. resolveDomainTrend's quality
    // gate catches that: it compares `current` (provisional) and returns not_comparable.
    const previous = comp.find((r) => r.scan_id !== cur.scan_id) || null;
    const domKey = `${cur.workspace_id}::${cur.domain_id}`;
    if (!out.has(domKey)) out.set(domKey, { workspace_id: cur.workspace_id, domain_id: cur.domain_id, domains: new Map() });
    out.get(domKey).domains.set(cur.domain_key, { current: cur, previous });
  }
  return out;
}

/**
 * readDomainStateHistory(db, workspaceId, domainId, { limit }) → per-domain_key series.
 *
 * The honest series behind a trend: every recorded state for this domain record, newest
 * first, each carrying the resolver_version and scan_quality that decide whether it may
 * be compared to its neighbour. The caller has already proved workspace access; the
 * query is bound to (workspace_id, domain_id) regardless, so a domain_id from another
 * tenant returns nothing rather than another tenant's history.
 */
export async function readDomainStateHistory(db, workspaceId, domainId, opts = {}) {
  const limit = opts.limit ?? 20;
  const res = await db.prepare(
    `SELECT domain_key, state, coverage, summary, highest_severity, finding_count,
            scan_quality, resolver_version, scan_id, assessed_at
     FROM cyber_mot_domain_states
     WHERE workspace_id = ? AND domain_id = ?
     ORDER BY assessed_at DESC, created_at DESC, id DESC
     LIMIT ?`
  ).bind(workspaceId, domainId, limit * CYBER_MOT_DOMAIN_KEYS.length).all();

  const out = Object.fromEntries(CYBER_MOT_DOMAIN_KEYS.map((k) => [k, []]));
  for (const r of (res.results || [])) {
    if (!out[r.domain_key]) continue;
    if (out[r.domain_key].length >= limit) continue;
    out[r.domain_key].push({
      state: r.state, coverage: r.coverage, summary: r.summary,
      highest_severity: r.highest_severity, finding_count: r.finding_count,
      scan_quality: r.scan_quality, resolver_version: r.resolver_version,
      scan_id: r.scan_id, assessed_at: r.assessed_at,
      // Published so a reader can see WHY two adjacent points were not compared,
      // rather than inferring it from a gap.
      comparable: r.scan_quality === "complete" && r.resolver_version === CYBER_MOT_RESOLVER_VERSION,
    });
  }
  return out;
}

/**
 * buildDomainMatrix(series, now) → exactly EIGHT entries, in canonical order, always.
 *
 * A domain with no row is not omitted and is not green — it is not_yet_assessed with a
 * reason. lib/cyberMotDisplay.js already guarantees eight on the frontend; this
 * guarantees eight from the API, so the two cannot disagree about what is missing.
 */
export function buildDomainMatrix(series, now = Date.now()) {
  const byKey = series?.domains ?? new Map();
  return CYBER_MOT_DOMAIN_KEYS.map((key) => {
    const meta = DOMAIN_META[key];
    const entry = byKey.get(key);
    if (!entry?.current) {
      return {
        domain_key: key, display_name: meta.display_name, description: meta.description,
        state: CYBER_MOT_STATES.NOT_YET_ASSESSED,
        summary: "Not yet assessed — no completed assessment has recorded a state for this domain.",
        coverage: null, highest_severity: null, finding_count: 0, evidence_count: 0,
        last_assessed_at: null, evidence_freshness: EVIDENCE_FRESHNESS.NONE,
        evidence_age_days: null, freshness_reason: "No assessment has been recorded for this domain yet.",
        trend: DOMAIN_TREND.INSUFFICIENT_HISTORY,
        trend_reason: "No assessment has been recorded for this domain yet.",
        trend_window_days: null, compared_scan_id: null, previous_state: null,
        new_finding_ids: [], resolved_finding_ids: [],
        source_scan_id: null, resolver_version: null,
        maturity: meta.maturity, managed_status: meta.managed_status, limitations: [...meta.limitations],
      };
    }
    const cur = entry.current;
    const fresh = evidenceFreshness(cur.assessed_at, now);
    const trend = resolveDomainTrend(cur, entry.previous);
    return {
      domain_key: key, display_name: meta.display_name, description: meta.description,
      state: cur.state, summary: cur.summary, coverage: cur.coverage,
      highest_severity: cur.highest_severity,
      finding_count: cur.finding_count ?? 0, evidence_count: cur.evidence_count ?? 0,
      last_assessed_at: cur.assessed_at,
      evidence_freshness: fresh.freshness, evidence_age_days: fresh.age_days, freshness_reason: fresh.reason,
      trend: trend.trend, trend_reason: trend.trend_reason,
      trend_window_days: trend.trend_window_days, compared_scan_id: trend.compared_scan_id,
      previous_state: trend.previous_state,
      new_finding_ids: trend.new_finding_ids, resolved_finding_ids: trend.resolved_finding_ids,
      source_scan_id: cur.scan_id, resolver_version: cur.resolver_version,
      maturity: meta.maturity, managed_status: meta.managed_status, limitations: [...meta.limitations],
    };
  });
}
