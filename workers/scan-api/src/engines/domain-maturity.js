// ── Canonical per-workspace eight-domain maturity ledger (M5.f) ───────────────
// ONE deterministic, auditable answer to: "how deep is the honest, evidenced managed
// control this workspace has for each of the eight canonical Cyber MOT domains?"
//
// Maturity is the lifecycle distance travelled — from "not reliably observed" toward
// "fixed, CyberMeters-verified and under recurrence watch". It is:
//   • DETERMINISTIC — a pure function of already-canonical inputs. No AI, no heuristics.
//   • DERIVED, never a second opinion. Domain STATE comes only from
//     resolveCyberMotDomainStates (engines/cyber-mot-domains.js). Lifecycle progress
//     comes only from managed_cases (status + verification_support + reopened_count).
//     Verification CAPABILITY comes only from the Canonical Remediation Registry.
//   • FLOORED by evidence honesty — missing / failed / partial / unavailable evidence is
//     never mature; a non-complete scan produces NO row at all.
//   • CAPPED by platform capability — a domain the registry says CyberMeters cannot
//     re-observe can never reach the verified/monitored stages (only attested/managed).
//
// It is NOT the score (posture goodness), NOT risk severity, NOT the domain state, NOT a
// finding count. A clean domain scores high yet sits at `observed` — nothing entered the
// managed lifecycle, and that is honest.
//
// This module adds NO domain-state semantics. If you find yourself deciding a domain's
// STATE here, it belongs in the resolver. This module only decides lifecycle DEPTH on top
// of a state the resolver already decided.

import { createId } from "../lib/util.js";
import {
  CYBER_MOT_DOMAINS,
  CYBER_MOT_RESOLVER_VERSION,
  resolveCyberMotDomainStates,
} from "./cyber-mot-domains.js";
import { REMEDIATION_REGISTRY } from "./remediation-registry.js";
import { verificationSupportForCase, verificationSupportForMethod } from "./managed-case-model.js";

// Bump when the determination algorithm, the stage ladder, or the capability-ceiling
// derivation changes — so a maturity change caused by a definition change can never read
// as the customer's doing. Compared alongside resolver_version: two rows are comparable
// only when BOTH versions match (the 091 trend doctrine).
export const MATURITY_LEDGER_CONTRACT_VERSION = "2026-07-17.1";

// The canonical eight, fixed order — re-exported so every maturity surface renders all
// eight in the one true order without importing the resolver directly.
export const MATURITY_DOMAIN_KEYS = Object.freeze(CYBER_MOT_DOMAINS.map((d) => d.domain_key));
const DOMAIN_DISPLAY = Object.freeze(Object.fromEntries(
  CYBER_MOT_DOMAINS.map((d) => [d.domain_key, d.display_name]),
));

// ── The ladder ────────────────────────────────────────────────────────────────
export const MATURITY_STAGES = Object.freeze([
  "not_established", // 0 — not reliably observed; nothing mature
  "observed",        // 1 — reliably observed; nothing (further) under managed control
  "managed",         // 2 — ≥1 issue under active managed ownership
  "verified",        // 3 — ≥1 issue fixed AND CyberMeters re-observed the fix
  "monitored",       // 4 — verified AND under active recurrence watch, no unmanaged issue
]);
const RANK = Object.freeze(Object.fromEntries(MATURITY_STAGES.map((s, i) => [s, i])));
const rank = (s) => RANK[s] ?? 0;
const minStage = (a, b) => (rank(a) <= rank(b) ? a : b);

export const MATURITY_STAGE_META = Object.freeze({
  not_established: { label: "Not established", tone: "neutral", description: "Not reliably observed on a complete assessment yet — no maturity can be claimed." },
  observed:        { label: "Observed",        tone: "info",    description: "Reliably observed on a complete assessment. Nothing (further) is under active managed control." },
  managed:         { label: "Under management", tone: "progress", description: "At least one issue is under active managed ownership." },
  verified:        { label: "Verified by CyberMeters", tone: "positive", description: "At least one issue has been fixed and CyberMeters re-observed the fix itself." },
  monitored:       { label: "Verified & monitored", tone: "positive", description: "Verified by CyberMeters re-observation and under active recurrence monitoring." },
});

// ── Capability ceiling per domain — derived from the registry, NOT hand-declared ──
// The highest stage a domain CAN reach, given what CyberMeters can verify for it:
//   any automated remediation → `monitored` (CyberMeters can re-observe → can monitor)
//   only manual/external       → `managed`   (attested/third-party only; never CyberMeters-verified)
//   none / unsupported only     → `observed`  (nothing to drive a case to closure)
// This is the honest, auditable replacement for the static CYBER_MOT_DOMAINS[].maturity tag.
function computeCapabilityCeilings() {
  const supports = new Map(MATURITY_DOMAIN_KEYS.map((k) => [k, new Set()]));
  for (const r of REMEDIATION_REGISTRY) {
    if (!supports.has(r.domain_key)) continue;
    supports.get(r.domain_key).add(verificationSupportForMethod(r.verification_method));
  }
  const out = {};
  for (const k of MATURITY_DOMAIN_KEYS) {
    const s = supports.get(k);
    if (s.has("automated")) out[k] = "monitored";
    else if (s.has("manual") || s.has("external")) out[k] = "managed";
    else out[k] = "observed";
  }
  return Object.freeze(out);
}
export const DOMAIN_CAPABILITY_CEILINGS = computeCapabilityCeilings();
export const domainCapabilityCeiling = (domainKey) => DOMAIN_CAPABILITY_CEILINGS[domainKey] ?? "observed";

// Case statuses that mark lifecycle depth.
const OWNED_STATES = new Set(["assigned", "approved", "action_in_progress", "awaiting_verification", "verified", "monitoring"]);
const VERIFIED_LIKE = new Set(["verified", "monitoring"]);
// Only these resolver states count as "reliably observed" for maturity. Everything else
// (not_yet_assessed, unavailable, evidence_insufficient, degraded, not_configured,
// customer_input_required, provisional) floors to not_established — never mature.
const OBSERVED_STATES = new Set(["assessed_healthy", "issue_detected", "monitoring_only"]);

/**
 * computeDomainMaturity — the pure, deterministic determination. AI-free.
 *
 * @param {object}   p
 * @param {string}   p.domainKey   canonical domain key
 * @param {string}   p.domainState resolver state for this domain on this scan
 * @param {string}   p.scanQuality complete|partial|degraded|unknown|null
 * @param {Array}    [p.cases]     managed_cases rows for (workspace, domain_key): {id, case_type, status, remediation_id, reopened_count}
 * @param {Array}    [p.findingIds] canonical finding ids behind the domain state
 * @param {string}   [p.priorStage] the latest prior eligible maturity_stage for this series
 * @returns {object|null} null → not eligible (write no row); else the ledger conclusion.
 */
export function computeDomainMaturity({ domainKey, domainState, scanQuality, cases = [], findingIds = [], priorStage = null }) {
  const ceiling = domainCapabilityCeiling(domainKey);
  const caseIds = cases.map((c) => c.id).filter(Boolean);
  const build = (stage, reason_code, extra = {}) => {
    const regressed = Boolean(extra.reopened) || (priorStage != null && rank(stage) < rank(priorStage));
    const previous_stage = priorStage != null && rank(stage) < rank(priorStage) ? priorStage : null;
    return {
      stage,
      capability_ceiling: ceiling,
      reason_code,
      previous_stage,
      flags: {
        attested: Boolean(extra.attested) && rank(stage) < rank("verified"),
        regressed,
        has_unmanaged_issue: Boolean(extra.unmanaged),
        capability_capped: Boolean(extra.capability_capped),
      },
      evidence: { source_scan_id: extra.scanId ?? null, case_ids: caseIds, finding_ids: [...findingIds] },
    };
  };

  // 1. Eligibility — a non-complete scan cannot create or advance maturity.
  if (scanQuality !== "complete") return null;

  // 2. Observation floor — the domain's OWN required evidence must have been obtained.
  if (!OBSERVED_STATES.has(domainState)) {
    const reason = domainState === "customer_input_required" ? "customer_input_required" : "domain_not_observed";
    return build("not_established", reason);
  }

  // 3. Fold the managed-case lifecycle for this (workspace, domain). Two distinct honest
  //    signals: `newUnmanaged` = an obligation with NO owner (detected/triaged, or a live
  //    issue with no owning case) → has_unmanaged_issue; `reopened` = a recurrence of a
  //    previously-owned case → regressed. A reopened case is still OWNED work (its owner
  //    persists across reopen), so it counts toward `owned`, but it is a recurrence, not a
  //    verified fix. Both block verified/monitored.
  let owned = false, obsVerified = false, monitoring = false, attested = false, newUnmanaged = false, reopened = false;
  for (const c of cases) {
    const st = c.status;
    const support = verificationSupportForCase(c);
    if (OWNED_STATES.has(st)) owned = true;
    if (st === "reopened") { owned = true; reopened = true; }
    if (VERIFIED_LIKE.has(st) && support === "automated") obsVerified = true;
    if (st === "monitoring" && support === "automated") monitoring = true;
    if (VERIFIED_LIKE.has(st) && support === "manual") attested = true;
    if (st === "detected" || st === "triaged") newUnmanaged = true;
    if ((c.reopened_count || 0) > 0) reopened = true;
  }
  // A live material finding stands in this domain right now.
  const liveIssue = domainState === "issue_detected";
  // An observed issue with no owning case is an unmanaged (unowned) obligation.
  if (liveIssue && !owned) newUnmanaged = true;

  // 4. Candidate stage from the deepest lifecycle milestone reached.
  let candidate = "observed";
  if (monitoring) candidate = "monitored";
  else if (obsVerified) candidate = "verified";
  else if (owned) candidate = "managed";

  // 5. Honest caps — floors only ever REDUCE the stage. Each is evaluated against the
  //    post-capability stage so the reason reflects the binding constraint:
  //    (a) capability: a domain CyberMeters cannot re-observe can never reach verified/monitored;
  //    (b) live issue: a domain currently showing a material finding (issue_detected) cannot
  //        claim CyberMeters-verified/monitored CONTROL while an issue stands — at most `managed`;
  //    (c) unmanaged obligation: an unowned open issue (detected/triaged, or a live issue with
  //        no owning case) or a recurrence (reopened) blocks verified/monitored, even when the
  //        latest scan is clean.
  //    verified/monitored therefore require a clean domain (assessed_healthy / monitoring_only),
  //    every issue owned, and nothing reopened.
  const blocked = newUnmanaged || reopened;
  const capabilityCapped = rank(ceiling) < rank(candidate);
  let stage = minStage(candidate, ceiling);
  const liveIssueCapped = liveIssue && rank(stage) > rank("managed");
  const unmanagedCapped = newUnmanaged && rank(stage) > rank("managed");
  const reopenedCapped = reopened && !newUnmanaged && rank(stage) > rank("managed");
  if (liveIssue || blocked) stage = minStage(stage, "managed");

  // 6. Reason code that matches the final stage AND the binding constraint.
  let reason;
  if (stage === "monitored") reason = "monitored_recurrence_watch";
  else if (stage === "verified") reason = "verified_by_observation";
  else if (stage === "managed") {
    reason = liveIssueCapped ? "live_issue_managed"
      : unmanagedCapped ? "issue_unmanaged"
      : reopenedCapped ? "recurrence_reopened"
      : capabilityCapped ? "capability_capped"
      : reopened ? "recurrence_reopened"
      : attested ? "attested_not_verified"
      : "managed_owned";
  } else { // observed
    reason = newUnmanaged ? "issue_unmanaged"
      : domainState === "assessed_healthy" ? "observed_clean"
      : domainState === "monitoring_only" ? "observed_monitoring"
      : "issue_unmanaged";
  }

  return build(stage, reason, {
    attested, reopened, scanId: null,
    unmanaged: newUnmanaged, // the honest "unowned obligation" signal, never suppressed
    capability_capped: capabilityCapped,
  });
}

/**
 * persistDomainMaturity — the ONLY writer. Called at scan finalize, non-fatally, right
 * after persistCyberMotDomainStates, sharing the SAME report + CE snapshot + completedAt
 * so maturity, 091 state and the M5.c snapshot can never disagree. Append-only,
 * idempotent (INSERT OR IGNORE against the UNIQUE), eligible-complete-scans only.
 *
 * @returns {Promise<{written:number, skipped:string|null}>}
 */
export async function persistDomainMaturity(env, opts = {}) {
  const { workspaceId, domainId, scanId, report, cyberEssentials = null, assessedAt = null } = opts;
  if (!workspaceId || !domainId || !scanId) return { written: 0, skipped: "missing_identity" };
  if (!report) return { written: 0, skipped: "no_report" };
  const quality = report?.scan_quality?.status ?? null;
  if (quality !== "complete") return { written: 0, skipped: "not_complete" }; // eligibility floor

  try {
    const states = resolveCyberMotDomainStates(report, { scanId, cyberEssentials });
    const at = assessedAt || report?.completed_at || report?.created_at || new Date().toISOString();

    // One read of the workspace's cases, grouped by domain_key. No N+1.
    const caseRes = await env.cybermeters_db
      .prepare(`SELECT id, case_type, status, remediation_id, reopened_count, domain_key
                FROM managed_cases WHERE workspace_id = ?`)
      .bind(workspaceId).all();
    const casesByDomain = new Map();
    for (const c of caseRes.results ?? []) {
      if (!casesByDomain.has(c.domain_key)) casesByDomain.set(c.domain_key, []);
      casesByDomain.get(c.domain_key).push(c);
    }

    // The latest prior eligible stage per domain_key for THIS series (this workspace+domain
    // record), so a regression is recorded honestly. Excludes this scan (idempotent re-runs).
    const priorRes = await env.cybermeters_db
      .prepare(`SELECT domain_key, maturity_stage FROM domain_maturity_ledger
                WHERE workspace_id = ? AND domain_id = ? AND scan_id != ?
                ORDER BY assessed_at DESC, created_at DESC`)
      .bind(workspaceId, domainId, scanId).all();
    const priorStage = new Map();
    for (const r of priorRes.results ?? []) {
      if (!priorStage.has(r.domain_key)) priorStage.set(r.domain_key, r.maturity_stage);
    }

    const stmt = env.cybermeters_db.prepare(
      `INSERT OR IGNORE INTO domain_maturity_ledger
         (id, workspace_id, domain_id, scan_id, domain_key, maturity_stage, capability_ceiling,
          reason_code, previous_stage, flags_json, evidence_json, scan_quality, resolver_version,
          ledger_contract_version, assessed_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    );

    const rows = [];
    for (const d of states) {
      const m = computeDomainMaturity({
        domainKey: d.domain_key,
        domainState: d.state,
        scanQuality: quality,
        cases: casesByDomain.get(d.domain_key) || [],
        findingIds: d.finding_ids || [],
        priorStage: priorStage.get(d.domain_key) ?? null,
      });
      if (!m) continue; // never happens here (quality gate already passed) but honest
      const evidence = { ...m.evidence, source_scan_id: scanId };
      rows.push(stmt.bind(
        createId("dml"), workspaceId, domainId, scanId, d.domain_key,
        m.stage, m.capability_ceiling, m.reason_code, m.previous_stage,
        JSON.stringify(m.flags), JSON.stringify(evidence),
        quality, CYBER_MOT_RESOLVER_VERSION, MATURITY_LEDGER_CONTRACT_VERSION, at,
      ));
    }

    if (typeof env.cybermeters_db.batch === "function") {
      await env.cybermeters_db.batch(rows);
    } else {
      for (const r of rows) await r.run();
    }
    return { written: rows.length, skipped: null };
  } catch {
    return { written: 0, skipped: "write_failed" };
  }
}

// ── Readers (ZERO writes) ─────────────────────────────────────────────────────

function viewFromRow(domainKey, row) {
  const meta = MATURITY_STAGE_META[row?.maturity_stage] || MATURITY_STAGE_META.not_established;
  const base = {
    domain_key: domainKey,
    display_name: DOMAIN_DISPLAY[domainKey] || domainKey,
    maturity_stage: "not_established",
    stage_label: MATURITY_STAGE_META.not_established.label,
    stage_description: MATURITY_STAGE_META.not_established.description,
    tone: MATURITY_STAGE_META.not_established.tone,
    capability_ceiling: domainCapabilityCeiling(domainKey),
    reason_code: "no_eligible_scan",
    previous_stage: null,
    flags: { attested: false, regressed: false, has_unmanaged_issue: false, capability_capped: false },
    evidence: null,
    assessed_at: null,
    source_scan_id: null,
    scan_quality: null,
    resolver_version: null,
    ledger_contract_version: MATURITY_LEDGER_CONTRACT_VERSION,
    established: false,
  };
  if (!row) return base;
  let flags = base.flags, evidence = base.evidence;
  try { flags = JSON.parse(row.flags_json || "{}"); } catch { /* keep default */ }
  try { evidence = JSON.parse(row.evidence_json || "null"); } catch { /* keep null */ }
  return {
    ...base,
    maturity_stage: row.maturity_stage,
    stage_label: meta.label,
    stage_description: meta.description,
    tone: meta.tone,
    capability_ceiling: row.capability_ceiling || base.capability_ceiling,
    reason_code: row.reason_code,
    previous_stage: row.previous_stage ?? null,
    flags,
    evidence,
    assessed_at: row.assessed_at ?? null,
    source_scan_id: evidence?.source_scan_id ?? row.scan_id ?? null,
    scan_quality: row.scan_quality ?? null,
    resolver_version: row.resolver_version ?? null,
    ledger_contract_version: row.ledger_contract_version ?? MATURITY_LEDGER_CONTRACT_VERSION,
    established: true,
  };
}

/**
 * readWorkspaceMaturity(db, workspaceId) → exactly eight domains, canonical order.
 * The current view is the LATEST eligible row per (domain_id, domain_key), folded to the
 * eight domain_keys by WORST case — a workspace's maturity for a domain is only as high as
 * its least-mature domain record, so a fresh scan of one hostname can never mask a stale or
 * regressed sibling (the 091/portfolio worst-case doctrine; never over-claims). Missing →
 * not_established, never healthy, never fewer than eight. ZERO writes. Tenant bound in SQL.
 */
export async function readWorkspaceMaturity(db, workspaceId) {
  const skeleton = () => MATURITY_DOMAIN_KEYS.map((k) => viewFromRow(k, null));
  if (!workspaceId) return skeleton();
  try {
    const res = await db.prepare(
      `SELECT domain_key, domain_id, scan_id, maturity_stage, capability_ceiling, reason_code,
              previous_stage, flags_json, evidence_json, scan_quality, resolver_version,
              ledger_contract_version, assessed_at
       FROM (
         SELECT *, ROW_NUMBER() OVER (
           PARTITION BY domain_id, domain_key ORDER BY assessed_at DESC, created_at DESC
         ) AS rn
         FROM domain_maturity_ledger WHERE workspace_id = ?
       ) WHERE rn = 1`
    ).bind(workspaceId).all();
    // Fold to one row per domain_key by worst case (lowest stage); ties keep the freshest
    // (rows already arrive newest-first per series, so the first seen at a given rank wins).
    const worst = new Map();
    for (const r of res.results ?? []) {
      const cur = worst.get(r.domain_key);
      if (!cur || rank(r.maturity_stage) < rank(cur.maturity_stage)) worst.set(r.domain_key, r);
    }
    return MATURITY_DOMAIN_KEYS.map((k) => viewFromRow(k, worst.get(k) || null));
  } catch {
    // A read failure is NEVER a clean zero or a healthy default — it is honestly unavailable.
    return MATURITY_DOMAIN_KEYS.map((k) => ({ ...viewFromRow(k, null), reason_code: "unavailable", tone: "neutral" }));
  }
}

/**
 * readDomainMaturityHistory(db, workspaceId, domainId, domainKey, {limit}) — append-only
 * history, newest first, bound to (workspace_id, domain_id, domain_key).
 */
export async function readDomainMaturityHistory(db, workspaceId, domainId, domainKey, { limit = 50 } = {}) {
  if (!workspaceId || !domainId || !domainKey) return [];
  const cap = Math.max(1, Math.min(200, Number(limit) || 50));
  // No catch: a query failure must NOT collapse into a clean empty that reads as "no
  // assessments yet". It propagates so the route returns a customer-safe error instead.
  const res = await db.prepare(
    `SELECT domain_key, scan_id, maturity_stage, capability_ceiling, reason_code, previous_stage,
            flags_json, evidence_json, scan_quality, resolver_version, ledger_contract_version, assessed_at
     FROM domain_maturity_ledger
     WHERE workspace_id = ? AND domain_id = ? AND domain_key = ?
     ORDER BY assessed_at DESC, created_at DESC LIMIT ?`
  ).bind(workspaceId, domainId, domainKey, cap).all();
  return (res.results ?? []).map((r) => viewFromRow(r.domain_key, r));
}

/**
 * computePortfolioMaturity(db, workspaceIds) — MSP aggregation across the caller's already
 * tenant-resolved workspace set. Only eligible rows exist (complete scans only), so partial
 * evidence is excluded by construction. No mean — worst-case fold per domain. A query
 * failure surfaces `unavailable`, never a clean zero or a healthy default.
 */
export async function computePortfolioMaturity(db, workspaceIds) {
  const emptyDomains = () => MATURITY_DOMAIN_KEYS.map((k) => ({
    domain_key: k, display_name: DOMAIN_DISPLAY[k] || k,
    portfolio_stage: "not_established", capability_ceiling: domainCapabilityCeiling(k),
    workspaces_established: 0, workspaces_total: (workspaceIds?.length ?? 0),
    stage_distribution: {}, regressed_count: 0, attested_count: 0, unmanaged_count: 0,
  }));
  if (!workspaceIds || workspaceIds.length === 0) {
    return { portfolio_state: "no_workspaces", domains: emptyDomains() };
  }
  try {
    const wsIn = workspaceIds.map(() => "?").join(",");
    const res = await db.prepare(
      `SELECT workspace_id, domain_key, maturity_stage, capability_ceiling, flags_json
       FROM (
         SELECT *, ROW_NUMBER() OVER (
           PARTITION BY workspace_id, domain_key ORDER BY assessed_at DESC, created_at DESC
         ) AS rn
         FROM domain_maturity_ledger WHERE workspace_id IN (${wsIn})
       ) WHERE rn = 1`
    ).bind(...workspaceIds).all();

    const agg = new Map(MATURITY_DOMAIN_KEYS.map((k) => [k, {
      domain_key: k, display_name: DOMAIN_DISPLAY[k] || k,
      capability_ceiling: domainCapabilityCeiling(k),
      stages: [], stage_distribution: {}, regressed_count: 0, attested_count: 0, unmanaged_count: 0,
    }]));
    for (const r of res.results ?? []) {
      const a = agg.get(r.domain_key);
      if (!a) continue;
      a.stages.push(r.maturity_stage);
      a.stage_distribution[r.maturity_stage] = (a.stage_distribution[r.maturity_stage] || 0) + 1;
      let flags = {};
      try { flags = JSON.parse(r.flags_json || "{}"); } catch { /* ignore */ }
      if (flags.regressed) a.regressed_count++;
      if (flags.attested) a.attested_count++;
      if (flags.has_unmanaged_issue) a.unmanaged_count++;
    }
    const domains = MATURITY_DOMAIN_KEYS.map((k) => {
      const a = agg.get(k);
      const established = a.stages.length;
      // Worst-case fold: the portfolio domain is only as mature as its least-mature
      // established workspace; workspaces with no eligible row are not_established.
      const worst = established && established === workspaceIds.length
        ? a.stages.reduce((lo, s) => (rank(s) < rank(lo) ? s : lo), a.stages[0])
        : "not_established";
      return {
        domain_key: k, display_name: a.display_name,
        portfolio_stage: worst, capability_ceiling: a.capability_ceiling,
        workspaces_established: established, workspaces_total: workspaceIds.length,
        stage_distribution: a.stage_distribution,
        regressed_count: a.regressed_count, attested_count: a.attested_count, unmanaged_count: a.unmanaged_count,
      };
    });
    const state = res.results && res.results.length ? "assessed" : "no_evidence";
    return { portfolio_state: state, domains };
  } catch {
    return { portfolio_state: "unavailable", domains: emptyDomains() };
  }
}
