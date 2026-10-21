// ── Brand candidate validation state (enrichment → scan decision) ────────────
// The scan's typosquat module (brand-typosquat.js) is pure: it generates
// candidates and marks them `candidates_validated: false`, because DNS/HTTPS
// checks are deferred to the canonical enrichment helpers (brand-dns-enrichment.js
// hourly, brand-http-enrichment.js daily). Until this module existed those
// enrichment results never reached the scan decision: every report carried the
// constant `false`, scoring skipped every brand candidate, and the Brand
// Protection card read `provisional` forever — even with a live, high-risk
// lookalike or an open confirmed-abuse case.
//
// This module closes that gap at scan time, BEFORE the report is frozen and
// scored, by reading the enrichment state the workspace already holds:
//   • workspace_brand_assets — the tri-state DNS result per candidate
//     (NULL unchecked · 0 no A record · 1 resolves), HTTPS state and the
//     customer's classification;
//   • managed_cases (brand_abuse) — cases in a confirmed-abuse state that is
//     still open.
// and deriving `candidates_validated` plus a `validation` summary from it. The
// resolver (security-check-domains.js), scoring (scoring.js), the 091 persisted
// state rows and the M5.c snapshot all read the SAME report, so they cannot
// disagree about what was validated.
//
// Honesty rules:
//   • A candidate counts as a finding only when CyberMeters' own DNS probe
//     resolved it (dns_resolves = 1) and the customer has not closed it.
//   • An unchecked candidate is never "inactive" and never a finding.
//   • `candidates_validated` is true only when at least one candidate has a
//     conclusive DNS result or an open confirmed-abuse case; a report whose
//     enrichment state could not be read stays `false` (fail closed: the card
//     stays provisional, never healthy).
//   • Any candidate still awaiting a probe is reported in `validation.unchecked`
//     so the resolver can refuse a healthy conclusion over unfinished checks.
//   • An open confirmed-abuse case is a finding regardless of the candidate's
//     current DNS state: the case is the customer's confirmed record.

import { readWatchlistDnsReceipts } from "./brand-dns-enrichment.js";

// Classifications the customer has closed — never a finding, never probed.
// Mirrors CLOSED_CLASSIFICATIONS in brand-dns-enrichment.js.
export const BRAND_CLOSED_CLASSIFICATIONS = Object.freeze(["owned", "ignored", "false_positive"]);

// Brand managed-case states in which abuse is confirmed and the case is still
// open. `detected`/`triage` are not yet confirmed; `resolved` and the terminal
// states are closed. Mirrors BRAND_CASE_STATES in brand-case-machine.js.
export const BRAND_OPEN_ABUSE_CASE_STATES = Object.freeze([
  "confirmed_abuse", "customer_approval", "evidence_ready", "takedown_submitted",
  "provider_followup", "verification_pending", "provider_no_response", "escalated", "reappeared",
]);

export const BRAND_VALIDATION_SOURCE = "brand_enrichment";
export const BRAND_VALIDATION_SCHEMA_VERSION = "brand-validation.v1";

const HIGH_RISK = new Set(["high", "critical"]);
const lower = (value) => String(value || "").trim().toLowerCase();

function triState(value) {
  if (value === 1 || value === true) return 1;
  if (value === 0 || value === false) return 0;
  return null;
}

/**
 * deriveBrandValidation — pure. Merges the persisted enrichment rows and open
 * abuse cases into the scan's brand module and derives the validation decision.
 *
 * @param {object} brandModule   runTyposquatModule() output
 * @param {object} inputs
 * @param {Array}  inputs.assetRows  workspace_brand_assets rows for this
 *                                   workspace + protected domain
 * @param {Array}  inputs.caseRows   open confirmed-abuse brand cases
 *                                   ({ id, candidate_domain, severity, status })
 * @param {string} inputs.checkedAt  ISO time the enrichment state was read
 * @param {boolean} [inputs.unavailable]  true when the state could not be read
 * @param {string}  [inputs.reason]       why it could not be read
 */
export function deriveBrandValidation(brandModule, {
  assetRows = [], caseRows = [], checkedAt = null, unavailable = false, reason = null,
} = {}) {
  if (!brandModule || typeof brandModule !== "object") return brandModule;
  const candidates = Array.isArray(brandModule.domains) ? brandModule.domains : [];

  if (unavailable || brandModule.error) {
    // Fail closed: nothing may be presented as validated, inactive or healthy
    // from a state we could not read. The module keeps its generated candidates.
    return {
      ...brandModule,
      candidates_validated: false,
      validation: {
        schema_version: BRAND_VALIDATION_SCHEMA_VERSION,
        source: BRAND_VALIDATION_SOURCE,
        state: "unavailable",
        reason: brandModule.error ? "candidate_generation_failed" : (reason || "enrichment_state_unavailable"),
        candidates: candidates.length,
        checked: 0, unchecked: candidates.length, active: 0, active_high_risk: 0,
        https_served: 0, closed_by_customer: 0,
        open_abuse_cases: 0, open_abuse_case_candidates: [],
        checked_at: checkedAt,
      },
    };
  }

  const rowByCandidate = new Map();
  for (const row of assetRows) {
    const key = lower(row?.candidate_domain);
    if (key && !rowByCandidate.has(key)) rowByCandidate.set(key, row);
  }
  const caseByCandidate = new Map();
  for (const row of caseRows) {
    const key = lower(row?.candidate_domain);
    if (!key || !BRAND_OPEN_ABUSE_CASE_STATES.includes(String(row?.status || ""))) continue;
    if (!caseByCandidate.has(key)) caseByCandidate.set(key, row);
  }

  let checked = 0, unchecked = 0, active = 0, activeHighRisk = 0, httpsServed = 0, closed = 0;
  const merged = candidates.map((candidate) => {
    const key = lower(candidate?.candidate_domain);
    const row = rowByCandidate.get(key) || null;
    const dns = row ? triState(row.dns_resolves) : null;
    const https = row ? triState(row.https_available) : null;
    const classification = row?.classification ? String(row.classification) : "unreviewed";
    const isClosed = BRAND_CLOSED_CLASSIFICATIONS.includes(classification);
    const abuseCase = caseByCandidate.get(key) || null;
    if (dns === null) unchecked += 1; else checked += 1;
    if (isClosed) closed += 1;
    if (dns === 1 && !isClosed) {
      active += 1;
      if (HIGH_RISK.has(String(candidate?.risk_level || ""))) activeHighRisk += 1;
      if (https === 1) httpsServed += 1;
    }
    return {
      ...candidate,
      dns_resolves: dns,
      https_available: https,
      classification,
      last_checked_at: row?.last_checked_at ?? null,
      enrichment_status: dns === null ? "unchecked" : dns === 1 ? "active" : "inactive",
      ...(abuseCase ? {
        open_abuse_case: {
          case_id: abuseCase.id ?? null,
          status: String(abuseCase.status),
          severity: abuseCase.severity ? String(abuseCase.severity) : null,
        },
      } : {}),
    };
  });

  // Open confirmed-abuse cases whose candidate is no longer in the generated set
  // (an older generation, or a manually added candidate) still count: the case is
  // the customer's confirmed record, not a string permutation.
  const generatedKeys = new Set(merged.map((c) => lower(c.candidate_domain)));
  const orphanCases = [...caseByCandidate.entries()]
    .filter(([key]) => !generatedKeys.has(key))
    .map(([key, row]) => ({
      candidate_domain: key, variant_type: "managed_case", risk_level: row.severity && HIGH_RISK.has(lower(row.severity)) ? lower(row.severity) : "high",
      risk_reasons: ["open confirmed-abuse case"], confidence: 90, validation_quality: "strong",
      dns_resolves: null, https_available: null, classification: "unreviewed", last_checked_at: null,
      enrichment_status: "unchecked",
      // Not generated by this scan: the candidate row already exists, so the
      // Phase 8e upsert must not re-persist it under a synthetic variant type.
      generated_this_scan: false,
      open_abuse_case: { case_id: row.id ?? null, status: String(row.status), severity: row.severity ? String(row.severity) : null },
    }));

  const openAbuseCandidates = [...caseByCandidate.keys()].sort();
  // "Validated" means at least one candidate's status rests on evidence beyond
  // string similarity: a conclusive DNS result from CyberMeters' own probe, or a
  // confirmed-abuse case the customer holds open.
  return {
    ...brandModule,
    domains: [...merged, ...orphanCases],
    watchlist_dns: readWatchlistDnsReceipts(assetRows),
    candidates_validated: checked > 0 || openAbuseCandidates.length > 0,
    validation: {
      schema_version: BRAND_VALIDATION_SCHEMA_VERSION,
      source: BRAND_VALIDATION_SOURCE,
      state: checked === 0 ? "unchecked" : unchecked > 0 ? "partial" : "complete",
      reason: null,
      candidates: candidates.length,
      checked, unchecked, active, active_high_risk: activeHighRisk,
      https_served: httpsServed, closed_by_customer: closed,
      open_abuse_cases: openAbuseCandidates.length,
      open_abuse_case_candidates: openAbuseCandidates,
      checked_at: checkedAt,
    },
  };
}

/** True when the merged candidate carries an open confirmed-abuse case. */
export function brandCandidateHasOpenAbuseCase(candidate) {
  const status = candidate?.open_abuse_case?.status;
  return typeof status === "string" && BRAND_OPEN_ABUSE_CASE_STATES.includes(status);
}

/** True when a merged candidate must be scored as a live finding. */
export function brandCandidateIsLive(candidate) {
  if (!candidate || typeof candidate !== "object") return false;
  if (brandCandidateHasOpenAbuseCase(candidate)) return true;
  if (BRAND_CLOSED_CLASSIFICATIONS.includes(String(candidate.classification || ""))) return false;
  // A candidate that carries a DNS result counts only when it resolves. A
  // candidate WITHOUT the field comes from a module that never merged
  // enrichment (legacy fixtures, lightweight routes); the module-level
  // `candidates_validated` gate in scoring decides those.
  if (candidate.dns_resolves === undefined) return true;
  return triState(candidate.dns_resolves) === 1;
}

// Bounded, tenant-scoped reads. Both queries verify the workspace is live and
// owns the protected domain, so a soft-deleted or foreign workspace yields no
// enrichment state. LIMITs bound the work: the generator caps candidates well
// below these, and older generations only add a few rows.
export const BRAND_VALIDATION_ASSET_ROW_LIMIT = 500;
export const BRAND_VALIDATION_CASE_ROW_LIMIT = 200;

export function selectBrandValidationAssetsSql() {
  return `SELECT a.candidate_domain, a.domain, a.evidence_json, a.dns_resolves, a.https_available, a.classification,
                 a.risk_level, a.status, a.last_checked_at
            FROM workspace_brand_assets a
           WHERE a.workspace_id = ? AND lower(a.domain) = lower(?)
             AND EXISTS (
                   SELECT 1
                     FROM workspaces w
                     JOIN workspace_domains wd ON wd.workspace_id = w.id
                     JOIN domains d ON d.id = wd.domain_id
                    WHERE w.id = a.workspace_id
                      AND w.deleted_at IS NULL
                      AND lower(d.domain) = lower(a.domain)
                 )
           ORDER BY a.candidate_domain ASC
           LIMIT ${BRAND_VALIDATION_ASSET_ROW_LIMIT}`;
}

export function selectBrandOpenAbuseCasesSql() {
  const states = BRAND_OPEN_ABUSE_CASE_STATES.map((s) => `'${s}'`).join(", ");
  return `SELECT c.id, c.domain AS candidate_domain, c.severity, c.status
            FROM managed_cases c
            JOIN workspace_brand_assets a
              ON a.workspace_id = c.workspace_id
             AND lower(a.candidate_domain) = lower(c.domain)
             AND lower(a.domain) = lower(?)
            JOIN workspaces w ON w.id = c.workspace_id AND w.deleted_at IS NULL
           WHERE c.workspace_id = ? AND c.case_type = 'brand_abuse'
             AND c.status IN (${states})
           ORDER BY c.created_at ASC
           LIMIT ${BRAND_VALIDATION_CASE_ROW_LIMIT}`;
}

/**
 * loadBrandValidationState — reads the enrichment state for this workspace and
 * protected domain and returns the brand module with the validation decision
 * merged in. Never throws; a read failure fails closed (candidates_validated
 * false, validation.state "unavailable").
 */
export async function loadBrandValidationState(env, { workspaceId, domain, brandModule, now = null } = {}) {
  const checkedAt = now || new Date().toISOString();
  if (!brandModule || typeof brandModule !== "object") return brandModule;
  if (!workspaceId || !domain) {
    return deriveBrandValidation(brandModule, { checkedAt, unavailable: true, reason: "no_workspace_context" });
  }
  const db = env?.cybermeters_db;
  if (!db) return deriveBrandValidation(brandModule, { checkedAt, unavailable: true, reason: "database_unavailable" });
  try {
    const [assets, cases] = await Promise.all([
      db.prepare(selectBrandValidationAssetsSql()).bind(workspaceId, domain).all(),
      db.prepare(selectBrandOpenAbuseCasesSql()).bind(domain, workspaceId).all(),
    ]);
    return deriveBrandValidation(brandModule, {
      assetRows: assets?.results || [],
      caseRows: cases?.results || [],
      checkedAt,
    });
  } catch {
    return deriveBrandValidation(brandModule, { checkedAt, unavailable: true, reason: "enrichment_state_read_failed" });
  }
}
