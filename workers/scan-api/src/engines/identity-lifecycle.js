// ── Identity Exposure Managed Workflow ──────────────────────────────────────
// Turns externally-observed identity/login surfaces into a canonical, workspace-
// scoped MANAGED record: observe → correlate provider/surface identity → assess
// externally observable risk → assign ownership → plan/record remediation →
// verify externally where supported → monitor change/recurrence → reopen the
// managed case when required.
//
// EXTENDS the existing identity-observation architecture — no second identity
// scanner, no duplicate identity-asset table. Source-of-truth split:
//   identity_assets (mig 030)   → raw externally-observed evidence + history
//   identity_exposure (mig 086) → classification, ownership, remediation,
//                                 verification and monitoring
// The raw store is referenced (source_evidence refs), never copied, and a
// provider/endpoint change never overwrites the old evidence.
//
// Honesty (permanent). External observation only. A publicly visible identity
// entry point is NOT automatically a vulnerability. CyberMeters does NOT observe
// leaked/breached credentials, dark-web/stealer data, MFA enrolment, Conditional
// Access, internal Entra/Google/Okta policy, sign-in telemetry or account
// takeover — those stay unknown. Customer classification is separate from
// observation; a customer-recorded change/removal is NOT verified until
// externally re-observed. Follow-up uses the Universal Managed-Case Model
// (identity_case → identity.* canonical remediation).

import { emitLifecycleAlert } from "./alert-consumers.js";
import { buildMonitoringTransitionDetail, isMonitoringTransition } from "./alert-occurrence.js";
import { createManagedCase, canTransitionCase, canonicalPhaseFor } from "./managed-case-model.js";
import { newCaseEventId } from "./case-workflow.js";
import {
  providerKey, deriveSurfaceType, canonicalIdentityKey, normalizeHostname, assessIdentityRisk,
} from "./identity-policy.js";

function newId(prefix) {
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return `${prefix}-${(uuid || "").slice(0, 12).padEnd(12, "0")}`;
}
function parseJson(v, fallback = null) { try { return v ? JSON.parse(v) : fallback; } catch { return fallback; } }
function safeJson(v, fallback = null) { try { return v == null ? fallback : JSON.stringify(v); } catch { return fallback; } }

// Signals CyberMeters can NEVER observe externally — carried on every record and
// every verification so the honesty scope is explicit, not implied.
export const IDENTITY_UNKNOWN_SIGNALS = Object.freeze([
  "leaked_credentials", "breached_passwords", "dark_web", "stealer_logs",
  "mfa_enrolment", "conditional_access", "internal_identity_policy",
  "signin_telemetry", "failed_login_telemetry", "account_takeover",
]);

export const IDENTITY_CLASSIFICATIONS = Object.freeze([
  "unreviewed", "expected", "unexpected", "investigate", "exception", "retired",
]);
export const IDENTITY_OWNERSHIP_STATUSES = Object.freeze(["known", "partial", "missing"]);
export const IDENTITY_EVENT_TYPES = Object.freeze([
  "observed", "material_change", "provider_change", "classified", "owner_assigned", "owner_missing",
  "purpose_set", "remediation_started", "customer_action_recorded", "verification_requested",
  "verified", "verification_failed", "exception_set", "exception_cleared", "retired",
  "reopened", "monitoring_changed", "case_linked",
  // "the already-open case was touched again for the same recurrence" — its own type
  // BECAUSE it is not a monitoring change: it records no transition and carries no
  // to_recurrence_type. See the append site below, and shadow-it-inventory.js.
  "case_recurrence_noted",
]);

// ── Ownership (three roles, server-derived) ──────────────────────────────────
export function deriveIdentityOwnershipStatus(business, technical, identity) {
  const owners = [business, technical, identity].map((o) => String(o || "").trim()).filter(Boolean);
  if (business && technical) return "known";
  if (owners.length) return "partial";
  return "missing";
}

const CONFIDENCE_RANK = { high: 3, medium: 2, low: 1 };
function strongerConfidence(a, b) {
  return (CONFIDENCE_RANK[a] || 0) >= (CONFIDENCE_RANK[b] || 0) ? (a || b || "low") : (b || "low");
}
// The raw store does not persist the module confidence; derive it honestly from
// the observation source (a fingerprinted provider is stronger than a hostname
// pattern guess).
function sourceConfidence(source) {
  const s = String(source || "").toLowerCase();
  if (s === "identity_discovery") return "high";
  if (s === "hostname_pattern") return "medium";
  return "low";
}
// Protocols we can reasonably attribute from the surface type (observable only).
function protocolsForSurface(surface) {
  if (surface === "saml_federation") return ["saml"];
  if (surface === "oauth_endpoint") return ["oidc", "oauth"];
  return [];
}

// Non-destructive evidence UNION — dedup by (source_table, source_record_id);
// prefer the freshest last_seen_at; never drop a prior source contribution.
export function unionIdentityEvidence(existing = [], incoming = []) {
  const seen = new Map();
  const keyOf = (e) => `${e.source_table}:${e.source_record_id ?? e.observed_identifier ?? ""}`;
  for (const e of [...(existing || []), ...(incoming || [])]) {
    if (!e || typeof e !== "object") continue;
    const k = keyOf(e);
    const prev = seen.get(k);
    if (!prev || (e.last_seen_at && (!prev.last_seen_at || e.last_seen_at > prev.last_seen_at))) seen.set(k, { ...prev, ...e });
  }
  return [...seen.values()];
}

async function appendEvent(env, rec, { actor_type = "system", actor_id = null, event_type, detail = null }) {
  await env.cybermeters_db
    .prepare(`INSERT INTO identity_exposure_events
      (id, record_id, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .bind(newId("iee"), rec.id, rec.workspace_id, actor_type, actor_id, event_type, safeJson(detail))
    .run();
}

// Machine-stable overall rollup (classification, verification, monitoring stay
// DISTINCT fields; this is the single customer-facing lifecycle_state).
function deriveLifecycleState(rec) {
  if (rec.customer_classification === "retired") return "retired";
  if (rec.exception_until && rec.exception_until > (rec._now || "")) return "exception";
  if (rec.verification_status === "verified") return "verified";
  if (rec.recurrence_type && rec.recurrence_type !== "none" && rec.monitoring_status !== "no_longer_observed") {
    if (rec.recurrence_type === "owner_missing") return "owner_missing";
    return "review_required";
  }
  if (rec.remediation_status === "customer_actioned") return "awaiting_verification";
  if (rec.remediation_status === "in_progress") return "remediation_in_progress";
  if (rec.monitoring_status === "reappeared") return "reopened";
  return "observed";
}

// ── Correlation / upsert ────────────────────────────────────────────────────
// Read the workspace's active identity_assets, correlate one managed record per
// distinct identity surface (per domain), and upsert. Observation fields refresh;
// classification/ownership/remediation/verification persist. A provider/endpoint
// change is a material event with the OLD evidence preserved. Soft-deleted
// workspaces are skipped.
export async function correlateIdentityExposure(env, workspaceId, { now = new Date().toISOString() } = {}) {
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(workspaceId).first().catch(() => null);
  if (!ws) return { correlated: 0, created: 0, changed: 0, skipped: "workspace_inactive" };

  const rows = (await env.cybermeters_db
    .prepare(`SELECT id, domain_id, hostname, asset_type, identity_type, provider, internet_exposed,
                     source, risk_score, evidence, first_seen, last_seen
              FROM identity_assets WHERE workspace_id = ? AND status = 'active'`)
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];

  // Group by (domain_id, canonical_identity_key).
  const groups = new Map();
  for (const r of rows) {
    const pk = providerKey(r.provider);
    const surface = deriveSurfaceType(r.asset_type, r.identity_type);
    const key = canonicalIdentityKey({ provider_key: pk, surface_type: surface, hostname: r.hostname });
    const gk = `${r.domain_id}::${key}`;
    if (!groups.has(gk)) groups.set(gk, { domain_id: r.domain_id, key, surface, rows: [] });
    groups.get(gk).rows.push({ ...r, provider_key: pk });
  }

  let created = 0, changed = 0;
  const seenKeys = new Set();
  for (const [, g] of groups) {
    seenKeys.add(`${g.domain_id}::${g.key}`);
    const rowsG = g.rows;
    const primary = rowsG.find((r) => r.asset_type === "provider") || rowsG[0];
    const provider_key = rowsG.map((r) => r.provider_key).find(Boolean) || null;
    const provider_name = rowsG.map((r) => r.provider).find(Boolean) || null;
    const primary_hostname = normalizeHostname(rowsG.map((r) => r.hostname).find(Boolean) || "") || null;
    const urls = new Set(), endpoints = new Set(), protocols = new Set(protocolsForSurface(g.surface));
    const sourceTypes = new Set();
    let confidence = "low", firstSeen = null, lastSeen = null, maxRisk = 0;
    const evidenceRefs = [];
    for (const r of rowsG) {
      const conf = sourceConfidence(r.source);
      confidence = strongerConfidence(confidence, conf);
      if (r.first_seen && (!firstSeen || r.first_seen < firstSeen)) firstSeen = r.first_seen;
      if (r.last_seen && (!lastSeen || r.last_seen > lastSeen)) lastSeen = r.last_seen;
      maxRisk = Math.max(maxRisk, Number(r.risk_score) || 0);
      sourceTypes.add(r.source);
      const host = normalizeHostname(r.hostname);
      if (host) urls.add(`https://${host}`);
      evidenceRefs.push({
        source_table: "identity_assets", source_record_id: r.id, source_type: r.source,
        observed_identifier: r.provider || host || r.identity_type, hostname: host || null,
        url: host ? `https://${host}` : null, protocol: [...protocols][0] || null,
        first_seen_at: r.first_seen || null, last_seen_at: r.last_seen || null, confidence: conf,
      });
    }

    const existing = await env.cybermeters_db
      .prepare(`SELECT * FROM identity_exposure WHERE workspace_id = ? AND domain_id = ? AND canonical_identity_key = ?`)
      .bind(workspaceId, g.domain_id, g.key).first().catch(() => null);

    if (!existing) {
      const id = newId("ie");
      const rec = { id, workspace_id: workspaceId };
      await env.cybermeters_db
        .prepare(`INSERT INTO identity_exposure
          (id, workspace_id, domain_id, canonical_identity_key, provider_key, provider_name, surface_type,
           primary_hostname, observed_urls_json, observed_endpoints_json, observed_protocols_json,
           source_types_json, source_evidence_json, first_seen_at, last_seen_at, confidence,
           exposure_status, customer_classification, ownership_status, monitoring_status, lifecycle_state, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'observed', 'unreviewed', 'missing', 'observed', 'observed', ?, ?)`)
        .bind(id, workspaceId, g.domain_id, g.key, provider_key, provider_name, g.surface, primary_hostname,
          safeJson([...urls], "[]"), safeJson([...endpoints], "[]"), safeJson([...protocols], "[]"),
          safeJson([...sourceTypes], "[]"), safeJson(evidenceRefs, "[]"), firstSeen || lastSeen || now, lastSeen || firstSeen || now,
          confidence, now, now)
        .run();
      await appendEvent(env, rec, { event_type: "observed", detail: { created: true, provider_key, surface_type: g.surface, confidence } });
      created++;
      continue;
    }

    // Material change: provider changed (old preserved in event), new URL, or a
    // surface-type shift. Provider change on a hostname-anchored surface keeps the
    // SAME record.
    const prevUrls = new Set(parseJson(existing.observed_urls_json, []) || []);
    const newUrl = [...urls].some((u) => !prevUrls.has(u));
    const providerChanged = existing.provider_key !== provider_key && Boolean(existing.provider_key) && Boolean(provider_key);
    const material = providerChanged || newUrl || existing.surface_type !== g.surface;
    const unionedUrls = [...new Set([...prevUrls, ...urls])];
    const unionedEvidence = unionIdentityEvidence(parseJson(existing.source_evidence_json, []) || [], evidenceRefs);
    const unionedSourceTypes = [...new Set([...(parseJson(existing.source_types_json, []) || []), ...sourceTypes])];
    const exposure_status = existing.exposure_status === "no_longer_observed" ? "reappeared" : "observed";

    await env.cybermeters_db
      .prepare(`UPDATE identity_exposure SET provider_key = ?, provider_name = ?, surface_type = ?, primary_hostname = ?,
                  observed_urls_json = ?, observed_protocols_json = ?, source_types_json = ?, source_evidence_json = ?,
                  last_seen_at = ?, confidence = ?, exposure_status = ?,
                  last_changed_at = CASE WHEN ? THEN ? ELSE last_changed_at END,
                  updated_at = ? WHERE id = ? AND workspace_id = ?`)
      .bind(provider_key, provider_name, g.surface, primary_hostname,
        safeJson(unionedUrls, "[]"), safeJson([...protocols], "[]"), safeJson(unionedSourceTypes, "[]"), safeJson(unionedEvidence, "[]"),
        lastSeen || now, confidence, exposure_status, material ? 1 : 0, now, now, existing.id, workspaceId)
      .run();
    if (providerChanged) { await appendEvent(env, existing, { event_type: "provider_change", detail: { from: existing.provider_key, to: provider_key, note: "old_provider_preserved" } }); changed++; }
    else if (material) { await appendEvent(env, existing, { event_type: "material_change", detail: { new_url: newUrl, surface_type: g.surface } }); changed++; }
    if (exposure_status === "reappeared") await appendEvent(env, existing, { event_type: "monitoring_changed", detail: { to: "reappeared" } });
  }

  const monitoring = await evaluateIdentityExposureMonitoring(env, workspaceId, { seenKeys, now });
  return { correlated: groups.size, created, changed, monitoring };
}

// ── Verification contract (external-observation only) ───────────────────────
// A customer action is an assertion, never proof. A positive verification needs
// the external observation to match the expected outcome. Disappearance may be
// inconclusive (transient outage / DNS / scan failure). Returns a STRUCTURED
// evidence record for every result.
export const IDENTITY_DISAPPEARANCE_WINDOW_DAYS = 14;

// The two timestamps this contract compares are written in DIFFERENT formats, and
// comparing them raw is a real defect, not a theoretical one:
//   • last_changed_at  — bound from `now`, an ISO string ("2026-07-16T11:00:00.000Z")
//   • customer_action_at — identity_exposure_events.created_at, written by SQLite's
//     datetime('now') as "2026-07-16 11:00:00" — UTC, but carrying NO zone marker.
// Date.parse() reads the second as LOCAL time. Workers run UTC so the skew is zero in
// production, but under Europe/London (BST) the SAME instant parses an hour apart and
// `iso > sqlite` returns true — i.e. a change recorded at the very moment of the
// assertion would read as "after" it and falsely verify. Normalising is what makes this
// comparison mean what it says wherever it runs.
// Exported for direct assertion: CI runs UTC, where the skew this guards against is zero,
// so a behavioural test alone would pass with the normalisation deleted. Testing the
// helper itself is what makes the regression catchable on the machine CI actually uses.
export function parseInstant(ts) {
  if (!ts) return NaN;
  const s = String(ts);
  // Bare SQLite datetime (no zone, no 'T'): it is UTC — say so explicitly.
  const utc = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(s) ? s.replace(" ", "T") + "Z" : s;
  return Date.parse(utc);
}

// `customer_action_at` is the created_at of the record's most recent
// `customer_action_recorded` event — the moment the customer told us they acted. It is
// passed IN so this function stays pure and directly testable; the caller resolves it
// from the append-only event log (there is no column for it on identity_exposure, and
// the event log already holds the fact, so no migration is needed to know it).
export function buildIdentityVerification(rec, { now = new Date().toISOString(), customer_action_at = null } = {}) {
  const action = rec.customer_action_status || null;
  const observedNow = rec.monitoring_status === "observed" || rec.monitoring_status === "reappeared";
  const age = rec.evidence_age_days;
  let verification_result, expected_outcome, actual_outcome;

  if (!action) {
    verification_result = "pending"; expected_outcome = "customer_action_recorded"; actual_outcome = "no_action_recorded";
  } else if (action === "surface_removed") {
    expected_outcome = "surface_no_longer_observed";
    if (observedNow) { verification_result = "failed"; actual_outcome = "still_observed"; }
    else if (age != null && age >= IDENTITY_DISAPPEARANCE_WINDOW_DAYS) { verification_result = "verified"; actual_outcome = "absent_across_window"; }
    else { verification_result = "inconclusive"; actual_outcome = "absent_but_within_window"; }
  } else if (action === "configuration_changed") {
    // The change must be observed AFTER the customer said they made it. This previously
    // accepted `rec.material_change || rec.last_changed_at` — ANY change we had ever
    // recorded, at any time — so a provider change from two years ago verified an
    // assertion made today, and the UI then told the customer "Verified by CyberMeters".
    // That is a product assertion of verification built from evidence that predates the
    // thing it claims to verify.
    //
    // `material_change` cannot stand in for this: it is a rolling "within the last 30
    // days of NOW" flag (see the evaluator), not an ordering against the assertion.
    //
    // Fail CLOSED when the ordering cannot be established (no recorded action time — e.g.
    // a legacy row whose event predates this contract): unknown ordering is inconclusive,
    // never verified. Inconclusive is honest and recoverable; a false "verified" is not.
    expected_outcome = "identity_configuration_change_observed_after_customer_action";
    const changedAfterAction = !!(rec.last_changed_at && customer_action_at)
      && parseInstant(rec.last_changed_at) > parseInstant(customer_action_at);
    if (changedAfterAction) {
      verification_result = "verified"; actual_outcome = "material_change_observed_after_action";
    } else if (!customer_action_at) {
      verification_result = "inconclusive"; actual_outcome = "customer_action_time_unknown";
    } else {
      verification_result = "inconclusive"; actual_outcome = "no_change_observed_since_action";
    }
  } else {
    verification_result = "unsupported"; expected_outcome = "unsupported"; actual_outcome = "unsupported";
  }

  return {
    verification_method: "external_observation",
    verification_result,
    evidence_type: "identity_observation",
    observed_at: now,
    previous_observation: { last_changed_at: rec.last_changed_at || null, provider_key: rec.provider_key || null, customer_action_at },
    current_observation: { monitoring_status: rec.monitoring_status, exposure_status: rec.exposure_status, evidence_age_days: age ?? null },
    expected_outcome, actual_outcome,
    confidence: rec.confidence || "low",
    observation_reference: rec.canonical_identity_key,
    limitations: "External observation only — cannot confirm internal policy, MFA/Conditional Access, or that a disappearance is a permanent removal.",
    unknown_signals: [...IDENTITY_UNKNOWN_SIGNALS],
  };
}

// ── Monitoring evaluator ────────────────────────────────────────────────────
// ONE deterministic pass. Explicit precedence; disappearance is never verified
// removal; an expected, owned provider login is not an alarm. Persists the
// snapshot and, where follow-up is due, opens or REOPENS the identity_case.
export const IDENTITY_STALE_EVIDENCE_DAYS = 45;

function daysBetween(from, to) {
  const d = (Date.parse(to) - Date.parse(from)) / 86400000;
  return Number.isFinite(d) ? Math.max(0, Math.floor(d)) : null;
}

// recurrence → { finding_type (resolves to canonical remediation), case_action }
const RECURRENCE_CASE = {
  public_admin_surface:  { finding_type: "identity_public_admin_surface", action: "open_or_reopen" },
  unexpected_surface:    { finding_type: "identity_unexpected_surface",   action: "open_or_reopen" },
  investigate_unresolved:{ finding_type: "identity_unexpected_surface",   action: "open_or_reopen" },
  retired_reappeared:    { finding_type: "identity_unexpected_surface",   action: "open_or_reopen" },
  removal_contradicted:  { finding_type: "identity_unexpected_surface",   action: "open_or_reopen" },
  verification_failed:   { finding_type: "identity_unexpected_surface",   action: "open_or_reopen" },
  provider_change:       { finding_type: "identity_provider_change",      action: "open_or_reopen" },
  exception_expired:     { finding_type: "identity_exception_expired",    action: "open_or_reopen" },
  owner_missing:         { finding_type: "identity_owner_missing",        action: "assign_owner" },
};

export async function evaluateIdentityExposureMonitoring(env, workspaceId, { seenKeys = null, now = new Date().toISOString() } = {}) {
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`).bind(workspaceId).first().catch(() => null);
  if (!ws) return { evaluated: 0, skipped: "workspace_inactive" };

  const recs = (await env.cybermeters_db
    .prepare(`SELECT * FROM identity_exposure WHERE workspace_id = ?`).bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];
  let disappeared = 0, cases = 0;

  for (const rec of recs) {
    let monitoring_status = rec.monitoring_status;
    const gk = `${rec.domain_id}::${rec.canonical_identity_key}`;
    // Disappearance — key no longer observed this correlation. NEVER verified removal.
    if (seenKeys && !seenKeys.has(gk) && monitoring_status !== "no_longer_observed") {
      monitoring_status = "no_longer_observed";
      await appendEvent(env, rec, { event_type: "monitoring_changed", detail: { to: "no_longer_observed", note: "not_verified_removed" } });
      disappeared++;
    } else if (rec.exposure_status === "reappeared") {
      monitoring_status = "reappeared";
    } else if (monitoring_status !== "no_longer_observed") {
      monitoring_status = "observed";
    }
    const stillObserved = monitoring_status === "observed" || monitoring_status === "reappeared";
    const evidence_age_days = daysBetween(rec.last_seen_at, now);
    const material_change = rec.last_changed_at ? (daysBetween(rec.last_changed_at, now) <= 30 ? 1 : 0) : 0;
    const stale = evidence_age_days != null && evidence_age_days > IDENTITY_STALE_EVIDENCE_DAYS;
    const ownership_status = deriveIdentityOwnershipStatus(rec.business_owner, rec.technical_owner, rec.identity_owner);
    const cls = rec.customer_classification;
    const admin = rec.surface_type === "admin_login";
    const inException = rec.exception_until && rec.exception_until > now;

    // Deterministic precedence. Owner assignment comes BEFORE the unexpected/
    // investigate follow-up: an at-risk surface with no owner needs an owner
    // first (assign_owner); once owned, the review case (open_or_reopen) applies.
    let recurrence_type = "none", monitoring_reason = null, required_case_action = "none";
    if (inException) { monitoring_reason = "under_exception"; }
    else if (rec.exception_until && rec.exception_until <= now && cls === "exception") { recurrence_type = "exception_expired"; monitoring_reason = "exception_window_expired"; required_case_action = "open_or_reopen"; }
    else if (rec.customer_action_status === "surface_removed" && stillObserved) { recurrence_type = "removal_contradicted"; monitoring_reason = "recorded_removed_but_still_observed"; required_case_action = "open_or_reopen"; }
    else if (rec.verification_status === "failed") { recurrence_type = "verification_failed"; monitoring_reason = "verification_failed"; required_case_action = "open_or_reopen"; }
    else if (ownership_status === "missing" && stillObserved && (cls === "unexpected" || cls === "investigate")) { recurrence_type = "owner_missing"; monitoring_reason = "no_owner_on_at_risk_surface"; required_case_action = "assign_owner"; }
    else if (admin && stillObserved && cls !== "expected") { recurrence_type = "public_admin_surface"; monitoring_reason = "public_admin_login_surface"; required_case_action = "open_or_reopen"; }
    else if (cls === "unexpected" && stillObserved) { recurrence_type = "unexpected_surface"; monitoring_reason = "unexpected_surface_still_observed"; required_case_action = "open_or_reopen"; }
    else if (cls === "retired" && monitoring_status === "reappeared") { recurrence_type = "retired_reappeared"; monitoring_reason = "retired_surface_reappeared"; required_case_action = "open_or_reopen"; }
    else if (cls === "investigate" && stillObserved) { recurrence_type = "investigate_unresolved"; monitoring_reason = "investigate_classification_unresolved"; required_case_action = "open_or_reopen"; }
    else if (material_change && rec.last_changed_at && stillObserved) { recurrence_type = "provider_change"; monitoring_reason = "material_identity_change"; required_case_action = "open_or_reopen"; }
    else if (stale && stillObserved) { recurrence_type = "evidence_stale"; monitoring_reason = "identity_evidence_stale"; required_case_action = "none"; }

    const { risk_status } = assessIdentityRisk({ surface_type: rec.surface_type, customer_classification: cls, ownership_status, recurrence_type: recurrence_type === "none" ? null : recurrence_type });
    const merged = { ...rec, _now: now, monitoring_status, recurrence_type, ownership_status };
    const lifecycle_state = deriveLifecycleState(merged);

    if (ownership_status === "missing" && rec.ownership_status && rec.ownership_status !== "missing") {
      await appendEvent(env, rec, { event_type: "owner_missing", detail: { classification: cls } });
    }

    // ── Monitoring transition (append-only) ──────────────────────────────────
    // The canonical occurrence record: findConditionOccurrence reads this event's
    // created_at as the condition-start and its id as the occurrence identity.
    // Without it the consumer resolves nothing and every condition here is treated
    // as pre-existing — i.e. this domain would be silently unable to alert.
    //
    // The OTHER monitoring_changed sites in this file ("reappeared",
    // "no_longer_observed", case-linkage) are different facts and carry different
    // payloads; only this one records a recurrence transition, so only this one
    // carries to_recurrence_type.
    //
    // Only a real CHANGE is appended: re-observing the same condition next hour is
    // not a new occurrence, and appending one would mint a fresh occurrence id and
    // re-alert the same unchanged item every hour.
    const nextIdentityMonitoring = { monitoring_status, recurrence_type: recurrence_type === "none" ? null : recurrence_type };
    if (isMonitoringTransition({ monitoring_status: rec.monitoring_status, recurrence_type: rec.recurrence_type }, nextIdentityMonitoring)) {
      await appendEvent(env, rec, {
        event_type: "monitoring_changed",
        detail: buildMonitoringTransitionDetail({
          from_monitoring_status: rec.monitoring_status ?? null,
          to_monitoring_status: nextIdentityMonitoring.monitoring_status ?? null,
          from_recurrence_type: rec.recurrence_type ?? null,
          to_recurrence_type: nextIdentityMonitoring.recurrence_type,
          required_case_action, reason: monitoring_reason,
          entity: rec.canonical_identity_key,
        }),
      }).catch(() => { /* history is best-effort; it must not break the evaluator */ });
    }

    await env.cybermeters_db
      .prepare(`UPDATE identity_exposure SET monitoring_status = ?, monitoring_reason = ?, exposure_status = ?, risk_status = ?,
                  ownership_status = ?, evidence_age_days = ?, material_change = ?, recurrence_type = ?, required_case_action = ?,
                  lifecycle_state = ?, evaluated_at = ?, updated_at = ? WHERE id = ? AND workspace_id = ?`)
      .bind(monitoring_status, monitoring_reason, monitoring_status, risk_status, ownership_status, evidence_age_days,
        material_change, recurrence_type === "none" ? null : recurrence_type, required_case_action, lifecycle_state, now, now, rec.id, workspaceId)
      .run();

    if (required_case_action === "open_or_reopen" || required_case_action === "assign_owner") {
      const acted = await openOrReopenIdentityCase(env, { ...rec, monitoring_status, ownership_status }, { recurrence: recurrence_type, now });
      // Tell the customer — through the ONE canonical pipeline, from the same
      // deterministic decision that just opened/reopened the case. Detection is not
      // repeated here. The condition-start and occurrence identity come from the
      // append-only monitoring_changed event, so hourly re-evaluation of the same
      // occurrence dedupes and pre-existing state stays silent. Never sends directly.
      await emitLifecycleAlert(env, {
        workspace_id: workspaceId, domain_key: "identity_exposure",
        record_id: rec.id, entity: rec.canonical_identity_key, hostname: rec.primary_hostname || null,
        recurrence: recurrence_type,
        finding_type: (RECURRENCE_CASE[recurrence_type] || {}).finding_type || null,
        case_id: rec.linked_case_id || null,
      }).catch(() => { /* alerting must never break the evaluator */ });
      if (acted?.ok) cases++;
    }
  }
  return { evaluated: recs.length, disappeared, cases };
}

// Open a new identity_case OR reopen/update the EXISTING linked case through the
// universal transition validator (never a separate table, never a bare dedup).
export async function openOrReopenIdentityCase(env, rec, { recurrence, now = new Date().toISOString() } = {}) {
  const cfg = RECURRENCE_CASE[recurrence] || { finding_type: "identity_unexpected_surface" };
  const label = String(recurrence || "review").replace(/_/g, " ");
  if (!rec.linked_case_id) {
    return linkIdentityCase(env, rec, {
      actor: { actor_type: "system", actor_id: null }, finding_type: cfg.finding_type,
      title: `Identity exposure review: ${rec.primary_hostname || rec.provider_name || rec.canonical_identity_key} (${label})`,
      summary: `Externally observed identity surface needs review: ${label}.`,
    });
  }
  const kase = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases WHERE id = ? AND workspace_id = ?`).bind(rec.linked_case_id, rec.workspace_id).first().catch(() => null);
  if (!kase) {
    await env.cybermeters_db.prepare(`UPDATE identity_exposure SET linked_case_id = NULL WHERE id = ? AND workspace_id = ?`).bind(rec.id, rec.workspace_id).run();
    return linkIdentityCase(env, rec, { actor: { actor_type: "system", actor_id: null }, finding_type: cfg.finding_type, title: `Identity exposure review: ${rec.primary_hostname || rec.canonical_identity_key}`, summary: `Recurrence: ${label}.` });
  }
  const phase = canonicalPhaseFor(kase.case_type, kase.status);
  if (phase === "verified" || phase === "monitoring") {
    const decision = canTransitionCase({ case: kase, target_status: "reopened", actor: { actor_type: "system", actor_id: null }, reason: recurrence, now });
    if (decision.ok) {
      const n = decision.case;
      await env.cybermeters_db
        .prepare(`UPDATE managed_cases SET status = ?, reopened_at = ?, reopened_count = ?, updated_at = ? WHERE id = ? AND workspace_id = ?`)
        .bind(n.status, n.reopened_at || now, Number(n.reopened_count || 0), n.updated_at, kase.id, kase.workspace_id).run();
      await env.cybermeters_db
        .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
                  VALUES (?, ?, ?, 'system', NULL, ?, ?, ?, ?, datetime('now'))`)
        .bind(newCaseEventId(), kase.id, kase.workspace_id, kase.status, n.status, decision.event.action, safeJson({ recurrence, record: rec.id })).run();
      await appendEvent(env, rec, { event_type: "reopened", detail: { case_id: kase.id, recurrence } });
      return { ok: true, reopened: true };
    }
  }
  // Active case → append a recurrence event (update, not a bare dedup return).
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
              VALUES (?, ?, ?, 'system', NULL, ?, ?, 'identity_recurrence', ?, datetime('now'))`)
    .bind(newCaseEventId(), kase.id, kase.workspace_id, kase.status, kase.status, safeJson({ recurrence, record: rec.id })).run();
  // NOT `monitoring_changed`: no monitoring state changed here. This records "the
  // already-open case was touched again for the same recurrence", on every evaluation
  // pass for as long as the condition persists. Typed as `monitoring_changed` it put an
  // ever-growing pile of rows into the namespace findConditionOccurrence searches. The
  // resolver no longer depends on a window, so this is not what makes it correct — it
  // keeps the resolver's index walk short and stops the log calling a case touch a
  // monitoring change. Same fix as shadow-it-inventory.js and certificate-lifecycle.js:
  // the three domains carried the identical row, so all three are corrected together
  // rather than leaving two siblings to be found later.
  await appendEvent(env, rec, { event_type: "case_recurrence_noted", detail: { case_id: kase.id, recurrence, updated_case: true } });
  return { ok: true, updated: true };
}

async function linkIdentityCase(env, rec, { actor, finding_type, title, summary } = {}) {
  const result = await createManagedCase(env, {
    workspace_id: rec.workspace_id,
    domain_key: "identity_exposure",
    case_type: "identity_case",
    source_finding_type: finding_type || "identity_unexpected_surface",
    source_finding_id: `identity:${rec.canonical_identity_key}`,
    title: title || `Identity exposure review: ${rec.canonical_identity_key}`,
    summary: summary || null,
    severity: "medium",
    actor: actor || { actor_type: "system", actor_id: null },
  });
  if (!result.ok) return result;
  await env.cybermeters_db
    .prepare(`UPDATE identity_exposure SET linked_case_id = ?, updated_at = datetime('now') WHERE id = ? AND workspace_id = ?`)
    .bind(result.case.id, rec.id, rec.workspace_id).run();
  await appendEvent(env, rec, { actor_type: actor?.actor_type || "system", actor_id: actor?.actor_id || null, event_type: "case_linked", detail: { case_id: result.case.id, remediation_id: result.case.remediation_id } });
  return { ok: true, case: result.case };
}
export { linkIdentityCase };

// ── Workflow service ────────────────────────────────────────────────────────
// Customer actions. Every action is workspace-scoped and audit-logged. Customer
// classification is a decision (not observation); recording a config change or
// removal is an ASSERTION (never product-verified); an exception does not make a
// surface secure.
export const IDENTITY_WORKFLOW_ACTIONS = Object.freeze([
  "classify_expected", "classify_unexpected", "classify_investigate", "record_exception", "clear_exception",
  "assign_business_owner", "assign_technical_owner", "assign_identity_owner", "set_business_purpose",
  "begin_remediation", "record_configuration_changed", "record_surface_removed", "request_verification",
  "retire", "reopen",
]);

// The moment the customer last told us they acted, read from the append-only event log
// (identity_exposure has no column for it). `rowid DESC` is the same tie-break the
// occurrence resolver uses: several events can share a created_at to the second, and
// insertion order is the only thing that answers "which did we record most recently".
// Returns null when no action was ever recorded — the caller MUST treat that as
// unknown ordering and fail closed, never as a verification.
async function lastCustomerActionAt(env, workspaceId, recordId) {
  try {
    const row = await env.cybermeters_db
      .prepare(`SELECT created_at FROM identity_exposure_events
                WHERE workspace_id = ? AND record_id = ? AND event_type = 'customer_action_recorded'
                ORDER BY created_at DESC, rowid DESC LIMIT 1`)
      .bind(workspaceId, recordId)
      .first();
    return row?.created_at ?? null;
  } catch {
    return null; // unreadable history => unknown ordering => inconclusive, never verified
  }
}

async function loadRecord(env, workspaceId, id) {
  return env.cybermeters_db
    .prepare(`SELECT * FROM identity_exposure WHERE id = ? AND workspace_id = ?`)
    .bind(id, workspaceId).first().catch(() => null);
}

export async function identityExposureAction(env, workspaceId, id, action, opts = {}) {
  if (!IDENTITY_WORKFLOW_ACTIONS.includes(action)) return { ok: false, code: "invalid_action" };
  const rec = await loadRecord(env, workspaceId, id);
  if (!rec) return { ok: false, code: "not_found" }; // same for foreign + nonexistent
  const actor = { actor_type: "customer", actor_id: opts.actor_id || null };
  const now = new Date().toISOString();
  const set = { updated_at: now };
  let eventType = "monitoring_changed", detail = { action }, openCase = false;

  switch (action) {
    case "classify_expected":
      set.customer_classification = "expected"; set.classification_reason = opts.reason || null;
      eventType = "classified"; detail = { classification: "expected" };
      break;
    case "classify_unexpected":
      if (!String(opts.reason || "").trim()) return { ok: false, code: "reason_required" };
      set.customer_classification = "unexpected"; set.classification_reason = opts.reason;
      eventType = "classified"; detail = { classification: "unexpected" };
      openCase = rec.monitoring_status !== "no_longer_observed";
      break;
    case "classify_investigate":
      if (!String(opts.reason || "").trim()) return { ok: false, code: "reason_required" };
      set.customer_classification = "investigate"; set.classification_reason = opts.reason;
      eventType = "classified"; detail = { classification: "investigate" };
      break;
    case "record_exception":
      if (!String(opts.reason || "").trim()) return { ok: false, code: "reason_required" };
      if (!opts.exception_until || !Number.isFinite(Date.parse(opts.exception_until))) return { ok: false, code: "expiry_required" };
      set.customer_classification = "exception"; set.exception_until = opts.exception_until; set.exception_reason = String(opts.reason).slice(0, 1000);
      set.classification_reason = opts.reason; eventType = "exception_set"; detail = { exception_until: opts.exception_until };
      break;
    case "clear_exception":
      set.exception_until = null; set.exception_reason = null;
      if (rec.customer_classification === "exception") set.customer_classification = "unreviewed";
      eventType = "exception_cleared"; detail = {};
      break;
    case "assign_business_owner":
      if (!String(opts.owner || "").trim()) return { ok: false, code: "owner_required" };
      set.business_owner = String(opts.owner).slice(0, 255);
      set.ownership_status = deriveIdentityOwnershipStatus(set.business_owner, rec.technical_owner, rec.identity_owner);
      eventType = "owner_assigned"; detail = { role: "business", owner: set.business_owner, ownership_status: set.ownership_status };
      break;
    case "assign_technical_owner":
      if (!String(opts.owner || "").trim()) return { ok: false, code: "owner_required" };
      set.technical_owner = String(opts.owner).slice(0, 255);
      set.ownership_status = deriveIdentityOwnershipStatus(rec.business_owner, set.technical_owner, rec.identity_owner);
      eventType = "owner_assigned"; detail = { role: "technical", owner: set.technical_owner, ownership_status: set.ownership_status };
      break;
    case "assign_identity_owner":
      if (!String(opts.owner || "").trim()) return { ok: false, code: "owner_required" };
      set.identity_owner = String(opts.owner).slice(0, 255);
      set.ownership_status = deriveIdentityOwnershipStatus(rec.business_owner, rec.technical_owner, set.identity_owner);
      eventType = "owner_assigned"; detail = { role: "identity", owner: set.identity_owner, ownership_status: set.ownership_status };
      break;
    case "set_business_purpose":
      set.business_purpose = String(opts.business_purpose || "").slice(0, 1000); eventType = "purpose_set"; detail = { business_purpose: set.business_purpose };
      break;
    case "begin_remediation":
      set.remediation_status = "in_progress"; eventType = "remediation_started"; detail = { remediation_status: "in_progress" };
      break;
    case "record_configuration_changed":
      // Customer ASSERTION — not product-verified.
      set.customer_action_status = "configuration_changed"; set.remediation_status = "customer_actioned"; set.verification_status = "not_verified";
      eventType = "customer_action_recorded"; detail = { action_type: "configuration_changed", note: "customer_asserted_not_verified" };
      break;
    case "record_surface_removed":
      set.customer_action_status = "surface_removed"; set.remediation_status = "customer_actioned"; set.verification_status = "not_verified";
      eventType = "customer_action_recorded"; detail = { action_type: "surface_removed", note: "customer_asserted_not_verified" };
      break;
    case "request_verification": {
      const customer_action_at = await lastCustomerActionAt(env, workspaceId, rec.id);
      const evidence = buildIdentityVerification(rec, { now, customer_action_at });
      set.verification_detail_json = safeJson(evidence); set.verification_method = "external_observation";
      if (evidence.verification_result === "verified") {
        set.verification_status = "verified"; set.verified_at = now; set.remediation_status = "verified";
        eventType = "verified"; detail = evidence;
      } else if (evidence.verification_result === "failed") {
        set.verification_status = "failed"; eventType = "verification_failed"; detail = evidence;
      } else {
        set.verification_status = evidence.verification_result; // inconclusive | unsupported | pending
        eventType = "verification_requested"; detail = evidence;
      }
      break;
    }
    case "retire":
      if (!String(opts.reason || "").trim()) return { ok: false, code: "reason_required" };
      set.customer_classification = "retired"; set.remediation_status = "retired"; set.classification_reason = opts.reason;
      eventType = "retired"; detail = { reason: String(opts.reason).slice(0, 1000) };
      break;
    case "reopen":
      set.customer_classification = "unreviewed"; set.remediation_status = "not_started";
      eventType = "reopened"; detail = {};
      break;
    default:
      return { ok: false, code: "invalid_action" };
  }

  const cols = Object.keys(set);
  await env.cybermeters_db
    .prepare(`UPDATE identity_exposure SET ${cols.map((c) => `${c} = ?`).join(", ")} WHERE id = ? AND workspace_id = ?`)
    .bind(...cols.map((c) => set[c]), id, workspaceId).run();
  const updated = { ...rec, ...set };
  await appendEvent(env, updated, { actor_type: "customer", actor_id: actor.actor_id, event_type: eventType, detail });
  if (openCase) await openOrReopenIdentityCase(env, updated, { recurrence: "unexpected_surface", now });
  const fresh = await loadRecord(env, workspaceId, id);
  return { ok: true, item: identityExposureToApi(fresh) };
}

// ── API serializer ──────────────────────────────────────────────────────────
export function identityExposureToApi(row) {
  if (!row) return null;
  return {
    identity_exposure_id: row.id,
    workspace_id: row.workspace_id,
    domain_id: row.domain_id,
    canonical_identity_key: row.canonical_identity_key,
    provider_key: row.provider_key || null,
    provider_name: row.provider_name || null,
    surface_type: row.surface_type || null,
    primary_hostname: row.primary_hostname || null,
    observed_urls: parseJson(row.observed_urls_json, []) || [],
    observed_endpoints: parseJson(row.observed_endpoints_json, []) || [],
    observed_protocols: parseJson(row.observed_protocols_json, []) || [],
    tenant_identifier: row.tenant_identifier || null,
    realm_identifier: row.realm_identifier || null,
    source_types: parseJson(row.source_types_json, []) || [],
    source_evidence: parseJson(row.source_evidence_json, []) || [],
    first_seen_at: row.first_seen_at,
    last_seen_at: row.last_seen_at,
    last_changed_at: row.last_changed_at || null,
    confidence: row.confidence || null,
    // Three DISTINCT dimensions surfaced separately so the UI can label them:
    externally_observed: true,                       // Observed externally
    exposure_status: row.exposure_status,
    risk_status: row.risk_status || null,
    customer_classification: row.customer_classification, // Classified by customer
    classification_reason: row.classification_reason || null,
    business_owner: row.business_owner || null,
    technical_owner: row.technical_owner || null,
    identity_owner: row.identity_owner || null,
    ownership_status: row.ownership_status || deriveIdentityOwnershipStatus(row.business_owner, row.technical_owner, row.identity_owner),
    business_purpose: row.business_purpose || null,
    remediation_status: row.remediation_status,
    customer_action_status: row.customer_action_status || null,
    verification_status: row.verification_status,     // Verified by CyberMeters (only 'verified')
    verification_method: row.verification_method || null,
    verified_at: row.verified_at || null,
    verification_detail: parseJson(row.verification_detail_json, null),
    monitoring_status: row.monitoring_status,
    monitoring_reason: row.monitoring_reason || null,
    material_change: Boolean(row.material_change),
    evidence_age_days: row.evidence_age_days ?? null,
    recurrence_type: row.recurrence_type || null,
    required_case_action: row.required_case_action || null,
    lifecycle_state: row.lifecycle_state,
    exception_until: row.exception_until || null,
    exception_reason: row.exception_reason || null,
    evaluated_at: row.evaluated_at || null,
    linked_case_id: row.linked_case_id || null,
    created_at: row.created_at,
    updated_at: row.updated_at,
    unknown_signals: [...IDENTITY_UNKNOWN_SIGNALS],
    scope_note: "Externally observed identity/login surface only. A publicly visible identity entry point is not automatically a vulnerability. No leaked-credential, breached-password, dark-web, MFA, Conditional Access or internal-policy visibility. Your classification is a decision; a recorded change or removal is not verified until CyberMeters re-observes it externally.",
  };
}

export async function listIdentityExposure(env, workspaceId, { customer_classification = null, risk_status = null, monitoring_status = null, surface_type = null, limit = 100 } = {}) {
  const where = ["workspace_id = ?"]; const binds = [workspaceId];
  if (customer_classification) { where.push("customer_classification = ?"); binds.push(customer_classification); }
  if (risk_status) { where.push("risk_status = ?"); binds.push(risk_status); }
  if (monitoring_status) { where.push("monitoring_status = ?"); binds.push(monitoring_status); }
  if (surface_type) { where.push("surface_type = ?"); binds.push(surface_type); }
  const rows = (await env.cybermeters_db
    .prepare(`SELECT * FROM identity_exposure WHERE ${where.join(" AND ")} ORDER BY last_seen_at DESC LIMIT ?`)
    .bind(...binds, Math.max(1, Math.min(500, Number(limit) || 100))).all().catch(() => ({ results: [] }))).results || [];
  return rows.map(identityExposureToApi);
}
export async function getIdentityExposureRecord(env, workspaceId, id) {
  const row = await loadRecord(env, workspaceId, id);
  return row ? identityExposureToApi(row) : null;
}
export async function listIdentityExposureEvents(env, workspaceId, id) {
  return (await env.cybermeters_db
    .prepare(`SELECT id, actor_type, actor_id, event_type, detail_json, created_at
              FROM identity_exposure_events WHERE workspace_id = ? AND record_id = ? ORDER BY created_at ASC`)
    .bind(workspaceId, id).all().catch(() => ({ results: [] }))).results || [];
}
export async function countIdentityExposureByClassification(env, workspaceId) {
  const rows = (await env.cybermeters_db
    .prepare(`SELECT customer_classification, COUNT(*) AS n FROM identity_exposure WHERE workspace_id = ? GROUP BY customer_classification`)
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];
  const counts = Object.fromEntries(IDENTITY_CLASSIFICATIONS.map((c) => [c, 0]));
  for (const r of rows) counts[r.customer_classification] = r.n;
  return counts;
}
