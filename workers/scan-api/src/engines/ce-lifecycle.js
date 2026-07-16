// ── Cyber Essentials external-evidence lifecycle ─────────────────────────────
// The eighth and last canonical alerting domain.
//
// CE detects nothing of its own (cyber-mot-domains.js: `modules: []`,
// `match: () => false`). Every control it grades re-interprets evidence another
// domain already owns and already alerts on. So it must never raise a second
// "we found X" — it owns exactly one claim no other domain makes:
//
//     a CONTROL THEME's externally evidenced readiness has changed.
//
// "Your Secure Configuration theme is no longer externally evidenced as ready" is a
// different question from "your HSTS header is missing", and it is the question a
// customer preparing for certification is actually asking. The underlying technical
// alert and this one have distinct, honest claims and distinct remediation.
//
// Three rules this engine exists to keep:
//   1. THE QUESTIONNAIRE IS NOT SECURITY TRUTH. It calls
//      buildCyberEssentialsReadiness directly — never getCyberEssentialsSnapshot,
//      which is where answers gate DISPLAY. Through the snapshot, a customer flipping
//      one answer to "unknown" flips `complete` false and `status` null, and would
//      mint a security occurrence from a form edit.
//   2. A SCORE MOVING IS NOT AN EVENT. State is derived from the SET of failing
//      canonical remediation ids, not from the percentage. 72→68 says nothing about
//      which evidence changed; "ce.backlog.remediate stopped failing" does.
//   3. ONLY EXTERNALLY SUPPORTABLE CONTROLS ALERT. access_control and
//      malware_protection declare external_coverage "none" in the repo's own
//      metadata — they are scored from email-auth proxies that measure anti-spoofing,
//      not user access control or endpoint AV. They stay visible and are persisted as
//      `not_externally_assessable`; they can never alert.
import { CE_QUESTIONS } from "../lib/cyber-essentials.js";
import { buildCyberEssentialsReadiness } from "./ce-readiness.js";
import {
  MONITORING_CHANGED, buildMonitoringTransitionDetail, isMonitoringTransition,
} from "./alert-occurrence.js";
import { emitLifecycleAlert } from "./alert-consumers.js";

export const CE_DOMAIN_KEY = "cyber_essentials_readiness";

export const CE_EVENT_WORKSPACE_BASELINE = "workspace_baseline_established";
export const CE_EVENT_BASELINE           = "baseline_established";
export const CE_EVENT_RECOVERED          = "control_recovered";
export const CE_EVENT_UNKNOWN            = "control_evidence_unknown";
export const CE_EVENT_CASE_LINKED        = "case_linked";

export const CE_NON_ALERTABLE_EVENT_TYPES = Object.freeze([
  CE_EVENT_WORKSPACE_BASELINE, CE_EVENT_BASELINE, CE_EVENT_RECOVERED,
  CE_EVENT_UNKNOWN, CE_EVENT_CASE_LINKED,
]);

// The two actionable readiness transitions. Deliberately few: CE re-frames evidence
// other domains own, so every extra recurrence here is another way to tell a customer
// the same thing twice.
export const CE_RECURRENCE_NOT_READY = "externally_observed_control_not_ready";
export const CE_RECURRENCE_WORSENED  = "externally_observed_control_worsened";

// recurrence → the canonical remediation's finding_type. Without this the consumer
// falls back to "<entity>: review required" — a content-free email, which is the one
// thing a readiness alert must never be. Kept as an explicit frozen map (the PR-B3
// shape) so a new recurrence cannot silently inherit someone else's copy.
export const CE_RECURRENCE_FINDING_TYPE = Object.freeze({
  [CE_RECURRENCE_NOT_READY]: "ce_control_not_ready",
  [CE_RECURRENCE_WORSENED]:  "ce_control_worsened",
});

// The repo's own honesty metadata decides who may alert. Read from CE_QUESTIONS
// rather than restated here, so it cannot drift from the questionnaire's own claim.
const COVERAGE = Object.freeze(Object.fromEntries(
  CE_QUESTIONS.map((c) => [c.control_key, c.external_coverage || "none"]),
));
const LABEL = Object.freeze(Object.fromEntries(CE_QUESTIONS.map((c) => [c.control_key, c.label])));

export function ceControlIsExternallyAssessable(controlKey) {
  return COVERAGE[String(controlKey || "")] === "partial";
}

const safeJson = (v) => { try { return v == null ? null : JSON.stringify(v); } catch { return null; } };
function newId(prefix) {
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return `${prefix}-${(uuid || "").slice(0, 12).padEnd(12, "0")}`;
}

async function appendEvent(env, { workspace_id, record_id, event_type, detail = null, actor_type = "system", actor_id = null }) {
  await env.cybermeters_db
    .prepare(`INSERT INTO cyber_essentials_events
        (id, record_id, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .bind(newId("cee"), record_id, workspace_id, actor_type, actor_id, event_type, safeJson(detail))
    .run();
}

async function workspaceIsBaselined(env, workspaceId) {
  const row = await env.cybermeters_db
    .prepare(`SELECT 1 AS x FROM cyber_essentials_events
              WHERE workspace_id = ? AND record_id = ? AND event_type = ? LIMIT 1`)
    .bind(workspaceId, workspaceId, CE_EVENT_WORKSPACE_BASELINE)
    .first().catch(() => null);
  return Boolean(row);
}

// One control category → its externally evidenced readiness.
//
// The fingerprint is the SORTED SET of failing canonical remediation ids. Two
// properties make it the right identity:
//   • a count moving does not change it — "1 critical finding" and "2 critical
//     findings" are both ce.backlog.remediate, so a backlog growing is not a new
//     readiness event;
//   • a scoring-weight change does not change it — the score is not consulted at all.
// It moves only when a genuinely different gap appears or clears.
export function gradeCeControl(category) {
  const key = category?.key;
  if (!key) return null;
  const coverage = COVERAGE[key] || "none";

  // external_coverage "none": visible in the product, never an alert. The proxies it
  // is scored from (SPF/DMARC) measure anti-spoofing, not this control.
  if (coverage !== "partial") {
    return {
      control_key: key, label: LABEL[key] || category.label || key, coverage,
      state: "not_externally_assessable",
      reason: "control_not_externally_observable",
      fingerprint: null, evidence: [], unknown: [],
    };
  }

  const unknown = Array.isArray(category.unknown) ? category.unknown : [];
  const evidence = (category.remediations || []).map((r) => ({
    remediation_id: r.remediation_id,
    customer_title: r.customer_title,
  }));

  // Evidence we did not collect => unknown. Never a pass, never a gap. This is the
  // branch that stops a timed-out probe or a missing scan becoming "not ready".
  if (unknown.length > 0) {
    return {
      control_key: key, label: LABEL[key] || category.label || key, coverage,
      state: "unknown",
      reason: "external_evidence_not_collected",
      fingerprint: null, evidence, unknown,
    };
  }

  const refs = [...new Set(evidence.map((e) => e.remediation_id))].sort();
  return {
    control_key: key, label: LABEL[key] || category.label || key, coverage,
    state: refs.length > 0 ? "not_ready" : "ready",
    reason: refs.length > 0 ? "external_evidence_shows_gaps" : "external_evidence_supports_readiness",
    fingerprint: refs.join("|") || null,
    evidence, unknown,
  };
}

/**
 * evaluateCyberEssentialsLifecycle — correlate the workspace's externally evidenced
 * CE readiness into durable per-control records + append-only history, and alert on
 * genuine control-theme readiness transitions.
 *
 * Never throws.
 */
export async function evaluateCyberEssentialsLifecycle(env, workspaceId, { scanId = null } = {}) {
  try {
    if (!workspaceId) return { skipped: "incomplete_context" };

    const live = await env.cybermeters_db
      .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
      .bind(workspaceId).first().catch(() => null);
    if (!live) return { skipped: "workspace_inactive" };

    // DIRECT, never getCyberEssentialsSnapshot: this is the answer-free external
    // verdict. Routing through the snapshot is how a form edit becomes an alert.
    const readiness = await buildCyberEssentialsReadiness(workspaceId, env).catch(() => null);
    if (!readiness) return { skipped: "readiness_unavailable" };

    // No external evidence at all => nothing to say. Not ready, not unready, not a
    // grade. ce-readiness returns `assessable:false` for no scan / missing R2 object
    // / a failed read alike.
    if (readiness.assessable === false) return { skipped: "no_external_evidence" };

    const existing = (await env.cybermeters_db
      .prepare(`SELECT * FROM cyber_essentials_control_records WHERE workspace_id = ?`)
      .bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];
    const byKey = new Map(existing.map((r) => [r.control_key, r]));

    const seeding = !(await workspaceIsBaselined(env, workspaceId));
    let created = 0, transitions = 0, alerts = 0, recovered = 0, unknown = 0;

    for (const category of (readiness.categories || [])) {
      const g = gradeCeControl(category);
      if (!g) continue;
      const rec = byKey.get(g.control_key) || null;

      // Only a not-ready, externally assessable control is an actionable condition.
      const actionable = g.state === "not_ready";
      const recurrence = actionable ? CE_RECURRENCE_NOT_READY : null;
      // The band is the evidence fingerprint, not a severity: it makes "a NEW gap
      // appeared on an already-not-ready control" a transition in its own right,
      // which is the PR-B2 band idea applied to evidence rather than to grade.
      const band = actionable ? g.fingerprint : null;

      if (!rec) {
        const id = newId("cec");
        await env.cybermeters_db
          .prepare(`INSERT INTO cyber_essentials_control_records
              (id, workspace_id, control_key, control_label, external_coverage, readiness_state,
               readiness_reason, evidence_fingerprint, evidence_json, unknown_json, last_scan_id,
               last_assessed_at, first_seen_at, last_seen_at, last_changed_at, monitoring_status,
               recurrence_type, recurrence_band, lifecycle_state, created_at, updated_at, evaluated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), datetime('now'),
                    datetime('now'), ?, ?, ?, 'observed', datetime('now'), datetime('now'), datetime('now'))`)
          .bind(id, workspaceId, g.control_key, g.label, g.coverage, g.state, g.reason,
                g.fingerprint, safeJson(g.evidence), safeJson(g.unknown), scanId,
                seeding ? "baseline" : "observed", recurrence, band)
          .run();
        created++;

        if (seeding) {
          await appendEvent(env, {
            workspace_id: workspaceId, record_id: id, event_type: CE_EVENT_BASELINE,
            detail: {
              reason: "pre_existing_at_baseline", control_key: g.control_key, control_label: g.label,
              readiness_state: g.state, external_coverage: g.coverage,
              evidence: g.evidence, unknown: g.unknown, scan_id: scanId,
            },
          }).catch(() => {});
          continue;
        }
        if (actionable) {
          await appendEvent(env, {
            workspace_id: workspaceId, record_id: id, event_type: MONITORING_CHANGED,
            detail: ceTransitionDetail({ g, from: null, recurrence, band, scanId, reason: "control_first_observed_not_ready" }),
          }).catch(() => {});
          transitions++;
          const r = await emitLifecycleAlert(env, {
            workspace_id: workspaceId, domain_key: CE_DOMAIN_KEY,
            record_id: id, entity: g.control_key, recurrence,
            finding_type: CE_RECURRENCE_FINDING_TYPE[recurrence] || null,
          }).catch(() => null);
          if (r?.emitted) alerts++;
        }
        continue;
      }

      // ── What counts as a move ─────────────────────────────────────────────
      // The READINESS STATE is this domain's monitoring dimension, and it must be in
      // the comparison rather than the recurrence alone. `ready` and `unknown` both
      // carry recurrence_type null — they are only actionable when not_ready — so
      // comparing recurrences alone makes ready↔unknown INVISIBLE, and a genuine
      // recovery out of an evidence outage would never be recorded. The fingerprint
      // rides as the band, so a NEW gap on an already-not-ready control is a move
      // too, while a count or a score moving is not.
      const evidenceChanged =
        String(rec.readiness_state ?? "") !== String(g.state ?? "")
        || String(rec.evidence_fingerprint ?? "") !== String(g.fingerprint ?? "");
      const wasBaseline = rec.monitoring_status === "baseline";
      // A control STAYS baseline until its evidence actually moves — the PR-B3
      // pass-two trap: flipping baseline→observed on identical evidence reads as a
      // transition and releases the backlog one pass later.
      const nextMonitoring = (wasBaseline && !evidenceChanged) ? "baseline" : "observed";

      const prev = { monitoring_status: rec.readiness_state, recurrence_type: rec.recurrence_type, recurrence_band: rec.evidence_fingerprint };
      const next = { monitoring_status: g.state, recurrence_type: recurrence, recurrence_band: g.fingerprint };

      await env.cybermeters_db
        .prepare(`UPDATE cyber_essentials_control_records
             SET control_label = ?, external_coverage = ?, readiness_state = ?, readiness_reason = ?,
                 evidence_fingerprint = ?, evidence_json = ?, unknown_json = ?, last_scan_id = ?,
                 last_assessed_at = datetime('now'), last_seen_at = datetime('now'),
                 last_changed_at = CASE WHEN ? = 1 THEN datetime('now') ELSE last_changed_at END,
                 monitoring_status = ?, recurrence_type = ?, recurrence_band = ?,
                 updated_at = datetime('now'), evaluated_at = datetime('now')
           WHERE id = ?`)
        .bind(g.label, g.coverage, g.state, g.reason, g.fingerprint, safeJson(g.evidence),
              safeJson(g.unknown), scanId, evidenceChanged ? 1 : 0,
              nextMonitoring, recurrence, band, rec.id)
        .run().catch(() => {});

      if (!isMonitoringTransition(prev, next)) continue;

      if (g.state === "ready") {
        await appendEvent(env, {
          workspace_id: workspaceId, record_id: rec.id, event_type: CE_EVENT_RECOVERED,
          detail: {
            reason: "external_evidence_supports_readiness_again", control_key: g.control_key,
            control_label: g.label, from_evidence_fingerprint: rec.evidence_fingerprint, scan_id: scanId,
          },
        }).catch(() => {});
        recovered++;
        continue;
      }
      if (g.state === "unknown" || g.state === "not_externally_assessable") {
        await appendEvent(env, {
          workspace_id: workspaceId, record_id: rec.id, event_type: CE_EVENT_UNKNOWN,
          detail: {
            reason: g.reason, control_key: g.control_key, control_label: g.label,
            external_coverage: g.coverage, unknown: g.unknown,
            from_evidence_fingerprint: rec.evidence_fingerprint, scan_id: scanId,
          },
        }).catch(() => {});
        unknown++;
        continue;
      }
      if (nextMonitoring === "baseline") continue;

      // not_ready: newly not-ready, or a NEW gap on an already-not-ready control.
      const worsened = rec.readiness_state === "not_ready" && rec.recurrence_band && band !== rec.recurrence_band;
      const rec2 = worsened ? CE_RECURRENCE_WORSENED : CE_RECURRENCE_NOT_READY;
      await appendEvent(env, {
        workspace_id: workspaceId, record_id: rec.id, event_type: MONITORING_CHANGED,
        detail: ceTransitionDetail({
          g, from: rec, recurrence: rec2, band, scanId,
          reason: worsened ? "external_evidence_worsened" : "control_became_not_ready",
        }),
      }).catch(() => {});
      transitions++;
      const r = await emitLifecycleAlert(env, {
        workspace_id: workspaceId, domain_key: CE_DOMAIN_KEY,
        record_id: rec.id, entity: g.control_key, recurrence: rec2,
        finding_type: CE_RECURRENCE_FINDING_TYPE[rec2] || null,
        case_id: rec.linked_case_id || null,
      }).catch(() => null);
      if (r?.emitted) alerts++;
    }

    if (seeding) {
      await appendEvent(env, {
        workspace_id: workspaceId, record_id: workspaceId, event_type: CE_EVENT_WORKSPACE_BASELINE,
        detail: { reason: "first_evaluation", baselined_controls: created, scan_id: scanId },
      }).catch(() => {});
    }

    return { evaluated: (readiness.categories || []).length, created, transitions, alerts, recovered, unknown, seeding };
  } catch (err) {
    console.error("[ce-lifecycle] evaluation failed", JSON.stringify({ workspace_id: workspaceId, reason: err?.message }));
    return { skipped: "evaluator_error" };
  }
}

// Every CE notification must be able to name: the control theme, the exact external
// evidence sources, the previous externally evidenced state, the current one, the
// assessment identity, and the honest limitation. A readiness verdict with nothing
// behind it is the thing this domain must never produce.
function ceTransitionDetail({ g, from, recurrence, band, scanId, reason }) {
  return {
    ...buildMonitoringTransitionDetail({
      from_monitoring_status: from?.monitoring_status ?? null,
      to_monitoring_status: "observed",
      from_recurrence_type: from?.recurrence_type ?? null,
      to_recurrence_type: recurrence,
      required_case_action: "open_or_reopen",
      reason,
      entity: g.control_key,
    }),
    recurrence_band: band,
    control_key: g.control_key,
    control_label: g.label,
    external_coverage: g.coverage,
    previous_readiness_state: from?.readiness_state ?? null,
    current_readiness_state: g.state,
    // The named external evidence behind the claim — canonical remediation ids, so
    // the customer can join this to the same advice the scan surfaces show.
    external_evidence: g.evidence,
    from_evidence_fingerprint: from?.evidence_fingerprint ?? null,
    evidence_fingerprint: band,
    assessment_scan_id: scanId,
    limitation: "Indicative readiness from externally observable evidence only. CyberMeters does not certify Cyber Essentials.",
  };
}

// ── Read accessors — the customer-facing shape ──────────────────────────────
// This helper had ZERO callers repo-wide: mig 090 persisted per-control readiness,
// evidence and recovery history that no route or page ever read, so customers received
// CE alerts about controls they could not open. Wiring it up meant fixing it first —
// `SELECT *` leaked internal fields and there was no bound.
//
// The honesty boundary is enforced HERE, not in the UI. There is no "verified" value in
// this domain's vocabulary and there must never be one: `readiness_state` is
// ready|not_ready|unknown|not_externally_assessable, and even `ready` means "the
// externally observable part of this control looks aligned", never that CyberMeters
// certified anything. `external_coverage` ships alongside it precisely so `ready` can
// never be read as a full pass — two of the five controls are permanently
// `not_externally_assessable` because nothing external can see them.
export function ceControlRecordToApi(row = {}) {
  const parse = (raw, fb) => { try { return raw ? JSON.parse(raw) : fb; } catch { return fb; } };
  return {
    id: row.id,
    control_key: row.control_key,
    control_label: row.control_label ?? null,
    // The verdict, and the reason it is only ever indicative.
    readiness_state: row.readiness_state ?? null,
    readiness_reason: row.readiness_reason ?? null,
    external_coverage: row.external_coverage ?? null,   // partial | none
    // WHICH evidence moved, and what we could not see. Both customer-facing: a gap the
    // product cannot observe must be visible as unobserved, not absent.
    evidence: parse(row.evidence_json, []),
    unknown_signals: parse(row.unknown_json, []),
    last_scan_id: row.last_scan_id ?? null,
    last_assessed_at: row.last_assessed_at ?? null,
    first_seen_at: row.first_seen_at ?? null,
    last_seen_at: row.last_seen_at ?? null,
    last_changed_at: row.last_changed_at ?? null,
    linked_case_id: row.linked_case_id ?? null,
  };
}

export function ceEventToApi(row = {}) {
  let detail = null;
  try { detail = row.detail_json ? JSON.parse(row.detail_json) : null; } catch { detail = null; }
  return {
    id: row.id,
    event_type: row.event_type,
    actor_type: row.actor_type ?? null,
    created_at: row.created_at,
    detail,
  };
}

// `control_key` is UNIQUE per workspace (mig 090:124), so ordering by it is already
// deterministic and needs no tie-break. Bounded anyway: the bound is the contract, not
// an assumption about how many controls exist today.
export async function listCeControlRecords(env, workspaceId, { readiness_state = null, limit = 50, offset = 0 } = {}) {
  const where = ["workspace_id = ?"];
  const binds = [workspaceId];
  if (readiness_state) { where.push("readiness_state = ?"); binds.push(String(readiness_state)); }
  const rows = await env.cybermeters_db
    .prepare(`SELECT * FROM cyber_essentials_control_records
              WHERE ${where.join(" AND ")}
              ORDER BY control_key ASC
              LIMIT ? OFFSET ?`)
    .bind(...binds, Number(limit), Number(offset)).all().catch(() => ({ results: [] }));
  return (rows.results || []).map(ceControlRecordToApi);
}

// Bounded by the CE model itself — five controls, one row each per workspace — but the
// count is still queried rather than assumed: a bound that comes from a constant in
// another file is a comment, not a contract.
export async function countCeControlRecords(env, workspaceId, { readiness_state = null } = {}) {
  const where = ["workspace_id = ?"];
  const binds = [workspaceId];
  if (readiness_state) { where.push("readiness_state = ?"); binds.push(String(readiness_state)); }
  const row = await env.cybermeters_db
    .prepare(`SELECT COUNT(*) AS n FROM cyber_essentials_control_records WHERE ${where.join(" AND ")}`)
    .bind(...binds).first().catch(() => null);
  return Number(row?.n ?? 0);
}

export async function getCeControlRecord(env, workspaceId, recordId) {
  const row = await env.cybermeters_db
    .prepare(`SELECT * FROM cyber_essentials_control_records WHERE workspace_id = ? AND id = ?`)
    .bind(workspaceId, recordId).first().catch(() => null);
  return row ? ceControlRecordToApi(row) : null;
}

export async function listCeControlEvents(env, workspaceId, recordId, { limit = 200 } = {}) {
  const rows = await env.cybermeters_db
    .prepare(`SELECT * FROM cyber_essentials_events
              WHERE workspace_id = ? AND record_id = ?
              ORDER BY created_at DESC, rowid DESC
              LIMIT ?`)
    .bind(workspaceId, recordId, Number(limit)).all().catch(() => ({ results: [] }));
  return (rows.results || []).map(ceEventToApi);
}
