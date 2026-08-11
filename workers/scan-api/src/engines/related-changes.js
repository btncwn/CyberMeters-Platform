// ── M6 Phase B1: Related Changes — orchestrator, persistence & read surface ──
//
// Runs as scan-finalize Phase 8x (AFTER the case-producing lifecycle phases 8a/8k–8n
// and P4's immutable DMARC phase 8p). The canonical snapshot is already durable;
// the existing report route freezes this summary separately in the snapshot row's
// related_changes_json sidecar the first time the report is rendered.
// Composes the read-only adapter (related-changes-adapter.js) and the deterministic
// rules engine (related-changes-rules.js), then persists clusters + evidence pointers
// per migration 098. (design note §4, §7, §8.)
//
// Invariants held here:
//   • Complete-evidence floor (§4.7): correlation runs ONLY on a complete scan with a
//     complete previous scan to bound the window — the posture-events precedent. A
//     partial/degraded scan produces nothing.
//   • Evidence by POINTER, never a copy (§7): related_change_evidence stores the source
//     table + record id + observation time; it never duplicates the producer's payload.
//   • Append-only recurrence: a source event is cited once per cluster; recurrence bumps
//     only when a scan adds genuinely NEW correlated evidence.
//   • Customer declaration is never silently reset (§4.6): a recurrence preserves an
//     existing customer_state (expected / unrelated / unexpected_confirmed).
//   • Manual case only (§8): no automatic case or alert creation in v1.

import { collectChangeEvents } from "./related-changes-adapter.js";
import { correlateChangeEvents } from "./related-changes-rules.js";
import { createManagedCase } from "./managed-case-model.js";
import { createAuditEvent } from "../lib/events.js";
import { projectRelatedChangeRecurrence } from "./identity-evidence-contract.js";

function newId(prefix) {
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return `${prefix}-${(uuid || "").slice(0, 16).padEnd(16, "0")}`;
}

async function sha256Hex(input) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(input)));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Stable cluster identity within a workspace: sha256(registrable_domain | rule_id).
export async function computeClusterKey(registrableDomain, ruleId) {
  return sha256Hex(`${String(registrableDomain).toLowerCase()}|${ruleId}`);
}

export const CUSTOMER_STATES = Object.freeze(["new", "expected", "unrelated", "unexpected_confirmed"]);
// Customer-settable states — 'new' is a system-assigned initial state, never a target.
export const CUSTOMER_FEEDBACK_STATES = Object.freeze(["expected", "unrelated", "unexpected_confirmed"]);
export const RELATED_CHANGES_CAUSALITY_NOTICE =
  "These changes were observed close together and may be related. CyberMeters has not established that one caused the other or that they indicate compromise.";

// B4 read projection. This is the sole approved raw identity_assets access
// outside the writer: append-only evidence pointers must be resolved to detect
// legacy tuple multiplicity and unavailable audit references. It is batched per
// list/detail statement and never rewrites history or supplies identity counts.
export const RELATED_CHANGE_IDENTITY_POINTER_CTES = `
WITH identity_pointers AS (
  SELECT evidence.related_change_id,
         evidence.id AS evidence_id,
         identity.id AS identity_id,
         identity.workspace_id,
         identity.domain_id,
         identity.identity_type,
         IFNULL(identity.hostname, '') AS canonical_hostname,
         IFNULL(identity.provider, '') AS canonical_provider
    FROM related_change_evidence evidence
    LEFT JOIN identity_assets identity
      ON identity.id = evidence.source_record_id
     AND identity.workspace_id = evidence.workspace_id
   WHERE evidence.workspace_id = ?
     AND evidence.source_table = 'identity_assets'
),
identity_pointer_stats AS (
  SELECT related_change_id,
         COUNT(*) AS identity_pointer_count,
         SUM(CASE WHEN identity_id IS NOT NULL THEN 1 ELSE 0 END) AS identity_resolved_pointer_count
    FROM identity_pointers
   GROUP BY related_change_id
),
identity_tuple_counts AS (
  SELECT related_change_id, workspace_id, domain_id, identity_type,
         canonical_hostname, canonical_provider,
         COUNT(DISTINCT identity_id) AS identity_row_count
    FROM identity_pointers
   WHERE identity_id IS NOT NULL
   GROUP BY related_change_id, workspace_id, domain_id, identity_type,
            canonical_hostname, canonical_provider
),
identity_pollution AS (
  SELECT related_change_id,
         MAX(CASE WHEN identity_row_count > 1 THEN 1 ELSE 0 END) AS polluted
    FROM identity_tuple_counts
   GROUP BY related_change_id
)
`;

// ── Window ───────────────────────────────────────────────────────────────────
// The bounded window is [previous-complete-scan time, this-scan time]. A complete
// previous scan must exist, exactly as posture-events requires, so a first scan (where
// everything is trivially "new") never floods correlations.
async function computeWindow(env, { workspaceId, domainId, scanId, assessedAt }) {
  // Scoped to THIS workspace's scans of the domain. Legacy scans predate the
  // scans.workspace_id backfill (mig 021) and carry NULL, so they are tolerated — the
  // query only needs a timestamp to bound the window; the evidence reads it bounds are
  // themselves strictly workspace_id-filtered in collectChangeEvents.
  const prev = await env.cybermeters_db
    .prepare(
      `SELECT created_at FROM scans
        WHERE domain_id = ? AND (workspace_id = ? OR workspace_id IS NULL)
          AND id != ? AND status = 'completed' AND scan_quality = 'complete'
          AND created_at <= ?
        ORDER BY created_at DESC LIMIT 1`
    )
    .bind(domainId, workspaceId, scanId, assessedAt)
    .first();
  if (!prev || !prev.created_at) return null; // no adjacent complete scan → no window
  return { windowStart: String(prev.created_at), windowEnd: String(assessedAt) };
}

// ── Persistence ────────────────────────────────────────────────────────────────
async function persistCluster(env, { workspaceId, scanId, assessedAt, cluster }) {
  const db = env.cybermeters_db;
  const clusterKey = await computeClusterKey(cluster.registrable_domain, cluster.rule_id);
  const observedTimes = cluster.events.map((e) => e.observed_at).filter(Boolean).sort();
  const firstObserved = observedTimes[0] || assessedAt;

  const existing = await db
    .prepare(`SELECT * FROM related_changes WHERE workspace_id = ? AND cluster_key = ?`)
    .bind(workspaceId, clusterKey)
    .first();

  let relatedChangeId;
  if (!existing) {
    relatedChangeId = newId("rc");
    await db
      .prepare(
        `INSERT INTO related_changes
           (id, workspace_id, cluster_key, registrable_domain, rule_id, direction,
            signal_family_count, independent_producer_count, confidence, completeness,
            customer_state, first_seen, last_seen, recurrence_count, last_scan_id,
            created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'correlated', ?, 'new', ?, ?, 1, ?, datetime('now'), datetime('now'))`
      )
      .bind(
        relatedChangeId, workspaceId, clusterKey, cluster.registrable_domain, cluster.rule_id,
        cluster.direction, cluster.signal_family_count, cluster.independent_producer_count,
        cluster.completeness, firstObserved, assessedAt, scanId
      )
      .run();
  } else {
    relatedChangeId = existing.id;
  }

  // Append evidence pointers (once per cluster). Count genuinely new rows so recurrence
  // reflects scans that added new correlated evidence, not re-observations of the same.
  let inserted = 0;
  for (const e of cluster.events) {
    const r = await db
      .prepare(
        `INSERT OR IGNORE INTO related_change_evidence
           (id, related_change_id, workspace_id, producer_family, source_table,
            source_record_id, source_event_type, entity_key, observed_at, evidence_ref, scan_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(
        newId("rce"), relatedChangeId, workspaceId, e.producer_family, e.source_table,
        String(e.source_record_id ?? ""), String(e.event_type ?? ""), e.entity_key,
        e.observed_at || assessedAt, e.evidence_ref ?? null, scanId
      )
      .run();
    inserted += Number(r?.meta?.changes || 0);
  }

  // Recurrence / refresh. A brand-new cluster is already at recurrence 1. An existing
  // cluster bumps ONLY when this scan (a) is a different scan than last recorded AND
  // (b) added new correlated evidence. customer_state is preserved (§4.6).
  if (existing) {
    const isNewScan = existing.last_scan_id !== scanId;
    if (isNewScan && inserted > 0) {
      await db
        .prepare(
          `UPDATE related_changes
              SET recurrence_count = recurrence_count + 1,
                  last_seen = ?, last_scan_id = ?,
                  direction = ?, signal_family_count = ?, independent_producer_count = ?,
                  completeness = ?, updated_at = datetime('now')
            WHERE id = ?`
        )
        .bind(
          assessedAt, scanId, cluster.direction, cluster.signal_family_count,
          cluster.independent_producer_count, cluster.completeness, relatedChangeId
        )
        .run();
    }
  }
  return { relatedChangeId, created: !existing, evidenceInserted: inserted };
}

// ── Phase 8x entrypoint ──────────────────────────────────────────────────────
/**
 * correlateRelatedChanges — non-fatal by construction (the scan already completed).
 * @returns {Promise<{ran:boolean, clusters:number, reason?:string}>}
 */
export async function correlateRelatedChanges(env, { workspaceId, domainId, scanId, scanQuality, assessedAt }) {
  if (!workspaceId || !domainId || !scanId) return { ran: false, clusters: 0, reason: "missing_context" };
  // §4.7 complete-evidence floor.
  if (scanQuality !== "complete") return { ran: false, clusters: 0, reason: "scan_not_complete" };

  const window = await computeWindow(env, { workspaceId, domainId, scanId, assessedAt });
  if (!window) return { ran: false, clusters: 0, reason: "no_adjacent_complete_scan" };

  const events = await collectChangeEvents(env, {
    workspaceId, windowStart: window.windowStart, windowEnd: window.windowEnd,
  });
  const clusters = correlateChangeEvents(events, { completeness: "complete" });

  let persisted = 0;
  for (const cluster of clusters) {
    try {
      await persistCluster(env, { workspaceId, scanId, assessedAt, cluster });
      persisted += 1;
    } catch { /* per-cluster non-fatal — one bad row must not drop the rest */ }
  }
  return { ran: true, clusters: persisted };
}

// ── Read surface (API) ───────────────────────────────────────────────────────
export async function listRelatedChanges(env, workspaceId, { customer_state = null, limit = 50, offset = 0 } = {}) {
  const lim = Math.min(Math.max(Number(limit) || 50, 1), 200);
  const off = Math.max(Number(offset) || 0, 0);
  const where = ["changes.workspace_id = ?"];
  const binds = [workspaceId, workspaceId];
  if (customer_state && CUSTOMER_STATES.includes(customer_state)) {
    where.push("changes.customer_state = ?");
    binds.push(customer_state);
  }
  const rows = await env.cybermeters_db
    .prepare(
      `${RELATED_CHANGE_IDENTITY_POINTER_CTES}
       SELECT changes.id, changes.registrable_domain, changes.rule_id, changes.direction,
              changes.signal_family_count, changes.independent_producer_count,
              changes.confidence, changes.completeness, changes.customer_state,
              changes.first_seen, changes.last_seen, changes.recurrence_count,
              changes.linked_case_id, changes.created_at, changes.updated_at,
              COALESCE(stats.identity_pointer_count, 0) -
                COALESCE(stats.identity_resolved_pointer_count, 0) AS identity_unresolved_pointer_count,
              COALESCE(pollution.polluted, 0) AS identity_polluted_tuple_count
         FROM related_changes changes
         LEFT JOIN identity_pointer_stats stats ON stats.related_change_id = changes.id
         LEFT JOIN identity_pollution pollution ON pollution.related_change_id = changes.id
        WHERE ${where.join(" AND ")}
        ORDER BY changes.last_seen DESC
        LIMIT ? OFFSET ?`
    )
    .bind(...binds, lim, off)
    .all();
  return (rows.results || []).map((row) => ({
    ...row,
    recurrence: projectRelatedChangeRecurrence(row),
  }));
}

/**
 * getAssessmentContext — read-only signal the empty state uses to distinguish "not yet
 * assessed" from "assessed, nothing found". It does NOT change the correlation model,
 * the schema or any persistence: it just counts the workspace's complete scans (a
 * complete PLUS a complete previous scan is what correlation needs) and reports the
 * latest scan's quality. Tenant-scoped via workspace_domains.
 *
 * The unobservable edge — a complete latest scan whose Phase 8x errored — cannot be
 * distinguished here without a schema marker (out of scope); it is surfaced to operators
 * by the sanitized scan-finalize log instead, and reads to the customer as "no related
 * changes", which is the honest customer-facing statement (we hold no clusters).
 */
export async function getAssessmentContext(env, workspaceId) {
  const db = env.cybermeters_db;
  const completeRow = await db
    .prepare(
      `SELECT COUNT(*) AS c FROM scans s
         JOIN workspace_domains wd ON wd.domain_id = s.domain_id
        WHERE wd.workspace_id = ? AND s.status = 'completed' AND s.scan_quality = 'complete'`
    )
    .bind(workspaceId)
    .first()
    .catch(() => null);
  const latestRow = await db
    .prepare(
      `SELECT s.scan_quality AS q FROM scans s
         JOIN workspace_domains wd ON wd.domain_id = s.domain_id
        WHERE wd.workspace_id = ? AND s.status = 'completed'
        ORDER BY s.created_at DESC LIMIT 1`
    )
    .bind(workspaceId)
    .first()
    .catch(() => null);
  const completeScans = Number(completeRow?.c || 0);
  return {
    complete_scans: completeScans,
    // Correlation needs a complete scan AND a complete previous scan to bound the window.
    correlation_possible: completeScans >= 2,
    latest_scan_quality: latestRow?.q ?? null,
  };
}

export async function getRelatedChange(env, workspaceId, id) {
  const cluster = await env.cybermeters_db
    .prepare(`${RELATED_CHANGE_IDENTITY_POINTER_CTES}
      SELECT changes.*,
             COALESCE(stats.identity_pointer_count, 0) -
               COALESCE(stats.identity_resolved_pointer_count, 0) AS identity_unresolved_pointer_count,
             COALESCE(pollution.polluted, 0) AS identity_polluted_tuple_count
        FROM related_changes changes
        LEFT JOIN identity_pointer_stats stats ON stats.related_change_id = changes.id
        LEFT JOIN identity_pollution pollution ON pollution.related_change_id = changes.id
       WHERE changes.workspace_id = ? AND changes.id = ?`)
    .bind(workspaceId, workspaceId, id)
    .first();
  if (!cluster) return null;
  const evidence = await env.cybermeters_db
    .prepare(
      `SELECT producer_family, source_table, source_record_id, source_event_type,
              entity_key, observed_at, evidence_ref, scan_id
         FROM related_change_evidence
        WHERE related_change_id = ? AND workspace_id = ?
        ORDER BY observed_at ASC`
    )
    .bind(id, workspaceId)
    .all();
  return {
    cluster: { ...cluster, recurrence: projectRelatedChangeRecurrence(cluster) },
    evidence: evidence.results || [],
  };
}

// ── Customer feedback (append-only via audit_events) ─────────────────────────
export async function setRelatedChangeCustomerState(env, workspaceId, id, newState, { userId = null, note = null } = {}) {
  if (!CUSTOMER_FEEDBACK_STATES.includes(newState)) {
    return { ok: false, code: "invalid_state" };
  }
  const cluster = await env.cybermeters_db
    .prepare(`SELECT id, customer_state FROM related_changes WHERE workspace_id = ? AND id = ?`)
    .bind(workspaceId, id)
    .first();
  if (!cluster) return { ok: false, code: "not_found" };

  await env.cybermeters_db
    .prepare(`UPDATE related_changes SET customer_state = ?, updated_at = datetime('now') WHERE workspace_id = ? AND id = ?`)
    .bind(newState, workspaceId, id)
    .run();

  await createAuditEvent(env, {
    workspace_id: workspaceId,
    user_id: userId,
    actor_type: userId ? "customer" : "system",
    event_type: "related_change_feedback",
    entity_type: "related_change",
    entity_id: id,
    description: `Related change marked '${newState}'`,
    metadata: { from_state: cluster.customer_state, to_state: newState, note: note ? String(note).slice(0, 2000) : null },
  });
  return { ok: true, customer_state: newState };
}

// ── Manual case linkage (§8) — no automatic case creation ────────────────────
export async function linkRelatedChangeToCase(env, workspaceId, id, caseId) {
  const cluster = await env.cybermeters_db
    .prepare(`SELECT id FROM related_changes WHERE workspace_id = ? AND id = ?`)
    .bind(workspaceId, id)
    .first();
  if (!cluster) return { ok: false, code: "not_found" };
  const kase = await env.cybermeters_db
    .prepare(`SELECT id FROM managed_cases WHERE id = ? AND workspace_id = ?`)
    .bind(caseId, workspaceId)
    .first();
  if (!kase) return { ok: false, code: "case_not_found" };
  await env.cybermeters_db
    .prepare(`UPDATE related_changes SET linked_case_id = ?, updated_at = datetime('now') WHERE workspace_id = ? AND id = ?`)
    .bind(caseId, workspaceId, id)
    .run();
  return { ok: true, linked_case_id: caseId };
}

// A cluster's signal family → the canonical BASE managed-case type it belongs to. Only
// base case types are creatable through createManagedCase (their machine starts at the
// factory's hardcoded 'detected' initial state; ASM/brand have their own creation
// paths and start at 'open'). Preference order below is deterministic. The 'asset'
// family has no base case type, so a case is opened under the cluster's OTHER family —
// every rule pairs asset with a family that does map, or pairs two mapping families.
const FAMILY_TO_BASE_CASE = Object.freeze({
  cert: { domain_key: "certificates_trust", case_type: "certificate_case" },
  identity: { domain_key: "identity_exposure", case_type: "identity_case" },
  email_config: { domain_key: "email_protection", case_type: "email_case" },
  email_sender: { domain_key: "email_protection", case_type: "email_case" },
  shadow_it: { domain_key: "shadow_it_unmanaged_technology", case_type: "shadow_it_case" },
});
const FAMILY_CASE_PREFERENCE = ["cert", "identity", "email_config", "email_sender", "shadow_it"];

function baseCaseForCluster(families, override) {
  if (override?.domain_key && override?.case_type) return override;
  const present = new Set(families || []);
  for (const fam of FAMILY_CASE_PREFERENCE) {
    if (present.has(fam) && FAMILY_TO_BASE_CASE[fam]) return FAMILY_TO_BASE_CASE[fam];
  }
  return null;
}

/**
 * createCaseFromRelatedChange — customer-initiated case creation from a cluster. Uses
 * the canonical createManagedCase factory (NO bypass, no separate case system). The
 * case opens under a BASE domain derived from the cluster's non-asset signal family
 * (or a caller override from the canonical base set). Language stays "related change" —
 * never attack chain / compromise / incident (§9).
 */
export async function createCaseFromRelatedChange(env, workspaceId, id, { userId = null, domainKey = null, caseType = null } = {}) {
  const detail = await getRelatedChange(env, workspaceId, id);
  if (!detail) return { ok: false, code: "not_found" };
  const { cluster, evidence } = detail;
  // Item 7 P4 activates timeline/correlation only. A cluster containing a
  // DMARCbis lifecycle event remains non-caseable until P5 adds the approved
  // manual-condition and canonical-remediation contract.
  if ((evidence || []).some((item) =>
    item.source_table === "email_protection_events" &&
    String(item.source_event_type || "").startsWith("dmarc_"))) {
    return { ok: false, code: "dmarc_case_deferred" };
  }
  const families = [...new Set((evidence || []).map((e) => e.producer_family))];

  const target = baseCaseForCluster(families, domainKey && caseType ? { domain_key: domainKey, case_type: caseType } : null);
  if (!target) return { ok: false, code: "no_base_case_type" };

  const base = {
    workspace_id: workspaceId,
    domain_key: target.domain_key,
    case_type: target.case_type,
    source_finding_type: "related_change",
    source_finding_id: cluster.id,
    title: `Related change on ${cluster.registrable_domain} — requires verification`,
    summary: `${cluster.signal_family_count} independent signal families changed together on ${cluster.registrable_domain} in the same period. ${RELATED_CHANGES_CAUSALITY_NOTICE}`,
    severity: "medium",
    actor: { actor_type: userId ? "customer" : "system", actor_id: userId },
  };
  // Supply the registrable domain when it is a linked workspace domain; otherwise open
  // the case without a domain rather than fail (the cluster is already tenant-scoped).
  let res = await createManagedCase(env, { ...base, domain: cluster.registrable_domain });
  if (res?.code === "domain_ineligible") {
    res = await createManagedCase(env, { ...base, domain: null });
  }
  if (!res?.ok || !res?.case?.id) return { ok: false, code: "case_create_failed", detail: res };
  await linkRelatedChangeToCase(env, workspaceId, id, res.case.id);
  return { ok: true, case: res.case };
}

// ── Snapshot-row sidecar summary (frozen lazily on first report render) ──────
/**
 * buildRelatedChangesSummary — a short, honest summary object for freezing into the
 * scan report snapshot and rendering in the PDF. Counts only; no attack language.
 */
export async function buildRelatedChangesSummary(env, workspaceId) {
  const rows = await env.cybermeters_db
    .prepare(
      `SELECT rule_id, registrable_domain, direction, signal_family_count,
              customer_state, last_seen
         FROM related_changes
        WHERE workspace_id = ?
        ORDER BY last_seen DESC
        LIMIT 20`
    )
    .bind(workspaceId)
    .all();
  const items = (rows.results || []).map((r) => ({
    rule_id: r.rule_id,
    registrable_domain: r.registrable_domain,
    direction: r.direction,
    signal_family_count: r.signal_family_count,
    customer_state: r.customer_state,
    last_seen: r.last_seen,
  }));
  return {
    schema: "related_changes.v1",
    total: items.length,
    note: RELATED_CHANGES_CAUSALITY_NOTICE,
    items,
  };
}
