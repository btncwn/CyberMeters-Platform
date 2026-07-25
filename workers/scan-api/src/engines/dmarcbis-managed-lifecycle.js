// Item 7 P5 — narrow DMARCbis alerts, manual cases and DNS re-verification.
//
// P4 owns detection and append-only occurrence identity. This module consumes
// only its bounded descriptors or integrity-verified current snapshots. It
// never re-parses historical DNS, opens a case automatically, accepts RUA
// reports as verification, or mutates DNS.
import { sha256Hex } from "../lib/aggregate-report-ingest.js";
import {
  emitLifecycleAlert,
} from "./alert-consumers.js";
import { parseUtcMs } from "./alert-occurrence.js";
import {
  DMARC_POLICY_CONDITION_RECORD_TYPE,
  EMAIL_EVENT_CASE_LINKED,
  EMAIL_EVENT_CASE_REOPENED,
  EMAIL_PROTECTION_DOMAIN_KEY,
  EMAIL_RECURRENCE_FINDING_TYPE,
  deriveDmarcPolicyConditions,
  dmarcPolicyConditionRecordId,
} from "./email-protection-lifecycle.js";
import {
  isDmarcPolicyConditionComplete,
} from "./dmarcbis-lifecycle.js";
import {
  canTransitionCase,
  canonicalPhaseFor,
  createManagedCase,
  verificationSupportForCase,
} from "./managed-case-model.js";
import {
  getRemediationById,
  resolveRemediation,
} from "./remediation-registry.js";
import { readScanReportSnapshot } from "./report-snapshot.js";

export const DMARC_ALERT_RECURRENCES = Object.freeze([
  "record_removed",
  "record_became_malformed",
  "multiple_records_detected",
  "enforcement_weakened",
  "external_rua_unauthorised",
]);

const ALERT_RECURRENCE_SET = new Set(DMARC_ALERT_RECURRENCES);

export const DMARC_CONDITION_FINDING_TYPE = Object.freeze({
  missing: "dmarc_exact_record_removed",
  malformed: "dmarc_invalid_record",
  multiple: "dmarc_multiple_records",
  weak: "email_dmarc_policy_none",
  unauthorised_rua: "dmarc_external_rua_unauthorised",
});

const FINDING_CONDITION_TYPE = Object.freeze(
  Object.fromEntries(
    Object.entries(DMARC_CONDITION_FINDING_TYPE)
      .map(([condition, finding]) => [finding, condition]),
  ),
);

const CONDITION_SEVERITY = Object.freeze({
  missing: "high",
  malformed: "high",
  multiple: "high",
  weak: "medium",
  unauthorised_rua: "medium",
});

const CONDITION_SUMMARY = Object.freeze({
  missing:
    "A complete CyberMeters DMARC lookup found no applicable policy.",
  malformed:
    "A complete CyberMeters DMARC lookup observed a record that cannot be used as a valid policy.",
  multiple:
    "A complete CyberMeters DMARC lookup observed multiple policy records at the same DNS name.",
  weak:
    "The complete current observation shows a no-action effective requested DMARC policy.",
  unauthorised_rua:
    "The complete current observation found no valid authorisation for an external aggregate-report destination.",
});

const POLICY_RANK = Object.freeze({ none: 0, quarantine: 1, reject: 2 });

export function isDmarcAlertDescriptorEligible(event) {
  return ALERT_RECURRENCE_SET.has(String(event?.recurrence_type || "")) &&
    event?.transition_completeness === "complete";
}

export function isDmarcCaseVerificationEligible({
  condition_type,
  evidence,
  condition_present,
  observed_at,
  requested_at,
} = {}) {
  if (
    !condition_type ||
    condition_present !== false ||
    !isDmarcPolicyConditionComplete(condition_type, evidence)
  ) {
    return false;
  }
  const observedMs = parseUtcMs(observed_at);
  const requestedMs = parseUtcMs(requested_at);
  return observedMs !== null &&
    requestedMs !== null &&
    observedMs > requestedMs;
}

function parseJson(value, fallback = null) {
  try {
    return value ? JSON.parse(value) : fallback;
  } catch {
    return fallback;
  }
}

function canonicalName(value) {
  return String(value || "").trim().replace(/\.$/, "").toLowerCase();
}

function isDmarcRecordId(value) {
  return /^dmarc:[^:]+:(missing|malformed|multiple|weak|unauthorised_rua):[a-f0-9]{64}$/
    .test(String(value || ""));
}

export function isDmarcPolicyCaseRequest({
  source_finding_id,
  source_finding_type,
} = {}) {
  return (
    String(source_finding_id || "").startsWith("dmarc:") ||
    Object.prototype.hasOwnProperty.call(
      FINDING_CONDITION_TYPE,
      String(source_finding_type || ""),
    )
  );
}

async function loadDmarcEventIdentity(env, workspaceId, recordId) {
  const row = await env.cybermeters_db
    .prepare(
      `SELECT id, detail_json
       FROM email_protection_events
       WHERE workspace_id = ? AND record_type = ? AND record_id = ?
         AND event_type = 'monitoring_changed'
         AND json_extract(detail_json, '$.domain_id') IS NOT NULL
       ORDER BY created_at DESC, rowid DESC
       LIMIT 1`,
    )
    .bind(workspaceId, DMARC_POLICY_CONDITION_RECORD_TYPE, recordId)
    .first()
    .catch(() => null);
  const detail = parseJson(row?.detail_json, null);
  const domainId = String(detail?.domain_id || "");
  return domainId
    ? {
        domain_id: domainId,
        author_domain: canonicalName(detail?.author_domain),
        occurrence_id: row.id,
        detail,
      }
    : null;
}

async function loadCurrentDmarcState(env, {
  workspaceId,
  domainId,
  scanId = null,
} = {}) {
  if (!workspaceId || !domainId) {
    return { status: "incomplete_context" };
  }
  const whereScan = scanId ? "AND s.scan_id = ?" : "";
  const binds = scanId
    ? [workspaceId, domainId, scanId]
    : [workspaceId, domainId];
  const row = await env.cybermeters_db
    .prepare(
      `SELECT s.id, s.scan_id, s.workspace_id, s.domain_id, s.scan_quality,
              s.assessed_at, d.domain
       FROM scan_report_snapshots s
       JOIN workspaces w
         ON w.id = s.workspace_id AND w.deleted_at IS NULL
       JOIN workspace_domains wd
         ON wd.workspace_id = s.workspace_id AND wd.domain_id = s.domain_id
       JOIN domains d ON d.id = s.domain_id
       WHERE s.workspace_id = ? AND s.domain_id = ?
         AND s.status = 'completed' ${whereScan}
       ORDER BY s.assessed_at DESC, s.rowid DESC
       LIMIT 1`,
    )
    .bind(...binds)
    .first()
    .catch(() => null);
  if (!row) return { status: "snapshot_unavailable" };
  if (row.scan_quality !== "complete") {
    return { status: "scan_incomplete", row };
  }
  const read = await readScanReportSnapshot(env, row.scan_id, {
    repair: false,
    allowReconstruction: false,
    includeSuccessor: false,
  });
  if (
    read.status !== "ok" ||
    read.row.workspace_id !== workspaceId ||
    read.row.domain_id !== domainId ||
    read.dmarcPolicy?.status !== "current"
  ) {
    return { status: "snapshot_integrity_unavailable", row };
  }
  return {
    status: "complete",
    row,
    evidence: read.dmarcPolicy.evidence,
  };
}

async function activeConditionRecords(domainId, evidence) {
  const records = new Map();
  for (const condition of deriveDmarcPolicyConditions(evidence)) {
    const recordId = await dmarcPolicyConditionRecordId({
      domain_id: domainId,
      condition_type: condition.condition_type,
      subject_key: condition.subject_key,
    });
    if (recordId) records.set(recordId, condition);
  }
  return records;
}

function exactRecordState(evidence) {
  const author = canonicalName(evidence?.author_domain);
  const qname = canonicalName(`_dmarc.${author}`);
  const exact = (evidence?.lookup_path || []).find((entry) =>
    entry?.question?.resolver === "primary" &&
    entry?.question?.purpose === "policy_tree_walk" &&
    canonicalName(entry?.question?.name) === qname &&
    canonicalName(entry?.question?.target_domain) === author &&
    entry?.logically_used !== false &&
    entry?.definitive === true &&
    entry?.record_set?.complete !== false);
  return exact?.record_set?.raw_state ?? null;
}

function recordRemovalStillActionable(evidence, previousPolicy) {
  const previousRank = POLICY_RANK[previousPolicy];
  const currentRank = POLICY_RANK[evidence?.effective_requested_policy];
  return exactRecordState(evidence) === "absent" &&
    Number.isInteger(previousRank) &&
    (!Number.isInteger(currentRank) || currentRank < previousRank);
}

async function currentConditionForRecord({
  recordId,
  identity,
  state,
  active,
} = {}) {
  const direct = active.get(recordId);
  if (direct) return direct;
  const detail = identity?.detail || {};
  if (
    detail.condition_type === "missing" &&
    detail.to_recurrence_type === "record_removed" &&
    recordRemovalStillActionable(
      state.evidence,
      detail.before?.effective_requested_policy,
    )
  ) {
    return {
      condition_type: "missing",
      subject_key:
        canonicalName(detail.author_domain || state.evidence.author_domain),
      condition_reason: "exact_record_removed",
      previous_effective_requested_policy:
        detail.before?.effective_requested_policy ?? null,
    };
  }
  return null;
}

// P4 already wrote and deduplicated these occurrences. The canonical consumer
// re-reads each row through alert-occurrence.js before publishing, so a write
// result is never treated as occurrence proof.
export async function emitDmarcPolicyAlerts(env, {
  workspace_id,
  lifecycle_result,
} = {}) {
  if (!workspace_id || !Array.isArray(lifecycle_result?.actionable_events)) {
    return { attempted: 0, emitted: 0, results: [] };
  }
  const results = [];
  for (const event of lifecycle_result.actionable_events) {
    const recurrence = String(event?.recurrence_type || "");
    if (!isDmarcAlertDescriptorEligible(event)) continue;
    const findingType = EMAIL_RECURRENCE_FINDING_TYPE[recurrence] || null;
    if (!findingType) continue;
    const result = await emitLifecycleAlert(env, {
      workspace_id,
      domain_key: EMAIL_PROTECTION_DOMAIN_KEY,
      record_id: event.record_id,
      entity: event.entity || event.author_domain || event.record_id,
      hostname: event.author_domain || null,
      monitored_domain: event.author_domain || null,
      recurrence,
      finding_type: findingType,
      case_id: null,
      evidence_source: {
        label: "Complete DMARC DNS observations",
        detail:
          "Derived from immutable previous and current CyberMeters snapshots.",
        last_seen_at: null,
      },
    });
    results.push({ event_id: event.event_id, recurrence, result });
  }
  return {
    attempted: results.length,
    emitted: results.filter((item) => item.result?.emitted).length,
    results,
  };
}

async function ensureCaseLinkEvent(env, {
  workspaceId,
  recordId,
  caseRow,
  condition,
  state,
  actor,
  reopened = false,
  occurrenceId = null,
} = {}) {
  const id = `epe-${await sha256Hex(
    reopened
      ? `${workspaceId}|dmarc_case_reopen|${recordId}|${caseRow.id}|${occurrenceId}`
      : `${workspaceId}|dmarc_case_link|${recordId}|${caseRow.id}`,
  )}`;
  await env.cybermeters_db
    .prepare(
      `INSERT OR IGNORE INTO email_protection_events
        (id, record_id, record_type, workspace_id, actor_type, actor_id,
         event_type, detail_json, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
    )
    .bind(
      id,
      recordId,
      DMARC_POLICY_CONDITION_RECORD_TYPE,
      workspaceId,
      actor?.actor_type || "customer",
      actor?.actor_id || null,
      reopened ? EMAIL_EVENT_CASE_REOPENED : EMAIL_EVENT_CASE_LINKED,
      JSON.stringify({
        case_id: caseRow.id,
        domain_id: state.row.domain_id,
        author_domain:
          canonicalName(state.evidence.author_domain || state.row.domain),
        condition_type: condition.condition_type,
        subject_key: condition.subject_key,
        remediation_id: caseRow.remediation_id ?? null,
        scan_id: state.row.scan_id,
        snapshot_id: state.row.id,
        evidence_fingerprint:
          state.evidence.evidence_fingerprint ?? null,
        methodology_version:
          state.evidence.methodology_version ?? null,
        transition_completeness: "complete",
        to_recurrence_type: null,
        occurrence_id: occurrenceId,
        reason: reopened ? "manual_case_reopened" : "manual_case_linked",
      }),
    )
    .run();
}

async function reopenExistingCaseForRecurrence(env, {
  workspaceId,
  result,
  identity,
  actor,
} = {}) {
  if (
    result?.created ||
    !["verified", "monitoring"].includes(
      canonicalPhaseFor(result?.case?.case_type, result?.case?.status),
    )
  ) {
    return { ...result, reopened: false };
  }
  const now = new Date().toISOString();
  const decision = canTransitionCase({
    case: result.case,
    target_status: "reopened",
    actor: {
      actor_type: actor?.actor_type || "customer",
      actor_id: actor?.actor_id || null,
    },
    now,
  });
  if (!decision.ok) {
    return { ok: false, code: "case_reopen_refused" };
  }
  const eventId = `mce-${await sha256Hex(
    `${result.case.id}|dmarc_manual_reopen|${identity.occurrence_id}`,
  )}`;
  const writes = await env.cybermeters_db.batch([
    env.cybermeters_db
      .prepare(
        `UPDATE managed_cases
         SET status = ?, reopened_count = ?, reopened_at = ?, updated_at = ?
         WHERE id = ? AND workspace_id = ? AND status = ?`,
      )
      .bind(
        decision.case.status,
        decision.case.reopened_count,
        decision.case.reopened_at || now,
        decision.case.updated_at,
        result.case.id,
        workspaceId,
        result.case.status,
      ),
    env.cybermeters_db
      .prepare(
        `INSERT OR IGNORE INTO managed_case_events
          (id, case_id, workspace_id, actor_type, actor_id, from_status,
           to_status, action, detail_json, created_at)
         SELECT ?, id, workspace_id, ?, ?, ?, ?, ?, ?, ?
         FROM managed_cases
         WHERE id = ? AND workspace_id = ? AND status = ?
           AND updated_at = ?`,
      )
      .bind(
        eventId,
        actor?.actor_type || "customer",
        actor?.actor_id || null,
        result.case.status,
        decision.case.status,
        decision.event.action,
        JSON.stringify({
          occurrence_id: identity.occurrence_id,
          reason: "manual_dmarc_recurrence",
        }),
        now,
        result.case.id,
        workspaceId,
        decision.case.status,
        decision.case.updated_at,
      ),
  ]);
  if (Number(writes?.[0]?.meta?.changes || 0) !== 1) {
    const current = await env.cybermeters_db
      .prepare(
        "SELECT * FROM managed_cases WHERE id = ? AND workspace_id = ?",
      )
      .bind(result.case.id, workspaceId)
      .first()
      .catch(() => null);
    return current
      ? { ok: true, created: false, reopened: false, case: current }
      : { ok: false, code: "case_reopen_race" };
  }
  return {
    ok: true,
    created: false,
    reopened: true,
    case: decision.case,
  };
}

// Manual only. The caller supplies an opaque stable record id; every other
// field is derived from the latest integrity-verified complete snapshot.
export async function createDmarcPolicyCase(env, {
  workspace_id,
  record_id,
  actor = {},
} = {}) {
  if (!env?.cybermeters_db || !workspace_id || !isDmarcRecordId(record_id)) {
    return { ok: false, code: "invalid_dmarc_condition" };
  }
  const identity = await loadDmarcEventIdentity(
    env,
    workspace_id,
    record_id,
  );
  if (!identity) return { ok: false, code: "condition_not_found" };

  const state = await loadCurrentDmarcState(env, {
    workspaceId: workspace_id,
    domainId: identity.domain_id,
  });
  if (state.status !== "complete") {
    return { ok: false, code: "current_evidence_incomplete" };
  }
  const active = await activeConditionRecords(
    identity.domain_id,
    state.evidence,
  );
  const condition = await currentConditionForRecord({
    recordId: record_id,
    identity,
    state,
    active,
  });
  if (
    !condition ||
    !isDmarcPolicyConditionComplete(
      condition.condition_type,
      state.evidence,
    )
  ) {
    return { ok: false, code: "condition_not_current_actionable" };
  }
  const findingType =
    DMARC_CONDITION_FINDING_TYPE[condition.condition_type] || null;
  const remediation = findingType
    ? resolveRemediation({ finding_type: findingType })
    : null;
  if (remediation?.status !== "resolved") {
    return { ok: false, code: "canonical_remediation_unavailable" };
  }
  const author =
    canonicalName(state.evidence.author_domain || state.row.domain) ||
    identity.author_domain;
  if (!author) return { ok: false, code: "author_domain_unavailable" };

  const result = await createManagedCase(env, {
    workspace_id,
    domain_key: EMAIL_PROTECTION_DOMAIN_KEY,
    case_type: "email_case",
    source_finding_type: findingType,
    source_finding_id: record_id,
    source_scan_id: state.row.scan_id,
    domain: author,
    asset_ref: condition.subject_key || author,
    title: `DMARC: ${remediation.customer_title}`,
    summary: `${
      condition.condition_reason === "exact_record_removed"
        ? "The previously observed exact DMARC record remains absent and the current inherited or absent requested policy is weaker than before."
        : CONDITION_SUMMARY[condition.condition_type]
    } Suggested DNS change only — not applied by CyberMeters.`,
    severity: CONDITION_SEVERITY[condition.condition_type] || "medium",
    evidence: {
      source_type: "dns_policy_snapshot",
      condition_type: condition.condition_type,
      subject_key: condition.subject_key,
      condition_reason: condition.condition_reason ?? null,
      previous_effective_requested_policy:
        condition.previous_effective_requested_policy ?? null,
      scan_id: state.row.scan_id,
      snapshot_id: state.row.id,
      evidence_fingerprint:
        state.evidence.evidence_fingerprint ?? null,
      methodology_version:
        state.evidence.methodology_version ?? null,
      limits: [
        "A published DMARC preference does not prove receiver enforcement.",
        "CyberMeters has not applied a DNS change.",
      ],
    },
    actor: {
      actor_type: actor.actor_type || "customer",
      actor_id: actor.actor_id || null,
    },
  });
  if (!result?.ok) return result;

  const linked = await reopenExistingCaseForRecurrence(env, {
    workspaceId: workspace_id,
    result,
    identity,
    actor,
  });
  if (!linked?.ok) return linked;
  await ensureCaseLinkEvent(env, {
    workspaceId: workspace_id,
    recordId: record_id,
    caseRow: linked.case,
    condition,
    state,
    actor,
    reopened: linked.reopened,
    occurrenceId: identity.occurrence_id,
  });
  return {
    ...linked,
    eligibility: {
      condition_type: condition.condition_type,
      scan_id: state.row.scan_id,
      snapshot_id: state.row.id,
      evidence_fingerprint:
        state.evidence.evidence_fingerprint ?? null,
    },
  };
}

function findingConditionType(caseRow) {
  return FINDING_CONDITION_TYPE[
    String(caseRow?.source_finding_type || "")
  ] || null;
}

function caseConditionPresent(caseRow, conditionType, evidence, active) {
  if (active.has(caseRow.finding_id)) return true;
  if (conditionType !== "missing") return false;
  const caseEvidence = parseJson(caseRow.evidence_json, {});
  if (caseEvidence?.condition_reason !== "exact_record_removed") return false;
  return recordRemovalStillActionable(
    evidence,
    caseEvidence.previous_effective_requested_policy,
  );
}

// A completed scan alone is insufficient. Verification requires a later,
// integrity-verified, whole-scan-complete snapshot in which the relevant
// current condition is absent and that condition's component is complete.
export async function verifyDmarcPolicyCasesForScan(env, {
  workspace_id,
  domain_id,
  scan_id,
} = {}) {
  const state = await loadCurrentDmarcState(env, {
    workspaceId: workspace_id,
    domainId: domain_id,
    scanId: scan_id,
  });
  if (state.status !== "complete") {
    return { ran: false, reason: state.status, verified: 0 };
  }
  const active = await activeConditionRecords(domain_id, state.evidence);
  const author = canonicalName(
    state.evidence.author_domain || state.row.domain,
  );
  const rows = await env.cybermeters_db
    .prepare(
      `SELECT *
       FROM managed_cases
       WHERE workspace_id = ? AND case_type = 'email_case'
         AND domain = ? AND status = 'awaiting_verification'
         AND finding_id LIKE 'dmarc:%'
       ORDER BY created_at ASC
       LIMIT 100`,
    )
    .bind(workspace_id, author)
    .all()
    .catch(() => ({ results: [] }));

  const statements = [];
  const decisions = [];
  for (const kase of rows.results || []) {
    const conditionType = findingConditionType(kase);
    const observedAt = state.row.assessed_at;
    if (!isDmarcCaseVerificationEligible({
      condition_type: conditionType,
      evidence: state.evidence,
      condition_present:
        caseConditionPresent(kase, conditionType, state.evidence, active),
      observed_at: observedAt,
      requested_at: kase.awaiting_verification_at,
    })) {
      continue;
    }
    const remediation = kase.remediation_id
      ? getRemediationById(kase.remediation_id)
      : null;
    if (
      remediation?.verification_method !== "dns_recheck" ||
      verificationSupportForCase(kase) !== "automated"
    ) {
      continue;
    }
    const evidence = {
      verification_method: "dns_recheck",
      verification_result: "fixed",
      evidence_type: "dmarc_complete_reobservation",
      evidence_reference: {
        scan_id: state.row.scan_id,
        snapshot_id: state.row.id,
        evidence_fingerprint:
          state.evidence.evidence_fingerprint ?? null,
      },
      observed_at: observedAt,
      observation: {
        source_type: "dns_policy_snapshot",
        condition_type: conditionType,
        condition_record_id: kase.finding_id,
        condition_present: false,
        scan_quality: state.row.scan_quality,
        methodology_version:
          state.evidence.methodology_version ?? null,
      },
    };
    const decision = canTransitionCase({
      case: kase,
      target_status: "verified",
      actor: { actor_type: "system", actor_id: null },
      evidence,
      now: observedAt,
    });
    if (!decision.ok || canonicalPhaseFor(
      kase.case_type,
      decision.case.status,
    ) !== "verified") {
      continue;
    }
    const eventId = `mce-${await sha256Hex(
      `${kase.id}|dmarc_complete_reobservation|${state.row.id}`,
    )}`;
    statements.push(
      env.cybermeters_db
        .prepare(
          `UPDATE managed_cases
           SET status = ?, verified_at = ?, last_verified_at = ?,
               updated_at = ?
           WHERE id = ? AND workspace_id = ?
             AND status = 'awaiting_verification'`,
        )
        .bind(
          decision.case.status,
          decision.case.verified_at || observedAt,
          observedAt,
          decision.case.updated_at,
          kase.id,
          workspace_id,
        ),
      env.cybermeters_db
        .prepare(
          `INSERT OR IGNORE INTO managed_case_events
            (id, case_id, workspace_id, actor_type, actor_id,
             from_status, to_status, action, detail_json, created_at)
           SELECT ?, id, workspace_id, 'system', NULL, ?, ?, ?, ?, ?
           FROM managed_cases
           WHERE id = ? AND workspace_id = ? AND status = ?
             AND updated_at = ?`,
        )
        .bind(
          eventId,
          kase.status,
          decision.case.status,
          decision.event.action,
          decision.event.detail_json,
          observedAt,
          kase.id,
          workspace_id,
          decision.case.status,
          decision.case.updated_at,
        ),
    );
    decisions.push({ case_id: kase.id, condition_type: conditionType });
  }
  if (!statements.length) {
    return { ran: true, reason: "no_verifiable_case", verified: 0 };
  }
  const results = await env.cybermeters_db.batch(statements);
  const verified = decisions.filter((_, index) =>
    Number(results?.[index * 2]?.meta?.changes || 0) > 0).length;
  return {
    ran: true,
    reason: "evaluated",
    verified,
    candidates: decisions.length,
  };
}
