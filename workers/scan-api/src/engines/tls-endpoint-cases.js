// ── TLS endpoint conditions as managed Certificates & Trust cases ─────────────
//
// Executive decision, 23 Oct 2026: Certificates & Trust owns a TLS endpoint
// condition (legacy protocol, weak cipher, … — tls-findings.js). Before this,
// those findings were HIGH in the report and opened nothing: no case, no domain
// alert, no owner, no recurrence (live: sheshire.co.uk accepted TLS 1.0/1.1).
//
// One case per condition, keyed by tlsCaseKey: the endpoint, the control and
// the protocol/cipher, NOT the engine build (Executive, 23 Oct 2026: a probe
// release must not orphan open cases or open duplicates). The build-specific
// finding id and the engine build ride on the occurrence and the verification
// evidence, so which tool measured what stays recorded:
//   • present, no open case          → open a certificate_case + domain alert
//   • present, case verified/monitoring → reopen it (system) + domain alert
//   • clear on an exact retest, case awaiting_verification → verified (system)
//   • anything else (deferred, still present on an open case) → nothing
//
// "clear" is evaluateTlsCase: every current measurement of the same condition,
// by whatever build this scan ran, evaluated exactly (a rejected protocol, a
// complete negative). A missing, blocked or inconclusive retest never verifies. The customer still submits the
// case for verification first: observing a fix on a case nobody acted on is
// history, not a completed remediation (the Website Security rule).
//
// Alerts go through the canonical pipeline: the transition is appended to
// certificate_lifecycle_events keyed by the case id (the domain's occurrence
// source), then emitLifecycleAlert grades it by the finding's own severity.
import { createManagedCase, canTransitionCase, canonicalPhaseFor } from "./managed-case-model.js";
import { newCaseEventId } from "./case-workflow.js";
import { evaluateTlsCase, tlsAssessmentFindings, tlsCaseKey } from "./tls-findings.js";
import { emitLifecycleAlert } from "./alert-consumers.js";
import { MONITORING_CHANGED, buildMonitoringTransitionDetail } from "./alert-occurrence.js";

export const TLS_CASE_DOMAIN_KEY = "certificates_trust";
export const TLS_CASE_TYPE = "certificate_case";
export const TLS_RECURRENCE_OBSERVED = "tls_condition_observed";
export const TLS_RECURRENCE_RETURNED = "tls_condition_returned";
const TLS_CASE_KEY = /^tlscase:tls_[a-z_]+:[a-f0-9]{64}$/;
const SEVERITIES = new Set(["critical", "high", "medium", "low"]);
const VERIFIED_PHASES = new Set(["verified", "monitoring"]);

const hostOf = (finding) => finding?.evidence?.[0]?.endpoint?.hostname || null;

// Append-only case history, system actor (never updates a prior row).
async function appendCaseEvent(env, kase, { from_status, to_status, action, detail }) {
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events
      (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
      VALUES (?, ?, ?, 'system', NULL, ?, ?, ?, ?, datetime('now'))`)
    .bind(newCaseEventId(), kase.id, kase.workspace_id, from_status, to_status, action, JSON.stringify(detail ?? null))
    .run();
}

async function recordTransition(env, { workspace_id, case_id, recurrence, entity, condition_id, engine_build_id }) {
  const id = `cle-tls-${case_id}-${recurrence}-${Date.now().toString(36)}`;
  await env.cybermeters_db
    .prepare(`INSERT INTO certificate_lifecycle_events
      (id, lifecycle_id, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
      VALUES (?, ?, ?, 'system', NULL, ?, ?, datetime('now'))`)
    .bind(id, case_id, workspace_id, MONITORING_CHANGED, JSON.stringify({
      ...buildMonitoringTransitionDetail({
        from_monitoring_status: recurrence === TLS_RECURRENCE_RETURNED ? "verified" : null,
        to_monitoring_status: "observed",
        to_recurrence_type: recurrence,
        required_case_action: "remediate",
        reason: "tls_condition_present_on_exact_measurement",
        entity,
      }),
      condition_id,
      engine_build_id,
    }))
    .run();
}

async function alert(env, { workspace_id, kase, finding, recurrence }) {
  const entity = hostOf(finding) || kase.asset_ref || kase.domain || "TLS endpoint";
  await recordTransition(env, {
    workspace_id, case_id: kase.id, recurrence, entity,
    condition_id: finding.id, engine_build_id: finding.tls_condition?.engine_build_id || null,
  });
  return emitLifecycleAlert(env, {
    workspace_id, domain_key: TLS_CASE_DOMAIN_KEY, record_id: kase.id,
    entity, hostname: hostOf(finding), recurrence,
    record_severity: SEVERITIES.has(finding.severity) ? finding.severity : null,
    finding_type: finding.tls_condition?.type || kase.source_finding_type,
    case_id: kase.id,
  }).catch(() => ({ skipped: "alert_failed" }));
}

/**
 * Reconcile one workspace's TLS endpoint cases with this scan's tls_assessment.
 * Never throws; returns counts for the scan log.
 */
export async function reconcileTlsEndpointCases(env, { workspace_id, domain, scan_id = null, tls_assessment, now = new Date().toISOString() } = {}) {
  const out = { opened: 0, reopened: 0, verified: 0 };
  try {
    if (!workspace_id || tls_assessment?.source !== "tls_assessment") return { ...out, skipped: "no_tls_assessment" };
    const present = tlsAssessmentFindings(tls_assessment)
      .map((f) => ({ finding: f, key: tlsCaseKey(f.tls_condition) }))
      .filter((p) => p.key);
    // One case per build-less condition, even if two builds measured it in one scan.
    const seen = new Set();

    for (const { finding, key } of present) {
      const type = finding.tls_condition?.type;
      if (!type || seen.has(key)) continue;
      seen.add(key);
      const created = await createManagedCase(env, {
        workspace_id, domain_key: TLS_CASE_DOMAIN_KEY, case_type: TLS_CASE_TYPE,
        source_finding_type: type, source_finding_id: key, source_scan_id: scan_id,
        domain, asset_ref: hostOf(finding) || domain,
        title: finding.title, summary: finding.description || null,
        severity: SEVERITIES.has(finding.severity) ? finding.severity : "medium",
        actor: { actor_type: "system", actor_id: null },
      });
      if (!created.ok) continue;
      const kase = created.case;
      if (created.created) {
        out.opened++;
        await alert(env, { workspace_id, kase, finding, recurrence: TLS_RECURRENCE_OBSERVED });
        continue;
      }
      // The same condition after a verification: it came back.
      if (VERIFIED_PHASES.has(canonicalPhaseFor(kase.case_type, kase.status))) {
        const decision = canTransitionCase({
          case: kase, target_status: "reopened",
          actor: { actor_type: "system", actor_id: null },
          reason: "The TLS condition was measured again on the same endpoint", now,
        });
        if (!decision.ok) continue;
        const n = decision.case;
        const updated = await env.cybermeters_db
          .prepare(`UPDATE managed_cases SET status = ?, reopened_at = ?, reopened_count = ?, updated_at = ?
                    WHERE id = ? AND workspace_id = ? AND status = ?`)
          .bind(n.status, n.reopened_at ?? now, Number(n.reopened_count || 0), n.updated_at ?? now, kase.id, workspace_id, kase.status)
          .run();
        if (updated?.meta?.changes !== 1) continue;
        await appendCaseEvent(env, kase, {
          from_status: kase.status, to_status: n.status, action: decision.event.action,
          detail: { recurrence: TLS_RECURRENCE_RETURNED, condition_id: finding.id, engine_build_id: finding.tls_condition?.engine_build_id || null, scan_id },
        });
        out.reopened++;
        await alert(env, { workspace_id, kase, finding, recurrence: TLS_RECURRENCE_RETURNED });
      }
    }

    // Verification: only an exact-retest "clear" on a case the customer submitted.
    const open = (await env.cybermeters_db
      .prepare(`SELECT * FROM managed_cases
                WHERE workspace_id = ? AND case_type = ? AND domain = ? AND status = 'awaiting_verification'
                  AND source_finding_type LIKE 'tls\\_%' ESCAPE '\\'`)
      .bind(workspace_id, TLS_CASE_TYPE, domain).all()).results || [];
    for (const kase of open) {
      if (!TLS_CASE_KEY.test(String(kase.finding_id || ""))) continue;
      const result = evaluateTlsCase(kase.finding_id, tls_assessment);
      if (result.state !== "clear") continue;
      const evidence = {
        verification_method: "certificate_recheck",
        verification_result: "fixed",
        evidence_type: "tls_exact_retest",
        observed_at: now,
        observation: { case_key: kase.finding_id, condition_ids: result.condition_ids, engine_build_ids: result.engine_build_ids, reason: result.reason, scan_id },
      };
      const decision = canTransitionCase({
        case: kase, target_status: "verified",
        actor: { actor_type: "system", actor_id: null }, evidence, now,
      });
      if (!decision.ok) continue;
      const n = decision.case;
      const updated = await env.cybermeters_db
        .prepare(`UPDATE managed_cases SET status = ?, verified_at = ?, last_verified_at = ?, updated_at = ?
                  WHERE id = ? AND workspace_id = ? AND status = 'awaiting_verification'`)
        .bind(n.status, n.verified_at ?? now, n.verified_at ?? now, n.updated_at ?? now, kase.id, workspace_id)
        .run();
      if (updated?.meta?.changes !== 1) continue;
      await appendCaseEvent(env, kase, {
        from_status: kase.status, to_status: n.status, action: decision.event.action, detail: evidence,
      });
      out.verified++;
    }
    return out;
  } catch (error) {
    console.error("[tls-endpoint-cases] reconcile failed", JSON.stringify({ workspace_id, reason: error?.message }));
    return { ...out, skipped: "reconcile_failed" };
  }
}
