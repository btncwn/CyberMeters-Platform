// ── TLS-RPT (RFC 8460) report ingestion ───────────────────────────────────────
// Parses the JSON reports that arrive at reports.cybermeters.com and stores them
// per workspace+domain. Completely separate from the DMARC XML path — TLS-RPT is
// JSON, so there is no XXE surface, but the input is still fully untrusted:
// size + array caps, JSON.parse in try/catch, never throws.
import { createId } from "./util.js";
import {
  isDmarcAuthorityEligibleSource,
  normalizeTransportSenderStatus,
} from "./dmarc-authority.js";
import { createAuditEvent } from "./events.js";
import {
  AGGREGATE_REPORT_MAX_PERSISTED_ROWS,
  acquireAggregateReportClaim,
  aggregateReportIdentity,
  aggregateReportSourceScope,
  assertAggregateReportClaimCompleteStatement,
  completeAggregateReportClaimStatement,
  failAggregateReportClaim,
  sha256Hex,
} from "./aggregate-report-ingest.js";

const MAX_JSON_BYTES = 2 * 1024 * 1024; // 2 MB decoded — same order as the DMARC cap
const MAX_POLICIES = 1000;
const MAX_FAILURES = 5000;

const str = (v) => (v == null ? null : String(v).slice(0, 512));
const intOf = (v) => (Number.isFinite(Number(v)) ? Math.max(0, Math.floor(Number(v))) : 0);

// Parse a TLS-RPT report body. Returns { ok, error } or { ok, report }.
export function parseTlsRptReport(jsonString) {
  if (typeof jsonString !== "string") return { ok: false, error: "missing_json" };
  if (jsonString.length > MAX_JSON_BYTES) return { ok: false, error: "attachment_too_large" };
  let obj;
  try { obj = JSON.parse(jsonString); } catch { return { ok: false, error: "parse_error" }; }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return { ok: false, error: "parse_error" };

  const reportId = str(obj["report-id"]);
  if (!reportId) return { ok: false, error: "missing_report_id" };

  const dr = (obj["date-range"] && typeof obj["date-range"] === "object") ? obj["date-range"] : {};
  const policiesRaw = Array.isArray(obj.policies) ? obj.policies.slice(0, MAX_POLICIES) : [];
  const policies = [];
  let totalSucc = 0, totalFail = 0, failuresTotal = 0;

  for (const p of policiesRaw) {
    if (!p || typeof p !== "object") continue;
    const policy = (p.policy && typeof p.policy === "object") ? p.policy : {};
    const summary = (p.summary && typeof p.summary === "object") ? p.summary : {};
    const succ = intOf(summary["total-successful-session-count"]);
    const fail = intOf(summary["total-failure-session-count"]);
    totalSucc += succ; totalFail += fail;

    const failures = [];
    const failsRaw = Array.isArray(p["failure-details"]) ? p["failure-details"] : [];
    for (const f of failsRaw) {
      if (failuresTotal >= MAX_FAILURES) break;
      if (!f || typeof f !== "object") continue;
      failures.push({
        result_type: str(f["result-type"]),
        sending_mta_ip: str(f["sending-mta-ip"]),
        receiving_mx_hostname: str(f["receiving-mx-hostname"]),
        receiving_ip: str(f["receiving-ip"]),
        failed_session_count: intOf(f["failed-session-count"]),
        additional_info: str(f["additional-information"] ?? f["failure-reason-code"]),
      });
      failuresTotal += 1;
    }
    policies.push({
      policy_type: str(policy["policy-type"]),
      policy_domain: str(policy["policy-domain"]),
      failures,
    });
  }

  return {
    ok: true,
    report: {
      org_name: str(obj["organization-name"]),
      contact_info: str(obj["contact-info"]),
      external_report_id: reportId.slice(0, 200),
      date_range_begin: str(dr["start-datetime"]),
      date_range_end: str(dr["end-datetime"]),
      policies,
      total_successful_sessions: totalSucc,
      total_failure_sessions: totalFail,
      failure_count: failuresTotal,
      primary_policy_type: policies[0]?.policy_type || null,
      primary_policy_domain: policies[0]?.policy_domain || null,
    },
  };
}

// Ingest a TLS-RPT report. Mirrors ingestDmarcReport's contract:
// { ok, status?, error?, duplicate?, sessions?, failures? }. Dedup by report-id.
export async function ingestTlsRptReport(env, opts = {}) {
  const {
    workspaceId, domain, jsonString, source = "inbound_email",
    ingestEndpointId = null, domainId = null, enforceDomainMatch = false, provenance = null,
  } = opts;
  if (!workspaceId || !domain) return { ok: false, status: 400, error: "missing_binding" };

  const parsed = parseTlsRptReport(jsonString);
  if (!parsed.ok) return { ok: false, status: 422, error: parsed.error };
  const rep = parsed.report;

  // Domain binding: at least one policy-domain must match the bound domain.
  if (enforceDomainMatch) {
    const d = domain.toLowerCase();
    const match = rep.policies.some((p) => (p.policy_domain || "").toLowerCase() === d);
    if (!match) return { ok: false, status: 422, error: "domain_mismatch" };
  }

  const sessions = rep.total_successful_sessions + rep.total_failure_sessions;
  if (rep.failure_count > AGGREGATE_REPORT_MAX_PERSISTED_ROWS) {
    await createAuditEvent(env, {
      workspace_id: workspaceId,
      user_id: null,
      event_type: "tlsrpt_report_rejected",
      entity_type: "domain",
      entity_id: domainId,
      description: `Rejected TLS-RPT report for ${domain}: row limit exceeded`,
      metadata: {
        domain,
        source,
        reason: "report_row_limit_exceeded",
        rows_present: rep.failure_count,
        rows_allowed: AGGREGATE_REPORT_MAX_PERSISTED_ROWS,
        ingest_endpoint_id: ingestEndpointId,
      },
      required: true,
    });
    return {
      ok: false,
      status: 422,
      error: "report_row_limit_exceeded",
      terminal: true,
      audited: true,
    };
  }

  const rawHash = await sha256Hex(jsonString);
  const authorityEligible = isDmarcAuthorityEligibleSource(source);
  const sourceScope = aggregateReportSourceScope(authorityEligible);
  const claim = await acquireAggregateReportClaim(env, {
    reportType: "tlsrpt",
    workspaceId,
    domain,
    source,
    sourceScope,
    identity: aggregateReportIdentity({
      externalReportId: rep.external_report_id,
    }),
    contentHash: rawHash,
  });

  if (claim.collision) {
    await createAuditEvent(env, {
      workspace_id: workspaceId,
      user_id: null,
      event_type: "tlsrpt_report_identity_collision",
      entity_type: "domain",
      entity_id: domainId,
      description: `Rejected colliding TLS-RPT report identity for ${domain}`,
      metadata: {
        domain,
        source,
        source_scope: sourceScope,
        report_id: rep.external_report_id,
        reason: "content_hash_mismatch",
        ingest_endpoint_id: ingestEndpointId,
      },
      required: true,
    });
    return {
      ok: false,
      status: 409,
      error: "report_identity_collision",
      terminal: true,
      audited: true,
    };
  }
  if (claim.inProgress) {
    await createAuditEvent(env, {
      workspace_id: workspaceId,
      user_id: null,
      event_type: "tlsrpt_report_ingest_deferred",
      entity_type: "domain",
      entity_id: domainId,
      description: `Deferred concurrent TLS-RPT ingestion for ${domain}`,
      metadata: {
        domain,
        source,
        source_scope: sourceScope,
        report_id: rep.external_report_id,
        reason: "ingest_in_progress",
        claim_id: claim.claimId,
      },
      required: true,
    });
    return {
      ok: false,
      status: 503,
      error: "ingest_in_progress",
      transient: true,
      audited: true,
    };
  }
  if (claim.duplicate) {
    return {
      ok: true,
      duplicate: true,
      sessions,
      failures: rep.failure_count,
      reportId: claim.reportId,
    };
  }

  // Transport metadata only. Header-From and recognised public-mail membership
  // do not authenticate the report producer and never grant report authority.
  // Legacy "verified" inputs are normalized to an honest claimed-identity label.
  const prov = provenance
    ? normalizeTransportSenderStatus(provenance.auth_verdict, provenance.reporter_domain)
    : null;

  const existingAcrossScope = await env.cybermeters_db
    .prepare(`SELECT id, raw_hash, source
              FROM tlsrpt_aggregate_reports
              WHERE workspace_id = ? AND domain = ? AND external_report_id = ?
              LIMIT 1`)
    .bind(workspaceId, domain, rep.external_report_id)
    .first();
  const repairingOwnLegacyParent = claim.repaired &&
    existingAcrossScope?.id === claim.reportId;
  if (existingAcrossScope && !repairingOwnLegacyParent) {
    if (existingAcrossScope.raw_hash &&
        existingAcrossScope.raw_hash !== rawHash) {
      const failed = await failAggregateReportClaim(
        env,
        claim,
        "cross_scope_content_hash_mismatch",
      );
      if (!failed) throw new Error("aggregate_ingest_claim_fail_transition_lost");
      await createAuditEvent(env, {
        workspace_id: workspaceId,
        user_id: null,
        event_type: "tlsrpt_report_identity_collision",
        entity_type: "domain",
        entity_id: domainId,
        description: `Rejected cross-scope TLS-RPT identity collision for ${domain}`,
        metadata: {
          domain,
          source,
          source_scope: sourceScope,
          report_id: rep.external_report_id,
          reason: "content_hash_mismatch",
          claim_id: claim.claimId,
        },
        required: true,
      });
      return {
        ok: false,
        status: 409,
        error: "report_identity_collision",
        terminal: true,
        audited: true,
      };
    }

    const promoted = authorityEligible &&
      !isDmarcAuthorityEligibleSource(existingAcrossScope.source);
    const statements = [
      env.cybermeters_db
        .prepare(`UPDATE aggregate_report_ingest_claims
                  SET report_id = ?, updated_at = datetime('now')
                  WHERE id = ? AND attempt_token = ? AND ingest_state = 'pending'`)
        .bind(existingAcrossScope.id, claim.claimId, claim.attemptToken),
    ];
    if (promoted) {
      statements.push(env.cybermeters_db
        .prepare("UPDATE tlsrpt_aggregate_reports SET source = ? WHERE id = ?")
        .bind(source, existingAcrossScope.id));
    }
    statements.push(completeAggregateReportClaimStatement(env, claim));
    statements.push(assertAggregateReportClaimCompleteStatement(env, claim));
    await env.cybermeters_db.batch(statements);
    return {
      ok: true,
      duplicate: !promoted,
      promoted,
      sessions,
      failures: rep.failure_count,
      reportId: existingAcrossScope.id,
    };
  }

  const reportRowId = claim.reportId;
  const transaction = [
    env.cybermeters_db
      .prepare("DELETE FROM tlsrpt_failure_details WHERE report_id = ?")
      .bind(reportRowId),
    env.cybermeters_db
      .prepare(`INSERT INTO tlsrpt_aggregate_reports
                  (id, workspace_id, domain, org_name, contact_info, external_report_id,
                   date_range_begin, date_range_end, policy_type, policy_domain,
                   total_successful_sessions, total_failure_sessions, failure_count,
                   raw_hash, provenance, source)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                  workspace_id = excluded.workspace_id,
                  domain = excluded.domain,
                  org_name = excluded.org_name,
                  contact_info = excluded.contact_info,
                  external_report_id = excluded.external_report_id,
                  date_range_begin = excluded.date_range_begin,
                  date_range_end = excluded.date_range_end,
                  policy_type = excluded.policy_type,
                  policy_domain = excluded.policy_domain,
                  total_successful_sessions = excluded.total_successful_sessions,
                  total_failure_sessions = excluded.total_failure_sessions,
                  failure_count = excluded.failure_count,
                  raw_hash = excluded.raw_hash,
                  provenance = excluded.provenance,
                  source = excluded.source`)
      .bind(reportRowId, workspaceId, domain, rep.org_name, rep.contact_info,
        rep.external_report_id, rep.date_range_begin, rep.date_range_end,
        rep.primary_policy_type, rep.primary_policy_domain,
        rep.total_successful_sessions, rep.total_failure_sessions,
        rep.failure_count, rawHash, prov, source),
  ];

  for (const p of rep.policies) {
    for (const f of p.failures) {
      transaction.push(env.cybermeters_db
        .prepare(`INSERT INTO tlsrpt_failure_details
                    (id, report_id, workspace_id, domain, result_type, sending_mta_ip,
                     receiving_mx_hostname, receiving_ip, failed_session_count, additional_info)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(createId("tlsf"), reportRowId, workspaceId, domain, f.result_type, f.sending_mta_ip,
          f.receiving_mx_hostname, f.receiving_ip, f.failed_session_count, f.additional_info)
      );
    }
  }
  transaction.push(completeAggregateReportClaimStatement(env, claim));
  transaction.push(assertAggregateReportClaimCompleteStatement(env, claim));

  try {
    await env.cybermeters_db.batch(transaction);
  } catch {
    let quarantined = false;
    try {
      quarantined = await failAggregateReportClaim(
        env,
        claim,
        "transient_storage_failure",
      );
      if (!quarantined) throw new Error("aggregate_ingest_claim_fail_transition_lost");
      await createAuditEvent(env, {
        workspace_id: workspaceId,
        user_id: null,
        event_type: "tlsrpt_report_ingest_failed",
        entity_type: "domain",
        entity_id: domainId,
        description: `TLS-RPT report ingestion failed safely for ${domain}`,
        metadata: {
          domain,
          source,
          source_scope: sourceScope,
          report_id: rep.external_report_id,
          reason: "transient_storage_failure",
          claim_id: claim.claimId,
          repairable: true,
          ingest_endpoint_id: ingestEndpointId,
        },
        required: true,
      });
    } catch (quarantineError) {
      throw quarantineError;
    }
    return {
      ok: false,
      status: 503,
      error: "ingest_transient_failure",
      transient: true,
      quarantined,
      audited: true,
    };
  }

  return {
    ok: true,
    duplicate: false,
    sessions,
    failures: rep.failure_count,
    reportId: reportRowId,
    repaired: claim.repaired,
  };
}
