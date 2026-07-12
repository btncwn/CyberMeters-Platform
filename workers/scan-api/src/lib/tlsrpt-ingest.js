// ── TLS-RPT (RFC 8460) report ingestion ───────────────────────────────────────
// Parses the JSON reports that arrive at reports.cybermeters.com and stores them
// per workspace+domain. Completely separate from the DMARC XML path — TLS-RPT is
// JSON, so there is no XXE surface, but the input is still fully untrusted:
// size + array caps, JSON.parse in try/catch, never throws.
import { createId } from "./util.js";

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
    workspaceId, domain, jsonString,
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

  // Dedup by (workspace, domain, report-id) — a re-sent report changes nothing.
  const dup = await env.cybermeters_db
    .prepare(`SELECT id FROM tlsrpt_aggregate_reports WHERE workspace_id = ? AND domain = ? AND external_report_id = ? LIMIT 1`)
    .bind(workspaceId, domain, rep.external_report_id).first();
  if (dup) return { ok: true, duplicate: true, sessions, failures: rep.failure_count };

  // Provenance: only a recognised reporter (header-From we trust) is 'verified'.
  const prov = provenance && provenance.auth_verdict === "verified" ? "verified" : (provenance ? "unverified" : null);

  const reportRowId = createId("tlsr");
  await env.cybermeters_db
    .prepare(`INSERT INTO tlsrpt_aggregate_reports
                (id, workspace_id, domain, org_name, contact_info, external_report_id,
                 date_range_begin, date_range_end, policy_type, policy_domain,
                 total_successful_sessions, total_failure_sessions, failure_count, provenance)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .bind(reportRowId, workspaceId, domain, rep.org_name, rep.contact_info, rep.external_report_id,
      rep.date_range_begin, rep.date_range_end, rep.primary_policy_type, rep.primary_policy_domain,
      rep.total_successful_sessions, rep.total_failure_sessions, rep.failure_count, prov)
    .run();

  for (const p of rep.policies) {
    for (const f of p.failures) {
      await env.cybermeters_db
        .prepare(`INSERT INTO tlsrpt_failure_details
                    (id, report_id, workspace_id, domain, result_type, sending_mta_ip,
                     receiving_mx_hostname, receiving_ip, failed_session_count, additional_info)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
        .bind(createId("tlsf"), reportRowId, workspaceId, domain, f.result_type, f.sending_mta_ip,
          f.receiving_mx_hostname, f.receiving_ip, f.failed_session_count, f.additional_info)
        .run();
    }
  }

  return { ok: true, duplicate: false, sessions, failures: rep.failure_count };
}
