// ── Hosted DMARC records engine + remediation ──
// Managed DMARC record lifecycle: DNS verification, Cloudflare-hosted TXT record CRUD +
// verification sweep, DMARC policy ramp/auto-rollback engine, hosted-intent reconciliation +
// plan gating, the remediation registry (DMARC/TLS-RPT/MTA-STS/BIMI/CAA), and SPF chain
// analysis. Extracted verbatim from index.js (monolith decomposition, Phase 1c). Ramp
// thresholds, CF patch/get helpers, remediation builders and normalizeDmarcRuaForComparison
// are module-internal.
import { RUA_INBOUND_DOMAIN_DEFAULT, normalizeInboundRecipientDomain } from "../lib/dmarc-ingest.js";
import {
  DMARC_EXTERNAL_AUTOMATION_EVIDENCE_SCOPE,
  dmarcExternalAutomationSourceSql,
} from "../lib/dmarc-authority.js";
import { aggregateReportCompleteSql } from "../lib/aggregate-report-ingest.js";
import { createAuditEvent } from "../lib/events.js";
// PR-B3: this engine no longer holds a sender. Every alert it used to deliver
// directly — bypassing occurrence identity, the activation watermark, dedupe and
// the delivery ledger — now goes through the canonical lifecycle engine.
import {
  EMAIL_EVENT_HOSTED_POLICY_CHANGED, EMAIL_EVENT_HOSTED_RECONNECTED,
  EMAIL_EVENT_HOSTED_ROLLED_BACK_MANUAL, recordHostedTransition,
} from "./email-protection-lifecycle.js";
import { assessImpactRollback, comparePolicyImpact } from "./dmarc-impact.js";
import { dnsQuery } from "./dns.js";
import { normalizeDnsTxtValue, parseDmarcRecord, parseSpfRecord } from "./email-analysis.js";
import { fetchMtaSts } from "./email-intel.js";
import { normalizePlan } from "./entitlements.js";
import { _cloudflareEmailRoutingRequest, classifyHostedCfError, ensureCloudflareEmailRoute } from "./rua-routing.js";

function normalizeDmarcRuaForComparison(value) {
  return String(value || "").trim().toLowerCase().replace(/!\d+[kmgt]?$/i, "");
}

// Preserve the customer's existing DMARC tags and policy. This helper only
// adds the CyberMeters aggregate-reporting URI; it never recommends stronger
// enforcement or mutates DNS. It is also the first value of a hosted record, so
// a legacy pct is never carried over: it is rewritten with its intent (a pct
// below 100 becomes t=y, RFC 9989 Appendix A.6).
export function buildDmarcDnsRecommendedValue(record, recommendedRua) {
  const raw = withoutLegacyPct(normalizeDnsTxtValue(record));
  if (!raw) return `v=DMARC1; p=none; rua=${recommendedRua}`;
  const parts = raw.split(";").map((part) => part.trim()).filter(Boolean);
  const ruaIndex = parts.findIndex((part) => /^rua\s*=/i.test(part));
  if (ruaIndex < 0) parts.push(`rua=${recommendedRua}`);
  else {
    const eq = parts[ruaIndex].indexOf("=");
    const existing = parts[ruaIndex].slice(eq + 1).split(",").map((value) => value.trim()).filter(Boolean);
    const wanted = normalizeDmarcRuaForComparison(recommendedRua);
    if (!existing.some((value) => normalizeDmarcRuaForComparison(value) === wanted)) existing.push(recommendedRua);
    parts[ruaIndex] = `rua=${existing.join(",")}`;
  }
  return parts.join("; ").slice(0, 4096);
}

function _dmarcDnsCheckResponse(domain, endpoint, records, checkedAt) {
  const inboundDomain = normalizeInboundRecipientDomain(endpoint.inbound_domain || RUA_INBOUND_DOMAIN_DEFAULT)
    || RUA_INBOUND_DOMAIN_DEFAULT;
  const recommendedRua = `mailto:${endpoint.address_local}@${inboundDomain}`;
  const base = {
    domain,
    checked_at: checkedAt,
    dmarc_present: records.length > 0,
    cybermeters_rua_present: false,
    policy: null,
    subdomain_policy: null,
    pct: null,
    rua: [],
    recommended_rua: recommendedRua,
    recommended_txt_value: records.length === 0
      ? buildDmarcDnsRecommendedValue(null, recommendedRua) : null,
  };
  if (records.length === 0) return {
    ...base, status: "no_dmarc", message: "No DMARC record was found.",
  };
  if (records.length > 1) return {
    ...base, status: "multiple_dmarc_records",
    message: "Multiple DMARC records were found. Publish exactly one DMARC record before verifying reporting.",
  };

  const record = records[0];
  const detail = parseDmarcRecord(record, 1);
  const safeRua = detail.rua.slice(0, 20).map((value) => String(value).slice(0, 512));
  const response = {
    ...base,
    policy: detail.policy,
    subdomain_policy: detail.subdomain_policy,
    pct: detail.pct,
    rua: safeRua,
    recommended_txt_value: buildDmarcDnsRecommendedValue(record, recommendedRua),
  };
  if (!detail.valid) return {
    ...response, status: "invalid_dmarc",
    message: "A DMARC record was found, but it is not valid.",
  };
  const wanted = normalizeDmarcRuaForComparison(recommendedRua);
  const present = safeRua.some((value) => normalizeDmarcRuaForComparison(value) === wanted);
  return present
    ? { ...response, cybermeters_rua_present: true, status: "verified",
        message: "DMARC record includes the CyberMeters reporting address." }
    : { ...response, status: "missing_cybermeters_rua",
        message: "DMARC exists, but the CyberMeters reporting address is not included yet." };
}

export async function verifyDmarcDnsSetup(env, workspaceId, domain, {
  dnsQueryImpl = dnsQuery,
  checkedAt = new Date().toISOString(),
} = {}) {
  // Select only the one non-secret value required for comparison. token_hash,
  // Cloudflare route identifiers, and raw upload tokens never enter the result.
  const endpoint = await env.cybermeters_db
    .prepare(`SELECT address_local FROM dmarc_ingest_endpoints
              WHERE workspace_id = ? AND domain = ? AND status = 'active' AND revoked_at IS NULL
              ORDER BY created_at DESC LIMIT 1`)
    .bind(workspaceId, domain).first();
  if (!endpoint?.address_local || !/^cmrua_[a-z0-9]{8,}$/.test(endpoint.address_local)) return {
    domain,
    checked_at: checkedAt,
    status: "endpoint_missing",
    message: "Create a CyberMeters reporting address before verifying DNS.",
  };

  const inboundDomain = normalizeInboundRecipientDomain(env.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT)
    || RUA_INBOUND_DOMAIN_DEFAULT;
  const boundEndpoint = { address_local: endpoint.address_local, inbound_domain: inboundDomain };
  let response;
  try { response = await dnsQueryImpl(`_dmarc.${domain}`, "TXT"); }
  catch {
    return {
      domain, checked_at: checkedAt, status: "dns_lookup_failed",
      message: "The DMARC DNS lookup could not be completed.",
    };
  }
  const dnsStatus = Number(response?.Status ?? 0);
  if (dnsStatus !== 0 && dnsStatus !== 3) return {
    domain, checked_at: checkedAt, status: "dns_lookup_failed",
    message: "The DMARC DNS lookup could not be completed.",
  };
  const records = (response?.Answer || [])
    .map((answer) => normalizeDnsTxtValue(answer?.data)
      .replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 4096))
    .filter((value) => /^v=DMARC1(?:\s*;|$)/i.test(value))
    .slice(0, 3);
  return _dmarcDnsCheckResponse(domain, boundEndpoint, records, checkedAt);
}

// ─── Hosted DNS Records Engine — Phase A: hosted DMARC ──────────────────────
// The customer CNAMEs _dmarc.<domain> to <id>.dmarc.cybermeters.com once; we
// manage the TXT value on our zone via the Cloudflare DNS API (same
// token/zone secrets and request helper as the email-routing automation).
// Phase A hosts a value mirroring the customer's existing record merged with
// our RUA — no policy transitions yet. The hourly sweep verifies both sides
// and NEVER deletes a hosted TXT while the customer's _dmarc still points at
// it (their policy would silently vanish otherwise).

const HOSTED_DMARC_SUBDOMAIN_DEFAULT = "dmarc.cybermeters.com";
export const HOSTED_DNS_REMOVAL_GRACE_DAYS = 7;
const HOSTED_DNS_SWEEP_LIMIT = 25;

export function hostedDmarcSubdomain(env) {
  const raw = String(env?.HOSTED_DMARC_SUBDOMAIN || HOSTED_DMARC_SUBDOMAIN_DEFAULT).trim().toLowerCase();
  return /^[a-z0-9][a-z0-9.-]{3,251}[a-z0-9]$/.test(raw) ? raw : HOSTED_DMARC_SUBDOMAIN_DEFAULT;
}

export function newHostedDnsRecordId() {
  // DNS-safe LDH label (no underscores): usable directly as the host label.
  return `hd-${crypto.randomUUID().replace(/-/g, "").slice(0, 12)}`;
}

// Hosted DNS v2: rows now live in hosted_dns_entries. This projection reads that
// table but aliases the new columns back to the legacy field names the engine +
// routes already use (status, hosted_name, current_value, cf_record_id,
// last_verified_at, record_type), so the repoint is SQL-only — no JS-access churn
// and no change to DMARC behaviour. The new native names are also present on the
// row (harmless). WHERE/ORDER-BY clauses must reference the real column names.
export const HOSTED_DNS_ENTRY_SELECT =
  "SELECT *, verification_state AS status, verified_at AS last_verified_at, " +
  "target_name AS hosted_name, target_value AS current_value, " +
  "provider_record_id AS cf_record_id, record_kind AS record_type " +
  "FROM hosted_dns_entries";

// Safe serialization: cf_record_id and created_by never leave the worker.
export function hostedDnsRecordToApi(row) {
  if (!row) return null;
  // Hosted DNS v2: record-kind aware. DMARC-ramp concepts only apply to dmarc;
  // other kinds (tlsrpt/mtasts/spf) get null ramp fields. cname_name is the
  // stored customer record name (falls back to _dmarc for legacy/ad-hoc rows).
  const kind = row.record_type || "dmarc";
  const isDmarc = kind === "dmarc";
  const stepIdx = isDmarc ? dmarcRampStepIndex(row.current_value) : -1;
  const step = stepIdx >= 0 ? DMARC_RAMP_LADDER[stepIdx] : null;
  const nextStep = stepIdx >= 0 ? DMARC_RAMP_LADDER[stepIdx + 1] || null : null;
  return {
    id: row.id,
    domain: row.domain,
    record_type: row.record_type,
    hosted_name: row.hosted_name,
    cname_name: row.customer_name || `_dmarc.${row.domain}`,
    cname_target: row.hosted_name,
    current_value: row.current_value,
    status: row.status,
    // Customer-safe issue class (K2): 'config_error' | 'temporary_issue' | null.
    issue: row.last_error || null,
    // Phase B: ramp position + self-driving state (dmarc only).
    policy_step: step ? dmarcRampStepToApi(stepIdx) : null,
    next_step: nextStep ? dmarcRampStepToApi(stepIdx + 1) : null,
    // One level less strict, for a step-down control; none at the bottom.
    previous_step: stepIdx > 0 ? dmarcRampStepToApi(stepIdx - 1) : null,
    // The whole ladder, so a client renders it without its own copy.
    ladder: isDmarc ? DMARC_RAMP_LADDER.map((_, index) => dmarcRampStepToApi(index)) : null,
    // A value that still carries pct (removed by RFC 9989), with what happens to it.
    legacy_pct: isDmarc ? legacyPctNotice(row.current_value) : null,
    autopilot: isDmarc && Number(row.autopilot) === 1,
    can_rollback: isDmarc && Boolean(row.previous_value),
    change_pending: Boolean(row.pending_value),
    // Per-tag diffs (transparency — the customer sees exactly what changes, never
    // a blind overwrite). pending_diff = current→in-flight; next_step_diff =
    // what advancing one ramp step would change.
    pending_diff: isDmarc && row.pending_value ? dmarcTagDiff(row.current_value, row.pending_value) : null,
    next_step_diff: isDmarc && nextStep
      ? dmarcTagDiff(row.current_value, buildDmarcPolicyValue(row.current_value, { policy: nextStep.policy, testing: nextStep.testing }).value)
      : null,
    policy_content: kind === "mtasts" ? row.policy_content || null : null,
    policy_path: kind === "mtasts" ? `https://mta-sts.${row.domain}/.well-known/mta-sts.txt` : null,
    last_change_at: row.last_change_at || null,
    last_verified_at: row.last_verified_at || null,
    created_at: row.created_at,
  };
}

// TLS-RPT reporting record value (RFC 8460). Points reporting at a mailbox we
// control (the domain's existing CyberMeters reporting address).
export function buildTlsRptValue(reportingAddress) {
  return `v=TLSRPTv1; rua=mailto:${reportingAddress}`;
}

export function buildMtaStsTxtValue(id) {
  return `v=STSv1; id=${id}`;
}

function normalizeMtaStsMxHost(value) {
  const host = String(value || "").trim().toLowerCase().replace(/\.$/, "");
  return /^[a-z0-9*][a-z0-9*.-]{0,251}[a-z0-9]$/.test(host) ? host : "";
}

export function mxHostsFromDnsResponse(response, domain) {
  const hosts = [];
  for (const answer of response?.Answer || []) {
    const data = String(answer?.data || "").trim();
    if (!data) continue;
    const parts = data.split(/\s+/);
    const host = normalizeMtaStsMxHost(parts[parts.length - 1]);
    if (host && !hosts.includes(host)) hosts.push(host);
  }
  return hosts.length ? hosts : [`*.${domain}`];
}

export function buildMtaStsPolicy(domain, mxHosts = []) {
  const hosts = (Array.isArray(mxHosts) ? mxHosts : [])
    .map(normalizeMtaStsMxHost)
    .filter(Boolean);
  const effectiveHosts = hosts.length ? [...new Set(hosts)] : [`*.${domain}`];
  return ["version: STSv1", "mode: testing", ...effectiveHosts.map((m) => `mx: ${m}`), "max_age: 604800"].join("\n");
}

function parseMtaStsPolicyContent(content) {
  const result = { mode: null, mx: [], max_age: null };
  for (const raw of String(content || "").split(/\r?\n/)) {
    const line = raw.trim();
    if (/^mode:/i.test(line)) result.mode = line.split(":", 2)[1]?.trim() || null;
    else if (/^mx:/i.test(line)) {
      const mx = line.split(":", 2)[1]?.trim();
      if (mx) result.mx.push(mx);
    } else if (/^max_age:/i.test(line)) {
      const n = parseInt((line.split(":", 2)[1] || "").trim(), 10);
      if (!Number.isNaN(n)) result.max_age = n;
    }
  }
  return result;
}

export async function verifyMtaStsHttpsPolicy(domain, expectedPolicyContent, { fetchMtaStsImpl = fetchMtaSts } = {}) {
  const path = `https://mta-sts.${domain}/.well-known/mta-sts.txt`;
  try {
    const fetched = await fetchMtaStsImpl(domain);
    if (!fetched?.enabled) return {
      state: "not_published",
      path,
      matches_pinned_policy: false,
      mode: null,
      version: null,
      mx_patterns: [],
      max_age: null,
      errors: fetched?.errors || [],
    };
    const valid = String(fetched.policy_version || "") === "STSv1" && Boolean(fetched.policy_mode) && Array.isArray(fetched.mx_patterns)
      && fetched.mx_patterns.length > 0 && fetched.max_age != null;
    const expected = parseMtaStsPolicyContent(expectedPolicyContent);
    const expectedMx = [...expected.mx].sort();
    const actualMx = [...(fetched.mx_patterns || [])].sort();
    const matches = valid
      && String(fetched.policy_mode || "") === String(expected.mode || "")
      && Number(fetched.max_age) === Number(expected.max_age)
      && expectedMx.length === actualMx.length
      && expectedMx.every((mx, idx) => mx === actualMx[idx]);
    return {
      state: valid ? "reachable_valid" : "reachable_invalid",
      path,
      matches_pinned_policy: matches,
      version: fetched.policy_version || null,
      mode: fetched.policy_mode || null,
      mx_patterns: fetched.mx_patterns || [],
      max_age: fetched.max_age ?? null,
      errors: fetched.errors || [],
    };
  } catch (e) {
    return {
      state: "not_published",
      path,
      matches_pinned_policy: false,
      mode: null,
      version: null,
      mx_patterns: [],
      max_age: null,
      errors: [e?.message || "MTA-STS policy check failed"],
    };
  }
}

// Customer-side record name we expect to CNAME to our hosted name, per kind.
export function hostedCustomerRecordName(domain, recordKind) {
  if (recordKind === "tlsrpt") return `_smtp._tls.${domain}`;
  if (recordKind === "mtasts") return `_mta-sts.${domain}`;
  return `_dmarc.${domain}`;
}

export async function cfCreateHostedTxt(env, name, content, { fetchImpl = fetch } = {}) {
  const zoneId = String(env?.CLOUDFLARE_ZONE_ID || "").trim();
  if (!String(env?.CLOUDFLARE_API_TOKEN || "").trim() || !/^[a-f0-9]{32}$/i.test(zoneId)) {
    return { ok: false, reason: "missing_config" };
  }
  const base = `/zones/${zoneId}/dns_records`;
  const wanted = String(content).replace(/\s+/g, " ").trim();

  // Idempotency (K1): adopt an existing TXT at this name instead of blindly
  // creating a duplicate. Two identical TXT records at the hosted name would
  // make the customer's CNAME resolve to two DMARC records — DMARC invalid.
  // Mirrors the list-before-create pattern in ensureCloudflareEmailRoute.
  const listed = await _cloudflareEmailRoutingRequest(
    env, `${base}?type=TXT&name=${encodeURIComponent(name)}&per_page=50`, {}, fetchImpl);
  if (listed.ok) {
    const matches = Array.isArray(listed.body?.result) ? listed.body.result : [];
    if (matches.length > 0) {
      const [keep, ...extras] = matches;
      // Self-heal any pre-existing duplicates from before this guard shipped.
      for (const dup of extras) {
        if (dup?.id) await cfDeleteHostedTxt(env, dup.id, { fetchImpl });
      }
      const keepContent = String(keep?.content || "").replace(/\s+/g, " ").trim();
      if (keep?.id && keepContent !== wanted) {
        // Correct drifted content in place — keep the same record id.
        await _cloudflareEmailRoutingRequest(env, `${base}/${encodeURIComponent(keep.id)}`, {
          method: "PATCH",
          body: JSON.stringify({ type: "TXT", name, content, ttl: 300 }),
        }, fetchImpl);
      }
      return keep?.id ? { ok: true, cf_record_id: keep.id, adopted: true } : { ok: false, reason: "api_rejected" };
    }
  } else if (listed.reason && listed.reason !== "unsupported_api") {
    // A hard list failure (auth/rate-limit/outage) — surface it rather than
    // falling through to a create that could race into a duplicate.
    return { ok: false, reason: listed.reason };
  }

  const res = await _cloudflareEmailRoutingRequest(env, base, {
    method: "POST",
    body: JSON.stringify({
      type: "TXT", name, content, ttl: 300,
      comment: "CyberMeters hosted DMARC — managed record",
    }),
  }, fetchImpl);
  if (!res.ok) return res;
  const cfRecordId = String(res.body?.result?.id || "").trim();
  return cfRecordId ? { ok: true, cf_record_id: cfRecordId } : { ok: false, reason: "api_rejected" };
}

async function cfDeleteHostedTxt(env, cfRecordId, { fetchImpl = fetch } = {}) {
  const zoneId = String(env?.CLOUDFLARE_ZONE_ID || "").trim();
  if (!cfRecordId || !/^[a-f0-9]{32}$/i.test(zoneId)) return { ok: false, reason: "missing_config" };
  return _cloudflareEmailRoutingRequest(
    env, `/zones/${zoneId}/dns_records/${encodeURIComponent(cfRecordId)}`,
    { method: "DELETE" }, fetchImpl,
  );
}

// Both checks resolve through public DNS, so they observe what receivers see:
// hosted_live — our TXT serves the expected value; cname_connected — the
// customer's _dmarc resolves (via their CNAME) to that same value.
export async function verifyHostedDmarcRecord(row, { dnsQueryImpl = dnsQuery } = {}) {
  const expected = String(row.current_value || "").replace(/\s+/g, " ").trim();
  const hostedTarget = String(row.hosted_name || "").toLowerCase().replace(/\.$/, "");
  const fetchAnswers = async (name, type) => {
    try {
      const res = await dnsQueryImpl(name, type);
      if (Number(res?.Status ?? 1) !== 0) return null;
      return res?.Answer || [];
    } catch { return null; }
  };
  const txtValueMatches = (a) =>
    normalizeDnsTxtValue(a?.data).replace(/\s+/g, " ").trim() === expected;

  const hostedAnswers = await fetchAnswers(row.hosted_name, "TXT");
  const hosted_live = (hostedAnswers || []).some(txtValueMatches);
  if (!hosted_live) return { hosted_live: false, cname_connected: false };

  // cname_connected requires GENUINE delegation: the customer record (e.g.
  // _dmarc.<domain> or _smtp._tls.<domain>) must CNAME to our hosted name, not
  // merely publish identical content. A standalone TXT with the same content
  // would otherwise read as "connected" while we manage nothing — and the
  // illusion would shatter (false disconnect alarm) on the first change.
  // v2: the customer record name is stored per row (kind-aware); legacy/ad-hoc
  // rows without it fall back to the DMARC name.
  const customerName = row.customer_name || `_dmarc.${row.domain}`;
  const answers = await fetchAnswers(customerName, "TXT");
  const contentMatches = (answers || []).some(txtValueMatches);
  if (!contentMatches) return { hosted_live, cname_connected: false };
  // Resolvers include the CNAME chain (type 5) in the answer section.
  const chainToUs = (answers || []).some((a) => Number(a?.type) === 5 &&
    String(a?.data || "").toLowerCase().replace(/\.$/, "") === hostedTarget);
  if (chainToUs) return { hosted_live, cname_connected: true };
  // Content matches but no visible chain — either a mirrored standalone TXT
  // (pre-CNAME) or a resolver omitting the chain. An explicit CNAME lookup
  // settles it either way.
  const cnameAnswers = await fetchAnswers(customerName, "CNAME");
  const cname_connected = (cnameAnswers || []).some((a) =>
    String(a?.data || "").toLowerCase().replace(/\.$/, "").replace(/^"|"$/g, "") === hostedTarget);
  return { hosted_live, cname_connected };
}

export function nextHostedDnsStatus(row, checks) {
  if (row.status === "pending_removal") return "pending_removal";
  if (!checks.hosted_live) return "pending_dns";
  if (checks.cname_connected) return "connected";
  // Once connected, a missing CNAME is a loud "disconnected", never a quiet
  // reset to awaiting_cname.
  return row.status === "connected" || row.status === "disconnected"
    ? "disconnected"
    : "awaiting_cname";
}

// Hourly sweep: retry pending CF creations, verify both sides, progress the
// status machine, alert on connected→disconnected, and complete removals only
// when safe. Per-row isolation — one failure never aborts the sweep.
export async function runHostedDnsVerificationSweep(env, {
  dnsQueryImpl = dnsQuery, fetchImpl = fetch, now = new Date(),
  // Test seam only: the production pass rate (getHostedDmarcPassRate) is
  // suspended and fails closed, so a harness injects one to reach autopilot.
  passRateImpl = getHostedDmarcPassRate,
} = {}) {
  let rows = [];
  try {
    // M1: least-recently-verified first (NULLs — never-verified — lead). Ordering
    // by updated_at let stable connected rows starve fresh pending ones at scale.
    const r = await env.cybermeters_db
      .prepare(`${HOSTED_DNS_ENTRY_SELECT}
                WHERE verification_state IN ('pending_dns','awaiting_cname','connected','disconnected','pending_removal')
                ORDER BY (verified_at IS NULL) DESC, verified_at ASC LIMIT ?`)
      .bind(HOSTED_DNS_SWEEP_LIMIT).all();
    rows = r.results || [];
  } catch { return { checked: 0, removed: 0 }; }

  const nowIso = now.toISOString();
  let checked = 0, removed = 0;
  for (const row of rows) {
    try {
      checked += 1;
      // H1: settle any stranded write-ahead intent first, and never run other
      // mutations on a row whose saga is unresolved.
      if (row.pending_value) {
        await reconcileHostedIntent(env, row, { fetchImpl, now });
        continue;
      }
      if (!row.cf_record_id && row.status === "pending_dns") {
        const created = await cfCreateHostedTxt(env, row.hosted_name, row.current_value, { fetchImpl });
        if (created.ok) {
          row.cf_record_id = created.cf_record_id;
          await env.cybermeters_db
            .prepare(`UPDATE hosted_dns_entries SET provider_record_id = ?, failure_count = 0, last_error = NULL, updated_at = ? WHERE id = ?`)
            .bind(created.cf_record_id, nowIso, row.id).run();
        } else {
          // K2: record the failure class. config_error surfaces to the customer
          // and to our logs; temporary_issue self-heals on the next sweep.
          const issue = classifyHostedCfError(created.reason);
          if (issue === "config_error") {
            console.error("[hosted-dmarc] config error", JSON.stringify({ id: row.id, reason: created.reason }));
          }
          await env.cybermeters_db
            .prepare(`UPDATE hosted_dns_entries SET failure_count = failure_count + 1, last_error = ?, updated_at = ? WHERE id = ?`)
            .bind(issue, nowIso, row.id).run();
          continue; // nothing to verify without a published TXT
        }
      }

      const checks = await verifyHostedDmarcRecord(row, { dnsQueryImpl });

      if (row.status === "pending_removal") {
        const updatedAt = String(row.updated_at || "");
        const updatedMs = new Date(updatedAt.includes("T") ? updatedAt : updatedAt.replace(" ", "T") + "Z").getTime();
        const graceOver = Number.isFinite(updatedMs)
          && (now.getTime() - updatedMs) > HOSTED_DNS_REMOVAL_GRACE_DAYS * 24 * 3600 * 1000;
        // Never pull the TXT out from under a CNAME that still depends on it.
        if (!checks.cname_connected || graceOver) {
          // The row is only removed once the Cloudflare record is confirmed
          // gone — otherwise the TXT would be orphaned on our zone with
          // nothing tracking it. Failed CF deletes retry on the next sweep.
          let cfCleared = !row.cf_record_id;
          if (row.cf_record_id) {
            const del = await cfDeleteHostedTxt(env, row.cf_record_id, { fetchImpl });
            cfCleared = del.ok === true;
          }
          if (cfCleared) {
            await env.cybermeters_db
              .prepare(`DELETE FROM hosted_dns_entries WHERE id = ?`).bind(row.id).run();
            removed += 1;
            await createAuditEvent(env, {
              workspace_id: row.workspace_id,
              event_type: "hosted_dmarc_removed", entity_type: "hosted_dns_record", entity_id: row.id,
              description: `Hosted DMARC record for ${row.domain} removed`,
            });
          }
        }
        continue;
      }

      let next = nextHostedDnsStatus(row, checks);
      // Propagation grace: a value change makes public DNS briefly disagree
      // with current_value (TTL 300s + resolver caches). Do not demote a
      // healthy record to pending_dns inside the grace window.
      const changeMs = parseServerMsHosted(row.last_change_at);
      const withinChangeGrace = changeMs != null
        && (now.getTime() - changeMs) < HOSTED_CHANGE_PROPAGATION_MS;
      if (withinChangeGrace && next === "pending_dns"
          && (row.status === "connected" || row.status === "disconnected")) {
        next = row.status;
      }
      if (next !== row.status) {
        await env.cybermeters_db
          .prepare(`UPDATE hosted_dns_entries SET verification_state = ?, verified_at = ?, updated_at = ? WHERE id = ?`)
          .bind(next, nowIso, nowIso, row.id).run();
        // PR-B3: the state machine above IS the transition guard — we only get
        // here when `next !== row.status` — so this is a genuine edge, exactly
        // like a managed-case transition. The lifecycle engine owns the append
        // and the alert; this engine no longer holds a sender.
        if (next === "disconnected" && row.status === "connected") {
          await recordHostedTransition(env, row, {
            recurrence: "hosted_record_disconnected",
            from_status: row.status, to_status: next,
            reason: "cname_no_longer_points_at_hosted_target",
          }).catch(() => { /* alerting must never break the sweep */ });
        }
        // Recovery. Non-alertable by founder decision: history and state
        // integrity only, and structurally unable to alert (its event_type is
        // not `monitoring_changed`, so no occurrence can resolve from it).
        if (next === "connected" && row.status === "disconnected") {
          await recordHostedTransition(env, row, {
            event_type: EMAIL_EVENT_HOSTED_RECONNECTED,
            from_status: row.status, to_status: next,
            reason: "cname_restored",
          }).catch(() => {});
        }
      } else {
        await env.cybermeters_db
          .prepare(`UPDATE hosted_dns_entries SET verified_at = ? WHERE id = ?`)
          .bind(nowIso, row.id).run();
      }

      // ── Self-driving evaluation (connected records only) ──────────────────
      // Auto-rollback watches every record with a recent change; autopilot
      // advances the ladder only when the pass-rate interlock holds.
      if (next === "connected" && row.cf_record_id && !withinChangeGrace) {
        const rate = await passRateImpl(env, row.workspace_id, row.domain);
        let impactAssessment = null;
        if (row.last_change_at) {
          try {
            const comparison = await comparePolicyImpact(env, row.workspace_id, row.domain, { changeAt: row.last_change_at, now });
            impactAssessment = assessImpactRollback(comparison);
            if (impactAssessment.rollbackRecommended) {
              // PR-B3. The old guard was an audit_events lookup with a 1-day
              // window, so an unchanged regression RE-ALERTED EVERY DAY for as
              // long as it persisted. audit_events is now audit history only and
              // is never consulted for identity (founder decision).
              //
              // The transition guard is the policy change this regression is
              // about: `last_change_at` is the band (PR-B2's third dimension).
              // The same regression against the same change is not a transition,
              // so no event is appended, the occurrence id is unchanged, the
              // dedupe key is unchanged, and the database silences the repeat.
              // A regression after a NEW policy change is a new band, so a new
              // occurrence, so it correctly alerts again.
              const outcome = await recordHostedTransition(env, row, {
                recurrence: "hosted_impact_regression",
                from_status: row.status, to_status: next,
                band: row.last_change_at || null,
                record_severity: impactAssessment.severity || "medium",
                reason: impactAssessment.triggers?.[0] || "legitimate_mail_failures_after_policy_change",
                detail: { assessment: impactAssessment },
              }).catch(() => null);
              // Audit records the transition, not every sweep that re-observed
              // the same unchanged condition.
              if (outcome && outcome.reason !== "unchanged" && !outcome.skipped) {
                await createAuditEvent(env, {
                  workspace_id: row.workspace_id,
                  event_type: "hosted_dmarc_impact_regression", entity_type: "hosted_dns_record", entity_id: row.id,
                  description: `Hosted DMARC impact monitor recommends review for ${row.domain}`,
                  metadata: { domain: row.domain, assessment: impactAssessment },
                });
              }
            }
          } catch { impactAssessment = null; }
        }
        if (row.previous_value && row.pass_rate_at_change != null &&
            shouldAutoRollback({
              baseline_pass_rate: Number(row.pass_rate_at_change),
              current_pass_rate: rate.pass_rate,
              total_messages: rate.total,
            }, resolveRampThresholds(env))) {
          await rollbackHostedDmarc(env, row, { source: "auto", fetchImpl });
        } else if (Number(row.autopilot) === 1) {
          const nextStep = autopilotNextStep(row.current_value);
          if (nextStep) {
            const daysSince = changeMs != null
              ? Math.floor((now.getTime() - changeMs) / 86400000) : null;
            const readiness = evaluateRampReadiness({
              pass_rate: rate.pass_rate, total_messages: rate.total,
              days_since_change: daysSince,
            }, resolveRampThresholds(env));
            if (readiness.ready) {
              await applyHostedDmarcChange(env, row, {
                policy: nextStep.policy, testing: nextStep.testing,
                source: "autopilot", passRateNow: rate.pass_rate, fetchImpl,
              });
            }
          }
        }
      }
    } catch { /* per-row isolation */ }
  }
  return { checked, removed };
}

// ─── Self-Driving DMARC — Phase B: policy ramp with pass-rate interlock ─────
// We host the record AND ingest the RUA reports, so the loop can be closed:
// advance p=none → quarantine → reject only while measured compliance stays
// healthy, and automatically roll back to previous_value if compliance drops
// materially after a change.
//
// RFC 9989 (DMARC, May 2026) removed the pct tag (Appendix A.6): receivers
// applied it reliably only at 0 and 100, and the testing tag t replaces it,
// t=y/n corresponding to the old pct=0/100. Section 4.7: with t=y the receiver
// is asked to apply one level below the published policy (p=quarantine; t=y →
// no action, p=reject; t=y → quarantine). So each policy is first published
// with t=y, then as written; the ladder never writes pct.

export const DMARC_RAMP_LADDER = Object.freeze([
  Object.freeze({ key: "none", policy: "none", testing: false, label: "Monitor only",
    description: "No action is requested for mail that fails DMARC; reports keep arriving." }),
  Object.freeze({ key: "quarantine_testing", policy: "quarantine", testing: true, label: "Quarantine (testing)",
    description: "p=quarantine with t=y: receivers are asked to apply one level less, so still no action (RFC 9989 §4.7)." }),
  Object.freeze({ key: "quarantine", policy: "quarantine", testing: false, label: "Quarantine",
    description: "Receivers are asked to quarantine mail that fails DMARC." }),
  Object.freeze({ key: "reject_testing", policy: "reject", testing: true, label: "Reject (testing)",
    description: "p=reject with t=y: receivers are asked to apply one level less, so quarantine (RFC 9989 §4.7)." }),
  Object.freeze({ key: "reject", policy: "reject", testing: false, label: "Reject",
    description: "Receivers are asked to reject mail that fails DMARC." }),
]);
const DMARC_RAMP_INDEX_BY_KEY = new Map(DMARC_RAMP_LADDER.map((step, index) => [step.key, index]));

/** The ladder index for a step key, or -1. */
export function dmarcRampStepByKey(key) {
  return DMARC_RAMP_INDEX_BY_KEY.has(key) ? DMARC_RAMP_INDEX_BY_KEY.get(key) : -1;
}

/** The change autopilot would make next ({ policy, testing }), or null at the top. */
export function autopilotNextStep(currentValue) {
  const index = dmarcRampStepIndex(currentValue);
  const next = index >= 0 ? DMARC_RAMP_LADDER[index + 1] : null;
  return next ? { policy: next.policy, testing: next.testing } : null;
}

export function dmarcRampStepToApi(index) {
  const step = DMARC_RAMP_LADDER[index];
  return step ? { index, key: step.key, policy: step.policy, testing: step.testing, label: step.label, description: step.description } : null;
}
const HOSTED_POLICY_DAILY_BUDGET = 10;   // manual + automatic changes per record per UTC day
const RAMP_MIN_MESSAGES = 50;            // minimum 7-day volume for a confident read
const RAMP_MIN_PASS_RATE = 97;           // % DMARC pass required to advance
const RAMP_MIN_DAYS_SINCE_CHANGE = 3;    // soak time between autopilot steps
const ROLLBACK_DROP_PP = 5;              // pass-rate drop (percentage points) that triggers rollback
const ROLLBACK_MIN_MESSAGES = 20;        // minimum volume before a drop is trusted
const HOSTED_CHANGE_PROPAGATION_MS = 15 * 60 * 1000; // verify grace after a value change

// The policy tags of a DMARC value (lower-cased tag names, trimmed values).
function dmarcTags(raw) {
  const map = new Map();
  for (const part of String(raw || "").split(";")) {
    const m = part.trim().match(/^([a-z]+)\s*=\s*(.*)$/i);
    if (m && !map.has(m[1].toLowerCase())) map.set(m[1].toLowerCase(), m[2].trim());
  }
  return map;
}

// A legacy pct below 100 (including 0) is treated as testing: Appendix A.6 maps
// pct=0 to t=y, and 1-99 has no RFC 9989 meaning, so the less strict reading is
// the honest one. pct=100 or no pct is the policy as written.
function legacyPctMeansTesting(tags) {
  if (!tags.has("pct")) return false;
  const pct = Number(tags.get("pct"));
  return !(Number.isInteger(pct) && pct >= 100);
}

export function dmarcRampStepIndex(raw) {
  const d = parseDmarcRecord(raw, 1);
  if (!d.valid) return -1;
  if (d.policy === "none") return 0;
  const tags = dmarcTags(raw);
  const testing = String(tags.get("t") || "").toLowerCase() === "y" || legacyPctMeansTesting(tags);
  const key = `${d.policy}${testing ? "_testing" : ""}`;
  return dmarcRampStepByKey(key);
}

/**
 * The record without pct (RFC 9989 removed it), keeping the policy intent: a
 * pct below 100 becomes t=y unless t is already set. Every other tag is kept
 * byte-for-byte. A value with no pct is returned unchanged.
 */
export function withoutLegacyPct(raw) {
  const parts = String(raw || "").split(";").map((p) => p.trim()).filter(Boolean);
  const tags = dmarcTags(raw);
  if (!tags.has("pct")) return String(raw || "");
  const testing = legacyPctMeansTesting(tags) && !tags.has("t")
    && ["quarantine", "reject"].includes(String(tags.get("p") || "").toLowerCase());
  const out = [];
  for (const part of parts) {
    if (/^pct\s*=/i.test(part)) continue;
    out.push(part);
    if (testing && /^p\s*=/i.test(part)) out.push("t=y");
  }
  return out.join("; ");
}

/** A notice for a hosted value that still carries pct, or null. */
export function legacyPctNotice(raw) {
  const tags = dmarcTags(raw);
  if (!tags.has("pct")) return null;
  return {
    pct: tags.get("pct"),
    message: `This record still carries pct=${tags.get("pct")}. RFC 9989 removed pct: receivers that follow it ignore the value and apply the policy as written. CyberMeters removes it on your next policy change.`,
  };
}

// Per-tag before→after diff of two DMARC record values — so a change is shown as
// "p: none→quarantine, t: (none)→y", never a blind overwrite. Returns
// [{ tag, before, after }] for every changed/added/removed tag.
export function dmarcTagDiff(beforeValue, afterValue) {
  const toMap = (v) => {
    const map = {};
    String(v || "").split(";").forEach((part) => {
      const m = part.trim().match(/^([a-z]+)\s*=\s*(.*)$/i);
      if (m) map[m[1].toLowerCase()] = m[2].trim();
    });
    return map;
  };
  const b = toMap(beforeValue), a = toMap(afterValue);
  const changes = [];
  for (const tag of [...new Set([...Object.keys(b), ...Object.keys(a)])]) {
    if ((b[tag] ?? null) !== (a[tag] ?? null)) changes.push({ tag, before: b[tag] ?? null, after: a[tag] ?? null });
  }
  return changes;
}

// Ramp/rollback thresholds, configurable per environment (defaults = the module
// constants). Keeps enforcement gating tunable without a code change.
export function resolveRampThresholds(env = {}) {
  const num = (v, d) => { const n = Number(v); return Number.isFinite(n) ? n : d; };
  return {
    minMessages:         num(env.HOSTED_DMARC_MIN_MESSAGES, RAMP_MIN_MESSAGES),
    minPassRate:         num(env.HOSTED_DMARC_MIN_PASS_RATE, RAMP_MIN_PASS_RATE),
    minDaysSinceChange:  num(env.HOSTED_DMARC_MIN_DAYS, RAMP_MIN_DAYS_SINCE_CHANGE),
    rollbackDropPp:      num(env.HOSTED_DMARC_ROLLBACK_DROP_PP, ROLLBACK_DROP_PP),
    rollbackMinMessages: num(env.HOSTED_DMARC_ROLLBACK_MIN_MESSAGES, ROLLBACK_MIN_MESSAGES),
  };
}

export function buildDmarcPolicyValue(raw, { policy, testing = false, ...rest } = {}) {
  if (!["none", "quarantine", "reject"].includes(policy)) {
    return { ok: false, error: "policy must be none, quarantine, or reject" };
  }
  if (rest.pct != null) return { ok: false, error: "pct was removed by RFC 9989; use a testing step (t=y) instead." };
  const parts = String(raw || "").split(";").map((p) => p.trim()).filter(Boolean);
  if (!/^v\s*=\s*DMARC1$/i.test(parts[0] || "")) {
    return { ok: false, error: "The current value is not a valid DMARC record." };
  }
  // p, sp, t and any legacy pct are rewritten; pct is never written (RFC 9989).
  const kept = parts.filter((p) => !/^(p|sp|pct|t)\s*=/i.test(p));
  const out = [kept[0], `p=${policy}`];
  if (testing === true && policy !== "none") out.push("t=y");
  out.push(...kept.slice(1));
  const value = out.join("; ").slice(0, 4096);
  const parsed = parseDmarcRecord(value, 1);
  if (!parsed.valid) return { ok: false, error: "The rewritten record failed validation." };
  return { ok: true, value };
}

export function evaluateRampReadiness({ pass_rate, total_messages, days_since_change }, overrides = {}) {
  const minMsgs = overrides.minMessages ?? RAMP_MIN_MESSAGES;
  const minRate = overrides.minPassRate ?? RAMP_MIN_PASS_RATE;
  const minDays = overrides.minDaysSinceChange ?? RAMP_MIN_DAYS_SINCE_CHANGE;
  const reasons = [];
  if (total_messages == null || total_messages < minMsgs) {
    reasons.push(`Not enough reporting volume yet (${total_messages ?? 0} of ${minMsgs} messages over 7 days).`);
  }
  if (pass_rate == null || pass_rate < minRate) {
    reasons.push(pass_rate == null
      ? "No DMARC compliance measurement is available yet."
      : `DMARC pass rate is ${pass_rate}% — ${minRate}% or higher is required before tightening.`);
  }
  if (days_since_change != null && days_since_change < minDays) {
    reasons.push(`The last policy change was ${days_since_change} day(s) ago — allow ${minDays} days of reports between steps.`);
  }
  return { ready: reasons.length === 0, reasons };
}

export function shouldAutoRollback({ baseline_pass_rate, current_pass_rate, total_messages }, overrides = {}) {
  const minMsgs = overrides.rollbackMinMessages ?? ROLLBACK_MIN_MESSAGES;
  const dropPp = overrides.rollbackDropPp ?? ROLLBACK_DROP_PP;
  if (baseline_pass_rate == null || current_pass_rate == null) return false;
  if ((total_messages ?? 0) < minMsgs) return false;
  return (baseline_pass_rate - current_pass_rate) >= dropPp;
}

// 7-day DMARC pass rate from externally corroborated aggregate records. DMARC
// passes when either aligned mechanism passes.
//
// PR-5.5 Gate 2 authority contract: no current report source has the additional
// independent corroboration required for destructive/external automation.
// Therefore aggregate reports MUST NOT drive auto-rollback, autopilot
// advancement, or any Cloudflare TXT PATCH. This suspension is deliberately
// separate from the internal-authority contract and fails closed.
export async function getHostedDmarcPassRate(env, workspaceId, domain, { sinceDays = 7 } = {}) {
  try {
    const row = await env.cybermeters_db
      .prepare(`SELECT SUM(r.message_count) AS total,
                       SUM(CASE WHEN dkim_aligned_result = 'pass' OR spf_aligned_result = 'pass'
                                THEN r.message_count ELSE 0 END) AS aligned
                FROM dmarc_aggregate_records r
                JOIN dmarc_aggregate_reports rep
                  ON rep.id = r.report_id
                 AND rep.workspace_id = r.workspace_id
                 AND rep.domain = r.domain
                WHERE r.workspace_id = ? AND r.domain = ?
                  AND ${aggregateReportCompleteSql("rep", "dmarc")}
                  AND r.created_at >= datetime('now', ?)
                  AND ${dmarcExternalAutomationSourceSql("rep")}`)
      .bind(workspaceId, domain, `-${Math.max(1, sinceDays)} days`).first();
    const total = Number(row?.total || 0);
    if (!total) return {
      total: 0,
      pass_rate: null,
      evidence_scope: DMARC_EXTERNAL_AUTOMATION_EVIDENCE_SCOPE,
      inbound_automation_suspended: true,
      external_automation_suspended: true,
      corroboration_required: true,
    };
    return {
      total,
      pass_rate: Math.round((Number(row?.aligned || 0) / total) * 1000) / 10,
      evidence_scope: DMARC_EXTERNAL_AUTOMATION_EVIDENCE_SCOPE,
      inbound_automation_suspended: true,
      external_automation_suspended: true,
      corroboration_required: true,
    };
  } catch {
    return {
      total: 0,
      pass_rate: null,
      evidence_scope: DMARC_EXTERNAL_AUTOMATION_EVIDENCE_SCOPE,
      inbound_automation_suspended: true,
      external_automation_suspended: true,
      corroboration_required: true,
    };
  }
}

async function countHostedPolicyChangesToday(env, recordId) {
  try {
    const row = await env.cybermeters_db
      .prepare(`SELECT COUNT(*) AS n FROM audit_events
                WHERE entity_id = ?
                  AND event_type IN ('hosted_dmarc_policy_changed','hosted_dmarc_rolled_back')
                  AND created_at >= date('now')`)
      .bind(recordId).first();
    return Number(row?.n || 0);
  } catch { return 0; }
}

// H2 (read-back assertion): the PATCH result reports what Cloudflare now
// serves. Callers must compare `served` against their intent — "don't guess,
// verify". When the response omits content, fall back to an authoritative GET.
async function cfPatchHostedTxt(env, cfRecordId, name, content, { fetchImpl = fetch } = {}) {
  const zoneId = String(env?.CLOUDFLARE_ZONE_ID || "").trim();
  if (!cfRecordId || !String(env?.CLOUDFLARE_API_TOKEN || "").trim() || !/^[a-f0-9]{32}$/i.test(zoneId)) {
    return { ok: false, reason: "missing_config" };
  }
  const res = await _cloudflareEmailRoutingRequest(
    env, `/zones/${zoneId}/dns_records/${encodeURIComponent(cfRecordId)}`,
    { method: "PATCH", body: JSON.stringify({ type: "TXT", name, content, ttl: 300 }) },
    fetchImpl,
  );
  if (!res.ok) return res;
  let served = res.body?.result?.content != null ? String(res.body.result.content) : null;
  if (served == null) {
    const read = await cfGetHostedTxt(env, name, { fetchImpl });
    served = read.ok ? read.content : null;
  }
  return { ok: true, served };
}

// Authoritative read of the hosted TXT straight from the Cloudflare API — the
// reconciler's source of truth. Public DNS caches (TTL 300s) would lie to us
// right after a change; the zone API cannot.
async function cfGetHostedTxt(env, name, { fetchImpl = fetch } = {}) {
  const zoneId = String(env?.CLOUDFLARE_ZONE_ID || "").trim();
  if (!String(env?.CLOUDFLARE_API_TOKEN || "").trim() || !/^[a-f0-9]{32}$/i.test(zoneId)) {
    return { ok: false, reason: "missing_config" };
  }
  const res = await _cloudflareEmailRoutingRequest(
    env, `/zones/${zoneId}/dns_records?type=TXT&name=${encodeURIComponent(name)}&per_page=5`,
    {}, fetchImpl,
  );
  if (!res.ok) return res;
  const first = Array.isArray(res.body?.result) ? res.body.result[0] : null;
  return { ok: true, content: first?.content != null ? String(first.content) : null, cf_record_id: first?.id || null };
}

const _normTxt = (v) => String(v ?? "").replace(/\s+/g, " ").trim();

// Shared apply path for manual (route) and autopilot changes — a write-ahead
// saga (H1): Prepare (intent to D1, BEFORE any side effect) → Execute (the
// Cloudflare PATCH) → Verify (read back what Cloudflare serves and assert it
// equals the intent) → Commit (one atomic swap). A crash at any point leaves
// either the old state or a recorded intent for the sweep reconciler — never
// a silent divergence between DNS and D1.
export async function applyHostedDmarcChange(env, row, {
  policy, testing = false, userId = null, source = "manual",
  passRateNow = null, fetchImpl = fetch, ...rest
} = {}) {
  // RFC 9989 removed pct: a caller still asking for one is refused, not ignored.
  if (rest.pct != null) return { ok: false, reason: "invalid_target", error: "pct was removed by RFC 9989." };
  if (!row?.cf_record_id) return { ok: false, reason: "not_published" };
  if (row.pending_value) return { ok: false, reason: "change_in_progress" };
  const built = buildDmarcPolicyValue(row.current_value, { policy, testing });
  if (!built.ok) return { ok: false, reason: "invalid_target", error: built.error };
  if (_normTxt(built.value) === _normTxt(row.current_value)) {
    return { ok: false, reason: "no_change" };
  }
  const changesToday = await countHostedPolicyChangesToday(env, row.id);
  if (changesToday >= HOSTED_POLICY_DAILY_BUDGET) {
    return { ok: false, reason: "change_budget_exceeded" };
  }

  const nowIso = new Date().toISOString();
  // PREPARE — write the intent before touching DNS.
  await env.cybermeters_db
    .prepare(`UPDATE hosted_dns_entries SET pending_value = ?, pending_since = ? WHERE id = ?`)
    .bind(built.value, nowIso, row.id).run();

  // EXECUTE — the only side effect.
  const patched = await cfPatchHostedTxt(env, row.cf_record_id, row.hosted_name, built.value, { fetchImpl });
  if (!patched.ok) {
    // Abort the intent: DNS untouched, old state is the safe state.
    await env.cybermeters_db
      .prepare(`UPDATE hosted_dns_entries SET pending_value = NULL, pending_since = NULL WHERE id = ?`)
      .bind(row.id).run();
    return { ok: false, reason: patched.reason || "api_rejected" };
  }

  // VERIFY — assert Cloudflare now serves exactly the intent. On mismatch the
  // intent stays recorded so the reconciler can settle it authoritatively.
  if (_normTxt(patched.served) !== _normTxt(built.value)) {
    return { ok: false, reason: "verify_mismatch" };
  }

  // COMMIT — one atomic swap; previous_value becomes the true safe state.
  // (SQLite evaluates right-hand sides against the OLD row, so this single
  // statement performs the whole swap.)
  await env.cybermeters_db
    .prepare(`UPDATE hosted_dns_entries
              SET previous_value = target_value, target_value = pending_value,
                  pending_value = NULL, pending_since = NULL,
                  last_change_at = ?, pass_rate_at_change = ?,
                  failure_count = 0, last_error = NULL, updated_at = ?
              WHERE id = ?`)
    .bind(nowIso, passRateNow, nowIso, row.id).run();
  await createAuditEvent(env, {
    workspace_id: row.workspace_id, user_id: userId,
    event_type: "hosted_dmarc_policy_changed", entity_type: "hosted_dns_record", entity_id: row.id,
    description: `Hosted DMARC policy for ${row.domain} set to p=${policy}${testing && policy !== "none" ? " t=y" : ""} (${source})`,
    metadata: { from: row.current_value, to: built.value, source },
  });
  // PR-B3: non-alertable by founder decision. A policy change is a confirmation
  // of an action (the customer's, or autopilot's on their standing instruction),
  // not a risk condition. It stays in history — and is structurally unable to
  // alert, because its event_type is not `monitoring_changed`.
  await recordHostedTransition(env, row, {
    event_type: EMAIL_EVENT_HOSTED_POLICY_CHANGED,
    actor_type: userId ? "customer" : "system", actor_id: userId,
    reason: `policy_${source}`,
    detail: { from: row.current_value, to: built.value, policy, testing: testing === true, source },
  }).catch(() => {});
  return { ok: true, value: built.value };
}

// Rollback: restore previous_value verbatim (never rebuild it), then clear
// previous_value so a second rollback cannot ping-pong. Same write-ahead saga
// as apply (H1): Prepare → Execute → Verify → Commit.
export async function rollbackHostedDmarc(env, row, { userId = null, source = "manual", fetchImpl = fetch } = {}) {
  if (!row?.previous_value) return { ok: false, reason: "nothing_to_roll_back" };
  if (!row.cf_record_id) return { ok: false, reason: "not_published" };
  if (row.pending_value) return { ok: false, reason: "change_in_progress" };
  // Never restore pct (removed by RFC 9989): the previous value is rewritten
  // without it, keeping its policy intent (a pct below 100 becomes t=y).
  const restore = withoutLegacyPct(row.previous_value);

  const nowIso = new Date().toISOString();
  // PREPARE
  await env.cybermeters_db
    .prepare(`UPDATE hosted_dns_entries SET pending_value = ?, pending_since = ? WHERE id = ?`)
    .bind(restore, nowIso, row.id).run();

  // EXECUTE
  const patched = await cfPatchHostedTxt(env, row.cf_record_id, row.hosted_name, restore, { fetchImpl });
  if (!patched.ok) {
    await env.cybermeters_db
      .prepare(`UPDATE hosted_dns_entries SET pending_value = NULL, pending_since = NULL WHERE id = ?`)
      .bind(row.id).run();
    return { ok: false, reason: patched.reason || "api_rejected" };
  }

  // VERIFY — intent stays recorded on mismatch for the reconciler.
  if (_normTxt(patched.served) !== _normTxt(restore)) {
    return { ok: false, reason: "verify_mismatch" };
  }

  // COMMIT
  await env.cybermeters_db
    .prepare(`UPDATE hosted_dns_entries
              SET target_value = pending_value, previous_value = NULL,
                  pending_value = NULL, pending_since = NULL,
                  last_change_at = ?, pass_rate_at_change = NULL,
                  failure_count = 0, last_error = NULL, updated_at = ?
              WHERE id = ?`)
    .bind(nowIso, nowIso, row.id).run();
  await createAuditEvent(env, {
    workspace_id: row.workspace_id, user_id: userId,
    event_type: "hosted_dmarc_rolled_back", entity_type: "hosted_dns_record", entity_id: row.id,
    description: `Hosted DMARC for ${row.domain} rolled back (${source})`,
    metadata: { restored: restore, source },
  });
  // PR-B3. The legacy path graded this inline (`source === "auto" ? "high" :
  // "medium"`) and alerted on both. The two halves are different facts and are
  // now split, so severity stays an ASSERTED lookup rather than a computed one:
  //
  //   auto   — CyberMeters intervened without being asked because compliance
  //            dropped. The customer did not do this and needs to know: actionable.
  //   manual — the customer rolled their own policy back. Alerting them about
  //            their own action is not a risk alert (founder decision), so it is
  //            history only.
  //
  // The COMMIT above nulls previous_value, so a second rollback returns
  // `nothing_to_roll_back` — the write itself is the transition guard and this
  // cannot fire twice for one rollback.
  if (source === "auto") {
    await recordHostedTransition(env, row, {
      recurrence: "hosted_rolled_back_auto",
      band: nowIso, reason: "compliance_dropped_after_policy_change",
      detail: { restored: restore, source },
    }).catch(() => {});
  } else {
    await recordHostedTransition(env, row, {
      event_type: EMAIL_EVENT_HOSTED_ROLLED_BACK_MANUAL,
      actor_type: userId ? "customer" : "system", actor_id: userId,
      reason: "customer_rolled_back",
      detail: { restored: restore, source },
    }).catch(() => {});
  }
  return { ok: true, value: restore };
}

// Reconciler (H1): settles a stranded write-ahead intent using the Cloudflare
// API as the source of truth (public DNS caches would lie for up to TTL).
//   - CF serves the intent      → COMMIT (finish what the crashed saga started)
//   - CF serves the old value   → ABORT once the grace window passes
//   - CF serves something else  → ABORT after grace + flag temporary_issue
// A fresh in-flight intent (inside grace) is left alone.
const HOSTED_INTENT_GRACE_MS = 30 * 60 * 1000;

export async function reconcileHostedIntent(env, row, { fetchImpl = fetch, now = new Date() } = {}) {
  if (!row?.pending_value) return { action: "none" };
  const nowIso = now.toISOString();
  const read = await cfGetHostedTxt(env, row.hosted_name, { fetchImpl });
  if (!read.ok) return { action: "deferred" }; // CF unreachable — try next sweep

  if (_normTxt(read.content) === _normTxt(row.pending_value)) {
    // DNS already serves the intent: commit exactly like a completed saga.
    await env.cybermeters_db
      .prepare(`UPDATE hosted_dns_entries
                SET previous_value = target_value, target_value = pending_value,
                    pending_value = NULL, pending_since = NULL,
                    last_change_at = ?, failure_count = 0, last_error = NULL, updated_at = ?
                WHERE id = ?`)
      .bind(nowIso, nowIso, row.id).run();
    await createAuditEvent(env, {
      workspace_id: row.workspace_id,
      event_type: "hosted_dmarc_policy_changed", entity_type: "hosted_dns_record", entity_id: row.id,
      description: `Hosted DMARC change for ${row.domain} reconciled after interruption`,
      metadata: { from: row.current_value, to: row.pending_value, source: "reconciled" },
    });
    return { action: "committed" };
  }

  const sinceMs = parseServerMsHosted(row.pending_since);
  const graceOver = sinceMs == null || (now.getTime() - sinceMs) > HOSTED_INTENT_GRACE_MS;
  if (!graceOver) return { action: "in_flight" };

  const revertedToOld = _normTxt(read.content) === _normTxt(row.current_value);
  await env.cybermeters_db
    .prepare(`UPDATE hosted_dns_entries
              SET pending_value = NULL, pending_since = NULL,
                  last_error = ?, updated_at = ?
              WHERE id = ?`)
    .bind(revertedToOld ? null : "temporary_issue", nowIso, row.id).run();
  await createAuditEvent(env, {
    workspace_id: row.workspace_id,
    event_type: "hosted_dmarc_change_aborted", entity_type: "hosted_dns_record", entity_id: row.id,
    description: `A stranded hosted DMARC change for ${row.domain} was aborted; the previous value remains in force`,
    metadata: { abandoned_intent: row.pending_value, dns_serves: read.content, source: "reconciler" },
  });
  return { action: "aborted" };
}

export function planAllowsHostedPolicyManagement(plan) {
  return normalizePlan(plan) !== "free";
}

export function parseServerMsHosted(value) {
  const s = String(value || "");
  const ms = new Date(s.includes("T") ? s : s.replace(" ", "T") + "Z").getTime();
  return Number.isFinite(ms) ? ms : null;
}

// ═══ Remediation Registry — plug-and-play auto-fix modules ══════════════════
// Redshift-class tools say "X is missing" and stop. Each entry here turns one
// gap into a self-contained module: detect (applicable? present?), generate
// (the exact record to publish), verify (is it live now?), and — for 'hosted'
// actions — apply (we execute it via the sealed Hosted Records Engine). Adding
// a new standard (a new RFC) is one descriptor + one line in the array; the
// dispatcher, Saga, CF error handling and verification are all shared. That
// one-file agility is what a monolithic competitor cannot copy.

async function _remediationTxtLookup(name, { dnsQueryImpl = dnsQuery } = {}) {
  try {
    const res = await dnsQueryImpl(name, "TXT");
    if (Number(res?.Status ?? 1) !== 0) return [];
    return (res?.Answer || []).map((a) => normalizeDnsTxtValue(a?.data)).filter(Boolean);
  } catch { return []; }
}

const dmarcRemediation = {
  id: "dmarc", title: "DMARC policy", category: "email", capability: "hosted",
  // DMARC has a dedicated managed flow (the Hosted Records Engine + Self-Driving
  // ramp). The registry lists it and points at that flow rather than duplicating
  // the create/Saga logic here.
  managed_via: "hosted-dmarc",
  async detect(ctx) {
    const records = await _remediationTxtLookup(`_dmarc.${ctx.domain}`, ctx);
    const rec = records.find((r) => /^v=DMARC1(?:\s*;|$)/i.test(r)) || null;
    const detail = rec ? parseDmarcRecord(rec, records.length) : null;
    return {
      applicable: true,
      present: Boolean(detail?.valid),
      ok: Boolean(detail?.valid) && ["quarantine", "reject"].includes(detail?.policy),
      evidence: { policy: detail?.policy ?? null, record: rec },
    };
  },
  generate(ctx) {
    return { records: [{ type: "TXT", name: `_dmarc.${ctx.domain}`, value: "v=DMARC1; p=none; rua=mailto:<your CyberMeters address>" }],
      note: "Use the managed DMARC card to have CyberMeters host and self-drive this record." };
  },
  async verify(ctx) { return (await this.detect(ctx)).ok; },
};

const tlsRptRemediation = {
  id: "tls_rpt", title: "TLS reporting (TLS-RPT)", category: "email", capability: "guided",
  async detect(ctx) {
    const records = await _remediationTxtLookup(`_smtp._tls.${ctx.domain}`, ctx);
    const present = records.some((r) => /^v=TLSRPTv1\b/i.test(r));
    return { applicable: true, present, ok: present, evidence: { record: records[0] || null } };
  },
  generate(ctx) {
    const rua = ctx.rua_email || `tls-reports@${ctx.domain}`;
    return {
      records: [{ type: "TXT", name: `_smtp._tls.${ctx.domain}`, value: `v=TLSRPTv1; rua=mailto:${rua}` }],
      note: "TLS-RPT gives you visibility into SMTP TLS delivery failures. Point rua at a mailbox you monitor.",
    };
  },
  async verify(ctx) { return (await this.detect(ctx)).ok; },
};

const mtaStsRemediation = {
  id: "mta_sts", title: "MTA-STS (enforce TLS for inbound mail)", category: "email", capability: "hosted",
  managed_via: "hosted-mta-sts",
  async detect(ctx) {
    let enabled = false;
    try { enabled = Boolean((await fetchMtaSts(ctx.domain))?.enabled); } catch { enabled = false; }
    const txt = await _remediationTxtLookup(`_mta-sts.${ctx.domain}`, ctx);
    const hasTxt = txt.some((r) => /^v=STSv1\b/i.test(r));
    return { applicable: true, present: enabled && hasTxt, ok: enabled && hasTxt,
      evidence: { policy_served: enabled, txt_present: hasTxt } };
  },
  generate(ctx) {
    const id = `${Math.floor(Date.now() / 1000)}`;
    const mx = Array.isArray(ctx.mx_hosts) && ctx.mx_hosts.length
      ? ctx.mx_hosts : [`*.${ctx.domain}`];
    const policyFile = buildMtaStsPolicy(ctx.domain, mx);
    return {
      records: [{ type: "TXT", name: `_mta-sts.${ctx.domain}`, value: buildMtaStsTxtValue(id) }],
      files: [{ path: `https://mta-sts.${ctx.domain}/.well-known/mta-sts.txt`, content: policyFile }],
      note: "MTA-STS needs BOTH the TXT record and the policy file served over HTTPS on mta-sts.<domain>. Start in mode: testing, then move to enforce once reports are clean.",
    };
  },
  async verify(ctx) { return (await this.detect(ctx)).ok; },
};

const bimiRemediation = {
  id: "bimi", title: "BIMI (brand logo in inbox)", category: "email", capability: "guided",
  async detect(ctx) {
    const dmarc = await dmarcRemediation.detect(ctx);
    const records = await _remediationTxtLookup(`default._bimi.${ctx.domain}`, ctx);
    const present = records.some((r) => /^v=BIMI1\b/i.test(r));
    // BIMI only takes effect under enforced DMARC — surface that dependency.
    return { applicable: dmarc.ok, present, ok: dmarc.ok && present,
      evidence: { requires_enforced_dmarc: true, dmarc_ok: dmarc.ok, record: records[0] || null } };
  },
  generate(ctx) {
    const logo = ctx.logo_url || `https://${ctx.domain}/bimi/logo.svg`;
    const vmc = ctx.vmc_url ? ` a=${ctx.vmc_url}` : "";
    return {
      records: [{ type: "TXT", name: `default._bimi.${ctx.domain}`, value: `v=BIMI1; l=${logo};${vmc}` }],
      note: "BIMI requires enforced DMARC (p=quarantine or reject), an SVG Tiny PS logo, and — for Gmail/Apple display — a VMC certificate issued to your brand.",
    };
  },
  async verify(ctx) { return (await this.detect(ctx)).ok; },
};

const caaRemediation = {
  id: "caa", title: "CAA (restrict who can issue your certs)", category: "dns", capability: "guided",
  async detect(ctx) {
    let present = false;
    try {
      const res = await (ctx.dnsQueryImpl || dnsQuery)(ctx.domain, "CAA");
      present = Number(res?.Status ?? 1) === 0 && (res?.Answer || []).length > 0;
    } catch { present = false; }
    return { applicable: true, present, ok: present, evidence: {} };
  },
  generate(ctx) {
    const ca = ctx.ca || "letsencrypt.org";
    return {
      records: [
        { type: "CAA", name: ctx.domain, value: `0 issue "${ca}"` },
        { type: "CAA", name: ctx.domain, value: `0 iodef "mailto:security@${ctx.domain}"` },
      ],
      note: "CAA restricts which certificate authorities may issue for your domain. Set it at the zone apex; list every CA you actually use.",
    };
  },
  async verify(ctx) { return (await this.detect(ctx)).ok; },
};

export const REMEDIATION_REGISTRY = [
  dmarcRemediation, tlsRptRemediation, mtaStsRemediation, bimiRemediation, caaRemediation,
];
export function getRemediation(id) {
  return REMEDIATION_REGISTRY.find((a) => a.id === String(id)) || null;
}
// Serialize a descriptor + its live detection for the API. Never leaks internal
// closures — only the declared, customer-safe fields.
export function remediationToApi(action, detection = null) {
  return {
    id: action.id, title: action.title, category: action.category,
    capability: action.capability,
    managed_via: action.managed_via || null,
    ...(detection ? {
      applicable: detection.applicable, present: detection.present, ok: detection.ok,
      evidence: detection.evidence || {},
    } : {}),
  };
}

// ─── SPF chain analysis ("SPF surgeon") ──────────────────────────────────────
// Live, read-only recursive walk of an SPF record's include:/redirect= tree.
// Counts RFC 7208 DNS-lookup mechanisms (include, a, mx, ptr, exists, redirect)
// against the 10-lookup limit, surfaces void includes and loops, and produces a
// flattened-record suggestion. dnsQueryImpl is injectable for tests (house
// pattern: verifyDmarcDnsSetup); total DNS queries are hard-capped so a deep or
// malicious chain cannot exhaust Worker subrequests.
const SPF_LOOKUP_MECHANISMS = ["include", "a", "mx", "ptr", "exists", "redirect"];

export async function analyzeSpfChain(domain, {
  dnsQueryImpl = dnsQuery,
  maxQueries = 15,
  maxDepth = 5,
  checkedAt = new Date().toISOString(),
} = {}) {
  const state = { queries: 0, truncated: false };
  const warnings = [];
  const tree = [];
  const ip4 = new Set();
  const ip6 = new Set();
  const visited = new Set();
  let lookups = 0;

  const fetchSpf = async (host) => {
    if (state.queries >= maxQueries) { state.truncated = true; return { records: [], status: "capped" }; }
    state.queries += 1;
    let res;
    try { res = await dnsQueryImpl(host, "TXT"); }
    catch { return { records: [], status: "lookup_failed" }; }
    const dnsStatus = Number(res?.Status ?? 0);
    if (dnsStatus !== 0 && dnsStatus !== 3) return { records: [], status: "lookup_failed" };
    const records = (res?.Answer || [])
      .map((a) => normalizeDnsTxtValue(a?.data).replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 4096))
      .filter((v) => /^v=spf1(\s|$)/i.test(v));
    return { records, status: "ok" };
  };

  const walk = async (host, depth, via) => {
    const key = String(host || "").toLowerCase().replace(/\.$/, "");
    if (!key) return;
    if (visited.has(key)) {
      warnings.push(`The SPF chain references ${key} more than once (possible loop).`);
      return;
    }
    visited.add(key);
    const { records, status } = await fetchSpf(key);
    const record = records[0] || null;
    const node = { domain: key, depth, via, status, record, lookups_here: 0 };
    tree.push(node);
    if (!record) {
      if (status === "ok" && depth > 0) {
        warnings.push(`${via} points at ${key}, which publishes no SPF record (void lookup — permerror risk).`);
      }
      return;
    }
    if (records.length > 1) {
      warnings.push(`${key} publishes multiple SPF records; SPF requires exactly one.`);
    }
    const detail = parseSpfRecord(record, records.length);
    for (const m of detail.mechanisms) {
      if (SPF_LOOKUP_MECHANISMS.includes(m.mechanism)) {
        lookups += 1;
        node.lookups_here += 1;
      }
      if (m.mechanism === "ip4" && m.value) ip4.add(m.value);
      if (m.mechanism === "ip6" && m.value) ip6.add(m.value);
      if ((m.mechanism === "include" || m.mechanism === "redirect") && m.value) {
        if (depth >= maxDepth) {
          state.truncated = true;
          warnings.push(`The SPF chain nests deeper than ${maxDepth} levels below ${key}; analysis stopped there.`);
        } else {
          await walk(m.value, depth + 1, `${m.mechanism}:${key}`);
        }
      }
    }
  };

  await walk(domain, 0, null);

  const root = tree[0] || null;
  const rootDetail = root?.record ? parseSpfRecord(root.record, 1) : null;
  const allToken = rootDetail?.mechanisms?.find((m) => m.mechanism === "all")?.raw || "~all";
  const flatIp4 = [...ip4];
  const flatIp6 = [...ip6];
  const suggested = root?.record
    ? `v=spf1${flatIp4.map((v) => ` ip4:${v}`).join("")}${flatIp6.map((v) => ` ip6:${v}`).join("")} ${allToken}`
    : null;
  if (suggested && suggested.length > 450) {
    warnings.push("The flattened record is very long; DNS TXT values above 255 characters must be split into multiple strings, and long allow-lists drift quickly — re-verify after provider changes.");
  }
  if (state.truncated) {
    warnings.push("Not every branch could be resolved within the analysis budget; counts are a lower bound.");
  }

  return {
    domain: String(domain || "").toLowerCase(),
    checked_at: checkedAt,
    status: !root || root.status !== "ok"
      ? "dns_lookup_failed"
      : (root.record ? "ok" : "no_spf"),
    record: root?.record || null,
    lookups_used: lookups,
    lookup_limit: 10,
    over_limit: lookups > 10,
    truncated: state.truncated,
    queries_used: state.queries,
    warnings: warnings.slice(0, 20),
    tree: tree.slice(0, 30),
    flattened: root?.record
      ? { ip4: flatIp4.slice(0, 100), ip6: flatIp6.slice(0, 100), suggested_record: suggested }
      : null,
  };
}
