// ── Hosted DMARC records engine + remediation ──
// Managed DMARC record lifecycle: DNS verification, Cloudflare-hosted TXT record CRUD +
// verification sweep, DMARC policy ramp/auto-rollback engine, hosted-intent reconciliation +
// plan gating, the remediation registry (DMARC/TLS-RPT/MTA-STS/BIMI/CAA), and SPF chain
// analysis. Extracted verbatim from index.js (monolith decomposition, Phase 1c). Ramp
// thresholds, CF patch/get helpers, remediation builders and normalizeDmarcRuaForComparison
// are module-internal.
import { RUA_INBOUND_DOMAIN_DEFAULT, normalizeInboundRecipientDomain } from "../lib/dmarc-ingest.js";
import { createAuditEvent } from "../lib/events.js";
import { deliverWorkspaceAlert } from "./alerts.js";
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
// enforcement or mutates DNS.
export function buildDmarcDnsRecommendedValue(record, recommendedRua) {
  const raw = normalizeDnsTxtValue(record);
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
    policy_step: step ? { index: stepIdx, policy: step.policy, pct: step.pct, label: step.label } : null,
    next_step: nextStep ? { index: stepIdx + 1, policy: nextStep.policy, pct: nextStep.pct, label: nextStep.label } : null,
    autopilot: isDmarc && Number(row.autopilot) === 1,
    can_rollback: isDmarc && Boolean(row.previous_value),
    change_pending: Boolean(row.pending_value),
    // Per-tag diffs (transparency — the customer sees exactly what changes, never
    // a blind overwrite). pending_diff = current→in-flight; next_step_diff =
    // what advancing one ramp step would change.
    pending_diff: isDmarc && row.pending_value ? dmarcTagDiff(row.current_value, row.pending_value) : null,
    next_step_diff: isDmarc && nextStep
      ? dmarcTagDiff(row.current_value, buildDmarcPolicyValue(row.current_value, { policy: nextStep.policy, pct: nextStep.pct }))
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
        if (next === "disconnected" && row.status === "connected") {
          try {
            await deliverWorkspaceAlert(env, row.workspace_id, {
              kind: "hosted_dmarc_disconnected", severity: "high",
              title: `Hosted DMARC disconnected for ${row.domain}`,
              summary: `The CNAME at _dmarc.${row.domain} no longer points at CyberMeters, so your DMARC policy may not be published. Restore the CNAME or review your DNS.`,
              domain: row.domain,
            });
          } catch { /* alerting is best-effort */ }
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
        const rate = await getHostedDmarcPassRate(env, row.workspace_id, row.domain);
        let impactAssessment = null;
        if (row.last_change_at) {
          try {
            const comparison = await comparePolicyImpact(env, row.workspace_id, row.domain, { changeAt: row.last_change_at, now });
            impactAssessment = assessImpactRollback(comparison);
            if (impactAssessment.rollbackRecommended) {
              const recent = await env.cybermeters_db
                .prepare(`SELECT id FROM audit_events
                          WHERE workspace_id = ? AND entity_id = ?
                            AND event_type = 'hosted_dmarc_impact_regression'
                            AND created_at >= datetime('now', '-1 day')
                          LIMIT 1`)
                .bind(row.workspace_id, row.id).first();
              if (!recent) {
                await createAuditEvent(env, {
                  workspace_id: row.workspace_id,
                  event_type: "hosted_dmarc_impact_regression", entity_type: "hosted_dns_record", entity_id: row.id,
                  description: `Hosted DMARC impact monitor recommends review for ${row.domain}`,
                  metadata: { domain: row.domain, assessment: impactAssessment },
                });
                try {
                  await deliverWorkspaceAlert(env, row.workspace_id, {
                    kind: "hosted_dmarc_impact_regression", severity: impactAssessment.severity || "medium",
                    title: `DMARC impact review recommended for ${row.domain}`,
                    summary: impactAssessment.triggers?.[0] || "Legitimate mail failures increased after a managed DMARC policy change.",
                    domain: row.domain,
                  });
                } catch { /* alerting is best-effort */ }
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
          const stepIdx = dmarcRampStepIndex(row.current_value);
          const nextStep = stepIdx >= 0 ? DMARC_RAMP_LADDER[stepIdx + 1] : null;
          if (nextStep) {
            const daysSince = changeMs != null
              ? Math.floor((now.getTime() - changeMs) / 86400000) : null;
            const readiness = evaluateRampReadiness({
              pass_rate: rate.pass_rate, total_messages: rate.total,
              days_since_change: daysSince,
            }, resolveRampThresholds(env));
            if (readiness.ready) {
              await applyHostedDmarcChange(env, row, {
                policy: nextStep.policy, pct: nextStep.pct,
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
// advance p=none → quarantine (pct 5→25→50→100) → reject only while measured
// compliance stays healthy, and automatically roll back to previous_value if
// compliance drops materially after a change. Competitors host OR measure —
// closing the loop needs both sides.

export const DMARC_RAMP_LADDER = [
  { policy: "none",       pct: 100, label: "Monitor only" },
  { policy: "quarantine", pct: 5,   label: "Quarantine 5%" },
  { policy: "quarantine", pct: 25,  label: "Quarantine 25%" },
  { policy: "quarantine", pct: 50,  label: "Quarantine 50%" },
  { policy: "quarantine", pct: 100, label: "Quarantine" },
  // Graduated reject soak — the riskiest transition (quarantine→reject) must not
  // jump straight to 100%. Percentage-ramp reject so a misclassified legitimate
  // sender surfaces on a small slice before full enforcement.
  { policy: "reject",     pct: 10,  label: "Reject 10%" },
  { policy: "reject",     pct: 25,  label: "Reject 25%" },
  { policy: "reject",     pct: 50,  label: "Reject 50%" },
  { policy: "reject",     pct: 100, label: "Reject" },
];
// Index of the first reject step (used by step-snapping below).
const DMARC_RAMP_FIRST_REJECT = 5;
const DMARC_RAMP_LAST_QUAR = 4;
const HOSTED_POLICY_DAILY_BUDGET = 10;   // manual + automatic changes per record per UTC day
const RAMP_MIN_MESSAGES = 50;            // minimum 7-day volume for a confident read
const RAMP_MIN_PASS_RATE = 97;           // % DMARC pass required to advance
const RAMP_MIN_DAYS_SINCE_CHANGE = 3;    // soak time between autopilot steps
const ROLLBACK_DROP_PP = 5;              // pass-rate drop (percentage points) that triggers rollback
const ROLLBACK_MIN_MESSAGES = 20;        // minimum volume before a drop is trusted
const HOSTED_CHANGE_PROPAGATION_MS = 15 * 60 * 1000; // verify grace after a value change

export function dmarcRampStepIndex(raw) {
  const d = parseDmarcRecord(raw, 1);
  if (!d.valid) return -1;
  const idx = DMARC_RAMP_LADDER.findIndex((s) => s.policy === d.policy
    && (d.policy === "none" || s.pct === d.percentage));
  if (idx >= 0) return idx;
  // Off-ladder but valid (e.g. quarantine pct=60): snap to the nearest step
  // at or below, so "next step" is always meaningful.
  if (d.policy === "reject") {
    for (let i = DMARC_RAMP_LADDER.length - 1; i >= DMARC_RAMP_FIRST_REJECT; i -= 1) {
      if (d.percentage >= DMARC_RAMP_LADDER[i].pct) return i;
    }
    return DMARC_RAMP_FIRST_REJECT;
  }
  if (d.policy === "quarantine") {
    for (let i = DMARC_RAMP_LAST_QUAR; i >= 1; i -= 1) {
      if (d.percentage >= DMARC_RAMP_LADDER[i].pct) return i;
    }
    return 1;
  }
  return 0;
}

// Token-preserving policy rewrite: only p=, sp= and pct= change; every other
// tag (rua, ruf, adkim, aspf, fo, ri, …) is kept byte-for-byte. pct=100 is
// omitted (the RFC default) to keep records tidy.
// Per-tag before→after diff of two DMARC record values — so a change is shown as
// "p: none→quarantine, pct: 100→5", never a blind overwrite. Returns
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

export function buildDmarcPolicyValue(raw, { policy, pct = 100 } = {}) {
  if (!["none", "quarantine", "reject"].includes(policy)) {
    return { ok: false, error: "policy must be none, quarantine, or reject" };
  }
  const pctNum = Number(pct);
  if (!Number.isInteger(pctNum) || pctNum < 1 || pctNum > 100) {
    return { ok: false, error: "pct must be an integer from 1 to 100" };
  }
  const parts = String(raw || "").split(";").map((p) => p.trim()).filter(Boolean);
  if (!/^v\s*=\s*DMARC1$/i.test(parts[0] || "")) {
    return { ok: false, error: "The current value is not a valid DMARC record." };
  }
  const kept = parts.filter((p) => !/^(p|sp|pct)\s*=/i.test(p));
  const out = [kept[0], `p=${policy}`];
  if (pctNum < 100) out.push(`pct=${pctNum}`);
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

// 7-day DMARC pass rate from ingested aggregate records. DMARC passes when
// either aligned mechanism passes.
export async function getHostedDmarcPassRate(env, workspaceId, domain, { sinceDays = 7 } = {}) {
  try {
    const row = await env.cybermeters_db
      .prepare(`SELECT SUM(message_count) AS total,
                       SUM(CASE WHEN dkim_aligned_result = 'pass' OR spf_aligned_result = 'pass'
                                THEN message_count ELSE 0 END) AS aligned
                FROM dmarc_aggregate_records
                WHERE workspace_id = ? AND domain = ? AND created_at >= datetime('now', ?)`)
      .bind(workspaceId, domain, `-${Math.max(1, sinceDays)} days`).first();
    const total = Number(row?.total || 0);
    if (!total) return { total: 0, pass_rate: null };
    return { total, pass_rate: Math.round((Number(row?.aligned || 0) / total) * 1000) / 10 };
  } catch { return { total: 0, pass_rate: null }; }
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
  policy, pct = 100, userId = null, source = "manual",
  passRateNow = null, fetchImpl = fetch,
} = {}) {
  if (!row?.cf_record_id) return { ok: false, reason: "not_published" };
  if (row.pending_value) return { ok: false, reason: "change_in_progress" };
  const built = buildDmarcPolicyValue(row.current_value, { policy, pct });
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
    description: `Hosted DMARC policy for ${row.domain} set to p=${policy}${pct < 100 ? ` pct=${pct}` : ""} (${source})`,
    metadata: { from: row.current_value, to: built.value, source },
  });
  try {
    await deliverWorkspaceAlert(env, row.workspace_id, {
      kind: "hosted_dmarc_policy_changed", severity: "info",
      title: `DMARC policy updated for ${row.domain}`,
      summary: `The managed DMARC policy moved to p=${policy}${pct < 100 ? ` (pct=${pct})` : ""}${source === "autopilot" ? " — advanced automatically because compliance stayed healthy." : "."}`,
      domain: row.domain,
    });
  } catch { /* best-effort */ }
  return { ok: true, value: built.value };
}

// Rollback: restore previous_value verbatim (never rebuild it), then clear
// previous_value so a second rollback cannot ping-pong. Same write-ahead saga
// as apply (H1): Prepare → Execute → Verify → Commit.
export async function rollbackHostedDmarc(env, row, { userId = null, source = "manual", fetchImpl = fetch } = {}) {
  if (!row?.previous_value) return { ok: false, reason: "nothing_to_roll_back" };
  if (!row.cf_record_id) return { ok: false, reason: "not_published" };
  if (row.pending_value) return { ok: false, reason: "change_in_progress" };

  const nowIso = new Date().toISOString();
  // PREPARE
  await env.cybermeters_db
    .prepare(`UPDATE hosted_dns_entries SET pending_value = ?, pending_since = ? WHERE id = ?`)
    .bind(row.previous_value, nowIso, row.id).run();

  // EXECUTE
  const patched = await cfPatchHostedTxt(env, row.cf_record_id, row.hosted_name, row.previous_value, { fetchImpl });
  if (!patched.ok) {
    await env.cybermeters_db
      .prepare(`UPDATE hosted_dns_entries SET pending_value = NULL, pending_since = NULL WHERE id = ?`)
      .bind(row.id).run();
    return { ok: false, reason: patched.reason || "api_rejected" };
  }

  // VERIFY — intent stays recorded on mismatch for the reconciler.
  if (_normTxt(patched.served) !== _normTxt(row.previous_value)) {
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
    metadata: { restored: row.previous_value, source },
  });
  try {
    await deliverWorkspaceAlert(env, row.workspace_id, {
      kind: "hosted_dmarc_rolled_back", severity: source === "auto" ? "high" : "medium",
      title: `DMARC policy rolled back for ${row.domain}`,
      summary: source === "auto"
        ? `Compliance dropped after the last policy change, so the previous policy was restored automatically. Review your sender inventory before tightening again.`
        : `The managed DMARC policy was rolled back to its previous value.`,
      domain: row.domain,
    });
  } catch { /* best-effort */ }
  return { ok: true, value: row.previous_value };
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
