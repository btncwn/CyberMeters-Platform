// ── DMARC report ingestion service ───────────────────────────────────────────
// The source-agnostic ingest pipeline (XML parse → identity → dedupe on the
// report natural key → persist → sender intel), shared by the HTTP import
// route and the inbound email worker path.
import { createId } from "./util.js";
import { createAuditEvent } from "./events.js";
import {
  DMARC_AUTHORITY_ELIGIBLE_SOURCES,
  isDmarcAuthorityEligibleSource,
} from "./dmarc-authority.js";
import { PROVIDER_MAP_VERSION, classifyWorkspaceDomainSenders } from "../engines/sender-classification.js";
import { evaluateEmailSenderMonitoring } from "../engines/email-protection-lifecycle.js";

const DMARC_XML_MAX_BYTES = 2 * 1024 * 1024; // 2 MB hard cap

const DMARC_MAX_RECORDS   = 5000;            // defensive row cap

async function sha256Hex(input) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(input)));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function _xmlDecodeEntities(s) {
  return String(s)
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#0*39;/g, "'").replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

// Extract the inner text of the FIRST occurrence of <tag>…</tag> (tag is a fixed literal).
function _xmlFirst(xml, tag) {
  if (!xml) return null;
  const m = xml.match(new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return m ? _xmlDecodeEntities(m[1]).trim() : null;
}

// Return the inner content of EVERY <tag>…</tag> block.
function _xmlBlocks(xml, tag) {
  if (!xml) return [];
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, "gi");
  const out = []; let m;
  while ((m = re.exec(xml)) !== null) { out.push(m[1]); if (out.length >= DMARC_MAX_RECORDS) break; }
  return out;
}

function _dmarcInt(v, dflt = 0) { const n = parseInt(v, 10); return Number.isFinite(n) ? n : dflt; }

/**
 * parseDmarcAggregateXml(xml) — controlled, defensive DMARC aggregate parser.
 *
 * Security: rejects empty input and input > 2 MB; rejects DOCTYPE/ENTITY/
 * stylesheet declarations (no XXE / entity expansion); performs no network
 * I/O; never returns or stores raw XML. Returns { error, message } on failure
 * or the structured { metadata, policy_published, records } shape on success.
 */
function parseDmarcAggregateXml(xml) {
  if (typeof xml !== "string" || xml.trim() === "") {
    return { error: "empty_xml", message: "No XML content was provided." };
  }
  const byteLen = new TextEncoder().encode(xml).length;
  if (byteLen > DMARC_XML_MAX_BYTES) {
    return { error: "xml_too_large", message: "The DMARC report exceeds the 2 MB limit." };
  }
  if (/<!DOCTYPE/i.test(xml) || /<!ENTITY/i.test(xml) || /<\?xml-stylesheet/i.test(xml)) {
    return { error: "unsafe_xml", message: "The XML contains a disallowed declaration." };
  }
  const metaBlock   = _xmlFirst(xml, "report_metadata");
  const policyBlock = _xmlFirst(xml, "policy_published");
  const recordBlocks = _xmlBlocks(xml, "record");
  if (!metaBlock && !policyBlock && recordBlocks.length === 0) {
    return { error: "invalid_structure", message: "The file does not look like a DMARC aggregate report." };
  }
  const dateRange = _xmlFirst(metaBlock || xml, "date_range");
  const metadata = {
    org_name:         _xmlFirst(metaBlock, "org_name"),
    email:            _xmlFirst(metaBlock, "email"),
    report_id:        _xmlFirst(metaBlock, "report_id"),
    date_range_begin: _dmarcInt(_xmlFirst(dateRange, "begin"), 0) || null,
    date_range_end:   _dmarcInt(_xmlFirst(dateRange, "end"), 0) || null,
  };
  const pctText = _xmlFirst(policyBlock, "pct");
  const policy_published = {
    domain: _xmlFirst(policyBlock, "domain"),
    adkim:  _xmlFirst(policyBlock, "adkim"),
    aspf:   _xmlFirst(policyBlock, "aspf"),
    p:      _xmlFirst(policyBlock, "p"),
    sp:     _xmlFirst(policyBlock, "sp"),
    pct:    pctText != null ? _dmarcInt(pctText, 100) : null,
  };
  const norm = (v) => (v ? String(v).trim().toLowerCase() : null);
  const records = [];
  for (const rec of recordBlocks) {
    const row   = _xmlFirst(rec, "row");
    const pe    = _xmlFirst(row, "policy_evaluated");
    const ident = _xmlFirst(rec, "identifiers");
    const auth  = _xmlFirst(rec, "auth_results");
    const dkimA = _xmlFirst(auth, "dkim");
    const spfA  = _xmlFirst(auth, "spf");
    records.push({
      source_ip:           _xmlFirst(row, "source_ip"),
      count:               _dmarcInt(_xmlFirst(row, "count"), 0),
      disposition:         norm(_xmlFirst(pe, "disposition")),
      dkim_aligned_result: norm(_xmlFirst(pe, "dkim")),
      spf_aligned_result:  norm(_xmlFirst(pe, "spf")),
      header_from:         _xmlFirst(ident, "header_from"),
      envelope_from:       _xmlFirst(ident, "envelope_from"),
      dkim_domain:         _xmlFirst(dkimA, "domain"),
      dkim_selector:       _xmlFirst(dkimA, "selector"),
      dkim_result:         norm(_xmlFirst(dkimA, "result")),
      spf_domain:          _xmlFirst(spfA, "domain"),
      spf_result:          norm(_xmlFirst(spfA, "result")),
    });
  }
  if (records.length === 0) {
    return { error: "no_records", message: "The DMARC report contained no record rows." };
  }
  return { metadata, policy_published, records };
}

// Basic, never-overclaiming provider guessing from real DMARC sender signals.
const DMARC_PROVIDER_PATTERNS = [
  { provider: "google",      needles: ["google.com", "gmail.com", "googlemail.com", "_spf.google.com"] },
  { provider: "microsoft",   needles: ["outlook.com", "protection.outlook.com", "microsoft.com", "office365", "spf.protection.outlook"] },
  { provider: "amazonses",   needles: ["amazonses.com"] },
  { provider: "sendgrid",    needles: ["sendgrid.net", "sendgrid.com"] },
  { provider: "mailchimp",   needles: ["mcsv.net", "mailchimp", "rsgsv.net", "mandrillapp.com"] },
  { provider: "mailgun",     needles: ["mailgun.org", "mailgun.net", "mailgun.com"] },
  { provider: "postmark",    needles: ["postmarkapp.com", "pm.mtasv.net"] },
  { provider: "zoho",        needles: ["zoho.com", "zohomail.com", "zoho.eu"] },
  { provider: "shopify",     needles: ["shopify.com", "shopifyemail.com"] },
  { provider: "wix",         needles: ["wixsite.com", "wix.com"] },
  { provider: "squarespace", needles: ["squarespace.com"] },
];

function guessEmailSenderProvider(record = {}) {
  const hay = [record.dkim_domain, record.spf_domain, record.envelope_from, record.header_from]
    .filter(Boolean).map((s) => String(s).toLowerCase()).join(" ");
  if (hay) {
    for (const { provider, needles } of DMARC_PROVIDER_PATTERNS) {
      if (needles.some((n) => hay.includes(n))) {
        return { provider, confidence: "medium",
          reason: `DKIM/SPF or envelope domain matched a known ${provider} sender pattern` };
      }
    }
  }
  return { provider: "unknown", confidence: "low", reason: "No known provider pattern matched" };
}

/**
 * updateEmailSenderSources(env, workspaceId, domain, parsedReport) — roll up the
 * parsed report's records into the per-source inventory. Only ever called for a
 * NEW (non-duplicate) report, so increments never double-count. Preserves any
 * existing classification and notes on a sender row.
 */
async function updateEmailSenderSources(env, workspaceId, domain, parsed) {
  if (!parsed || !Array.isArray(parsed.records)) return { sources_updated: 0 };
  const beginIso = parsed.metadata?.date_range_begin
    ? new Date(parsed.metadata.date_range_begin * 1000).toISOString()
    : new Date().toISOString();
  const endIso = parsed.metadata?.date_range_end
    ? new Date(parsed.metadata.date_range_end * 1000).toISOString()
    : beginIso;

  const bySource = new Map();
  for (const r of parsed.records) {
    const ip = (r.source_ip || "").trim();
    if (!ip) continue;
    let agg = bySource.get(ip);
    if (!agg) { agg = { ip, total: 0, aligned: 0, spfAligned: 0, dkimAligned: 0, failed: 0, quarantined: 0, rejected: 0, sample: r }; bySource.set(ip, agg); }
    const cnt = r.count || 0;
    agg.total += cnt;
    const aligned = r.spf_aligned_result === "pass" || r.dkim_aligned_result === "pass";
    if (aligned) agg.aligned += cnt; else agg.failed += cnt;
    if (r.spf_aligned_result === "pass") agg.spfAligned += cnt;
    if (r.dkim_aligned_result === "pass") agg.dkimAligned += cnt;
    if (r.disposition === "quarantine") agg.quarantined += cnt;
    if (r.disposition === "reject") agg.rejected += cnt;
  }

  let updated = 0;
  for (const agg of bySource.values()) {
    const guess = guessEmailSenderProvider(agg.sample);
    const existing = await env.cybermeters_db
      .prepare(`SELECT id, total_messages, aligned_messages, failed_messages,
                       spf_aligned_messages, dkim_aligned_messages,
                       quarantined_messages, rejected_messages, first_seen
                FROM email_sender_sources
                WHERE workspace_id = ? AND domain = ? AND source_ip = ? LIMIT 1`)
      .bind(workspaceId, domain, agg.ip).first();
    if (existing) {
      const total    = (existing.total_messages || 0) + agg.total;
      const alignedM = (existing.aligned_messages || 0) + agg.aligned;
      const spfAlignedM = (existing.spf_aligned_messages || 0) + agg.spfAligned;
      const dkimAlignedM = (existing.dkim_aligned_messages || 0) + agg.dkimAligned;
      const failedM  = (existing.failed_messages || 0) + agg.failed;
      const quarM    = (existing.quarantined_messages || 0) + agg.quarantined;
      const rejM     = (existing.rejected_messages || 0) + agg.rejected;
      const passRate = total > 0 ? Math.round((alignedM / total) * 1000) / 10 : 0;
      const firstSeen = existing.first_seen && existing.first_seen < beginIso ? existing.first_seen : beginIso;
      await env.cybermeters_db
        .prepare(`UPDATE email_sender_sources
                  SET last_seen = ?, total_messages = ?, aligned_messages = ?, failed_messages = ?,
                      spf_aligned_messages = ?, dkim_aligned_messages = ?,
                      quarantined_messages = ?, rejected_messages = ?, pass_rate = ?,
                      provider_guess = ?, provider_confidence = ?, provider_reason = ?, provider_map_version = ?,
                      header_from = COALESCE(header_from, ?), first_seen = ?, updated_at = datetime('now')
                  WHERE id = ?`)
        .bind(endIso, total, alignedM, failedM, spfAlignedM, dkimAlignedM, quarM, rejM, passRate,
              guess.provider, guess.confidence, guess.reason, PROVIDER_MAP_VERSION,
              agg.sample.header_from || null, firstSeen, existing.id)
        .run();
      // classification + notes deliberately omitted from UPDATE → preserved.
    } else {
      const passRate = agg.total > 0 ? Math.round((agg.aligned / agg.total) * 1000) / 10 : 0;
      await env.cybermeters_db
        .prepare(`INSERT INTO email_sender_sources
                  (id, workspace_id, domain, source_ip, provider_guess, provider_confidence, provider_reason,
                   header_from, first_seen, last_seen, total_messages, aligned_messages, failed_messages,
                   quarantined_messages, rejected_messages, pass_rate,
                   spf_aligned_messages, dkim_aligned_messages, classification, notes, provider_map_version, created_at, updated_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unknown', NULL, ?, datetime('now'), datetime('now'))`)
        .bind(createId("esender"), workspaceId, domain, agg.ip, guess.provider, guess.confidence, guess.reason,
              agg.sample.header_from || null, beginIso, endIso, agg.total, agg.aligned, agg.failed,
              agg.quarantined, agg.rejected, passRate, agg.spfAligned, agg.dkimAligned, PROVIDER_MAP_VERSION)
        .run();
    }
    updated++;
  }
  return { sources_updated: updated };
}

// Pure, testable: the report identity tuple used for dedupe. Deliberately
// EXCLUDES source/workspace/domain — dedupe is source-agnostic, so the same
// report imported via paste and via signed upload is counted exactly once.
async function dmarcReportIdentity(xmlString, parsed) {
  const m = parsed?.metadata || {};
  const rawHash = await sha256Hex(xmlString);
  const externalReportId = m.report_id || rawHash.slice(0, 32);
  return {
    org_name: m.org_name || null,
    external_report_id: externalReportId,
    date_range_begin: m.date_range_begin || null,
    date_range_end: m.date_range_end || null,
    raw_hash: rawHash,
  };
}

// Pure, testable: does a parsed report belong to the bound domain? Used to stop
// one domain's upload key from poisoning another domain's sender intelligence.
// A report with no published policy domain cannot be disproven, so it is allowed
// (documented limitation) — the workspace+domain binding still scopes the data.
function dmarcReportDomainMatches(parsed, boundDomain) {
  const reportDomain = (parsed?.policy_published?.domain || "").trim().toLowerCase();
  if (!reportDomain) return true;
  return reportDomain === String(boundDomain || "").trim().toLowerCase();
}

function ingestEndpointIsActive(row) {
  return !!row && row.status === "active" && !row.revoked_at;
}

/**
 * ingestDmarcReport(env, opts) — shared DMARC aggregate ingestion pipeline.
 *
 * Used by manual paste and signed upload (and, later, inbound email) so every
 * source shares identical parse → domain-validate → dedupe → insert → rollup →
 * audit behaviour. Never stores or returns raw XML.
 *
 * opts:
 *   workspaceId         (required)
 *   domain              (required, lowercased hostname the report is bound to)
 *   source              'manual_paste' | 'signed_upload' | 'inbound_email'
 *   xmlString           (required) raw report XML
 *   filename            optional display-only label (sanitised; never used for I/O)
 *   actorUserId         optional user id for audit (null for token ingest)
 *   ingestEndpointId    optional ingest endpoint id for audit (null for manual)
 *   domainId            optional pre-resolved domain row id (audit entity)
 *   enforceDomainMatch  when true, reject reports whose policy_published.domain
 *                       does not match the bound domain (token / inbound sources)
 *
 * Returns a discriminated result (no raw XML, ever):
 *   { ok:true,  imported:true,  duplicate:false, reportId, records, messages, sourcesUpdated }
 *   { ok:true,  imported:false, duplicate:true }
 *   { ok:false, status, error, message }
 */
async function ingestDmarcReport(env, opts = {}) {
  const {
    workspaceId, domain, source = "unknown", xmlString,
    filename: rawFilename = null, actorUserId = null,
    ingestEndpointId = null, domainId = null, enforceDomainMatch = false,
    provenance = null,
  } = opts;
  // Inbound sender provenance (null for authenticated manual/signed paths).
  const prov = provenance && typeof provenance === "object" ? provenance : {};

  if (!workspaceId || !domain) {
    return { ok: false, status: 400, error: "missing_binding", message: "Workspace and domain are required." };
  }
  if (typeof xmlString !== "string") {
    return { ok: false, status: 400, error: "missing_xml", message: "No XML content was provided." };
  }
  const filename = typeof rawFilename === "string"
    ? rawFilename.replace(/[^A-Za-z0-9._!@-]/g, "_").slice(0, 200) : null;

  const parsed = parseDmarcAggregateXml(xmlString);
  if (parsed.error) {
    return { ok: false, status: 422, error: parsed.error, message: parsed.message };
  }

  // Domain-binding safety: only enforced for non-interactive sources so existing
  // manual-paste behaviour is preserved exactly.
  if (enforceDomainMatch && !dmarcReportDomainMatches(parsed, domain)) {
    return { ok: false, status: 422, error: "domain_mismatch",
      message: "This report is for a different domain than the one this upload key is bound to." };
  }

  const identity = await dmarcReportIdentity(xmlString, parsed);
  const m = parsed.metadata;

  // Dedupe (null-safe with IS) — source-agnostic; the same report is never
  // double-counted regardless of which ingestion path delivered it.
  const dup = await env.cybermeters_db
    .prepare(`SELECT id FROM dmarc_aggregate_reports
              WHERE workspace_id = ? AND domain = ? AND org_name IS ?
                AND external_report_id = ? AND date_range_begin IS ? AND date_range_end IS ? LIMIT 1`)
    .bind(workspaceId, domain, identity.org_name, identity.external_report_id,
          identity.date_range_begin, identity.date_range_end)
    .first();
  if (dup) {
    await createAuditEvent(env, {
      workspace_id: workspaceId, user_id: actorUserId, event_type: "dmarc_report_duplicate",
      entity_type: "domain", entity_id: domainId,
      description: `Duplicate DMARC report ignored for ${domain}`,
      metadata: { domain, source, org_name: m.org_name, report_id: identity.external_report_id,
                  duplicate: true, ingest_endpoint_id: ingestEndpointId,
                  auth_verdict: prov.auth_verdict ?? null, reporter_domain: prov.reporter_domain ?? null },
    });
    return { ok: true, imported: false, duplicate: true };
  }

  const reportId = createId("dmarcrep");
  const pol = parsed.policy_published || {};
  const messageCount = parsed.records.reduce((a, r) => a + (r.count || 0), 0);
  await env.cybermeters_db
    .prepare(`INSERT INTO dmarc_aggregate_reports
              (id, workspace_id, domain, org_name, report_email, external_report_id, date_range_begin, date_range_end,
               policy_domain, policy_adkim, policy_aspf, policy_p, policy_sp, policy_pct,
               record_count, message_count, raw_hash, source,
               envelope_from, reporter_domain, auth_verdict, auth_evidence, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .bind(reportId, workspaceId, domain, m.org_name || null, m.email || null, identity.external_report_id,
          m.date_range_begin || null, m.date_range_end || null, pol.domain || null, pol.adkim || null,
          pol.aspf || null, pol.p || null, pol.sp || null, pol.pct ?? null,
          parsed.records.length, messageCount, identity.raw_hash, source,
          prov.envelope_from ?? null, prov.reporter_domain ?? null, prov.auth_verdict ?? null, prov.auth_evidence ?? null)
    .run();

  for (const r of parsed.records) {
    await env.cybermeters_db
      .prepare(`INSERT INTO dmarc_aggregate_records
                (id, report_id, workspace_id, domain, source_ip, message_count, disposition,
                 dkim_aligned_result, spf_aligned_result, header_from, envelope_from,
                 dkim_domain, dkim_selector, dkim_result, spf_domain, spf_result, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
      .bind(createId("dmarcrec"), reportId, workspaceId, domain, r.source_ip || null, r.count || 0,
            r.disposition || null, r.dkim_aligned_result || null, r.spf_aligned_result || null,
            r.header_from || null, r.envelope_from || null, r.dkim_domain || null, r.dkim_selector || null,
            r.dkim_result || null, r.spf_domain || null, r.spf_result || null)
      .run();
  }

  const rollup = await updateEmailSenderSources(env, workspaceId, domain, parsed);
  const authorityEligible = isDmarcAuthorityEligibleSource(source);
  // PR-5.5 Gate 1: inbound email remains stored and rolled up for observational
  // display, but it cannot refresh an authoritative classifier or enter the
  // case/alert/recovery consumer. Unknown/unmarked sources fail closed too.
  if (authorityEligible) {
    try {
      await classifyWorkspaceDomainSenders(env, workspaceId, domain, {
        reportSources: DMARC_AUTHORITY_ELIGIBLE_SOURCES,
      });
    } catch { /* auto-classification is best-effort */ }
  }
  // PR-B3: evaluate the sender lifecycle HERE, because ingesting a new report is
  // the only moment the receiver-reported evidence can have changed. This is
  // deliberately not a cron sweep: the legacy hourly sweep re-read cumulative
  // counters on a fixed schedule and re-alerted every 24h forever, whereas an
  // evaluation tied to new evidence cannot fire without new evidence.
  //
  // Runs AFTER auto-classification so the grading sees this report's verdict
  // rather than the previous one. Best-effort: alerting must never fail an
  // ingest, or a delivery problem would start losing customer evidence.
  if (authorityEligible) {
    try {
      await evaluateEmailSenderMonitoring(env, workspaceId, domain);
    } catch { /* alerting must never break evidence ingestion */ }
  }
  await createAuditEvent(env, {
    workspace_id: workspaceId, user_id: actorUserId, event_type: "dmarc_report_ingested",
    entity_type: "domain", entity_id: domainId,
    description: `Ingested DMARC report for ${domain} from ${m.org_name || "unknown reporter"} via ${source}`,
    metadata: { domain, source, org_name: m.org_name, report_id: identity.external_report_id,
                records: parsed.records.length, messages: messageCount, duplicate: false,
                filename, ingest_endpoint_id: ingestEndpointId,
                auth_verdict: prov.auth_verdict ?? null, reporter_domain: prov.reporter_domain ?? null,
                envelope_from: prov.envelope_from ?? null },
  });

  return { ok: true, imported: true, duplicate: false, reportId,
    records: parsed.records.length, messages: messageCount, sourcesUpdated: rollup.sources_updated };
}

const RUA_INBOUND_DOMAIN_DEFAULT = "reports.cybermeters.com";

// Normalize only DNS hostnames that are safe to retain in audit metadata.
function normalizeInboundRecipientDomain(domain) {
  if (typeof domain !== "string") return null;
  const normalized = domain.trim().toLowerCase().replace(/\.$/, "");
  if (!normalized || normalized.length > 253 || !/^[a-z0-9.-]+$/.test(normalized)) return null;
  const labels = normalized.split(".");
  if (labels.some((label) => !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return null;
  return normalized;
}

function parseEmailAuthHeaders(raw, domain) {
  const dom = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
  const text = String(raw || "");
  const out = {
    spf: null, dkim: null, dmarc: null, source_ip: null,
    from_domain: null, dkim_domain: null, dkim_selector: null,
    aligned: null, verdict: "unparseable",
  };
  if (!text.trim()) return out;

  // Unfold header continuation lines (leading whitespace) into single lines.
  const unfolded = text.replace(/\r?\n[ \t]+/g, " ");
  const lines = unfolded.split(/\r?\n/);

  const arBlob = lines.filter((l) => /^authentication-results\s*:/i.test(l)).join(" ").toLowerCase();
  const grab = (re) => { const m = arBlob.match(re); return m ? m[1] : null; };
  const norm = (v) => (v ? String(v).toLowerCase() : null);
  out.spf   = norm(grab(/\bspf=([a-z]+)/));
  out.dkim  = norm(grab(/\bdkim=([a-z]+)/));
  out.dmarc = norm(grab(/\bdmarc=([a-z]+)/));
  out.from_domain = grab(/header\.from=([a-z0-9.\-]+)/) || null;
  // SPF alignment (DMARC) is between the SMTP MAIL FROM domain and header.from,
  // so the SPF-aligned check must use the mailfrom domain, not header.from.
  const spfDomain = (grab(/smtp\.mailfrom=([a-z0-9.@\-]+)/) || "").split("@").pop() || null;
  if (!out.from_domain && spfDomain) out.from_domain = spfDomain;
  out.dkim_domain = grab(/header\.d=([a-z0-9.\-]+)/);

  const dkimSig = lines.find((l) => /^dkim-signature\s*:/i.test(l));
  if (dkimSig) {
    const d = dkimSig.match(/\bd=([a-z0-9.\-]+)/i);
    if (d && !out.dkim_domain) out.dkim_domain = d[1].toLowerCase();
    const s = dkimSig.match(/\bs=([a-z0-9._\-]+)/i);
    if (s) out.dkim_selector = s[1];
  }

  const cip = text.toLowerCase().match(/client-ip=([0-9a-f.:]+)/);
  if (cip) out.source_ip = cip[1];
  if (!out.source_ip) {
    const rip = text.match(/received:[^\n]*?\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]/is);
    if (rip) out.source_ip = rip[1];
  }
  if (out.from_domain) out.from_domain = out.from_domain.toLowerCase().replace(/\.$/, "");
  if (out.dkim_domain) out.dkim_domain = out.dkim_domain.toLowerCase().replace(/\.$/, "");

  const aligns = (h) => Boolean(h && dom && (h === dom || h.endsWith("." + dom) || dom.endsWith("." + h)));
  const dkimAligned = out.dkim === "pass" && aligns(out.dkim_domain);
  const spfAligned  = out.spf === "pass" && aligns(spfDomain ? spfDomain.toLowerCase().replace(/\.$/, "") : null);
  out.aligned = dkimAligned || spfAligned;

  if (!out.spf && !out.dkim && !out.dmarc) out.verdict = "unparseable";
  else if (out.aligned) out.verdict = "authenticated_aligned";
  else if (out.spf === "pass" || out.dkim === "pass") out.verdict = "passes_not_aligned";
  else out.verdict = "fails";
  return out;
}

export {
  DMARC_MAX_RECORDS,
  DMARC_PROVIDER_PATTERNS,
  DMARC_XML_MAX_BYTES,
  RUA_INBOUND_DOMAIN_DEFAULT,
  _dmarcInt,
  _xmlBlocks,
  _xmlDecodeEntities,
  _xmlFirst,
  dmarcReportDomainMatches,
  dmarcReportIdentity,
  guessEmailSenderProvider,
  ingestDmarcReport,
  ingestEndpointIsActive,
  normalizeInboundRecipientDomain,
  parseDmarcAggregateXml,
  parseEmailAuthHeaders,
  sha256Hex,
  updateEmailSenderSources,
};
