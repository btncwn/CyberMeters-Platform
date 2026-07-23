// ── Inbound DMARC (RUA) email module ─────────────────────────────────────────
// Sprint 9 phase-1 extraction: the email() handler plus its exclusive parsing
// layer (MIME split, gzip/zip bomb-capped decompression, sender provenance)
// moved out of the monolith. Shared app services are imported from the
// src/lib/ service modules — the Sprint 9 index ⇄ inbound cycle was dissolved
// in Sprint 10 Stage A; this module no longer imports index.js.
import { RUA_INBOUND_DOMAIN_DEFAULT, ingestDmarcReport, ingestEndpointIsActive, normalizeInboundRecipientDomain, parseEmailAuthHeaders } from "../lib/dmarc-ingest.js";
import { ingestTlsRptReport } from "../lib/tlsrpt-ingest.js";
import { createAuditEvent, createNotificationEvent } from "../lib/events.js";
import { sendLifecycleEmail } from "../lib/lifecycle-email.js";

const RUA_RAW_EMAIL_MAX_BYTES   = 25 * 1024 * 1024; // Cloudflare inbound ceiling
const RUA_ATTACHMENT_MAX_BYTES  = 10 * 1024 * 1024; // compressed attachment cap
const RUA_DECOMPRESSED_MAX_BYTES = 10 * 1024 * 1024; // decompressed output cap
const RUA_MAX_COMPRESSION_RATIO = 100;              // out/in ratio cap (bomb guard)
const RUA_MAX_MIME_PARTS        = 25;               // abuse guard

const RUA_DEFAULT_CAPS = {
  attachmentMax: RUA_ATTACHMENT_MAX_BYTES,
  decompressedMax: RUA_DECOMPRESSED_MAX_BYTES,
  ratioMax: RUA_MAX_COMPRESSION_RATIO,
};

// Opaque, non-guessable inbound localpart. Deliberately contains NO workspace id
// or domain — knowledge of the address must not leak tenancy.

// Parse a complete recipient without retaining headers or payload content.
// Cloudflare normally supplies a bare address; surrounding angle brackets are
// accepted for regression fixtures and defensive compatibility.
function parseInboundRecipient(recipient) {
  if (!recipient || typeof recipient !== "string") return null;
  let addr = recipient.trim();
  if (addr.startsWith("<") && addr.endsWith(">")) addr = addr.slice(1, -1).trim();
  if (!addr || /[<>\s]/.test(addr)) return null;
  const at = addr.indexOf("@");
  if (at <= 0 || at !== addr.lastIndexOf("@") || at === addr.length - 1) return null;
  const localpart = addr.slice(0, at).toLowerCase();
  if (localpart.length > 64 || !/^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(localpart) ||
      localpart.startsWith(".") || localpart.endsWith(".") || localpart.includes("..")) return null;
  const domain = normalizeInboundRecipientDomain(addr.slice(at + 1));
  return domain ? { localpart, domain } : null;
}

// Resolve a recipient address to our opaque localpart (or null if not ours).
function extractInboundLocalpart(recipient, expectedDomain = null) {
  const parsed = parseInboundRecipient(recipient);
  if (!parsed) return null;
  if (expectedDomain && parsed.domain !== normalizeInboundRecipientDomain(expectedDomain)) return null;
  let local = parsed.localpart;
  const plus = local.indexOf("+"); // strip +tags defensively (we don't issue any)
  if (plus >= 0) local = local.slice(0, plus);
  return /^cmrua_[a-z0-9]{8,}$/.test(local) ? local : null;
}

// ── byte/string helpers (latin1-safe; MIME headers + base64 are ASCII) ────────
function _latin1ToBytes(str) {
  const out = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) out[i] = str.charCodeAt(i) & 0xff;
  return out;
}
function _bytesToLatin1(bytes) {
  let s = ""; const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  return s;
}
function _base64ToBytes(b64) {
  return _latin1ToBytes(atob(String(b64).replace(/[^A-Za-z0-9+/=]/g, "")));
}
function _readU16(b, o) { return b[o] | (b[o + 1] << 8); }
function _readU32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

// Read a ReadableStream fully into bytes, aborting past maxBytes. Returns null
// if the cap is exceeded (caller drops the message).
async function readStreamCapped(stream, maxBytes) {
  const reader = stream.getReader();
  const chunks = []; let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) { try { await reader.cancel(); } catch { /* ignore */ } return null; }
    chunks.push(value);
  }
  const out = new Uint8Array(total); let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.byteLength; }
  return out;
}

// Decompress via the platform DecompressionStream with a hard output cap.
async function _inflateWithCap(bytes, format, maxOut) {
  const stream = new Response(bytes).body.pipeThrough(new DecompressionStream(format));
  const reader = stream.getReader();
  const chunks = []; let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxOut) { try { await reader.cancel(); } catch { /* ignore */ } throw new Error("decompressed_too_large"); }
    chunks.push(value);
  }
  const out = new Uint8Array(total); let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.byteLength; }
  return out;
}

async function gunzipXmlBytes(bytes, caps = RUA_DEFAULT_CAPS) {
  if (!bytes || !bytes.length) return { error: "empty_attachment" };
  if (bytes.length > caps.attachmentMax) return { error: "attachment_too_large" };
  let out;
  try { out = await _inflateWithCap(bytes, "gzip", caps.decompressedMax); }
  catch (e) { return { error: e.message === "decompressed_too_large" ? "decompressed_too_large" : "gzip_failed" }; }
  if (bytes.length > 0 && out.length / bytes.length > caps.ratioMax) return { error: "compression_ratio_exceeded" };
  return { bytes: out };
}

// Minimal, hardened single-entry ZIP reader. Supports STORED (0) and DEFLATE (8)
// only. Enforces single entry via the End-Of-Central-Directory total count, and
// applies the same size/ratio caps. Rejects multi-entry, nested, streamed
// (data-descriptor) and unknown-method archives. No general unzip library.
async function unzipSingleEntryXmlBytes(bytes, caps = RUA_DEFAULT_CAPS) {
  if (!bytes || bytes.length < 22) return { error: "zip_invalid" };
  if (bytes.length > caps.attachmentMax) return { error: "attachment_too_large" };
  if (!(bytes[0] === 0x50 && bytes[1] === 0x4b && bytes[2] === 0x03 && bytes[3] === 0x04)) return { error: "zip_invalid" };
  let eocd = -1;
  for (let i = bytes.length - 22; i >= 0; i--) {
    if (bytes[i] === 0x50 && bytes[i + 1] === 0x4b && bytes[i + 2] === 0x05 && bytes[i + 3] === 0x06) { eocd = i; break; }
  }
  if (eocd < 0) return { error: "zip_invalid" };
  if (_readU16(bytes, eocd + 10) !== 1) return { error: "zip_multi_entry" };
  const method   = _readU16(bytes, 8);
  const compSize = _readU32(bytes, 18);
  const uncomp   = _readU32(bytes, 22);
  const nameLen  = _readU16(bytes, 26);
  const extraLen = _readU16(bytes, 28);
  if (compSize === 0) return { error: "zip_unsupported_streaming" }; // data-descriptor not supported
  if (compSize > caps.attachmentMax || uncomp > caps.decompressedMax) return { error: "zip_too_large" };
  const dataStart = 30 + nameLen + extraLen;
  const comp = bytes.subarray(dataStart, dataStart + compSize);
  if (method === 0) {
    if (comp.length > caps.decompressedMax) return { error: "zip_too_large" };
    return { bytes: comp.slice() };
  }
  if (method === 8) {
    let out;
    try { out = await _inflateWithCap(comp, "deflate-raw", caps.decompressedMax); }
    catch (e) { return { error: e.message === "decompressed_too_large" ? "decompressed_too_large" : "zip_inflate_failed" }; }
    if (comp.length > 0 && out.length / comp.length > caps.ratioMax) return { error: "compression_ratio_exceeded" };
    return { bytes: out };
  }
  return { error: "zip_unsupported_method" };
}

// Dispatch an attachment to the right safe decoder and return XML text plus
// safe diagnostic sizes (no raw bytes, no XML content) for audit metadata.
async function extractDmarcXmlFromAttachment(filename, bytes, caps = RUA_DEFAULT_CAPS) {
  if (!bytes || !bytes.length) return { error: "empty_attachment" };
  const name = (filename || "").toLowerCase();
  const looksGz  = name.endsWith(".gz") || name.endsWith(".gzip") || (bytes[0] === 0x1f && bytes[1] === 0x8b);
  const looksZip = name.endsWith(".zip") || (bytes[0] === 0x50 && bytes[1] === 0x4b);
  let xmlBytes;
  let attachmentType;
  if (looksGz) {
    const r = await gunzipXmlBytes(bytes, caps); if (r.error) return r; xmlBytes = r.bytes; attachmentType = "gzip";
  } else if (looksZip) {
    const r = await unzipSingleEntryXmlBytes(bytes, caps); if (r.error) return r; xmlBytes = r.bytes; attachmentType = "zip";
  } else if (name.endsWith(".xml") || /^\s*<\?xml|^\s*<feedback/i.test(_bytesToLatin1(bytes.subarray(0, 64)))) {
    if (bytes.length > caps.decompressedMax) return { error: "attachment_too_large" };
    xmlBytes = bytes; attachmentType = "xml";
  } else {
    return { error: "unsupported_attachment" };
  }
  return {
    xml: new TextDecoder("utf-8").decode(xmlBytes),
    attachment_type: attachmentType,
    compressed_size: bytes.length,
    decompressed_size: xmlBytes.length,
  };
}

// Map any internal extraction/ingestion error to a STABLE, customer-safe drop
// reason for audit metadata (no internal detail leaks into events).
function normalizeInboundDropReason(reason) {
  switch (String(reason || "")) {
    case "unsupported_recipient_domain": return "unsupported_recipient_domain";
    case "invalid_recipient":
    case "unknown_address":
    case "endpoint_not_found":      return "endpoint_not_found";
    case "endpoint_revoked":
    case "endpoint_inactive":       return "endpoint_inactive";
    case "no_dmarc_attachment":     return "no_dmarc_attachment";
    case "multiple_attachments":
    case "multiple_dmarc_attachments": return "multiple_dmarc_attachments";
    case "email_too_large":
    case "attachment_too_large":
    case "zip_too_large":           return "attachment_too_large";
    case "decompressed_too_large":  return "decompressed_too_large";
    case "compression_ratio_exceeded": return "compression_ratio_exceeded";
    case "domain_mismatch":         return "domain_mismatch";
    case "unsupported_attachment":
    case "empty_attachment":        return "unsupported_attachment";
    default:                        return "parse_error";
  }
}

// Customer-safe wording for inbound DMARC report drop notifications. Keyed by
// the normalized drop reason; anything unknown falls back to the generic parse
// text. Deliberately calm — a single malformed report from a provider is
// normal and must not read as an incident.
function inboundDropCustomerMessage(reason) {
  switch (reason) {
    case "endpoint_inactive":
      return "It was sent to a CyberMeters reporting address that is no longer active. Update the rua address in your DMARC record to your current reporting address.";
    case "domain_mismatch":
      return "It was a report for a different domain than the one this reporting address belongs to.";
    case "attachment_too_large":
    case "decompressed_too_large":
    case "compression_ratio_exceeded":
      return "The report attachment was larger than the supported size.";
    default:
      return "The report attachment could not be read. Occasional malformed reports from providers are normal — no action is needed unless this keeps happening.";
  }
}

// Sanitize internal platform errors (e.g. Cloudflare subrequest-budget messages)
// before they can surface to customers. Genuine findings pass through unchanged.

// ── minimal MIME parsing (no external lib) ────────────────────────────────────
function _parseMimeHeaders(headerText) {
  const headers = {};
  const lines = headerText.replace(/\r\n/g, "\n").split("\n");
  let cur = null;
  for (const line of lines) {
    if (/^[ \t]/.test(line) && cur) { headers[cur] += " " + line.trim(); continue; } // unfold
    const idx = line.indexOf(":");
    if (idx < 0) continue;
    cur = line.slice(0, idx).trim().toLowerCase();
    headers[cur] = line.slice(idx + 1).trim();
  }
  return headers;
}
function _mimeParam(value, name) {
  if (!value) return null;
  const m = value.match(new RegExp(name + '\\s*=\\s*"([^"]*)"|' + name + '\\s*=\\s*([^;\\s]+)', "i"));
  return m ? (m[1] ?? m[2] ?? null) : null;
}
// Returns flat leaf parts: { contentType, encoding, filename, bytes }.
function parseMimeParts(rawLatin1, depth = 0) {
  const parts = [];
  if (depth > 3 || typeof rawLatin1 !== "string") return parts;
  const sep = rawLatin1.indexOf("\r\n\r\n") >= 0 ? "\r\n\r\n" : "\n\n";
  const splitIdx = rawLatin1.indexOf(sep);
  const headerText = splitIdx >= 0 ? rawLatin1.slice(0, splitIdx) : rawLatin1;
  const body = splitIdx >= 0 ? rawLatin1.slice(splitIdx + sep.length) : "";
  const headers = _parseMimeHeaders(headerText);
  const ctypeRaw = headers["content-type"] || "";
  const ctype = ctypeRaw.toLowerCase();
  const boundary = _mimeParam(ctypeRaw, "boundary");
  if (ctype.startsWith("multipart/") && boundary) {
    for (const seg of body.split("--" + boundary)) {
      if (parts.length >= RUA_MAX_MIME_PARTS) break;
      const s = seg.replace(/^\r?\n/, "");
      if (!s || s.startsWith("--")) continue; // preamble / closing boundary
      for (const p of parseMimeParts(s, depth + 1)) parts.push(p);
    }
    return parts;
  }
  const encoding = (headers["content-transfer-encoding"] || "7bit").toLowerCase();
  const filename = _mimeParam(headers["content-disposition"], "filename") || _mimeParam(ctypeRaw, "name");
  const bytes = encoding === "base64" ? _base64ToBytes(body) : _latin1ToBytes(body.replace(/\r?\n$/, ""));
  parts.push({ contentType: ctype.split(";")[0].trim(), encoding, filename, bytes });
  return parts;
}
// Choose exactly one DMARC report attachment. Zero or more-than-one → error
// (deterministic, documented MVP behaviour).
function selectDmarcAttachment(parts) {
  const candidates = (parts || []).filter((p) => {
    const n = (p.filename || "").toLowerCase();
    const ct = (p.contentType || "").toLowerCase();
    const extOk = n.endsWith(".gz") || n.endsWith(".gzip") || n.endsWith(".zip") || n.endsWith(".xml");
    const ctOk = ["application/gzip", "application/x-gzip", "application/zip",
      "application/x-zip-compressed", "text/xml", "application/xml"].includes(ct);
    return extOk || ctOk || (ct === "application/octet-stream" && extOk);
  });
  if (candidates.length === 0) return { error: "no_dmarc_attachment" };
  if (candidates.length > 1) return { error: "multiple_attachments" };
  return { part: candidates[0] };
}

// ── TLS-RPT (RFC 8460) attachment handling ────────────────────────────────────
// TLS-RPT reports arrive at the same mailbox as DMARC but are JSON. Detect them
// so the handler can route to the JSON path; absence of a match just means "not
// TLS-RPT, try DMARC" (returns { part: null }, never an error).
function selectTlsRptAttachment(parts) {
  const candidates = (parts || []).filter((p) => {
    const n = (p.filename || "").toLowerCase();
    const ct = (p.contentType || "").toLowerCase();
    const ctOk = ct === "application/tlsrpt+gzip" || ct === "application/tlsrpt+json";
    const extOk = n.endsWith(".json") || n.endsWith(".json.gz");
    return ctOk || extOk;
  });
  if (candidates.length === 0) return { part: null };
  return { part: candidates[0] };
}

// Extract the JSON body from a TLS-RPT attachment (gzip or plain JSON), applying
// the same size/ratio caps as DMARC. Returns { json, attachment_type, sizes } or { error }.
async function extractTlsRptFromAttachment(filename, bytes, caps = RUA_DEFAULT_CAPS) {
  if (!bytes || !bytes.length) return { error: "empty_attachment" };
  const name = (filename || "").toLowerCase();
  const looksGz = name.endsWith(".gz") || (bytes[0] === 0x1f && bytes[1] === 0x8b);
  let jsonBytes, attachmentType;
  if (looksGz) {
    const r = await gunzipXmlBytes(bytes, caps); if (r.error) return r; jsonBytes = r.bytes; attachmentType = "gzip";
  } else {
    if (bytes.length > caps.decompressedMax) return { error: "attachment_too_large" };
    jsonBytes = bytes; attachmentType = "json";
  }
  return {
    json: new TextDecoder("utf-8").decode(jsonBytes),
    attachment_type: attachmentType,
    compressed_size: bytes.length,
    decompressed_size: jsonBytes.length,
  };
}

/**
 * parseEmailAuthHeaders(raw, domain) — instant sender validation from pasted
 * email headers, without waiting for DMARC aggregate reports to arrive. Parses
 * the RFC 8601 Authentication-Results header (plus DKIM-Signature and the
 * sending IP) and decides whether the message is authenticated and aligned to
 * `domain`. Pure and defensive — never throws; returns verdict "unparseable"
 * when it cannot find authentication results rather than guessing.
 */

// Public mailbox domains commonly seen in DMARC aggregate (RUA) traffic.
// Membership is descriptive metadata only. Header-From is attacker-controlled,
// and Cloudflare Email Routing does not expose a trusted Authentication-Results
// value to this Worker, so this list MUST NOT authenticate a sender, report
// producer, or report-body claim and MUST NOT grant authority.
const KNOWN_DMARC_REPORTERS = [
  "google.com", "microsoft.com", "outlook.com", "hotmail.com",
  "yahoo.com", "yahooinc.com", "yahoo.co.jp", "aol.com",
  "fastmail.com", "mail.ru", "comcast.net", "gmx.net", "gmx.com",
  "web.de", "seznam.cz", "t-online.de", "laposte.net", "163.com", "qq.com",
];

function isKnownDmarcReporter(domain) {
  const d = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
  if (!d) return false;
  return KNOWN_DMARC_REPORTERS.some((r) => d === r || d.endsWith("." + r));
}

// Extract the domain from an RFC5322 mailbox/address header value ("Name <a@b>"
// or a bare "a@b"). Returns a normalized hostname or null.
function extractEmailDomainFromHeader(value) {
  if (!value || typeof value !== "string") return null;
  const m = value.match(/<([^<>@\s]+@[^<>@\s]+)>/) || value.match(/([^\s<>@]+@[^\s<>@]+)/);
  if (!m) return null;
  const at = m[1].lastIndexOf("@");
  if (at < 0) return null;
  return normalizeInboundRecipientDomain(m[1].slice(at + 1));
}

// Extract a claimed header-From domain only when the top-level header block has
// exactly ONE From header. This is forensic metadata, never a trust anchor.
function extractSingleFromDomain(headerBlock) {
  const unfolded = String(headerBlock || "").replace(/\r?\n[ \t]+/g, " ");
  const froms = unfolded.split(/\r?\n/).filter((l) => /^from\s*:/i.test(l));
  if (froms.length !== 1) return null;
  return extractEmailDomainFromHeader(froms[0].replace(/^from\s*:/i, ""));
}

// Best-effort transport metadata for one inbound RUA email. NEVER throws and
// NEVER blocks ingestion. No value returned here grants report authority.
//
// Header-From, envelope From, Authentication-Results and DKIM header lines are
// all sender-controlled at this boundary. They may be retained as bounded
// forensic claims, but transport_authenticated_sender remains unknown.
function deriveInboundReportProvenance(rawLatin1, message, boundDomain) {
  const out = {
    envelope_from: null,
    reporter_domain: null,
    auth_verdict: "sender_identity_unavailable",
    auth_evidence: null,
  };
  try {
    // Only the top-level header block (before the first blank line) is inspected
    // for auth signals; the body may contain forged header-like lines.
    const a = rawLatin1.indexOf("\r\n\r\n");
    const b = rawLatin1.indexOf("\n\n");
    const sepIdx = a < 0 ? b : (b < 0 ? a : Math.min(a, b));
    const headerBlock = sepIdx >= 0 ? rawLatin1.slice(0, sepIdx) : rawLatin1;

    const headerFromDomain = extractSingleFromDomain(headerBlock);
    const envRaw = message && typeof message.from === "string" ? message.from.trim() : "";
    const envelopeFromDomain = envRaw
      ? extractEmailDomainFromHeader(envRaw) || normalizeInboundRecipientDomain(envRaw.split("@").pop())
      : null;
    out.envelope_from = envRaw ? envRaw.slice(0, 320).toLowerCase() : null;

    // Untrusted forensic signals only (self-asserted by the sender). Restricted to
    // the header block so body-injected Authentication-Results cannot even appear.
    const auth = parseEmailAuthHeaders(headerBlock, boundDomain || headerFromDomain || "");

    const recognisedReporterDomain = Boolean(
      headerFromDomain && isKnownDmarcReporter(headerFromDomain),
    );
    out.auth_verdict = recognisedReporterDomain
      ? "sender_domain_claimed_recognised"
      : ((headerFromDomain || envelopeFromDomain)
        ? "sender_domain_claimed"
        : "sender_identity_unavailable");
    out.reporter_domain = headerFromDomain || envelopeFromDomain || null;
    out.auth_evidence = JSON.stringify({
      claimed_header_from: headerFromDomain || null,
      claimed_envelope_from: envelopeFromDomain || null,
      self_asserted_dkim: auth ? auth.dkim : null,
      self_asserted_dkim_d: auth ? auth.dkim_domain : null,
      self_asserted_spf: auth ? auth.spf : null,
      self_asserted_dmarc: auth ? auth.dmarc : null,
      transport_authenticated_sender: null,
      recognised_reporter_domain: recognisedReporterDomain,
      basis: recognisedReporterDomain ? "recognised_reporter_domain_metadata" : null,
    }).slice(0, 500);
  } catch { /* provenance is best-effort; ingestion must proceed regardless */ }
  return out;
}

// Additive remediation actions derived from imported DMARC report data.

// ── Inbound DMARC aggregate (RUA) email handler ──────────────────────────────
// Assisted RUA Ingestion v1. Cloudflare Email Routing (catch-all on
// RUA_INBOUND_DOMAIN) invokes this for every message. We resolve the recipient
// localpart to an active ingestion endpoint, safely extract the DMARC XML from
// a gzip/zip/raw attachment (hard bomb caps), and run it through the SAME
// ingestDmarcReport() pipeline with source=inbound_email. The handler never
// throws, never stores raw payloads, and drops invalid mail with an audit note.
// Operator routing: private beta may use exact per-address routes; public beta
// should send *@reports.cybermeters.com to this Worker. D1 address_local lookup
// authorizes known recipients, and unknown localparts are safely dropped.
export async function handleInboundEmail(message, env, _ctx, deps = {}) {
  const caps = {
    attachmentMax: RUA_ATTACHMENT_MAX_BYTES,
    decompressedMax: RUA_DECOMPRESSED_MAX_BYTES,
    ratioMax: RUA_MAX_COMPRESSION_RATIO,
  };
  // Drop safely with a STABLE, customer-safe reason and no raw payload.
  // `kind` labels the report type in customer-facing text ("DMARC"/"TLS-RPT").
  const drop = async (endpoint, rawReason, recipient = null, kind = "DMARC") => {
    try {
      const reason = normalizeInboundDropReason(rawReason);
      await createAuditEvent(env, {
        workspace_id: endpoint?.workspace_id || null, user_id: null,
        event_type: "dmarc_inbound_email_dropped", entity_type: "domain",
        entity_id: endpoint?.domain_id || null,
        description: `Dropped inbound ${kind} email (${reason})`,
        metadata: {
          source: "inbound_email",
          reason,
          recipient_localpart: recipient?.localpart || null,
          recipient_domain: recipient?.domain || null,
        },
      });

      // Customer visibility: an audit row alone leaves the customer blind to
      // "my reports aren't arriving". When the drop maps to a known workspace,
      // surface one calm notification — deduped per workspace+domain per 24h
      // so a misbehaving reporter can't flood the bell.
      if (endpoint?.workspace_id && endpoint?.domain) {
        const title = `A ${kind} report for ${endpoint.domain} could not be processed`;
        const dup = await env.cybermeters_db
          .prepare(`SELECT id FROM notification_events
                    WHERE workspace_id = ? AND type = 'dmarc_report_dropped' AND title = ?
                      AND created_at >= datetime('now', '-1 day') LIMIT 1`)
          .bind(endpoint.workspace_id, title)
          .first();
        if (!dup) {
          await createNotificationEvent(env, endpoint.workspace_id, {
            type: "dmarc_report_dropped",
            severity: "info",
            title,
            message: inboundDropCustomerMessage(reason),
            metadata: { domain: endpoint.domain, domain_id: endpoint.domain_id || null, reason },
          });
        }
      }
    } catch { /* never throw from the email handler */ }
  };
  try {
    const recipient = parseInboundRecipient(message.to);
    if (!recipient) { await drop(null, "parse_error"); return; }
    const inboundDomain = normalizeInboundRecipientDomain(env.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT);
    if (!inboundDomain || recipient.domain !== inboundDomain) {
      await drop(null, "unsupported_recipient_domain", recipient); return;
    }
    const localpart = extractInboundLocalpart(message.to, inboundDomain);
    if (!localpart) { await drop(null, "endpoint_not_found", recipient); return; }

    const endpoint = await env.cybermeters_db
      .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE address_local = ? LIMIT 1`)
      .bind(localpart).first();
    if (!ingestEndpointIsActive(endpoint)) {
      await drop(endpoint, endpoint ? "endpoint_inactive" : "endpoint_not_found", recipient);
      return;
    }

    // Per-endpoint inbound rate limit (Q7 hardening). The rua address is published
    // publicly in the customer's DNS, so anyone can send forged reports to a known
    // endpoint. Per-message bomb/size caps bound each message; this bounds the
    // CROSS-message flood (storage growth / alert-evaluation churn) that the
    // per-message caps cannot. Fail-OPEN — a rate-limit-store outage must NEVER drop
    // legitimate customer evidence. Legitimate reporters send a handful of reports/day
    // per endpoint, far under this ceiling. A limited drop is audited (append-only)
    // but NOT surfaced as a misleading "malformed report" customer notification.
    if (typeof deps.consumeApiRateLimit === "function") {
      const scopeId = typeof deps.rateLimitScopeId === "function"
        ? await deps.rateLimitScopeId("rua_inbound", endpoint.id)
        : `rua_inbound_${endpoint.id}`;
      const limited = await deps.consumeApiRateLimit(env,
        [{ scope: "rua_inbound_endpoint", scope_id: scopeId }],
        "rua_inbound", 120, 3600).catch(() => null);
      if (limited) {
        await createAuditEvent(env, {
          workspace_id: endpoint.workspace_id, user_id: null,
          event_type: "dmarc_inbound_email_rate_limited", entity_type: "domain",
          entity_id: endpoint.domain_id,
          description: `Inbound report rate limit reached for ${endpoint.domain}`,
          metadata: { source: "inbound_email", reason: "rate_limited", recipient_localpart: localpart },
        }).catch(() => {});
        return;
      }
    }

    if (typeof message.rawSize === "number" && message.rawSize > RUA_RAW_EMAIL_MAX_BYTES) {
      await drop(endpoint, "attachment_too_large", recipient); return;
    }
    const raw = await readStreamCapped(message.raw, RUA_RAW_EMAIL_MAX_BYTES);
    if (!raw) { await drop(endpoint, "attachment_too_large", recipient); return; }

    const rawLatin1 = _bytesToLatin1(raw);
    // Record bounded sender claims without authenticating them. A recognised
    // public-mail header-From is metadata only; it grants no report authority.
    // The report remains auditable and purgeable, while enforceDomainMatch only
    // checks the body claim against the endpoint binding.
    const provenance = deriveInboundReportProvenance(rawLatin1, message, endpoint.domain);

    const parts = parseMimeParts(rawLatin1);

    // Route by attachment type: TLS-RPT (JSON) → its own parser; DMARC XML falls
    // through to the existing path, byte-for-byte unchanged.
    const tlsSel = selectTlsRptAttachment(parts);
    if (tlsSel.part) {
      const tlsExt = await extractTlsRptFromAttachment(tlsSel.part.filename, tlsSel.part.bytes, caps);
      if (tlsExt.error) { await drop(endpoint, tlsExt.error, recipient, "TLS-RPT"); return; }
      const tlsResult = await ingestTlsRptReport(env, {
        workspaceId: endpoint.workspace_id, domain: endpoint.domain, jsonString: tlsExt.json,
        ingestEndpointId: endpoint.id, domainId: endpoint.domain_id, enforceDomainMatch: true, provenance,
      });
      if (!tlsResult.ok) { await drop(endpoint, tlsResult.error, recipient, "TLS-RPT"); return; }
      await env.cybermeters_db
        .prepare(`UPDATE dmarc_ingest_endpoints SET last_used_at = datetime('now'), last_inbound_at = datetime('now') WHERE id = ?`)
        .bind(endpoint.id).run();
      if (tlsResult.duplicate) return;
      await createAuditEvent(env, {
        workspace_id: endpoint.workspace_id, user_id: null, event_type: "tlsrpt_inbound_email_received",
        entity_type: "domain", entity_id: endpoint.domain_id,
        description: `Received inbound TLS-RPT report for ${endpoint.domain}`,
        metadata: {
          domain: endpoint.domain, recipient_localpart: localpart, source: "inbound_email",
          attachment_type: tlsExt.attachment_type, compressed_size: tlsExt.compressed_size,
          decompressed_size: tlsExt.decompressed_size, sessions: tlsResult.sessions, failures: tlsResult.failures,
          auth_verdict: provenance.auth_verdict, reporter_domain: provenance.reporter_domain,
        },
      }).catch(() => {});
      return;
    }

    const sel = selectDmarcAttachment(parts);
    if (sel.error) { await drop(endpoint, sel.error, recipient); return; }
    const ext = await extractDmarcXmlFromAttachment(sel.part.filename, sel.part.bytes, caps);
    if (ext.error) { await drop(endpoint, ext.error, recipient); return; }

    const result = await ingestDmarcReport(env, {
      workspaceId: endpoint.workspace_id, domain: endpoint.domain, source: "inbound_email",
      xmlString: ext.xml, actorUserId: null, ingestEndpointId: endpoint.id,
      domainId: endpoint.domain_id, enforceDomainMatch: true, provenance,
    });

    // Parse/validation rejection (e.g. domain_mismatch). Do NOT mark the
    // address as "receiving" — it did not deliver a valid report.
    if (!result.ok) { await drop(endpoint, result.error, recipient); return; }

    // A valid report arrived (new import OR an already-seen duplicate). Both
    // are honest "we received an inbound report" signals.
    await env.cybermeters_db
      .prepare(`UPDATE dmarc_ingest_endpoints SET last_used_at = datetime('now'), last_inbound_at = datetime('now') WHERE id = ?`)
      .bind(endpoint.id).run();

    // Duplicate: ingestDmarcReport already emitted dmarc_report_duplicate
    // (source=inbound_email) and did not change any totals.
    if (result.duplicate) return;

    // Genuine import — rich, safe transport-level audit (no raw XML/email).
    await createAuditEvent(env, {
      workspace_id: endpoint.workspace_id, user_id: null, event_type: "dmarc_inbound_email_received",
      entity_type: "domain", entity_id: endpoint.domain_id,
      description: `Received inbound DMARC report for ${endpoint.domain}`,
      metadata: {
        domain: endpoint.domain,
        recipient_localpart: localpart,
        source: "inbound_email",
        attachment_type: ext.attachment_type,
        compressed_size: ext.compressed_size,
        decompressed_size: ext.decompressed_size,
        message_count: result.messages,
        record_count: result.records,
        // Sender transport status is a claimed identity label, not authority.
        auth_verdict: provenance.auth_verdict,
        reporter_domain: provenance.reporter_domain,
        envelope_from: provenance.envelope_from,
      },
    });

    // Lifecycle: nudge the customer to finish DMARC DNS setup. Reports are now
    // arriving but that does NOT confirm DNS is verified — the email says so
    // explicitly and never claims "Connected". Deduped once per workspace+domain.
    await sendLifecycleEmail(env, {
      type: "lifecycle_email_protection_next_step",
      workspace_id: endpoint.workspace_id, domain: endpoint.domain,
    }).catch(() => {});
  } catch (e) {
    console.error("[email-ingest]", String(e?.message ?? e));
    // Swallow — an inbound mail handler must never throw.
  }
}

// Exported for index.js re-export → the test harnesses.
export {
  deriveInboundReportProvenance,
  extractDmarcXmlFromAttachment,
  extractEmailDomainFromHeader,
  extractInboundLocalpart,
  extractSingleFromDomain,
  gunzipXmlBytes,
  isKnownDmarcReporter,
  normalizeInboundDropReason,
  parseInboundRecipient,
  parseMimeParts,
  selectDmarcAttachment,
  unzipSingleEntryXmlBytes,
};
