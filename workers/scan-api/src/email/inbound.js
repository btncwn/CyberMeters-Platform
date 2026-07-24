// ── Inbound DMARC (RUA) email module ─────────────────────────────────────────
// Sprint 9 phase-1 extraction: the email() handler plus its exclusive parsing
// layer (streamed MIME, gzip/zip bomb-capped decompression, sender provenance)
// moved out of the monolith. Shared app services are imported from the
// src/lib/ service modules — the Sprint 9 index ⇄ inbound cycle was dissolved
// in Sprint 10 Stage A; this module no longer imports index.js.
import { RUA_INBOUND_DOMAIN_DEFAULT, ingestDmarcReport, ingestEndpointIsActive, normalizeInboundRecipientDomain, parseEmailAuthHeaders } from "../lib/dmarc-ingest.js";
import { ingestTlsRptReport } from "../lib/tlsrpt-ingest.js";
import { createAuditEvent, createNotificationEvent } from "../lib/events.js";
import { sendLifecycleEmail } from "../lib/lifecycle-email.js";

// Gate 4 memory envelope: DMARC XML and TLS-RPT JSON are each capped at 2 MiB
// after decoding. A 4 MiB raw message therefore leaves room for base64 expansion
// and MIME headers while keeping one streamed entity + decoded attachment far
// below the Worker's 128 MiB isolate ceiling under concurrent deliveries.
const RUA_RAW_EMAIL_MAX_BYTES    = 4 * 1024 * 1024;
const RUA_ATTACHMENT_MAX_BYTES   = 2 * 1024 * 1024;
const RUA_DECOMPRESSED_MAX_BYTES = 2 * 1024 * 1024;
const RUA_MAX_COMPRESSION_RATIO = 100;              // out/in ratio cap (bomb guard)
const RUA_MAX_MIME_PARTS        = 25;               // abuse guard
// Root multipart is depth 1. Five levels admit common provider wrappers such
// as mixed → related → alternative while rejecting adversarial deep nesting.
const RUA_MAX_MIME_DEPTH        = 5;
const RUA_MIME_HEADER_MAX_BYTES = 64 * 1024;
// 2 MiB decoded base64 expands to ~2.67 MiB; 3 MiB admits normal line folding.
// The entity bound includes its separately bounded headers.
const RUA_ENCODED_ATTACHMENT_MAX_BYTES = 3 * 1024 * 1024;
const RUA_MIME_ENTITY_MAX_BYTES =
  RUA_ENCODED_ATTACHMENT_MAX_BYTES + RUA_MIME_HEADER_MAX_BYTES;
const RUA_STREAM_CONVERSION_CHUNK_BYTES = 32 * 1024;
// A stream chunk may contain the delimiter immediately after the maximum entity.
// This is the absolute retained MIME buffer ceiling, checked before concatenation.
const RUA_MIME_BUFFER_MAX_BYTES =
  RUA_MIME_ENTITY_MAX_BYTES + RUA_STREAM_CONVERSION_CHUNK_BYTES + 206;
const BASE64_DECODE_CHUNK_CHARS = 32 * 1024;         // divisible by four
// Conservative app-owned per-invocation envelope (not a runtime measurement):
// raw envelope + ONE candidate MIME entity (counted as a conservative two-byte
// JS string) + decoded attachment + bounded decompression chunks/output/decoded
// text + a bounded header/chunk tail per nesting level. Parent parsers retain no
// entity body while a child is active. Implementations below may retain less,
// but must never add an unbounded term.
const RUA_PARSER_MAX_RETAINED_BYTES =
  RUA_RAW_EMAIL_MAX_BYTES +
  (2 * RUA_MIME_BUFFER_MAX_BYTES) +
  RUA_ATTACHMENT_MAX_BYTES +
  (3 * RUA_DECOMPRESSED_MAX_BYTES) +
  ((RUA_MAX_MIME_DEPTH + 1) * RUA_MIME_HEADER_MAX_BYTES) +
  ((RUA_MAX_MIME_DEPTH + 2) * RUA_STREAM_CONVERSION_CHUNK_BYTES) +
  (RUA_MAX_MIME_DEPTH * 206);

const RUA_DEFAULT_CAPS = {
  attachmentMax: RUA_ATTACHMENT_MAX_BYTES,
  decompressedMax: RUA_DECOMPRESSED_MAX_BYTES,
  ratioMax: RUA_MAX_COMPRESSION_RATIO,
};

function _limitExceeded(reason, name, observed, maximum) {
  const error = new Error(reason);
  error.limit_name = name;
  error.observed = observed;
  error.maximum = maximum;
  return error;
}

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
function _latin1ToBytes(str, start = 0, end = str.length) {
  const out = new Uint8Array(end - start);
  for (let i = start; i < end; i++) out[i - start] = str.charCodeAt(i) & 0xff;
  return out;
}
function _bytesToLatin1(bytes) {
  let s = ""; const CH = 0x8000;
  for (let i = 0; i < bytes.length; i += CH) s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
  return s;
}
function _isBase64Code(code) {
  return (code >= 65 && code <= 90) || (code >= 97 && code <= 122) ||
    (code >= 48 && code <= 57) || code === 43 || code === 47;
}

// Validate and size base64 before allocating decoded output. Decoding then uses
// fixed 32 KiB encoded chunks, avoiding simultaneous full-size compact and
// atob-result strings.
function _base64ToBytes(
  input,
  maxDecodedBytes = RUA_ATTACHMENT_MAX_BYTES,
  maxEncodedBytes = RUA_ENCODED_ATTACHMENT_MAX_BYTES,
  start = 0,
  end = typeof input === "string" ? input.length : 0,
) {
  if (typeof input !== "string" || start < 0 || end < start ||
      end > input.length) {
    throw new Error("attachment_too_large");
  }
  if (end - start > maxEncodedBytes) {
    throw _limitExceeded(
      "attachment_too_large",
      "encoded_attachment_bytes",
      end - start,
      maxEncodedBytes,
    );
  }
  let encodedChars = 0;
  let padding = 0;
  let sawPadding = false;
  for (let i = start; i < end; i++) {
    const code = input.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13 || code === 32) continue;
    if (code === 61) {
      sawPadding = true;
      padding += 1;
      if (padding > 2) throw new Error("invalid_base64");
    } else {
      if (!_isBase64Code(code) || sawPadding) throw new Error("invalid_base64");
    }
    encodedChars += 1;
  }
  if (!encodedChars || encodedChars % 4 === 1) throw new Error("invalid_base64");
  const decodedLength = Math.floor((encodedChars * 3) / 4) - padding;
  if (decodedLength < 0) throw new Error("invalid_base64");
  if (decodedLength > maxDecodedBytes) {
    throw _limitExceeded(
      "attachment_too_large",
      "transfer_decoded_attachment_bytes",
      decodedLength,
      maxDecodedBytes,
    );
  }

  const out = new Uint8Array(decodedLength);
  let encodedChunk = "";
  let offset = 0;
  const flush = () => {
    if (!encodedChunk) return;
    let decoded;
    try { decoded = atob(encodedChunk); }
    catch { throw new Error("invalid_base64"); }
    if (offset + decoded.length > out.length) throw new Error("invalid_base64");
    for (let i = 0; i < decoded.length; i++) out[offset + i] = decoded.charCodeAt(i);
    offset += decoded.length;
    encodedChunk = "";
  };
  for (let i = start; i < end; i++) {
    const code = input.charCodeAt(i);
    if (code === 9 || code === 10 || code === 13 || code === 32) continue;
    encodedChunk += input[i];
    if (encodedChunk.length === BASE64_DECODE_CHUNK_CHARS) flush();
  }
  flush();
  if (offset !== decodedLength) throw new Error("invalid_base64");
  return out;
}
function _readU16(b, o) { return b[o] | (b[o + 1] << 8); }
function _readU32(b, o) { return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; }

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
    case "multiple_tlsrpt_attachments": return "multiple_tlsrpt_attachments";
    case "email_too_large":          return "email_too_large";
    case "attachment_too_large":
    case "zip_too_large":           return "attachment_too_large";
    case "decompressed_too_large":  return "decompressed_too_large";
    case "compression_ratio_exceeded": return "compression_ratio_exceeded";
    case "domain_mismatch":         return "domain_mismatch";
    case "invalid_base64":          return "invalid_base64";
    case "stream_read_error":        return "stream_read_error";
    case "truncated_mime":           return "truncated_mime";
    case "unterminated_multipart":   return "unterminated_multipart";
    case "header_too_large":         return "header_too_large";
    case "invalid_mime":             return "invalid_mime";
    case "mime_complexity_exceeded": return "mime_complexity_exceeded";
    case "mime_nesting_too_deep":    return "mime_nesting_too_deep";
    case "unsupported_transfer_encoding": return "unsupported_transfer_encoding";
    case "report_row_limit_exceeded": return "report_row_limit_exceeded";
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
    case "email_too_large":
    case "attachment_too_large":
    case "decompressed_too_large":
    case "compression_ratio_exceeded":
    case "report_row_limit_exceeded":
      return "The report attachment was larger than the supported size.";
    case "invalid_base64":
      return "The report attachment used an invalid transfer encoding and could not be read.";
    default:
      return "The report attachment could not be read. Occasional malformed reports from providers are normal — no action is needed unless this keeps happening.";
  }
}

// Sanitize internal platform errors (e.g. Cloudflare subrequest-budget messages)
// before they can surface to customers. Genuine findings pass through unchanged.

// ── bounded streaming MIME parsing (no external lib) ─────────────────────────
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

function _headerBoundary(raw, end = raw.length) {
  const crlf = raw.indexOf("\r\n\r\n");
  const lf = raw.indexOf("\n\n");
  const boundedCrlf = crlf >= 0 && crlf + 4 <= end ? crlf : -1;
  const boundedLf = lf >= 0 && lf + 2 <= end ? lf : -1;
  if (boundedCrlf < 0) {
    return boundedLf < 0 ? null : { index: boundedLf, length: 2 };
  }
  if (boundedLf < 0 || boundedCrlf <= boundedLf) {
    return { index: boundedCrlf, length: 4 };
  }
  return { index: boundedLf, length: 2 };
}

function _isDmarcAttachment(contentType, filename) {
  const n = (filename || "").toLowerCase();
  const ct = (contentType || "").toLowerCase();
  const extOk = n.endsWith(".gz") || n.endsWith(".gzip") ||
    n.endsWith(".zip") || n.endsWith(".xml");
  const ctOk = ["application/gzip", "application/x-gzip", "application/zip",
    "application/x-zip-compressed", "text/xml", "application/xml"].includes(ct);
  return extOk || ctOk || (ct === "application/octet-stream" && extOk);
}

function _isTlsRptAttachment(contentType, filename) {
  const n = (filename || "").toLowerCase();
  const ct = (contentType || "").toLowerCase();
  return ct === "application/tlsrpt+gzip" || ct === "application/tlsrpt+json" ||
    n.endsWith(".json") || n.endsWith(".json.gz");
}

function _withoutTrailingLineBreakEnd(value, start, end) {
  if (end - start >= 2 && value[end - 2] === "\r" && value[end - 1] === "\n") {
    return end - 2;
  }
  if (end > start && value[end - 1] === "\n") return end - 1;
  return end;
}

function _findMimeBoundary(body, marker, from = 0) {
  let index = body.indexOf(marker, from);
  while (index >= 0) {
    const atLineStart = index === 0 || body[index - 1] === "\n";
    const after = index + marker.length;
    // A marker ending exactly at the current stream chunk is incomplete: its
    // closing "--" or line ending may arrive in the next chunk.
    const validEnd = body.startsWith("--", after) ||
      body.startsWith("\r\n", after) || body[after] === "\n";
    if (atLineStart && validEnd) return index;
    index = body.indexOf(marker, index + marker.length);
  }
  return -1;
}

function _afterMimeBoundaryLine(body, index, marker) {
  let cursor = index + marker.length;
  const closing = body.startsWith("--", cursor);
  if (closing) cursor += 2;
  while (body[cursor] === " " || body[cursor] === "\t") cursor += 1;
  if (body.startsWith("\r\n", cursor)) cursor += 2;
  else if (body[cursor] === "\n") cursor += 1;
  else if (cursor !== body.length) throw new Error("invalid_mime");
  return { cursor, closing };
}

function _newMimeState() {
  return {
    parts: [],
    candidateKind: null,
    entityCount: 0,
    maxDepth: 0,
    maxBufferedBytes: 0,
    totalBytes: 0,
  };
}

function _describeMimeEntity(headerText, state) {
  if (headerText.length > RUA_MIME_HEADER_MAX_BYTES) {
    throw _limitExceeded(
      "header_too_large",
      "mime_header_bytes",
      headerText.length,
      RUA_MIME_HEADER_MAX_BYTES,
    );
  }

  const headers = _parseMimeHeaders(headerText);
  const ctypeRaw = headers["content-type"] || "";
  const contentType = ctypeRaw.split(";")[0].trim().toLowerCase();
  if (contentType.startsWith("multipart/")) {
    return {
      kind: "multipart",
      boundary: _mimeParam(ctypeRaw, "boundary"),
    };
  }

  const encoding = (headers["content-transfer-encoding"] || "7bit").trim().toLowerCase();
  const filename = _mimeParam(headers["content-disposition"], "filename") ||
    _mimeParam(ctypeRaw, "name");
  if (!_isDmarcAttachment(contentType, filename) &&
      !_isTlsRptAttachment(contentType, filename)) {
    return { kind: "ignored" };
  }

  // Keep exactly one decoded report candidate. A second candidate is rejected
  // from its headers before its encoded body is decoded or retained separately.
  const candidateKind = _isTlsRptAttachment(contentType, filename) ? "tlsrpt" : "dmarc";
  if (state.parts.length) {
    const firstKind = state.candidateKind;
    if (candidateKind === "tlsrpt" && firstKind === "tlsrpt") {
      throw new Error("multiple_tlsrpt_attachments");
    }
    if (candidateKind === "dmarc" && firstKind === "dmarc") {
      throw new Error("multiple_dmarc_attachments");
    }
    throw new Error("multiple_attachments");
  }
  return {
    kind: "candidate",
    candidateKind,
    contentType,
    encoding,
    filename,
  };
}

function _decodeMimeCandidate(descriptor, rawBody, bodyStart, bodyEnd, state) {
  const leafEnd = _withoutTrailingLineBreakEnd(rawBody, bodyStart, bodyEnd);
  const leafLength = leafEnd - bodyStart;
  let bytes;
  if (descriptor.encoding === "base64") {
    if (leafLength > RUA_ENCODED_ATTACHMENT_MAX_BYTES) {
      throw _limitExceeded(
        "attachment_too_large",
        "encoded_attachment_bytes",
        leafLength,
        RUA_ENCODED_ATTACHMENT_MAX_BYTES,
      );
    }
    bytes = _base64ToBytes(
      rawBody,
      RUA_ATTACHMENT_MAX_BYTES,
      RUA_ENCODED_ATTACHMENT_MAX_BYTES,
      bodyStart,
      leafEnd,
    );
  } else if (["7bit", "8bit", "binary"].includes(descriptor.encoding)) {
    if (leafLength > RUA_ATTACHMENT_MAX_BYTES) {
      throw _limitExceeded(
        "attachment_too_large",
        "transfer_decoded_attachment_bytes",
        leafLength,
        RUA_ATTACHMENT_MAX_BYTES,
      );
    }
    bytes = _latin1ToBytes(rawBody, bodyStart, leafEnd);
  } else {
    throw new Error("unsupported_transfer_encoding");
  }
  state.candidateKind = descriptor.candidateKind;
  // Safe envelope diagnostics for the offline Gate 5 preflight. These counts
  // describe only the selected attachment body; no header or body content is
  // retained beyond the existing bounded parser state.
  state.parts.push({
    contentType: descriptor.contentType,
    encoding: descriptor.encoding,
    filename: descriptor.filename,
    bytes,
    encoded_size: leafLength,
    transfer_decoded_size: bytes.length,
  });
}

function _parseMimeEntity(headerText, rawBody, bodyStart, bodyEnd, state) {
  const descriptor = _describeMimeEntity(headerText, state);
  if (descriptor.kind === "multipart") throw new Error("invalid_mime");
  if (descriptor.kind === "candidate") {
    _decodeMimeCandidate(descriptor, rawBody, bodyStart, bodyEnd, state);
  }
}

class StreamingMultipartParser {
  constructor(
    boundary,
    state,
    depth = 1,
    maxDepth = RUA_MAX_MIME_DEPTH,
  ) {
    if (!boundary || boundary.length > 200 || /[\r\n]/.test(boundary)) {
      throw new Error("invalid_mime");
    }
    if (!Number.isInteger(depth) || depth < 1 || depth > maxDepth) {
      throw new Error("mime_nesting_too_deep");
    }
    this.marker = `--${boundary}`;
    this.state = state;
    this.depth = depth;
    this.maxDepth = maxDepth;
    this.buffer = "";
    this.started = false;
    this.closed = false;
    this.mode = "preamble";
    this.descriptor = null;
    this.child = null;
    this.searchFrom = 0;
    this.state.maxDepth = Math.max(this.state.maxDepth, depth);
  }

  beginPart() {
    this.state.entityCount += 1;
    if (this.state.entityCount > RUA_MAX_MIME_PARTS) {
      throw _limitExceeded(
        "mime_complexity_exceeded",
        "mime_parts",
        this.state.entityCount,
        RUA_MAX_MIME_PARTS,
      );
    }
    this.mode = "headers";
    this.descriptor = null;
    this.child = null;
    this.searchFrom = 0;
  }

  append(text, maximum = RUA_MIME_BUFFER_MAX_BYTES) {
    if (!text) return;
    if (text.length > RUA_STREAM_CONVERSION_CHUNK_BYTES ||
        this.buffer.length + text.length > maximum) {
      throw _limitExceeded(
        "attachment_too_large",
        "retained_mime_buffer_bytes",
        this.buffer.length + text.length,
        maximum,
      );
    }
    this.buffer += text;
    this.state.maxBufferedBytes = Math.max(
      this.state.maxBufferedBytes,
      this.buffer.length,
    );
  }

  trimDiscardTail() {
    const keep = this.marker.length + 8;
    if (this.buffer.length > keep) {
      this.buffer = this.buffer.slice(-keep);
      this.searchFrom = 0;
    }
  }

  consumeBoundary(boundaryIndex) {
    const line = _afterMimeBoundaryLine(this.buffer, boundaryIndex, this.marker);
    const remainder = this.buffer.slice(line.cursor);
    this.buffer = "";
    this.searchFrom = 0;
    this.descriptor = null;
    this.child = null;
    if (line.closing) {
      this.closed = true;
      this.mode = "closed";
      return remainder;
    }
    this.beginPart();
    this.buffer = remainder;
    return null;
  }

  push(text) {
    if (this.closed) return text || "";
    let incoming = text || "";

    for (;;) {
      if (this.mode === "child") {
        const remainder = this.child.push(incoming);
        incoming = "";
        if (!this.child.closed) return "";
        this.child = null;
        this.mode = "discard";
        incoming = remainder;
        continue;
      }

      if (incoming) {
        const maximum = this.mode === "headers"
          ? RUA_MIME_HEADER_MAX_BYTES + 4
          : RUA_MIME_BUFFER_MAX_BYTES;
        if (this.mode === "headers" &&
            this.buffer.length + incoming.length > maximum) {
          const allowed = maximum - this.buffer.length;
          if (allowed <= 0) {
            throw _limitExceeded(
              "header_too_large",
              "mime_header_bytes",
              this.buffer.length + incoming.length,
              RUA_MIME_HEADER_MAX_BYTES,
            );
          }
          this.append(incoming.slice(0, allowed), maximum);
          incoming = incoming.slice(allowed);
        } else {
          this.append(incoming, maximum);
          incoming = "";
        }
      }

      if (this.mode === "preamble") {
        const boundaryIndex = _findMimeBoundary(
          this.buffer,
          this.marker,
          this.searchFrom,
        );
        if (boundaryIndex < 0) {
          this.trimDiscardTail();
          return "";
        }
        this.buffer = this.buffer.slice(boundaryIndex);
        const first = _afterMimeBoundaryLine(this.buffer, 0, this.marker);
        const remainder = this.buffer.slice(first.cursor);
        this.buffer = "";
        this.started = true;
        if (first.closing) {
          this.closed = true;
          this.mode = "closed";
          return remainder;
        }
        this.beginPart();
        this.buffer = remainder;
        continue;
      }

      if (this.mode === "headers") {
        const header = _headerBoundary(this.buffer);
        if (!header) {
          if (this.buffer.length > RUA_MIME_HEADER_MAX_BYTES) {
            throw _limitExceeded(
              "header_too_large",
              "mime_header_bytes",
              this.buffer.length,
              RUA_MIME_HEADER_MAX_BYTES,
            );
          }
          return "";
        }
        if (header.index > RUA_MIME_HEADER_MAX_BYTES) {
          throw _limitExceeded(
            "header_too_large",
            "mime_header_bytes",
            header.index,
            RUA_MIME_HEADER_MAX_BYTES,
          );
        }
        const headerText = this.buffer.slice(0, header.index);
        const firstBody = this.buffer.slice(header.index + header.length);
        this.buffer = "";
        const descriptor = _describeMimeEntity(headerText, this.state);
        if (descriptor.kind === "multipart") {
          const childDepth = this.depth + 1;
          if (childDepth > this.maxDepth) {
            throw new Error("mime_nesting_too_deep");
          }
          this.child = new StreamingMultipartParser(
            descriptor.boundary,
            this.state,
            childDepth,
            this.maxDepth,
          );
          this.mode = "child";
          incoming = firstBody;
          continue;
        }
        this.descriptor = descriptor;
        this.mode = descriptor.kind === "candidate" ? "candidate" : "discard";
        incoming = firstBody;
        continue;
      }

      if (this.mode === "candidate" || this.mode === "discard") {
        const boundaryIndex = _findMimeBoundary(
          this.buffer,
          this.marker,
          this.searchFrom,
        );
        if (boundaryIndex < 0) {
          this.searchFrom = Math.max(
            0,
            this.buffer.length - this.marker.length - 4,
          );
          if (this.mode === "candidate") {
            if (this.buffer.length > RUA_MIME_ENTITY_MAX_BYTES) {
              throw _limitExceeded(
                "attachment_too_large",
                "mime_entity_bytes",
                this.buffer.length,
                RUA_MIME_ENTITY_MAX_BYTES,
              );
            }
          } else {
            // Preamble, human-readable leaves, and nested multipart epilogues
            // are not evidence. Stream-discard them while retaining only the
            // delimiter tail needed across chunk boundaries.
            this.trimDiscardTail();
          }
          return "";
        }

        if (this.mode === "candidate") {
          const entityEnd = _withoutTrailingLineBreakEnd(
            this.buffer,
            0,
            boundaryIndex,
          );
          _decodeMimeCandidate(
            this.descriptor,
            this.buffer,
            0,
            entityEnd,
            this.state,
          );
        }
        const remainder = this.consumeBoundary(boundaryIndex);
        if (this.closed) return remainder;
        continue;
      }

      throw new Error("invalid_mime");
    }
  }

  finish() {
    if (this.child && !this.child.closed) this.child.finish();
    if (this.started && !this.closed && this.mode === "headers") {
      throw new Error("truncated_mime");
    }
    if (!this.started || !this.closed) throw new Error("unterminated_multipart");
  }
}

async function parseMimeMessageStream(
  stream,
  maxBytes = RUA_RAW_EMAIL_MAX_BYTES,
  maxDepth = RUA_MAX_MIME_DEPTH,
) {
  if (!stream || typeof stream.getReader !== "function") throw new Error("invalid_mime");
  if (!Number.isInteger(maxDepth) || maxDepth < 1 ||
      maxDepth > RUA_MAX_MIME_DEPTH) {
    throw new Error("mime_nesting_too_deep");
  }
  let reader;
  try { reader = stream.getReader(); }
  catch { throw new Error("stream_read_error"); }
  const state = _newMimeState();
  let rootHeaderBuffer = "";
  let rootHeaderText = null;
  let rootHeaders = null;
  let multipart = null;
  let leafBody = "";

  try {
    for (;;) {
      let read;
      try { read = await reader.read(); }
      catch { throw new Error("stream_read_error"); }
      const { done, value } = read;
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error("invalid_mime");
      state.totalBytes += value.byteLength;
      if (state.totalBytes > maxBytes) {
        throw _limitExceeded(
          "email_too_large",
          "raw_email_bytes",
          state.totalBytes,
          maxBytes,
        );
      }
      for (let offset = 0; offset < value.byteLength;
        offset += RUA_STREAM_CONVERSION_CHUNK_BYTES) {
        const text = _bytesToLatin1(value.subarray(
          offset,
          Math.min(value.byteLength, offset + RUA_STREAM_CONVERSION_CHUNK_BYTES),
        ));

        if (rootHeaderText == null) {
          if (rootHeaderBuffer.length + text.length > RUA_MIME_HEADER_MAX_BYTES) {
            throw _limitExceeded(
              "header_too_large",
              "mime_header_bytes",
              rootHeaderBuffer.length + text.length,
              RUA_MIME_HEADER_MAX_BYTES,
            );
          }
          rootHeaderBuffer += text;
          const separator = _headerBoundary(rootHeaderBuffer);
          if (!separator) continue;
          rootHeaderText = rootHeaderBuffer.slice(0, separator.index);
          const firstBody = rootHeaderBuffer.slice(separator.index + separator.length);
          rootHeaderBuffer = "";
          rootHeaders = _parseMimeHeaders(rootHeaderText);
          const ctypeRaw = rootHeaders["content-type"] || "";
          const contentType = ctypeRaw.split(";")[0].trim().toLowerCase();
          if (contentType.startsWith("multipart/")) {
            multipart = new StreamingMultipartParser(
              _mimeParam(ctypeRaw, "boundary"),
              state,
              1,
              maxDepth,
            );
            multipart.push(firstBody);
          } else {
            state.entityCount = 1;
            leafBody = firstBody;
          }
          continue;
        }

        if (multipart) multipart.push(text);
        else {
          if (leafBody.length + text.length > RUA_MIME_ENTITY_MAX_BYTES) {
            throw _limitExceeded(
              "attachment_too_large",
              "mime_entity_bytes",
              leafBody.length + text.length,
              RUA_MIME_ENTITY_MAX_BYTES,
            );
          }
          leafBody += text;
          state.maxBufferedBytes = Math.max(state.maxBufferedBytes, leafBody.length);
        }
      }
    }
  } catch (error) {
    try { await reader.cancel(); } catch { /* ignore */ }
    throw error;
  }

  if (rootHeaderText == null) throw new Error("truncated_mime");
  if (multipart) multipart.finish();
  else _parseMimeEntity(rootHeaderText, leafBody, 0, leafBody.length, state);
  return {
    headerText: rootHeaderText,
    parts: state.parts,
    stats: {
      total_bytes: state.totalBytes,
      max_buffered_bytes: state.maxBufferedBytes,
      entity_count: state.entityCount,
      max_depth: state.maxDepth,
    },
  };
}

// Bounded compatibility helper retained for existing internal test consumers.
// Production ingress uses parseMimeMessageStream(); this helper likewise feeds
// one fixed-size slice at a time and never splits/materialises all MIME parts.
function parseMimeParts(rawLatin1) {
  if (typeof rawLatin1 !== "string") throw new Error("invalid_mime");
  if (rawLatin1.length > RUA_RAW_EMAIL_MAX_BYTES) throw new Error("email_too_large");
  const separator = _headerBoundary(rawLatin1);
  if (!separator) throw new Error("truncated_mime");
  if (separator.index > RUA_MIME_HEADER_MAX_BYTES) throw new Error("header_too_large");

  const state = _newMimeState();
  const headerText = rawLatin1.slice(0, separator.index);
  const headers = _parseMimeHeaders(headerText);
  const ctypeRaw = headers["content-type"] || "";
  const contentType = ctypeRaw.split(";")[0].trim().toLowerCase();
  const bodyStart = separator.index + separator.length;
  if (contentType.startsWith("multipart/")) {
    const parser = new StreamingMultipartParser(_mimeParam(ctypeRaw, "boundary"), state);
    for (let offset = bodyStart; offset < rawLatin1.length;
      offset += RUA_STREAM_CONVERSION_CHUNK_BYTES) {
      parser.push(rawLatin1.slice(
        offset,
        Math.min(rawLatin1.length, offset + RUA_STREAM_CONVERSION_CHUNK_BYTES),
      ));
    }
    parser.finish();
  } else {
    state.entityCount = 1;
    _parseMimeEntity(headerText, rawLatin1, bodyStart, rawLatin1.length, state);
  }
  return state.parts;
}

// Choose exactly one DMARC report attachment. Zero or more-than-one → error
// (deterministic, documented MVP behaviour).
function selectDmarcAttachment(parts) {
  const candidates = (parts || []).filter((p) =>
    _isDmarcAttachment(p.contentType, p.filename));
  if (candidates.length === 0) return { error: "no_dmarc_attachment" };
  if (candidates.length > 1) return { error: "multiple_attachments" };
  return { part: candidates[0] };
}

// ── TLS-RPT (RFC 8460) attachment handling ────────────────────────────────────
// TLS-RPT reports arrive at the same mailbox as DMARC but are JSON. Detect them
// so the handler can route to the JSON path; absence of a match just means "not
// TLS-RPT, try DMARC" (returns { part: null }, never an error).
function selectTlsRptAttachment(parts) {
  const candidates = (parts || []).filter((p) =>
    _isTlsRptAttachment(p.contentType, p.filename));
  if (candidates.length === 0) return { part: null };
  if (candidates.length > 1) return { error: "multiple_tlsrpt_attachments" };
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
// stores raw payloads. Permanent invalid mail has a required append-only audit;
// if neither a terminal nor transient audit can be persisted, the invocation
// throws rather than reporting silent success.
// Operator routing: only exact per-address Email Routing rules may target this
// Worker. Never enable catch-all routing. D1 address_local lookup is a second
// recipient gate, not permission to broaden the Cloudflare routing boundary.
export async function handleInboundEmail(message, env, _ctx, deps = {}) {
  if (typeof deps.consumeApiRateLimit !== "function" ||
      typeof deps.rateLimitScopeId !== "function") {
    throw new Error("inbound_rate_limiter_not_wired");
  }
  const caps = {
    attachmentMax: RUA_ATTACHMENT_MAX_BYTES,
    decompressedMax: RUA_DECOMPRESSED_MAX_BYTES,
    ratioMax: RUA_MAX_COMPRESSION_RATIO,
  };
  // Drop safely with a STABLE, customer-safe reason and no raw payload.
  // `kind` labels the report type in customer-facing text ("DMARC"/"TLS-RPT").
  const drop = async (endpoint, rawReason, recipient = null, kind = "DMARC") => {
    const reason = normalizeInboundDropReason(rawReason);
    // The append-only audit is the terminal outcome. It is intentionally not
    // swallowed: if D1 cannot durably record it, the outer handler records a
    // transient failure or rethrows so the delivery never looks successful.
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
      required: true,
    });

    // Customer visibility is best-effort after the durable terminal audit.
    if (endpoint?.workspace_id && endpoint?.domain) {
      try {
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
      } catch { /* the terminal audit above is already durable */ }
    }
    return reason;
  };

  let activeEndpoint = null;
  let activeRecipient = null;
  let activeKind = "aggregate";
  try {
    const recipient = parseInboundRecipient(message.to);
    activeRecipient = recipient;
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
    activeEndpoint = endpoint;
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
    const scopeId = await deps.rateLimitScopeId("rua_inbound", endpoint.id);
    const limited = await deps.consumeApiRateLimit(env,
      [{ scope: "rua_inbound_endpoint", scope_id: scopeId }],
      "rua_inbound", 120, 3600);
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

    if (typeof message.rawSize === "number" && message.rawSize > RUA_RAW_EMAIL_MAX_BYTES) {
      await drop(endpoint, "email_too_large", recipient); return;
    }
    let parsedMessage;
    try {
      parsedMessage = await parseMimeMessageStream(
        message.raw,
        RUA_RAW_EMAIL_MAX_BYTES,
      );
    } catch (error) {
      await drop(endpoint, error?.message || "parse_error", recipient);
      return;
    }
    const parts = parsedMessage.parts;

    // Record bounded sender claims from root headers only. A recognised public-
    // mail header-From is metadata, not authority; retaining the message body is
    // unnecessary and would defeat the streaming memory boundary.
    const provenance = deriveInboundReportProvenance(
      parsedMessage.headerText,
      message,
      endpoint.domain,
    );

    // Route by attachment type: TLS-RPT (JSON) → its own parser; DMARC XML falls
    // through to the existing path, byte-for-byte unchanged.
    const tlsSel = selectTlsRptAttachment(parts);
    if (tlsSel.error) {
      activeKind = "TLS-RPT";
      await drop(endpoint, tlsSel.error, recipient, "TLS-RPT");
      return;
    }
    if (tlsSel.part) {
      activeKind = "TLS-RPT";
      const tlsExt = await extractTlsRptFromAttachment(tlsSel.part.filename, tlsSel.part.bytes, caps);
      if (tlsExt.error) { await drop(endpoint, tlsExt.error, recipient, "TLS-RPT"); return; }
      const tlsResult = await ingestTlsRptReport(env, {
        workspaceId: endpoint.workspace_id, domain: endpoint.domain, jsonString: tlsExt.json,
        ingestEndpointId: endpoint.id, domainId: endpoint.domain_id, enforceDomainMatch: true, provenance,
      });
      if (!tlsResult.ok) {
        if (tlsResult.transient && tlsResult.audited) return;
        await drop(endpoint, tlsResult.error, recipient, "TLS-RPT");
        return;
      }
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
          raw_email_size: parsedMessage.stats.total_bytes,
          encoded_attachment_size: tlsSel.part.encoded_size,
          mime_part_count: parsedMessage.stats.entity_count,
          nested_multipart: false,
          auth_verdict: provenance.auth_verdict, reporter_domain: provenance.reporter_domain,
        },
      }).catch(() => {});
      return;
    }

    const sel = selectDmarcAttachment(parts);
    activeKind = "DMARC";
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
    if (!result.ok) {
      if (result.transient && result.audited) return;
      await drop(endpoint, result.error, recipient);
      return;
    }

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
        raw_email_size: parsedMessage.stats.total_bytes,
        encoded_attachment_size: sel.part.encoded_size,
        mime_part_count: parsedMessage.stats.entity_count,
        nested_multipart: false,
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
    try {
      await createAuditEvent(env, {
        workspace_id: activeEndpoint?.workspace_id || null,
        user_id: null,
        event_type: "aggregate_report_inbound_transient_failure",
        entity_type: "domain",
        entity_id: activeEndpoint?.domain_id || null,
        description: `Inbound ${activeKind} ingestion failed before a terminal outcome`,
        metadata: {
          source: "inbound_email",
          reason: "transient_platform_failure",
          repairable: true,
          recipient_localpart: activeRecipient?.localpart || null,
          recipient_domain: activeRecipient?.domain || null,
        },
        required: true,
      });
    } catch {
      // Neither persistence nor the append-only quarantine audit succeeded.
      // Rethrow so Cloudflare records a failed invocation; never report success.
      throw e;
    }
  }
}

// Exported for index.js re-export → the test harnesses.
export {
  RUA_ATTACHMENT_MAX_BYTES,
  RUA_DECOMPRESSED_MAX_BYTES,
  RUA_ENCODED_ATTACHMENT_MAX_BYTES,
  RUA_MAX_MIME_DEPTH,
  RUA_MAX_MIME_PARTS,
  RUA_MIME_BUFFER_MAX_BYTES,
  RUA_MIME_ENTITY_MAX_BYTES,
  RUA_MIME_HEADER_MAX_BYTES,
  RUA_PARSER_MAX_RETAINED_BYTES,
  RUA_RAW_EMAIL_MAX_BYTES,
  _base64ToBytes,
  deriveInboundReportProvenance,
  extractDmarcXmlFromAttachment,
  extractEmailDomainFromHeader,
  extractInboundLocalpart,
  extractSingleFromDomain,
  extractTlsRptFromAttachment,
  gunzipXmlBytes,
  isKnownDmarcReporter,
  normalizeInboundDropReason,
  parseInboundRecipient,
  parseMimeMessageStream,
  parseMimeParts,
  selectDmarcAttachment,
  selectTlsRptAttachment,
  unzipSingleEntryXmlBytes,
};
