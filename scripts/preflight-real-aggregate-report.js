#!/usr/bin/env node
//
// PR-5.5 Gate 5 — offline, read-only envelope/schema preflight for one captured
// RFC822 DMARC RUA or TLS-RPT message. This tool performs no D1, R2, network,
// Email Routing, DNS, or Worker mutation. It drives the production parser and
// reports the terminal audit outcome that delivery would take.
//
// Usage:
//   node scripts/preflight-real-aggregate-report.js \
//     --file /absolute/path/to/report.eml \
//     --expect-domain cybermeters.com
//
import fs from "node:fs";
import path from "node:path";
import { Readable } from "node:stream";

import {
  RUA_ATTACHMENT_MAX_BYTES,
  RUA_DECOMPRESSED_MAX_BYTES,
  RUA_ENCODED_ATTACHMENT_MAX_BYTES,
  RUA_MAX_MIME_PARTS,
  RUA_MIME_HEADER_MAX_BYTES,
  RUA_RAW_EMAIL_MAX_BYTES,
  extractDmarcXmlFromAttachment,
  extractTlsRptFromAttachment,
  normalizeInboundDropReason,
  parseMimeMessageStream,
  selectDmarcAttachment,
  selectTlsRptAttachment,
} from "../workers/scan-api/src/email/inbound.js";
import {
  dmarcReportDomainMatches,
  parseDmarcAggregateXml,
} from "../workers/scan-api/src/lib/dmarc-ingest.js";
import { parseTlsRptReport } from "../workers/scan-api/src/lib/tlsrpt-ingest.js";

const argv = process.argv.slice(2);
const valueOf = (name) => {
  const index = argv.indexOf(name);
  return index >= 0 ? argv[index + 1] : null;
};
const fileArg = valueOf("--file");
const expectedDomain = String(valueOf("--expect-domain") || "")
  .trim()
  .toLowerCase()
  .replace(/\.$/, "");

function usage() {
  console.error(
    "Usage: node scripts/preflight-real-aggregate-report.js " +
    "--file /absolute/path/report.eml --expect-domain example.com",
  );
}

if (!fileArg || !expectedDomain || !/^[a-z0-9.-]+$/.test(expectedDomain)) {
  usage();
  process.exit(64);
}

const inputPath = path.resolve(fileArg);
let stat;
try {
  stat = fs.statSync(inputPath);
} catch {
  console.error(`Cannot read captured message: ${inputPath}`);
  process.exit(66);
}
if (!stat.isFile()) {
  console.error(`Captured message is not a regular file: ${inputPath}`);
  process.exit(66);
}

const limits = {
  raw_email_bytes: RUA_RAW_EMAIL_MAX_BYTES,
  root_or_part_header_bytes: RUA_MIME_HEADER_MAX_BYTES,
  mime_parts: RUA_MAX_MIME_PARTS,
  encoded_attachment_bytes: RUA_ENCODED_ATTACHMENT_MAX_BYTES,
  transfer_decoded_attachment_bytes: RUA_ATTACHMENT_MAX_BYTES,
  decoded_report_body_bytes: RUA_DECOMPRESSED_MAX_BYTES,
};

function finish(outcome, details = {}) {
  const result = {
    schema: "cybermeters.aggregate-report-envelope-preflight/v1",
    mode: "offline_read_only",
    production_mutated: false,
    captured_file: path.basename(inputPath),
    expected_domain: expectedDomain,
    outcome,
    limits,
    ...details,
  };
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  if (outcome !== "PASS") process.exitCode = 2;
}

function reject(reason, details = {}) {
  const parserReason = String(reason || "parse_error");
  const auditedReason = normalizeInboundDropReason(parserReason);
  finish("AUDITED_REJECT", {
    parser_reason: parserReason,
    audited_reason: auditedReason,
    // The production terminal-drop contract uses one canonical event type for
    // both report formats; the event description records DMARC vs TLS-RPT.
    terminal_audit_event: "dmarc_inbound_email_dropped",
    ...details,
  });
}

let message;
try {
  const nodeStream = fs.createReadStream(inputPath, {
    highWaterMark: 32 * 1024,
  });
  message = await parseMimeMessageStream(
    Readable.toWeb(nodeStream),
    RUA_RAW_EMAIL_MAX_BYTES,
  );
} catch (error) {
  reject(error?.message, {
    raw_email_bytes: stat.size,
    limit_hit: error?.limit_name ? {
      name: error.limit_name,
      observed: error.observed ?? null,
      maximum: error.maximum ?? null,
    } : null,
    nested_multipart: error?.message === "unsupported_nested_multipart"
      ? "present_rejected"
      : "unknown_on_reject",
  });
  process.exit();
}

const tlsSelection = selectTlsRptAttachment(message.parts);
if (tlsSelection.error) {
  reject(tlsSelection.error, {
    report_type: "tlsrpt",
    raw_email_bytes: message.stats.total_bytes,
    mime_entity_count: message.stats.entity_count,
    nested_multipart: false,
  });
  process.exit();
}

let reportType;
let part;
let extraction;
let claimedDomains = [];
if (tlsSelection.part) {
  reportType = "tlsrpt";
  part = tlsSelection.part;
  extraction = await extractTlsRptFromAttachment(part.filename, part.bytes);
  if (!extraction.error) {
    const parsed = parseTlsRptReport(extraction.json);
    if (!parsed.ok) {
      reject(parsed.error, envelopeDetails());
      process.exit();
    }
    claimedDomains = parsed.report.policies
      .map((policy) => String(policy.policy_domain || "").toLowerCase())
      .filter(Boolean);
    if (!claimedDomains.includes(expectedDomain)) {
      reject("domain_mismatch", envelopeDetails());
      process.exit();
    }
  }
} else {
  reportType = "dmarc";
  const dmarcSelection = selectDmarcAttachment(message.parts);
  if (dmarcSelection.error) {
    reject(dmarcSelection.error, {
      report_type: reportType,
      raw_email_bytes: message.stats.total_bytes,
      mime_entity_count: message.stats.entity_count,
      nested_multipart: false,
    });
    process.exit();
  }
  part = dmarcSelection.part;
  extraction = await extractDmarcXmlFromAttachment(part.filename, part.bytes);
  if (!extraction.error) {
    const parsed = parseDmarcAggregateXml(extraction.xml);
    if (parsed.error) {
      reject(parsed.error, envelopeDetails());
      process.exit();
    }
    claimedDomains = [parsed.policy_published.domain];
    if (!dmarcReportDomainMatches(parsed, expectedDomain)) {
      reject("domain_mismatch", envelopeDetails());
      process.exit();
    }
  }
}

function envelopeDetails() {
  return {
    report_type: reportType,
    raw_email_bytes: message.stats.total_bytes,
    encoded_attachment_bytes: part?.encoded_size ?? null,
    transfer_decoded_attachment_bytes:
      part?.transfer_decoded_size ?? part?.bytes?.byteLength ?? null,
    decoded_report_body_bytes: extraction?.decompressed_size ?? null,
    attachment_type: extraction?.attachment_type ?? null,
    content_transfer_encoding: part?.encoding ?? null,
    mime_entity_count: message.stats.entity_count,
    max_parser_buffer_bytes: message.stats.max_buffered_bytes,
    nested_multipart: false,
    claimed_domains: claimedDomains,
  };
}

if (extraction?.error) {
  const limitName = extraction.error === "decompressed_too_large"
    ? "decoded_report_body_bytes"
    : (extraction.error === "compression_ratio_exceeded"
      ? "compression_ratio"
      : (extraction.error === "attachment_too_large" ||
        extraction.error === "zip_too_large"
        ? "transfer_decoded_attachment_bytes"
        : null));
  reject(extraction.error, {
    ...envelopeDetails(),
    limit_hit: limitName ? {
      name: limitName,
      observed: limitName === "compression_ratio"
        ? null
        : (extraction.decompressed_size ??
          part?.transfer_decoded_size ?? null),
      maximum: limitName === "compression_ratio"
        ? 100
        : RUA_DECOMPRESSED_MAX_BYTES,
    } : null,
  });
} else {
  finish("PASS", {
    ...envelopeDetails(),
    terminal_audit_event: reportType === "tlsrpt"
      ? "tlsrpt_inbound_email_received"
      : "dmarc_inbound_email_received",
  });
}
