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
import { PROVIDER_MAP_VERSION, classifyWorkspaceDomainSenders } from "../engines/sender-classification.js";
import { evaluateEmailSenderMonitoring } from "../engines/email-protection-lifecycle.js";

const DMARC_XML_MAX_BYTES = 2 * 1024 * 1024; // 2 MB hard cap

const DMARC_MAX_RECORDS   = 5000;            // defensive row cap
const DMARC_MAX_MESSAGES_PER_RECORD = 10_000_000;
const DMARC_MAX_EPOCH_SECONDS = 4_102_444_800; // 2100-01-01T00:00:00Z
const DMARC_MAX_REPORT_WINDOW_SECONDS = 366 * 24 * 60 * 60;
const DMARC_AGGREGATE_PARSER_VERSION = "dmarc-aggregate-rfc9990-v1";
const DMARC_RFC9990_NAMESPACE = "urn:ietf:params:xml:ns:dmarc-2.0";

function _xmlDecodeEntities(s) {
  const raw = String(s);
  const entityPattern = /&(lt|gt|quot|apos|amp|#\d+|#x[0-9a-f]+);/gi;
  if (raw.replace(entityPattern, "").includes("&")) {
    throw new Error("invalid_xml_entity");
  }
  return raw.replace(
    entityPattern,
    (match, entity) => {
      const lower = entity.toLowerCase();
      if (lower === "lt") return "<";
      if (lower === "gt") return ">";
      if (lower === "quot") return '"';
      if (lower === "apos") return "'";
      if (lower === "amp") return "&";
      const codePoint = lower.startsWith("#x")
        ? Number.parseInt(lower.slice(2), 16)
        : Number.parseInt(lower.slice(1), 10);
      if (!Number.isInteger(codePoint) || codePoint <= 0 ||
          codePoint > 0x10ffff || (codePoint >= 0xd800 && codePoint <= 0xdfff)) {
        throw new Error("invalid_xml_entity");
      }
      return String.fromCodePoint(codePoint);
    },
  );
}

// Return raw inner content for fixed-literal tags. Decoding is deliberately
// deferred until a leaf text field is validated, so an escaped string can never
// manufacture structural tags.
function _xmlBlocks(xml, tag, limit = DMARC_MAX_RECORDS + 1) {
  if (!xml) return [];
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, "gi");
  const out = []; let m;
  while ((m = re.exec(xml)) !== null) {
    out.push(m[1]);
    if (out.length >= limit) break;
  }
  return out;
}

function _xmlFirst(xml, tag) {
  const blocks = _xmlBlocks(xml, tag, 1);
  return blocks.length ? _xmlDecodeEntities(blocks[0]).trim() : null;
}

function _schemaFailure(code, message) {
  const error = new Error(message);
  error.code = code;
  throw error;
}

function _singleXmlBlock(container, tag, { required = true } = {}) {
  const blocks = _xmlBlocks(container, tag, 2);
  if (blocks.length > 1) {
    _schemaFailure("invalid_structure", `DMARC ${tag} must appear at most once.`);
  }
  if (!blocks.length) {
    if (required) _schemaFailure("invalid_structure", `DMARC ${tag} is required.`);
    return null;
  }
  return blocks[0];
}

function _xmlText(container, tag, {
  required = false,
  maxLength = 512,
  normalize = null,
} = {}) {
  const block = _singleXmlBlock(container, tag, { required });
  if (block == null) return null;
  if (/<[^>]*>/.test(block)) {
    _schemaFailure("invalid_structure", `DMARC ${tag} must contain text only.`);
  }
  let value;
  try { value = _xmlDecodeEntities(block).trim(); }
  catch { _schemaFailure("invalid_text", `DMARC ${tag} contains an invalid entity.`); }
  if (!value) {
    if (required) _schemaFailure("invalid_structure", `DMARC ${tag} cannot be empty.`);
    return null;
  }
  if (value.length > maxLength ||
      /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)) {
    _schemaFailure("invalid_text", `DMARC ${tag} is outside the accepted text bounds.`);
  }
  return normalize ? normalize(value) : value;
}

function _boundedDmarcInteger(container, tag, {
  min = 0,
  max,
  required = true,
  code = "invalid_integer",
} = {}) {
  const text = _xmlText(container, tag, { required, maxLength: 20 });
  if (text == null) return null;
  if (!/^(?:0|[1-9]\d*)$/.test(text)) {
    _schemaFailure(code, `DMARC ${tag} must be a non-negative integer.`);
  }
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    _schemaFailure(code, `DMARC ${tag} is outside the accepted range.`);
  }
  return value;
}

function _normalizeDmarcDomain(value) {
  const normalized = String(value || "").trim().toLowerCase().replace(/\.$/, "");
  if (!normalized || normalized.length > 253 || !/^[a-z0-9.-]+$/.test(normalized)) {
    _schemaFailure("invalid_domain", "DMARC domain is invalid.");
  }
  const labels = normalized.split(".");
  if (labels.some((label) => !label || label.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) {
    _schemaFailure("invalid_domain", "DMARC domain is invalid.");
  }
  return normalized;
}

function _isIpv4(value) {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) =>
    /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function _isIpv6(value) {
  if (!/^[0-9a-f:.]+$/i.test(value) || value.includes(":::")) return false;
  const halves = value.split("::");
  if (halves.length > 2) return false;
  const groups = [];
  for (const half of halves) {
    if (!half) continue;
    groups.push(...half.split(":"));
  }
  let units = 0;
  for (let index = 0; index < groups.length; index++) {
    const group = groups[index];
    if (group.includes(".")) {
      if (index !== groups.length - 1 || !_isIpv4(group)) return false;
      units += 2;
    } else {
      if (!/^[0-9a-f]{1,4}$/i.test(group)) return false;
      units += 1;
    }
  }
  return halves.length === 2 ? units < 8 : units === 8;
}

function _validatedIp(value) {
  const candidate = String(value || "").trim().toLowerCase();
  if (!_isIpv4(candidate) && !_isIpv6(candidate)) {
    _schemaFailure("invalid_source_ip", "DMARC source_ip is invalid.");
  }
  return candidate;
}

function _enumValue(container, tag, allowed, { required = true } = {}) {
  const value = _xmlText(container, tag, {
    required,
    maxLength: 32,
    normalize: (text) => text.toLowerCase(),
  });
  if (value == null) return null;
  if (!allowed.has(value)) {
    _schemaFailure("invalid_enum", `DMARC ${tag} has an unsupported value.`);
  }
  return value;
}

const DMARC_POLICY_VALUES = new Set(["none", "quarantine", "reject"]);
const DMARC_ALIGNMENT_VALUES = new Set(["r", "s"]);
const DMARC_DISCOVERY_METHOD_VALUES = new Set(["psl", "treewalk"]);
const DMARC_TESTING_VALUES = new Set(["n", "y"]);
const DMARC_EVALUATED_VALUES = new Set(["pass", "fail"]);
const DMARC_DKIM_RESULTS = new Set([
  "none", "pass", "fail", "policy", "neutral", "temperror", "permerror",
]);
const DMARC_SPF_RESULTS = new Set([
  "none", "neutral", "pass", "fail", "softfail", "temperror", "permerror",
]);
const DMARC_SUPPORTED_DEFAULT_NAMESPACES = new Set([
  "http://dmarc.org/dmarc-xml/0.1",
  "urn:ietf:params:xml:ns:dmarc-2.0",
]);

const DMARC_CRITICAL_ELEMENT_PARENTS = new Map([
  ["feedback", new Set([null])],
  ["version", new Set(["feedback"])],
  ["report_metadata", new Set(["feedback"])],
  ["policy_published", new Set(["feedback"])],
  ["record", new Set(["feedback"])],
  ["date_range", new Set(["report_metadata"])],
  ["org_name", new Set(["report_metadata"])],
  ["email", new Set(["report_metadata"])],
  ["report_id", new Set(["report_metadata"])],
  ["begin", new Set(["date_range"])],
  ["end", new Set(["date_range"])],
  ["row", new Set(["record"])],
  ["identifiers", new Set(["record"])],
  ["auth_results", new Set(["record"])],
  ["source_ip", new Set(["row"])],
  ["count", new Set(["row"])],
  ["policy_evaluated", new Set(["row"])],
  ["disposition", new Set(["policy_evaluated"])],
  ["header_from", new Set(["identifiers"])],
  ["envelope_from", new Set(["identifiers"])],
  ["envelope_to", new Set(["identifiers"])],
  ["adkim", new Set(["policy_published"])],
  ["aspf", new Set(["policy_published"])],
  ["p", new Set(["policy_published"])],
  ["sp", new Set(["policy_published"])],
  ["np", new Set(["policy_published"])],
  ["fo", new Set(["policy_published"])],
  ["testing", new Set(["policy_published"])],
  ["discovery_method", new Set(["policy_published"])],
  ["pct", new Set(["policy_published"])],
  ["dkim", new Set(["policy_evaluated", "auth_results"])],
  ["spf", new Set(["policy_evaluated", "auth_results"])],
  ["domain", new Set(["policy_published", "dkim", "spf"])],
  ["selector", new Set(["dkim"])],
  ["result", new Set(["dkim", "spf"])],
]);

// Validate the element stack before fixed-literal extraction. This does not
// resolve entities or namespaces; it only prevents a critical lookalike/nested
// field from being accepted out of its DMARC schema position.
function _validateDmarcElementStructure(xml) {
  if (/<!--|<!\[CDATA\[|<\?(?!xml(?:\s|[?]))/i.test(xml)) {
    _schemaFailure("invalid_structure", "Unsupported XML markup is present.");
  }
  const stack = [];
  let rootCount = 0;
  const tags = xml.match(/<[^>]+>/g) || [];
  for (const token of tags) {
    if (/^<\?xml(?:\s[^?]*)?\?>$/i.test(token)) {
      if (stack.length || rootCount) {
        _schemaFailure("invalid_structure", "The XML declaration is misplaced.");
      }
      continue;
    }
    if (/^<!|^<\?/.test(token)) {
      _schemaFailure("invalid_structure", "Unsupported XML markup is present.");
    }
    const nameMatch = token.match(/^<\s*\/?\s*([A-Za-z_][A-Za-z0-9_.-]*)/);
    if (!nameMatch) _schemaFailure("invalid_structure", "An XML element is malformed.");
    const name = nameMatch[1].toLowerCase();
    const closing = /^<\s*\//.test(token);
    const selfClosing = /\/\s*>$/.test(token);
    if (closing) {
      if (selfClosing || stack.pop() !== name) {
        _schemaFailure("invalid_structure", "DMARC elements are not properly nested.");
      }
      continue;
    }

    const parent = stack.length ? stack[stack.length - 1] : null;
    const allowedParents = DMARC_CRITICAL_ELEMENT_PARENTS.get(name);
    if (allowedParents && !allowedParents.has(parent)) {
      _schemaFailure("invalid_structure", `DMARC ${name} is in an invalid position.`);
    }
    if (name === "feedback") rootCount += 1;
    if (!selfClosing) stack.push(name);
  }
  if (stack.length || rootCount !== 1) {
    _schemaFailure("invalid_structure", "DMARC elements are not properly nested.");
  }
}

/**
 * parseDmarcAggregateXml(xml) — controlled, defensive DMARC aggregate parser.
 *
 * Security: rejects empty input and input > 2 MB; rejects DOCTYPE/ENTITY/
 * stylesheet declarations (no XXE / entity expansion); rejects namespace-
 * prefixed/lookalike critical elements and duplicate singleton structures;
 * performs no network I/O; never returns or stores raw XML. Returns
 * { error, message } on failure or the strict structured
 * { metadata, policy_published, records } shape on success.
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
  // The fixed-literal parser deliberately supports an optional default namespace
  // on <feedback>, but not prefixed element names. A prefix must never make a
  // lookalike element satisfy a critical DMARC field.
  if (/<\/?[A-Za-z_][A-Za-z0-9_.-]*:[A-Za-z_][A-Za-z0-9_.-]*(?:\s|\/?>)/.test(xml)) {
    return {
      error: "unsupported_namespace",
      message: "Namespace-prefixed DMARC elements are not supported.",
    };
  }
  try {
    _validateDmarcElementStructure(xml);
    const root = xml.match(
      /^\s*(?:<\?xml(?:\s[^?]*)?\?>\s*)?<feedback(\s[^>]*)?>([\s\S]*)<\/feedback>\s*$/i,
    );
    if (!root) {
      return {
        error: "invalid_structure",
        message: "A DMARC report must contain one feedback document.",
      };
    }
    const rootAttributes = root[1] || "";
    const namespaceMatches = [...rootAttributes.matchAll(
      /\bxmlns\s*=\s*(?:"([^"]*)"|'([^']*)')/gi,
    )];
    if (/\bxmlns\s*=/i.test(rootAttributes) && namespaceMatches.length === 0) {
      _schemaFailure("unsupported_namespace", "The DMARC default namespace is malformed.");
    }
    if (namespaceMatches.length > 1) {
      _schemaFailure("unsupported_namespace", "The DMARC default namespace is ambiguous.");
    }
    let xmlNamespace = null;
    if (namespaceMatches.length === 1) {
      xmlNamespace = namespaceMatches[0][1] ?? namespaceMatches[0][2] ?? "";
      if (!DMARC_SUPPORTED_DEFAULT_NAMESPACES.has(xmlNamespace)) {
        _schemaFailure("unsupported_namespace", "The DMARC default namespace is unsupported.");
      }
    }
    const feedback = root[2];
    if (/<\/?feedback(?:\s|>)/i.test(feedback)) {
      _schemaFailure("invalid_structure", "DMARC feedback must appear exactly once.");
    }
    const formatVersion = _xmlText(feedback, "version", {
      required: false,
      maxLength: 16,
    });
    // RFC 9990 §3.1.1.2: when present, version MUST be exactly 1.0.
    if (formatVersion != null && formatVersion !== "1.0") {
      _schemaFailure("unsupported_version", "DMARC aggregate report version must be 1.0.");
    }
    const metaBlock = _singleXmlBlock(feedback, "report_metadata");
    const policyBlock = _singleXmlBlock(feedback, "policy_published");
    const recordBlocks = _xmlBlocks(feedback, "record", DMARC_MAX_RECORDS + 1);
    if (recordBlocks.length > DMARC_MAX_RECORDS) {
      return {
        error: "too_many_records",
        message: `The DMARC report exceeds ${DMARC_MAX_RECORDS} record rows.`,
      };
    }
    if (recordBlocks.length === 0) {
      return { error: "no_records", message: "The DMARC report contained no record rows." };
    }

    const dateRange = _singleXmlBlock(metaBlock, "date_range");
    const begin = _boundedDmarcInteger(dateRange, "begin", {
      min: 1,
      max: DMARC_MAX_EPOCH_SECONDS,
      code: "invalid_date_range",
    });
    const end = _boundedDmarcInteger(dateRange, "end", {
      min: 1,
      max: DMARC_MAX_EPOCH_SECONDS,
      code: "invalid_date_range",
    });
    if (end < begin || end - begin > DMARC_MAX_REPORT_WINDOW_SECONDS) {
      _schemaFailure("invalid_date_range", "DMARC date_range is invalid.");
    }
    const metadata = {
      org_name: _xmlText(metaBlock, "org_name", { required: true, maxLength: 256 }),
      email: _xmlText(metaBlock, "email", { required: true, maxLength: 320 }),
      report_id: _xmlText(metaBlock, "report_id", { required: true, maxLength: 256 }),
      date_range_begin: begin,
      date_range_end: end,
      report_format_version: formatVersion,
      xml_namespace: xmlNamespace,
      schema_conformance:
        xmlNamespace === DMARC_RFC9990_NAMESPACE
          ? "rfc9990_profile_accepted_not_full_xsd"
          : "legacy_rfc7489_profile_accepted",
      parser_version: DMARC_AGGREGATE_PARSER_VERSION,
    };

    const policy_published = {
      domain: _xmlText(policyBlock, "domain", {
        required: true,
        maxLength: 253,
        normalize: _normalizeDmarcDomain,
      }),
      adkim: _enumValue(policyBlock, "adkim", DMARC_ALIGNMENT_VALUES, { required: false }),
      aspf: _enumValue(policyBlock, "aspf", DMARC_ALIGNMENT_VALUES, { required: false }),
      p: _enumValue(policyBlock, "p", DMARC_POLICY_VALUES),
      sp: _enumValue(policyBlock, "sp", DMARC_POLICY_VALUES, { required: false }),
      np: _enumValue(policyBlock, "np", DMARC_POLICY_VALUES, { required: false }),
      fo: _xmlText(policyBlock, "fo", { required: false, maxLength: 128 }),
      pct: _boundedDmarcInteger(policyBlock, "pct", {
        min: 0,
        max: 100,
        required: false,
        code: "invalid_policy",
      }),
      testing: _enumValue(policyBlock, "testing", DMARC_TESTING_VALUES, {
        required: false,
      }),
      // RFC 9990 currently defines psl/treewalk. Preserve a bounded future/raw
      // token instead of silently losing it or assigning current semantics.
      discovery_method: _xmlText(policyBlock, "discovery_method", {
        required: false,
        maxLength: 32,
        normalize: (text) => text.toLowerCase(),
      }),
    };
    policy_published.discovery_method_state =
      policy_published.discovery_method == null
        ? "absent"
        : DMARC_DISCOVERY_METHOD_VALUES.has(policy_published.discovery_method)
          ? "recognized"
          : "unknown_preserved";

    const records = [];
    for (const rec of recordBlocks) {
      const row = _singleXmlBlock(rec, "row");
      const policyEvaluated = _singleXmlBlock(row, "policy_evaluated");
      const identifiers = _singleXmlBlock(rec, "identifiers");
      const authResults = _singleXmlBlock(rec, "auth_results", { required: false });

      let firstDkim = null;
      let firstSpf = null;
      if (authResults) {
        const dkimBlocks = _xmlBlocks(authResults, "dkim", 11);
        const spfBlocks = _xmlBlocks(authResults, "spf", 11);
        if (dkimBlocks.length > 10 || spfBlocks.length > 10) {
          _schemaFailure("invalid_structure", "DMARC auth_results is too complex.");
        }
        for (const dkim of dkimBlocks) {
          const parsed = {
            domain: _xmlText(dkim, "domain", {
              required: true,
              maxLength: 253,
              normalize: _normalizeDmarcDomain,
            }),
            selector: _xmlText(dkim, "selector", { required: false, maxLength: 253 }),
            result: _enumValue(dkim, "result", DMARC_DKIM_RESULTS),
          };
          if (!firstDkim) firstDkim = parsed;
        }
        for (const spf of spfBlocks) {
          const parsed = {
            domain: _xmlText(spf, "domain", {
              required: true,
              maxLength: 253,
              normalize: _normalizeDmarcDomain,
            }),
            result: _enumValue(spf, "result", DMARC_SPF_RESULTS),
          };
          if (!firstSpf) firstSpf = parsed;
        }
      }

      records.push({
        source_ip: _validatedIp(_xmlText(row, "source_ip", {
          required: true,
          maxLength: 45,
        })),
        count: _boundedDmarcInteger(row, "count", {
          min: 0,
          max: DMARC_MAX_MESSAGES_PER_RECORD,
          code: "invalid_record_count",
        }),
        disposition: _enumValue(policyEvaluated, "disposition", DMARC_POLICY_VALUES),
        dkim_aligned_result: _enumValue(
          policyEvaluated,
          "dkim",
          DMARC_EVALUATED_VALUES,
        ),
        spf_aligned_result: _enumValue(
          policyEvaluated,
          "spf",
          DMARC_EVALUATED_VALUES,
        ),
        header_from: _xmlText(identifiers, "header_from", {
          required: true,
          maxLength: 253,
          normalize: _normalizeDmarcDomain,
        }),
        envelope_from: _xmlText(identifiers, "envelope_from", {
          required: false,
          maxLength: 253,
          normalize: _normalizeDmarcDomain,
        }),
        dkim_domain: firstDkim?.domain || null,
        dkim_selector: firstDkim?.selector || null,
        dkim_result: firstDkim?.result || null,
        spf_domain: firstSpf?.domain || null,
        spf_result: firstSpf?.result || null,
      });
    }
    return { metadata, policy_published, records };
  } catch (error) {
    return {
      error: error?.code || "invalid_structure",
      message: String(error?.message || "The DMARC report is malformed.").slice(0, 300),
    };
  }
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

function emailSenderSourceStatements(env, workspaceId, domain, parsed) {
  if (!parsed || !Array.isArray(parsed.records)) return [];
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

  const statements = [];
  for (const agg of bySource.values()) {
    const guess = guessEmailSenderProvider(agg.sample);
    const passRate = agg.total > 0 ? Math.round((agg.aligned / agg.total) * 1000) / 10 : 0;
    statements.push(env.cybermeters_db
      .prepare(`INSERT INTO email_sender_sources
                (id, workspace_id, domain, source_ip, provider_guess, provider_confidence, provider_reason,
                 header_from, first_seen, last_seen, total_messages, aligned_messages, failed_messages,
                 quarantined_messages, rejected_messages, pass_rate,
                 spf_aligned_messages, dkim_aligned_messages, classification, notes, provider_map_version,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unknown', NULL, ?,
                        datetime('now'), datetime('now'))
                ON CONFLICT(workspace_id, domain, source_ip) DO UPDATE SET
                  last_seen = excluded.last_seen,
                  total_messages = email_sender_sources.total_messages + excluded.total_messages,
                  aligned_messages = email_sender_sources.aligned_messages + excluded.aligned_messages,
                  failed_messages = email_sender_sources.failed_messages + excluded.failed_messages,
                  spf_aligned_messages = email_sender_sources.spf_aligned_messages + excluded.spf_aligned_messages,
                  dkim_aligned_messages = email_sender_sources.dkim_aligned_messages + excluded.dkim_aligned_messages,
                  quarantined_messages = email_sender_sources.quarantined_messages + excluded.quarantined_messages,
                  rejected_messages = email_sender_sources.rejected_messages + excluded.rejected_messages,
                  pass_rate = CASE
                    WHEN email_sender_sources.total_messages + excluded.total_messages > 0
                    THEN ROUND(
                      1000.0 * (email_sender_sources.aligned_messages + excluded.aligned_messages)
                      / (email_sender_sources.total_messages + excluded.total_messages)
                    ) / 10.0
                    ELSE 0
                  END,
                  provider_guess = excluded.provider_guess,
                  provider_confidence = excluded.provider_confidence,
                  provider_reason = excluded.provider_reason,
                  provider_map_version = excluded.provider_map_version,
                  header_from = COALESCE(email_sender_sources.header_from, excluded.header_from),
                  first_seen = CASE
                    WHEN email_sender_sources.first_seen IS NULL
                      OR excluded.first_seen < email_sender_sources.first_seen
                    THEN excluded.first_seen
                    ELSE email_sender_sources.first_seen
                  END,
                  updated_at = datetime('now')`)
      .bind(createId("esender"), workspaceId, domain, agg.ip,
        guess.provider, guess.confidence, guess.reason,
        agg.sample.header_from || null, beginIso, endIso,
        agg.total, agg.aligned, agg.failed, agg.quarantined, agg.rejected,
        passRate, agg.spfAligned, agg.dkimAligned, PROVIDER_MAP_VERSION));
  }
  return statements;
}

/**
 * Compatibility export used by existing callers/tests. New report ingestion
 * includes these statements in the same transaction as report persistence.
 */
async function updateEmailSenderSources(env, workspaceId, domain, parsed) {
  const statements = emailSenderSourceStatements(env, workspaceId, domain, parsed);
  if (statements.length) await env.cybermeters_db.batch(statements);
  return { sources_updated: statements.length };
}

// Pure, testable: the report identity tuple used for dedupe. The claim table
// adds workspace/domain and the authority-vs-observational source scope, so
// manual + signed submissions dedupe together while inbound cannot suppress
// a later authoritative copy.
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
// Missing/invalid policy domains fail closed in the strict parser and again here
// so no caller can attribute an unbound report body to the endpoint domain.
function dmarcReportDomainMatches(parsed, boundDomain) {
  const reportDomain = (parsed?.policy_published?.domain || "").trim().toLowerCase();
  if (!reportDomain) return false;
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
  // Inbound sender-claim metadata (null for authenticated customer-submission
  // paths). It does not authenticate the report producer or report body.
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

  const m = parsed.metadata;
  if (parsed.records.length > AGGREGATE_REPORT_MAX_PERSISTED_ROWS) {
    await createAuditEvent(env, {
      workspace_id: workspaceId,
      user_id: actorUserId,
      event_type: "dmarc_report_rejected",
      entity_type: "domain",
      entity_id: domainId,
      description: `Rejected DMARC report for ${domain}: row limit exceeded`,
      metadata: {
        domain,
        source,
        reason: "report_row_limit_exceeded",
        rows_present: parsed.records.length,
        rows_allowed: AGGREGATE_REPORT_MAX_PERSISTED_ROWS,
        ingest_endpoint_id: ingestEndpointId,
      },
      required: true,
    });
    return {
      ok: false,
      status: 422,
      error: "report_row_limit_exceeded",
      message: `The report contains more than ${AGGREGATE_REPORT_MAX_PERSISTED_ROWS} record rows.`,
      terminal: true,
      audited: true,
    };
  }

  const identity = await dmarcReportIdentity(xmlString, parsed);
  const authorityEligible = isDmarcAuthorityEligibleSource(source);
  const sourceScope = aggregateReportSourceScope(authorityEligible);
  const claim = await acquireAggregateReportClaim(env, {
    reportType: "dmarc",
    workspaceId,
    domain,
    source,
    sourceScope,
    identity: aggregateReportIdentity({
      orgName: identity.org_name,
      externalReportId: identity.external_report_id,
      dateBegin: identity.date_range_begin,
      dateEnd: identity.date_range_end,
    }),
    contentHash: identity.raw_hash,
  });

  if (claim.collision) {
    await createAuditEvent(env, {
      workspace_id: workspaceId,
      user_id: actorUserId,
      event_type: "dmarc_report_identity_collision",
      entity_type: "domain",
      entity_id: domainId,
      description: `Rejected colliding DMARC report identity for ${domain}`,
      metadata: {
        domain,
        source,
        source_scope: sourceScope,
        report_id: identity.external_report_id,
        reason: "content_hash_mismatch",
        ingest_endpoint_id: ingestEndpointId,
      },
      required: true,
    });
    return {
      ok: false,
      status: 409,
      error: "report_identity_collision",
      message: "A different report body already uses this report identity.",
      terminal: true,
      audited: true,
    };
  }

  if (claim.inProgress) {
    await createAuditEvent(env, {
      workspace_id: workspaceId,
      user_id: actorUserId,
      event_type: "dmarc_report_ingest_deferred",
      entity_type: "domain",
      entity_id: domainId,
      description: `Deferred concurrent DMARC report ingestion for ${domain}`,
      metadata: {
        domain,
        source,
        source_scope: sourceScope,
        report_id: identity.external_report_id,
        reason: "ingest_in_progress",
        claim_id: claim.claimId,
      },
      required: true,
    });
    return {
      ok: false,
      status: 503,
      error: "ingest_in_progress",
      message: "This report is already being processed. Retry shortly.",
      transient: true,
      audited: true,
    };
  }

  if (claim.duplicate) {
    await createAuditEvent(env, {
      workspace_id: workspaceId, user_id: actorUserId, event_type: "dmarc_report_duplicate",
      entity_type: "domain", entity_id: domainId,
      description: `Duplicate DMARC report ignored for ${domain}`,
      metadata: { domain, source, org_name: m.org_name, report_id: identity.external_report_id,
                  duplicate: true, source_scope: sourceScope, ingest_endpoint_id: ingestEndpointId,
                  auth_verdict: prov.auth_verdict ?? null, reporter_domain: prov.reporter_domain ?? null },
    });
    return { ok: true, imported: false, duplicate: true, reportId: claim.reportId };
  }

  const pol = parsed.policy_published || {};
  const messageCount = parsed.records.reduce((a, r) => a + (r.count || 0), 0);
  const existingAcrossScope = await env.cybermeters_db
    .prepare(`SELECT id, raw_hash, source
              FROM dmarc_aggregate_reports
              WHERE workspace_id = ? AND domain = ? AND org_name IS ?
                AND external_report_id = ? AND date_range_begin IS ? AND date_range_end IS ?
              LIMIT 1`)
    .bind(workspaceId, domain, identity.org_name, identity.external_report_id,
      identity.date_range_begin, identity.date_range_end)
    .first();

  const repairingOwnLegacyParent = claim.repaired &&
    existingAcrossScope?.id === claim.reportId;
  if (existingAcrossScope && !repairingOwnLegacyParent) {
    if (existingAcrossScope.raw_hash &&
        existingAcrossScope.raw_hash !== identity.raw_hash) {
      const failed = await failAggregateReportClaim(
        env,
        claim,
        "cross_scope_content_hash_mismatch",
      );
      if (!failed) throw new Error("aggregate_ingest_claim_fail_transition_lost");
      await createAuditEvent(env, {
        workspace_id: workspaceId,
        user_id: actorUserId,
        event_type: "dmarc_report_identity_collision",
        entity_type: "domain",
        entity_id: domainId,
        description: `Rejected cross-scope DMARC identity collision for ${domain}`,
        metadata: {
          domain,
          source,
          source_scope: sourceScope,
          report_id: identity.external_report_id,
          reason: "content_hash_mismatch",
          claim_id: claim.claimId,
        },
        required: true,
      });
      return {
        ok: false,
        status: 409,
        error: "report_identity_collision",
        message: "A different report body already uses this report identity.",
        terminal: true,
        audited: true,
      };
    }

    const promoted = authorityEligible &&
      !isDmarcAuthorityEligibleSource(existingAcrossScope.source);
    const crossScopeStatements = [
      env.cybermeters_db
        .prepare(`UPDATE aggregate_report_ingest_claims
                  SET report_id = ?, updated_at = datetime('now')
                  WHERE id = ? AND attempt_token = ? AND ingest_state = 'pending'`)
        .bind(existingAcrossScope.id, claim.claimId, claim.attemptToken),
    ];
    if (promoted) {
      crossScopeStatements.push(env.cybermeters_db
        .prepare(`UPDATE dmarc_aggregate_reports
                  SET source = ?
                  WHERE id = ?`)
        .bind(source, existingAcrossScope.id));
    }
    crossScopeStatements.push(completeAggregateReportClaimStatement(env, claim));
    crossScopeStatements.push(
      assertAggregateReportClaimCompleteStatement(env, claim),
    );
    await env.cybermeters_db.batch(crossScopeStatements);

    await createAuditEvent(env, {
      workspace_id: workspaceId,
      user_id: actorUserId,
      event_type: promoted ? "dmarc_report_scope_promoted" : "dmarc_report_duplicate",
      entity_type: "domain",
      entity_id: domainId,
      description: promoted
        ? `Accepted authoritative copy of an observational DMARC report for ${domain}`
        : `Duplicate DMARC report ignored for ${domain}`,
      metadata: {
        domain,
        source,
        source_scope: sourceScope,
        report_id: identity.external_report_id,
        duplicate: !promoted,
        promoted,
        content_hash_match: true,
        claim_id: claim.claimId,
        ingest_endpoint_id: ingestEndpointId,
      },
    });

    if (!promoted) {
      return {
        ok: true,
        imported: false,
        duplicate: true,
        reportId: existingAcrossScope.id,
      };
    }

    try {
      await classifyWorkspaceDomainSenders(env, workspaceId, domain, {
        reportSources: DMARC_AUTHORITY_ELIGIBLE_SOURCES,
      });
    } catch { /* auto-classification is best-effort */ }
    try {
      await evaluateEmailSenderMonitoring(env, workspaceId, domain);
    } catch { /* alerting must never break evidence ingestion */ }
    return {
      ok: true,
      imported: true,
      duplicate: false,
      promoted: true,
      reportId: existingAcrossScope.id,
      records: parsed.records.length,
      messages: messageCount,
      sourcesUpdated: 0,
    };
  }

  const reportId = claim.reportId;
  const transaction = [
    // A failed legacy/pre-Gate-3B row may already have children. Repair replaces
    // them inside this transaction; a new failed batch leaves no children at all.
    env.cybermeters_db
      .prepare("DELETE FROM dmarc_aggregate_records WHERE report_id = ?")
      .bind(reportId),
    env.cybermeters_db
      .prepare(`INSERT INTO dmarc_aggregate_reports
                (id, workspace_id, domain, org_name, report_email, external_report_id,
                 date_range_begin, date_range_end, policy_domain, policy_adkim, policy_aspf,
                 policy_p, policy_sp, policy_pct, record_count, message_count, raw_hash, source,
                 envelope_from, reporter_domain, auth_verdict, auth_evidence,
                 report_format_version, xml_namespace, discovery_method, policy_np,
                 policy_testing, policy_fo, schema_conformance, parser_version, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?,
                        datetime('now'))
                ON CONFLICT(id) DO UPDATE SET
                  workspace_id = excluded.workspace_id,
                  domain = excluded.domain,
                  org_name = excluded.org_name,
                  report_email = excluded.report_email,
                  external_report_id = excluded.external_report_id,
                  date_range_begin = excluded.date_range_begin,
                  date_range_end = excluded.date_range_end,
                  policy_domain = excluded.policy_domain,
                  policy_adkim = excluded.policy_adkim,
                  policy_aspf = excluded.policy_aspf,
                  policy_p = excluded.policy_p,
                  policy_sp = excluded.policy_sp,
                  policy_pct = excluded.policy_pct,
                  record_count = excluded.record_count,
                  message_count = excluded.message_count,
                  raw_hash = excluded.raw_hash,
                  source = excluded.source,
                  envelope_from = excluded.envelope_from,
                  reporter_domain = excluded.reporter_domain,
                  auth_verdict = excluded.auth_verdict,
                  auth_evidence = excluded.auth_evidence,
                  report_format_version = excluded.report_format_version,
                  xml_namespace = excluded.xml_namespace,
                  discovery_method = excluded.discovery_method,
                  policy_np = excluded.policy_np,
                  policy_testing = excluded.policy_testing,
                  policy_fo = excluded.policy_fo,
                  schema_conformance = excluded.schema_conformance,
                  parser_version = excluded.parser_version`)
      .bind(reportId, workspaceId, domain, m.org_name || null, m.email || null,
        identity.external_report_id, m.date_range_begin || null, m.date_range_end || null,
        pol.domain || null, pol.adkim || null, pol.aspf || null, pol.p || null,
        pol.sp || null, pol.pct ?? null, parsed.records.length, messageCount,
        identity.raw_hash, source, prov.envelope_from ?? null,
        prov.reporter_domain ?? null, prov.auth_verdict ?? null,
        prov.auth_evidence ?? null, m.report_format_version ?? null,
        m.xml_namespace ?? null, pol.discovery_method ?? null, pol.np ?? null,
        pol.testing ?? null, pol.fo ?? null, m.schema_conformance ?? null,
        m.parser_version ?? DMARC_AGGREGATE_PARSER_VERSION),
  ];

  for (const r of parsed.records) {
    transaction.push(env.cybermeters_db
      .prepare(`INSERT INTO dmarc_aggregate_records
                (id, report_id, workspace_id, domain, source_ip, message_count, disposition,
                 dkim_aligned_result, spf_aligned_result, header_from, envelope_from,
                 dkim_domain, dkim_selector, dkim_result, spf_domain, spf_result, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
      .bind(createId("dmarcrec"), reportId, workspaceId, domain, r.source_ip || null, r.count || 0,
            r.disposition || null, r.dkim_aligned_result || null, r.spf_aligned_result || null,
            r.header_from || null, r.envelope_from || null, r.dkim_domain || null, r.dkim_selector || null,
            r.dkim_result || null, r.spf_domain || null, r.spf_result || null)
    );
  }

  const sourceStatements = emailSenderSourceStatements(env, workspaceId, domain, parsed);
  transaction.push(...sourceStatements);
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
        user_id: actorUserId,
        event_type: "dmarc_report_ingest_failed",
        entity_type: "domain",
        entity_id: domainId,
        description: `DMARC report ingestion failed safely for ${domain}`,
        metadata: {
          domain,
          source,
          source_scope: sourceScope,
          report_id: identity.external_report_id,
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
      message: "The report was not partially stored and can be retried.",
      transient: true,
      quarantined,
      audited: true,
    };
  }

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
                filename, source_scope: sourceScope, claim_id: claim.claimId,
                repaired: claim.repaired, ingest_endpoint_id: ingestEndpointId,
                auth_verdict: prov.auth_verdict ?? null, reporter_domain: prov.reporter_domain ?? null,
                envelope_from: prov.envelope_from ?? null },
  });

  return { ok: true, imported: true, duplicate: false, reportId,
    records: parsed.records.length, messages: messageCount,
    sourcesUpdated: sourceStatements.length, repaired: claim.repaired };
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
  DMARC_MAX_MESSAGES_PER_RECORD,
  DMARC_PROVIDER_PATTERNS,
  DMARC_XML_MAX_BYTES,
  RUA_INBOUND_DOMAIN_DEFAULT,
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
