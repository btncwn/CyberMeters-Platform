// Pure RFC 9989 policy-record and RFC 9990 authorisation-record parsing.
//
// P1 deliberately has no production DNS caller. TXT RR character-string chunks
// enter explicitly, remain ordered, and are never truncated for parsing.
import { canonicalizeDmarcbisDomain } from "./dmarcbis-idna.js";

export const DMARCBIS_PARSER_VERSION = "rfc9989-parser-v1";
export const DMARCBIS_MAX_TXT_RR_BYTES = 64 * 1024;
export const DMARCBIS_MAX_DNS_EVIDENCE_BYTES = 256 * 1024;
export const DMARCBIS_MAX_REPORT_URIS = 10;
export const DMARCBIS_MAX_EXTERNAL_HOSTS = 5;
export const DMARCBIS_MAX_URI_CHARACTERS = 2_048;

const POLICY_VALUES = new Set(["none", "quarantine", "reject"]);
const YORN_VALUES = new Set(["y", "n"]);
const PSD_VALUES = new Set(["y", "n", "u"]);
const ALIGNMENT_VALUES = new Set(["r", "s"]);
const KNOWN_POLICY_TAGS = new Set([
  "v", "p", "sp", "np", "t", "psd", "adkim", "aspf", "rua", "ruf", "fo",
]);

function decodeDnsPresentationTxt(value) {
  const input = String(value || "");
  if (!input.trimStart().startsWith('"')) return [input];
  const chunks = [];
  let index = 0;
  while (index < input.length) {
    while (index < input.length && /[ \t]/.test(input[index])) index += 1;
    if (index >= input.length) break;
    if (input[index] !== '"') return [input];
    index += 1;
    let chunk = "";
    let closed = false;
    while (index < input.length) {
      const char = input[index++];
      if (char === '"') {
        closed = true;
        break;
      }
      if (char !== "\\") {
        chunk += char;
        continue;
      }
      if (index >= input.length) return [input];
      const digits = input.slice(index, index + 3);
      if (/^[0-9]{3}$/.test(digits)) {
        chunk += String.fromCharCode(Number(digits));
        index += 3;
      } else {
        chunk += input[index++];
      }
    }
    if (!closed) return [input];
    chunks.push(chunk);
  }
  return chunks.length ? chunks : [input];
}

export function concatenateDmarcbisTxtRecord(record, index = 0) {
  let chunks;
  if (typeof record === "string") {
    chunks = [record];
  } else if (Array.isArray(record?.chunks)) {
    chunks = record.chunks.map((chunk) => String(chunk));
  } else if (typeof record?.value === "string") {
    chunks = [record.value];
  } else if (typeof record?.data === "string") {
    chunks = decodeDnsPresentationTxt(record.data);
  } else {
    chunks = [];
  }
  const value = chunks.join("");
  return {
    index,
    chunks,
    value,
    byte_length: new TextEncoder().encode(value).byteLength,
    truncated: record?.truncated === true,
    raw: record,
  };
}

function parseTagList(value) {
  const segments = String(value || "").split(";");
  const tags = [];
  const errors = [];
  const seen = new Set();
  const duplicates = [];

  for (let index = 0; index < segments.length; index += 1) {
    const rawSegment = segments[index];
    const isTrailing = index === segments.length - 1 && rawSegment.trim() === "";
    if (isTrailing) continue;
    if (rawSegment.trim() === "") {
      errors.push({ code: "empty_tag", segment_index: index, raw: rawSegment });
      continue;
    }
    // RFC 9989 §4.8 permits WSP after a separator, but not before the first
    // version tag.
    const segment = index === 0 ? rawSegment : rawSegment.replace(/^[ \t]*/, "");
    const match = segment.match(/^([A-Za-z]+)[ \t]*=[ \t]*(.+?)[ \t]*$/s);
    if (!match) {
      errors.push({ code: "invalid_tag_syntax", segment_index: index, raw: rawSegment });
      continue;
    }
    const nameRaw = match[1];
    const name = nameRaw.toLowerCase();
    const rawValue = match[2];
    const normalizedValue = rawValue.trim();
    if (!normalizedValue || /[^\x20-\x7e]/.test(rawValue)) {
      errors.push({ code: "invalid_tag_value_syntax", segment_index: index, name, raw: rawSegment });
      continue;
    }
    const duplicate = seen.has(name);
    if (duplicate) duplicates.push(name);
    seen.add(name);
    tags.push({
      index,
      name,
      name_raw: nameRaw,
      raw_value: rawValue,
      normalized_value: normalizedValue,
      duplicate,
      known: KNOWN_POLICY_TAGS.has(name),
    });
  }

  const first = tags[0] || null;
  const currentVersion =
    first?.index === 0 &&
    first.name === "v" &&
    first.normalized_value === "DMARC1";

  return {
    tags,
    errors,
    duplicate_tags: [...new Set(duplicates)],
    current_version: currentVersion,
    first_tag: first,
  };
}

function tagEntries(parsed, name) {
  return parsed.tags.filter((tag) => tag.name === name);
}

function valueTag(parsed, name, allowed, defaultValue = null) {
  const entries = tagEntries(parsed, name);
  if (!entries.length) {
    return {
      present: false,
      raw: null,
      normalized: defaultValue,
      validity: defaultValue == null ? "absent" : "defaulted",
      defaulted: defaultValue != null,
    };
  }
  const raw = entries[0].normalized_value;
  const normalized = raw.toLowerCase();
  if (!allowed.has(normalized)) {
    return {
      present: true,
      raw,
      normalized: defaultValue,
      validity: "invalid",
      defaulted: defaultValue != null,
    };
  }
  return {
    present: true,
    raw,
    normalized,
    validity: "valid",
    defaulted: false,
  };
}

function parseFoTag(parsed) {
  const entries = tagEntries(parsed, "fo");
  if (!entries.length) {
    return {
      present: false,
      raw: null,
      normalized: ["0"],
      validity: "defaulted",
      defaulted: true,
    };
  }
  const raw = entries[0].normalized_value;
  const values = raw.toLowerCase().split(":");
  const set = new Set(values);
  const valid =
    values.every((value) => ["0", "1", "d", "s"].includes(value)) &&
    values.length === set.size &&
    !(set.has("0") && set.has("1"));
  return {
    present: true,
    raw,
    normalized: valid ? values : ["0"],
    validity: valid ? "valid" : "invalid",
    defaulted: !valid,
  };
}

function splitObsoleteSize(raw) {
  const match = String(raw).match(/^(.*)!([0-9]+[kmgt]?)$/);
  return match
    ? { uri: match[1], obsolete_size: match[2] }
    : { uri: String(raw), obsolete_size: null };
}

function mailtoDestinationHost(url) {
  const address = url.pathname;
  const at = address.lastIndexOf("@");
  if (at <= 0 || at === address.length - 1) return null;
  return address.slice(at + 1);
}

export function parseDmarcbisReportingUri(raw, { index = 0 } = {}) {
  const original = String(raw ?? "");
  const trimmed = original.trim();
  const base = {
    index,
    raw: original,
    normalized_uri: null,
    scheme: null,
    supported_scheme: false,
    uri_parse_status: "malformed",
    syntax_valid: false,
    destination_host: null,
    destination_host_raw: null,
    obsolete_size: null,
    over_product_limit: trimmed.length > DMARCBIS_MAX_URI_CHARACTERS,
    limits: [],
  };
  if (!trimmed) return { ...base, error: "empty_uri" };
  if (/[\u0000-\u0020\u007f]/.test(trimmed)) return { ...base, error: "invalid_uri_character" };
  if (/%(?![0-9a-fA-F]{2})/.test(trimmed)) return { ...base, error: "invalid_percent_escape" };

  const { uri, obsolete_size: obsoleteSize } = splitObsoleteSize(trimmed);
  if (uri.includes("!")) return { ...base, obsolete_size: obsoleteSize, error: "unencoded_exclamation" };
  const schemeMatch = uri.match(/^([A-Za-z][A-Za-z0-9+.-]*):/);
  if (!schemeMatch) return { ...base, obsolete_size: obsoleteSize, error: "missing_scheme" };

  let url;
  try {
    url = new URL(uri);
  } catch (error) {
    return {
      ...base,
      obsolete_size: obsoleteSize,
      error: "invalid_uri",
      detail: String(error?.message || error),
    };
  }

  const scheme = schemeMatch[1].toLowerCase();
  const overProductLimit = trimmed.length > DMARCBIS_MAX_URI_CHARACTERS;
  const limits = overProductLimit
    ? [{ type: "uri_characters", actual: trimmed.length, maximum: DMARCBIS_MAX_URI_CHARACTERS }]
    : [];
  if (scheme !== "mailto") {
    return {
      ...base,
      normalized_uri: url.href,
      scheme,
      syntax_valid: true,
      supported_scheme: false,
      uri_parse_status: overProductLimit ? "limit_exceeded" : "unsupported_scheme",
      obsolete_size: obsoleteSize,
      over_product_limit: overProductLimit,
      limits,
      error: null,
    };
  }

  const rawHost = mailtoDestinationHost(url);
  if (!rawHost) {
    return {
      ...base,
      normalized_uri: url.href,
      scheme,
      supported_scheme: true,
      obsolete_size: obsoleteSize,
      over_product_limit: overProductLimit,
      limits,
      error: "mailto_destination_host_missing",
    };
  }
  const host = canonicalizeDmarcbisDomain(rawHost);
  if (!host.ok) {
    return {
      ...base,
      normalized_uri: url.href,
      scheme,
      supported_scheme: true,
      destination_host_raw: rawHost,
      obsolete_size: obsoleteSize,
      over_product_limit: overProductLimit,
      limits,
      error: host.error,
      host_diagnostic: host,
    };
  }

  return {
    ...base,
    normalized_uri: url.href,
    scheme,
    supported_scheme: true,
    uri_parse_status: overProductLimit ? "limit_exceeded" : "valid",
    syntax_valid: true,
    destination_host: host.alabel,
    destination_host_raw: rawHost,
    obsolete_size: obsoleteSize,
    over_product_limit: overProductLimit,
    limits,
    error: null,
    host_diagnostic: host,
  };
}

function parseUriTag(parsed, name) {
  const entries = tagEntries(parsed, name);
  if (!entries.length) return [];
  return entries[0].normalized_value
    .split(",")
    .map((value, index) => parseDmarcbisReportingUri(value, { index }));
}

function legacyPctTag(parsed) {
  const entries = tagEntries(parsed, "pct");
  if (!entries.length) {
    return {
      observed: false,
      raw: null,
      numeric: null,
      semantics: "rfc7489_legacy",
      applied_to_effective_policy: false,
    };
  }
  const raw = entries[0].normalized_value;
  const numeric = /^[0-9]+$/.test(raw) && Number(raw) >= 0 && Number(raw) <= 100
    ? Number(raw)
    : null;
  return {
    observed: true,
    raw,
    numeric,
    semantics: "rfc7489_legacy",
    applied_to_effective_policy: false,
  };
}

export function parseDmarcbisPolicyRecord(record, index = 0) {
  const txt = concatenateDmarcbisTxtRecord(record, index);
  const initial = parseTagList(txt.value);
  const base = {
    ...txt,
    parser_version: DMARCBIS_PARSER_VERSION,
    is_current_version: initial.current_version,
    tags: initial.tags,
    unknown_tags: initial.tags.filter((tag) => !tag.known),
    duplicate_tags: initial.duplicate_tags,
    diagnostics: [...initial.errors],
  };

  if (!initial.current_version) {
    return {
      ...base,
      validity: "not_current_version",
      valid_for_discovery: false,
      policy_processing: false,
      policy_mode: "not_applicable",
    };
  }
  if (txt.truncated || txt.byte_length > DMARCBIS_MAX_TXT_RR_BYTES) {
    return {
      ...base,
      validity: "incomplete",
      valid_for_discovery: false,
      policy_processing: false,
      policy_mode: "incomplete",
      diagnostics: [
        ...base.diagnostics,
        {
          code: txt.truncated ? "truncated_unresolved" : "txt_rr_byte_limit",
          actual: txt.byte_length,
          maximum: DMARCBIS_MAX_TXT_RR_BYTES,
        },
      ],
    };
  }

  const duplicateFatal = initial.duplicate_tags.length > 0;
  const p = valueTag(initial, "p", POLICY_VALUES, "none");
  const sp = valueTag(initial, "sp", POLICY_VALUES);
  const np = valueTag(initial, "np", POLICY_VALUES);
  const t = valueTag(initial, "t", YORN_VALUES, "n");
  const psd = valueTag(initial, "psd", PSD_VALUES, "u");
  const adkim = valueTag(initial, "adkim", ALIGNMENT_VALUES, "r");
  const aspf = valueTag(initial, "aspf", ALIGNMENT_VALUES, "r");
  const fo = parseFoTag(initial);
  const rua = parseUriTag(initial, "rua");
  const ruf = parseUriTag(initial, "ruf");
  // RFC 9989 §4.10.1 applies this rule to the policy-tag set, not only p:
  // after §4.7's p=none default, an invalid p OR a present invalid sp/np uses
  // fallback p=none when at least one rua URI is syntactically valid; otherwise
  // no DMARC processing applies. A valid p never rescues an invalid sp or np.
  const invalidPolicyTag = [p, sp, np].some((tag) => tag.validity === "invalid");
  const validRua = rua.some((uri) => uri.syntax_valid);
  // RFC 9989 §4.8 requires syntax errors after the valid version tag to use
  // the tag's default, when defined, or otherwise be ignored. Preserve every
  // diagnostic, but do not make an unrelated remainder error fatal. Duplicate
  // tags remain fatal under the approved CyberMeters fail-honest contract.
  const fallbackNone = !duplicateFatal && invalidPolicyTag && validRua;
  const normalPolicy = !duplicateFatal && !invalidPolicyTag;
  const validForDiscovery = normalPolicy || fallbackNone;
  const defaulted =
    [p, t, psd, adkim, aspf, fo].some((tag) => tag.defaulted) ||
    [t, psd, adkim, aspf, fo].some((tag) => tag.validity === "invalid");

  const diagnostics = [...base.diagnostics];
  if (duplicateFatal) diagnostics.push({ code: "duplicate_tag", tags: initial.duplicate_tags });
  for (const [name, tag] of Object.entries({ p, sp, np, t, psd, adkim, aspf, fo })) {
    if (tag.validity === "invalid") diagnostics.push({ code: "invalid_tag_value", tag: name, raw: tag.raw });
  }

  return {
    ...base,
    diagnostics,
    validity: duplicateFatal || (!normalPolicy && !fallbackNone)
      ? "invalid"
      : defaulted
        ? "valid_with_defaults"
        : "valid",
    valid_for_discovery: validForDiscovery,
    policy_processing: validForDiscovery,
    policy_mode: fallbackNone
      ? "invalid_policy_fallback_none"
      : normalPolicy
        ? "normal"
        : "no_processing_invalid_policy",
    p,
    sp,
    np,
    t,
    psd,
    adkim,
    aspf,
    fo,
    rua,
    ruf,
    legacy_pct: legacyPctTag(initial),
    has_valid_rua: validRua,
    ignored_syntax_errors: initial.errors.length > 0,
  };
}

export function parseDmarcbisPolicyRecordSet(records = []) {
  const parsed_records = (Array.isArray(records) ? records : [])
    .map((record, index) => parseDmarcbisPolicyRecord(record, index));
  const candidates = parsed_records.filter((record) => record.is_current_version);
  const aggregateBytes = parsed_records.reduce((total, record) => total + record.byte_length, 0);

  if (aggregateBytes > DMARCBIS_MAX_DNS_EVIDENCE_BYTES) {
    return {
      raw_state: "incomplete_oversized",
      candidate_count: candidates.length,
      parsed_records,
      candidates,
      selected: null,
      complete: false,
      limits: [{
        type: "aggregate_dns_evidence_bytes",
        actual: aggregateBytes,
        maximum: DMARCBIS_MAX_DNS_EVIDENCE_BYTES,
      }],
    };
  }

  if (candidates.length === 0) {
    return {
      raw_state: parsed_records.length ? "non_dmarc_txt_only" : "absent",
      candidate_count: 0,
      parsed_records,
      candidates,
      selected: null,
      complete: true,
    };
  }
  if (candidates.some((record) => record.validity === "incomplete")) {
    return {
      raw_state: "incomplete_oversized",
      candidate_count: candidates.length,
      parsed_records,
      candidates,
      selected: null,
      complete: false,
    };
  }
  if (candidates.length > 1) {
    const validCount = candidates.filter((record) => record.valid_for_discovery).length;
    const rawState = validCount === candidates.length
      ? "multiple"
      : validCount > 0
        ? "multiple_mixed"
        : "multiple_invalid";
    return {
      raw_state: rawState,
      candidate_count: candidates.length,
      parsed_records,
      candidates,
      selected: null,
      complete: true,
    };
  }

  const selected = candidates[0];
  const rawState = selected.valid_for_discovery
    ? parsed_records.length > 1
      ? "single_valid_with_non_dmarc_txt"
      : selected.validity === "valid_with_defaults"
        ? "single_valid_with_defaults"
        : "single_valid"
    : selected.duplicate_tags.length
      ? "single_invalid_duplicate_tag"
      : "single_invalid";
  return {
    raw_state: rawState,
    candidate_count: 1,
    parsed_records,
    candidates,
    selected: selected.valid_for_discovery ? selected : null,
    invalid_candidate: selected.valid_for_discovery ? null : selected,
    complete: true,
  };
}

export function parseDmarcbisAuthorizationRecord(record, index = 0) {
  const txt = concatenateDmarcbisTxtRecord(record, index);
  const parsed = parseTagList(txt.value);
  const base = {
    ...txt,
    parser_version: DMARCBIS_PARSER_VERSION,
    is_current_version: parsed.current_version,
    tags: parsed.tags,
    duplicate_tags: parsed.duplicate_tags,
    diagnostics: [...parsed.errors],
    rua: [],
  };
  if (!parsed.current_version) return { ...base, valid: false, validity: "not_current_version" };
  if (txt.truncated || txt.byte_length > DMARCBIS_MAX_TXT_RR_BYTES) {
    return {
      ...base,
      valid: false,
      validity: "incomplete",
      diagnostics: [
        ...base.diagnostics,
        {
          code: txt.truncated ? "truncated_unresolved" : "txt_rr_byte_limit",
          actual: txt.byte_length,
          maximum: DMARCBIS_MAX_TXT_RR_BYTES,
        },
      ],
    };
  }
  const valid = parsed.errors.length === 0 && parsed.duplicate_tags.length === 0;
  return {
    ...base,
    valid,
    validity: valid ? "valid" : "invalid",
    rua: parseUriTag(parsed, "rua"),
  };
}

export function parseDmarcbisAuthorizationRecordSet(records = []) {
  const parsed_records = (Array.isArray(records) ? records : [])
    .map((record, index) => parseDmarcbisAuthorizationRecord(record, index));
  const valid_records = parsed_records.filter((record) => record.valid);
  const currentRecords = parsed_records.filter((record) => record.is_current_version);
  const currentInvalid = parsed_records.filter(
    (record) => record.is_current_version && !record.valid,
  );
  const aggregateBytes = parsed_records.reduce(
    (total, record) => total + record.byte_length,
    0,
  );

  if (aggregateBytes > DMARCBIS_MAX_DNS_EVIDENCE_BYTES) {
    return {
      authorized: false,
      record_state: "incomplete_oversized",
      parsed_records,
      valid_records: [],
      complete: false,
      limits: [{
        type: "aggregate_dns_evidence_bytes",
        actual: aggregateBytes,
        maximum: DMARCBIS_MAX_DNS_EVIDENCE_BYTES,
      }],
    };
  }

  let record_state = "absent";
  if (valid_records.length === 1 && currentInvalid.length === 0) record_state = "single_valid";
  else if (valid_records.length > 1 && currentInvalid.length === 0) record_state = "multiple_valid";
  else if (valid_records.length > 0) record_state = "mixed";
  else if (currentRecords.length > 0) record_state = "malformed";

  return {
    authorized: valid_records.length > 0,
    record_state,
    parsed_records,
    current_records: currentRecords,
    valid_records,
    complete: true,
  };
}
