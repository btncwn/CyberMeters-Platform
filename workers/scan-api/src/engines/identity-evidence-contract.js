// Canonical Identity evidence-in-TEXT contract.
//
// New Identity evidence remains an array in the existing TEXT carriers. This
// module owns its vocabulary, typed confidence, compatibility reader and pure
// claim projection. It performs no persistence and no network I/O.

export const IDENTITY_EVIDENCE_SCHEMA_VERSION = "identity_evidence.v2";
export const IDENTITY_CONFIDENCE_SCHEMA_VERSION = "identity_confidence.v1";
export const IDENTITY_CLAIM_SCHEMA_VERSION = "identity_claim.v2";

export const IDENTITY_EVIDENCE_SOURCES = Object.freeze([
  "cname", "spf", "mx", "csp", "server",
  "certificate_transparency", "dns_bruteforce", "dns_mx", "unknown",
]);
export const IDENTITY_PROVENANCE_MODULES = Object.freeze([
  "subdomain_takeover", "asset_exposure", "dns_bruteforce", "email_security",
  "dns", "headers", "subdomains", "unknown",
]);
export const IDENTITY_MATCH_PRECISIONS = Object.freeze([
  "exact_host", "label_boundary", "host_substring", "token_substring",
  "hostname_prefix", "not_applicable", "unknown",
]);
export const IDENTITY_NAME_RESOLUTION_STATES = Object.freeze([
  "resolved", "mx_only", "not_evaluated", "unknown_legacy",
]);
export const IDENTITY_VALIDATION_STATES = Object.freeze([
  "observed", "source_incomplete", "unknown_legacy", "malformed",
]);

const SOURCE_SET = new Set(IDENTITY_EVIDENCE_SOURCES);
const PROVENANCE_MODULE_SET = new Set(IDENTITY_PROVENANCE_MODULES);
const PRECISION_SET = new Set(IDENTITY_MATCH_PRECISIONS);
const RESOLUTION_SET = new Set(IDENTITY_NAME_RESOLUTION_STATES);
const VALIDATION_SET = new Set(IDENTITY_VALIDATION_STATES);
const CONFIDENCE_SUBJECTS = new Set(["provider_identification", "hostname_classification", "unknown"]);
const CONFIDENCE_LEVELS = new Set(["high", "medium", "low", "unknown"]);
const CONFIDENCE_QUALITIES = new Set(["excellent", "good", "partial", "unknown"]);
const CONFIDENCE_BASES = new Set([
  "exact_host", "label_boundary", "host_substring", "token_substring",
  "hostname_prefix", "legacy", "malformed",
]);
const PRECISION_RANK = Object.freeze({
  exact_host: 5,
  label_boundary: 4,
  host_substring: 3,
  token_substring: 2,
  hostname_prefix: 1,
  not_applicable: 0,
  unknown: 0,
});

export function normalizeIdentityObservedAt(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) {
    return null;
  }
  return Number.isFinite(Date.parse(value)) ? value : null;
}

export function identityConfidenceForPrecision(precision, subject = "unknown") {
  const safeSubject = CONFIDENCE_SUBJECTS.has(subject) ? subject : "unknown";
  const mapping = {
    exact_host: ["high", 90, "excellent", "exact_host"],
    label_boundary: ["high", 85, "good", "label_boundary"],
    host_substring: ["medium", 65, "partial", "host_substring"],
    token_substring: ["low", 45, "partial", "token_substring"],
    hostname_prefix: ["medium", 60, "partial", "hostname_prefix"],
  }[precision];
  const [level, score, quality, basis] = mapping ?? ["unknown", null, "unknown", "legacy"];
  return {
    schema_version: IDENTITY_CONFIDENCE_SCHEMA_VERSION,
    subject: safeSubject,
    level,
    score,
    quality,
    basis,
  };
}

export function createIdentityEvidenceDatum({
  source,
  value = null,
  provenance = {},
  matchPrecision = "unknown",
  nameResolution = "not_evaluated",
  validationState = "observed",
  confidenceSubject = "unknown",
  observedAt = null,
  ipAddresses,
}) {
  const safeSource = SOURCE_SET.has(source) ? source : "unknown";
  const safePrecision = PRECISION_SET.has(matchPrecision) ? matchPrecision : "unknown";
  const safeResolution = RESOLUTION_SET.has(nameResolution) ? nameResolution : "not_evaluated";
  const safeValidation = VALIDATION_SET.has(validationState) ? validationState : "malformed";
  const datum = {
    schema_version: IDENTITY_EVIDENCE_SCHEMA_VERSION,
    source: safeSource,
    value: value == null ? null : String(value),
    provenance: {
      producer: typeof provenance.producer === "string" ? provenance.producer : "identity_discovery",
      module: PROVENANCE_MODULE_SET.has(provenance.module) ? provenance.module : "unknown",
      path: typeof provenance.path === "string" ? provenance.path : null,
    },
    match_precision: safePrecision,
    name_resolution: safeResolution,
    validation_state: safeValidation,
    confidence_detail: identityConfidenceForPrecision(safePrecision, confidenceSubject),
    observed_at: normalizeIdentityObservedAt(observedAt),
  };
  if (safeSource === "dns_bruteforce" && safeResolution === "resolved" && Array.isArray(ipAddresses)) {
    datum.ip_addresses = [...new Set(ipAddresses.map((item) => String(item).trim()).filter(Boolean))];
  }
  return datum;
}

export function serializeIdentityEvidence(value) {
  if (!Array.isArray(value)) throw new TypeError("Identity evidence must be a JSON array");
  try {
    const encoded = JSON.stringify(value);
    if (typeof encoded !== "string") throw new TypeError("Identity evidence is not serializable");
    return encoded;
  } catch (error) {
    throw new TypeError(`Identity evidence is not serializable: ${error?.message ?? error}`);
  }
}

function isConfidenceDetail(value) {
  return value?.schema_version === IDENTITY_CONFIDENCE_SCHEMA_VERSION &&
    CONFIDENCE_SUBJECTS.has(value.subject) &&
    CONFIDENCE_LEVELS.has(value.level) &&
    (value.score === null || (Number.isInteger(value.score) && value.score >= 0 && value.score <= 100)) &&
    CONFIDENCE_QUALITIES.has(value.quality) &&
    CONFIDENCE_BASES.has(value.basis);
}

function isValidV2Datum(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (value.schema_version !== IDENTITY_EVIDENCE_SCHEMA_VERSION) return false;
  if (!SOURCE_SET.has(value.source) || (value.value !== null && typeof value.value !== "string")) return false;
  if (!value.provenance || typeof value.provenance !== "object" || Array.isArray(value.provenance)) return false;
  if (value.provenance.producer !== "identity_discovery" || !PROVENANCE_MODULE_SET.has(value.provenance.module)) return false;
  if (value.provenance.path !== null && typeof value.provenance.path !== "string") return false;
  if (!PRECISION_SET.has(value.match_precision) || !RESOLUTION_SET.has(value.name_resolution)) return false;
  if (!VALIDATION_SET.has(value.validation_state) || !isConfidenceDetail(value.confidence_detail)) return false;
  if (value.observed_at !== null && normalizeIdentityObservedAt(value.observed_at) === null) return false;
  if (value.ip_addresses !== undefined && (!Array.isArray(value.ip_addresses) ||
    value.source !== "dns_bruteforce" || value.name_resolution !== "resolved" ||
    value.ip_addresses.some((item) => typeof item !== "string"))) return false;
  return true;
}

function isLegacyDatum(value) {
  return value && typeof value === "object" && !Array.isArray(value) &&
    value.schema_version === undefined && typeof value.source === "string" &&
    (Object.hasOwn(value, "value") || Object.hasOwn(value, "detail"));
}

function projectLegacyDatum(value) {
  return {
    ...value,
    match_precision: "unknown",
    name_resolution: "unknown_legacy",
    validation_state: "unknown_legacy",
    confidence_detail: {
      schema_version: IDENTITY_CONFIDENCE_SCHEMA_VERSION,
      subject: "unknown",
      level: "unknown",
      score: null,
      quality: "unknown",
      basis: "legacy",
    },
    observed_at: null,
  };
}

function malformedProjection(value) {
  return {
    schema_version: null,
    source: "unknown",
    value: null,
    raw_type: value === null ? "null" : Array.isArray(value) ? "array" : typeof value,
    match_precision: "unknown",
    name_resolution: "not_evaluated",
    validation_state: "malformed",
    confidence_detail: {
      schema_version: IDENTITY_CONFIDENCE_SCHEMA_VERSION,
      subject: "unknown",
      level: "unknown",
      score: null,
      quality: "unknown",
      basis: "malformed",
    },
    observed_at: null,
  };
}

export function readIdentityEvidence(raw) {
  if (raw == null || raw === "") {
    return { status: "empty", items: [], valid_v2_count: 0, legacy_count: 0, malformed_count: 0 };
  }

  let decoded = raw;
  if (typeof raw === "string") {
    try {
      decoded = JSON.parse(raw);
    } catch {
      return {
        status: "malformed", items: [], valid_v2_count: 0, legacy_count: 0, malformed_count: 1,
      };
    }
  }

  let legacyEnvelope = false;
  if (decoded && typeof decoded === "object" && !Array.isArray(decoded) && Array.isArray(decoded.evidence)) {
    decoded = decoded.evidence;
    legacyEnvelope = true;
  } else if (isLegacyDatum(decoded)) {
    decoded = [decoded];
  }

  if (!Array.isArray(decoded)) {
    return {
      status: "malformed", items: [], valid_v2_count: 0, legacy_count: 0, malformed_count: 1,
    };
  }
  if (decoded.length === 0) {
    return {
      status: legacyEnvelope ? "legacy" : "empty",
      items: [], valid_v2_count: 0, legacy_count: 0, malformed_count: 0,
      ...(legacyEnvelope ? { legacy_envelope: true } : {}),
    };
  }

  let validV2Count = 0;
  let legacyCount = 0;
  let malformedCount = 0;
  const items = decoded.map((item) => {
    if (isValidV2Datum(item)) {
      validV2Count += 1;
      return item;
    }
    if (isLegacyDatum(item)) {
      legacyCount += 1;
      return projectLegacyDatum(item);
    }
    malformedCount += 1;
    return malformedProjection(item);
  });

  const populatedKinds = [validV2Count, legacyCount, malformedCount].filter((count) => count > 0).length;
  const status = populatedKinds > 1
    ? "mixed"
    : validV2Count > 0
      ? "valid_v2"
      : legacyCount > 0
        ? "legacy"
        : "malformed";
  return {
    status,
    items,
    valid_v2_count: validV2Count,
    legacy_count: legacyCount,
    malformed_count: malformedCount,
    ...(legacyEnvelope ? { legacy_envelope: true } : {}),
  };
}

export function strongestIdentityConfidence(items, subject = null) {
  const eligible = (items ?? []).filter((item) => item?.schema_version === IDENTITY_EVIDENCE_SCHEMA_VERSION &&
    (!subject || item?.confidence_detail?.subject === subject));
  if (eligible.length === 0) return {
    schema_version: IDENTITY_CONFIDENCE_SCHEMA_VERSION,
    subject: subject ?? "unknown",
    level: "unknown",
    score: null,
    quality: "unknown",
    basis: "legacy",
  };
  return eligible.reduce((strongest, item) =>
    (PRECISION_RANK[item.match_precision] ?? 0) > (PRECISION_RANK[strongest.match_precision] ?? 0)
      ? item
      : strongest).confidence_detail;
}

export function aggregateIdentityNameResolution(items, evidenceStatus = "empty") {
  const valid = (items ?? []).filter((item) => item?.schema_version === IDENTITY_EVIDENCE_SCHEMA_VERSION);
  let status = "not_evaluated";
  if (valid.some((item) => item.name_resolution === "resolved")) status = "resolved";
  else if (valid.some((item) => item.name_resolution === "mx_only")) status = "mx_only";
  else if (valid.length === 0 && (evidenceStatus === "legacy" || evidenceStatus === "mixed") &&
    (items ?? []).some((item) => item?.validation_state === "unknown_legacy")) status = "unknown_legacy";
  const supporting = valid.filter((item) => item.name_resolution === status);
  return {
    status,
    evidence_sources: [...new Set(supporting.map((item) => item.source))],
    measured_at: status === "resolved" || status === "mx_only"
      ? supporting.map((item) => normalizeIdentityObservedAt(item.observed_at)).find(Boolean) ?? null
      : null,
  };
}

function relationshipStatus(items, provider) {
  if (!provider) return "not_applicable";
  const providerItems = items.filter((item) => item?.schema_version === IDENTITY_EVIDENCE_SCHEMA_VERSION &&
    item?.confidence_detail?.subject === "provider_identification");
  if (providerItems.some((item) => item.match_precision === "exact_host" || item.match_precision === "label_boundary")) return "observed";
  if (providerItems.some((item) => ["host_substring", "token_substring"].includes(item.match_precision))) return "possible";
  return "unknown";
}

export function buildIdentityClaim(row = {}) {
  const evidence = readIdentityEvidence(row.evidence);
  const validItems = evidence.items.filter((item) => item?.schema_version === IDENTITY_EVIDENCE_SCHEMA_VERSION);
  const provider = typeof row.provider === "string" && row.provider ? row.provider : null;
  const hostname = typeof row.hostname === "string" && row.hostname ? row.hostname : null;
  const providerItems = validItems.filter((item) => item?.confidence_detail?.subject === "provider_identification");
  const classificationItems = validItems.filter((item) => item?.confidence_detail?.subject === "hostname_classification");
  const providerStatus = relationshipStatus(validItems, provider);
  const surfaceStatus = hostname
    ? classificationItems.length > 0 ? "possible" : "unknown"
    : "not_applicable";
  const resolution = aggregateIdentityNameResolution(evidence.items, evidence.status);
  return {
    schema_version: IDENTITY_CLAIM_SCHEMA_VERSION,
    claim_kind: provider ? "provider_relationship" : "surface_candidate",
    provider_relationship: {
      status: providerStatus,
      provider,
      evidence_sources: [...new Set(providerItems.map((item) => item.source))],
      confidence_detail: strongestIdentityConfidence(providerItems, "provider_identification"),
    },
    surface_classification: {
      status: surfaceStatus,
      surface_type: hostname ? row.identity_type ?? null : null,
      basis: surfaceStatus === "possible" ? "hostname_prefix" : surfaceStatus === "unknown" ? "unknown" : null,
      confidence_detail: strongestIdentityConfidence(classificationItems, "hostname_classification"),
    },
    name_resolution: resolution,
    reachability: {
      status: "not_evaluated",
      endpoint: null,
      method: null,
      measured_at: null,
      confidence_detail: null,
    },
    evidence_grade: {
      relationship: providerItems.length > 0 ? "L1" : "L0",
      classification: classificationItems.length > 0 ? "L1" : "L0",
      name_resolution: ["resolved", "mx_only"].includes(resolution.status) ? "L1" : "L0",
      reachability: "L0",
    },
  };
}

export function buildIdentityEvidenceProjection(row = {}) {
  const evidence = readIdentityEvidence(row.evidence);
  const subject = row.provider ? "provider_identification" : "hostname_classification";
  return {
    evidence_status: evidence.status,
    confidence_detail: strongestIdentityConfidence(evidence.items, subject),
    identity_claim: buildIdentityClaim(row),
  };
}
