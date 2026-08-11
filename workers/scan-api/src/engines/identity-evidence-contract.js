// Canonical Identity evidence-in-TEXT contract.
//
// New Identity evidence remains an array in the existing TEXT carriers. This
// module owns its vocabulary, typed confidence, compatibility reader and pure
// claim projection. It performs no persistence and no network I/O.

export const IDENTITY_EVIDENCE_SCHEMA_VERSION = "identity_evidence.v2";
export const IDENTITY_CONFIDENCE_SCHEMA_VERSION = "identity_confidence.v1";
export const IDENTITY_CLAIM_SCHEMA_VERSION = "identity_claim.v2";

// U1 canonical storage/read grain. Keep this as the only declaration of the
// tuple so writers, consumers and mutation tests cannot silently diverge.
export const CANONICAL_IDENTITY_TUPLE_COLUMNS = Object.freeze([
  "workspace_id", "domain_id", "identity_type",
  "IFNULL(hostname,'')", "IFNULL(provider,'')",
]);

// Existing rows are immutable evidence history. Reads collapse legacy physical
// multiplicity deterministically without a migration or delimiter-built key.
// The representative owns the stable pointer; the latest row owns mutable
// observation payload; group aggregates own first/last/risk semantics.
export const CANONICAL_IDENTITY_CTE = `
WITH identity_ranked AS (
  SELECT ia.*,
         ROW_NUMBER() OVER (
           PARTITION BY workspace_id, domain_id, identity_type,
                        IFNULL(hostname, ''), IFNULL(provider, '')
           ORDER BY first_seen ASC, created_at ASC, id ASC
         ) AS representative_rank,
         ROW_NUMBER() OVER (
           PARTITION BY workspace_id, domain_id, identity_type,
                        IFNULL(hostname, ''), IFNULL(provider, '')
           ORDER BY last_seen DESC,
                    COALESCE(updated_at, created_at, '') DESC,
                    scan_id DESC, id DESC
         ) AS latest_rank
    FROM identity_assets ia
   WHERE workspace_id = ? AND status = 'active'
),
identity_groups AS (
  SELECT workspace_id, domain_id, identity_type,
         IFNULL(hostname, '') AS canonical_hostname,
         IFNULL(provider, '') AS canonical_provider,
         MIN(first_seen) AS first_seen,
         MAX(last_seen) AS last_seen,
         MAX(risk_score) AS risk_score,
         COUNT(*) AS historical_row_count
    FROM identity_ranked
   GROUP BY workspace_id, domain_id, identity_type,
            IFNULL(hostname, ''), IFNULL(provider, '')
),
identity_representatives AS (
  SELECT * FROM identity_ranked WHERE representative_rank = 1
),
identity_latest AS (
  SELECT * FROM identity_ranked WHERE latest_rank = 1
),
canonical_identity_assets AS (
  SELECT representative.id,
         grouped.workspace_id,
         grouped.domain_id,
         latest.scan_id,
         NULLIF(grouped.canonical_hostname, '') AS hostname,
         representative.asset_type,
         grouped.identity_type,
         NULLIF(grouped.canonical_provider, '') AS provider,
         representative.internet_exposed,
         representative.source,
         grouped.risk_score,
         latest.evidence,
         grouped.first_seen,
         grouped.last_seen,
         representative.status,
         representative.created_at,
         latest.updated_at,
         grouped.historical_row_count
    FROM identity_groups grouped
    JOIN identity_representatives representative
      ON representative.workspace_id = grouped.workspace_id
     AND representative.domain_id = grouped.domain_id
     AND representative.identity_type = grouped.identity_type
     AND IFNULL(representative.hostname, '') = grouped.canonical_hostname
     AND IFNULL(representative.provider, '') = grouped.canonical_provider
    JOIN identity_latest latest
      ON latest.workspace_id = grouped.workspace_id
     AND latest.domain_id = grouped.domain_id
     AND latest.identity_type = grouped.identity_type
     AND IFNULL(latest.hostname, '') = grouped.canonical_hostname
     AND IFNULL(latest.provider, '') = grouped.canonical_provider
)
`;

export const IDENTITY_CANONICAL_SUMMARY_TOTAL_QUERY = `${CANONICAL_IDENTITY_CTE}
SELECT COUNT(*) AS n FROM canonical_identity_assets`;
export const IDENTITY_CANONICAL_SUMMARY_TYPE_QUERY = `${CANONICAL_IDENTITY_CTE}
SELECT identity_type, COUNT(*) AS n FROM canonical_identity_assets GROUP BY identity_type`;
export const IDENTITY_CANONICAL_SUMMARY_PROVIDER_QUERY = `${CANONICAL_IDENTITY_CTE}
SELECT provider, COUNT(*) AS n FROM canonical_identity_assets
 WHERE provider IS NOT NULL AND provider != ''
 GROUP BY provider ORDER BY n DESC, provider ASC`;
export const IDENTITY_CANONICAL_SUMMARY_HIGH_RISK_QUERY = `${CANONICAL_IDENTITY_CTE}
SELECT COUNT(*) AS n FROM canonical_identity_assets WHERE risk_score >= 15`;
export const IDENTITY_CANONICAL_EXPOSURE_QUERY = `${CANONICAL_IDENTITY_CTE}
SELECT hostname, identity_type, provider, internet_exposed, risk_score
  FROM canonical_identity_assets
 ORDER BY risk_score DESC, internet_exposed DESC, id ASC LIMIT 100`;
export const IDENTITY_CANONICAL_SHADOW_QUERY = `${CANONICAL_IDENTITY_CTE}
SELECT id, hostname, provider, risk_score, first_seen, last_seen
  FROM canonical_identity_assets
 WHERE provider IS NOT NULL AND provider != ''`;
export const IDENTITY_CANONICAL_LIFECYCLE_QUERY = `${CANONICAL_IDENTITY_CTE}
SELECT id, domain_id, hostname, asset_type, identity_type, provider,
       internet_exposed, source, risk_score, evidence, first_seen, last_seen
  FROM canonical_identity_assets`;
export const IDENTITY_CANONICAL_RELATED_CHANGES_QUERY = `${CANONICAL_IDENTITY_CTE}
SELECT id, hostname, identity_type, provider, first_seen
  FROM canonical_identity_assets
 WHERE first_seen >= ? AND first_seen <= ?`;

export function buildCanonicalIdentityListQuery({ filterType, filterProvider, filterRisk } = {}) {
  const clauses = [];
  if (filterType) clauses.push("identity_type = ?");
  if (filterProvider) clauses.push("provider = ?");
  if (filterRisk !== null && filterRisk !== undefined) clauses.push("risk_score >= ?");
  return `${CANONICAL_IDENTITY_CTE}
SELECT * FROM canonical_identity_assets${clauses.length ? ` WHERE ${clauses.join(" AND ")}` : ""}
 ORDER BY risk_score DESC, first_seen DESC, id ASC LIMIT ?`;
}

export const IDENTITY_CANONICAL_LIST_QUERY = buildCanonicalIdentityListQuery({});

export const RELATED_CHANGE_RECURRENCE_SCHEMA_VERSION = "related_change_recurrence.v2";

export function projectRelatedChangeRecurrence(row = {}) {
  const polluted = Number(row.identity_polluted_tuple_count || 0);
  const unresolved = Number(row.identity_unresolved_pointer_count || 0);
  if (polluted > 0) return {
    schema_version: RELATED_CHANGE_RECURRENCE_SCHEMA_VERSION,
    status: "not_comparable", count: null,
    reason: "legacy_identity_multiplicity",
    source: "canonical_evidence_projection",
  };
  if (unresolved > 0 || !Number.isInteger(Number(row.recurrence_count)) || Number(row.recurrence_count) < 1) return {
    schema_version: RELATED_CHANGE_RECURRENCE_SCHEMA_VERSION,
    status: "unknown", count: null,
    reason: "identity_evidence_unavailable",
    source: "canonical_evidence_projection",
  };
  return {
    schema_version: RELATED_CHANGE_RECURRENCE_SCHEMA_VERSION,
    status: "comparable", count: Number(row.recurrence_count), reason: null,
    source: "canonical_evidence_projection",
  };
}

// Raw-access allow-list (NEW in U1): related-changes.js may access physical
// identity_assets solely for append-only/audit pointer resolution, detecting
// legacy tuple pollution and missing references. It must never
// use that raw join as a customer count or canonical identity consumer.

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
