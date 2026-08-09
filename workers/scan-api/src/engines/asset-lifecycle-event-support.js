import {
  applyAssetRemovalConfirmation,
  ASSET_REMOVAL_CONFIRMATION_POLICY,
} from "./attack-surface-signal-completeness.js";

export const ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION =
  "asset-lifecycle-claim-projection-v1";
export const ASSET_LIFECYCLE_REPLAY_ORDER_VERSION =
  "asset-lifecycle-replay-order-v1";
export const ASSET_LIFECYCLE_TIMESTAMP_VERSION =
  "asset-lifecycle-timestamp-v1";
export const ASSET_LIFECYCLE_D1_BINDING_LIMIT = 100;
export const ASSET_LIFECYCLE_BINDINGS_PER_ANCHOR = 3;
export const ASSET_LIFECYCLE_MIN_WORKSPACES_PER_PACK = 1;
export const ASSET_LIFECYCLE_MAX_SINGLE_WORKSPACE_ANCHORS = Math.floor(
  (ASSET_LIFECYCLE_D1_BINDING_LIMIT - ASSET_LIFECYCLE_MIN_WORKSPACES_PER_PACK) /
  ASSET_LIFECYCLE_BINDINGS_PER_ANCHOR,
);
export const ASSET_LIFECYCLE_MAX_QUERY_CONCURRENCY = 4;

export const ASSET_LIFECYCLE_SUPPORT_REASON_CODES = Object.freeze([
  "eligible_confirmed_removal",
  "eligible_reappearance_after_confirmed_removal",
  "withheld_removal_confirmation_not_satisfied",
  "withheld_reappearance_predecessor_unconfirmed",
  "withheld_support_not_evaluable",
  "withheld_lifecycle_evidence_not_recorded",
  "withheld_lifecycle_schema_absent",
  "withheld_evidence_lookup_unavailable",
  "withheld_lifecycle_policy_unknown",
  "withheld_lifecycle_source_detail_malformed",
  "withheld_lifecycle_timestamp_invalid",
  "withheld_lifecycle_replay_truncated",
]);

export const ASSET_LIFECYCLE_SUPPORT_LIMITATION_CODES = Object.freeze([
  "asset_identity_not_recorded",
  "event_scan_not_recorded",
  "lifecycle_schema_absent",
  "lifecycle_evidence_read_failed",
  "exact_lifecycle_anchor_absent",
  "bounded_relevant_replay_truncated",
  "invalid_relevant_timestamp",
  "unknown_policy_version",
  "malformed_source_detail",
  "collection_limit_exceeded",
]);

const LIFECYCLE_EVENT_TYPES = Object.freeze([
  "asset_no_longer_seen",
  "asset_reappeared",
]);
const LIFECYCLE_EVENT_SET = new Set(LIFECYCLE_EVENT_TYPES);
const ZONED_ISO = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?(Z|([+-])(\d{2}):(\d{2}))$/;
const SQLITE_UTC = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?$/;

// SQL companion to normalizeLifecycleTimestamp(). `columnExpression` must be a
// trusted static SQL identifier/expression supplied by application source, never
// request data. The lexical envelope is deliberately explicit: julianday() alone
// accepts formats and normalisations that the frozen Worker parser rejects.
export function lifecycleTimestampValiditySql(columnExpression) {
  const value = `CAST(${columnExpression} AS TEXT)`;
  const sqliteSeconds = `(${value} GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9]')`;
  const sqliteMillis = `(${value} GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]')`;
  const isoZuluSeconds = `(${value} GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]Z')`;
  const isoZuluMillis = `(${value} GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9]Z')`;
  const isoOffsetSeconds = `(${value} GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9][+-][0-9][0-9]:[0-9][0-9]')`;
  const isoOffsetMillis = `(${value} GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][+-][0-9][0-9]:[0-9][0-9]')`;
  const isOffset = `(length(${value}) IN (25,29) AND substr(${value}, -6, 1) IN ('+','-'))`;
  const offsetHour = `CAST(substr(${value}, -5, 2) AS INTEGER)`;
  const offsetMinute = `CAST(substr(${value}, -2, 2) AS INTEGER)`;
  const year = `CAST(substr(${value}, 1, 4) AS INTEGER)`;
  const month = `CAST(substr(${value}, 6, 2) AS INTEGER)`;
  const day = `CAST(substr(${value}, 9, 2) AS INTEGER)`;
  const hour = `CAST(substr(${value}, 12, 2) AS INTEGER)`;
  const minute = `CAST(substr(${value}, 15, 2) AS INTEGER)`;
  const second = `CAST(substr(${value}, 18, 2) AS INTEGER)`;
  const lastDay = `CAST(strftime('%d', date(substr(${value}, 1, 7) || '-01', '+1 month', '-1 day')) AS INTEGER)`;
  return `(typeof(${columnExpression}) = 'text'
    AND (${sqliteSeconds} OR ${sqliteMillis} OR ${isoZuluSeconds} OR ${isoZuluMillis}
      OR ${isoOffsetSeconds} OR ${isoOffsetMillis})
    AND ${year} >= 1
    AND ${month} BETWEEN 1 AND 12
    AND ${day} BETWEEN 1 AND ${lastDay}
    AND ${hour} BETWEEN 0 AND 23
    AND ${minute} BETWEEN 0 AND 59
    AND ${second} BETWEEN 0 AND 59
    AND (NOT ${isOffset} OR (
      ${offsetHour} BETWEEN 0 AND 14
      AND ${offsetMinute} BETWEEN 0 AND 59
      AND (${offsetHour} < 14 OR ${offsetMinute} = 0)
    ))
    AND julianday(${columnExpression}) IS NOT NULL)`;
}

function utcEpoch(year, month, day, hour, minute, second, millisecond) {
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, millisecond);
  if (
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second ||
    date.getUTCMilliseconds() !== millisecond
  ) return null;
  return date.getTime();
}

export function normalizeLifecycleTimestamp(value) {
  if (typeof value !== "string") return { valid: false };
  const iso = value.match(ZONED_ISO);
  const sqlite = value.match(SQLITE_UTC);
  const match = iso || sqlite;
  if (!match) return { valid: false };

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const millisecond = Number(match[7] || 0);
  if (year < 1 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) {
    return { valid: false };
  }
  const localEpoch = utcEpoch(year, month, day, hour, minute, second, millisecond);
  if (localEpoch === null) return { valid: false };

  let offsetMinutes = 0;
  if (iso && match[8] !== "Z") {
    const offsetHours = Number(match[10]);
    const offsetRemainder = Number(match[11]);
    if (
      offsetHours > 14 ||
      offsetRemainder > 59 ||
      (offsetHours === 14 && offsetRemainder !== 0)
    ) return { valid: false };
    offsetMinutes = (offsetHours * 60 + offsetRemainder) * (match[9] === "+" ? 1 : -1);
  }
  const epochMs = localEpoch - offsetMinutes * 60_000;
  if (!Number.isFinite(epochMs)) return { valid: false };
  return {
    valid: true,
    epoch_ms: epochMs,
    canonical_utc: new Date(epochMs).toISOString(),
    source_format: sqlite ? "sqlite_utc" : "iso_zoned",
  };
}

function compareBytewise(a, b) {
  const left = String(a ?? "");
  const right = String(b ?? "");
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const delta = left.charCodeAt(index) - right.charCodeAt(index);
    if (delta !== 0) return delta < 0 ? -1 : 1;
  }
  return left.length === right.length ? 0 : left.length < right.length ? -1 : 1;
}

export function compareLifecycleObservationOrder(a, b) {
  const observedA = normalizeLifecycleTimestamp(a?.observed_at);
  const observedB = normalizeLifecycleTimestamp(b?.observed_at);
  if (!observedA.valid || !observedB.valid) {
    throw new TypeError("Lifecycle observations require valid observed_at timestamps");
  }
  if (observedA.epoch_ms !== observedB.epoch_ms) {
    return observedA.epoch_ms < observedB.epoch_ms ? -1 : 1;
  }
  const createdA = normalizeLifecycleTimestamp(a?.created_at);
  const createdB = normalizeLifecycleTimestamp(b?.created_at);
  if (!createdA.valid || !createdB.valid) {
    throw new TypeError("Lifecycle observations require valid created_at timestamps");
  }
  if (createdA.epoch_ms !== createdB.epoch_ms) {
    return createdA.epoch_ms < createdB.epoch_ms ? -1 : 1;
  }
  return compareBytewise(a?.scan_id, b?.scan_id);
}

export function isDecisionRelevantLifecycleObservation(row) {
  return row?.qualifies_removal === 1 || row?.observation_state === "observed";
}

const LIMITATION_PRECEDENCE = Object.freeze([
  "asset_identity_not_recorded", "event_scan_not_recorded",
  "lifecycle_schema_absent", "lifecycle_evidence_read_failed",
  "exact_lifecycle_anchor_absent", "bounded_relevant_replay_truncated",
  "invalid_relevant_timestamp", "unknown_policy_version", "malformed_source_detail",
]);
const LIMITATION_REASON = Object.freeze({
  asset_identity_not_recorded: "withheld_support_not_evaluable",
  event_scan_not_recorded: "withheld_support_not_evaluable",
  lifecycle_schema_absent: "withheld_lifecycle_schema_absent",
  lifecycle_evidence_read_failed: "withheld_evidence_lookup_unavailable",
  exact_lifecycle_anchor_absent: "withheld_lifecycle_evidence_not_recorded",
  bounded_relevant_replay_truncated: "withheld_lifecycle_replay_truncated",
  invalid_relevant_timestamp: "withheld_lifecycle_timestamp_invalid",
  unknown_policy_version: "withheld_lifecycle_policy_unknown",
  malformed_source_detail: "withheld_lifecycle_source_detail_malformed",
});

function uncertain(reasonCode, limitation, eventType = null, limitationCodes = null) {
  const codes = limitationCodes?.length ? limitationCodes : [limitation];
  const ordered = [...new Set(codes)].sort((a, b) =>
    LIMITATION_PRECEDENCE.indexOf(a) - LIMITATION_PRECEDENCE.indexOf(b));
  const primary = ordered[0] || limitation;
  return {
    state: "uncertain",
    evidence_backed: null,
    reason_code: LIMITATION_REASON[primary] || reasonCode,
    limitation: primary,
    limitation_codes: ordered,
    event_type: eventType,
  };
}

function lifecycleReadFailure(status, eventType) {
  if (status === "schema_absent") {
    return uncertain(
      "withheld_lifecycle_schema_absent",
      "lifecycle_schema_absent",
      eventType,
    );
  }
  return uncertain(
    "withheld_evidence_lookup_unavailable",
    "lifecycle_evidence_read_failed",
    eventType,
  );
}

function parseSourceDetail(row) {
  let detail;
  try {
    detail = typeof row?.source_detail_json === "string"
      ? JSON.parse(row.source_detail_json)
      : row?.source_detail_json;
  } catch {
    return { valid: false };
  }
  if (!detail || typeof detail !== "object" || Array.isArray(detail)) {
    return { valid: false };
  }
  if (!Array.isArray(detail.active_sources)) return { valid: false };
  if (
    !detail.dns_resolution || typeof detail.dns_resolution !== "object" ||
    typeof detail.dns_resolution.state !== "string" ||
    !detail.http_https_service || typeof detail.http_https_service !== "object" ||
    typeof detail.http_https_service.state !== "string"
  ) return { valid: false };
  const activeSources = new Set(detail.active_sources);
  return {
    valid: true,
    detail,
    has_required_active_sources:
      ASSET_REMOVAL_CONFIRMATION_POLICY.relevant_active_sources.every(
        (source) => activeSources.has(source),
      ),
  };
}

function replaySignalStates(row, sourceDetail) {
  if (row.observation_state === "observed") {
    return {
      dns_resolution: { state: "observed" },
      http_https_service: { state: "observed" },
    };
  }
  if (
    row.qualifies_removal === 1 &&
    row.observation_state === "not_observed" &&
    sourceDetail.has_required_active_sources
  ) {
    return {
      dns_resolution: { state: row.dns_state },
      http_https_service: { state: row.http_state },
    };
  }
  return {
    dns_resolution: { state: "not_assessed" },
    http_https_service: { state: "not_assessed" },
  };
}

export function evaluateAssetLifecycleEventSupport({
  event,
  observations = [],
  lifecycleStatus = "available",
  replayComplete = true,
} = {}) {
  const eventType = event?.event_type || null;
  if (!event?.asset_id) {
    return uncertain("withheld_support_not_evaluable", "asset_identity_not_recorded", eventType);
  }
  if (!event?.scan_id) {
    return uncertain("withheld_support_not_evaluable", "event_scan_not_recorded", eventType);
  }
  if (lifecycleStatus !== "available") return lifecycleReadFailure(lifecycleStatus, eventType);

  const matchingRows = (observations || []).filter(
    (row) => row?.asset_id === event.asset_id,
  );
  const anchor = matchingRows.find((row) => row.scan_id === event.scan_id);
  if (!anchor) {
    return uncertain(
      "withheld_lifecycle_evidence_not_recorded",
      "exact_lifecycle_anchor_absent",
      eventType,
    );
  }
  const initialLimitations = [];
  if (!replayComplete) initialLimitations.push("bounded_relevant_replay_truncated");
  if (matchingRows.some((row) => Number(row?.invalid_relevant_timestamp) === 1 ||
    !normalizeLifecycleTimestamp(row?.observed_at).valid ||
    !normalizeLifecycleTimestamp(row?.created_at).valid)) {
    initialLimitations.push("invalid_relevant_timestamp");
  }
  if (initialLimitations.length) {
    return uncertain(null, initialLimitations[0], eventType, initialLimitations);
  }

  const assetRows = [
    ...matchingRows.filter((row) =>
      row.scan_id !== anchor.scan_id && isDecisionRelevantLifecycleObservation(row)),
    anchor,
  ];

  const preceding = assetRows
    .filter((row) => row.scan_id !== anchor.scan_id && compareLifecycleObservationOrder(row, anchor) < 0)
    .sort(compareLifecycleObservationOrder)
    .slice(-3);
  const selected = [...preceding, anchor].sort(compareLifecycleObservationOrder);

  const parsedByScan = new Map();
  const interpretationLimitations = [];
  for (const row of selected) {
    if (row.policy_version !== ASSET_REMOVAL_CONFIRMATION_POLICY.version) {
      interpretationLimitations.push("unknown_policy_version");
    }
    const parsed = parseSourceDetail(row);
    if (!parsed.valid) {
      interpretationLimitations.push("malformed_source_detail");
    } else {
      parsedByScan.set(row.scan_id, parsed);
    }
  }
  if (interpretationLimitations.length) {
    return uncertain(null, interpretationLimitations[0], eventType, interpretationLimitations);
  }

  let current = {
    lifecycle_state: "not_assessed",
    qualifying_observations: [],
    confirmed_removed_at: null,
  };
  let targetTransition = null;
  for (const row of selected) {
    const next = applyAssetRemovalConfirmation(current, {
      scan_id: row.scan_id,
      observed_at: normalizeLifecycleTimestamp(row.observed_at).canonical_utc,
      signal_states: replaySignalStates(row, parsedByScan.get(row.scan_id)),
    });
    current = next;
    if (row.scan_id === anchor.scan_id) targetTransition = next.transition;
  }

  const supported =
    (eventType === "asset_no_longer_seen" && targetTransition === "confirmed_removed") ||
    (eventType === "asset_reappeared" && targetTransition === "reappeared");
  if (supported) {
    return {
      state: "supported",
      evidence_backed: true,
      reason_code: eventType === "asset_no_longer_seen"
        ? "eligible_confirmed_removal"
        : "eligible_reappearance_after_confirmed_removal",
      limitation: null,
      limitation_codes: [],
      event_type: eventType,
    };
  }
  return {
    state: "unsupported",
    evidence_backed: false,
    reason_code: eventType === "asset_no_longer_seen"
      ? "withheld_removal_confirmation_not_satisfied"
      : "withheld_reappearance_predecessor_unconfirmed",
    limitation: null,
    limitation_codes: [],
    event_type: eventType,
  };
}

function hostnameForCustomer(event) {
  return event?.hostname || "this asset";
}

export function projectAssetLifecycleEventForCustomer(event, claim) {
  if (!LIFECYCLE_EVENT_SET.has(event?.event_type)) return { ...event };
  const state = claim?.state || "uncertain";
  const hostname = hostnameForCustomer(event);
  let title;
  let description;
  if (state === "supported" && event.event_type === "asset_no_longer_seen") {
    title = "No longer externally observed";
    description = `CyberMeters did not observe ${hostname} through authoritative DNS and HTTP/HTTPS checks in three qualifying observations, each at least 24 hours apart and spanning at least 48 hours. This does not prove removal, decommissioning or remediation.`;
  } else if (state === "supported") {
    title = "Externally observed again";
    description = `CyberMeters observed ${hostname} after a policy-qualified period in which authoritative DNS and HTTP/HTTPS checks did not observe it. This is an external-visibility change, not proof that the asset had previously been removed.`;
  } else if (state === "unsupported") {
    title = "Historical lifecycle record";
    description = event.event_type === "asset_no_longer_seen"
      ? `A historical “no longer seen” record exists for ${hostname}, but the current evidence policy does not confirm that transition.`
      : `A historical “reappeared” record exists for ${hostname}, but the current evidence policy does not confirm the required earlier absence transition.`;
  } else {
    title = "Historical lifecycle record — support undetermined";
    description = `A historical lifecycle record exists for ${hostname}, but support for it could not be determined from the available lifecycle evidence.`;
  }
  return {
    ...event,
    recorded_description: event?.recorded_description ?? event?.description ?? null,
    title,
    description,
    lifecycle_claim_support: {
      version: ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION,
      ordering_version: ASSET_LIFECYCLE_REPLAY_ORDER_VERSION,
      timestamp_version: ASSET_LIFECYCLE_TIMESTAMP_VERSION,
      state,
      evidence_backed: claim?.evidence_backed ?? null,
      reason_code: claim?.reason_code || "withheld_support_not_evaluable",
      limitation_codes: claim?.limitation_codes || (claim?.limitation ? [claim.limitation] : []),
    },
  };
}

function claimForEvent(claims, event, index) {
  if (claims instanceof Map) return claims.get(event?.id) || claims.get(`__index_${index}`);
  return claims?.[event?.id] || claims?.[`__index_${index}`];
}

export function summariseLifecycleClaimProjection(events = [], projection = {}) {
  const lifecycleTypes = [...new Set(
    events.map((event) => event?.event_type).filter((type) => LIFECYCLE_EVENT_SET.has(type)),
  )];
  const base = {
    version: ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION,
    ordering_version: ASSET_LIFECYCLE_REPLAY_ORDER_VERSION,
    timestamp_version: ASSET_LIFECYCLE_TIMESTAMP_VERSION,
    coverage: projection.coverage || "complete",
    coverage_reason: projection.coverage_reason || null,
    scope: projection.scope || "unspecified",
  };
  if (base.coverage !== "complete") {
    return {
      ...base,
      total: null,
      supported: null,
      unsupported: null,
      uncertain: null,
      non_lifecycle: null,
      by_event_type: Object.fromEntries(lifecycleTypes.map((type) => [type, {
        total: null, supported: null, unsupported: null, uncertain: null,
      }])),
      customer_change_count: null,
      customer_change_count_basis: null,
    };
  }

  const counts = { total: events.length, supported: 0, unsupported: 0, uncertain: 0, non_lifecycle: 0 };
  const byType = Object.fromEntries(lifecycleTypes.map((type) => [type, {
    total: 0, supported: 0, unsupported: 0, uncertain: 0,
  }]));
  for (const [index, event] of events.entries()) {
    if (!LIFECYCLE_EVENT_SET.has(event?.event_type)) {
      counts.non_lifecycle += 1;
      continue;
    }
    const claim = claimForEvent(projection.claims_by_event_id, event, index) || { state: "uncertain" };
    const state = ["supported", "unsupported", "uncertain"].includes(claim.state)
      ? claim.state
      : "uncertain";
    counts[state] += 1;
    byType[event.event_type].total += 1;
    byType[event.event_type][state] += 1;
  }
  return {
    ...base,
    ...counts,
    by_event_type: byType,
    customer_change_count: counts.supported + counts.non_lifecycle,
    customer_change_count_basis: "supported_lifecycle_plus_non_lifecycle_event_records",
  };
}

function evidenceReadStatus(error) {
  return /no such (?:table|column)/i.test(String(error?.message || ""))
    ? "schema_absent"
    : "unavailable";
}

function projectionBase(scope) {
  return {
    projection_version: ASSET_LIFECYCLE_SUPPORT_PROJECTION_VERSION,
    ordering_version: ASSET_LIFECYCLE_REPLAY_ORDER_VERSION,
    timestamp_version: ASSET_LIFECYCLE_TIMESTAMP_VERSION,
    scope,
  };
}

function eventDescriptorsByWorkspace(events) {
  const localIndexes = new Map();
  return (events || []).map((event) => {
    const workspaceId = event?.workspace_id || "";
    const localIndex = localIndexes.get(workspaceId) || 0;
    localIndexes.set(workspaceId, localIndex + 1);
    return {
      event,
      workspace_id: workspaceId,
      event_key: event?.id || `__index_${localIndex}`,
    };
  });
}

function collectionClaims(descriptors, buildClaim) {
  const claims = new Map();
  for (const descriptor of descriptors) {
    if (!LIFECYCLE_EVENT_SET.has(descriptor.event?.event_type)) continue;
    claims.set(descriptor.event_key, buildClaim(descriptor.event));
  }
  return claims;
}

export function createAssetLifecycleUnavailableProjection({
  events = [],
  scope = "unspecified",
  coverageReason = "event_collection_read_failed",
} = {}) {
  const descriptors = eventDescriptorsByWorkspace(events);
  return {
    ...projectionBase(scope),
    coverage: "unavailable",
    coverage_reason: coverageReason,
    claims_by_event_id: collectionClaims(descriptors, (event) => lifecycleReadFailure(
      coverageReason === "lifecycle_schema_absent" ? "schema_absent" : "unavailable",
      event.event_type,
    )),
  };
}

function truncatedProjection(descriptors, scope) {
  return {
    ...projectionBase(scope),
    coverage: "truncated",
    coverage_reason: "collection_limit_exceeded",
    claims_by_event_id: collectionClaims(descriptors, (event) => uncertain(
      "withheld_support_not_evaluable",
      "collection_limit_exceeded",
      event.event_type,
    )),
  };
}

function unavailableProjection(descriptors, scope, status, coverageReason = null) {
  const reason = coverageReason || (status === "schema_absent"
    ? "lifecycle_schema_absent"
    : "lifecycle_evidence_read_failed");
  return {
    ...projectionBase(scope),
    coverage: "unavailable",
    coverage_reason: reason,
    claims_by_event_id: collectionClaims(descriptors, (event) => lifecycleReadFailure(
      status,
      event.event_type,
    )),
  };
}

// A packed statement binds each distinct workspace once, then exactly three
// values per event anchor. This retains the canonical single-workspace maximum
// derived from the binding budget while safely admitting mixed-tenant batches.
function packAnchorDescriptors(descriptors) {
  const packs = [];
  let current = [];
  let workspaces = new Set();
  const flush = () => {
    if (current.length > 0) packs.push(current);
    current = [];
    workspaces = new Set();
  };
  for (const descriptor of descriptors) {
    const nextWorkspaceCount = workspaces.size + (workspaces.has(descriptor.workspace_id) ? 0 : 1);
    const nextBindingCount =
      (current.length + 1) * ASSET_LIFECYCLE_BINDINGS_PER_ANCHOR + nextWorkspaceCount;
    if (
      current.length > 0 &&
      (current.length + 1 > ASSET_LIFECYCLE_MAX_SINGLE_WORKSPACE_ANCHORS ||
       nextBindingCount > ASSET_LIFECYCLE_D1_BINDING_LIMIT)
    ) flush();
    current.push(descriptor);
    workspaces.add(descriptor.workspace_id);
  }
  flush();
  return packs;
}

function rowCollectionKey(workspaceId, eventKey) {
  return JSON.stringify([workspaceId, eventKey]);
}

async function loadAnchorPack(env, descriptors) {
  const workspaceIds = [...new Set(descriptors.map((descriptor) => descriptor.workspace_id))];
  const slotByWorkspace = new Map(workspaceIds.map((workspaceId, index) => [workspaceId, index]));
  const workspaceValues = workspaceIds.map((_, index) => `(${index},?)`).join(",");
  const eventValues = descriptors.map((descriptor) =>
    `(?,${slotByWorkspace.get(descriptor.workspace_id)},?,?)`).join(",");
  const bindings = [
    ...workspaceIds,
    ...descriptors.flatMap((descriptor) => [
      descriptor.event_key,
      descriptor.event.asset_id,
      descriptor.event.scan_id,
    ]),
  ];
  if (bindings.length > ASSET_LIFECYCLE_D1_BINDING_LIMIT) {
    throw new RangeError("Lifecycle anchor query exceeds the D1 binding budget");
  }
  const validCandidateObserved = lifecycleTimestampValiditySql("candidate.observed_at");
  const validCandidateCreated = lifecycleTimestampValiditySql("candidate.created_at");
  const validPrecedingObserved = lifecycleTimestampValiditySql("alo.observed_at");
  const validPrecedingCreated = lifecycleTimestampValiditySql("alo.created_at");
  const validAnchorObserved = lifecycleTimestampValiditySql("anchor.observed_at");
  const validAnchorCreated = lifecycleTimestampValiditySql("anchor.created_at");
  const sql = `WITH workspace_input(workspace_slot, workspace_id) AS (
      VALUES ${workspaceValues}
    ), event_input(event_key, workspace_slot, asset_id, scan_id) AS (
      VALUES ${eventValues}
    ), exact_anchor AS (
      SELECT ei.event_key, wi.workspace_id,
             alo.asset_id, alo.scan_id, alo.observation_state,
             alo.dns_state, alo.http_state, alo.qualifies_removal,
             alo.policy_version, alo.source_detail_json,
             alo.observed_at, alo.created_at
      FROM event_input ei
      JOIN workspace_input wi ON wi.workspace_slot = ei.workspace_slot
      JOIN asset_lifecycle_observations alo
        ON alo.workspace_id = wi.workspace_id
       AND alo.asset_id = ei.asset_id
       AND alo.scan_id = ei.scan_id
    ), invalid_relevant AS (
      SELECT anchor.workspace_id, anchor.event_key,
             MAX(CASE WHEN ${validCandidateObserved} AND ${validCandidateCreated}
                      THEN 0 ELSE 1 END) AS invalid_relevant_timestamp
      FROM exact_anchor anchor
      JOIN asset_lifecycle_observations candidate
        ON candidate.workspace_id = anchor.workspace_id
       AND candidate.asset_id = anchor.asset_id
       AND (candidate.qualifies_removal = 1 OR candidate.observation_state = 'observed')
      GROUP BY anchor.workspace_id, anchor.event_key
    ), preceding AS (
      SELECT anchor.workspace_id, anchor.event_key,
             alo.asset_id, alo.scan_id, alo.observation_state,
             alo.dns_state, alo.http_state, alo.qualifies_removal,
             alo.policy_version, alo.source_detail_json,
             alo.observed_at, alo.created_at,
             ROW_NUMBER() OVER (
               PARTITION BY anchor.workspace_id, anchor.event_key
               ORDER BY julianday(alo.observed_at) DESC,
                        julianday(alo.created_at) DESC,
                        alo.scan_id COLLATE BINARY DESC
             ) AS replay_rank
      FROM exact_anchor anchor
      JOIN asset_lifecycle_observations alo
        ON alo.workspace_id = anchor.workspace_id
       AND alo.asset_id = anchor.asset_id
       AND (alo.qualifies_removal = 1 OR alo.observation_state = 'observed')
       AND ${validPrecedingObserved} AND ${validPrecedingCreated}
       AND ${validAnchorObserved} AND ${validAnchorCreated}
       AND (
         julianday(alo.observed_at) < julianday(anchor.observed_at)
         OR (
           julianday(alo.observed_at) = julianday(anchor.observed_at)
           AND julianday(alo.created_at) < julianday(anchor.created_at)
         )
         OR (
           julianday(alo.observed_at) = julianday(anchor.observed_at)
           AND julianday(alo.created_at) = julianday(anchor.created_at)
           AND alo.scan_id COLLATE BINARY < anchor.scan_id COLLATE BINARY
         )
       )
    )
    SELECT anchor.workspace_id, anchor.event_key, anchor.asset_id, anchor.scan_id,
           anchor.observation_state, anchor.dns_state, anchor.http_state,
           anchor.qualifies_removal, anchor.policy_version, anchor.source_detail_json,
           anchor.observed_at, anchor.created_at,
           COALESCE(invalid.invalid_relevant_timestamp, 0) AS invalid_relevant_timestamp,
           1 AS is_exact_anchor, 0 AS replay_rank
    FROM exact_anchor anchor
    LEFT JOIN invalid_relevant invalid
      ON invalid.workspace_id = anchor.workspace_id AND invalid.event_key = anchor.event_key
    UNION ALL
    SELECT preceding.workspace_id, preceding.event_key, preceding.asset_id, preceding.scan_id,
           preceding.observation_state, preceding.dns_state, preceding.http_state,
           preceding.qualifies_removal, preceding.policy_version, preceding.source_detail_json,
           preceding.observed_at, preceding.created_at,
           COALESCE(invalid.invalid_relevant_timestamp, 0) AS invalid_relevant_timestamp,
           0 AS is_exact_anchor, preceding.replay_rank
    FROM preceding
    LEFT JOIN invalid_relevant invalid
      ON invalid.workspace_id = preceding.workspace_id AND invalid.event_key = preceding.event_key
    WHERE preceding.replay_rank <= 3
    ORDER BY 1, 2, 14, 15`;
  const result = await env.cybermeters_db.prepare(sql).bind(...bindings).all();
  return result.results || [];
}

async function loadPackedAnchors(env, packs) {
  const outcomes = [];
  for (let index = 0; index < packs.length; index += ASSET_LIFECYCLE_MAX_QUERY_CONCURRENCY) {
    const wave = packs.slice(index, index + ASSET_LIFECYCLE_MAX_QUERY_CONCURRENCY);
    const settled = await Promise.allSettled(wave.map((pack) => loadAnchorPack(env, pack)));
    outcomes.push(...settled.map((outcome, offset) => ({
      pack: wave[offset],
      ...outcome,
    })));
  }
  return outcomes;
}

export async function loadAssetLifecycleEventSupportForWorkspaces(env, {
  workspaceIds = [],
  events = [],
  collectionLimit = 2000,
  scope = "unspecified",
} = {}) {
  const allowedWorkspaceIds = [...new Set((workspaceIds || []).filter(Boolean))];
  const allowed = new Set(allowedWorkspaceIds);
  const descriptors = eventDescriptorsByWorkspace(events);
  const byWorkspace = new Map(allowedWorkspaceIds.map((workspaceId) => [workspaceId, []]));
  const result = new Map();

  if (descriptors.some((descriptor) => !allowed.has(descriptor.workspace_id))) {
    for (const workspaceId of allowedWorkspaceIds) {
      result.set(workspaceId, unavailableProjection(
        byWorkspace.get(workspaceId), scope, "unavailable", "workspace_scope_mismatch",
      ));
    }
    return result;
  }
  for (const descriptor of descriptors) byWorkspace.get(descriptor.workspace_id).push(descriptor);

  const eligibleAnchors = [];
  for (const workspaceId of allowedWorkspaceIds) {
    const workspaceDescriptors = byWorkspace.get(workspaceId);
    if (workspaceDescriptors.length > collectionLimit) {
      result.set(workspaceId, truncatedProjection(workspaceDescriptors, scope));
      continue;
    }
    eligibleAnchors.push(...workspaceDescriptors.filter((descriptor) =>
      LIFECYCLE_EVENT_SET.has(descriptor.event?.event_type) &&
      descriptor.event?.asset_id && descriptor.event?.scan_id));
  }

  const rowsByEvent = new Map();
  const failedWorkspaceStatus = new Map();
  const packs = packAnchorDescriptors(eligibleAnchors);
  const outcomes = await loadPackedAnchors(env, packs);
  for (const outcome of outcomes) {
    if (outcome.status === "rejected") {
      const status = evidenceReadStatus(outcome.reason);
      for (const descriptor of outcome.pack) {
        failedWorkspaceStatus.set(descriptor.workspace_id, status);
      }
      continue;
    }
    for (const row of outcome.value) {
      const key = rowCollectionKey(row.workspace_id, row.event_key);
      if (!rowsByEvent.has(key)) rowsByEvent.set(key, []);
      rowsByEvent.get(key).push(row);
    }
  }

  if ([...failedWorkspaceStatus.values()].includes("schema_absent")) {
    for (const workspaceId of allowedWorkspaceIds) {
      if (!result.has(workspaceId)) failedWorkspaceStatus.set(workspaceId, "schema_absent");
    }
  }

  for (const workspaceId of allowedWorkspaceIds) {
    if (result.has(workspaceId)) continue;
    const workspaceDescriptors = byWorkspace.get(workspaceId);
    const failedStatus = failedWorkspaceStatus.get(workspaceId);
    if (failedStatus) {
      result.set(workspaceId, unavailableProjection(workspaceDescriptors, scope, failedStatus));
      continue;
    }
    const claims = new Map();
    for (const descriptor of workspaceDescriptors) {
      if (!LIFECYCLE_EVENT_SET.has(descriptor.event?.event_type)) continue;
      const observations = rowsByEvent.get(
        rowCollectionKey(workspaceId, descriptor.event_key),
      ) || [];
      claims.set(descriptor.event_key, evaluateAssetLifecycleEventSupport({
        event: descriptor.event,
        observations,
      }));
    }
    result.set(workspaceId, {
      ...projectionBase(scope),
      coverage: "complete",
      coverage_reason: null,
      claims_by_event_id: claims,
    });
  }
  return result;
}

export async function loadAssetLifecycleEventSupport(env, {
  workspaceId,
  events = [],
  collectionLimit = 2000,
  scope = "unspecified",
} = {}) {
  const projections = await loadAssetLifecycleEventSupportForWorkspaces(env, {
    workspaceIds: workspaceId ? [workspaceId] : [],
    events,
    collectionLimit,
    scope,
  });
  return projections.get(workspaceId) || unavailableProjection(
    eventDescriptorsByWorkspace(events), scope, "unavailable", "workspace_scope_mismatch",
  );
}

export function projectLifecycleCollectionForCustomer(events, projection) {
  return events.map((event, index) => {
    if (!LIFECYCLE_EVENT_SET.has(event?.event_type)) return { ...event };
    let claim = claimForEvent(projection?.claims_by_event_id, event, index);
    if (!claim && projection?.coverage === "truncated") {
      claim = uncertain(
        "withheld_support_not_evaluable",
        projection.coverage_reason || "collection_limit_exceeded",
        event.event_type,
      );
    }
    if (!claim) claim = uncertain(
      "withheld_support_not_evaluable",
      "lifecycle_evidence_read_failed",
      event.event_type,
    );
    return projectAssetLifecycleEventForCustomer(event, claim);
  });
}
