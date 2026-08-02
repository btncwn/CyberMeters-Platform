// CT-R2 PR-2A: policy-independent, customer-inert provider-overlap telemetry.
//
// This module never contributes hostnames to the production subdomain merge. It
// observes the terminal provider values already consumed by subdomains-scan,
// keeps a separately bounded shadow set, returns count-only measurements, and
// persists one append-only row after scan finalization.
import { normalizeDiscoveredHostname } from "./hostnames.js";
import { createId } from "../lib/util.js";

export const CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION = "ct-provider-overlap/1";

// Measurement bounds, not production discovery bounds. PER_CAP/MERGE_CAP in
// subdomains-scan.js retain their original, independent customer-result meaning.
// The normalization cap bounds new normalization work and the unique set; raw
// provider candidate enumeration still walks the provider data. The smaller
// retention cap bounds the two sets used by the comparison itself.
export const CT_PROVIDER_OVERLAP_NORMALIZATION_LIMIT = 4_096;
export const CT_PROVIDER_OVERLAP_RETAINED_LIMIT = 256;

export const CT_PROVIDER_OVERLAP_ATTEMPT_STATES = Object.freeze([
  "terminal_success",
  "terminal_failure",
  "not_started",
  "in_flight_at_consumer_release",
]);

export const CT_PROVIDER_OVERLAP_COMPARISON_STATUSES = Object.freeze([
  "compared",
  "compared_truncated",
  "censored_provider_failure",
  "censored_in_flight",
  "not_started",
]);

const PROVIDERS = Object.freeze(["crt_sh", "certspotter"]);

function isoNow(now) {
  try {
    const value = Number(now?.());
    if (Number.isFinite(value) && Math.abs(value) <= 8.64e15) {
      return new Date(value).toISOString();
    }
  } catch { /* observational clock only */ }
  return new Date().toISOString();
}

function candidateStrings(provider, entry) {
  if (provider === "crt_sh") {
    return [
      ...String(entry?.name_value || "").split(/\n/),
      String(entry?.common_name || ""),
    ];
  }
  return Array.isArray(entry?.dns_names) ? entry.dns_names : [];
}

function measureSuccessfulProvider(provider, data, domain, {
  normalizationLimit,
  retainedLimit,
}) {
  const unique = new Set();
  let expandedCandidateCount = 0;
  let normalizationInputCount = 0;
  let normalizedCandidateCount = 0;

  for (const entry of data) {
    for (const raw of candidateStrings(provider, entry)) {
      // Blank provider fields are not candidates. Invalid, out-of-domain and
      // wildcard values are candidates and count here, then fail normalization.
      if (String(raw || "").trim() === "") continue;
      expandedCandidateCount += 1;
      if (normalizationInputCount >= normalizationLimit) continue;
      normalizationInputCount += 1;
      const hostname = normalizeDiscoveredHostname(raw, domain);
      if (!hostname) continue;
      normalizedCandidateCount += 1;
      unique.add(hostname);
    }
  }

  const normalizationDroppedCandidateCount =
    expandedCandidateCount - normalizationInputCount;
  const orderedUnique = [...unique].sort();
  const retainedHostnames = new Set(orderedUnique.slice(0, retainedLimit));
  const uniqueHostnameCount = orderedUnique.length;
  const retainedHostnameCount = retainedHostnames.size;
  const droppedHostnameCount = uniqueHostnameCount - retainedHostnameCount;

  return {
    attempt_state: "terminal_success",
    raw_record_count: data.length,
    expanded_candidate_count: expandedCandidateCount,
    normalization_input_count: normalizationInputCount,
    normalization_dropped_candidate_count: normalizationDroppedCandidateCount,
    normalization_truncated: normalizationDroppedCandidateCount > 0,
    normalized_candidate_count: normalizedCandidateCount,
    unique_hostname_count: uniqueHostnameCount,
    retained_hostname_count: retainedHostnameCount,
    dropped_hostname_count: droppedHostnameCount,
    truncated: droppedHostnameCount > 0,
    retainedHostnames,
  };
}

function unmeasuredProvider(attemptState) {
  return {
    attempt_state: attemptState,
    raw_record_count: null,
    expanded_candidate_count: null,
    normalization_input_count: null,
    normalization_dropped_candidate_count: null,
    normalization_truncated: null,
    normalized_candidate_count: null,
    unique_hostname_count: null,
    retained_hostname_count: null,
    dropped_hostname_count: null,
    truncated: null,
    retainedHostnames: null,
  };
}

function publicProviderFields(provider, measurement) {
  const fields = {};
  for (const key of [
    "attempt_state",
    "raw_record_count",
    "expanded_candidate_count",
    "normalization_input_count",
    "normalization_dropped_candidate_count",
    "normalization_truncated",
    "normalized_candidate_count",
    "unique_hostname_count",
    "retained_hostname_count",
    "dropped_hostname_count",
    "truncated",
  ]) {
    fields[`${provider}_${key}`] = measurement[key];
  }
  return fields;
}

function compareProviders(crtSh, certspotter) {
  const states = [crtSh.attempt_state, certspotter.attempt_state];
  if (states.includes("not_started")) {
    return { comparison_status: "not_started" };
  }
  if (states.includes("in_flight_at_consumer_release")) {
    return { comparison_status: "censored_in_flight" };
  }
  if (states.includes("terminal_failure")) {
    return { comparison_status: "censored_provider_failure" };
  }

  let intersectionCount = 0;
  for (const hostname of crtSh.retainedHostnames) {
    if (certspotter.retainedHostnames.has(hostname)) intersectionCount += 1;
  }
  const crtShOnlyCount = crtSh.retainedHostnames.size - intersectionCount;
  const certspotterOnlyCount = certspotter.retainedHostnames.size - intersectionCount;
  const unionCount = crtShOnlyCount + certspotterOnlyCount + intersectionCount;
  const truncated = crtSh.truncated || certspotter.truncated
    || crtSh.normalization_truncated || certspotter.normalization_truncated;

  return {
    comparison_status: truncated ? "compared_truncated" : "compared",
    intersection_count: intersectionCount,
    crt_sh_only_count: crtShOnlyCount,
    certspotter_only_count: certspotterOnlyCount,
    union_count: unionCount,
  };
}

export function createCtProviderOverlapCollector({
  normalizationLimit = CT_PROVIDER_OVERLAP_NORMALIZATION_LIMIT,
  retainedLimit = CT_PROVIDER_OVERLAP_RETAINED_LIMIT,
  now = Date.now,
} = {}) {
  const normalizedLimit = Math.max(1, Math.min(
    CT_PROVIDER_OVERLAP_NORMALIZATION_LIMIT,
    Math.floor(Number(normalizationLimit) || CT_PROVIDER_OVERLAP_NORMALIZATION_LIMIT),
  ));
  const boundedRetainedLimit = Math.max(1, Math.min(
    normalizedLimit,
    CT_PROVIDER_OVERLAP_RETAINED_LIMIT,
    Math.floor(Number(retainedLimit) || CT_PROVIDER_OVERLAP_RETAINED_LIMIT),
  ));
  const providerMeasurements = new Map();
  const startedProviders = new Set();
  let moduleStarted = false;
  let consumerReleased = false;
  let releasedAt = null;

  const buildFrozenSnapshot = () => {
    if (!moduleStarted || releasedAt === null) return null;
    const crtSh = providerMeasurements.get("crt_sh")
      || unmeasuredProvider("not_started");
    const certspotter = providerMeasurements.get("certspotter")
      || unmeasuredProvider("not_started");
    const comparison = compareProviders(crtSh, certspotter);
    return {
      module: "subdomains",
      source_set_version: CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION,
      observed_at: releasedAt,
      normalization_candidate_limit: normalizedLimit,
      retained_hostname_limit: boundedRetainedLimit,
      ...publicProviderFields("crt_sh", crtSh),
      ...publicProviderFields("certspotter", certspotter),
      comparison_status: comparison.comparison_status,
      intersection_count: comparison.intersection_count ?? null,
      crt_sh_only_count: comparison.crt_sh_only_count ?? null,
      certspotter_only_count: comparison.certspotter_only_count ?? null,
      union_count: comparison.union_count ?? null,
    };
  };

  return {
    begin(provider) {
      if (consumerReleased || !PROVIDERS.includes(provider)) return;
      moduleStarted = true;
      startedProviders.add(provider);
    },

    observe(provider, settled, domain) {
      if (consumerReleased || !PROVIDERS.includes(provider)) return;
      moduleStarted = true;
      startedProviders.add(provider);
      const value = settled?.status === "fulfilled" ? settled.value : null;
      if (settled?.status !== "fulfilled"
        || value?.status !== "available"
        || !Array.isArray(value?.data)) {
        providerMeasurements.set(provider, unmeasuredProvider("terminal_failure"));
        return;
      }
      providerMeasurements.set(provider, measureSuccessfulProvider(
        provider,
        value.data,
        domain,
        { normalizationLimit: normalizedLimit, retainedLimit: boundedRetainedLimit },
      ));
    },

    freeze() {
      if (consumerReleased) return buildFrozenSnapshot();
      for (const provider of PROVIDERS) {
        if (providerMeasurements.has(provider)) continue;
        providerMeasurements.set(
          provider,
          unmeasuredProvider(startedProviders.has(provider)
            ? "in_flight_at_consumer_release"
            : "not_started"),
        );
      }
      releasedAt = isoNow(now);
      consumerReleased = true;
      return buildFrozenSnapshot();
    },

    snapshot() {
      return releasedAt === null ? null : buildFrozenSnapshot();
    },
  };
}

function persistenceErrorClass(error) {
  const text = String(error?.message || error || "").toLowerCase();
  if (/foreign key|constraint|integrity/.test(text)) return "integrity_error";
  if (/d1|database|unavailable|timeout|connection|binding/.test(text)) {
    return "db_unavailable";
  }
  return "unknown";
}

const PROVIDER_COUNT_COLUMNS = Object.freeze([
  "attempt_state",
  "raw_record_count",
  "expanded_candidate_count",
  "normalization_input_count",
  "normalization_dropped_candidate_count",
  "normalization_truncated",
  "normalized_candidate_count",
  "unique_hostname_count",
  "retained_hostname_count",
  "dropped_hostname_count",
  "truncated",
]);

export async function persistCtProviderOverlapTelemetry(scanId, measurement, env) {
  if (!measurement) return { status: "not_attempted_empty" };

  try {
    if (!scanId || typeof env?.cybermeters_db?.prepare !== "function"
      || typeof env?.cybermeters_db?.batch !== "function") {
      throw new Error("D1 binding unavailable");
    }

    const providerColumns = PROVIDERS.flatMap((provider) =>
      PROVIDER_COUNT_COLUMNS.map((column) => `${provider}_${column}`));
    const columns = [
      "id", "scan_id", "module", "source_set_version", "observed_at",
      "normalization_candidate_limit", "retained_hostname_limit",
      ...providerColumns,
      "comparison_status", "intersection_count", "crt_sh_only_count",
      "certspotter_only_count", "union_count",
    ];
    const values = [
      createId("ctpot"), scanId, measurement.module,
      measurement.source_set_version, measurement.observed_at,
      measurement.normalization_candidate_limit,
      measurement.retained_hostname_limit,
      ...providerColumns.map((column) => {
        const value = measurement[column];
        return typeof value === "boolean" ? (value ? 1 : 0) : (value ?? null);
      }),
      measurement.comparison_status, measurement.intersection_count ?? null,
      measurement.crt_sh_only_count ?? null,
      measurement.certspotter_only_count ?? null, measurement.union_count ?? null,
    ];
    const placeholders = columns.map(() => "?").join(", ");
    const insert = env.cybermeters_db
      .prepare(
        `INSERT OR IGNORE INTO ct_provider_overlap_telemetry
           (${columns.join(", ")})
         VALUES (${placeholders})`,
      )
      .bind(...values);
    const durableCount = env.cybermeters_db
      .prepare(
        `SELECT COUNT(*) AS durable_count
         FROM ct_provider_overlap_telemetry
         WHERE scan_id = ? AND module = ? AND source_set_version = ?`,
      )
      .bind(scanId, measurement.module, measurement.source_set_version);
    const results = await env.cybermeters_db.batch([insert, durableCount]);
    if (results?.some((result) => result?.success === false)) {
      throw new Error("D1 telemetry batch did not commit");
    }
    const count = Number(results?.[1]?.results?.[0]?.durable_count);
    if (count !== 1) throw new Error("D1 telemetry durable count unknown");
    return { status: "persisted", count };
  } catch (error) {
    return {
      status: "persistence_failed",
      error_class: persistenceErrorClass(error),
      // If D1 itself is unavailable, no second D1 marker can honestly prove the
      // failure. The caller receives UNKNOWN durability and scan finalization is
      // deliberately unaffected.
      durability: "unknown",
    };
  }
}
