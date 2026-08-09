// ── Item 10 Attack Surface per-signal evidence contract ─────────────────────
//
// P1 is deliberately pure: no D1/R2/network I/O and no production caller.
// Each signal resolves independently so a failed sibling cannot erase reliable
// evidence. The state vocabulary is closed and non-overlapping.

export const ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION =
  "attack-surface-signal-completeness-v1";

export const ATTACK_SURFACE_SIGNAL_STATES = Object.freeze([
  "observed",
  "not_observed",
  "absent",
  "unavailable",
  "incomplete",
  "not_assessed",
]);

export const ATTACK_SURFACE_SIGNAL_KEYS = Object.freeze([
  "subdomain_discovery",
  "dns_resolution",
  "http_https_service",
  "technology",
  "exposure_admin_surface",
  "takeover_candidate",
  "cve",
  "kev",
  "cloud_storage",
]);

const STATE_SET = new Set(ATTACK_SURFACE_SIGNAL_STATES);
const ACTIVE_REMOVAL_SOURCES = Object.freeze([
  "dns_resolution",
  "http_https_service",
]);
const COMPLETE_NEGATIVE_STATES = new Set(["absent", "not_observed"]);

export const ASSET_REMOVAL_CONFIRMATION_POLICY = Object.freeze({
  version: "asset-removal-confirmation-v1",
  required_qualifying_observations: 3,
  minimum_observation_spacing_ms: 24 * 60 * 60 * 1000,
  minimum_confirmation_window_ms: 48 * 60 * 60 * 1000,
  relevant_active_sources: ACTIVE_REMOVAL_SOURCES,
  passive_sources_excluded: Object.freeze([
    "crt_sh",
    "certspotter",
    "certificate_transparency",
  ]),
});

function count(value) {
  return Array.isArray(value) ? value.length : 0;
}

function finiteCount(value) {
  return Number.isFinite(Number(value)) ? Number(value) : 0;
}

function moduleNotAssessed(module) {
  return !module || module.skipped === true || module.executed === false;
}

function signal(state, reason, {
  evidence_count = 0,
  sources = [],
  limitations = [],
} = {}) {
  if (!STATE_SET.has(state)) {
    throw new TypeError(`Unsupported Attack Surface signal state: ${state}`);
  }
  return {
    state,
    reason,
    evidence_count,
    sources: [...new Set(sources.filter(Boolean))],
    limitations: [...new Set(limitations.filter(Boolean))],
  };
}

function sourceErrors(module) {
  return Object.entries(module?.sources || {})
    .filter(([, value]) => value?.error)
    .map(([name]) => name);
}

function resolveSubdomainDiscovery(modules) {
  const ct = modules?.subdomains;
  const brute = modules?.dns_bruteforce;
  const ctItems = ct?.items || [];
  const bruteItems = brute?.items || [];
  const observedCount = new Set([
    ...ctItems,
    ...bruteItems.map((item) => item?.hostname).filter(Boolean),
  ]).size;
  const failedSources = sourceErrors(ct);
  const sources = [
    ...(ct ? ["crt_sh", "certspotter"] : []),
    ...(brute ? ["dns_bruteforce"] : []),
  ];
  const limitations = [
    ...failedSources.map((name) => `${name}_unavailable`),
    ct?.incomplete_reason,
    brute?.incomplete_reason,
    ct?.ct_error ? "ct_sources_unavailable" : null,
  ];

  if (observedCount > 0) {
    return signal("observed", "hostname_observed", {
      evidence_count: observedCount,
      sources,
      limitations,
    });
  }
  if (moduleNotAssessed(ct) && moduleNotAssessed(brute)) {
    return signal("not_assessed", "discovery_not_evaluated", { sources });
  }

  const ctUnavailable = Boolean(ct?.error || ct?.ct_error) &&
    failedSources.length >= 2;
  const bruteUnavailable = Boolean(brute?.error);
  if ((moduleNotAssessed(ct) || ctUnavailable) &&
      (moduleNotAssessed(brute) || bruteUnavailable)) {
    return signal("unavailable", "all_discovery_sources_unavailable", {
      sources,
      limitations,
    });
  }

  const ctComplete = Boolean(
    ct &&
    !ct.error &&
    !ct.ct_error &&
    ct.incomplete !== true &&
    ct.sources?.crt_sh &&
    ct.sources?.certspotter &&
    !ct.sources.crt_sh.error &&
    !ct.sources.certspotter.error
  );
  const bruteComplete = Boolean(
    brute &&
    !brute.error &&
    brute.incomplete !== true &&
    Number.isFinite(Number(brute.checked))
  );
  if (!ctComplete || !bruteComplete) {
    return signal("incomplete", "discovery_sources_incomplete", {
      sources,
      limitations,
    });
  }
  return signal("not_observed", "complete_discovery_no_hostname", { sources });
}

// Exported so customer SCORING consumes the identical DNS semantics rather than
// re-deriving them. scoring.js previously had its own `resolution_assessed !== false`
// rule, which read MISSING contract fields as authoritative absence and emitted a
// critical "Domain Does Not Resolve" (-30) for a deadline-deferred module that never
// performed a single lookup. There is now one DNS resolution vocabulary, not two.
export function resolveDnsResolution(modules) {
  const dns = modules?.dns;
  if (moduleNotAssessed(dns)) {
    return signal("not_assessed", "dns_not_evaluated", { sources: ["dns"] });
  }
  if (dns.error) {
    return signal("unavailable", "dns_module_unavailable", { sources: ["dns"] });
  }
  if (dns.resolves_any === true || dns.resolves === true) {
    return signal("observed", "dns_records_observed", {
      evidence_count: count(dns.a_records) + count(dns.aaaa_records),
      sources: ["dns"],
    });
  }
  if (dns.resolution_assessed === true) {
    // Positive absence is allowed only because at least one resolver returned an
    // authoritative NOERROR/NXDOMAIN answer for the requested record contract.
    return signal("absent", "authoritative_dns_absence", { sources: ["dns"] });
  }
  // `undefined` (contract never recorded) and `null` (probe not executed — nothing
  // measured) are both NON-MEASUREMENTS. Without this they fell through to
  // `unavailable`, which means "resolvers WERE queried and gave no authoritative
  // answer" — a genuinely MEASURED outage.
  //
  // Scope note: this is NOT a second producer of the critical absence verdict —
  // `unavailable` never fires dns_no_resolution either. It is a distinct
  // evidence-state defect: a non-measurement was being classified as a measurement,
  // which misreports WHY the signal is missing to every completeness consumer.
  if (dns.resolution_assessed === undefined || dns.resolution_assessed === null) {
    return signal("incomplete", "dns_resolution_contract_not_recorded", {
      sources: ["dns"],
    });
  }
  return signal("unavailable", "authoritative_dns_evidence_unavailable", {
    sources: ["dns"],
    limitations: [dns.incomplete_reason],
  });
}

function resolveHttpHttpsService(modules) {
  const exposure = modules?.asset_exposure;
  const assets = exposure?.assets || [];
  const reachable = assets.filter((asset) => asset?.reachable === true);
  if (reachable.length > 0) {
    return signal("observed", "http_https_service_observed", {
      evidence_count: reachable.length,
      sources: ["http_probe"],
      limitations: exposure?.incomplete === true
        ? [exposure.incomplete_reason || "some_hosts_unassessed"]
        : [],
    });
  }
  if (moduleNotAssessed(exposure)) {
    return signal("not_assessed", "http_https_not_evaluated", {
      sources: ["http_probe"],
    });
  }
  if (exposure.error && assets.length === 0) {
    return signal("unavailable", "http_https_module_unavailable", {
      sources: ["http_probe"],
    });
  }
  if (exposure.incomplete === true) {
    return signal("incomplete", "http_https_evidence_incomplete", {
      sources: ["http_probe"],
      limitations: [exposure.incomplete_reason],
    });
  }
  if (finiteCount(exposure.checked) === 0) {
    return signal("not_assessed", "no_http_https_targets", {
      sources: ["http_probe"],
    });
  }
  return signal("not_observed", "complete_http_https_probe_no_service", {
    sources: ["http_probe"],
  });
}

function resolveTechnology(modules) {
  const technology = modules?.technology_detection;
  const observed = new Set([
    ...(technology?.technologies || []),
    technology?.server,
    technology?.x_powered_by,
  ].filter(Boolean));
  if (observed.size > 0) {
    return signal("observed", "technology_observed", {
      evidence_count: observed.size,
      sources: ["technology_detection"],
      limitations: technology?.incomplete === true
        ? [technology.incomplete_reason]
        : [],
    });
  }
  if (moduleNotAssessed(technology)) {
    return signal("not_assessed", "technology_not_evaluated", {
      sources: ["technology_detection"],
    });
  }
  if (technology.error) {
    return signal("unavailable", "technology_probe_unavailable", {
      sources: ["technology_detection"],
    });
  }
  if (technology.incomplete === true) {
    return signal("incomplete", "technology_evidence_incomplete", {
      sources: ["technology_detection"],
      limitations: [technology.incomplete_reason],
    });
  }
  if (!Number.isFinite(Number(technology.status_code))) {
    return signal("incomplete", "technology_completion_not_recorded", {
      sources: ["technology_detection"],
    });
  }
  return signal("not_observed", "complete_technology_probe_no_fingerprint", {
    sources: ["technology_detection"],
  });
}

function resolveExposureAdminSurface(modules) {
  const exposure = modules?.asset_exposure;
  const admin = modules?.admin_surface_detection;
  const reachable = (exposure?.assets || [])
    .filter((asset) => asset?.reachable === true);
  const services = (admin?.services || [])
    .filter((service) => service?.finding_type !== "observation");
  if (reachable.length > 0 || services.length > 0) {
    return signal("observed", "exposure_or_admin_surface_observed", {
      evidence_count: reachable.length + services.length,
      sources: ["http_probe", "asset_exposure_fingerprint"],
      limitations: exposure?.incomplete === true
        ? [exposure.incomplete_reason || "some_hosts_unassessed"]
        : [],
    });
  }
  if (moduleNotAssessed(exposure) && moduleNotAssessed(admin)) {
    return signal("not_assessed", "exposure_admin_not_evaluated", {
      sources: ["http_probe", "asset_exposure_fingerprint"],
    });
  }
  if (exposure?.error && !(exposure?.assets || []).length) {
    return signal("unavailable", "exposure_admin_evidence_unavailable", {
      sources: ["http_probe", "asset_exposure_fingerprint"],
    });
  }
  if (exposure?.incomplete === true || admin?.evidence_status === "unavailable") {
    return signal("incomplete", "exposure_admin_evidence_incomplete", {
      sources: ["http_probe", "asset_exposure_fingerprint"],
      limitations: [exposure?.incomplete_reason],
    });
  }
  if (finiteCount(exposure?.checked) === 0) {
    return signal("not_assessed", "no_exposure_admin_targets", {
      sources: ["http_probe", "asset_exposure_fingerprint"],
    });
  }
  return signal("not_observed", "complete_exposure_admin_probe_no_signal", {
    sources: ["http_probe", "asset_exposure_fingerprint"],
  });
}

function resolveTakeoverCandidate(modules) {
  const takeover = modules?.subdomain_takeover;
  const candidateCount = Math.max(
    finiteCount(takeover?.potential_risks),
    count(takeover?.risks) + count(takeover?.unconfirmed)
  );
  if (candidateCount > 0) {
    return signal("observed", "takeover_candidate_observed", {
      evidence_count: candidateCount,
      sources: ["dns_cname", "provider_fingerprint"],
      limitations: count(takeover?.unconfirmed) > 0
        ? ["candidate_confirmation_incomplete"]
        : [],
    });
  }
  if (moduleNotAssessed(takeover)) {
    return signal("not_assessed", "takeover_not_evaluated", {
      sources: ["dns_cname", "provider_fingerprint"],
    });
  }
  if (takeover.error) {
    return signal("unavailable", "takeover_module_unavailable", {
      sources: ["dns_cname", "provider_fingerprint"],
    });
  }
  if (takeover.incomplete === true ||
      count(takeover.lookup_failed_hosts) > 0 ||
      count(takeover.unconfirmed) > 0) {
    return signal("incomplete", "takeover_evidence_incomplete", {
      sources: ["dns_cname", "provider_fingerprint"],
      limitations: [takeover.incomplete_reason],
    });
  }
  if (!Number.isFinite(Number(takeover.checked))) {
    return signal("incomplete", "takeover_completion_not_recorded", {
      sources: ["dns_cname", "provider_fingerprint"],
    });
  }
  return signal("not_observed", "complete_takeover_probe_no_candidate", {
    sources: ["dns_cname", "provider_fingerprint"],
  });
}

function resolveCve(modules, technologySignal) {
  const cve = modules?.cve_intelligence;
  if (finiteCount(cve?.total_cves) > 0) {
    const unavailableTechnologies = Object.entries(cve?.lookup_statuses ?? {})
      .filter(([, row]) => !["complete", "available", "completed"].includes(row?.status))
      .map(([technology]) => technology);
    return signal("observed", "cve_observed", {
      evidence_count: finiteCount(cve.total_cves),
      sources: ["nvd_api"],
      limitations: cve?.cve_coverage === "partial"
        ? unavailableTechnologies.map((technology) => `${technology}_cve_lookup_unavailable`)
        : [],
    });
  }
  if (moduleNotAssessed(cve)) {
    return signal("not_assessed", "cve_not_evaluated", { sources: ["nvd_api"] });
  }
  if (cve.error) {
    return signal("unavailable", "cve_provider_unavailable", {
      sources: ["nvd_api"],
    });
  }
  if (cve.cve_coverage === "dependency_unavailable") {
    return signal("incomplete", "technology_dependency_incomplete", {
      sources: ["nvd_api", "technology_detection"],
      limitations: [cve.incomplete_reason],
    });
  }
  if (cve.cve_coverage === "unavailable") {
    return signal("unavailable", "all_cve_lookups_unavailable", {
      sources: ["nvd_api"],
      limitations: [cve.incomplete_reason],
    });
  }
  if (cve.cve_coverage === "partial") {
    return signal("incomplete", "some_cve_lookups_unavailable", {
      sources: ["nvd_api"],
      limitations: Object.entries(cve.lookup_statuses ?? {})
        .filter(([, row]) => !["complete", "available", "completed"].includes(row?.status))
        .map(([technology]) => `${technology}_cve_lookup_unavailable`),
    });
  }
  if (cve.cve_coverage === "complete") {
    return signal("not_observed", "complete_cve_lookup_no_match", {
      sources: ["nvd_api"],
    });
  }
  if (cve.cve_coverage === "not_applicable") {
    return signal("not_observed", "no_supported_technology_for_cve_lookup", {
      sources: ["nvd_api", "technology_detection"],
    });
  }
  if (cve.incomplete === true) {
    return signal("incomplete", "cve_evidence_incomplete", {
      sources: ["nvd_api"],
      limitations: [cve.incomplete_reason],
    });
  }
  if (["unavailable", "incomplete"].includes(technologySignal.state)) {
    return signal("incomplete", "technology_dependency_incomplete", {
      sources: ["nvd_api", "technology_detection"],
    });
  }
  if (!Array.isArray(cve.technologies_checked)) {
    return signal("incomplete", "cve_completion_not_recorded", {
      sources: ["nvd_api"],
    });
  }

  const lookupStatuses = cve.lookup_statuses || {};
  const lookupRows = Object.values(lookupStatuses);
  if (lookupRows.length > 0) {
    const failed = lookupRows.filter((row) =>
      !["complete", "available"].includes(row?.status)
    );
    if (failed.length === lookupRows.length) {
      return signal("unavailable", "all_cve_lookups_unavailable", {
        sources: ["nvd_api"],
      });
    }
    if (failed.length > 0) {
      return signal("incomplete", "some_cve_lookups_unavailable", {
        sources: ["nvd_api"],
      });
    }
    return signal("not_observed", "complete_cve_lookup_no_match", {
      sources: ["nvd_api"],
    });
  }

  if (count(cve.technologies_checked) > 0) {
    // Current production lookupCvesForTechnology returns [] for both a valid
    // zero-result response and every provider/network failure. Until P2 records
    // per-technology outcomes, that zero can never be called not_observed.
    return signal("incomplete", "cve_provider_outcome_not_recorded", {
      sources: ["nvd_api"],
    });
  }
  return signal("not_observed", "no_supported_technology_for_cve_lookup", {
    sources: ["nvd_api", "technology_detection"],
  });
}

function resolveKev(modules, technologySignal) {
  const kev = modules?.known_exploited_vulnerabilities;
  if (finiteCount(kev?.matched) > 0 || count(kev?.matches) > 0) {
    return signal("observed", "kev_observed", {
      evidence_count: Math.max(finiteCount(kev?.matched), count(kev?.matches)),
      sources: ["cisa_kev"],
      limitations: kev?.catalogue_stale ? ["catalogue_stale"] : [],
    });
  }
  if (moduleNotAssessed(kev)) {
    return signal("not_assessed", "kev_not_evaluated", { sources: ["cisa_kev"] });
  }
  if (kev.error || kev.catalogue_source === "unavailable") {
    return signal("unavailable", "kev_catalogue_unavailable", {
      sources: ["cisa_kev"],
    });
  }
  if (kev.incomplete === true) {
    return signal("incomplete", "kev_evidence_incomplete", {
      sources: ["cisa_kev"],
      limitations: [kev.incomplete_reason],
    });
  }
  if (["unavailable", "incomplete"].includes(technologySignal.state)) {
    return signal("incomplete", "technology_dependency_incomplete", {
      sources: ["cisa_kev", "technology_detection"],
    });
  }
  if (!Number.isFinite(Number(kev.checked)) || !kev.catalogue_source) {
    return signal("incomplete", "kev_completion_not_recorded", {
      sources: ["cisa_kev"],
    });
  }
  return signal("not_observed", "complete_kev_correlation_no_match", {
    sources: ["cisa_kev"],
    limitations: kev?.catalogue_stale ? ["catalogue_stale"] : [],
  });
}

function resolveCloudStorage(modules, dependencies) {
  const cloud = modules?.cloud_storage_discovery;
  const observedCount = Math.max(
    finiteCount(cloud?.total),
    count(cloud?.findings),
    count(cloud?.candidates)
  );
  if (observedCount > 0) {
    return signal("observed", "cloud_storage_signal_observed", {
      evidence_count: observedCount,
      sources: ["cloud_storage_discovery"],
      limitations: cloud?.incomplete === true
        ? [cloud.incomplete_reason]
        : [],
    });
  }
  if (moduleNotAssessed(cloud)) {
    return signal("not_assessed", "cloud_storage_not_evaluated", {
      sources: ["cloud_storage_discovery"],
    });
  }
  if (cloud.error) {
    return signal("unavailable", "cloud_storage_module_unavailable", {
      sources: ["cloud_storage_discovery"],
    });
  }
  if (cloud.incomplete === true) {
    return signal("incomplete", "cloud_storage_evidence_incomplete", {
      sources: ["cloud_storage_discovery"],
      limitations: [cloud.incomplete_reason],
    });
  }
  if (dependencies.some((dependency) =>
    ["unavailable", "incomplete"].includes(dependency.state) ||
    dependency.limitations.length > 0
  )) {
    return signal("incomplete", "cloud_storage_source_evidence_incomplete", {
      sources: ["cloud_storage_discovery"],
    });
  }
  if (!Number.isFinite(Number(cloud.checked)) ||
      !Array.isArray(cloud.findings) ||
      !Array.isArray(cloud.candidates)) {
    return signal("incomplete", "cloud_storage_completion_not_recorded", {
      sources: ["cloud_storage_discovery"],
    });
  }
  return signal("not_observed", "complete_cloud_storage_pass_no_signal", {
    sources: ["cloud_storage_discovery"],
  });
}

export function deriveAttackSurfaceSignalCompleteness(modules = {}) {
  const signals = {};
  signals.subdomain_discovery = resolveSubdomainDiscovery(modules);
  signals.dns_resolution = resolveDnsResolution(modules);
  signals.http_https_service = resolveHttpHttpsService(modules);
  signals.technology = resolveTechnology(modules);
  signals.exposure_admin_surface = resolveExposureAdminSurface(modules);
  signals.takeover_candidate = resolveTakeoverCandidate(modules);
  signals.cve = resolveCve(modules, signals.technology);
  signals.kev = resolveKev(modules, signals.technology);
  signals.cloud_storage = resolveCloudStorage(modules, [
    signals.subdomain_discovery,
    signals.http_https_service,
    signals.takeover_candidate,
  ]);

  const summary = Object.fromEntries(
    ATTACK_SURFACE_SIGNAL_STATES.map((state) => [
      state,
      ATTACK_SURFACE_SIGNAL_KEYS.filter((key) => signals[key].state === state).length,
    ])
  );
  return {
    model_version: ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
    signals,
    summary,
  };
}

export function deriveRemovalObservation(signalStates = {}) {
  const states = ACTIVE_REMOVAL_SOURCES.map((source) =>
    signalStates?.[source]?.state ?? signalStates?.[source] ?? "not_assessed"
  );
  if (states.some((state) => state === "observed")) return "observed";
  if (states.some((state) => state === "unavailable")) {
    return "observation_unavailable";
  }
  if (states.some((state) => state === "incomplete")) {
    return "observation_incomplete";
  }
  if (states.some((state) => state === "not_assessed")) return "not_assessed";
  const [dnsState, httpState] = states;
  if (dnsState === "absent" && COMPLETE_NEGATIVE_STATES.has(httpState)) {
    return "not_observed";
  }
  return "observation_incomplete";
}

const CANONICAL_LIFECYCLE_INSTANT =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function canonicalLifecycleEpoch(value) {
  // Raw SQLite UTC-space and offset timestamps must first pass through the
  // shared lifecycle normaliser. Date.parse is safe here only after this exact
  // canonical-Z contract has been established.
  if (typeof value !== "string" || !CANONICAL_LIFECYCLE_INSTANT.test(value)) {
    return null;
  }
  const epochMs = Date.parse(value);
  if (!Number.isFinite(epochMs) || new Date(epochMs).toISOString() !== value) {
    return null;
  }
  return epochMs;
}

function validObservationRows(rows) {
  return (rows || [])
    .map((row) => ({ row, epochMs: canonicalLifecycleEpoch(row?.observed_at) }))
    .filter(({ row, epochMs }) => row?.scan_id && epochMs !== null)
    .map((row) => ({
      scan_id: row.row.scan_id,
      observed_at: new Date(row.epochMs).toISOString(),
    }));
}

export function applyAssetRemovalConfirmation(current = {}, observation = {}) {
  const policy = ASSET_REMOVAL_CONFIRMATION_POLICY;
  const previousLifecycle = current.lifecycle_state || "not_assessed";
  const previousRows = validObservationRows(current.qualifying_observations);
  const observationState = deriveRemovalObservation(observation.signal_states);
  const base = {
    policy_version: policy.version,
    lifecycle_state: previousLifecycle,
    last_observation_state: observationState,
    qualifying_observations: previousRows,
    confirmed_removed_at: current.confirmed_removed_at || null,
    transition: null,
  };

  if (observationState === "observed") {
    return {
      ...base,
      lifecycle_state: "observed",
      qualifying_observations: [],
      confirmed_removed_at: null,
      transition: previousLifecycle === "confirmed_removed"
        ? "reappeared"
        : "observed",
    };
  }

  // Unavailable, incomplete and not-assessed scans are append-only evidence but
  // do not mutate the confirmation counter or the durable lifecycle projection.
  if (observationState !== "not_observed") return base;
  if (previousLifecycle === "confirmed_removed") return base;

  const observedMs = canonicalLifecycleEpoch(observation.observed_at);
  if (!observation.scan_id || observedMs === null) {
    return { ...base, last_observation_state: "observation_incomplete" };
  }
  if (previousRows.some((row) => row.scan_id === observation.scan_id)) return base;

  const last = previousRows.at(-1);
  if (last &&
      observedMs - canonicalLifecycleEpoch(last.observed_at) <
        policy.minimum_observation_spacing_ms) {
    return base;
  }

  const rows = [
    ...previousRows,
    {
      scan_id: observation.scan_id,
      observed_at: new Date(observedMs).toISOString(),
    },
  ].slice(-policy.required_qualifying_observations);
  const windowMs = rows.length > 1
    ? canonicalLifecycleEpoch(rows.at(-1).observed_at) -
      canonicalLifecycleEpoch(rows[0].observed_at)
    : 0;
  const confirmed =
    rows.length >= policy.required_qualifying_observations &&
    windowMs >= policy.minimum_confirmation_window_ms;

  if (confirmed) {
    return {
      ...base,
      lifecycle_state: "confirmed_removed",
      qualifying_observations: rows,
      confirmed_removed_at: rows.at(-1).observed_at,
      transition: previousLifecycle === "confirmed_removed"
        ? null
        : "confirmed_removed",
    };
  }
  return {
    ...base,
    lifecycle_state: previousLifecycle === "confirmed_removed"
      ? "confirmed_removed"
      : "not_observed",
    qualifying_observations: rows,
  };
}
