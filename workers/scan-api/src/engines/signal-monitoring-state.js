// ── Canonical within-scan signal monitoring state ────────────────────────────
//
// This is the ONE backend-owned resolver for customer-facing monitoring health.
// It translates evidence already collected during the current scan into exactly
// one state per signal. It does not probe, score, compare with an earlier scan,
// or change scan_quality. Missing or unrecognised evidence fails closed.

export const SIGNAL_MONITORING_STATE_VERSION = "signal-monitoring-state-v3";

export const SIGNAL_MONITORING_STATES = Object.freeze({
  MONITORING_HEALTHY:  "monitoring_healthy",
  MONITORING_DEGRADED: "monitoring_degraded",
  SIGNAL_UNAVAILABLE:  "signal_unavailable",
  EVIDENCE_INCOMPLETE: "evidence_incomplete",
});

// Canonical evidence ownership. Signal names are stable customer-facing areas;
// module names remain evidence pointers, not customer verdicts. Every signal is
// produced by CyberMeters' own observation of the scanned domain.
//
// v3: outside vulnerability data is no longer part of a scan (check-pack.js),
// so there is no vulnerability-intelligence signal. Registration data is read
// from the registry's RDAP service and is `optional`: it is still reported
// honestly, but a registry that does not answer never makes the assessment
// incomplete, because nothing else in the scan depends on it.
export const SIGNAL_MONITORING_DEFINITIONS = Object.freeze({
  dns: Object.freeze({
    modules: Object.freeze(["dns"]),
  }),
  website_security: Object.freeze({
    modules: Object.freeze(["ssl", "headers"]),
  }),
  email_protection: Object.freeze({
    modules: Object.freeze([
      "email_security",
      "dmarc_core",
      "email_security_intelligence",
    ]),
  }),
  attack_surface: Object.freeze({
    modules: Object.freeze([
      "dns_bruteforce",
      "subdomain_takeover",
      "asset_exposure",
      "cloud_storage_discovery",
    ]),
  }),
  technology_visibility: Object.freeze({
    modules: Object.freeze(["technology_detection"]),
  }),
  registration_data: Object.freeze({
    modules: Object.freeze(["whois_intelligence"]),
    optional: true,
  }),
});

// The signal set every v1/v2 payload was recorded against. A stored payload is
// always read against the definitions it was produced under, so a historical
// scan whose vulnerability-intelligence evidence was incomplete reads exactly
// as it did when it was recorded.
const LEGACY_SIGNAL_MONITORING_DEFINITIONS = Object.freeze({
  dns: SIGNAL_MONITORING_DEFINITIONS.dns,
  website_security: SIGNAL_MONITORING_DEFINITIONS.website_security,
  email_protection: SIGNAL_MONITORING_DEFINITIONS.email_protection,
  attack_surface: SIGNAL_MONITORING_DEFINITIONS.attack_surface,
  technology_visibility: SIGNAL_MONITORING_DEFINITIONS.technology_visibility,
  vulnerability_intelligence: Object.freeze({
    modules: Object.freeze([
      "cve_intelligence",
      "known_exploited_vulnerabilities",
    ]),
  }),
  registration_data: Object.freeze({
    modules: Object.freeze(["whois_intelligence"]),
  }),
});
const LEGACY_SIGNAL_MONITORING_VERSIONS = new Set([
  "signal-monitoring-state-v1",
  "signal-monitoring-state-v2",
]);
// The version an unversioned payload is normalised to: the set it is read with.
const LEGACY_SIGNAL_MONITORING_DEFAULT_VERSION = "signal-monitoring-state-v2";

// Every producer stamps a version, so an unversioned payload can only come from
// a report recorded before monitoring states existed; it is read against the
// legacy set too. Unknown future versions read against the current set.
export function signalMonitoringDefinitionsFor(monitoringStates) {
  const version = monitoringStates?.version;
  return version == null || LEGACY_SIGNAL_MONITORING_VERSIONS.has(version)
    ? LEGACY_SIGNAL_MONITORING_DEFINITIONS
    : SIGNAL_MONITORING_DEFINITIONS;
}

// The signals whose state decides whether a scan's evidence coverage was
// complete. Optional signals are reported, never required.
export function requiredMonitoringSignals(monitoringStates) {
  return Object.entries(signalMonitoringDefinitionsFor(monitoringStates))
    .filter(([, definition]) => definition.optional !== true)
    .map(([signal]) => signal);
}

// Canonical customer wording map. Keep this calm, signal-specific, and limited
// to what the current run proves. A monitoring state describes evidence coverage,
// never the customer's security posture and never a recovery from an earlier run.
export const SIGNAL_MONITORING_WORDING = Object.freeze({
  dns: Object.freeze({
    monitoring_healthy:  "DNS checks completed normally in this run.",
    monitoring_degraded: "We could not fully verify DNS data in this run.",
    signal_unavailable:  "DNS data was unavailable in this run.",
    evidence_incomplete: "DNS checks did not complete in this run.",
  }),
  website_security: Object.freeze({
    monitoring_healthy:  "Website security checks completed normally in this run.",
    monitoring_degraded: "We could not fully verify website security data in this run.",
    signal_unavailable:  "Website security data was unavailable in this run.",
    evidence_incomplete: "Website security checks did not complete in this run.",
  }),
  email_protection: Object.freeze({
    monitoring_healthy:  "Email protection checks completed normally in this run.",
    monitoring_degraded: "We could not fully verify email protection data in this run.",
    signal_unavailable:  "Email protection data was unavailable in this run.",
    evidence_incomplete: "Email protection checks did not complete in this run.",
  }),
  attack_surface: Object.freeze({
    monitoring_healthy:  "Attack-surface checks completed normally in this run.",
    monitoring_degraded: "We could not fully verify attack-surface data in this run.",
    signal_unavailable:  "Attack-surface data was unavailable in this run.",
    evidence_incomplete: "Attack-surface checks did not complete in this run.",
  }),
  technology_visibility: Object.freeze({
    monitoring_healthy:  "Technology visibility checks completed normally in this run.",
    monitoring_degraded: "We could not fully verify technology visibility data in this run.",
    signal_unavailable:  "Technology visibility data was unavailable in this run.",
    evidence_incomplete: "Technology visibility checks did not complete in this run.",
  }),
  // Read only for v1/v2 payloads recorded while vulnerability data was a source.
  vulnerability_intelligence: Object.freeze({
    monitoring_healthy:  "Vulnerability intelligence checks completed normally in this run.",
    monitoring_degraded: "We could not fully verify vulnerability intelligence data in this run.",
    signal_unavailable:  "Vulnerability intelligence data was unavailable in this run.",
    evidence_incomplete: "Vulnerability intelligence checks did not complete in this run.",
  }),
  registration_data: Object.freeze({
    monitoring_healthy:  "Domain-registration data checks completed normally in this run.",
    monitoring_degraded: "We could not fully verify domain-registration data in this run.",
    signal_unavailable:  "Domain-registration data was unavailable in this run.",
    evidence_incomplete: "Domain-registration data checks did not complete in this run.",
  }),
});

const RECOGNISED_MONITORING_STATES = new Set(Object.values(SIGNAL_MONITORING_STATES));

// Normalise persisted/read monitoring evidence at the trust boundary. A missing
// signal, missing state, or future/unrecognised state is evidence_incomplete —
// never monitoring_healthy. This lets every downstream coverage consumer use the
// same fail-closed contract instead of inventing its own optimistic fallback.
export function normalizeSignalMonitoringStates(monitoringStates) {
  const signals = {};
  for (const [signal, definition] of Object.entries(signalMonitoringDefinitionsFor(monitoringStates))) {
    const raw = monitoringStates?.signals?.[signal];
    const recognised = RECOGNISED_MONITORING_STATES.has(raw?.state);
    const state = recognised
      ? raw.state
      : SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
    signals[signal] = {
      state,
      message: String(
        (recognised ? raw?.message : null) ||
        SIGNAL_MONITORING_WORDING[signal]?.[state] ||
        "Monitoring evidence was incomplete in this run."
      ),
      evidence: raw?.evidence ?? {
        modules: [...definition.modules],
        incomplete_modules: [...definition.modules],
      },
      ...(definition.optional === true ? { optional: true } : {}),
    };
  }
  return {
    version: monitoringStates?.version || LEGACY_SIGNAL_MONITORING_DEFAULT_VERSION,
    signals,
  };
}

// Aggregate a declared set of signal dependencies without turning monitoring
// health into a security verdict. The result answers only whether the evidence
// coverage required by a consumer was complete. State precedence is deliberately
// fail-closed: incomplete provenance outranks explicit unavailability, which
// outranks partial degradation.
export function resolveSignalMonitoringCoverage(monitoringStates, signalNames = []) {
  const names = [...new Set(
    (Array.isArray(signalNames) ? signalNames : [])
      .map((name) => String(name || "").trim())
      .filter(Boolean)
  )];
  if (names.length === 0) {
    return {
      state: SIGNAL_MONITORING_STATES.MONITORING_HEALTHY,
      complete: true,
      signals: {},
      messages: [],
    };
  }

  const normalised = normalizeSignalMonitoringStates(monitoringStates);
  const signals = {};
  for (const name of names) {
    const entry = normalised.signals[name];
    signals[name] = entry ?? {
      state: SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE,
      message: "Required monitoring evidence was not recorded in this run.",
      evidence: null,
    };
  }

  const states = Object.values(signals).map((entry) => entry.state);
  let state = SIGNAL_MONITORING_STATES.MONITORING_HEALTHY;
  if (states.includes(SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE)) {
    state = SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
  } else if (states.includes(SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE)) {
    state = SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE;
  } else if (states.includes(SIGNAL_MONITORING_STATES.MONITORING_DEGRADED)) {
    state = SIGNAL_MONITORING_STATES.MONITORING_DEGRADED;
  }

  return {
    state,
    complete: state === SIGNAL_MONITORING_STATES.MONITORING_HEALTHY,
    signals,
    messages: [...new Set(
      Object.values(signals)
        .filter((entry) => entry.state !== SIGNAL_MONITORING_STATES.MONITORING_HEALTHY)
        .map((entry) => String(entry.message || "").trim())
        .filter(Boolean)
    )],
  };
}

function nonEmptyError(value) {
  return value != null && String(value).trim() !== "";
}

function skippedModuleNames(scanQuality) {
  return new Set(
    Array.isArray(scanQuality?.modules_skipped)
      ? scanQuality.modules_skipped.map((name) => String(name))
      : []
  );
}

function moduleEvidenceState(modules, moduleName, skipped) {
  if (!Object.prototype.hasOwnProperty.call(modules, moduleName)) {
    return SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
  }
  const value = modules[moduleName];
  if (
    value == null ||
    skipped.has(moduleName) ||
    value.incomplete === true ||
    value.executed === false ||
    value.skipped === true ||
    nonEmptyError(value.error)
  ) {
    return SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
  }
  if (value.outcome === "unavailable" || value.unavailable === true) {
    return SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE;
  }
  if (value.outcome === "degraded" || value.degraded === true) {
    return SIGNAL_MONITORING_STATES.MONITORING_DEGRADED;
  }
  return SIGNAL_MONITORING_STATES.MONITORING_HEALTHY;
}

function combineModuleStates(states) {
  if (states.includes(SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE)) {
    return SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
  }
  const unavailable = states.filter(
    (state) => state === SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE
  ).length;
  if (unavailable === states.length && states.length > 0) {
    return SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE;
  }
  if (
    unavailable > 0 ||
    states.includes(SIGNAL_MONITORING_STATES.MONITORING_DEGRADED)
  ) {
    return SIGNAL_MONITORING_STATES.MONITORING_DEGRADED;
  }
  return SIGNAL_MONITORING_STATES.MONITORING_HEALTHY;
}

function resolveSignalState(definition, modules, skipped) {
  return combineModuleStates(
    definition.modules.map((moduleName) => moduleEvidenceState(modules, moduleName, skipped))
  );
}

const ATTACK_SURFACE_INCOMPLETE_CAUSES = Object.freeze({
  asset_exposure: Object.freeze({
    server_error: "A website target returned a server error after retry.",
    probe_timeout: "A website target did not answer before the probe deadline.",
    subrequest_budget_exhausted: "The HTTP probe request budget was exhausted.",
    dns_resolution_unavailable: "DNS resolution for a website target was unavailable.",
    exposure_probe_failed: "The asset exposure probe failed before it could assess its targets.",
  }),
  dns_bruteforce: Object.freeze({
    dns_not_executed: "Hostname discovery did not finish within the scan budget.",
  }),
  subdomain_takeover: Object.freeze({
    takeover_probe_failed: "The hostname takeover probe failed before it could finish.",
  }),
  cloud_storage_discovery: Object.freeze({
    cloud_storage_probe_failed: "The cloud storage probe failed before it could finish.",
  }),
});

function attackSurfaceIncompleteMessage(incompleteModules, modules) {
  const causes = incompleteModules.map(name =>
    ATTACK_SURFACE_INCOMPLETE_CAUSES[name]?.[modules[name]?.incomplete_reason]
  ).filter(Boolean);
  return causes.length
    ? `Attack-surface checks did not complete in this run. ${[...new Set(causes)].join(" ")}`
    : SIGNAL_MONITORING_WORDING.attack_surface.evidence_incomplete;
}

export function deriveSignalMonitoringStates({
  modules = {},
  scanQuality = null,
} = {}) {
  const skipped = skippedModuleNames(scanQuality);
  const signals = {};

  for (const [signal, definition] of Object.entries(SIGNAL_MONITORING_DEFINITIONS)) {
    const state = resolveSignalState(definition, modules || {}, skipped);
    const incompleteModules = definition.modules.filter((moduleName) =>
      moduleEvidenceState(modules || {}, moduleName, skipped) ===
        SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE
    );
    signals[signal] = {
      state,
      message: signal === "attack_surface" && state === SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE
        ? attackSurfaceIncompleteMessage(incompleteModules, modules)
        : SIGNAL_MONITORING_WORDING[signal]?.[state]
        ?? "Monitoring evidence was incomplete in this run.",
      evidence: {
        modules: [...definition.modules],
        incomplete_modules: incompleteModules,
      },
      ...(definition.optional === true ? { optional: true } : {}),
    };
  }

  return {
    version: SIGNAL_MONITORING_STATE_VERSION,
    signals,
  };
}
