// ── Canonical within-scan signal monitoring state ────────────────────────────
//
// This is the ONE backend-owned resolver for customer-facing monitoring health.
// It translates evidence already collected during the current scan into exactly
// one state per signal. It does not probe, score, compare with an earlier scan,
// or change scan_quality. Missing or unrecognised evidence fails closed.

export const SIGNAL_MONITORING_STATE_VERSION = "signal-monitoring-state-v1";

export const SIGNAL_MONITORING_STATES = Object.freeze({
  MONITORING_HEALTHY:  "monitoring_healthy",
  MONITORING_DEGRADED: "monitoring_degraded",
  SIGNAL_UNAVAILABLE:  "signal_unavailable",
  EVIDENCE_INCOMPLETE: "evidence_incomplete",
});

// Canonical evidence ownership. Signal names are stable customer-facing areas;
// module/provider names remain evidence pointers, not customer verdicts.
export const SIGNAL_MONITORING_DEFINITIONS = Object.freeze({
  dns: Object.freeze({
    modules: Object.freeze(["dns"]),
    providers: Object.freeze([]),
  }),
  certificate_transparency: Object.freeze({
    modules: Object.freeze(["subdomains"]),
    providers: Object.freeze(["crt_sh", "certspotter"]),
  }),
  website_security: Object.freeze({
    modules: Object.freeze(["ssl", "headers"]),
    providers: Object.freeze([]),
  }),
  email_protection: Object.freeze({
    modules: Object.freeze(["email_security", "email_security_intelligence"]),
    providers: Object.freeze([]),
  }),
  attack_surface: Object.freeze({
    modules: Object.freeze([
      "dns_bruteforce",
      "subdomain_takeover",
      "asset_exposure",
      "cloud_storage_discovery",
    ]),
    providers: Object.freeze([]),
  }),
  technology_visibility: Object.freeze({
    modules: Object.freeze(["technology_detection"]),
    providers: Object.freeze([]),
  }),
  vulnerability_intelligence: Object.freeze({
    modules: Object.freeze([
      "cve_intelligence",
      "known_exploited_vulnerabilities",
    ]),
    providers: Object.freeze([]),
  }),
  registration_data: Object.freeze({
    modules: Object.freeze(["whois_intelligence"]),
    providers: Object.freeze([]),
  }),
});

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
  certificate_transparency: Object.freeze({
    monitoring_healthy:  "Certificate transparency checks completed normally in this run.",
    monitoring_degraded: "We could not fully verify certificate transparency data in this run.",
    signal_unavailable:  "Certificate transparency data was unavailable in this run.",
    evidence_incomplete: "Certificate transparency checks did not complete in this run.",
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

function providerEvidenceState(providerNames, providerHealth) {
  if (providerNames.length === 0) return null;
  const outcomes = providerNames.map((provider) => providerHealth?.[provider]?.outcome ?? null);
  const available = outcomes.filter((outcome) => outcome === "available").length;
  const unavailable = outcomes.filter((outcome) => outcome === "unavailable").length;
  const unknown = outcomes.length - available - unavailable;

  // No provider telemetry means the signal's evidence did not complete. If at
  // least one provider explicitly failed and no fallback produced evidence, the
  // signal itself was unavailable even when a second provider was not recorded.
  if (available === 0 && unavailable === 0) {
    return SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
  }
  if (available === 0 && unavailable > 0) {
    return SIGNAL_MONITORING_STATES.SIGNAL_UNAVAILABLE;
  }
  if (unknown > 0) {
    return SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
  }
  if (unavailable > 0) {
    return SIGNAL_MONITORING_STATES.MONITORING_DEGRADED;
  }
  return SIGNAL_MONITORING_STATES.MONITORING_HEALTHY;
}

function resolveSignalState(definition, modules, skipped, providerHealth) {
  const moduleStates = definition.modules.map((moduleName) =>
    moduleEvidenceState(modules, moduleName, skipped)
  );
  const combinedModules = combineModuleStates(moduleStates);
  if (combinedModules !== SIGNAL_MONITORING_STATES.MONITORING_HEALTHY) {
    return combinedModules;
  }
  return providerEvidenceState(definition.providers, providerHealth)
    ?? SIGNAL_MONITORING_STATES.MONITORING_HEALTHY;
}

export function deriveSignalMonitoringStates({
  modules = {},
  scanQuality = null,
  providerHealth = {},
} = {}) {
  const skipped = skippedModuleNames(scanQuality);
  const signals = {};

  for (const [signal, definition] of Object.entries(SIGNAL_MONITORING_DEFINITIONS)) {
    const state = resolveSignalState(definition, modules || {}, skipped, providerHealth || {});
    const incompleteModules = definition.modules.filter((moduleName) =>
      moduleEvidenceState(modules || {}, moduleName, skipped) ===
        SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE
    );
    signals[signal] = {
      state,
      message: SIGNAL_MONITORING_WORDING[signal]?.[state]
        ?? "Monitoring evidence was incomplete in this run.",
      evidence: {
        modules: [...definition.modules],
        incomplete_modules: incompleteModules,
        providers: Object.fromEntries(
          definition.providers.map((provider) => [
            provider,
            providerHealth?.[provider]?.outcome ?? "unknown",
          ])
        ),
      },
    };
  }

  return {
    version: SIGNAL_MONITORING_STATE_VERSION,
    signals,
  };
}
