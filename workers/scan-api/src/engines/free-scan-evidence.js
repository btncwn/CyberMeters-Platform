// ── Anonymous free-scan evidence contract ───────────────────────────────────
//
// The public preview executes four modules, not the full Cyber MOT. This module
// keeps execution outcome, canonical signal coverage, and customer conclusion
// separate so a zero-finding response can never become a healthy verdict when a
// probe failed or returned incomplete evidence.

import {
  deriveDeclaredSignalMonitoringStates,
  resolveSignalMonitoringCoverage,
  SIGNAL_MONITORING_STATES,
} from "./signal-monitoring-state.js";

export const FREE_SCAN_MODULE_STATES = Object.freeze({
  ATTEMPTED:   "attempted",
  COMPLETED:   "completed",
  FAILED:      "failed",
  PARTIAL:     "partial",
  INCOMPLETE:  "incomplete",
  UNAVAILABLE: "unavailable",
});

export const FREE_SCAN_PREVIEW_STATES = Object.freeze({
  ISSUES_OBSERVED:    "issues_observed",
  NO_ISSUES_OBSERVED: "no_issues_observed",
  EVIDENCE_INCOMPLETE:"evidence_incomplete",
});

export const FREE_SCAN_MODULE_DEFINITIONS = Object.freeze([
  Object.freeze({ module: "dns", label: "DNS" }),
  Object.freeze({ module: "ssl", label: "TLS" }),
  Object.freeze({ module: "headers", label: "Headers" }),
  Object.freeze({ module: "email_security", label: "Email" }),
]);

const FREE_SCAN_SIGNAL_DEFINITIONS = Object.freeze({
  dns: Object.freeze({
    modules: Object.freeze(["dns"]),
    providers: Object.freeze([]),
  }),
  website_security: Object.freeze({
    modules: Object.freeze(["ssl", "headers"]),
    providers: Object.freeze([]),
  }),
  email_protection: Object.freeze({
    modules: Object.freeze(["email_security"]),
    providers: Object.freeze([]),
  }),
});

const FINDING_CAPABLE_STATES = new Set([
  FREE_SCAN_MODULE_STATES.COMPLETED,
  FREE_SCAN_MODULE_STATES.PARTIAL,
]);

function nonEmptyError(value) {
  return value != null && String(value).trim() !== "";
}

export function classifyFreeScanSettlement(settlement, moduleName = null) {
  if (!settlement) return FREE_SCAN_MODULE_STATES.INCOMPLETE;
  if (settlement.status === "pending") {
    return FREE_SCAN_MODULE_STATES.ATTEMPTED;
  }
  if (settlement.status === "rejected") return FREE_SCAN_MODULE_STATES.FAILED;

  const value = settlement.value;
  if (
    value?.outcome === "unavailable" ||
    value?.unavailable === true
  ) {
    return FREE_SCAN_MODULE_STATES.UNAVAILABLE;
  }
  if (
    value == null ||
    value?.incomplete === true ||
    value?.executed === false ||
    value?.skipped === true ||
    nonEmptyError(value?.error)
  ) {
    return FREE_SCAN_MODULE_STATES.INCOMPLETE;
  }
  if (moduleName === "email_security") {
    const emailStatuses = [
      value.spf_evidence_status,
      value.dkim_evidence_status,
      value.dmarc_state?.evidence_status,
    ];
    if (emailStatuses.some((status) => status == null || status === "not_yet_assessed")) {
      return FREE_SCAN_MODULE_STATES.INCOMPLETE;
    }
    const unavailableCount = emailStatuses.filter(
      (status) => status === "unavailable",
    ).length;
    if (unavailableCount === emailStatuses.length) {
      return FREE_SCAN_MODULE_STATES.UNAVAILABLE;
    }
    if (unavailableCount > 0) return FREE_SCAN_MODULE_STATES.PARTIAL;
  }
  if (
    value?.outcome === "degraded" ||
    value?.degraded === true ||
    value?.validation_uncertain === true
  ) {
    return FREE_SCAN_MODULE_STATES.PARTIAL;
  }
  return FREE_SCAN_MODULE_STATES.COMPLETED;
}

function canonicalModuleEvidence(state, value) {
  switch (state) {
    case FREE_SCAN_MODULE_STATES.COMPLETED:
      return value;
    case FREE_SCAN_MODULE_STATES.PARTIAL: {
      // Email observation statuses are deliberately non-enumerable in the
      // production module. Preserve their property descriptors so scoring does
      // not regress an unavailable SPF/DMARC/DKIM probe into a missing-record
      // finding while adding the canonical degraded marker.
      const copy = Object.defineProperties(
        {},
        Object.getOwnPropertyDescriptors(value || {}),
      );
      copy.degraded = true;
      copy.outcome = "degraded";
      return copy;
    }
    case FREE_SCAN_MODULE_STATES.UNAVAILABLE:
      return { unavailable: true, outcome: "unavailable" };
    case FREE_SCAN_MODULE_STATES.FAILED:
      return { incomplete: true, error: "module_failed" };
    case FREE_SCAN_MODULE_STATES.ATTEMPTED:
      return { incomplete: true, executed: false };
    case FREE_SCAN_MODULE_STATES.INCOMPLETE:
    default:
      return { ...(value || {}), incomplete: true };
  }
}

export function deriveFreeScanModulesScanned(moduleEvidence) {
  return moduleEvidence
    .filter((entry) => entry.state === FREE_SCAN_MODULE_STATES.COMPLETED)
    .map((entry) => entry.module);
}

export function buildFreeScanEvidence(settlements = {}) {
  const moduleEvidence = FREE_SCAN_MODULE_DEFINITIONS.map(({ module, label }) => {
    const settlement = settlements[module] ?? null;
    return {
      module,
      label,
      attempted: settlement != null,
      state: classifyFreeScanSettlement(settlement, module),
    };
  });

  const modules = Object.fromEntries(moduleEvidence.map((entry) => {
    const settlement = settlements[entry.module];
    const value = settlement?.status === "fulfilled" ? settlement.value : null;
    return [entry.module, canonicalModuleEvidence(entry.state, value)];
  }));

  const monitoringStates = deriveDeclaredSignalMonitoringStates({
    modules,
    definitions: FREE_SCAN_SIGNAL_DEFINITIONS,
  });
  const coverage = resolveSignalMonitoringCoverage(
    monitoringStates,
    Object.keys(FREE_SCAN_SIGNAL_DEFINITIONS),
  );

  return {
    module_evidence: moduleEvidence,
    modules_attempted: moduleEvidence
      .filter((entry) => entry.attempted)
      .map((entry) => entry.module),
    modules_scanned: deriveFreeScanModulesScanned(moduleEvidence),
    monitoring_states: monitoringStates,
    evidence_coverage: {
      state: coverage.state,
      complete: coverage.complete,
      messages: coverage.messages,
    },
    modules,
  };
}

export function filterFreeScanFindings(findings, moduleEvidence) {
  const states = new Map(
    (moduleEvidence || []).map((entry) => [entry.module, entry.state]),
  );
  return (Array.isArray(findings) ? findings : []).filter((finding) =>
    FINDING_CAPABLE_STATES.has(states.get(finding?.module))
  );
}

export function resolveFreeScanPreviewState({
  findingsCount = 0,
  coverage = null,
  moduleEvidence = [],
} = {}) {
  const allModulesCompleted =
    moduleEvidence.length === FREE_SCAN_MODULE_DEFINITIONS.length &&
    moduleEvidence.every(
      (entry) => entry.state === FREE_SCAN_MODULE_STATES.COMPLETED,
    );
  if (findingsCount > 0) return FREE_SCAN_PREVIEW_STATES.ISSUES_OBSERVED;
  if (findingsCount === 0 && coverage?.complete === true && allModulesCompleted) {
    return FREE_SCAN_PREVIEW_STATES.NO_ISSUES_OBSERVED;
  }
  return FREE_SCAN_PREVIEW_STATES.EVIDENCE_INCOMPLETE;
}

export function freeScanSignalState(monitoringStates, signal) {
  return monitoringStates?.signals?.[signal]?.state
    ?? SIGNAL_MONITORING_STATES.EVIDENCE_INCOMPLETE;
}
