// Shared validator fixture: canonical monitoring states built from the live
// signal definitions, so fixtures follow the product's signal set instead of a
// hand-copied list.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const {
  SIGNAL_MONITORING_DEFINITIONS,
  SIGNAL_MONITORING_STATE_VERSION,
  SIGNAL_MONITORING_WORDING,
} = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "signal-monitoring-state.js")).href);

// Every canonical signal healthy; `overrides` maps a signal to another state.
export function healthyMonitoringStates(overrides = {}) {
  const signals = {};
  for (const [signal, definition] of Object.entries(SIGNAL_MONITORING_DEFINITIONS)) {
    const state = overrides[signal] ?? "monitoring_healthy";
    signals[signal] = {
      state,
      message: SIGNAL_MONITORING_WORDING[signal]?.[state] ?? "Monitoring evidence was incomplete in this run.",
      evidence: {
        modules: [...definition.modules],
        incomplete_modules: state === "evidence_incomplete" ? [...definition.modules] : [],
      },
    };
  }
  return { version: SIGNAL_MONITORING_STATE_VERSION, signals };
}
