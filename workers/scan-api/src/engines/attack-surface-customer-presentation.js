// ── Item 10 P5 Attack Surface customer-surface projection ──────────────────
//
// Presentation only. P1-P4's signal-completeness, lifecycle and alert-
// eligibility models remain the sources of truth; this module never re-runs
// discovery, lifecycle confirmation, alert eligibility or case derivation.
// It maps those frozen models onto one additive contract shared by APIs,
// immutable snapshots, Executive Reports, PDFs and the frontend.
//
// Historical law: a snapshot without this P5 block is not upgraded in place
// and no missing security fact is invented. Readers return a notice-only
// `not_recorded` projection whose signals explicitly say that the historical
// snapshot did not record them.
import {
  ASSET_REMOVAL_CONFIRMATION_POLICY,
  ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
  ATTACK_SURFACE_SIGNAL_KEYS,
  ATTACK_SURFACE_SIGNAL_STATES,
} from "./attack-surface-signal-completeness.js";
import {
  ASSET_ALERT_ELIGIBILITY_REASON_CODES,
  ASSET_ALERT_ELIGIBILITY_VERSION,
} from "./asset-alerts.js";

export const ATTACK_SURFACE_CUSTOMER_PRESENTATION_SCHEMA =
  "attack-surface-customer-presentation-v1";

export const ATTACK_SURFACE_CUSTOMER_SIGNAL_STATES = Object.freeze([
  ...ATTACK_SURFACE_SIGNAL_STATES,
]);

export const ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES = Object.freeze([
  "not_assessed",
  "observed",
  "not_observed",
  "confirmed_removed",
]);

export const ATTACK_SURFACE_CUSTOMER_OBSERVATION_STATES = Object.freeze([
  "not_assessed",
  "observed",
  "not_observed",
  "observation_unavailable",
  "observation_incomplete",
]);

const SIGNAL_STATE_SET = new Set(ATTACK_SURFACE_CUSTOMER_SIGNAL_STATES);
const LIFECYCLE_STATE_SET =
  new Set(ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES);
const OBSERVATION_STATE_SET =
  new Set(ATTACK_SURFACE_CUSTOMER_OBSERVATION_STATES);
const ALERT_REASON_SET = new Set(ASSET_ALERT_ELIGIBILITY_REASON_CODES);

const SIGNAL_META = Object.freeze({
  subdomain_discovery: "Subdomain discovery",
  dns_resolution: "DNS resolution",
  http_https_service: "HTTP / HTTPS service",
  technology: "Technology",
  exposure_admin_surface: "Exposure / admin surface",
  takeover_candidate: "Takeover candidate",
  cve: "CVE",
  kev: "Known Exploited Vulnerability (KEV)",
  cloud_storage: "Cloud storage",
});

const SIGNAL_STATE_LABELS = Object.freeze({
  observed: "Observed",
  not_observed: "Not observed in this scan",
  absent: "Confirmed absent",
  unavailable: "Evidence unavailable",
  incomplete: "Evidence incomplete",
  not_assessed: "Not assessed",
});

const LIFECYCLE_STATE_LABELS = Object.freeze({
  not_assessed: "Not assessed",
  observed: "Observed",
  not_observed: "Not observed in this scan",
  confirmed_removed: "Confirmed removed",
});

const OBSERVATION_STATE_LABELS = Object.freeze({
  not_assessed: "Not assessed",
  observed: "Observed",
  not_observed: "Not observed in this scan",
  observation_unavailable: "Evidence unavailable",
  observation_incomplete: "Evidence incomplete",
});

const ALERT_REASON_MESSAGES = Object.freeze({
  eligible_signal_observed:
    "The alert claim was supported by an independently observed signal.",
  eligible_event_evidence:
    "The alert claim was supported by its canonical event evidence.",
  eligible_event_evidence_fallback:
    "The lifecycle schema was not recorded, but the independent event evidence remained eligible.",
  eligible_confirmed_removal:
    "The removal claim satisfied the canonical confirmation policy.",
  eligible_reappearance_after_confirmed_removal:
    "The asset was observed again after a canonically confirmed removal.",
  withheld_signal_not_supported:
    "The recorded signal evidence did not support this alert claim.",
  withheld_lifecycle_schema_absent:
    "The lifecycle model was not recorded, so a confirmed lifecycle claim was withheld.",
  withheld_evidence_lookup_unavailable:
    "Eligibility evidence could not be read, so the lifecycle claim was withheld.",
  withheld_removal_confirmation_not_satisfied:
    "The canonical removal-confirmation policy was not satisfied.",
  withheld_reappearance_predecessor_unconfirmed:
    "The earlier disappearance was not confirmed, so a reappearance claim was withheld.",
  withheld_all_claims_unsupported:
    "All alert claims were withheld because their recorded evidence did not support them.",
});

function asObject(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function parseJson(value, fallback = null) {
  if (value && typeof value === "object") return value;
  try { return value ? JSON.parse(value) : fallback; } catch { return fallback; }
}

function stringArray(value) {
  const parsed = parseJson(value, value);
  return Array.isArray(parsed)
    ? [...new Set(parsed.map((entry) => String(entry || "").trim()).filter(Boolean))]
    : [];
}

function signalMessage(key, state, presentInModel, reason) {
  const label = SIGNAL_META[key] || key;
  if (!presentInModel) {
    return "This signal was not recorded. No security or availability conclusion is inferred.";
  }
  switch (state) {
    case "observed":
      return `${label} evidence was observed in the recorded scope. Detection alone does not establish maliciousness or compromise.`;
    case "not_observed":
      return `${label} was not observed in this scan. No absence or removal conclusion is inferred.`;
    case "absent":
      return `${label} was confirmed absent from the complete evidence contract recorded for this scan.`;
    case "unavailable":
      return `${label} evidence was unavailable. This does not establish a favourable or absent result.`;
    case "incomplete":
      return `${label} evidence was incomplete. No favourable or absence conclusion is inferred.`;
    default:
      return `${label} was not assessed. No favourable conclusion is inferred.`;
  }
}

function presentSignal(key, rawSignal, presentInModel) {
  const raw = asObject(rawSignal);
  const validState = SIGNAL_STATE_SET.has(raw?.state);
  const state = presentInModel
    ? (validState ? raw.state : "incomplete")
    : "not_assessed";
  return {
    signal_key: key,
    label: SIGNAL_META[key] || key,
    status: presentInModel ? "recorded" : "not_recorded",
    state,
    state_label: SIGNAL_STATE_LABELS[state],
    customer_message: signalMessage(
      key,
      state,
      presentInModel,
      raw?.reason,
    ),
    reason: raw?.reason || null,
    evidence_count: Number.isFinite(Number(raw?.evidence_count))
      ? Number(raw.evidence_count)
      : 0,
    sources: stringArray(raw?.sources ?? raw?.sources_json),
    limitations: stringArray(raw?.limitations ?? raw?.limitations_json),
  };
}

function lifecycleMessage(state) {
  switch (state) {
    case "observed":
      return "The same asset identity was observed in the latest recorded lifecycle assessment.";
    case "not_observed":
      return "The asset was not observed in this scan. This is not confirmed removal.";
    case "confirmed_removed":
      return "The asset met the deterministic confirmed-removal policy using qualifying active-source observations.";
    default:
      return "The asset lifecycle was not assessed. No absence, removal or healthy conclusion is inferred.";
  }
}

function observationMessage(state) {
  switch (state) {
    case "observed":
      return "The asset was observed by the relevant active evidence contract.";
    case "not_observed":
      return "The asset was not observed in this scan; confirmation remains a separate lifecycle state.";
    case "observation_unavailable":
      return "The relevant lifecycle evidence was unavailable and did not advance removal confirmation.";
    case "observation_incomplete":
      return "The relevant lifecycle evidence was incomplete and did not advance removal confirmation.";
    default:
      return "The lifecycle signal was not assessed and did not advance removal confirmation.";
  }
}

function presentLifecycleRecord(row) {
  const lifecycleState = LIFECYCLE_STATE_SET.has(row?.lifecycle_state)
    ? row.lifecycle_state
    : "not_assessed";
  const observationState =
    OBSERVATION_STATE_SET.has(row?.last_observation_state)
      ? row.last_observation_state
      : "not_assessed";
  return {
    asset_id: row?.asset_id ?? row?.id ?? null,
    hostname: row?.hostname || null,
    lifecycle_state: lifecycleState,
    lifecycle_state_label: LIFECYCLE_STATE_LABELS[lifecycleState],
    lifecycle_message: lifecycleMessage(lifecycleState),
    last_observation_state: observationState,
    last_observation_state_label:
      OBSERVATION_STATE_LABELS[observationState],
    last_observation_message: observationMessage(observationState),
    lifecycle_policy_version: row?.lifecycle_policy_version || null,
    confirmed_removed_at: row?.confirmed_removed_at || null,
    last_observation_scan_id: row?.last_observation_scan_id || null,
  };
}

function alertDecision(item, eligible) {
  const reasonCode = ALERT_REASON_SET.has(item?.reason_code)
    ? item.reason_code
    : "withheld_signal_not_supported";
  return {
    event_type: item?.event_type || null,
    eligible,
    reason_code: reasonCode,
    reason_message: ALERT_REASON_MESSAGES[reasonCode],
    count: Number.isFinite(Number(item?.count))
      ? Math.max(0, Number(item.count))
      : 0,
  };
}

function presentAlertEligibility(rawEligibility, absenceReason) {
  const raw = asObject(
    rawEligibility?._eligibility ||
    rawEligibility?.record ||
    rawEligibility,
  );
  const recorded =
    raw?.policy_version === ASSET_ALERT_ELIGIBILITY_VERSION &&
    (Array.isArray(raw?.eligible) || Array.isArray(raw?.withheld));
  const decisions = recorded
    ? [
        ...(raw.eligible || []).map((item) => alertDecision(item, true)),
        ...(raw.withheld || []).map((item) => alertDecision(item, false)),
      ]
    : [];
  return {
    status: recorded ? "recorded" : "not_recorded",
    policy_version: recorded ? raw.policy_version : null,
    reason_code_vocabulary: [...ASSET_ALERT_ELIGIBILITY_REASON_CODES],
    decisions,
    customer_message: recorded
      ? (decisions.length
          ? "Alert eligibility was evaluated per claim. Each decision and its canonical reason are shown below."
          : "Alert eligibility was evaluated and no ASM alert claim was recorded.")
      : (absenceReason ||
        "Alert eligibility was not recorded in this presentation. No alert outcome is inferred."),
  };
}

function lifecyclePresentation(records, absenceReason) {
  const recorded = Array.isArray(records);
  const projected = recorded ? records.map(presentLifecycleRecord) : [];
  return {
    status: recorded ? "recorded" : "not_recorded",
    records: projected,
    customer_message: recorded
      ? (projected.length
          ? "Asset lifecycle states were recorded separately from the legacy active/inactive inventory status."
          : "The lifecycle model was available, but no asset lifecycle record was present for this scope.")
      : (absenceReason ||
        "Asset lifecycle evidence was not recorded. Legacy active/inactive status is not interpreted as confirmed removal or observation."),
  };
}

export function buildAttackSurfaceCustomerPresentation({
  signalCompleteness = null,
  lifecycleRecords = null,
  alertEligibility = null,
  absenceReason = null,
  lifecycleAbsenceReason = null,
  alertAbsenceReason = null,
  asOf = null,
} = {}) {
  const canonical = asObject(signalCompleteness);
  const signalInput = asObject(canonical?.signals);
  const signals = {};
  for (const key of ATTACK_SURFACE_SIGNAL_KEYS) {
    signals[key] = presentSignal(
      key,
      signalInput?.[key],
      Boolean(signalInput) &&
        Object.prototype.hasOwnProperty.call(signalInput, key),
    );
  }
  const lifecycle = lifecyclePresentation(
    lifecycleRecords,
    lifecycleAbsenceReason,
  );
  const alert = presentAlertEligibility(
    alertEligibility,
    alertAbsenceReason,
  );
  const signalRecorded = Boolean(signalInput);
  const status =
    signalRecorded ||
    lifecycle.status === "recorded" ||
    alert.status === "recorded"
      ? "current"
      : "not_recorded";
  const lifecycleVersions = [...new Set(
    lifecycle.records
      .map((record) => record.lifecycle_policy_version)
      .filter(Boolean),
  )].sort();

  return {
    schema: ATTACK_SURFACE_CUSTOMER_PRESENTATION_SCHEMA,
    status,
    as_of: asOf || null,
    model_versions: {
      signal_completeness: signalRecorded
        ? (canonical.model_version || null)
        : null,
      lifecycle_policy: lifecycleVersions.length === 1
        ? lifecycleVersions[0]
        : null,
      alert_eligibility: alert.policy_version,
    },
    contract_versions: {
      signal_completeness: ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
      lifecycle_policy: ASSET_REMOVAL_CONFIRMATION_POLICY.version,
      alert_eligibility: ASSET_ALERT_ELIGIBILITY_VERSION,
    },
    state_vocabulary: {
      signals: [...ATTACK_SURFACE_CUSTOMER_SIGNAL_STATES],
      lifecycle: [...ATTACK_SURFACE_CUSTOMER_LIFECYCLE_STATES],
      last_observation: [...ATTACK_SURFACE_CUSTOMER_OBSERVATION_STATES],
    },
    signal_order: [...ATTACK_SURFACE_SIGNAL_KEYS],
    signals,
    lifecycle: {
      ...lifecycle,
      confirmation_policy: {
        version: ASSET_REMOVAL_CONFIRMATION_POLICY.version,
        required_qualifying_observations:
          ASSET_REMOVAL_CONFIRMATION_POLICY.required_qualifying_observations,
        minimum_observation_spacing_ms:
          ASSET_REMOVAL_CONFIRMATION_POLICY.minimum_observation_spacing_ms,
        minimum_confirmation_window_ms:
          ASSET_REMOVAL_CONFIRMATION_POLICY.minimum_confirmation_window_ms,
        relevant_active_sources: [
          ...ASSET_REMOVAL_CONFIRMATION_POLICY.relevant_active_sources,
        ],
        passive_sources_excluded: [
          ...ASSET_REMOVAL_CONFIRMATION_POLICY.passive_sources_excluded,
        ],
      },
    },
    alert_eligibility: alert,
    historical_notice: status === "not_recorded"
      ? (absenceReason ||
        "Attack Surface per-signal, lifecycle and alert-eligibility evidence was not recorded in this historical snapshot. Missing fields are not interpreted as favourable results.")
      : null,
    scope_note:
      "Attack Surface evidence is reported per signal. Unavailable, incomplete and not-assessed evidence remains distinct; one degraded signal does not erase a reliable sibling.",
  };
}

export function attackSurfaceAssuranceFromSnapshot(snapshot) {
  const recorded = snapshot?.attack_surface_assurance;
  if (
    recorded?.schema === ATTACK_SURFACE_CUSTOMER_PRESENTATION_SCHEMA &&
    recorded?.signals &&
    recorded?.lifecycle &&
    recorded?.alert_eligibility
  ) {
    return recorded;
  }
  const reason = recorded
    ? "This snapshot contains an unsupported Attack Surface presentation schema. It is unavailable to this reader and is not interpreted."
    : "Attack Surface per-signal, lifecycle and alert-eligibility evidence was not recorded in this historical snapshot. Missing fields are not interpreted as favourable results.";
  return buildAttackSurfaceCustomerPresentation({
    absenceReason: reason,
    lifecycleAbsenceReason: reason,
    alertAbsenceReason: reason,
  });
}

export function attackSurfaceAssuranceApiProjection(snapshot) {
  return {
    attack_surface_assurance:
      attackSurfaceAssuranceFromSnapshot(snapshot),
  };
}

export function attackSurfacePresentationModelCompatible(presentation) {
  return presentation?.status !== "current" || (
    presentation?.model_versions?.signal_completeness === null ||
    presentation?.model_versions?.signal_completeness ===
      ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION
  );
}
