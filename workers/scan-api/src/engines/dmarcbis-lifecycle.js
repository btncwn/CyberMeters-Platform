// Item 7 P4 — immutable DMARCbis lifecycle transitions.
//
// This module compares only integrity-verified canonical snapshots. It never
// re-runs current derivation over historical raw DNS, and it never copies an RR
// set into D1. The append-only email_protection_events row is the occurrence
// identity; created_at is the current snapshot's assessment time.
import { sha256Hex } from "../lib/aggregate-report-ingest.js";
import {
  deriveDmarcPolicyConditions,
  dmarcDomainBaselineRecordId,
  dmarcPolicyConditionRecordId,
} from "./email-protection-lifecycle.js";
import {
  DMARC_POLICY_CONDITION_RECORD_TYPE,
  DMARC_LIFECYCLE_SUBTYPES,
  DMARC_RELATED_CHANGES_SUBTYPES,
} from "./dmarcbis-lifecycle-contract.js";
import { readScanReportSnapshot } from "./report-snapshot.js";

export const DMARC_EVENT_POLICY_TRANSITION = "dmarc_policy_transition";
export const DMARC_EVENT_MONITORING_DEGRADED = "dmarc_monitoring_degraded";
export const DMARC_EVENT_CONDITION_CLEARED = "condition_no_longer_observed";

export { DMARC_LIFECYCLE_SUBTYPES, DMARC_RELATED_CHANGES_SUBTYPES };

const RELATED_SUBTYPES = new Set(DMARC_RELATED_CHANGES_SUBTYPES);
const USABLE_EXACT_STATES = new Set([
  "present_valid",
  "present_valid_with_defaults",
]);
const USABLE_RECORD_SET_STATES = new Set([
  "single_valid",
  "single_valid_with_defaults",
  "single_valid_with_non_dmarc_txt",
]);
const MALFORMED_RECORD_SET_STATES = new Set([
  "single_invalid",
  "single_invalid_duplicate_tag",
]);
const MULTIPLE_RECORD_SET_STATES = new Set([
  "multiple",
  "multiple_mixed",
  "multiple_invalid",
]);
const POLICY_RANK = Object.freeze({ none: 0, quarantine: 1, reject: 2 });

const CUSTOMER_WORDING = Object.freeze({
  record_created: "A DMARC record was newly observed.",
  record_removed:
    "The previously observed exact DMARC record is no longer present.",
  record_became_malformed:
    "The observed DMARC record changed into a form that cannot be used.",
  multiple_records_detected: "Multiple DMARC policy records are now present.",
  policy_changed: "The published requested DMARC policy changed.",
  policy_inherited: "The domain now relies on an inherited DMARC policy.",
  inheritance_source_changed:
    "The source of the applicable DMARC policy changed.",
  organisational_domain_changed:
    "RFC 9989 discovery now identifies a different organisational-policy boundary.",
  subdomain_policy_changed:
    "The published DMARC subdomain preference changed.",
  non_existent_subdomain_policy_changed:
    "The DMARC preference for nonexistent subdomains changed.",
  enforcement_strengthened: "The requested DMARC policy became stronger.",
  enforcement_weakened:
    "The requested DMARC policy became less restrictive.",
  legacy_pct_observed:
    "A legacy DMARC pct value was observed and was not applied.",
  external_rua_added: "An aggregate-report destination was added.",
  external_rua_removed: "An aggregate-report destination was removed.",
  external_rua_authorised:
    "The aggregate-report destination now publishes valid authorisation.",
  external_rua_unauthorised:
    "Valid external aggregate-report destination authorisation is no longer present.",
  external_rua_authorisation_unavailable:
    "Aggregate-report destination authorisation could not be checked.",
  monitoring_degraded: "DMARC monitoring was incomplete for this scan.",
});

function canonicalName(value) {
  return String(value || "").trim().replace(/\.$/, "").toLowerCase();
}

function compactPolicyState(evidence) {
  return {
    observation_state: evidence?.observation_state ?? null,
    record_validity: evidence?.record_validity ?? null,
    policy_source_domain: evidence?.policy_source_domain ?? null,
    policy_source_kind: evidence?.policy_source_kind ?? null,
    organisational_domain: evidence?.organisational_domain ?? null,
    domain_existence: evidence?.domain_existence ?? null,
    declared_policy: evidence?.declared_policy ?? null,
    effective_requested_policy:
      evidence?.effective_requested_policy ?? null,
    effective_policy_tag: evidence?.effective_policy_tag ?? null,
    inheritance_reason: evidence?.inheritance_reason ?? null,
    testing_adjustment: evidence?.testing_adjustment ?? null,
    p: evidence?.p?.normalized ?? null,
    sp: evidence?.sp?.normalized ?? null,
    np: evidence?.np?.normalized ?? null,
    t: evidence?.t?.normalized ?? null,
    legacy_pct_raw: evidence?.legacy_pct?.observed
      ? evidence.legacy_pct.raw ?? null
      : null,
    core_completeness: evidence?.core_completeness ?? "unavailable",
    policy_completeness: evidence?.policy_completeness ?? "unavailable",
    rua_authorisation_completeness:
      evidence?.rua_authorisation_completeness ?? "unavailable",
    monitoring_state: evidence?.monitoring_state ?? "monitoring_degraded",
    provider_state: evidence?.provider_state ?? "unavailable",
  };
}

function transition(subtype, subjectKey, predicate, before, after, extra = {}) {
  return {
    subtype,
    subject_key: canonicalName(subjectKey),
    predicate,
    customer_wording: CUSTOMER_WORDING[subtype],
    related_changes_eligible: RELATED_SUBTYPES.has(subtype),
    before: compactPolicyState(before),
    after: compactPolicyState(after),
    ...extra,
  };
}

function exactQuestionName(evidence) {
  const author = canonicalName(evidence?.author_domain);
  const found = (evidence?.lookup_path || []).find((entry) =>
    entry?.question?.resolver === "primary" &&
    entry?.question?.purpose === "policy_tree_walk" &&
    canonicalName(entry?.question?.target_domain) === author);
  return canonicalName(found?.question?.name || `_dmarc.${author}`);
}

function sourceQuestionName(evidence) {
  const source = canonicalName(evidence?.policy_source_domain);
  if (!source) return exactQuestionName(evidence);
  return canonicalName(`_dmarc.${source}`);
}

function policyRecordSets(evidence) {
  if (!coreComplete(evidence)) return null;
  const sets = new Map();
  for (const entry of evidence?.lookup_path || []) {
    if (
      entry?.question?.resolver !== "primary" ||
      entry?.question?.purpose !== "policy_tree_walk" ||
      entry?.logically_used === false ||
      entry?.definitive !== true ||
      entry?.record_set?.complete === false
    ) {
      continue;
    }
    const name = canonicalName(entry?.question?.name);
    const target = canonicalName(entry?.question?.target_domain);
    const state = entry?.record_set?.raw_state;
    if (name && state) sets.set(name, { name, target, state });
  }
  return sets;
}

function contradictionFree(evidence) {
  return evidence?.corroboration_state !== "resolver_disagreement" &&
    evidence?.observation_state !== "resolver_disagreement";
}

function coreComplete(evidence) {
  return evidence?.core_completeness === "complete" &&
    contradictionFree(evidence);
}

function policyComplete(evidence) {
  return coreComplete(evidence) &&
    evidence?.policy_completeness === "complete";
}

function exactComplete(evidence) {
  return coreComplete(evidence) &&
    !["unavailable", "incomplete_oversized", "resolver_disagreement"]
      .includes(evidence?.observation_state);
}

function organisationalComplete(evidence) {
  return policyComplete(evidence) &&
    evidence?.organisational_domain_completeness === "complete";
}

function tagApplicabilityContextComplete(evidence, tag) {
  if (!policyComplete(evidence)) return false;
  if (!["organisational", "psd"].includes(evidence?.policy_source_kind)) {
    return false;
  }
  if (tag === "np") {
    return evidence?.domain_existence === "nonexistent" &&
      evidence?.existence_completeness === "complete";
  }
  if (tag === "sp") {
    return evidence?.domain_existence === "exists" &&
      evidence?.existence_completeness === "complete";
  }
  return false;
}

function ruaKey(uri) {
  // The parser has already normalised the URI syntax and A-label destination
  // host. Preserve the remaining URI octets: a mailto local-part can be
  // case-sensitive, so lowercasing the whole URI would collapse two distinct
  // destinations into one lifecycle identity.
  return String(
    uri?.normalized_uri || uri?.uri || uri?.raw || uri?.raw_uri || "",
  ).trim();
}

function ruaSet(evidence) {
  if (!policyComplete(evidence) || !Array.isArray(evidence?.rua_destinations)) {
    return null;
  }
  const map = new Map();
  for (const uri of evidence.rua_destinations) {
    const key = ruaKey(uri);
    if (key && !map.has(key)) map.set(key, uri);
  }
  return map;
}

function authorizationMap(evidence) {
  const destinations = evidence?.external_rua_authorisation?.destinations;
  if (!Array.isArray(destinations)) return null;
  const map = new Map();
  for (const destination of destinations) {
    const key = ruaKey(destination);
    if (key && !map.has(key)) map.set(key, destination);
  }
  return map;
}

function authorizedStatus(value) {
  return value === "authorized" ||
    value === "not_required_same_organisational_domain";
}

function externalDestinationState(destination) {
  if (!destination) return null;
  if (
    destination.same_organisational_domain === true ||
    destination.authorization_status ===
      "not_required_same_organisational_domain"
  ) {
    return false;
  }
  if (destination.same_organisational_domain === false) return true;
  if (["authorized", "unauthorized", "malformed"].includes(
    destination.authorization_status,
  )) {
    return true;
  }
  return null;
}

function authorizationConditionSubject(destination, uri) {
  const queryName =
    destination?.authorization_query_name || uri?.authorization_query_name;
  return queryName ? canonicalName(queryName) : ruaKey(destination || uri);
}

function sameValue(left, right) {
  return (left ?? null) === (right ?? null);
}

function addPolicyTransitions(events, before, after) {
  if (!policyComplete(before) || !policyComplete(after)) return;
  const author = canonicalName(after.author_domain || before.author_domain);
  const beforeRank = POLICY_RANK[before.effective_requested_policy];
  const afterRank = POLICY_RANK[after.effective_requested_policy];
  const sourceChanged =
    !sameValue(before.policy_source_domain, after.policy_source_domain) ||
    !sameValue(before.policy_source_kind, after.policy_source_kind) ||
    !sameValue(before.effective_policy_tag, after.effective_policy_tag);
  const policyChanged =
    !sameValue(before.declared_policy, after.declared_policy) ||
    !sameValue(
      before.effective_requested_policy,
      after.effective_requested_policy,
    ) ||
    !sameValue(before.testing_adjustment, after.testing_adjustment);
  const rankChanged =
    Number.isInteger(beforeRank) &&
    Number.isInteger(afterRank) &&
    beforeRank !== afterRank;

  // The stable taxonomy keeps the generic subtype only when the change is not
  // fully represented by the stronger requested-policy-strength subtype.
  if (policyChanged && !rankChanged) {
    events.push(transition(
      "policy_changed",
      `${author}|${canonicalName(after.policy_source_domain || "none")}`,
      "complete declared/effective requested policy changed",
      before,
      after,
    ));
  }
  if (
    before.policy_source_kind === "exact" &&
    ["organisational", "psd"].includes(after.policy_source_kind)
  ) {
    events.push(transition(
      "policy_inherited",
      author,
      "complete exact source changed to inherited source",
      before,
      after,
    ));
  }
  if (
    ["organisational", "psd"].includes(before.policy_source_kind) &&
    ["organisational", "psd"].includes(after.policy_source_kind) &&
    sourceChanged
  ) {
    events.push(transition(
      "inheritance_source_changed",
      `${author}|${canonicalName(before.policy_source_domain)}>` +
        `${canonicalName(after.policy_source_domain)}`,
      "complete inherited source domain, kind, or applicable tag changed",
      before,
      after,
    ));
  }
  if (
    rankChanged
  ) {
    const stronger = afterRank > beforeRank;
    events.push(transition(
      stronger ? "enforcement_strengthened" : "enforcement_weakened",
      author,
      "complete effective requested-policy ordinal changed",
      before,
      after,
      stronger
        ? {}
        : {
            actionable_condition_type: "weak",
            actionable_group: `policy|${author}`,
            recurrence_type: "enforcement_weakened",
            action_priority: 50,
          },
    ));
  }
}

function addTagTransitions(events, before, after) {
  const author = canonicalName(after.author_domain || before.author_domain);
  for (const [tag, subtype] of [
    ["sp", "subdomain_policy_changed"],
    ["np", "non_existent_subdomain_policy_changed"],
  ]) {
    const applicable =
      tagApplicabilityContextComplete(before, tag) &&
      tagApplicabilityContextComplete(after, tag) &&
      (
        before.effective_policy_tag === tag ||
        after.effective_policy_tag === tag
      );
    if (!applicable || sameValue(before?.[tag]?.normalized, after?.[tag]?.normalized)) {
      continue;
    }
    const source = canonicalName(
      after.policy_source_domain || before.policy_source_domain,
    );
    events.push(transition(
      subtype,
      tag === "np" ? `${source}|${author}|np` : `${source}|sp`,
      `complete applicable ${tag} value changed`,
      before,
      after,
    ));
  }
}

function addExternalRuaTransitions(events, before, after) {
  const beforeUris = ruaSet(before);
  const afterUris = ruaSet(after);
  const beforeAuth = authorizationMap(before);
  const afterAuth = authorizationMap(after);
  if (beforeUris && afterUris) {
    for (const [key, uri] of afterUris) {
      if (beforeUris.has(key)) continue;
      const afterAssessment = afterAuth?.get(key);
      if (externalDestinationState(afterAssessment) !== true) continue;
      const definitivelyUnauthorised =
        after.rua_authorisation_completeness === "complete" &&
        afterAssessment?.lookup_completeness === "complete" &&
        afterAssessment?.authorization_status === "unauthorized";
      events.push(transition(
        "external_rua_added",
        key,
        "complete ordered RUA URI set gained a destination",
        before,
        after,
        {
          subject_key: key,
          destination_uri: key,
          authorization_status:
            afterAssessment?.authorization_status ?? "not_assessed",
          ...(definitivelyUnauthorised
            ? {
                actionable_condition_type: "unauthorised_rua",
                actionable_subject:
                  authorizationConditionSubject(afterAssessment, uri),
                actionable_group:
                  `rua|${authorizationConditionSubject(afterAssessment, uri)}`,
                recurrence_type: "external_rua_unauthorised",
                action_priority: 40,
              }
            : {}),
        },
      ));
    }
    for (const key of beforeUris.keys()) {
      if (afterUris.has(key)) continue;
      if (externalDestinationState(beforeAuth?.get(key)) !== true) continue;
      events.push(transition(
        "external_rua_removed",
        key,
        "complete ordered RUA URI set lost a destination",
        before,
        after,
        { subject_key: key, destination_uri: key },
      ));
    }
  }

  const bothAuthComplete =
    before.rua_authorisation_completeness === "complete" &&
    after.rua_authorisation_completeness === "complete" &&
    beforeAuth && afterAuth;
  if (bothAuthComplete) {
    for (const [key, current] of afterAuth) {
      const previous = beforeAuth.get(key);
      if (!previous) continue;
      const previousStatus = previous.authorization_status;
      const currentStatus = current.authorization_status;
      const conditionSubject = authorizationConditionSubject(
        current,
        afterUris?.get(key),
      );
      if (
        previousStatus === "unauthorized" &&
        authorizedStatus(currentStatus)
      ) {
        events.push(transition(
          "external_rua_authorised",
          key,
          "complete external authorisation changed from unauthorised to authorised",
          before,
          after,
          {
            subject_key: key,
            destination_uri: key,
            before_authorization_status: previousStatus,
            after_authorization_status: currentStatus,
          },
        ));
      } else if (
        authorizedStatus(previousStatus) &&
        currentStatus === "unauthorized"
      ) {
        events.push(transition(
          "external_rua_unauthorised",
          key,
          "complete external authorisation changed from authorised to unauthorised",
          before,
          after,
          {
            subject_key: key,
            destination_uri: key,
            before_authorization_status: previousStatus,
            after_authorization_status: currentStatus,
            actionable_condition_type: "unauthorised_rua",
            actionable_subject: conditionSubject,
            actionable_group: `rua|${conditionSubject}`,
            recurrence_type: "external_rua_unauthorised",
            action_priority: 40,
          },
        ));
      }
    }
  }

  if (
    before.rua_authorisation_completeness === "complete" &&
    after.rua_authorisation_completeness !== "complete" &&
    beforeAuth
  ) {
    for (const [key, previous] of beforeAuth) {
      if (!afterUris?.has(key)) continue;
      const current = afterAuth?.get(key);
      const provider = canonicalName(after.provider_state || "provider");
      events.push(transition(
        "external_rua_authorisation_unavailable",
        `${key}|${provider}`,
        "previous complete external authorisation became unavailable",
        before,
        after,
        {
          subject_key: `${key}|${provider}`,
          destination_uri: key,
          before_authorization_status:
            previous.authorization_status ?? null,
          after_authorization_status:
            current?.authorization_status ?? "unavailable",
          related_changes_eligible: false,
        },
      ));
    }
  }
}

function addMonitoringDegradation(events, before, after) {
  const components = [];
  if (
    before.core_completeness === "complete" &&
    after.core_completeness !== "complete"
  ) {
    components.push("core");
  } else if (
    before.policy_completeness === "complete" &&
    after.policy_completeness !== "complete"
  ) {
    components.push("policy");
  }
  if (
    before.rua_authorisation_completeness === "complete" &&
    !["complete", "not_applicable"].includes(
      after.rua_authorisation_completeness,
    )
  ) {
    components.push("external_rua_authorisation");
  }
  for (const component of components) {
    events.push(transition(
      "monitoring_degraded",
      `${component}|${canonicalName(after.provider_state || "provider")}`,
      `previous complete ${component} evidence became incomplete`,
      before,
      after,
      {
        component,
        provider_state: after.provider_state ?? "unavailable",
        related_changes_eligible: false,
      },
    ));
  }
}

// Pure comparison. Missing, legacy, or incomplete prerequisites suppress risk
// transitions; they never become absence. monitoring_recovered is intentionally
// absent from both the taxonomy and this function.
export function deriveDmarcPolicyTransitions(before, after) {
  if (!before || !after) return [];
  const events = [];
  const author = canonicalName(after.author_domain || before.author_domain);
  const exactSubject = exactQuestionName(after);
  const beforeRecordSets = policyRecordSets(before);
  const afterRecordSets = policyRecordSets(after);

  if (exactComplete(before) && exactComplete(after)) {
    // Production snapshots retain every logically used tree-walk record set.
    // Compare by DNS question so inherited-source defects use the source qname,
    // not the author-domain exact qname. The high-level exact state remains the
    // legacy-snapshot/fixture fallback when detailed record sets are absent.
    const comparableSets =
      beforeRecordSets?.size > 0 && afterRecordSets?.size > 0
        ? [...beforeRecordSets.keys()]
            .filter((name) => afterRecordSets.has(name))
            .map((name) => [
              beforeRecordSets.get(name),
              afterRecordSets.get(name),
            ])
        : [[
            {
              name: exactSubject,
              target: author,
              state: USABLE_EXACT_STATES.has(before.observation_state)
                ? "single_valid"
                : before.observation_state === "present_invalid"
                  ? "single_invalid"
                  : before.observation_state,
            },
            {
              name: exactSubject,
              target: author,
              state: USABLE_EXACT_STATES.has(after.observation_state)
                ? "single_valid"
                : after.observation_state === "present_invalid"
                  ? "single_invalid"
                  : after.observation_state,
            },
          ]];
    for (const [previousSet, currentSet] of comparableSets) {
      const beforeUsable = USABLE_RECORD_SET_STATES.has(previousSet.state);
      const afterUsable = USABLE_RECORD_SET_STATES.has(currentSet.state);
      if (
        !beforeUsable &&
        previousSet.state === "absent" &&
        afterUsable
      ) {
        events.push(transition(
          "record_created",
          currentSet.name,
          "complete candidate count changed from zero to one usable record",
          before,
          after,
        ));
      }
      if (beforeUsable && currentSet.state === "absent") {
        const beforeRank = POLICY_RANK[before.effective_requested_policy];
        const afterRank = POLICY_RANK[after.effective_requested_policy];
        const protectedByEqualOrStrongerInheritance =
          Number.isInteger(beforeRank) &&
          Number.isInteger(afterRank) &&
          afterRank >= beforeRank &&
          ["organisational", "psd"].includes(after.policy_source_kind);
        const wasApplicableSource =
          canonicalName(before.policy_source_domain) === previousSet.target;
        events.push(transition(
          "record_removed",
          previousSet.name,
          "complete usable policy record changed to definitive zero records",
          before,
          after,
          protectedByEqualOrStrongerInheritance || !wasApplicableSource
            ? { equal_or_stronger_inheritance:
                protectedByEqualOrStrongerInheritance }
            : {
                equal_or_stronger_inheritance: false,
                actionable_condition_type: "missing",
                actionable_group: `policy|${author}`,
                recurrence_type: "record_removed",
                action_priority: 80,
              },
        ));
      }
      if (
        beforeUsable &&
        MALFORMED_RECORD_SET_STATES.has(currentSet.state)
      ) {
        events.push(transition(
          "record_became_malformed",
          currentSet.name,
          "complete usable policy record changed to one fatal current-version record",
          before,
          after,
          {
            actionable_condition_type: "malformed",
            actionable_group: `policy|${author}`,
            recurrence_type: "record_became_malformed",
            action_priority: 100,
          },
        ));
      }
      if (
        !MULTIPLE_RECORD_SET_STATES.has(previousSet.state) &&
        MULTIPLE_RECORD_SET_STATES.has(currentSet.state)
      ) {
        events.push(transition(
          "multiple_records_detected",
          currentSet.name,
          "complete non-multiple candidate set changed to multiple current-version records",
          before,
          after,
          {
            actionable_condition_type: "multiple",
            actionable_group: `policy|${author}`,
            recurrence_type: "multiple_records_detected",
            action_priority: 90,
          },
        ));
      }
    }
    const beforePct = before.legacy_pct?.observed
      ? String(before.legacy_pct.raw ?? "")
      : null;
    const afterPct = after.legacy_pct?.observed
      ? String(after.legacy_pct.raw ?? "")
      : null;
    if (afterPct !== null && beforePct !== afterPct) {
      events.push(transition(
        "legacy_pct_observed",
        `${sourceQuestionName(after)}|pct=${afterPct}`,
        "complete source observation gained or changed a legacy pct value",
        before,
        after,
        {
          legacy_pct_raw: afterPct,
          legacy_pct_applied: false,
          related_changes_eligible: false,
        },
      ));
    }
  }

  addPolicyTransitions(events, before, after);
  if (
    organisationalComplete(before) &&
    organisationalComplete(after) &&
    !sameValue(
      before.organisational_domain,
      after.organisational_domain,
    )
  ) {
    events.push(transition(
      "organisational_domain_changed",
      author,
      "complete RFC 9989 organisational-policy boundary changed",
      before,
      after,
    ));
  }
  addTagTransitions(events, before, after);
  addExternalRuaTransitions(events, before, after);
  addMonitoringDegradation(events, before, after);
  return events;
}

export function dmarcLifecycleEventIdentity({
  workspaceId,
  domainId,
  methodologyVersion,
  subtype,
  subjectKey,
  beforeSnapshotId,
  afterSnapshotId,
  beforeFingerprint,
  afterFingerprint,
}) {
  return [
    workspaceId,
    domainId,
    methodologyVersion,
    subtype,
    subjectKey,
    beforeSnapshotId,
    afterSnapshotId,
    beforeFingerprint,
    afterFingerprint,
  ].join("|");
}

async function deterministicEventId(identity) {
  return `epe-${await sha256Hex(identity)}`;
}

function transitionCompleteness(subtype) {
  return subtype === "monitoring_degraded"
    ? "limitation_evidenced"
    : "complete";
}

function transitionEvidenceGrade(subtype) {
  if (subtype === "monitoring_degraded") {
    return {
      observable_ceiling: "L4",
      beta_target: "L3",
      minimum_publishable: "L2",
      degrade_behavior:
        "Publish the evidenced monitoring limitation; infer no DNS policy regression.",
      required_corroboration: ["provider or component limitation evidence"],
      grade: "L3",
      source_type: "derived_transition",
      basis:
        "A previously complete DMARC component became incomplete in the immutable observation pair.",
      limits: [
        "This is a monitoring limitation, not a security regression or recovery claim.",
      ],
      repeat_confirmed: false,
    };
  }
  if (subtype === "legacy_pct_observed") {
    return {
      observable_ceiling: "L5",
      beta_target: "L3",
      minimum_publishable: "L1",
      degrade_behavior:
        "Preserve the raw legacy value without applying it to current policy.",
      required_corroboration: [],
      grade: "L2",
      source_type: "dns_policy_snapshot",
      basis: "Immutable before/after DNS policy evidence.",
      limits: [
        "The legacy pct value is not current DMARCbis enforcement semantics.",
      ],
      repeat_confirmed: false,
    };
  }
  return {
    observable_ceiling: "L5",
    beta_target: "L4",
    minimum_publishable: "L3",
    degrade_behavior:
      "Suppress the transition when either relevant observation is incomplete or contradictory.",
    required_corroboration: [
      "two immutable complete DMARC observations",
      "decisive resolver evidence where applicable",
    ],
    grade: "L3",
    source_type: "derived_transition",
    basis: "Complete before/after DMARCbis snapshot fingerprints.",
    limits: [
      "A published requested policy does not prove receiver enforcement.",
      "Timing does not establish causality, malicious activity, or compromise.",
    ],
    repeat_confirmed: false,
  };
}

async function currentAndPreviousSnapshots(
  env,
  workspaceId,
  domainId,
  scanId,
) {
  const currentRow = await env.cybermeters_db
    .prepare(
      `SELECT s.id, s.scan_id, s.supersedes_snapshot_id, s.assessed_at
       FROM scan_report_snapshots s
       JOIN workspaces w ON w.id = s.workspace_id AND w.deleted_at IS NULL
       WHERE s.workspace_id = ? AND s.domain_id = ? AND s.scan_id = ?
         AND s.status = 'completed'
       LIMIT 1`,
    )
    .bind(workspaceId, domainId, scanId)
    .first()
    .catch(() => null);
  if (!currentRow) return { status: "current_snapshot_unavailable" };
  if (!currentRow.supersedes_snapshot_id) {
    return { status: "baseline_only", currentRow };
  }
  const previousRow = await env.cybermeters_db
    .prepare(
      `SELECT id, scan_id, assessed_at
       FROM scan_report_snapshots
       WHERE workspace_id = ? AND domain_id = ? AND id = ?
         AND status = 'completed'
       LIMIT 1`,
    )
    .bind(workspaceId, domainId, currentRow.supersedes_snapshot_id)
    .first()
    .catch(() => null);
  if (!previousRow) return { status: "previous_snapshot_unavailable", currentRow };
  const [previous, current] = await Promise.all([
    readScanReportSnapshot(env, previousRow.scan_id, {
      repair: false,
      allowReconstruction: false,
      includeSuccessor: false,
    }),
    readScanReportSnapshot(env, currentRow.scan_id, {
      repair: false,
      allowReconstruction: false,
      includeSuccessor: false,
    }),
  ]);
  if (
    previous.status !== "ok" ||
    current.status !== "ok" ||
    previous.row.workspace_id !== workspaceId ||
    current.row.workspace_id !== workspaceId ||
    previous.row.domain_id !== domainId ||
    current.row.domain_id !== domainId
  ) {
    return { status: "snapshot_integrity_unavailable", currentRow, previousRow };
  }
  if (
    previous.dmarcPolicy?.status !== "current" ||
    current.dmarcPolicy?.status !== "current"
  ) {
    return { status: "methodology_baseline_unavailable", currentRow, previousRow };
  }
  return { status: "comparable", currentRow, previousRow, previous, current };
}

async function recordIdForTransition(
  domainId,
  domainMarkerId,
  item,
  selectedAction,
) {
  if (selectedAction) {
    return dmarcPolicyConditionRecordId({
      domain_id: domainId,
      condition_type: item.actionable_condition_type,
      subject_key: item.actionable_subject || item.subject_key,
    });
  }
  return domainMarkerId;
}

function selectedActionIndexes(transitions) {
  const selected = new Map();
  transitions.forEach((item, index) => {
    if (!item.actionable_group || !item.actionable_condition_type) return;
    const current = selected.get(item.actionable_group);
    if (
      current == null ||
      (item.action_priority || 0) >
        (transitions[current].action_priority || 0)
    ) {
      selected.set(item.actionable_group, index);
    }
  });
  return new Set(selected.values());
}

function conditionKey(condition) {
  return `${condition.condition_type}|${canonicalName(condition.subject_key)}`;
}

export function isDmarcPolicyConditionComplete(conditionType, evidence) {
  if (["malformed", "multiple"].includes(conditionType)) {
    return exactComplete(evidence);
  }
  if (["missing", "weak"].includes(conditionType)) {
    return policyComplete(evidence);
  }
  if (conditionType === "unauthorised_rua") {
    return policyComplete(evidence) &&
      evidence.rua_authorisation_completeness === "complete";
  }
  return false;
}

function conditionResolutionComplete(conditionType, before, after) {
  return isDmarcPolicyConditionComplete(conditionType, before) &&
    isDmarcPolicyConditionComplete(conditionType, after);
}

function actionableEventDescriptors(candidates) {
  return candidates
    .filter((candidate) =>
      candidate.event_type === "monitoring_changed" &&
      candidate.detail?.transition_completeness === "complete" &&
      candidate.detail?.to_recurrence_type)
    .map((candidate) => ({
      event_id: candidate.id,
      record_id: candidate.record_id,
      recurrence_type: candidate.detail.to_recurrence_type,
      condition_type: candidate.detail.condition_type,
      entity: candidate.detail.entity,
      author_domain: candidate.detail.author_domain,
      after_scan_id: candidate.detail.after_scan_id,
      after_snapshot_id: candidate.detail.after_snapshot_id,
      after_evidence_fingerprint:
        candidate.detail.after_evidence_fingerprint,
      transition_completeness:
        candidate.detail.transition_completeness,
    }));
}

// Production writer: one tenant/membership gate, two bounded snapshot reads, and
// one conflict-safe batch. The exact observation pair always hashes to the same
// event primary keys; a later recurrence uses different immutable snapshots.
export async function recordDmarcPolicyLifecycle(env, {
  workspace_id,
  domain_id,
  domain,
  scan_id,
} = {}) {
  if (!env?.cybermeters_db || !workspace_id || !domain_id || !domain || !scan_id) {
    return { ran: false, reason: "incomplete_context", inserted: 0 };
  }
  const live = await env.cybermeters_db
    .prepare(
      `SELECT wd.domain_id
       FROM workspace_domains wd
       JOIN workspaces w ON w.id = wd.workspace_id
       JOIN domains d ON d.id = wd.domain_id
       WHERE wd.workspace_id = ? AND wd.domain_id = ?
         AND w.deleted_at IS NULL AND lower(d.domain) = lower(?)
       LIMIT 1`,
    )
    .bind(workspace_id, domain_id, domain)
    .first()
    .catch(() => null);
  if (!live) {
    return { ran: false, reason: "workspace_or_domain_inactive", inserted: 0 };
  }

  const pair = await currentAndPreviousSnapshots(
    env,
    workspace_id,
    domain_id,
    scan_id,
  );
  if (pair.status !== "comparable") {
    return { ran: false, reason: pair.status, inserted: 0 };
  }
  const before = pair.previous.dmarcPolicy.evidence;
  const after = pair.current.dmarcPolicy.evidence;
  const transitions = deriveDmarcPolicyTransitions(before, after);
  const selectedActions = selectedActionIndexes(transitions);
  const author = canonicalName(after.author_domain || domain);
  const domainMarkerId = await dmarcDomainBaselineRecordId({
    domain_id,
    author_domain: author,
  });
  const common = {
    domain_id,
    author_domain: author,
    before_scan_id: pair.previousRow.scan_id,
    after_scan_id: pair.currentRow.scan_id,
    before_snapshot_id: pair.previousRow.id,
    after_snapshot_id: pair.currentRow.id,
    before_evidence_fingerprint: before.evidence_fingerprint,
    after_evidence_fingerprint: after.evidence_fingerprint,
    methodology_version: after.methodology_version,
  };
  const candidates = [];

  for (let index = 0; index < transitions.length; index += 1) {
    const item = transitions[index];
    const selectedAction = selectedActions.has(index);
    const recordId = await recordIdForTransition(
      domain_id,
      domainMarkerId,
      item,
      selectedAction,
    );
    if (!recordId || !item.subject_key) continue;
    const identity = dmarcLifecycleEventIdentity({
      workspaceId: workspace_id,
      domainId: domain_id,
      methodologyVersion: after.methodology_version,
      subtype: item.subtype,
      subjectKey: item.subject_key,
      beforeSnapshotId: pair.previousRow.id,
      afterSnapshotId: pair.currentRow.id,
      beforeFingerprint: before.evidence_fingerprint,
      afterFingerprint: after.evidence_fingerprint,
    });
    candidates.push({
      id: await deterministicEventId(identity),
      record_id: recordId,
      event_type: selectedAction
        ? "monitoring_changed"
        : item.subtype === "monitoring_degraded"
          ? DMARC_EVENT_MONITORING_DEGRADED
          : DMARC_EVENT_POLICY_TRANSITION,
      created_at: pair.currentRow.assessed_at,
      detail: {
        entity: item.subject_key,
        condition_type:
          selectedAction ? item.actionable_condition_type : null,
        subject_key: item.subject_key,
        subtype: item.subtype,
        predicate: item.predicate,
        customer_wording: item.customer_wording,
        transition_completeness: transitionCompleteness(item.subtype),
        evidence_grade: transitionEvidenceGrade(item.subtype),
        related_changes_eligible: item.related_changes_eligible === true,
        to_recurrence_type:
          selectedAction ? item.recurrence_type : null,
        from_recurrence_type: null,
        from_monitoring_status:
          before.monitoring_state ?? "monitoring_degraded",
        to_monitoring_status:
          after.monitoring_state ?? "monitoring_degraded",
        before: item.before,
        after: item.after,
        destination_uri: item.destination_uri ?? null,
        authorization_status:
          item.after_authorization_status ??
          item.authorization_status ??
          null,
        equal_or_stronger_inheritance:
          item.equal_or_stronger_inheritance ?? null,
        component: item.component ?? null,
        provider_state: item.provider_state ?? null,
        legacy_pct_raw: item.legacy_pct_raw ?? null,
        legacy_pct_applied: item.legacy_pct_applied ?? null,
        ...common,
      },
    });
  }

  // Resolution history is non-occurrence. It is allowed only when both complete
  // resolver outputs can prove that a previously active stable condition is no
  // longer observed.
  if (coreComplete(before) && coreComplete(after)) {
    const previousConditions = deriveDmarcPolicyConditions(before);
    const currentConditions = new Set(
      deriveDmarcPolicyConditions(after).map(conditionKey),
    );
    for (const condition of previousConditions) {
      if (!conditionResolutionComplete(condition.condition_type, before, after)) {
        continue;
      }
      if (currentConditions.has(conditionKey(condition))) continue;
      const recordId = await dmarcPolicyConditionRecordId({
        domain_id,
        condition_type: condition.condition_type,
        subject_key: condition.subject_key,
      });
      if (!recordId) continue;
      const subject = canonicalName(condition.subject_key);
      const identity = dmarcLifecycleEventIdentity({
        workspaceId: workspace_id,
        domainId: domain_id,
        methodologyVersion: after.methodology_version,
        subtype: DMARC_EVENT_CONDITION_CLEARED,
        subjectKey: `${condition.condition_type}|${subject}`,
        beforeSnapshotId: pair.previousRow.id,
        afterSnapshotId: pair.currentRow.id,
        beforeFingerprint: before.evidence_fingerprint,
        afterFingerprint: after.evidence_fingerprint,
      });
      candidates.push({
        id: await deterministicEventId(identity),
        record_id: recordId,
        event_type: DMARC_EVENT_CONDITION_CLEARED,
        created_at: pair.currentRow.assessed_at,
        detail: {
          entity: subject,
          condition_type: condition.condition_type,
          subject_key: subject,
          subtype: DMARC_EVENT_CONDITION_CLEARED,
          predicate: "previous complete condition absent from current complete evidence",
          customer_wording:
            "The previously observed DMARC condition was not present in this complete observation.",
          transition_completeness: "complete",
          evidence_grade: transitionEvidenceGrade(
            DMARC_EVENT_CONDITION_CLEARED,
          ),
          related_changes_eligible: false,
          to_recurrence_type: null,
          before: compactPolicyState(before),
          after: compactPolicyState(after),
          ...common,
        },
      });
    }
  }

  if (candidates.length === 0) {
    return {
      ran: true,
      reason: "no_transition",
      inserted: 0,
      actionable_events: [],
    };
  }
  const statements = candidates.map((candidate) =>
    env.cybermeters_db
      .prepare(
        `INSERT OR IGNORE INTO email_protection_events
          (id, record_id, record_type, workspace_id, actor_type, actor_id,
           event_type, detail_json, created_at)
         VALUES (?, ?, ?, ?, 'system', NULL, ?, ?, ?)`,
      )
      .bind(
        candidate.id,
        candidate.record_id,
        DMARC_POLICY_CONDITION_RECORD_TYPE,
        workspace_id,
        candidate.event_type,
        JSON.stringify(candidate.detail),
        candidate.created_at,
      ),
  );
  const results = await env.cybermeters_db.batch(statements);
  return {
    ran: true,
    reason: "compared",
    inserted: (results || []).reduce(
      (sum, result) => sum + Number(result?.meta?.changes || 0),
      0,
    ),
    candidates: candidates.length,
    // P5 consumes only this bounded descriptor list. emitLifecycleAlert then
    // re-reads the append-only row through the canonical occurrence resolver;
    // no alert trusts this write result as occurrence proof.
    actionable_events: actionableEventDescriptors(candidates),
  };
}
