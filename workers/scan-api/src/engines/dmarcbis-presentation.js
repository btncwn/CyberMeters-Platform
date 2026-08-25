// Item 7 P6 — customer-safe DMARCbis presentation contract.
//
// This is a PURE projection over P3's integrity-checked immutable evidence
// read. It never parses DNS, discovers policy, changes a conclusion, or fills a
// legacy snapshot with current semantics. Renderers consume the strings and
// labels below; they do not independently derive DMARC meaning.
import { deriveDmarcStateFromPolicyEvidence } from "./dmarc-state.js";

export const DMARCBIS_PRESENTATION_SCHEMA =
  "dmarc-policy-presentation.v1";

const POLICY_LABELS = Object.freeze({
  none: "No-action policy",
  quarantine: "Quarantine requested",
  reject: "Rejection requested",
});

const SOURCE_LABELS = Object.freeze({
  exact: "Exact-domain record",
  organisational: "Organisational-domain record",
  psd: "Public-suffix policy record",
  none: "No applicable policy",
  unknown: "Policy source unavailable",
});

const COMPLETENESS_LABELS = Object.freeze({
  complete: "Complete",
  incomplete: "Incomplete",
  unavailable: "Unavailable",
  not_applicable: "Not applicable",
});

const MONITORING_LABELS = Object.freeze({
  monitoring_healthy: "DMARC evidence complete",
  monitoring_degraded: "DMARC monitoring incomplete",
});

const RUA_LABELS = Object.freeze({
  not_required_same_organisational_domain: "Same organisational domain",
  not_required_cybermeters_hosted: "CyberMeters-hosted destination",
  authorized: "Authorised external destination",
  unauthorized: "Unauthorised external destination",
  malformed: "Malformed authorisation record",
  unavailable: "Authorisation unavailable",
  not_assessed_budget: "Authorisation not assessed in this scan",
  not_assessed_limit: "Authorisation not assessed",
  not_assessed_limit_exceeded: "Authorisation not assessed",
  not_assessed_malformed_uri: "Destination URI malformed",
  not_assessed_unsupported_scheme: "Destination scheme not supported",
});

function text(value) {
  return value == null ? null : String(value);
}

function policyTagValue(evidence, tag) {
  const value = evidence?.[tag];
  if (!value || typeof value !== "object") return null;
  return {
    tag,
    present: value.present === true,
    raw: text(value.raw),
    normalized: text(value.normalized),
    valid: value.valid === true,
  };
}

function observationMessage(evidence) {
  const author = evidence?.author_domain || evidence?.submitted_domain || "the domain";
  const qname = `_dmarc.${author}`;
  switch (evidence?.observation_state) {
    case "present_valid":
    case "present_valid_with_defaults":
      return `A DMARC record was observed at ${qname}.`;
    case "present_invalid":
      return "A DMARC-looking record was observed, but its syntax prevents it from being used as a valid policy.";
    case "multiple":
      return "Multiple DMARC policy records were observed at the same DNS name. RFC 9989 does not allow CyberMeters to select one as authoritative.";
    case "absent":
      if (
        evidence?.policy_completeness === "complete" &&
        !evidence?.effective_requested_policy
      ) {
        return "CyberMeters completed the DMARC policy lookup and found no applicable policy.";
      }
      return "No applicable DMARC record was observed at the exact domain.";
    case "resolver_disagreement":
      return "CyberMeters could not determine the current DMARC policy because the resolvers disagreed. This is not a missing-record result.";
    case "incomplete_oversized":
      return "CyberMeters could not determine the current DMARC policy because the DNS response exceeded the supported evidence limit. This is not a missing-record result.";
    case "unavailable":
    default:
      return "CyberMeters could not determine the current DMARC policy because a required DNS lookup was unavailable. This is not a missing-record result.";
  }
}

function testingMessage(evidence) {
  if (evidence?.t?.normalized !== "y") return null;
  const declared = evidence?.declared_policy;
  const effective = evidence?.effective_requested_policy;
  if (declared === "reject" && effective === "quarantine") {
    return "The record declares p=reject with t=y; RFC 9989 makes the effective requested policy quarantine while testing.";
  }
  if (declared === "quarantine" && effective === "none") {
    return "The record declares p=quarantine with t=y; RFC 9989 makes the effective requested policy no action while testing.";
  }
  if (declared === "none" && effective === "none") {
    return "The record declares p=none with t=y; the effective requested policy remains no action.";
  }
  return "The record declares testing mode. The effective requested policy shown here is the result retained in the immutable scan evidence.";
}

function policyMessage(evidence) {
  const policy = evidence?.effective_requested_policy;
  if (!policy) {
    if (evidence?.policy_completeness === "complete") {
      return "No applicable DMARC policy was determined.";
    }
    return "The effective requested policy could not be determined from the available evidence.";
  }
  if (policy === "none") {
    return "The domain publishes a no-action DMARC policy.";
  }
  if (policy === "quarantine") {
    return "The published policy requests quarantine treatment for messages that fail DMARC. Receivers retain final handling discretion.";
  }
  return "The published policy requests rejection of messages that fail DMARC. This does not prove every receiver applied that request.";
}

function inheritanceMessage(evidence) {
  const sourceKind = evidence?.policy_source_kind;
  if (sourceKind === "exact" || sourceKind === "none" || sourceKind === "unknown") {
    return null;
  }
  const source = evidence?.policy_source_domain || "the discovered policy source";
  const tag = evidence?.effective_policy_tag || "p";
  const policy = evidence?.effective_requested_policy || "an undetermined";
  if (evidence?.inheritance_reason?.endsWith("_np")) {
    return `The subdomain did not exist in DNS when checked. The ${sourceKind === "psd" ? "public-suffix" : "organisational"} policy's ${tag}=${policy} preference therefore applied.`;
  }
  return `No applicable record was found at the exact domain. RFC 9989 discovery found a policy at ${source}; its ${tag}=${policy} preference applies.`;
}

function legacyPctMessage(evidence) {
  if (evidence?.legacy_pct?.observed !== true) return null;
  const raw = text(evidence.legacy_pct.raw);
  return `Legacy pct=${raw ?? "unknown"} was observed. RFC 9989 no longer applies this value to the current effective policy.`;
}

function ruaMessage(destination) {
  switch (destination?.authorization_status) {
    case "not_required_same_organisational_domain":
      return "This reporting destination is within the same organisational domain; external authorisation is not required.";
    case "not_required_cybermeters_hosted":
      return "This aggregate-report destination is hosted by CyberMeters, which is authoritative for it, so external DNS authorisation is not required. This does not prove reports were sent, received, or trusted.";
    case "authorized":
      return "The external reporting destination published a valid DMARC authorisation record. This does not prove reports were sent, received, or trusted.";
    case "unauthorized":
      return "CyberMeters found no valid authorisation for this external aggregate-report destination.";
    case "malformed":
      return "A DMARC authorisation record was observed for this destination, but it was malformed and did not provide a positive authorisation.";
    case "not_assessed_unsupported_scheme":
      return "CyberMeters preserved this destination, but its URI scheme is outside the product's supported authorisation checks.";
    case "not_assessed_malformed_uri":
      return "CyberMeters preserved this destination, but its URI could not be assessed safely.";
    case "not_assessed_limit":
    case "not_assessed_limit_exceeded":
      return "External destination authorisation could not be determined because an operational support limit was reached. This is not an RFC-invalidity claim.";
    case "not_assessed_budget":
    case "unavailable":
    default:
      return "External destination authorisation could not be determined for this scan.";
  }
}

function destinationPresentation(destination, index) {
  const status = destination?.authorization_status || "unavailable";
  return {
    destination_index: index,
    uri: text(destination?.uri ?? destination?.raw),
    destination_host: text(destination?.destination_host),
    authorization_status: status,
    status_label: RUA_LABELS[status] || "Authorisation not determined",
    message: ruaMessage(destination),
    lookup_completeness:
      destination?.lookup_completeness ?? "unavailable",
    authorization_record_state:
      destination?.authorization_record_state ?? null,
    trusted_ingestion_status:
      destination?.trusted_ingestion_status ?? null,
    authorized_destination:
      destination?.authorized_destination ?? null,
    evidence_grade: destination?.evidence_grade ?? null,
  };
}

function technicalFacts(evidence) {
  return [
    ["Methodology", evidence?.methodology_version],
    ["Parser", evidence?.parser_version],
    ["Resolver profile", evidence?.resolver_profile],
    ["Observed at", evidence?.observed_at],
    ["Author domain", evidence?.author_domain],
    ["Organisational domain", evidence?.organisational_domain],
    ["Organisational-domain provenance",
      evidence?.organisational_domain_provenance],
    ["Policy source", evidence?.policy_source_domain],
    ["Policy source kind", evidence?.policy_source_kind],
    ["Record validity", evidence?.record_validity],
    ["Domain existence", evidence?.domain_existence],
    ["Declared policy", evidence?.declared_policy],
    ["Effective requested policy", evidence?.effective_requested_policy],
    ["Effective policy tag", evidence?.effective_policy_tag],
    ["Inheritance reason", evidence?.inheritance_reason],
    ["Testing adjustment", evidence?.testing_adjustment],
    ["Core completeness", evidence?.core_completeness],
    ["Policy completeness", evidence?.policy_completeness],
    ["RUA authorisation completeness",
      evidence?.rua_authorisation_completeness],
    ["Provider state", evidence?.provider_state],
    ["Corroboration state", evidence?.corroboration_state],
    ["Evidence fingerprint", evidence?.evidence_fingerprint],
  ]
    .filter(([, value]) => value != null)
    .map(([label, value]) => ({ label, value: text(value) }));
}

function currentPresentation(evidence) {
  const canonicalAssessment = deriveDmarcStateFromPolicyEvidence(evidence);
  const destinations = Array.isArray(
    evidence?.external_rua_authorisation?.destinations,
  )
    ? evidence.external_rua_authorisation.destinations
    : (Array.isArray(evidence?.rua_destinations)
      ? evidence.rua_destinations
      : []);
  const effective = evidence?.effective_requested_policy ?? null;
  const observation = observationMessage(evidence);
  const policy = policyMessage(evidence);
  const inherited = inheritanceMessage(evidence);
  const testing = testingMessage(evidence);
  const pct = legacyPctMessage(evidence);
  const completeness = evidence?.core_completeness || "unavailable";
  const monitoring = evidence?.monitoring_state || "monitoring_degraded";

  return {
    schema: DMARCBIS_PRESENTATION_SCHEMA,
    status: "current",
    canonical_assessment: canonicalAssessment,
    headline: effective
      ? `DMARC requested policy: ${POLICY_LABELS[effective] || effective}`
      : "DMARC policy not determined",
    customer_message: observation,
    observation: {
      state: evidence?.observation_state ?? "unavailable",
      validity: evidence?.record_validity ?? "indeterminate",
      label: evidence?.record_validity === "valid" ||
        evidence?.record_validity === "valid_with_defaults"
        ? "Observed DMARC record"
        : "DMARC record observation",
      message: observation,
      dns_name: evidence?.author_domain
        ? `_dmarc.${evidence.author_domain}`
        : null,
    },
    policy: {
      declared: evidence?.declared_policy ?? null,
      effective_requested: effective,
      effective_requested_label:
        effective ? (POLICY_LABELS[effective] || effective) : "Not determined",
      effective_tag: evidence?.effective_policy_tag ?? null,
      source_domain: evidence?.policy_source_domain ?? null,
      source_kind: evidence?.policy_source_kind ?? "unknown",
      source_label:
        SOURCE_LABELS[evidence?.policy_source_kind] ||
        SOURCE_LABELS.unknown,
      inheritance_reason: evidence?.inheritance_reason ?? "unknown",
      message: policy,
      inheritance_message: inherited,
      testing_adjustment: evidence?.testing_adjustment ?? null,
      testing_message: testing,
      p: policyTagValue(evidence, "p"),
      sp: policyTagValue(evidence, "sp"),
      np: policyTagValue(evidence, "np"),
      t: policyTagValue(evidence, "t"),
      psd: policyTagValue(evidence, "psd"),
      receiver_enforcement_observed: false,
    },
    organisational_domain: {
      value: evidence?.organisational_domain ?? null,
      provenance:
        evidence?.organisational_domain_provenance ?? "unresolved",
      completeness:
        evidence?.organisational_domain_completeness ?? "unavailable",
    },
    legacy_pct: {
      observed: evidence?.legacy_pct?.observed === true,
      raw: text(evidence?.legacy_pct?.raw),
      applied_to_effective_policy: false,
      message: pct,
    },
    external_rua: {
      completeness:
        evidence?.rua_authorisation_completeness ?? "unavailable",
      completeness_label:
        COMPLETENESS_LABELS[evidence?.rua_authorisation_completeness] ||
        "Unavailable",
      all_destinations_authorized:
        evidence?.external_rua_authorisation
          ?.all_destinations_authorized ?? null,
      destinations: destinations.map(destinationPresentation),
    },
    completeness: {
      core: completeness,
      core_label: COMPLETENESS_LABELS[completeness] || "Unavailable",
      policy: evidence?.policy_completeness ?? "unavailable",
      organisational_domain:
        evidence?.organisational_domain_completeness ?? "unavailable",
      existence: evidence?.existence_completeness ?? "unavailable",
      external_rua:
        evidence?.rua_authorisation_completeness ?? "unavailable",
    },
    monitoring: {
      state: monitoring,
      label:
        MONITORING_LABELS[monitoring] ||
        MONITORING_LABELS.monitoring_degraded,
      message: monitoring === "monitoring_healthy"
        ? "The DMARC policy evidence required for this conclusion was complete when the scan ran."
        : "DMARC monitoring was incomplete for this scan. CyberMeters has not inferred a configuration change from the incomplete result.",
    },
    evidence_grade: evidence?.evidence_grade ?? null,
    limits: Array.isArray(evidence?.evidence_grade?.limits)
      ? evidence.evidence_grade.limits
      : [],
    methodology_version: evidence?.methodology_version ?? null,
    technical_appendix: {
      facts: technicalFacts(evidence),
      lookup_path: Array.isArray(evidence?.lookup_path)
        ? evidence.lookup_path
        : [],
      raw_records: Array.isArray(evidence?.raw_records)
        ? evidence.raw_records
        : [],
      parsed_tags: Array.isArray(evidence?.parsed_tags)
        ? evidence.parsed_tags
        : [],
    },
  };
}

export function buildDmarcPolicyPresentation(read) {
  if (read?.status === "current" && read?.evidence) {
    return currentPresentation(read.evidence);
  }
  if (read?.status === "legacy_snapshot") {
    return {
      schema: DMARCBIS_PRESENTATION_SCHEMA,
      status: "legacy_snapshot",
      headline: "Historical DMARC methodology",
      customer_message:
        read.notice ||
        "This report preserves the DMARC methodology and conclusions used when the scan completed.",
      historical_notice:
        read.notice ||
        "This report preserves the DMARC methodology and conclusions used when the scan completed.",
      evidence_grade: null,
      technical_appendix: null,
    };
  }
  return {
    schema: DMARCBIS_PRESENTATION_SCHEMA,
    status: read?.status || "not_available",
    headline: "DMARC evidence unavailable",
    customer_message:
      "CyberMeters could not display the current DMARC policy conclusion because the stored evidence was unavailable or did not pass its integrity contract. This is not a healthy or missing-record result.",
    unavailable_reason: read?.reason ?? null,
    evidence_grade: null,
    technical_appendix: null,
  };
}
