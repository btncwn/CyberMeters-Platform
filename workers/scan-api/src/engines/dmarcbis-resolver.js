// Pure DMARCbis discovery and derivation with an injected DNS interface.
//
// P1 intentionally has no production caller and performs no fetch. Callers pass
// either an async function(question) or { query(question) }. P2 will supply the
// shared-cache, deadline, accounting, and provider adapter.
import {
  DMARCBIS_MAX_EXTERNAL_HOSTS,
  DMARCBIS_MAX_REPORT_URIS,
  DMARCBIS_PARSER_VERSION,
  parseDmarcbisAuthorizationRecordSet,
  parseDmarcbisPolicyRecordSet,
} from "./dmarcbis-parser.js";
import { RUA_INBOUND_DOMAIN_DEFAULT } from "../lib/dmarc-ingest.js";

// A DMARC aggregate-report destination under our own hosted RUA endpoint
// (reports.cybermeters.com) is a domain CyberMeters is authoritative for, so
// external RFC 9990 authorisation is derivable by us and never "unavailable".
// Matches ONLY the hosted RUA domain and its subdomains — NOT the wider
// organisational domain (a customer rua at cybermeters.com is not our hosted
// endpoint). Mirrors the same-org derivation proven in rua-routing.js.
function isCybermetersHostedDestination(destinationHost, hostedDomain) {
  if (!destinationHost || !hostedDomain) return false;
  const host = String(destinationHost).trim().toLowerCase().replace(/\.$/, "");
  const hosted = String(hostedDomain).trim().toLowerCase().replace(/\.$/, "");
  if (!host || !hosted) return false;
  return host === hosted || host.endsWith(`.${hosted}`);
}
import {
  DMARCBIS_IDNA_PROFILE,
  canonicalizeDmarcbisDomain,
  constructDmarcPolicyName,
  constructExternalRuaAuthorizationName,
} from "./dmarcbis-idna.js";

export const DMARCBIS_METHODOLOGY_VERSION = "rfc9989-treewalk-v1";
export const DMARCBIS_MAX_TREE_QUESTIONS = 8;

const DEFINITIVE_DNS_OUTCOMES = new Set(["success", "nodata", "nxdomain"]);
const TEMPORARY_DNS_OUTCOMES = new Set([
  "servfail",
  "refused",
  "timeout",
  "transport_error",
  "malformed_response",
  "truncated_unresolved",
  "cancelled_deadline",
  "not_issued_budget",
]);

function txtRecordsFromObservation(raw) {
  if (Array.isArray(raw?.txt_records)) return raw.txt_records;
  const answers = Array.isArray(raw?.answers)
    ? raw.answers
    : Array.isArray(raw?.Answer)
      ? raw.Answer
      : [];
  return answers
    .filter((answer) => {
      const type = answer?.type ?? answer?.Type;
      return type == null || type === 16 || String(type).toUpperCase() === "TXT";
    })
    .map((answer) => {
      if (Array.isArray(answer?.chunks)) return answer;
      if (typeof answer?.value === "string") return answer;
      return { data: answer?.data ?? answer?.Data ?? "" };
    });
}

export function normalizeDmarcbisDnsObservation(raw, question = {}) {
  if (!raw || typeof raw !== "object") {
    return {
      question,
      outcome: "malformed_response",
      definitive: false,
      txt_records: null,
      raw,
    };
  }

  const hasRecordContainer =
    Array.isArray(raw.txt_records) ||
    Array.isArray(raw.answers) ||
    Array.isArray(raw.Answer);
  let outcome = String(raw.outcome || "").toLowerCase();
  if (!outcome && Number.isFinite(Number(raw.Status))) {
    const status = Number(raw.Status);
    if (status === 3) outcome = "nxdomain";
    else if (status === 2) outcome = "servfail";
    else if (status === 5) outcome = "refused";
    else if (status === 0) {
      const answers = Array.isArray(raw.Answer) ? raw.Answer : [];
      outcome = answers.length ? "success" : "nodata";
    } else outcome = "malformed_response";
  }
  if (!outcome) {
    if (hasRecordContainer) {
      const records = txtRecordsFromObservation(raw);
      outcome = records.length ? "success" : "nodata";
    } else {
      outcome = "malformed_response";
    }
  }
  if (outcome === "success" && !hasRecordContainer) outcome = "malformed_response";
  const truncated = raw.truncated === true || raw.TC === true;
  if (truncated) outcome = "truncated_unresolved";
  if (!DEFINITIVE_DNS_OUTCOMES.has(outcome) && !TEMPORARY_DNS_OUTCOMES.has(outcome)) {
    outcome = "malformed_response";
  }

  return {
    question,
    outcome,
    definitive: DEFINITIVE_DNS_OUTCOMES.has(outcome),
    rcode: raw.rcode ?? raw.Status ?? null,
    txt_records: outcome === "success" ? txtRecordsFromObservation(raw) : [],
    answers: Array.isArray(raw.answers)
      ? raw.answers
      : Array.isArray(raw.Answer)
        ? raw.Answer
        : [],
    ttl: raw.ttl ?? null,
    negative_ttl: raw.negative_ttl ?? null,
    truncated,
    elapsed_ms: raw.elapsed_ms ?? null,
    cache_disposition: raw.cache_disposition ?? null,
    raw,
  };
}

async function injectedQuery(dns, question) {
  try {
    const raw = typeof dns === "function"
      ? await dns(question)
      : await dns?.query?.(question);
    return normalizeDmarcbisDnsObservation(raw, question);
  } catch (error) {
    return {
      question,
      outcome: error?.name === "TimeoutError" ? "timeout" : "transport_error",
      definitive: false,
      rcode: null,
      txt_records: null,
      answers: [],
      ttl: null,
      negative_ttl: null,
      truncated: false,
      elapsed_ms: null,
      cache_disposition: null,
      error: String(error?.message || error),
      raw: null,
    };
  }
}

export function planDmarcbisTreeWalk(domain) {
  const canonical = typeof domain === "object" && domain?.alabel
    ? domain
    : canonicalizeDmarcbisDomain(domain);
  if (!canonical.ok) {
    return { ok: false, domain: canonical, questions: [], error: canonical.error };
  }
  const initialLabels = canonical.alabel.split(".");
  let labels = [...initialLabels];
  const questions = [];

  while (labels.length && questions.length < DMARCBIS_MAX_TREE_QUESTIONS) {
    const target = labels.join(".");
    const qname = constructDmarcPolicyName(target);
    if (!qname.ok) {
      return { ok: false, domain: canonical, questions, error: qname.error };
    }
    questions.push({
      ordinal: questions.length + 1,
      target_domain: target,
      name: qname.name,
      type: "TXT",
    });
    if (questions.length === 1 && labels.length >= DMARCBIS_MAX_TREE_QUESTIONS) {
      labels = labels.slice(-7);
    } else {
      labels = labels.slice(1);
    }
  }

  return { ok: true, domain: canonical, questions, error: null };
}

function recordSetFingerprint(recordSet) {
  return [...(recordSet?.candidates || [])]
    .map((record) => record.value)
    .sort()
    .join("\u0000");
}

function sourceEntryAt(entries, domain) {
  return entries.find((entry) => entry.target_domain === domain) || null;
}

function domainOneLabelBelow(authorDomain, ancestorDomain) {
  const authorLabels = authorDomain.split(".");
  const ancestorLabels = ancestorDomain.split(".");
  if (authorLabels.length <= ancestorLabels.length) return null;
  return authorLabels.slice(-(ancestorLabels.length + 1)).join(".");
}

export function deriveDmarcbisOrganizationalDomain({
  authorDomain,
  validEntries,
  walkComplete,
}) {
  if (!walkComplete) {
    return {
      organisational_domain: null,
      provenance: "unresolved",
      decisive_entry: null,
    };
  }
  for (const entry of validEntries) {
    const psd = entry.record.psd?.normalized;
    if (entry.record.psd?.validity === "valid" && psd === "n") {
      return {
        organisational_domain: entry.target_domain,
        provenance: "psd_n",
        decisive_entry: entry,
      };
    }
    if (entry.ordinal > 1 && entry.record.psd?.validity === "valid" && psd === "y") {
      return {
        organisational_domain: domainOneLabelBelow(authorDomain, entry.target_domain),
        provenance: "below_psd_y",
        decisive_entry: entry,
      };
    }
  }
  if (validEntries.length) {
    const decisive = validEntries[validEntries.length - 1];
    return {
      organisational_domain: decisive.target_domain,
      provenance: "highest_valid_record",
      decisive_entry: decisive,
    };
  }
  return {
    organisational_domain: authorDomain,
    provenance: "fallback_initial_target",
    decisive_entry: null,
  };
}

async function performPrimaryWalk({ domain, dns, resolver = "primary", purpose = "policy_tree_walk" }) {
  const plan = planDmarcbisTreeWalk(domain);
  if (!plan.ok) {
    return {
      plan,
      path: [],
      valid_entries: [],
      walk_complete: false,
      stop_reason: "invalid_name",
      first_failure: plan.error,
    };
  }
  const observations = await Promise.all(plan.questions.map((question) =>
    injectedQuery(dns, {
      ...question,
      resolver,
      purpose,
      dnssec_profile: "default",
    })));

  const path = [];
  const validEntries = [];
  let walkComplete = true;
  let stopReason = "labels_exhausted";
  let logicalStopped = false;
  let firstFailure = null;

  for (let index = 0; index < observations.length; index += 1) {
    const observation = observations[index];
    if (logicalStopped) {
      path.push({
        ...observation,
        logically_used: false,
        disposition: "prefetched_not_logically_required",
        record_set: null,
      });
      continue;
    }
    if (!observation.definitive) {
      walkComplete = false;
      firstFailure = observation.outcome;
      stopReason = "required_dns_unavailable";
      logicalStopped = true;
      path.push({
        ...observation,
        logically_used: true,
        disposition: "required_unavailable",
        record_set: null,
      });
      continue;
    }

    const recordSet = parseDmarcbisPolicyRecordSet(observation.txt_records);
    path.push({
      ...observation,
      logically_used: true,
      disposition: "evaluated",
      record_set: recordSet,
    });
    if (!recordSet.complete) {
      walkComplete = false;
      firstFailure = recordSet.raw_state;
      stopReason = "record_set_incomplete";
      logicalStopped = true;
      continue;
    }
    if (recordSet.selected) {
      validEntries.push({
        ordinal: index + 1,
        target_domain: plan.questions[index].target_domain,
        qname: plan.questions[index].name,
        record: recordSet.selected,
        record_set: recordSet,
      });
    }

    const soleCandidate = recordSet.candidates.length === 1
      ? recordSet.candidates[0]
      : null;
    // RFC 9989 §4.10.1 treats the exact-domain lookup specially: when it
    // yields no usable policy record, the Tree Walk starts at the parent.
    // Therefore, an unusable exact candidate cannot terminate discovery with
    // its psd tag. At later Tree Walk targets, §4.10 step 6 applies directly.
    const stopEligible = index > 0 || Boolean(recordSet.selected);
    if (
      stopEligible &&
      soleCandidate?.psd?.validity === "valid" &&
      ["y", "n"].includes(soleCandidate.psd.normalized)
    ) {
      logicalStopped = true;
      stopReason = `psd_${soleCandidate.psd.normalized}`;
    }
  }

  return {
    plan,
    path,
    valid_entries: validEntries,
    walk_complete: walkComplete,
    stop_reason: stopReason,
    first_failure: firstFailure,
  };
}

async function corroborateRecordSet({ dns, name, primaryRecordSet, purpose }) {
  if (!name || !primaryRecordSet) {
    return { state: "not_applicable", observation: null, record_set: null };
  }
  const observation = await injectedQuery(dns, {
    name,
    type: "TXT",
    resolver: "secondary",
    purpose,
    dnssec_profile: "default",
  });
  if (!observation.definitive) {
    return { state: "unavailable", observation, record_set: null };
  }
  const secondarySet = parseDmarcbisPolicyRecordSet(observation.txt_records);
  if (!secondarySet.complete) {
    return { state: "unavailable", observation, record_set: secondarySet };
  }
  return {
    state: recordSetFingerprint(primaryRecordSet) === recordSetFingerprint(secondarySet)
      ? "corroborated"
      : "resolver_disagreement",
    observation,
    record_set: secondarySet,
  };
}

function selectPolicySource({ authorDomain, organisationalDomain, validEntries }) {
  const exact = sourceEntryAt(validEntries, authorDomain);
  if (exact) return { entry: exact, kind: "exact" };
  if (!organisationalDomain) return { entry: null, kind: "unknown" };
  const organisational = sourceEntryAt(validEntries, organisationalDomain);
  if (organisational) return { entry: organisational, kind: "organisational" };
  const psd = validEntries.find((entry) =>
    entry.record.psd?.normalized === "y" &&
    domainOneLabelBelow(authorDomain, entry.target_domain) === organisationalDomain);
  if (psd) return { entry: psd, kind: "psd" };
  return { entry: null, kind: "none" };
}

function exactObservationState(exactPath) {
  if (!exactPath || !exactPath.definitive) {
    return { observation_state: "unavailable", record_validity: "indeterminate" };
  }
  const state = exactPath.record_set?.raw_state;
  if (["multiple", "multiple_mixed", "multiple_invalid"].includes(state)) {
    return { observation_state: "multiple", record_validity: "invalid" };
  }
  if (state === "incomplete_oversized") {
    return { observation_state: "incomplete_oversized", record_validity: "indeterminate" };
  }
  if (["single_invalid", "single_invalid_duplicate_tag"].includes(state)) {
    return { observation_state: "present_invalid", record_validity: "invalid" };
  }
  if (state === "single_valid_with_defaults") {
    return { observation_state: "present_valid_with_defaults", record_validity: "valid_with_defaults" };
  }
  if (["single_valid", "single_valid_with_non_dmarc_txt"].includes(state)) {
    return { observation_state: "present_valid", record_validity: "valid" };
  }
  return { observation_state: "absent", record_validity: "not_applicable" };
}

function effectiveAfterTesting(declaredPolicy, testing) {
  if (testing !== "y" || declaredPolicy === "none") {
    return {
      effective_requested_policy: declaredPolicy,
      testing_adjustment: testing === "y" ? "no_effect_on_none" : "none",
    };
  }
  return {
    effective_requested_policy: declaredPolicy === "reject" ? "quarantine" : "none",
    testing_adjustment: "one_level_below",
  };
}

async function determineExistence({ authorDomain, dns, required }) {
  if (!required) {
    return {
      state: "not_required",
      completeness: "not_applicable",
      observation: null,
    };
  }
  const observation = await injectedQuery(dns, {
    name: authorDomain,
    type: "A",
    resolver: "primary",
    purpose: "author_domain_existence",
    dnssec_profile: "default",
  });
  if (observation.outcome === "nxdomain") {
    return { state: "nonexistent", completeness: "complete", observation };
  }
  if (observation.outcome === "nodata" || observation.outcome === "success") {
    return { state: "exists", completeness: "complete", observation };
  }
  return { state: "unknown", completeness: "unavailable", observation };
}

function derivePolicy({ source, existence }) {
  if (!source.entry) {
    return {
      declared_policy: null,
      effective_requested_policy: null,
      effective_policy_tag: null,
      inheritance_reason: source.kind === "none" ? "none" : "unknown",
      testing_adjustment: "not_applicable",
    };
  }
  const record = source.entry.record;
  if (record.policy_mode === "invalid_policy_fallback_none") {
    const tested = effectiveAfterTesting("none", record.t.normalized);
    return {
      declared_policy: "none",
      ...tested,
      effective_policy_tag: "p",
      inheritance_reason: "invalid_policy_fallback_none",
    };
  }

  let declaredPolicy;
  let tag;
  if (source.kind === "exact") {
    declaredPolicy = record.p.normalized;
    tag = "p";
  } else if (existence.state === "unknown") {
    return {
      declared_policy: null,
      effective_requested_policy: null,
      effective_policy_tag: null,
      inheritance_reason: "unknown",
      testing_adjustment: "unknown",
    };
  } else if (existence.state === "nonexistent" && record.np.present) {
    declaredPolicy = record.np.normalized;
    tag = "np";
  } else if (record.sp.present) {
    declaredPolicy = record.sp.normalized;
    tag = "sp";
  } else {
    declaredPolicy = record.p.normalized;
    tag = "p";
  }

  const prefix = source.kind === "psd" ? "psd" : "organisational";
  const inheritanceReason = source.kind === "exact"
    ? "exact_p"
    : `${prefix}_${tag}`;
  return {
    declared_policy: declaredPolicy,
    ...effectiveAfterTesting(declaredPolicy, record.t.normalized),
    effective_policy_tag: tag,
    inheritance_reason: inheritanceReason,
  };
}

export async function resolveDmarcbisPolicy({
  authorDomain,
  dns,
  primaryResolver = "primary",
}) {
  const canonical = canonicalizeDmarcbisDomain(authorDomain);
  if (!canonical.ok) {
    return {
      schema: "dmarc-policy.v2",
      methodology_version: DMARCBIS_METHODOLOGY_VERSION,
      parser_version: DMARCBIS_PARSER_VERSION,
      resolver_profile: "primary-plus-decisive-corroboration-v1",
      idna_profile: DMARCBIS_IDNA_PROFILE,
      author_domain: null,
      submitted_domain: authorDomain == null ? "" : String(authorDomain),
      observation_state: "unavailable",
      record_validity: "indeterminate",
      policy_completeness: "unavailable",
      organisational_domain_completeness: "unavailable",
      effective_requested_policy: null,
      error: canonical.error,
      lookup_path: [],
    };
  }

  const walk = await performPrimaryWalk({
    domain: canonical,
    dns,
    resolver: primaryResolver,
    purpose: "policy_tree_walk",
  });
  const organisation = deriveDmarcbisOrganizationalDomain({
    authorDomain: canonical.alabel,
    validEntries: walk.valid_entries,
    walkComplete: walk.walk_complete,
  });
  const source = selectPolicySource({
    authorDomain: canonical.alabel,
    organisationalDomain: organisation.organisational_domain,
    validEntries: walk.valid_entries,
  });
  const inherited = source.entry && source.kind !== "exact";
  const existenceRequired = Boolean(
    inherited &&
    source.entry.record.policy_mode === "normal" &&
    source.entry.record.np.present,
  );
  const existence = await determineExistence({
    authorDomain: canonical.alabel,
    dns,
    required: existenceRequired,
  });
  const derived = derivePolicy({
    source,
    existence,
  });
  const corroboration = await corroborateRecordSet({
    dns,
    name: source.entry?.qname,
    primaryRecordSet: source.entry?.record_set,
    purpose: "decisive_policy_corroboration",
  });

  const exactPath = walk.path.find((entry) => entry.question?.ordinal === 1) || null;
  const exactState = exactObservationState(exactPath);
  const disagreement = corroboration.state === "resolver_disagreement";
  const policyUnavailable =
    !walk.walk_complete && source.kind !== "exact" ||
    existence.state === "unknown" ||
    disagreement;
  const policyCompleteness = policyUnavailable
    ? "unavailable"
    : corroboration.state === "unavailable"
      ? "incomplete"
      : "complete";
  const noPolicy = source.kind === "none" && walk.walk_complete;
  const parsedListsComplete = Boolean(source.entry) || noPolicy;
  const policy = disagreement || policyUnavailable
    ? {
      ...derived,
      declared_policy: null,
      effective_requested_policy: null,
      effective_policy_tag: null,
      inheritance_reason: "unknown",
    }
    : derived;

  return {
    schema: "dmarc-policy.v2",
    methodology_version: DMARCBIS_METHODOLOGY_VERSION,
    parser_version: DMARCBIS_PARSER_VERSION,
    resolver_profile: "primary-plus-decisive-corroboration-v1",
    idna_profile: DMARCBIS_IDNA_PROFILE,
    author_domain: canonical.alabel,
    submitted_domain: canonical.submitted,
    ...exactState,
    raw_records: exactPath?.definitive
      ? (exactPath.record_set?.parsed_records || [])
      : null,
    parsed_tags: exactPath?.definitive
      ? (exactPath.record_set?.parsed_records?.flatMap((record) => record.tags) || [])
      : null,
    lookup_path: [
      ...walk.path,
      ...(existence.observation ? [{ ...existence.observation, logically_used: true }] : []),
      ...(corroboration.observation
        ? [{ ...corroboration.observation, logically_used: true, corroborating: true }]
        : []),
    ],
    tree_walk: {
      planned_questions: walk.plan.questions,
      stop_reason: walk.stop_reason,
      complete: walk.walk_complete,
      first_failure: walk.first_failure,
    },
    organisational_domain: organisation.organisational_domain,
    organisational_domain_provenance: organisation.provenance,
    organisational_domain_completeness: walk.walk_complete ? "complete" : "unavailable",
    policy_source_domain: source.entry?.target_domain || null,
    policy_source_kind: source.kind,
    source_record: source.entry?.record || null,
    domain_existence: existence.state,
    existence_completeness: existence.completeness,
    ...policy,
    p: source.entry?.record?.p || null,
    sp: source.entry?.record?.sp || null,
    np: source.entry?.record?.np || null,
    t: source.entry?.record?.t || null,
    psd: source.entry?.record?.psd || null,
    legacy_pct: source.entry?.record?.legacy_pct || {
      observed: false,
      raw: null,
      numeric: null,
      semantics: "rfc7489_legacy",
      applied_to_effective_policy: false,
    },
    rua_destinations: parsedListsComplete ? (source.entry?.record?.rua || []) : null,
    ruf_destinations: parsedListsComplete ? (source.entry?.record?.ruf || []) : null,
    policy_completeness: noPolicy ? "complete" : policyCompleteness,
    corroboration_state: corroboration.state,
    monitoring_state: policyCompleteness === "complete"
      ? "monitoring_healthy"
      : "monitoring_degraded",
    provider_state: walk.walk_complete
      ? corroboration.state === "resolver_disagreement"
        ? "resolver_disagreement"
        : corroboration.state === "unavailable"
          ? "corroboration_unavailable"
          : "available"
      : walk.first_failure || "unavailable",
    receiver_enforcement_observed: false,
    limits: {
      maximum_tree_questions: DMARCBIS_MAX_TREE_QUESTIONS,
      planned_tree_questions: walk.plan.questions.length,
      issued_tree_questions: walk.path.length,
      existence_questions: existence.observation ? 1 : 0,
      corroboration_questions: corroboration.observation ? 1 : 0,
    },
  };
}

async function resolveDestinationOrganisation({ destinationHost, dns }) {
  const walk = await performPrimaryWalk({
    domain: destinationHost,
    dns,
    resolver: "primary",
    purpose: "rua_destination_tree_walk",
  });
  const organisation = deriveDmarcbisOrganizationalDomain({
    authorDomain: destinationHost,
    validEntries: walk.valid_entries,
    walkComplete: walk.walk_complete,
  });
  const decisive = organisation.decisive_entry;
  const corroboration = await corroborateRecordSet({
    dns,
    name: decisive?.qname,
    primaryRecordSet: decisive?.record_set,
    purpose: "rua_destination_decisive_corroboration",
  });
  const complete =
    walk.walk_complete &&
    !["unavailable", "resolver_disagreement"].includes(corroboration.state);
  return { walk, organisation, corroboration, complete };
}

function authorizationSetFingerprint(set) {
  return [...(set?.current_records || [])]
    .map((record) => record.value)
    .sort()
    .join("\u0000");
}

function reuseHostAssessment(uri, assessment) {
  const reused = {
    ...uri,
    ...assessment,
    index: uri.index,
    raw: uri.raw,
    normalized_uri: uri.normalized_uri,
    scheme: uri.scheme,
    supported_scheme: uri.supported_scheme,
    uri_parse_status: uri.uri_parse_status,
    syntax_valid: uri.syntax_valid,
    destination_host: uri.destination_host,
    destination_host_raw: uri.destination_host_raw,
    obsolete_size: uri.obsolete_size,
    over_product_limit: uri.over_product_limit,
    limits: [
      ...(uri.limits || []),
      ...(assessment.limits || []),
    ],
    reused_host_assessment: true,
  };
  if (
    assessment.authorization_status === "not_required_same_organisational_domain" ||
    assessment.override_status === "not_present"
  ) {
    reused.authorized_destination = uri.normalized_uri;
  }
  return reused;
}

function evaluateAuthorizationOverride(set, originalUri, destinationHost) {
  const overrides = set.valid_records.flatMap((record) => record.rua || []);
  const supported = overrides.filter(
    (entry) => entry.syntax_valid && entry.supported_scheme && !entry.over_product_limit,
  );
  if (!supported.length) {
    return {
      override_status: "not_present",
      authorized_destination: originalUri.normalized_uri,
      destination_usability: "usable",
    };
  }
  if (supported.some((entry) => entry.destination_host !== destinationHost)) {
    return {
      override_status: "prohibited_second_hop",
      authorized_destination: null,
      destination_usability: "prohibited_second_hop",
    };
  }
  const unique = [...new Set(supported.map((entry) => entry.normalized_uri))];
  if (unique.length !== 1) {
    return {
      override_status: "conflicting_same_host",
      authorized_destination: null,
      destination_usability: "unresolved_override_conflict",
    };
  }
  return {
    override_status: "same_host_override",
    authorized_destination: unique[0],
    destination_usability: "usable",
  };
}

async function resolveOneExternalHost({
  uri,
  policySourceDomain,
  policySourceOrganisationalDomain,
  dns,
  hostedRuaDomain = RUA_INBOUND_DOMAIN_DEFAULT,
}) {
  // CyberMeters-hosted destination: we are authoritative for this endpoint, so
  // external DNS authorisation is not required and never "unavailable". Resolve
  // it positively WITHOUT a live lookup, before any DNS timeout/servfail path.
  if (isCybermetersHostedDestination(uri.destination_host, hostedRuaDomain)) {
    return {
      authorization_status: "not_required_cybermeters_hosted",
      authorization_record_state: "not_required_hosted",
      lookup_completeness: "complete",
      same_organisational_domain: false,
      destination_organisation: null,
      authorization_query_name: null,
      authorized_destination: uri.normalized_uri,
      destination_usability: "usable",
      trusted_ingestion_status: "observational_item5_gate_required",
    };
  }
  const destination = await resolveDestinationOrganisation({
    destinationHost: uri.destination_host,
    dns,
  });
  if (!destination.complete || !destination.organisation.organisational_domain) {
    return {
      authorization_status: "unavailable",
      authorization_record_state:
        destination.corroboration.state === "resolver_disagreement"
          ? "resolver_disagreement"
          : "unavailable",
      lookup_completeness: "incomplete",
      same_organisational_domain: null,
      destination_organisation: destination,
      authorization_query_name: null,
      authorized_destination: null,
      trusted_ingestion_status: "observational_item5_gate_required",
    };
  }
  const same =
    destination.organisation.organisational_domain === policySourceOrganisationalDomain;
  if (same) {
    return {
      authorization_status: "not_required_same_organisational_domain",
      authorization_record_state: "absent",
      lookup_completeness: "complete",
      same_organisational_domain: true,
      destination_organisation: destination,
      authorization_query_name: null,
      authorized_destination: uri.normalized_uri,
      destination_usability: "usable",
      trusted_ingestion_status: "observational_item5_gate_required",
    };
  }

  const queryName = constructExternalRuaAuthorizationName(
    policySourceDomain,
    uri.destination_host,
  );
  if (!queryName.ok) {
    return {
      authorization_status: "unavailable",
      authorization_record_state: "name_too_long",
      lookup_completeness: "incomplete",
      same_organisational_domain: false,
      destination_organisation: destination,
      authorization_query_name: null,
      authorized_destination: null,
      trusted_ingestion_status: "observational_item5_gate_required",
      limits: [{ type: "dns_name", reason: queryName.error }],
    };
  }

  const [primary, secondary] = await Promise.all([
    injectedQuery(dns, {
      name: queryName.name,
      type: "TXT",
      resolver: "primary",
      purpose: "external_rua_authorization",
      dnssec_profile: "default",
    }),
    injectedQuery(dns, {
      name: queryName.name,
      type: "TXT",
      resolver: "secondary",
      purpose: "external_rua_authorization_corroboration",
      dnssec_profile: "default",
    }),
  ]);
  if (!primary.definitive || !secondary.definitive) {
    return {
      authorization_status: "unavailable",
      authorization_record_state:
        primary.outcome === "timeout" || secondary.outcome === "timeout"
          ? "timeout"
          : "unavailable",
      lookup_completeness: "incomplete",
      same_organisational_domain: false,
      destination_organisation: destination,
      authorization_query_name: queryName.name,
      authorization_observations: { primary, secondary },
      authorized_destination: null,
      trusted_ingestion_status: "observational_item5_gate_required",
    };
  }

  const primarySet = parseDmarcbisAuthorizationRecordSet(primary.txt_records);
  const secondarySet = parseDmarcbisAuthorizationRecordSet(secondary.txt_records);
  if (!primarySet.complete || !secondarySet.complete) {
    return {
      authorization_status: "unavailable",
      authorization_record_state: "incomplete_oversized",
      lookup_completeness: "incomplete",
      same_organisational_domain: false,
      destination_organisation: destination,
      authorization_query_name: queryName.name,
      authorization_observations: { primary, secondary },
      authorization_record_sets: { primary: primarySet, secondary: secondarySet },
      authorized_destination: null,
      trusted_ingestion_status: "observational_item5_gate_required",
    };
  }
  if (authorizationSetFingerprint(primarySet) !== authorizationSetFingerprint(secondarySet)) {
    return {
      authorization_status: "unavailable",
      authorization_record_state: "resolver_disagreement",
      lookup_completeness: "incomplete",
      same_organisational_domain: false,
      destination_organisation: destination,
      authorization_query_name: queryName.name,
      authorization_observations: { primary, secondary },
      authorization_record_sets: { primary: primarySet, secondary: secondarySet },
      authorized_destination: null,
      trusted_ingestion_status: "observational_item5_gate_required",
    };
  }

  if (!primarySet.authorized) {
    return {
      authorization_status: primarySet.record_state === "malformed" ? "malformed" : "unauthorized",
      authorization_record_state: primarySet.record_state,
      lookup_completeness: "complete",
      same_organisational_domain: false,
      destination_organisation: destination,
      authorization_query_name: queryName.name,
      authorization_observations: { primary, secondary },
      authorization_record_sets: { primary: primarySet, secondary: secondarySet },
      authorized_destination: null,
      trusted_ingestion_status: "not_authoritative",
    };
  }

  const override = evaluateAuthorizationOverride(primarySet, uri, uri.destination_host);
  return {
    authorization_status: "authorized",
    authorization_record_state: primarySet.record_state,
    lookup_completeness: "complete",
    same_organisational_domain: false,
    destination_organisation: destination,
    authorization_query_name: queryName.name,
    authorization_observations: { primary, secondary },
    authorization_record_sets: { primary: primarySet, secondary: secondarySet },
    ...override,
    trusted_ingestion_status: "observational_item5_gate_required",
  };
}

function unassessedUri(uri, status, recordState, reason) {
  return {
    ...uri,
    authorization_status: status,
    authorization_record_state: recordState,
    lookup_completeness: "incomplete",
    same_organisational_domain: null,
    authorization_query_name: null,
    authorized_destination: null,
    trusted_ingestion_status: "observational_item5_gate_required",
    assessment_reason: reason,
  };
}

export async function resolveDmarcbisExternalRuaAuthorizations({
  policyEvidence,
  dns,
  reserveHost = () => true,
  hostedRuaDomain = RUA_INBOUND_DOMAIN_DEFAULT,
}) {
  if (!Array.isArray(policyEvidence?.rua_destinations)) {
    return {
      destinations: null,
      rua_authorisation_completeness: "incomplete",
      all_destinations_authorized: null,
      admitted_external_hosts: 0,
      uri_count: null,
      trusted_ingestion_status: "item5_gate_unchanged",
      receiver_enforcement_observed: false,
      assessment_reason: "policy_uri_set_unavailable",
      limits: {
        maximum_uris: DMARCBIS_MAX_REPORT_URIS,
        maximum_external_hosts: DMARCBIS_MAX_EXTERNAL_HOSTS,
        per_host_question_reservation: 11,
      },
    };
  }
  const uris = policyEvidence.rua_destinations;
  if (uris.length === 0) {
    return {
      destinations: [],
      rua_authorisation_completeness: "not_applicable",
      all_destinations_authorized: null,
      admitted_external_hosts: 0,
      uri_count: 0,
      trusted_ingestion_status: "item5_gate_unchanged",
      receiver_enforcement_observed: false,
      limits: {
        maximum_uris: DMARCBIS_MAX_REPORT_URIS,
        maximum_external_hosts: DMARCBIS_MAX_EXTERNAL_HOSTS,
        per_host_question_reservation: 11,
      },
    };
  }
  const results = [];
  const hostResults = new Map();
  const admittedHosts = new Set();
  let budgetClosed = false;

  for (let index = 0; index < uris.length; index += 1) {
    const uri = uris[index];
    if (index >= DMARCBIS_MAX_REPORT_URIS) {
      results.push(unassessedUri(
        uri,
        "not_assessed_limit_exceeded",
        "not_assessed_limit",
        "uri_count_limit",
      ));
      continue;
    }
    if (!uri.syntax_valid) {
      results.push(unassessedUri(
        uri,
        "not_assessed_malformed_uri",
        "malformed",
        uri.error || "malformed_uri",
      ));
      continue;
    }
    if (!uri.supported_scheme) {
      results.push(unassessedUri(
        uri,
        "not_assessed_unsupported_scheme",
        "not_assessed_limit",
        "unsupported_scheme",
      ));
      continue;
    }
    if (uri.over_product_limit) {
      results.push(unassessedUri(
        uri,
        "not_assessed_limit_exceeded",
        "not_assessed_limit",
        "uri_character_limit",
      ));
      continue;
    }
    if (
      !policyEvidence?.policy_source_domain ||
      !policyEvidence?.organisational_domain
    ) {
      results.push(unassessedUri(
        uri,
        "unavailable",
        "unavailable",
        "policy_source_organisation_unavailable",
      ));
      continue;
    }
    if (hostResults.has(uri.destination_host)) {
      results.push(reuseHostAssessment(uri, hostResults.get(uri.destination_host)));
      continue;
    }
    if (budgetClosed) {
      results.push(unassessedUri(
        uri,
        "not_assessed_budget",
        "not_assessed_budget",
        "earlier_host_reservation_refused",
      ));
      continue;
    }
    if (admittedHosts.size >= DMARCBIS_MAX_EXTERNAL_HOSTS) {
      results.push(unassessedUri(
        uri,
        "not_assessed_limit_exceeded",
        "not_assessed_limit",
        "external_host_limit",
      ));
      continue;
    }

    const reserved = await reserveHost({
      host: uri.destination_host,
      questions: 11,
      ordinal: admittedHosts.size + 1,
    });
    if (!reserved) {
      budgetClosed = true;
      const refused = unassessedUri(
        uri,
        "not_assessed_budget",
        "not_assessed_budget",
        "full_host_reservation_refused",
      );
      hostResults.set(uri.destination_host, refused);
      results.push(refused);
      continue;
    }

    admittedHosts.add(uri.destination_host);
    const resolved = await resolveOneExternalHost({
      uri,
      policySourceDomain: policyEvidence.policy_source_domain,
      policySourceOrganisationalDomain: policyEvidence.organisational_domain,
      dns,
      hostedRuaDomain,
    });
    hostResults.set(uri.destination_host, resolved);
    results.push({ ...uri, ...resolved, reused_host_assessment: false });
  }

  const incomplete = results.some((result) =>
    result.lookup_completeness !== "complete" ||
    result.authorization_status?.startsWith("not_assessed"));
  const definitivePositive = results.every((result) =>
    ["authorized", "not_required_same_organisational_domain", "not_required_cybermeters_hosted"].includes(
      result.authorization_status,
    ));

  return {
    destinations: results,
    rua_authorisation_completeness: incomplete ? "incomplete" : "complete",
    all_destinations_authorized: incomplete ? null : definitivePositive,
    admitted_external_hosts: admittedHosts.size,
    uri_count: uris.length,
    trusted_ingestion_status: "item5_gate_unchanged",
    receiver_enforcement_observed: false,
    limits: {
      maximum_uris: DMARCBIS_MAX_REPORT_URIS,
      maximum_external_hosts: DMARCBIS_MAX_EXTERNAL_HOSTS,
      per_host_question_reservation: 11,
    },
  };
}
