// Production adapter for the pure DMARCbis P1 resolver.
//
// This module owns only invocation-scoped DNS observation, the approved
// 750 ms/600 ms phase bounds, Item 6 evidence metadata, and compatibility-safe
// degradation. Protocol parsing and derivation remain in dmarcbis-resolver.js.
import { dnsQuery, dnsQueryGoogle } from "./dns.js";
import {
  DMARCBIS_METHODOLOGY_VERSION,
  resolveDmarcbisExternalRuaAuthorizations,
  resolveDmarcbisPolicy,
} from "./dmarcbis-resolver.js";

export const DMARCBIS_CORE_BUDGET_MS = 750;
export const DMARCBIS_PRIMARY_BUDGET_MS = 500;
export const DMARCBIS_CORROBORATION_DEADLINE_MS = 650;
export const DMARCBIS_EXTERNAL_RUA_BUDGET_MS = 600;
export const DMARCBIS_EXTERNAL_HOST_RESERVATION = 11;
export const DMARCBIS_EXTERNAL_PRIMARY_DEADLINE_MS = 300;
export const DMARCBIS_EXTERNAL_CORROBORATION_DEADLINE_MS = 400;
export const DMARCBIS_EXTERNAL_AUTHORIZATION_DEADLINE_MS = 525;

function combineSignals(...signals) {
  const active = signals.filter(Boolean);
  if (!active.length) return undefined;
  if (active.length === 1) return active[0];
  if (typeof AbortSignal.any === "function") return AbortSignal.any(active);
  const controller = new AbortController();
  const abort = () => controller.abort(active.find((signal) => signal.aborted)?.reason);
  for (const signal of active) {
    if (signal.aborted) { abort(); break; }
    signal.addEventListener("abort", abort, { once: true });
  }
  return controller.signal;
}

function unavailableOutcome(error, localTimedOut, parentSignal) {
  if (localTimedOut || error?.name === "TimeoutError") return "timeout";
  if (parentSignal?.aborted || error?.name === "AbortError") return "cancelled_deadline";
  return "transport_error";
}

async function boundedProviderQuery({
  provider,
  question,
  cache,
  accounting,
  parentSignal,
  remainingMs,
  setTimer,
  clearTimer,
  now,
}) {
  if (remainingMs <= 0 || parentSignal?.aborted) {
    return {
      outcome: parentSignal?.aborted ? "cancelled_deadline" : "timeout",
      resolver: question.resolver,
      elapsed_ms: 0,
      txt_records: null,
    };
  }

  const controller = new AbortController();
  const signal = combineSignals(parentSignal, controller.signal);
  let timer = null;
  let localTimedOut = false;
  const started = now();
  const TIMEOUT = Symbol("dmarcbis_question_timeout");
  const timeout = new Promise((resolve) => {
    timer = setTimer(() => {
      localTimedOut = true;
      controller.abort("dmarcbis_question_deadline");
      resolve(TIMEOUT);
    }, remainingMs);
  });
  const work = Promise.resolve()
    .then(() => provider(question.name, question.type, {
      cache,
      accounting,
      signal,
    }))
    .then((value) => ({ value }), (error) => ({ error }));
  const winner = await Promise.race([work, timeout]);
  if (timer != null) clearTimer(timer);

  if (winner === TIMEOUT) {
    return {
      outcome: "timeout",
      resolver: question.resolver,
      elapsed_ms: Math.max(0, now() - started),
      txt_records: null,
    };
  }
  if (winner.error) {
    return {
      outcome: unavailableOutcome(winner.error, localTimedOut, parentSignal),
      resolver: question.resolver,
      elapsed_ms: Math.max(0, now() - started),
      txt_records: null,
      error: String(winner.error?.message || winner.error),
    };
  }
  return {
    ...winner.value,
    resolver: question.resolver,
    elapsed_ms: Math.max(0, now() - started),
  };
}

export function createProductionDmarcbisDnsClient({
  cache = null,
  accounting = null,
  signal = null,
  phase = "core",
  phaseStartedAt = null,
  now = Date.now,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  primaryProvider = dnsQuery,
  secondaryProvider = dnsQueryGoogle,
} = {}) {
  const startedAt = phaseStartedAt ?? now();
  return async (question) => {
    const secondary = question?.resolver === "secondary";
    const provider = secondary ? secondaryProvider : primaryProvider;
    const elapsed = Math.max(0, now() - startedAt);
    let boundary = DMARCBIS_EXTERNAL_RUA_BUDGET_MS;
    if (phase === "core") {
      boundary = secondary
        ? DMARCBIS_CORROBORATION_DEADLINE_MS
        : DMARCBIS_PRIMARY_BUDGET_MS;
    } else if (question?.purpose === "rua_destination_tree_walk") {
      boundary = DMARCBIS_EXTERNAL_PRIMARY_DEADLINE_MS;
    } else if (
      question?.purpose === "rua_destination_decisive_corroboration"
    ) {
      boundary = DMARCBIS_EXTERNAL_CORROBORATION_DEADLINE_MS;
    } else if (
      question?.purpose === "external_rua_authorization" ||
      question?.purpose === "external_rua_authorization_corroboration"
    ) {
      boundary = DMARCBIS_EXTERNAL_AUTHORIZATION_DEADLINE_MS;
    }
    return boundedProviderQuery({
      provider,
      question,
      cache,
      accounting,
      parentSignal: signal,
      remainingMs: boundary - elapsed,
      setTimer,
      clearTimer,
      now,
    });
  };
}

function evidenceGradeForCore(policyEvidence, observedAt) {
  const complete = policyEvidence?.policy_completeness === "complete"
    && policyEvidence?.organisational_domain_completeness === "complete"
    && ["complete", "not_applicable"].includes(
      policyEvidence?.existence_completeness,
    );
  const grade = complete ? "L3" : policyEvidence?.lookup_path?.length ? "L1" : "L0";
  return {
    observable_ceiling: "L5",
    beta_target: "L4",
    minimum_publishable: "L3",
    degrade_behavior:
      "Unavailable or incomplete required DNS evidence withholds policy and cannot become absence or healthy.",
    required_corroboration: [
      "RFC 9989 logical tree walk",
      "decisive policy-record resolver comparison",
    ],
    grade,
    source_type: "normative_protocol",
    basis:
      "RFC 9989 DNS policy discovery and requested-policy derivation; receiver handling is not observed.",
    limits: [
      "A DNS policy observation does not prove receiver enforcement.",
      "DNSSEC flags are retained only as limits; authenticated denial is not claimed.",
    ],
    repeat_confirmed: false,
    observed_at: observedAt,
  };
}

function evidenceGradeForExternal(result, observedAt, destination = null) {
  // CyberMeters-hosted destination: definitive positive derived from our own
  // authority over the endpoint, NOT from an external RFC 9990 DNS lookup. Grade
  // it publishable but under a distinct self-authority basis so we never claim a
  // DNS corroboration that did not happen.
  if (destination?.authorization_status === "not_required_cybermeters_hosted") {
    return {
      observable_ceiling: "L5",
      beta_target: "L4",
      minimum_publishable: "L3",
      degrade_behavior:
        "Applies only to destinations under the CyberMeters hosted RUA domain; any other destination follows the external RFC 9990 lookup path.",
      required_corroboration: [
        "CyberMeters authority over the hosted RUA destination domain",
      ],
      grade: "L3",
      source_type: "operator_authority",
      basis:
        "CyberMeters is authoritative for this hosted aggregate-report destination; external RFC 9990 DNS authorisation is not required. Ingestion authority remains governed by Item 5.",
      limits: [
        "Authorization does not prove receipt, custody, authenticity, or receiver enforcement.",
        "Confirms only that the destination is CyberMeters-hosted, not that any report was received.",
      ],
      repeat_confirmed: false,
      observed_at: observedAt,
    };
  }
  const complete = destination
    ? destination.lookup_completeness === "complete"
    : result?.rua_authorisation_completeness === "complete" ||
      result?.rua_authorisation_completeness === "not_applicable";
  const observed = destination
    ? Boolean(
      destination.authorization_observations ||
      destination.destination_organisation?.walk?.path?.length,
    )
    : Array.isArray(result?.destinations) &&
      result.destinations.some((entry) =>
        entry.authorization_observations ||
        entry.destination_organisation?.walk?.path?.length);
  return {
    observable_ceiling: "L5",
    beta_target: "L4",
    minimum_publishable: "L3",
    degrade_behavior:
      "Timeout, provider disagreement, limit, or budget refusal remains unavailable/incomplete and cannot authorize a destination.",
    required_corroboration: [
      "RFC 9989 destination organisational-domain walk",
      "RFC 9990 primary and corroborating authorization record lookup",
    ],
    grade: complete ? "L3" : observed ? "L1" : "L0",
    source_type: "normative_protocol",
    basis:
      "RFC 9990 external aggregate-report destination authorization DNS; ingestion authority remains governed by Item 5.",
    limits: [
      "Authorization does not prove receipt, custody, authenticity, or receiver enforcement.",
      "Unsupported or over-bound URI destinations are not assessed as invalid under the RFC.",
    ],
    repeat_confirmed: false,
    observed_at: observedAt,
  };
}

function withExternalEvidenceGrades(result, policyEvidence) {
  const observedAt =
    policyEvidence?.observed_at || new Date().toISOString();
  const destinations = Array.isArray(result?.destinations)
    ? result.destinations.map((destination) => ({
      ...destination,
      evidence_grade: evidenceGradeForExternal(
        result,
        observedAt,
        destination,
      ),
    }))
    : result?.destinations ?? null;
  return {
    ...result,
    destinations,
    evidence_grade: evidenceGradeForExternal(result, observedAt),
  };
}

export function unavailableDmarcbisCore(
  authorDomain,
  reason = "core_deadline",
  observedAt = new Date().toISOString(),
) {
  return {
    schema: "dmarc-policy.v2",
    methodology_version: DMARCBIS_METHODOLOGY_VERSION,
    author_domain: authorDomain ? String(authorDomain).toLowerCase() : null,
    submitted_domain: authorDomain == null ? "" : String(authorDomain),
    observed_at: observedAt,
    observation_state: "unavailable",
    record_validity: "indeterminate",
    raw_records: null,
    parsed_tags: null,
    lookup_path: [],
    organisational_domain: null,
    organisational_domain_provenance: "unresolved",
    organisational_domain_completeness: "unavailable",
    policy_source_domain: null,
    policy_source_kind: "unknown",
    declared_policy: null,
    effective_requested_policy: null,
    effective_policy_tag: null,
    inheritance_reason: "unknown",
    domain_existence: "unknown",
    existence_completeness: "unavailable",
    p: null,
    sp: null,
    np: null,
    t: null,
    psd: null,
    legacy_pct: {
      observed: false,
      raw: null,
      numeric: null,
      semantics: "rfc7489_legacy",
      applied_to_effective_policy: false,
    },
    rua_destinations: null,
    ruf_destinations: null,
    policy_completeness: "unavailable",
    rua_authorisation_completeness: "incomplete",
    corroboration_state: "unavailable",
    monitoring_state: "monitoring_degraded",
    provider_state: reason,
    receiver_enforcement_observed: false,
    core_completeness: "unavailable",
    executed: true,
    incomplete: true,
    outcome: "unavailable",
    reason,
    evidence_grade: evidenceGradeForCore(null, observedAt),
    limits: {
      maximum_core_ms: DMARCBIS_CORE_BUDGET_MS,
      maximum_primary_ms: DMARCBIS_PRIMARY_BUDGET_MS,
      maximum_corroboration_deadline_ms: DMARCBIS_CORROBORATION_DEADLINE_MS,
      maximum_logical_questions: 10,
    },
  };
}

async function raceBounded(work, {
  milliseconds,
  controller,
  setTimer,
  clearTimer,
}) {
  const TIMEOUT = Symbol("dmarcbis_phase_timeout");
  let timer = null;
  const timeout = new Promise((resolve) => {
    timer = setTimer(() => {
      controller.abort("dmarcbis_phase_deadline");
      resolve(TIMEOUT);
    }, milliseconds);
  });
  const settled = Promise.resolve(work).then(
    (value) => ({ value }),
    (error) => ({ error }),
  );
  const winner = await Promise.race([settled, timeout]);
  if (timer != null) clearTimer(timer);
  return winner === TIMEOUT ? { timed_out: true } : winner;
}

export async function runDmarcbisCore(authorDomain, {
  cache = null,
  accounting = null,
  signal = null,
  now = Date.now,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  primaryProvider = dnsQuery,
  secondaryProvider = dnsQueryGoogle,
} = {}) {
  const observedAt = new Date(now()).toISOString();
  const startedAt = now();
  const controller = new AbortController();
  const combined = combineSignals(signal, controller.signal);
  const dns = createProductionDmarcbisDnsClient({
    cache,
    accounting,
    signal: combined,
    phase: "core",
    phaseStartedAt: startedAt,
    now,
    setTimer,
    clearTimer,
    primaryProvider,
    secondaryProvider,
  });
  const winner = await raceBounded(
    resolveDmarcbisPolicy({ authorDomain, dns }),
    {
      milliseconds: DMARCBIS_CORE_BUDGET_MS,
      controller,
      setTimer,
      clearTimer,
    },
  );
  if (winner.timed_out) {
    return unavailableDmarcbisCore(authorDomain, "core_deadline", observedAt);
  }
  if (winner.error) {
    return unavailableDmarcbisCore(
      authorDomain,
      "core_provider_error",
      observedAt,
    );
  }

  const policy = winner.value;
  const complete = policy.policy_completeness === "complete"
    && policy.organisational_domain_completeness === "complete"
    && ["complete", "not_applicable"].includes(policy.existence_completeness);
  return {
    ...policy,
    observed_at: observedAt,
    rua_authorisation_completeness:
      Array.isArray(policy.rua_destinations) && policy.rua_destinations.length === 0
        ? "not_applicable"
        : "incomplete",
    external_rua_authorisation: null,
    // Reconcile monitoring_state with the FULL core-completeness check. The
    // resolver freezes monitoring_state from policy_completeness alone; core
    // completeness additionally requires the org-domain walk and existence to be
    // complete. Recompute here so the panel (monitoring_state) can never read
    // "evidence complete" while core_completeness is incomplete.
    monitoring_state: complete ? "monitoring_healthy" : "monitoring_degraded",
    core_completeness: complete ? "complete" : "incomplete",
    executed: true,
    ...(complete ? {} : { incomplete: true }),
    outcome: complete ? "available" : "unavailable",
    evidence_grade: evidenceGradeForCore(policy, observedAt),
    limits: {
      ...(policy.limits || {}),
      maximum_core_ms: DMARCBIS_CORE_BUDGET_MS,
      maximum_primary_ms: DMARCBIS_PRIMARY_BUDGET_MS,
      maximum_corroboration_deadline_ms: DMARCBIS_CORROBORATION_DEADLINE_MS,
      maximum_logical_questions: 10,
      observed_core_ms: Math.max(0, now() - startedAt),
    },
  };
}

export async function budgetRefusedDmarcbisExternal(
  policyEvidence,
  reason = "launch_refused",
) {
  const result = await resolveDmarcbisExternalRuaAuthorizations({
    policyEvidence,
    dns: async () => ({ outcome: "not_issued_budget" }),
    reserveHost: () => false,
  });
  return withExternalEvidenceGrades({
    ...result,
    rua_authorisation_completeness:
      result.rua_authorisation_completeness === "not_applicable"
        ? "not_applicable"
        : "incomplete",
    assessment_reason: reason,
  }, policyEvidence);
}

export async function runDmarcbisExternalRuaPhase(policyEvidence, {
  cache = null,
  accounting = null,
  signal = null,
  reserveHost = () => true,
  now = Date.now,
  setTimer = setTimeout,
  clearTimer = clearTimeout,
  primaryProvider = dnsQuery,
  secondaryProvider = dnsQueryGoogle,
} = {}) {
  if (!Array.isArray(policyEvidence?.rua_destinations)
      || policyEvidence.rua_destinations.length === 0) {
    return budgetRefusedDmarcbisExternal(policyEvidence, "not_applicable");
  }
  const startedAt = now();
  const controller = new AbortController();
  const combined = combineSignals(signal, controller.signal);
  const dns = createProductionDmarcbisDnsClient({
    cache,
    accounting,
    signal: combined,
    phase: "external",
    phaseStartedAt: startedAt,
    now,
    setTimer,
    clearTimer,
    primaryProvider,
    secondaryProvider,
  });
  const winner = await raceBounded(
    resolveDmarcbisExternalRuaAuthorizations({
      policyEvidence,
      dns,
      reserveHost,
    }),
    {
      milliseconds: DMARCBIS_EXTERNAL_RUA_BUDGET_MS,
      controller,
      setTimer,
      clearTimer,
    },
  );
  if (winner.timed_out || winner.error) {
    const result = await budgetRefusedDmarcbisExternal(
      policyEvidence,
      winner.timed_out ? "provider_timeout" : "provider_error",
    );
    return withExternalEvidenceGrades({
      ...result,
      destinations: Array.isArray(result.destinations)
        ? result.destinations.map((destination) => ({
          ...destination,
          authorization_status: destination.authorization_status?.startsWith("not_assessed")
            ? "unavailable"
            : destination.authorization_status,
          authorization_record_state: "unavailable",
          lookup_completeness: "incomplete",
        }))
        : result.destinations,
    }, policyEvidence);
  }
  return withExternalEvidenceGrades({
    ...winner.value,
    observed_phase_ms: Math.max(0, now() - startedAt),
  }, policyEvidence);
}

export function attachDmarcbisExternalResult(policyEvidence, external) {
  const completeness = external?.rua_authorisation_completeness || "incomplete";
  const degraded = completeness === "incomplete";
  return {
    ...policyEvidence,
    rua_authorisation_completeness: completeness,
    external_rua_authorisation: external || null,
    ...(degraded && policyEvidence?.core_completeness === "complete"
      ? {
        degraded: true,
        outcome: "degraded",
        monitoring_state: "monitoring_degraded",
      }
      : {}),
  };
}
