// CT-R2 PR-2A.1 pre-execution old-runtime classification record.
//
// This module is data only. The semantic oracle imports its immutable PASS/FAIL
// partition, but this file does not import or execute production runtime code.
// Every source snippet is copied from the frozen base commit and its SHA-256 is
// calculated over the exact UTF-8 snippet bytes, including the final newline.

export const CT_ISOLATION_BASE_COMMIT =
  "5fa32135fd5adc18e62649bbe22bc92cb9f83f19";

const evidence = (path, line, sourceSnippet, snippetSha256) => Object.freeze({
  commit: CT_ISOLATION_BASE_COMMIT,
  path,
  line,
  source_snippet: sourceSnippet,
  snippet_sha256: snippetSha256,
});

const BASE_EVIDENCE = Object.freeze({
  FIRST_CONSUMER_OWNS_PHYSICAL_ACCOUNTING: evidence(
    "workers/scan-api/src/engines/ct-provider-cache.js",
    413,
    `      if (!entries.has(key)) {
        entries.set(
          key,
          fetchProvider(config, provider, normalizedDomain, {
            accounting,
            fetcher,
            signal,
            policy: resolvePolicy(provider, policies),
            recordAttempt: captureTelemetry ? recordAttempt : null,
            remainingMs,
            now,
            sleep,
            telemetryNow,
            timeoutSignal,
            recordHealth,
          })
        );
      }
      return entries.get(key);
`,
    "83e855b0c6c87371688bf6120c8926a59691622195fefa64792746ea5b2ea71c",
  ),
  CACHE_GET_HAS_NO_CONSUMER_BOUNDARY: evidence(
    "workers/scan-api/src/engines/ct-provider-cache.js",
    394,
    `  return {
    get(domain, provider, { accounting = null, module = null } = {}) {
      const normalizedDomain = normalizeDomain(domain);
      const config = PROVIDERS[provider];
      if (captureTelemetry && CT_PROVIDER_TELEMETRY_MODULES.includes(module)) {
        if (!providerConsumers.has(provider)) providerConsumers.set(provider, new Set());
        providerConsumers.get(provider).add(module);
      }
`,
    "0d6f87571f16a60a2bcb8e2cce8ae76154a8b59a11f0cafc4f10f7bad1267c4c",
  ),
  CT_R1_ABORT_CLASSIFIER: evidence(
    "workers/scan-api/src/engines/ct-provider-cache.js",
    157,
    `  try {
    accounting?.assertCanIssue?.();
    accounting?.recordAttempt?.();
    attempted = true;
    response = await fetcher(config.url(domain), {
      headers: { Accept: "application/json", "User-Agent": "CyberMeters/1.0" },
      signal: combineSignals(signal, accounting?.signal, timeoutSignal(timeoutMs)),
    });
    accounting?.recordCompleted?.();
  } catch (err) {
    if (attempted) accounting?.recordError?.(err);
    const completedMs = readTelemetryClock(telemetryNow);
    if (attempted) {
      safeAttemptObservation(recordAttempt, {
        provider,
        outcome: timeoutFailure(err) ? "timeout" : "network_error",
        http_status: null,
        latency_ms: Math.max(0, completedMs - startedMs),
        result_count: null,
        started_at: new Date(startedMs).toISOString(),
        completed_at: new Date(completedMs).toISOString(),
        cache_state: "miss",
        cache_age_s: null,
      });
`,
    "e779d053d67b47845a83b18de702964e292a9de1882ea477d8e4321bc13db31d",
  ),
  GLOBAL_DEADLINE_API: evidence(
    "workers/scan-api/src/engines/scan-budget.js",
    146,
    `export function createScanDeadline(env = {}, now = Date.now) {
  const budgetMs = clampInt(env.SCAN_DEADLINE_MS, SCAN_DEADLINE_DEFAULTS.budgetMs,
    SCAN_DEADLINE_DEFAULTS.minBudgetMs, SCAN_DEADLINE_DEFAULTS.maxBudgetMs);
  const startedAtMs = now();
  const controller = new AbortController();
  return {
    budgetMs,
    totalCeilingMs: SCAN_DEADLINE_DEFAULTS.totalCeilingMs,
    finalizationReserveMs: SCAN_DEADLINE_DEFAULTS.finalizationReserveMs,
    startedAtMs,
    signal: controller.signal,
    elapsedMs()   { return now() - startedAtMs; },
    remainingMs() { return Math.max(0, budgetMs - (now() - startedAtMs)); },
    exceeded()    { return now() - startedAtMs >= budgetMs; },
    // A phase launches only if elapsed + its estimate still fits the budget.
    canRun(estimateMs = 0) { return (now() - startedAtMs) + estimateMs < budgetMs; },
    cancel(reason = "scan_deadline_exhausted") { if (!controller.signal.aborted) controller.abort(reason); },
  };
`,
    "b1329019b5fac0a628e1a38752097e9ccc6d6091574673475373176f5cfc5469",
  ),
  OVERLAP_VOCABULARY: evidence(
    "workers/scan-api/src/engines/ct-provider-overlap.js",
    20,
    `export const CT_PROVIDER_OVERLAP_ATTEMPT_STATES = Object.freeze([
  "terminal_success",
  "terminal_failure",
  "not_started",
  "in_flight_at_consumer_release",
]);

export const CT_PROVIDER_OVERLAP_COMPARISON_STATUSES = Object.freeze([
  "compared",
  "compared_truncated",
  "censored_provider_failure",
  "censored_in_flight",
  "not_started",
]);
`,
    "e2ac7ad9941b06c634bd5b5999ceb096b1bcc0bde6dc34d483262f0ac58246f7",
  ),
  OVERLAP_FREEZE_CLASSIFIER: evidence(
    "workers/scan-api/src/engines/ct-provider-overlap.js",
    242,
    `    freeze() {
      if (consumerReleased) return buildFrozenSnapshot();
      for (const provider of PROVIDERS) {
        if (providerMeasurements.has(provider)) continue;
        providerMeasurements.set(
          provider,
          unmeasuredProvider(startedProviders.has(provider)
            ? "in_flight_at_consumer_release"
            : "not_started"),
        );
      }
      releasedAt = isoNow(now);
      consumerReleased = true;
      return buildFrozenSnapshot();
`,
    "c102e3f79408ae1ba22ebf2968692ffee8c999b4a5e1fb88ebac407d384cec74",
  ),
  RESERVED_DIRECT_COMPOSITION: evidence(
    "workers/scan-api/src/engines/reserved-scan.js",
    186,
    `  // Stage 6: remaining modules, budget-gated (customer-critical exposure already done).
  const dns                  = await gateModule(budget, "dns", () => runDnsModule(domain, { cache: dnsCache }), { resolves });
  const ssl                  = await gateModule(budget, "ssl", () => runSslModule(domain, { ctCache: sharedCtCache }));
  const headers              = await gateModule(budget, "headers", () => runHeadersModule(domain));
  const email_security       = await gateModule(budget, "email_security", () => runEmailModule(domain, {
    cache: dnsCache,
    dmarcOwnedByCore: true,
  }));
  const subdomains           = await gateModule(budget, "subdomains", () => runSubdomainsModule(domain, { cache: dnsCache, ctCache: sharedCtCache, ctOverlap }), { count: 0, items: [], wildcard_dns: false, wildcard_dns_addresses: [] });
  const technology_detection = await gateModule(budget, "technology_detection", () => runTechModule(domain));
`,
    "94f06561e6a4601dbe92bec0779d0823863381ea4db0aadc6f4a53f3fd34766f",
  ),
  SOURCE_SET_V1: evidence(
    "workers/scan-api/src/engines/ct-provider-overlap.js",
    10,
    `export const CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION = "ct-provider-overlap/1";
`,
    "96ddaa95fdd8c69625f2d180f3788a90d36aa05c1211b7a1a7d8753e1b0aab5f",
  ),
  ANALYZER_OUTPUT_WITHOUT_PLATFORM_POPULATION: evidence(
    "scripts/analyze-ct-provider-telemetry.js",
    213,
    `    telemetry_coverage: {
      measurement_state: telemetryMeasurementState,
      message: telemetryCoverageMessage,
      scans_total: scans.size,
      scans_with_ct_telemetry: scansWithTelemetry.size,
      scans_without_ct_telemetry: scansWithoutTelemetry,
      telemetry_coverage_pct: telemetryCoveragePct,
      completion_loss_total: completionLoss,
      completion_loss_attributed: completionLossAttributed,
      completion_loss_unattributed: completionLossUnattributed,
    },
    failure_attribution: {
      measurement_state: telemetryMeasurementState,
      message: telemetryMeasurementState === "not_measured"
        ? "Provider failure attribution is not measured because no CT telemetry rows exist."
        : telemetryMeasurementState === "partial_coverage"
          ? "Provider failure attribution uses available rows; uncovered completion loss remains unattributed."
          : "Provider failure attribution uses full CT telemetry coverage.",
      rows: failureAttribution,
    },
    latency_percentiles: latencyPercentiles,
    co_failure: {
      measurement_state: coFailureMeasurementState,
      message: bothAttempted === 0
        ? "Co-failure is not measured because no scan attempted both providers."
        : coFailureMeasurementState === "partial_coverage"
          ? "Co-failure uses scans where both providers were measured; overall CT telemetry coverage is partial."
          : "Co-failure uses all scans where both providers were measured.",
      scans_with_both_providers_attempted: bothAttempted,
      both_providers_failed: bothFailed,
      co_failure_rate_pct: bothAttempted === 0
        ? null
        : Number(((bothFailed / bothAttempted) * 100).toFixed(2)),
    },
  };
`,
    "70df79955b5e3509a2c39b63554092eee2b824049ef0f6e1bd0d1d6cfdfd03d5",
  ),
});

const failure = ({
  failureClass,
  rulingId,
  assertionId,
  baseCarrier,
  baseEvidence,
  expectedObserved,
  requiredCorrected,
  claimLimit,
}) => Object.freeze({
  failure_class: failureClass,
  ruling_id: rulingId,
  assertion_id: assertionId,
  base_carrier: baseCarrier,
  base_evidence: baseEvidence,
  expected_observed_value_or_state: expectedObserved,
  required_corrected_value_or_state: requiredCorrected,
  claim_limit: claimLimit,
});

export const CT_ISOLATION_OLD_RUNTIME_FAILURE_CLASSIFICATIONS = Object.freeze([
  failure({
    failureClass: "BEHAVIOURAL",
    rulingId: "R2A1-CONSUMER-OWNERSHIP",
    assertionId: "SSL_RELEASE_IS_CONSUMER_ONLY",
    baseCarrier: "createCertificateTransparencyCache().get through the first SSL and second subdomains consumers",
    baseEvidence: BASE_EVIDENCE.FIRST_CONSUMER_OWNS_PHYSICAL_ACCOUNTING,
    expectedObserved: "Aborting the first SSL accounting signal aborts the one physical fetch signal.",
    requiredCorrected: "SSL release does not abort physical work while the subdomains consumer remains entitled to wait.",
    claimLimit: "Proves the reachable first-consumer ownership mechanism; it does not quantify production occurrence.",
  }),
  failure({
    failureClass: "BEHAVIOURAL",
    rulingId: "R2A1-SIBLING-ENTITLEMENT",
    assertionId: "SIBLING_LATE_SUCCESS_RECEIVED",
    baseCarrier: "createCertificateTransparencyCache().get shared promise returned to subdomains after SSL starts first",
    baseEvidence: BASE_EVIDENCE.FIRST_CONSUMER_OWNS_PHYSICAL_ACCOUNTING,
    expectedObserved: "Subdomains receives status=unavailable after SSL aborts, even when the provider fixture later succeeds.",
    requiredCorrected: "Subdomains receives status=available with the late provider evidence before its own release boundary.",
    claimLimit: "Proves sibling poisoning in the executable cache path; it does not claim every late provider response succeeds.",
  }),
  failure({
    failureClass: "BEHAVIOURAL",
    rulingId: "R2A1-CTR1-PHYSICAL-TRUTH",
    assertionId: "CT_R1_LATE_SUCCESS_IS_OK",
    baseCarrier: "createCertificateTransparencyCache().telemetrySnapshot after the shared physical attempt",
    baseEvidence: BASE_EVIDENCE.CT_R1_ABORT_CLASSIFIER,
    expectedObserved: "The poisoned physical attempt is recorded as network_error with null result_count for both consumer rows.",
    requiredCorrected: "The one physical provider success is recorded as outcome=ok with the exact result count.",
    claimLimit: "Proves physical telemetry distortion caused by the base ownership path; it does not infer production frequency.",
  }),
  failure({
    failureClass: "STRUCTURAL",
    rulingId: "R2A1-RELEASE-LATCH",
    assertionId: "RELEASED_CONSUMER_REJECTS_LATE_RESULT",
    baseCarrier: "Feature detection on the object returned by createCertificateTransparencyCache",
    baseEvidence: BASE_EVIDENCE.CACHE_GET_HAS_NO_CONSUMER_BOUNDARY,
    expectedObserved: "releaseConsumer, consumerSnapshot and physicalSnapshot are absent.",
    requiredCorrected: "A released SSL consumer stays released_budget_exhausted after the physical promise settles.",
    claimLimit: "Proves capability absence only; it does not claim the base customer JSON historically mutated after publication.",
  }),
  failure({
    failureClass: "STRUCTURAL",
    rulingId: "R2A1-STATE-SEPARATION",
    assertionId: "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL",
    baseCarrier: "Feature detection on the object returned by createCertificateTransparencyCache",
    baseEvidence: BASE_EVIDENCE.CACHE_GET_HAS_NO_CONSUMER_BOUNDARY,
    expectedObserved: "No public consumer snapshot exists separately from physical provider state.",
    requiredCorrected: "SSL remains released_budget_exhausted while the physical request transitions independently to terminal_success.",
    claimLimit: "Proves missing state separation at base, not an incorrect historical customer response field.",
  }),
  failure({
    failureClass: "STRUCTURAL",
    rulingId: "R2A1-LATE-PUBLICATION",
    assertionId: "RELEASED_OUTPUT_IMMUTABLE",
    baseCarrier: "Feature detection on the actual exported runReservedScan composition before invoking an isolation boundary",
    baseEvidence: BASE_EVIDENCE.RESERVED_DIRECT_COMPOSITION,
    expectedObserved: "runReservedScan directly gates runSslModule and runSubdomainsModule and has no isolated CT consumer boundary.",
    requiredCorrected: "The reserved composition uses a release-latched boundary whose late work cannot replace the published fallback.",
    claimLimit: "Proves the reserved-path boundary is absent; it does not assert a measured historical late-mutation occurrence.",
  }),
  failure({
    failureClass: "STRUCTURAL",
    rulingId: "R2A1-CONSUMER-FAILURE-STATE",
    assertionId: "CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL",
    baseCarrier: "Feature detection on createCertificateTransparencyCache().consumerSnapshot after a genuine HTTP failure",
    baseEvidence: BASE_EVIDENCE.CACHE_GET_HAS_NO_CONSUMER_BOUNDARY,
    expectedObserved: "consumerSnapshot is absent, so the base cannot express received_failure separately from terminal_failure.",
    requiredCorrected: "A genuine HTTP failure yields consumer_wait_state=received_failure and physical_attempt_state=terminal_failure.",
    claimLimit: "Proves the state capability is absent; GENUINE_FAILURE_REMAINS_PROVIDER_FAILURE separately preserves base customer behaviour.",
  }),
  failure({
    failureClass: "STRUCTURAL",
    rulingId: "R2A1-STRUCTURED-GLOBAL-PROVENANCE",
    assertionId: "STRUCTURED_GLOBAL_DEADLINE_PROVENANCE",
    baseCarrier: "Feature detection on the object returned by createScanDeadline",
    baseEvidence: BASE_EVIDENCE.GLOBAL_DEADLINE_API,
    expectedObserved: "globalDeadlineProvenance() is absent; cancel only aborts the signal with an unstructured reason.",
    requiredCorrected: "The controller exposes aborted, owner=scan_global_deadline, reason and observed_at from one canonical event.",
    claimLimit: "Proves structured provenance capability absence, not incorrect historical customer output.",
  }),
  failure({
    failureClass: "BEHAVIOURAL",
    rulingId: "R2A1-PLATFORM-OUTCOME",
    assertionId: "CT_R1_GLOBAL_DEADLINE_CAUSE",
    baseCarrier: "createCertificateTransparencyCache telemetry after its public global signal aborts the physical fetch",
    baseEvidence: BASE_EVIDENCE.CT_R1_ABORT_CLASSIFIER,
    expectedObserved: "The global deadline rejection is classified as network_error (or timeout by message), not platform provenance.",
    requiredCorrected: "CT-R1 records outcome=platform_deadline_abort from the canonical global-deadline event.",
    claimLimit: "Proves source-reachable misclassification; production occurrence remains unknown.",
  }),
  failure({
    failureClass: "BEHAVIOURAL",
    rulingId: "R2A1-ABORT-ORDERING",
    assertionId: "ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT",
    baseCarrier: "createCtProviderOverlapCollector().begin followed by freeze with structured release context",
    baseEvidence: BASE_EVIDENCE.OVERLAP_FREEZE_CLASSIFIER,
    expectedObserved: "Both started unobserved providers freeze as in_flight_at_consumer_release/censored_in_flight because freeze ignores provenance.",
    requiredCorrected: "Abort-before-release freezes terminal_platform_deadline_abort/censored_platform_deadline_abort.",
    claimLimit: "Proves base release classification, not production frequency or migration application.",
  }),
  failure({
    failureClass: "STRUCTURAL",
    rulingId: "R2A1-SHARED-SIGNAL-PAIR",
    assertionId: "PA_IF_UNREACHABLE_ON_SHARED_SIGNAL",
    baseCarrier: "Feature detection on exported overlap attempt vocabulary and pair-status table",
    baseEvidence: BASE_EVIDENCE.OVERLAP_VOCABULARY,
    expectedObserved: "terminal_platform_deadline_abort and the canonical shared-signal pair table are absent.",
    requiredCorrected: "The corrected shared-signal composition exposes platform abort and rejects a PA+IF canonical pair.",
    claimLimit: "Proves missing representational capability; executed corrected-runtime composition must establish reachability separately.",
  }),
  failure({
    failureClass: "STRUCTURAL",
    rulingId: "R2A1-RESERVED-PARITY",
    assertionId: "RESERVED_PATH_USES_ISOLATED_BOUNDARY",
    baseCarrier: "Feature detection on Function.prototype.toString(runReservedScan), then boundary export only if detected in that composition",
    baseEvidence: BASE_EVIDENCE.RESERVED_DIRECT_COMPOSITION,
    expectedObserved: "The actual reserved scan composition directly invokes the existing SSL and subdomains modules.",
    requiredCorrected: "runReservedScan itself routes both CT consumers through the same isolated lifecycle boundary as the queue path.",
    claimLimit: "Proves actual reserved composition capability absence; it does not depend on blindly importing a proposed new export.",
  }),
  failure({
    failureClass: "BEHAVIOURAL",
    rulingId: "R2A1-COHORT-V2",
    assertionId: "SOURCE_SET_VERSION_IS_V2",
    baseCarrier: "Public CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION export",
    baseEvidence: BASE_EVIDENCE.SOURCE_SET_V1,
    expectedObserved: "ct-provider-overlap/1",
    requiredCorrected: "ct-provider-overlap/2",
    claimLimit: "Proves the base cohort label only; it does not reinterpret or backfill v1 history.",
  }),
  failure({
    failureClass: "STRUCTURAL",
    rulingId: "R2A1-ANALYZER-POPULATION",
    assertionId: "ANALYZER_COUNTS_DIRECT_ATTEMPT_POPULATION",
    baseCarrier: "Feature detection on analyzeCtProviderTelemetry() output after base-compatible invocation",
    baseEvidence: BASE_EVIDENCE.ANALYZER_OUTPUT_WITHOUT_PLATFORM_POPULATION,
    expectedObserved: "The output has no platform_deadline_censorship population or cohort breakdown.",
    requiredCorrected: "Direct attempt counting precedes completeness filtering and reports total, platform, impact, module/provider and cohort scopes.",
    claimLimit: "Proves analyzer capability absence; it makes no claim about historical platform-abort frequency.",
  }),
]);

export const CT_ISOLATION_OLD_RUNTIME_FAILURE_IDS = Object.freeze(
  CT_ISOLATION_OLD_RUNTIME_FAILURE_CLASSIFICATIONS.map((entry) => entry.assertion_id),
);

export const CT_ISOLATION_OLD_RUNTIME_POSITIVE_CONTROLS = Object.freeze([
  Object.freeze({
    assertion_id: "SHARED_PHYSICAL_REQUEST_ONE",
    base_carrier: "createCertificateTransparencyCache().get called by SSL then subdomains",
    expected_old_runtime_state: "Exactly one physical fetch is launched.",
    claim_limit: "Preserves one-request cache cardinality only.",
  }),
  Object.freeze({
    assertion_id: "SUCCESSFUL_EMPTY_IS_ZERO",
    base_carrier: "createCertificateTransparencyCache().get plus resolveCertificateTransparency",
    expected_old_runtime_state: "A successful empty response remains available and projects count=0,error=null.",
    claim_limit: "Preserves successful-empty semantics on the SSL CT source projection.",
  }),
  Object.freeze({
    assertion_id: "GENUINE_FAILURE_REMAINS_PROVIDER_FAILURE",
    base_carrier: "createCertificateTransparencyCache().get with HTTP 503",
    expected_old_runtime_state: "status=unavailable,error=HTTP 503,data=null.",
    claim_limit: "Preserves genuine provider failure; the structural consumer-state contract is separate.",
  }),
  Object.freeze({
    assertion_id: "GLOBAL_DEADLINE_STOPS_PHYSICAL_WORK",
    base_carrier: "createCertificateTransparencyCache public global signal delivered to the fetch signal",
    expected_old_runtime_state: "Global abort reaches and terminates the physical fetch.",
    claim_limit: "Preserves cancellation safety without requiring new physicalSnapshot output.",
  }),
  Object.freeze({
    assertion_id: "RELEASE_BEFORE_ABORT_IS_IN_FLIGHT",
    base_carrier: "createCtProviderOverlapCollector().begin then freeze",
    expected_old_runtime_state: "A started unobserved provider freezes in_flight_at_consumer_release/censored_in_flight.",
    claim_limit: "Preserves the no-prior-global-abort release state.",
  }),
  Object.freeze({
    assertion_id: "FROZEN_OVERLAP_REJECTS_LATE_OBSERVE",
    base_carrier: "createCtProviderOverlapCollector().freeze then observe",
    expected_old_runtime_state: "Late observe does not mutate the frozen snapshot.",
    claim_limit: "Preserves overlap snapshot immutability only.",
  }),
  Object.freeze({
    assertion_id: "CUSTOMER_SOURCE_SCHEMA_IS_STABLE",
    base_carrier: "resolveCertificateTransparency with an injected base-compatible ctCache",
    expected_old_runtime_state: "ct_sources.crt_sh serializes as count,error only.",
    claim_limit: "Preserves the SSL crt_sh source object shape; no blanket customer-output claim.",
  }),
  Object.freeze({
    assertion_id: "CUSTOMER_SOURCE_HAS_NO_LIFECYCLE_FIELDS",
    base_carrier: "resolveCertificateTransparency with injected unavailable provider values",
    expected_old_runtime_state: "Both SSL ct_sources provider objects expose only count,error.",
    claim_limit: "Proves lifecycle state remains internal to the tested SSL projection.",
  }),
]);

export const CT_ISOLATION_OLD_RUNTIME_PASS_IDS = Object.freeze(
  CT_ISOLATION_OLD_RUNTIME_POSITIVE_CONTROLS.map((entry) => entry.assertion_id),
);
