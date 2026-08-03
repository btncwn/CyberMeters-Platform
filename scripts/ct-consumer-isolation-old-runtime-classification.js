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

// Appended frozen-base evidence. The original BASE_EVIDENCE object above is
// deliberately untouched so its previously reviewed bytes remain stable.
const ADDITIONAL_BASE_EVIDENCE = Object.freeze({
  SSL_CUSTOMER_SOURCE_PROJECTION: evidence(
    "workers/scan-api/src/engines/ssl-scan.js",
    40,
    `  const ct_sources = { crt_sh: null, certspotter: null };
  try {
    const crtResult = await ctCache.get(domain, "crt_sh", { accounting, module: "ssl" });
    ct_sources.crt_sh = {
      count: crtResult.status === "available" ? crtResult.data.length : 0,
      error: crtResult.status === "unavailable" ? crtResult.error : null,
    };
`,
    "3ff6a5ae5a889ee7759118cd6da8be55635453c551845bf2b0a851aad161c098",
  ),
  SUBDOMAINS_CUSTOMER_SOURCE_PROJECTION: evidence(
    "workers/scan-api/src/engines/subdomains-scan.js",
    238,
    `  const seen    = new Set();
  const sources = { crt_sh: null, certspotter: null };

  // ── Source 1: crt.sh ───────────────────────────────────────────────────
  try {
    const result = crtShSettled.status === "fulfilled" ? crtShSettled.value : null;
    if (!result) {
      sources.crt_sh = { count: 0, error: customerSafeFailure("scan/ct/crt-sh", crtShSettled.reason, "fetch failed") };
    } else if (result.status === "unavailable") {
      sources.crt_sh = { count: 0, error: result.error };
`,
    "747b42803ffc8801f15953843b1e6d03e4dcea32b98ff791f8de2631f45b03d4",
  ),
  TELEMETRY_OUTCOME_VOCABULARY: evidence(
    "workers/scan-api/src/engines/ct-provider-cache.js",
    12,
    `export const CT_PROVIDER_TELEMETRY_OUTCOMES = Object.freeze([
  "ok",
  "timeout",
  "http_error",
  "parse_error",
  "rate_limited",
  "network_error",
]);
`,
    "f3a5c9e5d147f90e2178f2cd0d9740dfb498cc4e3b2a1606e59c5dbadf46eb90",
  ),
  PLATFORM_ABORT_FETCH_WORDING: evidence(
    "workers/scan-api/src/engines/ct-provider-cache.js",
    182,
    `    return {
      result: unavailable(
        provider,
        domain,
        customerSafeFailure(config.fetchContext, err, "fetch failed")
      ),
      transient: attempted && !externallyAborted(signal, accounting),
    };
`,
    "0b360109c3d91adf2efbfb89fabebeee42439f6b7f7ea92c07c75e95a26a38f9",
  ),
});

const assertion = ({
  assertionId,
  rulingIds,
  fixtureId,
  failureClass = null,
  baseCarrier,
  baseEvidence = null,
  expectedObserved,
  requiredCorrected,
  claimLimit,
}) => Object.freeze({
  assertion_id: assertionId,
  ruling_ids: Object.freeze([...rulingIds]),
  ruling_tests: Object.freeze(Object.fromEntries(
    rulingIds.map((rulingId) => [rulingId, requiredCorrected]),
  )),
  fixture_id: fixtureId,
  expected_old_runtime_result: failureClass ? "FAIL" : "PASS",
  failure_class: failureClass,
  base_carrier: baseCarrier,
  base_evidence: baseEvidence,
  expected_observed_value_or_state: expectedObserved,
  required_corrected_value_or_state: requiredCorrected,
  claim_limit: claimLimit,
});

export const CT_ISOLATION_ASSERTIONS = Object.freeze([
  assertion({
    assertionId: "SHARED_PHYSICAL_REQUEST_ONE",
    rulingIds: ["CT2A1-CACHE-01"],
    fixtureId: "shared_late_success",
    baseCarrier: "createCertificateTransparencyCache().get called by SSL then subdomains",
    expectedObserved: "Exactly one physical fetch is launched.",
    requiredCorrected: "Exactly one physical fetch remains shared per scan/domain/provider.",
    claimLimit: "Preserves cache cardinality only.",
  }),
  assertion({
    assertionId: "SSL_RELEASE_IS_CONSUMER_ONLY",
    rulingIds: ["CT2A1-CACHE-01", "CT2A1-CACHE-02"],
    fixtureId: "shared_late_success",
    failureClass: "BEHAVIOURAL",
    baseCarrier: "createCertificateTransparencyCache().get through first SSL and second subdomains consumers",
    baseEvidence: BASE_EVIDENCE.FIRST_CONSUMER_OWNS_PHYSICAL_ACCOUNTING,
    expectedObserved: "Aborting SSL accounting aborts the shared physical fetch.",
    requiredCorrected: "SSL release affects only SSL while shared physical work remains eligible for subdomains.",
    claimLimit: "Proves the executable first-consumer ownership mechanism, not production frequency.",
  }),
  assertion({
    assertionId: "SIBLING_LATE_SUCCESS_RECEIVED",
    rulingIds: ["CT2A1-CACHE-02"],
    fixtureId: "shared_late_success",
    failureClass: "BEHAVIOURAL",
    baseCarrier: "Shared cache promise returned to subdomains after SSL starts first",
    baseEvidence: BASE_EVIDENCE.FIRST_CONSUMER_OWNS_PHYSICAL_ACCOUNTING,
    expectedObserved: "Subdomains receives unavailable after SSL aborts the physical promise.",
    requiredCorrected: "Subdomains receives the provider success before its own release boundary.",
    claimLimit: "Proves sibling poisoning, not that every late provider request succeeds.",
  }),
  assertion({
    assertionId: "CT_R1_LATE_SUCCESS_IS_OK",
    rulingIds: ["CT2A1-PROV-01", "CT2A1-PROV-03"],
    fixtureId: "shared_late_success",
    failureClass: "BEHAVIOURAL",
    baseCarrier: "telemetrySnapshot() after the shared physical attempt",
    baseEvidence: BASE_EVIDENCE.CT_R1_ABORT_CLASSIFIER,
    expectedObserved: "The poisoned attempt is network_error with null result_count.",
    requiredCorrected: "The physical success is outcome=ok with its exact result count.",
    claimLimit: "Proves physical-telemetry distortion in the base path, not production frequency.",
  }),
  assertion({
    assertionId: "RELEASED_CONSUMER_REJECTS_LATE_RESULT",
    rulingIds: ["CT2A1-PROV-02"],
    fixtureId: "shared_late_success",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection on createCertificateTransparencyCache() result",
    baseEvidence: BASE_EVIDENCE.CACHE_GET_HAS_NO_CONSUMER_BOUNDARY,
    expectedObserved: "releaseConsumer(), consumerSnapshot() and physicalSnapshot() are absent.",
    requiredCorrected: "Released SSL remains released_budget_exhausted after physical settlement.",
    claimLimit: "Proves capability absence only, not historical customer-output mutation.",
  }),
  assertion({
    assertionId: "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL",
    rulingIds: ["CT2A1-PROV-01", "CT2A1-PROV-02"],
    fixtureId: "shared_late_success",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection on cache consumer and physical snapshots",
    baseEvidence: BASE_EVIDENCE.CACHE_GET_HAS_NO_CONSUMER_BOUNDARY,
    expectedObserved: "No public consumer state exists separately from physical state.",
    requiredCorrected: "SSL remains released while physical state independently reaches terminal_success.",
    claimLimit: "Proves missing state separation at base.",
  }),
  assertion({
    assertionId: "RELEASED_OUTPUT_IMMUTABLE",
    rulingIds: ["CT2A1-CACHE-02", "CT2A1-PROV-02"],
    fixtureId: "reserved_late_success",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection starting from the actual runReservedScan composition",
    baseEvidence: BASE_EVIDENCE.RESERVED_DIRECT_COMPOSITION,
    expectedObserved: "The reserved composition has no release-latched CT consumer boundary.",
    requiredCorrected: "Late physical settlement cannot replace an already published reserved fallback.",
    claimLimit: "Proves boundary absence only; final proof must execute the reserved path.",
  }),
  assertion({
    assertionId: "SUCCESSFUL_EMPTY_IS_ZERO",
    rulingIds: ["CT2A1-SENTINEL-01"],
    fixtureId: "successful_empty",
    baseCarrier: "createCertificateTransparencyCache().get plus resolveCertificateTransparency()",
    expectedObserved: "Successful empty projects { count: 0, error: null }.",
    requiredCorrected: "The same measured-zero result is preserved.",
    claimLimit: "Preserves successful-empty semantics only.",
  }),
  assertion({
    assertionId: "GENUINE_FAILURE_REMAINS_PROVIDER_FAILURE",
    rulingIds: ["CT2A1-PROV-01"],
    fixtureId: "genuine_http_failure",
    baseCarrier: "createCertificateTransparencyCache().get with HTTP 503",
    expectedObserved: "status=unavailable,error=HTTP 503,data=null.",
    requiredCorrected: "Genuine terminal provider failure remains unavailable.",
    claimLimit: "Preserves the genuine-provider-failure negative control.",
  }),
  assertion({
    assertionId: "CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL",
    rulingIds: ["CT2A1-PROV-01", "CT2A1-PROV-02"],
    fixtureId: "genuine_http_failure",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection on consumerSnapshot() after HTTP 503",
    baseEvidence: BASE_EVIDENCE.CACHE_GET_HAS_NO_CONSUMER_BOUNDARY,
    expectedObserved: "The base cannot express received_failure separately from terminal_failure.",
    requiredCorrected: "Consumer received_failure and physical terminal_failure are both present and distinct.",
    claimLimit: "Proves state capability absence; provider failure itself remains supported.",
  }),
  assertion({
    assertionId: "STRUCTURED_GLOBAL_DEADLINE_PROVENANCE",
    rulingIds: ["CT2A1-CACHE-02", "CT2A1-PROV-01", "CT2A1-PROV-02"],
    fixtureId: "scan_deadline_controller",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection on createScanDeadline() result",
    baseEvidence: BASE_EVIDENCE.GLOBAL_DEADLINE_API,
    expectedObserved: "globalDeadlineProvenance() is absent.",
    requiredCorrected: "One canonical event exposes aborted, owner, reason and observed_at.",
    claimLimit: "Proves structured-provenance capability absence, not historical customer output.",
  }),
  assertion({
    assertionId: "GLOBAL_DEADLINE_STOPS_PHYSICAL_WORK",
    rulingIds: ["CT2A1-CACHE-02"],
    fixtureId: "global_abort",
    baseCarrier: "Cache global signal delivered to the physical fetch signal",
    expectedObserved: "The global abort terminates the physical fetch.",
    requiredCorrected: "Canonical global cancellation remains authoritative.",
    claimLimit: "Preserves cancellation safety only.",
  }),
  assertion({
    assertionId: "CT_R1_GLOBAL_DEADLINE_CAUSE",
    rulingIds: ["CT2A1-PROV-01", "CT2A1-PROV-03", "CT2A1-VOCAB-01"],
    fixtureId: "global_abort",
    failureClass: "BEHAVIOURAL",
    baseCarrier: "Cache telemetry after its public global signal aborts physical fetch",
    baseEvidence: BASE_EVIDENCE.CT_R1_ABORT_CLASSIFIER,
    expectedObserved: "The abort is classified network_error or timeout.",
    requiredCorrected: "CT-R1 outcome is platform_deadline_abort from canonical provenance.",
    claimLimit: "Proves source-reachable misclassification; production occurrence is unknown.",
  }),
  assertion({
    assertionId: "STATE_MACHINE_TYPES_REMAIN_DISTINCT",
    rulingIds: ["CT2A1-PROV-01", "CT2A1-PROV-02", "CT2A1-PROV-03", "CT2A1-PROV-04"],
    fixtureId: "state_machine_exports",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection on cache and overlap lifecycle vocabularies",
    baseEvidence: BASE_EVIDENCE.OVERLAP_VOCABULARY,
    expectedObserved: "The base has no independent consumer-wait or persistence vocabularies.",
    requiredCorrected: "Physical, consumer, comparison and persistence vocabularies are separately exported and disjoint in meaning.",
    claimLimit: "Proves representational capability absence, not historical row content.",
  }),
  assertion({
    assertionId: "ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT",
    rulingIds: ["CT2A1-PROV-02", "CT2A1-PROV-03", "CT2A1-VOCAB-01"],
    fixtureId: "real_abort_before_release",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection before real cache/signal/subdomains/overlap composition",
    baseEvidence: BASE_EVIDENCE.OVERLAP_FREEZE_CLASSIFIER,
    expectedObserved: "The real composition cannot carry structured abort provenance to release/freeze.",
    requiredCorrected: "Abort signal before release yields terminal_platform_deadline_abort/censored_platform_deadline_abort.",
    claimLimit: "Proves capability absence only; direct observe/freeze injection is inadmissible final proof.",
  }),
  assertion({
    assertionId: "RELEASE_BEFORE_ABORT_IS_IN_FLIGHT",
    rulingIds: ["CT2A1-PROV-02", "CT2A1-PROV-03", "CT2A1-VOCAB-01"],
    fixtureId: "real_release_before_abort",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection before real cache/signal/subdomains/overlap composition",
    baseEvidence: BASE_EVIDENCE.CACHE_GET_HAS_NO_CONSUMER_BOUNDARY,
    expectedObserved: "The base lacks the real consumer release boundary required by the ordering proof.",
    requiredCorrected: "Release before abort yields in_flight_at_consumer_release/censored_in_flight.",
    claimLimit: "Proves capability absence only; direct collector injection is inadmissible final proof.",
  }),
  assertion({
    assertionId: "FROZEN_OVERLAP_REJECTS_LATE_OBSERVE",
    rulingIds: ["CT2A1-PROV-03"],
    fixtureId: "frozen_overlap",
    baseCarrier: "createCtProviderOverlapCollector().freeze then observe",
    expectedObserved: "Late observe does not mutate the frozen snapshot.",
    requiredCorrected: "The immutability guard remains in force.",
    claimLimit: "Preserves overlap snapshot immutability only.",
  }),
  assertion({
    assertionId: "PA_IF_UNREACHABLE_ON_SHARED_SIGNAL",
    rulingIds: ["CT2A1-PAIF-01"],
    fixtureId: "real_asymmetric_shared_abort",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection before real asymmetric shared-signal composition",
    baseEvidence: BASE_EVIDENCE.OVERLAP_VOCABULARY,
    expectedObserved: "The platform-abort vocabulary and shared-signal composition are absent.",
    requiredCorrected: "Executed promises/signals/releases never persist PA+IF for one release boundary.",
    claimLimit: "Structural absence is not reachability proof; final proof must execute real composition.",
  }),
  assertion({
    assertionId: "PERSISTENCE_OUTCOME_IS_INDEPENDENT",
    rulingIds: ["CT2A1-PROV-04"],
    fixtureId: "persistence_outcomes",
    baseCarrier: "persistCtProviderOverlapTelemetry() with empty, failing and durable fixtures",
    expectedObserved: "not_attempted_empty, persistence_failed and persisted do not rewrite measurement fields.",
    requiredCorrected: "The independent persistence outcome remains unchanged.",
    claimLimit: "Preserves persistence-state separation without D1 activity.",
  }),
  assertion({
    assertionId: "CUSTOMER_PLATFORM_ABORT_WORDING_EXACT",
    rulingIds: ["CT2A1-CUSTOMER-01"],
    fixtureId: "global_abort_customer_projection",
    failureClass: "BEHAVIOURAL",
    baseCarrier: "Global-aborted cache result through SSL and subdomains customer projection",
    baseEvidence: ADDITIONAL_BASE_EVIDENCE.PLATFORM_ABORT_FETCH_WORDING,
    expectedObserved: "The customer error uses fetch failed wording.",
    requiredCorrected: "The error exactly equals the contract sentence with ASCII apostrophe.",
    claimLimit: "Proves base wording for a source-reachable global abort, not production occurrence.",
  }),
  assertion({
    assertionId: "CUSTOMER_PLATFORM_ABORT_FORBIDS_PROVIDER_FAILURE",
    rulingIds: ["CT2A1-CUSTOMER-02"],
    fixtureId: "global_abort_customer_projection",
    failureClass: "BEHAVIOURAL",
    baseCarrier: "Global-aborted cache result through customer projection",
    baseEvidence: ADDITIONAL_BASE_EVIDENCE.PLATFORM_ABORT_FETCH_WORDING,
    expectedObserved: "The projection says fetch failed and presents unavailable provider meaning.",
    requiredCorrected: "Platform abort wording contains neither fetch failed nor provider unavailable meaning.",
    claimLimit: "Applies only to canonical platform-global abort cause.",
  }),
  assertion({
    assertionId: "CUSTOMER_SOURCE_SCHEMA_IS_STABLE",
    rulingIds: ["CT2A1-CUSTOMER-03"],
    fixtureId: "customer_source_shape",
    baseCarrier: "resolveCertificateTransparency() with base-compatible injected cache",
    expectedObserved: "ct_sources.crt_sh serializes as exactly count,error.",
    requiredCorrected: "The exact two-field compatibility shape remains.",
    claimLimit: "Preserves source-object shape, not blanket JSON parity.",
  }),
  assertion({
    assertionId: "CUSTOMER_SOURCE_HAS_NO_LIFECYCLE_FIELDS",
    rulingIds: ["CT2A1-CUSTOMER-03"],
    fixtureId: "customer_source_shape",
    baseCarrier: "resolveCertificateTransparency() with injected lifecycle metadata",
    expectedObserved: "Lifecycle metadata does not escape into ct_sources.",
    requiredCorrected: "Lifecycle and provenance remain outside { count, error }.",
    claimLimit: "Covers the provider-source customer object only.",
  }),
  assertion({
    assertionId: "SSL_SUBDOMAINS_PLATFORM_ABORT_WORDING_MATCH",
    rulingIds: ["CT2A1-CUSTOMER-04"],
    fixtureId: "global_abort_cross_module_projection",
    failureClass: "BEHAVIOURAL",
    baseCarrier: "Base SSL and subdomains projections fed the same global-aborted shared value",
    baseEvidence: ADDITIONAL_BASE_EVIDENCE.SUBDOMAINS_CUSTOMER_SOURCE_PROJECTION,
    expectedObserved: "Both projections inherit fetch failed rather than canonical platform-abort meaning.",
    requiredCorrected: "Both projections expose the exact contract wording and meaning.",
    claimLimit: "Tests SSL/subdomains equivalence for platform abort only.",
  }),
  assertion({
    assertionId: "RESERVED_PLATFORM_ABORT_WORDING_MATCH",
    rulingIds: ["CT2A1-CUSTOMER-04", "CT2A1-RESERVED-01"],
    fixtureId: "reserved_global_abort",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection starting from runReservedScan before real reserved execution",
    baseEvidence: BASE_EVIDENCE.RESERVED_DIRECT_COMPOSITION,
    expectedObserved: "Reserved scan lacks the isolated, provenance-aware CT boundary.",
    requiredCorrected: "Real reserved execution publishes the same canonical platform-abort wording.",
    claimLimit: "Capability absence only; final proof must execute runReservedScan.",
  }),
  assertion({
    assertionId: "SENTINEL_ERROR_PRECEDENCE",
    rulingIds: ["CT2A1-SENTINEL-02", "CT2A1-INVENTORY-01"],
    fixtureId: "inventory_detector_calibration",
    baseCarrier: "Mechanical AST detector calibration over direct, alias, computed, helper and transport forms",
    expectedObserved: "Unsafe count decisions are detected and non-null error dominance is required.",
    requiredCorrected: "The same fail-closed detector governs the final derived inventory.",
    claimLimit: "Tests detector semantics; it does not pin or certify the final runtime inventory.",
  }),
  assertion({
    assertionId: "SOURCE_SET_VERSION_IS_V2",
    rulingIds: ["CT2A1-VERSION-01"],
    fixtureId: "source_set_version",
    failureClass: "BEHAVIOURAL",
    baseCarrier: "Public CT_PROVIDER_OVERLAP_SOURCE_SET_VERSION export",
    baseEvidence: BASE_EVIDENCE.SOURCE_SET_V1,
    expectedObserved: "ct-provider-overlap/1",
    requiredCorrected: "ct-provider-overlap/2",
    claimLimit: "Does not reinterpret or backfill v1 history.",
  }),
  assertion({
    assertionId: "V1_ROWS_ARE_DECISION_QUARANTINED",
    rulingIds: ["CT2A1-VERSION-01"],
    fixtureId: "analyzer_v1_quarantine",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection on analyzer cohort output",
    baseEvidence: BASE_EVIDENCE.ANALYZER_OUTPUT_WITHOUT_PLATFORM_POPULATION,
    expectedObserved: "No decision-grade v2-only cohort gate exists.",
    requiredCorrected: "Decision analysis excludes v1 and rejects mixed v1/v2 aggregates.",
    claimLimit: "Proves analyzer capability absence, not any conclusion from historical v1 rows.",
  }),
  assertion({
    assertionId: "INVENTORY_MECHANISM_IS_UNPINNED",
    rulingIds: ["CT2A1-INVENTORY-01"],
    fixtureId: "inventory_detector_metadata",
    baseCarrier: "Oracle-only inventory detector metadata and calibration",
    expectedObserved: "The detector has no final runtime count, set or fingerprint pin.",
    requiredCorrected: "Only the later measured final-head inventory may be pinned.",
    claimLimit: "Proves freeze discipline, not final runtime completeness.",
  }),
  assertion({
    assertionId: "EXACT_PLATFORM_ABORT_VOCABULARY",
    rulingIds: ["CT2A1-VOCAB-01"],
    fixtureId: "state_machine_exports",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection on exported CT-R1 and overlap vocabularies",
    baseEvidence: ADDITIONAL_BASE_EVIDENCE.TELEMETRY_OUTCOME_VOCABULARY,
    expectedObserved: "The three platform-abort strings are absent; release-before-abort strings exist.",
    requiredCorrected: "All five exact strings from CT2A1-VOCAB-01 are present in their proper vocabularies.",
    claimLimit: "Proves representational capability, not migration application.",
  }),
  assertion({
    assertionId: "ANALYZER_COUNTS_DIRECT_ATTEMPT_POPULATION",
    rulingIds: ["CT2A1-PROV-01", "CT2A1-VERSION-01"],
    fixtureId: "analyzer_population",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection on analyzeCtProviderTelemetry() output",
    baseEvidence: BASE_EVIDENCE.ANALYZER_OUTPUT_WITHOUT_PLATFORM_POPULATION,
    expectedObserved: "No platform-deadline population or source-set cohort breakdown exists.",
    requiredCorrected: "Direct attempt count precedes impact filtering and reports total, impact, module/provider and cohort scopes.",
    claimLimit: "Makes no claim about historical platform-abort frequency.",
  }),
  assertion({
    assertionId: "RESERVED_PATH_USES_ISOLATED_BOUNDARY",
    rulingIds: ["CT2A1-CACHE-01", "CT2A1-CACHE-02", "CT2A1-RESERVED-01"],
    fixtureId: "reserved_real_composition",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection from actual runReservedScan composition",
    baseEvidence: BASE_EVIDENCE.RESERVED_DIRECT_COMPOSITION,
    expectedObserved: "runReservedScan directly gates SSL and subdomains without the shared release boundary.",
    requiredCorrected: "Real reserved execution proves isolation, provenance ordering, one request and no late mutation.",
    claimLimit: "Structural absence is not final proof; helper existence and static source checks are insufficient.",
  }),
  assertion({
    assertionId: "CT_R1_OVERLAP_CAUSAL_COHERENCE",
    rulingIds: ["CT2A1-PROV-01", "CT2A1-PROV-03"],
    fixtureId: "real_abort_before_release",
    failureClass: "STRUCTURAL",
    baseCarrier: "Feature detection before one real global event drives cache telemetry and overlap freeze",
    baseEvidence: BASE_EVIDENCE.GLOBAL_DEADLINE_API,
    expectedObserved: "The base cannot expose one structured event to both tables.",
    requiredCorrected: "One canonical deadline event yields CT-R1 platform_deadline_abort and overlap platform-abort states.",
    claimLimit: "Proves shared causal capability absence; final proof requires real composition.",
  }),
]);

export const CT_ISOLATION_OLD_RUNTIME_FAILURE_CLASSIFICATIONS = Object.freeze(
  CT_ISOLATION_ASSERTIONS.filter((entry) => entry.expected_old_runtime_result === "FAIL"),
);
export const CT_ISOLATION_OLD_RUNTIME_FAILURE_IDS = Object.freeze(
  CT_ISOLATION_OLD_RUNTIME_FAILURE_CLASSIFICATIONS.map((entry) => entry.assertion_id),
);
export const CT_ISOLATION_OLD_RUNTIME_POSITIVE_CONTROLS = Object.freeze(
  CT_ISOLATION_ASSERTIONS.filter((entry) => entry.expected_old_runtime_result === "PASS"),
);
export const CT_ISOLATION_OLD_RUNTIME_PASS_IDS = Object.freeze(
  CT_ISOLATION_OLD_RUNTIME_POSITIVE_CONTROLS.map((entry) => entry.assertion_id),
);

const mutant = (mutantId, expectedFailureIds) => Object.freeze({
  mutant_id: mutantId,
  expected_failure_ids: Object.freeze([...expectedFailureIds]),
});

// Exact ordered FAIL sets are frozen before either oracle or mutant execution.
export const CT_ISOLATION_SEMANTIC_MUTANTS = Object.freeze([
  mutant("DUPLICATE_PHYSICAL_REQUEST", ["SHARED_PHYSICAL_REQUEST_ONE", "CT_R1_LATE_SUCCESS_IS_OK", "RESERVED_PATH_USES_ISOLATED_BOUNDARY"]),
  mutant("RESTORE_FIRST_CONSUMER_SIGNAL_CAPTURE", ["SSL_RELEASE_IS_CONSUMER_ONLY", "SIBLING_LATE_SUCCESS_RECEIVED", "CT_R1_LATE_SUCCESS_IS_OK", "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL"]),
  mutant("ACCEPT_LATE_RESULT_FOR_RELEASED_CONSUMER", ["SSL_RELEASE_IS_CONSUMER_ONLY", "RELEASED_CONSUMER_REJECTS_LATE_RESULT", "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL"]),
  mutant("ALLOW_LATE_RESERVED_PUBLICATION", ["SSL_RELEASE_IS_CONSUMER_ONLY", "RELEASED_CONSUMER_REJECTS_LATE_RESULT", "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL", "RELEASED_OUTPUT_IMMUTABLE"]),
  mutant("COLLAPSE_SUCCESSFUL_EMPTY", ["SUCCESSFUL_EMPTY_IS_ZERO"]),
  mutant("ERASE_GENUINE_PROVIDER_FAILURE", ["GENUINE_FAILURE_REMAINS_PROVIDER_FAILURE", "CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL"]),
  mutant("ERASE_STRUCTURED_DEADLINE_OWNER", ["STRUCTURED_GLOBAL_DEADLINE_PROVENANCE", "CT_R1_GLOBAL_DEADLINE_CAUSE", "ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT", "PA_IF_UNREACHABLE_ON_SHARED_SIGNAL", "CUSTOMER_PLATFORM_ABORT_WORDING_EXACT", "CUSTOMER_PLATFORM_ABORT_FORBIDS_PROVIDER_FAILURE", "SSL_SUBDOMAINS_PLATFORM_ABORT_WORDING_MATCH", "CT_R1_OVERLAP_CAUSAL_COHERENCE"]),
  mutant("LOSE_GLOBAL_DEADLINE_CANCELLATION", ["GLOBAL_DEADLINE_STOPS_PHYSICAL_WORK", "CT_R1_GLOBAL_DEADLINE_CAUSE", "CUSTOMER_PLATFORM_ABORT_WORDING_EXACT", "CUSTOMER_PLATFORM_ABORT_FORBIDS_PROVIDER_FAILURE", "SSL_SUBDOMAINS_PLATFORM_ABORT_WORDING_MATCH", "CT_R1_OVERLAP_CAUSAL_COHERENCE"]),
  mutant("CONFUSE_CONSUMER_AND_PHYSICAL_STATE", ["CONSUMER_STATE_SEPARATE_FROM_PHYSICAL", "CONSUMER_FAILURE_STATE_MATCHES_PHYSICAL"]),
  mutant("COLLAPSE_STATE_MACHINE_TYPES", ["STATE_MACHINE_TYPES_REMAIN_DISTINCT"]),
  mutant("ABORT_BEFORE_RELEASE_AS_IN_FLIGHT", ["ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT", "PA_IF_UNREACHABLE_ON_SHARED_SIGNAL", "CT_R1_OVERLAP_CAUSAL_COHERENCE"]),
  mutant("RELEASE_BEFORE_ABORT_AS_PLATFORM_ABORT", ["RELEASE_BEFORE_ABORT_IS_IN_FLIGHT"]),
  mutant("ALLOW_LATE_OVERLAP_OBSERVE", ["FROZEN_OVERLAP_REJECTS_LATE_OBSERVE"]),
  mutant("ADMIT_PA_IF_SHARED_SIGNAL", ["PA_IF_UNREACHABLE_ON_SHARED_SIGNAL"]),
  mutant("COLLAPSE_PERSISTENCE_OUTCOME", ["PERSISTENCE_OUTCOME_IS_INDEPENDENT"]),
  mutant("TYPO_PLATFORM_ABORT_WORDING", ["CUSTOMER_PLATFORM_ABORT_WORDING_EXACT", "CUSTOMER_PLATFORM_ABORT_FORBIDS_PROVIDER_FAILURE", "SSL_SUBDOMAINS_PLATFORM_ABORT_WORDING_MATCH"]),
  mutant("PLATFORM_ABORT_AS_PROVIDER_UNAVAILABLE", ["CUSTOMER_PLATFORM_ABORT_WORDING_EXACT", "CUSTOMER_PLATFORM_ABORT_FORBIDS_PROVIDER_FAILURE", "SSL_SUBDOMAINS_PLATFORM_ABORT_WORDING_MATCH"]),
  mutant("LEAK_LIFECYCLE_INTO_SOURCE_OBJECT", ["CUSTOMER_SOURCE_SCHEMA_IS_STABLE", "CUSTOMER_SOURCE_HAS_NO_LIFECYCLE_FIELDS"]),
  mutant("DRIFT_SSL_PLATFORM_WORDING", ["CUSTOMER_PLATFORM_ABORT_WORDING_EXACT", "CUSTOMER_PLATFORM_ABORT_FORBIDS_PROVIDER_FAILURE", "SSL_SUBDOMAINS_PLATFORM_ABORT_WORDING_MATCH"]),
  mutant("DRIFT_RESERVED_PLATFORM_WORDING", ["RESERVED_PLATFORM_ABORT_WORDING_MATCH"]),
  mutant("IGNORE_SENTINEL_ERROR_PRECEDENCE", ["SENTINEL_ERROR_PRECEDENCE"]),
  mutant("RESTORE_SOURCE_SET_V1", ["SOURCE_SET_VERSION_IS_V2"]),
  mutant("ALLOW_V1_DECISION_ROWS", ["V1_ROWS_ARE_DECISION_QUARANTINED"]),
  mutant("PIN_INVENTORY_BEFORE_RUNTIME", ["INVENTORY_MECHANISM_IS_UNPINNED"]),
  mutant("OMIT_PLATFORM_ABORT_VOCABULARY", ["STATE_MACHINE_TYPES_REMAIN_DISTINCT", "EXACT_PLATFORM_ABORT_VOCABULARY"]),
  mutant("FILTER_ATTEMPTS_BY_IMPACT_FIRST", ["ANALYZER_COUNTS_DIRECT_ATTEMPT_POPULATION"]),
  mutant("OMIT_RESERVED_CONSUMER_BOUNDARY", ["ABORT_BEFORE_RELEASE_IS_PLATFORM_ABORT", "RESERVED_PATH_USES_ISOLATED_BOUNDARY"]),
  mutant("SPLIT_CT_R1_OVERLAP_PROVENANCE", ["CT_R1_GLOBAL_DEADLINE_CAUSE", "CT_R1_OVERLAP_CAUSAL_COHERENCE"]),
  mutant("REPORT_CONSUMER_RELEASE_AS_PROVIDER_FAILURE", ["SSL_RELEASE_IS_CONSUMER_ONLY", "RELEASED_CONSUMER_REJECTS_LATE_RESULT", "CONSUMER_STATE_SEPARATE_FROM_PHYSICAL"]),
]);

export const CT_ISOLATION_HARNESS_CONTROLS = Object.freeze([
  "HARNESS_REJECTS_SYNTAX_OR_IMPORT_FAILURE",
  "HARNESS_REJECTS_WRONG_FAILURE_SET",
]);
