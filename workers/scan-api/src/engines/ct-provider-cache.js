// Per-scan Certificate Transparency provider cache.
//
// Provider responses are parsed once and cached as an in-flight promise so concurrent
// SSL and subdomain consumers share one outbound request. A successful empty response
// remains distinct from an unavailable provider; failures never collapse to [].
import { customerSafeFailure } from "../lib/errors.js";

// One retry restores bounded resilience after PR-5.2 removed the duplicate
// per-consumer lookups. The hard cap is deliberately independent of tunable policy.
export const CT_PROVIDER_HARD_ATTEMPT_CAP = 2;
export const CT_PROVIDER_TELEMETRY_ROW_LIMIT = 8;
export const CT_PROVIDER_TELEMETRY_OUTCOMES = Object.freeze([
  "ok",
  "timeout",
  "http_error",
  "parse_error",
  "rate_limited",
  "network_error",
  "platform_deadline_abort",
]);
export const CT_PROVIDER_PHYSICAL_ATTEMPT_STATES = Object.freeze([
  "in_flight",
  "terminal_success",
  "terminal_failure",
  "global_deadline_aborted",
]);
export const CT_PROVIDER_CONSUMER_WAIT_STATES = Object.freeze([
  "waiting",
  "received_success",
  "received_failure",
  "released_budget_exhausted",
]);
export const CT_PROVIDER_PLATFORM_ABORT_CUSTOMER_WORDING =
  "CyberMeters did not observe the provider result within the scan's global execution window.";
// A consumer release is neither a provider failure nor a platform abort: this
// module stopped waiting, and says so without attributing a cause to anyone.
export const CT_PROVIDER_CONSUMER_RELEASE_CUSTOMER_WORDING =
  "CyberMeters did not receive the provider result before this module's observation budget ended.";
export const CT_PROVIDER_FIRST_SUCCESS_RELEASE_CUSTOMER_WORDING =
  "CyberMeters released this module after another Certificate Transparency provider succeeded; this provider result was still in flight and was excluded from the immutable module output.";
const CT_PROVIDER_TELEMETRY_MODULES = Object.freeze(["ssl", "subdomains"]);
const CT_PROVIDER_PHYSICAL_ATTEMPT_LIMIT = 4;
export const CT_PROVIDER_POLICIES = Object.freeze({
  // crt.sh serves a broad suffix query and is historically the slower provider.
  crt_sh: Object.freeze({ timeoutMs: 6_000, maxAttempts: 2, backoffMs: 150 }),
  // CertSpotter is a narrower indexed API and should normally answer faster.
  certspotter: Object.freeze({ timeoutMs: 4_000, maxAttempts: 2, backoffMs: 100 }),
});

const PROVIDERS = Object.freeze({
  crt_sh: {
    // One suffix-wide response covers both the former apex certificate lookup and
    // the former %.domain discovery lookup. Consumers restore their prior view.
    url: (domain) => `https://crt.sh/?q=${encodeURIComponent("%" + domain)}&output=json`,
    fetchContext: "scan/ct/crt-sh",
    parseContext: "scan/ct/crt-sh-parse",
  },
  certspotter: {
    url: (domain) =>
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`,
    fetchContext: "scan/ct/certspotter",
    parseContext: "scan/ct/certspotter-parse",
  },
});

function combineSignals(...signals) {
  const active = signals.filter(Boolean);
  if (active.length === 0) return undefined;
  if (active.length === 1) return active[0];
  if (typeof AbortSignal.any === "function") return AbortSignal.any(active);
  const controller = new AbortController();
  const abort = () => {
    const aborted = active.find((candidate) => candidate.aborted);
    controller.abort(aborted?.reason);
  };
  for (const signal of active) {
    if (signal.aborted) {
      abort();
      break;
    }
    signal.addEventListener("abort", abort, { once: true });
  }
  return controller.signal;
}

function normalizeDomain(domain) {
  return String(domain || "").trim().toLowerCase().replace(/\.$/, "");
}

function unavailable(provider, domain, error) {
  return {
    provider,
    domain,
    status: "unavailable",
    data: null,
    error,
    physical_attempt_state: "terminal_failure",
  };
}

function withPhysicalAttemptState(result, physicalAttemptState, provenance = null) {
  return {
    ...result,
    physical_attempt_state: physicalAttemptState,
    ...(provenance ? { platform_abort_provenance: { ...provenance } } : {}),
  };
}

function boundedInteger(value, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(parsed)));
}

function resolvePolicy(provider, policies) {
  const defaults = CT_PROVIDER_POLICIES[provider];
  const override = policies?.[provider] || {};
  return {
    timeoutMs: boundedInteger(override.timeoutMs, defaults.timeoutMs, { min: 1 }),
    maxAttempts: Math.min(
      CT_PROVIDER_HARD_ATTEMPT_CAP,
      boundedInteger(override.maxAttempts, defaults.maxAttempts, { min: 1 })
    ),
    backoffMs: boundedInteger(override.backoffMs, defaults.backoffMs, { min: 0 }),
  };
}

function remainingBudgetMs(remainingMs, accounting) {
  const values = [];
  for (const read of [remainingMs, accounting?.remainingMs]) {
    if (typeof read !== "function") continue;
    try {
      const value = Number(read());
      if (Number.isFinite(value)) values.push(Math.max(0, Math.floor(value)));
    } catch {
      values.push(0);
    }
  }
  return values.length > 0 ? Math.min(...values) : Infinity;
}

function externallyAborted(signal, accounting) {
  return signal?.aborted === true || accounting?.signal?.aborted === true;
}

// The two platform-abort verdicts have DIFFERENT carriers, and conflating them
// is what lets a genuine transport failure be relabelled as a platform abort.
//
//  - The customer projection asks "did OUR cancellation stop this request?".
//    Only the global deadline aborts a physical entry's controller, so the
//    aborted physical signal itself is the evidence. We never blame a provider
//    for work CyberMeters stopped.
//  - The CT-R1 evidence row asks "may we RECORD the platform cause?". That
//    requires the canonical structured deadline event to be carried on the
//    abort reason. Without it we record the transport outcome and make no
//    platform claim, rather than inventing one from an ambient read.
function physicalAbortStoppedRequest(signal) {
  if (signal?.aborted !== true) return false;
  const reason = signal.reason;
  // Only the scan-global deadline ever aborts a physical entry, so an
  // unstructured reason still leaves that cause standing. A structured carrier
  // that names a DIFFERENT owner is positive evidence against it, and we do not
  // claim a cause the evidence contradicts.
  if (reason && typeof reason === "object" && "owner" in reason) {
    return reason.owner === "scan_global_deadline";
  }
  return true;
}

// A release cause may arrive as a bare string or as the structured provenance
// object carried on an abort reason.
function isGlobalDeadlineCause(cause) {
  if (cause && typeof cause === "object") return cause.owner === "scan_global_deadline";
  return String(cause || "") === "scan_global_deadline";
}

function structuredAbortProvenance(signal) {
  if (signal?.aborted !== true) return null;
  const reason = signal.reason;
  return reason?.aborted === true && reason.owner === "scan_global_deadline"
    ? reason
    : null;
}

function transientHttpStatus(status) {
  return status === 408 || status === 429 || (status >= 500 && status <= 599);
}

function timeoutFailure(error) {
  const name = String(error?.name || "").toLowerCase();
  const message = String(error?.message || error || "").toLowerCase();
  return name === "timeouterror" || message.includes("timeout") || message.includes("timed out");
}

function safeAttemptObservation(recordAttempt, row) {
  try {
    recordAttempt?.(row);
  } catch {
    // CT-R1 is observational only. A collector defect cannot change provider I/O.
  }
}

function readTelemetryClock(clock) {
  try {
    const value = Number(clock?.());
    return Number.isFinite(value) && Math.abs(value) <= 8.64e15
      ? value
      : Date.now();
  } catch {
    return Date.now();
  }
}

async function fetchAttempt(config, provider, domain, {
  accounting,
  fetcher,
  recordAttempt,
  readGlobalDeadlineProvenance,
  signal,
  telemetryNow,
  timeoutMs,
  timeoutSignal,
}) {
  const startedMs = readTelemetryClock(telemetryNow);
  let attempted = false;
  let response;
  try {
    accounting?.assertCanIssue?.();
    accounting?.recordAttempt?.();
    attempted = true;
    response = await fetcher(config.url(domain), {
      headers: { Accept: "application/json", "User-Agent": "CyberMeters/1.0" },
      redirect: "manual",
      signal: combineSignals(signal, accounting?.signal, timeoutSignal(timeoutMs)),
    });
    accounting?.recordCompleted?.();
  } catch (err) {
    if (attempted) accounting?.recordError?.(err);
    const completedMs = readTelemetryClock(telemetryNow);
    const stoppedByPlatform = physicalAbortStoppedRequest(signal);
    const provenance = structuredAbortProvenance(signal);
    if (attempted) {
      safeAttemptObservation(recordAttempt, {
        provider,
        outcome: provenance
          ? "platform_deadline_abort"
          : (timeoutFailure(err) ? "timeout" : "network_error"),
        http_status: null,
        latency_ms: Math.max(0, completedMs - startedMs),
        result_count: null,
        started_at: new Date(startedMs).toISOString(),
        completed_at: new Date(completedMs).toISOString(),
        cache_state: "miss",
        cache_age_s: null,
      });
    }
    return {
      result: stoppedByPlatform
        ? withPhysicalAttemptState(
          unavailable(provider, domain, CT_PROVIDER_PLATFORM_ABORT_CUSTOMER_WORDING),
          "global_deadline_aborted",
          provenance,
        )
        : withPhysicalAttemptState(
          unavailable(
            provider,
            domain,
            customerSafeFailure(config.fetchContext, err, "fetch failed")
          ),
          "terminal_failure",
        ),
      transient: attempted && !stoppedByPlatform && !externallyAborted(signal, accounting),
    };
  }

  const responseStatus = Number(response?.status);
  if (Number.isInteger(responseStatus) && responseStatus >= 300 && responseStatus <= 399) {
    const completedMs = readTelemetryClock(telemetryNow);
    safeAttemptObservation(recordAttempt, {
      provider,
      outcome: "http_error",
      redirect_disposition: "redirect_refused",
      http_status: responseStatus,
      latency_ms: Math.max(0, completedMs - startedMs),
      result_count: null,
      started_at: new Date(startedMs).toISOString(),
      completed_at: new Date(completedMs).toISOString(),
      cache_state: "miss",
      cache_age_s: null,
    });
    return {
      result: withPhysicalAttemptState(
        unavailable(provider, domain, "redirect_refused"),
        "terminal_failure",
      ),
      transient: false,
    };
  }

  if (!response?.ok) {
    const status = Number(response?.status);
    const completedMs = readTelemetryClock(telemetryNow);
    safeAttemptObservation(recordAttempt, {
      provider,
      outcome: status === 429
        ? "rate_limited"
        : (status === 408 ? "timeout" : "http_error"),
      http_status: Number.isInteger(status) ? status : null,
      latency_ms: Math.max(0, completedMs - startedMs),
      result_count: null,
      started_at: new Date(startedMs).toISOString(),
      completed_at: new Date(completedMs).toISOString(),
      cache_state: "miss",
      cache_age_s: null,
    });
    return {
      result: unavailable(provider, domain, `HTTP ${response?.status ?? "unknown"}`),
      transient: transientHttpStatus(status),
    };
  }

  const contentType = response.headers?.get?.("content-type") || "";
  if (!contentType.includes("json")) {
    const completedMs = readTelemetryClock(telemetryNow);
    safeAttemptObservation(recordAttempt, {
      provider,
      outcome: "parse_error",
      http_status: Number.isInteger(Number(response?.status)) ? Number(response.status) : null,
      latency_ms: Math.max(0, completedMs - startedMs),
      result_count: null,
      started_at: new Date(startedMs).toISOString(),
      completed_at: new Date(completedMs).toISOString(),
      cache_state: "miss",
      cache_age_s: null,
    });
    return {
      result: withPhysicalAttemptState(
        unavailable(provider, domain, "non-JSON response"),
        "terminal_failure",
      ),
      transient: false,
    };
  }

  try {
    const data = await response.json();
    if (!Array.isArray(data)) {
      const completedMs = readTelemetryClock(telemetryNow);
      safeAttemptObservation(recordAttempt, {
        provider,
        outcome: "parse_error",
        http_status: Number.isInteger(Number(response?.status)) ? Number(response.status) : null,
        latency_ms: Math.max(0, completedMs - startedMs),
        result_count: null,
        started_at: new Date(startedMs).toISOString(),
        completed_at: new Date(completedMs).toISOString(),
        cache_state: "miss",
        cache_age_s: null,
      });
      return {
        result: withPhysicalAttemptState(
          unavailable(provider, domain, "unexpected response shape"),
          "terminal_failure",
        ),
        transient: false,
      };
    }
    const completedMs = readTelemetryClock(telemetryNow);
    safeAttemptObservation(recordAttempt, {
      provider,
      outcome: "ok",
      http_status: Number.isInteger(Number(response?.status)) ? Number(response.status) : null,
      latency_ms: Math.max(0, completedMs - startedMs),
      result_count: data.length,
      started_at: new Date(startedMs).toISOString(),
      completed_at: new Date(completedMs).toISOString(),
      cache_state: "miss",
      cache_age_s: null,
    });
    return {
      result: {
        provider,
        domain,
        status: "available",
        data,
        error: null,
        physical_attempt_state: "terminal_success",
      },
      transient: false,
    };
  } catch (err) {
    const completedMs = readTelemetryClock(telemetryNow);
    safeAttemptObservation(recordAttempt, {
      provider,
      outcome: "parse_error",
      http_status: Number.isInteger(Number(response?.status)) ? Number(response.status) : null,
      latency_ms: Math.max(0, completedMs - startedMs),
      result_count: null,
      started_at: new Date(startedMs).toISOString(),
      completed_at: new Date(completedMs).toISOString(),
      cache_state: "miss",
      cache_age_s: null,
    });
    return {
      result: withPhysicalAttemptState(
        unavailable(
          provider,
          domain,
          customerSafeFailure(config.parseContext, err, "parse error")
        ),
        "terminal_failure",
      ),
      transient: false,
    };
  }
}

async function fetchProvider(config, provider, domain, {
  accounting,
  fetcher,
  signal,
  policy,
  recordAttempt,
  readGlobalDeadlineProvenance,
  remainingMs,
  now,
  sleep,
  telemetryNow,
  timeoutSignal,
  recordHealth,
}) {
  const startedMs = now();
  let attempts = 0;
  let finalResult = withPhysicalAttemptState(
    unavailable(provider, domain, "scan budget exhausted"),
    "terminal_failure",
  );

  while (attempts < policy.maxAttempts) {
    const remaining = remainingBudgetMs(remainingMs, accounting);
    if (remaining <= 0 || externallyAborted(signal, accounting)) break;

    const attemptTimeoutMs = Math.min(policy.timeoutMs, remaining);
    attempts += 1;
    const attempt = await fetchAttempt(config, provider, domain, {
      accounting,
      fetcher,
      recordAttempt,
      readGlobalDeadlineProvenance,
      signal,
      telemetryNow,
      timeoutMs: attemptTimeoutMs,
      timeoutSignal,
    });
    finalResult = attempt.result;
    if (finalResult.status === "available") {
      recordHealth(provider, {
        outcome: "available",
        attempts,
        latency_ms: Math.max(0, now() - startedMs),
        final_error: null,
      });
      return finalResult;
    }

    if (!attempt.transient || attempts >= policy.maxAttempts) break;
    if (externallyAborted(signal, accounting)) break;
    const remainingAfterAttempt = remainingBudgetMs(remainingMs, accounting);
    if (remainingAfterAttempt <= policy.backoffMs) break;
    await sleep(policy.backoffMs);
  }

  recordHealth(provider, {
    outcome: "unavailable",
    attempts,
    latency_ms: Math.max(0, now() - startedMs),
    final_error: finalResult.error,
  });
  return finalResult;
}

export function createCertificateTransparencyCache({
  accounting: physicalAccounting = null,
  fetcher = globalThis.fetch,
  signal = null,
  globalDeadlineProvenance = null,
  policies = CT_PROVIDER_POLICIES,
  remainingMs = null,
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  captureTelemetry = true,
  telemetryNow = Date.now,
  timeoutSignal = (ms) => AbortSignal.timeout(ms),
} = {}) {
  if (typeof fetcher !== "function") {
    throw new TypeError("Certificate Transparency cache requires a fetch function");
  }

  const entries = new Map();
  const consumers = new Map();
  const providerHealth = new Map();
  const providerConsumers = new Map();
  const providerAttempts = [];
  // The classifier above is the sole producer of these rows and always emits a
  // declared outcome. Coercing an unrecognised value to "network_error" here
  // would silently rewrite a truthful platform-abort record into a false
  // provider-failure verdict, which is the exact substitution CT2A1-PROV-01
  // forbids; a guard that fails open into a wrong provider verdict is worse
  // than no guard. CT_PROVIDER_TELEMETRY_OUTCOMES stays the declared schema.
  const recordAttempt = (row) => {
    if (!captureTelemetry || providerAttempts.length >= CT_PROVIDER_PHYSICAL_ATTEMPT_LIMIT) return;
    const outcome = row?.outcome;
    providerAttempts.push({ ...row, outcome });
  };
  const recordHealth = (provider, row) => {
    providerHealth.set(provider, {
      outcome: row.outcome,
      attempts: row.attempts,
      latency_ms: row.latency_ms,
      final_error: row.final_error,
    });
  };

  const readGlobalDeadlineProvenance = () => {
    try {
      const value = globalDeadlineProvenance?.();
      if (value && typeof value === "object") return { ...value };
    } catch { /* fail closed to the signal below */ }
    const reason = signal?.reason;
    if (signal?.aborted === true) {
      if (reason && typeof reason === "object" && reason.owner === "scan_global_deadline") {
        return { ...reason, aborted: true };
      }
      return {
        aborted: true,
        owner: "scan_global_deadline",
        reason: String(reason || "scan_deadline_exhausted"),
        observed_at: null,
      };
    }
    return {
      aborted: false,
      owner: "scan_global_deadline",
      reason: null,
      observed_at: null,
    };
  };
  const physicalStateOf = (entry) => entry?.state || "in_flight";
  let pendingConsumerAccounting = null;
  const physicalAccountingFor = (domain, provider) => {
    let source = null;
    try {
      source = typeof physicalAccounting === "function"
        ? physicalAccounting({ domain, provider })
        : physicalAccounting;
    } catch { source = null; }
    source ||= pendingConsumerAccounting;
    if (!source) return null;
    // Preserve outbound-count observations and the platform's issue gate, but
    // never inherit a consumer's release signal or remaining budget. Whether a
    // NEW request may be ISSUED is a scan-level budget question; whether work
    // already in flight is CANCELLED is the consumer question that CT2A1-CACHE-01
    // forbids. Dropping assertCanIssue with the signal would let CT requests
    // escape the outbound ceiling entirely.
    return {
      assertCanIssue: source.assertCanIssue?.bind(source),
      recordAttempt: source.recordAttempt?.bind(source),
      recordCompleted: source.recordCompleted?.bind(source),
      recordError: source.recordError?.bind(source),
      markUnsettled: source.markUnsettled?.bind(source),
      markSettled: source.markSettled?.bind(source),
    };
  };
  const physicalEntry = (normalizedDomain, provider, config) => {
    const key = `${normalizedDomain}\u0000${provider}`;
    if (entries.has(key)) return entries.get(key);
    const controller = new AbortController();
    const abortFromGlobalDeadline = () => {
      const provenance = readGlobalDeadlineProvenance();
      controller.abort(provenance || signal?.reason || "scan_deadline_exhausted");
    };
    if (signal?.aborted) abortFromGlobalDeadline();
    else signal?.addEventListener?.("abort", abortFromGlobalDeadline, { once: true });
    const entry = {
      controller,
      state: "in_flight",
      promise: null,
    };
    const accounting = physicalAccountingFor(normalizedDomain, provider);
    entry.promise = fetchProvider(config, provider, normalizedDomain, {
      accounting,
      fetcher,
      signal: controller.signal,
      policy: resolvePolicy(provider, policies),
      recordAttempt: captureTelemetry ? recordAttempt : null,
      readGlobalDeadlineProvenance,
      remainingMs,
      now,
      sleep,
      telemetryNow,
      timeoutSignal,
      recordHealth,
    }).then((result) => {
      entry.state = result?.physical_attempt_state || (result?.status === "available"
        ? "terminal_success"
        : "terminal_failure");
      return result;
    });
    entries.set(key, entry);
    return entry;
  };
  const consumerKey = (domain, module, provider) => `${domain}\u0000${module}\u0000${provider}`;

  // Releasing a consumer records ONLY that consumer's wait state. The physical
  // attempt state is read, never written, so shared work is never terminated
  // and never reclassified as a provider failure.
  const releaseConsumerRecord = (record, cause) => {
    if (!record || record.state !== "waiting") return;
    record.state = "released_budget_exhausted";
    record.physicalAttemptState = physicalStateOf(record.entry);
    const globalDeadline = isGlobalDeadlineCause(cause);
    const firstSuccess = String(cause || "") === "first_success";
    record.releaseCause = globalDeadline
      ? "scan_global_deadline"
      : (firstSuccess ? "first_success" : String(cause || "module_budget_exhausted"));
    // The consumer's WAIT ends here; the shared physical work does not. Leaving
    // the wait pending would tie this consumer's lifetime to physical
    // settlement, which is precisely the separation CT2A1-PROV-02 requires.
    //
    // A release the scan-global deadline caused keeps the platform-abort
    // meaning, so SSL, subdomains and reserved all say the same thing about the
    // same cause rather than degrading it into a generic budget notice.
    record.customerEvidenceDisposition = firstSuccess
      ? "in_flight_excluded_after_first_success"
      : "in_flight_excluded_after_consumer_release";
    record.releasedResult = withPhysicalAttemptState(
      unavailable(
        record.provider,
        record.domain,
        globalDeadline
          ? CT_PROVIDER_PLATFORM_ABORT_CUSTOMER_WORDING
          : (firstSuccess
            ? CT_PROVIDER_FIRST_SUCCESS_RELEASE_CUSTOMER_WORDING
            : CT_PROVIDER_CONSUMER_RELEASE_CUSTOMER_WORDING),
      ),
      record.physicalAttemptState,
    );
    record.settleWait(record.releasedResult);
  };
  const releaseConsumer = (domain, module, cause = "module_budget_exhausted") => {
    const normalizedDomain = normalizeDomain(domain);
    for (const provider of Object.keys(PROVIDERS)) {
      releaseConsumerRecord(
        consumers.get(consumerKey(normalizedDomain, module, provider)),
        cause,
      );
    }
  };

  return {
    get(domain, provider, { accounting = null, module = null, signal: consumerSignal = null } = {}) {
      const normalizedDomain = normalizeDomain(domain);
      const config = PROVIDERS[provider];
      if (captureTelemetry && CT_PROVIDER_TELEMETRY_MODULES.includes(module)) {
        if (!providerConsumers.has(provider)) providerConsumers.set(provider, new Set());
        providerConsumers.get(provider).add(module);
      }
      if (!normalizedDomain) {
        recordHealth(provider, {
          outcome: "unavailable", attempts: 0, latency_ms: 0, final_error: "invalid domain",
        });
        return Promise.resolve(unavailable(provider, normalizedDomain, "invalid domain"));
      }
      if (!config) {
        return Promise.resolve(unavailable(provider, normalizedDomain, "unsupported provider"));
      }

      // Every get() reassigns this before physicalEntry() reads it, so the
      // physical attempt never inherits a later consumer's accounting.
      pendingConsumerAccounting = accounting;
      const entry = physicalEntry(normalizedDomain, provider, config);
      if (!module) return entry.promise;

      const key = consumerKey(normalizedDomain, module, provider);
      if (consumers.has(key)) return consumers.get(key).wait;
      let settleWait = null;
      const wait = new Promise((resolve) => { settleWait = resolve; });
      const record = {
        entry,
        domain: normalizedDomain,
        module,
        provider,
        state: "waiting",
        physicalAttemptState: physicalStateOf(entry),
        terminalPhysicalAttemptState: null,
        releaseCause: null,
        customerEvidenceDisposition: null,
        releasedResult: null,
        wait,
        settleWait,
      };
      consumers.set(key, record);
      entry.promise.then((result) => {
        if (record.state !== "waiting") {
          const succeeded = result?.status === "available";
          record.terminalPhysicalAttemptState = result?.physical_attempt_state
            || (succeeded ? "terminal_success" : "terminal_failure");
          const firstSuccessRelease = record.releaseCause === "first_success";
          record.customerEvidenceDisposition = succeeded
            ? (firstSuccessRelease
              ? "late_success_excluded_after_first_success"
              : "late_success_excluded_after_consumer_release")
            : (firstSuccessRelease
              ? "late_failure_after_first_success"
              : "late_failure_after_consumer_release");
        }
        if (record.state !== "waiting") return;
        const succeeded = result?.status === "available";
        record.state = succeeded ? "received_success" : "received_failure";
        record.physicalAttemptState = result?.physical_attempt_state
          || (succeeded ? "terminal_success" : "terminal_failure");
        record.terminalPhysicalAttemptState = record.physicalAttemptState;
        record.customerEvidenceDisposition = "included_before_release";
        record.settleWait(result);
      });
      // The scan-global deadline is NOT a consumer budget boundary. It stops the
      // shared physical work, and every waiting consumer is entitled to that
      // outcome; treating it as a consumer release would replace the honest
      // platform-abort result with a release notice and lose the cause.
      const releaseSignal = consumerSignal || accounting?.signal || null;
      if (releaseSignal && releaseSignal !== signal) {
        const release = () => releaseConsumer(normalizedDomain, module, releaseSignal.reason);
        if (releaseSignal.aborted) release();
        else releaseSignal.addEventListener?.("abort", release, { once: true });
      }
      return wait;
    },
    releaseConsumer,
    consumerSnapshot(domain, module) {
      const normalizedDomain = normalizeDomain(domain);
      const providers = {};
      for (const provider of Object.keys(PROVIDERS)) {
        const record = consumers.get(consumerKey(normalizedDomain, module, provider));
        if (!record) continue;
        providers[provider] = {
          consumer_wait_state: record.state,
          physical_attempt_state: record.physicalAttemptState,
          terminal_physical_attempt_state: record.terminalPhysicalAttemptState,
          release_cause: record.releaseCause,
          customer_evidence_disposition: record.customerEvidenceDisposition,
        };
      }
      return { module, providers };
    },
    physicalSnapshot(domain) {
      const normalizedDomain = normalizeDomain(domain);
      return Object.fromEntries(Object.keys(PROVIDERS).flatMap((provider) => {
        const entry = entries.get(`${normalizedDomain}\u0000${provider}`);
        return entry ? [[provider, physicalStateOf(entry)]] : [];
      }));
    },
    healthSnapshot() {
      return Object.fromEntries(
        [...providerHealth.entries()].map(([provider, row]) => [provider, { ...row }])
      );
    },
    telemetrySnapshot({ modules = {}, scanQuality = null } = {}) {
      const subdomains = modules?.subdomains || {};
      // D1 Option D (FD-006 seq 50): a single-provider loss still REDUCES
      // completeness, so its telemetry impact must still be recorded. The legacy
      // signal was the blanket `incomplete` flag, which the governed case no
      // longer sets — without this the impact row would silently disappear for
      // exactly the case D1 governs, which is a monitoring loss, not a fix.
      // Additive: the legacy reasons keep working unchanged.
      const ctDegradedScan = scanQuality?.status !== "complete" && (
        (subdomains?.incomplete === true &&
          ["ct_source_degraded", "ct_sources_unavailable"].includes(
            subdomains?.incomplete_reason
          )) ||
        (Array.isArray(subdomains?.degradations) && subdomains.degradations.length > 0)
      );
      const rows = [];
      for (const attempt of providerAttempts) {
        for (const module of providerConsumers.get(attempt.provider) || []) {
          if (rows.length >= CT_PROVIDER_TELEMETRY_ROW_LIMIT) return rows;
          const consumerRecord = [...consumers.values()].find((record) =>
            record.module === module && record.provider === attempt.provider);
          const completenessImpact = module === "subdomains" &&
            attempt.outcome !== "ok" &&
            ctDegradedScan &&
            Boolean(subdomains?.sources?.[attempt.provider]?.error);
          rows.push({
            module,
            ...attempt,
            customer_evidence_disposition:
              consumerRecord?.customerEvidenceDisposition ?? null,
            completeness_impact: completenessImpact,
            affected_signal: completenessImpact ? "subdomain_discovery" : null,
          });
        }
      }
      return rows;
    },
  };
}
