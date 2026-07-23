// Per-scan Certificate Transparency provider cache.
//
// Provider responses are parsed once and cached as an in-flight promise so concurrent
// SSL and subdomain consumers share one outbound request. A successful empty response
// remains distinct from an unavailable provider; failures never collapse to [].
import { customerSafeFailure } from "../lib/errors.js";

// One retry restores bounded resilience after PR-5.2 removed the duplicate
// per-consumer lookups. The hard cap is deliberately independent of tunable policy.
export const CT_PROVIDER_HARD_ATTEMPT_CAP = 2;
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

function transientHttpStatus(status) {
  return status === 408 || status === 429 || (status >= 500 && status <= 599);
}

async function fetchAttempt(config, provider, domain, {
  accounting,
  fetcher,
  signal,
  timeoutMs,
  timeoutSignal,
}) {
  let attempted = false;
  let response;
  try {
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
    return {
      result: unavailable(
        provider,
        domain,
        customerSafeFailure(config.fetchContext, err, "fetch failed")
      ),
      transient: attempted && !externallyAborted(signal, accounting),
    };
  }

  if (!response?.ok) {
    const status = Number(response?.status);
    return {
      result: unavailable(provider, domain, `HTTP ${response?.status ?? "unknown"}`),
      transient: transientHttpStatus(status),
    };
  }

  const contentType = response.headers?.get?.("content-type") || "";
  if (!contentType.includes("json")) {
    return {
      result: unavailable(provider, domain, "non-JSON response"),
      transient: false,
    };
  }

  try {
    const data = await response.json();
    if (!Array.isArray(data)) {
      return {
        result: unavailable(provider, domain, "unexpected response shape"),
        transient: false,
      };
    }
    return {
      result: {
        provider,
        domain,
        status: "available",
        data,
        error: null,
      },
      transient: false,
    };
  } catch (err) {
    return {
      result: unavailable(
        provider,
        domain,
        customerSafeFailure(config.parseContext, err, "parse error")
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
  remainingMs,
  now,
  sleep,
  timeoutSignal,
  recordHealth,
}) {
  const startedMs = now();
  let attempts = 0;
  let finalResult = unavailable(provider, domain, "scan budget exhausted");

  while (attempts < policy.maxAttempts) {
    const remaining = remainingBudgetMs(remainingMs, accounting);
    if (remaining <= 0 || externallyAborted(signal, accounting)) break;

    const attemptTimeoutMs = Math.min(policy.timeoutMs, remaining);
    attempts += 1;
    const attempt = await fetchAttempt(config, provider, domain, {
      accounting,
      fetcher,
      signal,
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
  fetcher = globalThis.fetch,
  signal = null,
  policies = CT_PROVIDER_POLICIES,
  remainingMs = null,
  now = Date.now,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  timeoutSignal = (ms) => AbortSignal.timeout(ms),
} = {}) {
  if (typeof fetcher !== "function") {
    throw new TypeError("Certificate Transparency cache requires a fetch function");
  }

  const entries = new Map();
  const providerHealth = new Map();
  const recordHealth = (provider, row) => {
    providerHealth.set(provider, {
      outcome: row.outcome,
      attempts: row.attempts,
      latency_ms: row.latency_ms,
      final_error: row.final_error,
    });
  };

  return {
    get(domain, provider, { accounting = null } = {}) {
      const normalizedDomain = normalizeDomain(domain);
      const config = PROVIDERS[provider];
      if (!normalizedDomain) {
        recordHealth(provider, {
          outcome: "unavailable", attempts: 0, latency_ms: 0, final_error: "invalid domain",
        });
        return Promise.resolve(unavailable(provider, normalizedDomain, "invalid domain"));
      }
      if (!config) {
        return Promise.resolve(unavailable(provider, normalizedDomain, "unsupported provider"));
      }

      const key = `${normalizedDomain}\u0000${provider}`;
      if (!entries.has(key)) {
        entries.set(
          key,
          fetchProvider(config, provider, normalizedDomain, {
            accounting,
            fetcher,
            signal,
            policy: resolvePolicy(provider, policies),
            remainingMs,
            now,
            sleep,
            timeoutSignal,
            recordHealth,
          })
        );
      }
      return entries.get(key);
    },
    healthSnapshot() {
      return Object.fromEntries(
        [...providerHealth.entries()].map(([provider, row]) => [provider, { ...row }])
      );
    },
  };
}
