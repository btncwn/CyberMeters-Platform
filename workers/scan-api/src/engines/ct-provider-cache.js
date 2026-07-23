// Per-scan Certificate Transparency provider cache.
//
// Provider responses are parsed once and cached as an in-flight promise so concurrent
// SSL and subdomain consumers share one outbound request. A successful empty response
// remains distinct from an unavailable provider; failures never collapse to [].
import { customerSafeFailure } from "../lib/errors.js";

const PROVIDERS = Object.freeze({
  crt_sh: {
    timeoutMs: 8_000,
    // One suffix-wide response covers both the former apex certificate lookup and
    // the former %.domain discovery lookup. Consumers restore their prior view.
    url: (domain) => `https://crt.sh/?q=${encodeURIComponent("%" + domain)}&output=json`,
    fetchContext: "scan/ct/crt-sh",
    parseContext: "scan/ct/crt-sh-parse",
  },
  certspotter: {
    timeoutMs: 8_000,
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

async function fetchProvider(config, provider, domain, { accounting, fetcher, signal }) {
  let attempted = false;
  let response;
  try {
    accounting?.assertCanIssue?.();
    accounting?.recordAttempt?.();
    attempted = true;
    response = await fetcher(config.url(domain), {
      headers: { Accept: "application/json", "User-Agent": "CyberMeters/1.0" },
      signal: combineSignals(signal, accounting?.signal, AbortSignal.timeout(config.timeoutMs)),
    });
    accounting?.recordCompleted?.();
  } catch (err) {
    if (attempted) accounting?.recordError?.(err);
    return unavailable(
      provider,
      domain,
      customerSafeFailure(config.fetchContext, err, "fetch failed")
    );
  }

  if (!response?.ok) {
    return unavailable(provider, domain, `HTTP ${response?.status ?? "unknown"}`);
  }

  const contentType = response.headers?.get?.("content-type") || "";
  if (!contentType.includes("json")) {
    return unavailable(provider, domain, "non-JSON response");
  }

  try {
    const data = await response.json();
    if (!Array.isArray(data)) {
      return unavailable(provider, domain, "unexpected response shape");
    }
    return {
      provider,
      domain,
      status: "available",
      data,
      error: null,
    };
  } catch (err) {
    return unavailable(
      provider,
      domain,
      customerSafeFailure(config.parseContext, err, "parse error")
    );
  }
}

export function createCertificateTransparencyCache({
  fetcher = globalThis.fetch,
  signal = null,
} = {}) {
  if (typeof fetcher !== "function") {
    throw new TypeError("Certificate Transparency cache requires a fetch function");
  }

  const entries = new Map();

  return {
    get(domain, provider, { accounting = null } = {}) {
      const normalizedDomain = normalizeDomain(domain);
      const config = PROVIDERS[provider];
      if (!normalizedDomain) {
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
          })
        );
      }
      return entries.get(key);
    },
  };
}
