// ── DNS resolution engine ─────────────────────────────────────────────────────
// DoH resolvers (Cloudflare / Google / Quad9) + resolver cross-check.
// Pure module: depends only on global fetch/AbortSignal. Extracted verbatim from
// index.js (monolith decomposition, Phase 1). Behavior-preserving — no logic change.
import { dnsCacheKey } from "./scan-budget.js";

function combineSignals(...signals) {
  const active = signals.filter(Boolean);
  if (active.length === 0) return undefined;
  if (active.length === 1) return active[0];
  if (typeof AbortSignal.any === "function") return AbortSignal.any(active);
  const controller = new AbortController();
  const abort = () => {
    const aborted = active.find((s) => s.aborted);
    controller.abort(aborted?.reason);
  };
  for (const signal of active) {
    if (signal.aborted) { abort(); break; }
    signal.addEventListener("abort", abort, { once: true });
  }
  return controller.signal;
}

function cacheDecorated(value, disposition) {
  if (!value || typeof value !== "object") return value;
  return { ...value, cache_disposition: disposition };
}

function refuseProviderRedirect(response, accounting, provider) {
  const status = Number(response?.status);
  if (!Number.isInteger(status) || status < 300 || status > 399) return;
  const error = new Error(`${provider} redirect_refused`);
  error.code = "redirect_refused";
  error.outcome = "redirect_refused";
  error.provider = provider;
  error.http_status = status;
  accounting?.recordError?.(error);
  throw error;
}

// Invocation-scoped question dedupe. The promise is inserted before it is
// awaited, matching the shared CT-cache law: concurrent DNS/Email/DMARC
// consumers share one physical provider attempt. Rejections are deliberately
// cached as rejections for this invocation; a failed lookup must not be retried
// by a second consumer and then misrepresented as one coherent observation.
async function runCachedDnsQuestion(cache, key, producer) {
  if (!cache) return producer();
  const existing = cache.get(key);
  if (existing?.promise) {
    const disposition = existing.settled ? "completed_hit" : "in_flight_hit";
    return cacheDecorated(await existing.promise, disposition);
  }
  // Backwards-compatible read for a caller-provided legacy value cache.
  if (existing !== undefined) return cacheDecorated(existing, "completed_hit");

  const entry = { promise: null, settled: false };
  entry.promise = Promise.resolve()
    .then(producer)
    .finally(() => { entry.settled = true; });
  cache.set(key, entry);
  return cacheDecorated(await entry.promise, "miss");
}

async function fetchCloudflareDns(name, type, opts, dnssecProfile) {
  opts.accounting?.assertCanIssue?.();
  opts.accounting?.recordAttempt?.();
  let attemptInFlight = true;
  let res;
  const doDnssec = dnssecProfile === "do1";
  try {
    res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}${doDnssec ? "&do=1" : ""}`,
      {
        headers: { Accept: "application/dns-json" },
        redirect: "manual",
        signal: combineSignals(opts.signal, opts.accounting?.signal, AbortSignal.timeout(6_000)),
      }
    );
    opts.accounting?.recordCompleted?.();
    attemptInFlight = false;
  } catch (err) {
    if (attemptInFlight) opts.accounting?.recordError?.(err);
    throw err;
  }
  refuseProviderRedirect(res, opts.accounting, "cloudflare_doh");
  if (!res.ok) {
    throw new Error(
      `${doDnssec ? "DoH DNSSEC" : "DoH"} ${res.status} for ${type} ${name}`,
    );
  }
  return res.json();
}

export async function dnsQuery(name, type, opts = {}) {
  const key = dnsCacheKey(name, type, "cloudflare", "default");
  return runCachedDnsQuestion(
    opts.cache,
    key,
    () => fetchCloudflareDns(name, type, opts, "default"),
  );
}

// Single-resolver A lookup with an optional per-scan cache (dnsCacheKey format
// "resolver|name|A|dnssec-profile"). Used by the critical-prefix discovery pass:
// strict — one resolver,
// A-only, no cross-check — and budget-safe (never throws; returns null on failure).
// The cache guarantees each (name,"A") is resolved at most once per scan.
export async function dnsResolveACached(name, cache = null, opts = {}) {
  try {
    return await dnsQuery(name, "A", { ...opts, cache });
  } catch (error) {
    if (error?.code === "redirect_refused") {
      try {
        opts.onUnavailable?.({
          reason: "redirect_refused",
          provider: error.provider ?? null,
          http_status: error.http_status ?? null,
        });
      } catch {
        // Observation hooks cannot change this helper's non-throwing contract.
      }
    }
    return null;
  }
}

export async function dnsQueryDnssec(name, type, opts = {}) {
  const key = dnsCacheKey(name, type, "cloudflare", "do1");
  return runCachedDnsQuestion(
    opts.cache,
    key,
    () => fetchCloudflareDns(name, type, opts, "do1"),
  );
}

export async function dnsQueryGoogle(name, type, opts = {}) {
  const key = dnsCacheKey(name, type, "google", "default");
  return runCachedDnsQuestion(opts.cache, key, async () => {
    opts.accounting?.assertCanIssue?.();
    opts.accounting?.recordAttempt?.();
    let attemptInFlight = true;
    let res;
    try {
      res = await fetch(
        `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
        {
          redirect: "manual",
          signal: combineSignals(opts.signal, opts.accounting?.signal, AbortSignal.timeout(6_000)),
        }
      );
      opts.accounting?.recordCompleted?.();
      attemptInFlight = false;
    } catch (err) {
      if (attemptInFlight) opts.accounting?.recordError?.(err);
      throw err;
    }
    refuseProviderRedirect(res, opts.accounting, "google_doh");
    if (!res.ok) throw new Error(`Google DoH ${res.status} for ${type} ${name}`);
    return res.json();
  });
}

export async function dnsQueryQuad9(name, type, opts = {}) {
  // Quad9 DoH — optional third resolver for A/AAAA agreement checks.
  // Never throws: failure returns null so budget-safe.
  const key = dnsCacheKey(name, type, "quad9", "default");
  try {
    return await runCachedDnsQuestion(opts.cache, key, async () => {
      let attemptInFlight = false;
      try {
        opts.accounting?.assertCanIssue?.();
        opts.accounting?.recordAttempt?.();
        attemptInFlight = true;
        const res = await fetch(
          `https://dns.quad9.net/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
          {
            headers: { Accept: "application/dns-json" },
            redirect: "manual",
            signal: combineSignals(opts.signal, opts.accounting?.signal, AbortSignal.timeout(5_000)),
          }
        );
        opts.accounting?.recordCompleted?.();
        attemptInFlight = false;
        refuseProviderRedirect(res, opts.accounting, "quad9_doh");
        if (!res.ok) return null;
        return res.json();
      } catch (err) {
        if (attemptInFlight) opts.accounting?.recordError?.(err);
        return null;
      }
    });
  } catch {
    return null;
  }
}

export function dnsAnswerValues(response) {
  return (response?.Answer || [])
    .map((r) => r.data)
    .filter(Boolean)
    .sort();
}

/**
 * computeResolverAgreementScore(resolvers)
 *
 * Given an array of { status, returned_records } resolver objects,
 * returns a 0–100 score:
 *   100 = all available resolvers agree
 *   50  = partial disagreement among available resolvers
 *   0   = all available resolvers disagree
 *   null = fewer than 2 resolvers available (insufficient data)
 */
export function computeResolverAgreementScore(resolvers) {
  const available = resolvers.filter((r) => r.status === "ok");
  if (available.length < 2) return null;
  const reference = available[0].returned_records;
  const agreements = available.filter(
    (r) => r.returned_records.length === reference.length
      && r.returned_records.every((v, i) => v === reference[i])
  ).length;
  return Math.round((agreements / available.length) * 100);
}

export function buildDnsCrossCheck(name, type, primaryResult, googleResult, quad9Result) {
  const primaryRecords = dnsAnswerValues(primaryResult);
  const googleAvailable = googleResult?.status === "fulfilled";
  const quad9Available  = quad9Result != null;
  const googleRecords   = googleAvailable ? dnsAnswerValues(googleResult.value) : [];
  const quad9Records    = quad9Available  ? dnsAnswerValues(quad9Result)         : [];

  const resolvers = [
    { resolver: "cloudflare", status: primaryResult ? "ok" : "unavailable", returned_records: primaryRecords },
    googleAvailable
      ? { resolver: "google",  status: "ok",          returned_records: googleRecords }
      : { resolver: "google",  status: "unavailable", returned_records: [] },
  ];
  if (quad9Result !== undefined) {
    resolvers.push(
      quad9Available
        ? { resolver: "quad9",  status: "ok",          returned_records: quad9Records }
        : { resolver: "quad9",  status: "unavailable", returned_records: [] }
    );
  }

  const agreementScore = computeResolverAgreementScore(resolvers.filter((r) => r.status === "ok").length >= 2 ? resolvers : resolvers.slice(0, 2));
  const googleRec = googleAvailable ? dnsAnswerValues(googleResult.value) : [];
  const sameRecords = googleAvailable
    && primaryRecords.length === googleRec.length
    && primaryRecords.every((v, i) => v === googleRec[i]);

  return {
    query: { name, type },
    primary_resolver: {
      resolver: "cloudflare",
      status: primaryResult ? "ok" : "unavailable",
      returned_records: primaryRecords,
    },
    cloudflare_resolver: {
      resolver: "cloudflare",
      status: primaryResult ? "ok" : "unavailable",
      returned_records: primaryRecords,
    },
    google_resolver: googleAvailable
      ? { resolver: "google", status: "ok", returned_records: googleRecords }
      : { resolver: "google", status: "unavailable", returned_records: [] },
    ...(quad9Result !== undefined ? {
      quad9_resolver: quad9Available
        ? { resolver: "quad9", status: "ok", returned_records: quad9Records }
        : { resolver: "quad9", status: "unavailable", returned_records: [] },
    } : {}),
    authoritative_nameserver: {
      status: "unavailable",
      reason: "Raw authoritative DNS queries are not available from Cloudflare Workers.",
      returned_records: [],
    },
    resolver_agreement_score: agreementScore,
    resolver_disagreement: googleAvailable ? !sameRecords : false,
  };
}
