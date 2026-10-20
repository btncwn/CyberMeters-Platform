// ── HTTP helpers ──
// Shared fetch utilities. safeFetch is now SSRF-aware (see below) — the single
// choke point every scan module already routes through.
import { isOutboundControlError, resolvePublicDnsTarget, STRICT_DNS_STATES, urlIsBlockedTarget } from "./ssrf.js";

const MAX_REDIRECT_HOPS = 4;

// Honest scanner identification for every request to a customer origin. A request
// with no User-Agent is refused by common edge bot rules (Shopify answers 403
// "Access denied"), which read as an unassessable website even when the origin
// serves normally. This is the same identity the headers module always sent.
export const SCANNER_USER_AGENT =
  "Mozilla/5.0 (compatible; CyberMeters-Scanner/1.0; +https://cybermeters.com/scanner)";

// Page probes (website, technology, TLS, asset exposure) ask for a page the way
// the headers module does, so every module observes the same origin answer.
export const SCANNER_PAGE_HEADERS = Object.freeze({
  "User-Agent": SCANNER_USER_AGENT,
  "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
});

// Adds the scanner User-Agent unless the caller set its own. Every other header
// the caller supplied is kept exactly as given.
export function withScannerUserAgent(headers) {
  if (headers instanceof Headers) {
    const copy = new Headers(headers);
    if (!copy.has("user-agent")) copy.set("User-Agent", SCANNER_USER_AGENT);
    return copy;
  }
  const entries = Array.isArray(headers)
    ? headers
    : Object.entries(headers && typeof headers === "object" ? headers : {});
  const hasUserAgent = entries.some(([name]) => String(name).toLowerCase() === "user-agent");
  const plain = Object.fromEntries(entries);
  return hasUserAgent ? plain : { ...plain, "User-Agent": SCANNER_USER_AGENT };
}

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

// SSRF-aware fetch. Validates the target host on EVERY hop (refusing loopback /
// private / reserved targets) and follows redirects MANUALLY so a public domain
// that 302s to an internal address is refused mid-chain — the redirect-time
// SSRF the string input-gate cannot see.
//
// Behaviour-preserving:
//  • redirect:"follow" (the default) callers get the final Response, with
//    .url = the final URL, exactly as native follow did — just validated.
//  • redirect:"manual" callers keep single-hop semantics (they read Location
//    themselves and re-enter safeFetch for the next hop, which re-validates).
//  • A blocked / ordinary transport failure returns null — the existing contract
//    every caller already handles (`if (!res) …`). Typed budget/deadline/cancel
//    errors remain observable and are re-thrown for honest incomplete outcomes.
//  • A request that hit only its own 10 s per-hop timer (no caller, deadline or
//    budget signal aborted) is the target not answering in time: an ordinary
//    transport failure, returned as null, with the reason "origin_timeout"
//    reported through the optional onFailure(reason) callback.
export async function safeFetch(url, options = {}) {
  const followManually = options.redirect !== "manual";
  const accounting = options.accounting || null;
  const dnsResolver = options.dnsResolver || null;
  const dnsCache = options.dnsCache || null;
  const fetchImpl = typeof options.fetchImpl === "function" ? options.fetchImpl : fetch;
  const onFailure = typeof options.onFailure === "function" ? options.onFailure : null;
  const fetchOptions = { ...options };
  delete fetchOptions.onFailure;
  delete fetchOptions.accounting;
  delete fetchOptions.dnsResolver;
  delete fetchOptions.dnsCache;
  delete fetchOptions.fetchImpl;
  fetchOptions.headers = withScannerUserAgent(fetchOptions.headers);
  let attemptInFlight = false;
  try {
    let current = url;
    for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
      if (urlIsBlockedTarget(current)) return null;
      if (dnsResolver) {
        const hostname = new URL(current).hostname;
        const resolution = await resolvePublicDnsTarget(hostname, dnsResolver, {
          cache: dnsCache,
          accounting,
          signal: fetchOptions.signal,
        });
        if (resolution.state !== STRICT_DNS_STATES.PUBLIC) return null;
      }
      attemptInFlight = false;
      accounting?.assertCanIssue?.();
      accounting?.recordAttempt?.();
      attemptInFlight = true;
      const res = await fetchImpl(current, {
        ...fetchOptions,
        redirect: "manual",
        signal: combineSignals(fetchOptions.signal, accounting?.signal, AbortSignal.timeout(10_000)),
      });
      accounting?.recordCompleted?.();
      attemptInFlight = false;
      if (!followManually) return res;
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const loc = res.headers.get("location");
        if (!loc) return res;
        try { current = new URL(loc, current).toString(); } catch { return res; }
        continue; // re-validate the next hop before following it
      }
      return res; // final (non-redirect) response
    }
    return null; // redirect loop / exceeded MAX_REDIRECT_HOPS
  } catch (err) {
    if (attemptInFlight) accounting?.recordError?.(err);
    const hopTimeout = attemptInFlight && err?.name === "TimeoutError"
      && fetchOptions.signal?.aborted !== true && accounting?.signal?.aborted !== true;
    if (hopTimeout) {
      try { onFailure?.("origin_timeout"); } catch { /* reporting only */ }
      return null;
    }
    if (isOutboundControlError(err)) throw err;
    return null;
  }
}

// Shared RDAP/WHOIS request User-Agent (identifies the CyberMeters scanner honestly).
export const RDAP_UA = "CyberMeters/1.0 (https://cybermeters.com)";
