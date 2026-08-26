// ── HTTP helpers ──
// Shared fetch utilities. safeFetch is now SSRF-aware (see below) — the single
// choke point every scan module already routes through.
import { isOutboundControlError, resolvePublicDnsTarget, STRICT_DNS_STATES, urlIsBlockedTarget } from "./ssrf.js";

const MAX_REDIRECT_HOPS = 4;

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
export async function safeFetch(url, options = {}) {
  const followManually = options.redirect !== "manual";
  const accounting = options.accounting || null;
  const dnsResolver = options.dnsResolver || null;
  const dnsCache = options.dnsCache || null;
  const fetchImpl = typeof options.fetchImpl === "function" ? options.fetchImpl : fetch;
  const fetchOptions = { ...options };
  delete fetchOptions.accounting;
  delete fetchOptions.dnsResolver;
  delete fetchOptions.dnsCache;
  delete fetchOptions.fetchImpl;
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
    if (isOutboundControlError(err)) throw err;
    return null;
  }
}

// Shared RDAP/WHOIS request User-Agent (identifies the CyberMeters scanner honestly).
export const RDAP_UA = "CyberMeters/1.0 (https://cybermeters.com)";
