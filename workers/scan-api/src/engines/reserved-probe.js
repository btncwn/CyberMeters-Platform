// ── Reserved-mode SSRF-safe exposure fetcher ──────────────────────────────────
// Used ONLY by the reserved path (SCAN_CAPACITY_MODE=reserved). The legacy prober is
// untouched. This follows redirects MANUALLY with a hard hop cap, and validates every
// hop with the CANONICAL SSRF validator (lib/ssrf.js) — no re-implemented guard logic:
//   • urlIsBlockedTarget: http(s) only, no credentials, reject loopback/RFC1918/
//     link-local/metadata/IPv6-loopback+ULA+link-local LITERALS, reject malformed.
//   • resolvesToPrivateIp: re-resolves the hostname (A+AAAA) EVERY hop and rejects if
//     it points at a private/reserved IP — the DNS-rebinding guard.
// A blocked target returns null (the caller skips it). fetch() errors (including the
// "Too many subrequests" budget throw) propagate so probeAsset can classify them.
import { resolvesToPrivateIp, urlIsBlockedTarget } from "../lib/ssrf.js";
import { dnsQuery, dnsResolveACached } from "./dns.js";
import { dnsCacheKey } from "./scan-budget.js";

export const RESERVED_MAX_REDIRECT_HOPS = 3;   // follow up to 3 redirects; cap the 4th

// Resolver for resolvesToPrivateIp — BOTH A and AAAA go through the shared per-scan
// cache so a host is resolved at most once per (name,type) across the whole scan (A is
// often already cached by the critical-prefix pass). Never throws (resolvesToPrivateIp
// fails open on error). NOTE: the mandatory per-hop rebinding guard resolves AAAA in
// addition to A, so the true exposure cost exceeds the projected C_h model by ~1 DoH
// for the first resolution of each new host; the trust-fix runtime guard backstops any
// real exhaustion (not_executed), and Tier-2's live counter makes `consumed` exact.
function makeSsrfResolver(cache, onOutbound) {
  return async (name, type) => {
    const key = dnsCacheKey(name, type);
    if (cache && cache.has(key)) return cache.get(key);      // cache hit → no outbound call
    let ans = null;
    try { onOutbound?.(); ans = await dnsQuery(name, type); } catch { ans = null; }
    if (cache) cache.set(key, ans);
    return ans;
  };
}

// Build a fetcher(url) → Response | null suitable for probeAsset({ fetcher }).
// onOutbound() is invoked once per ACTUAL outbound call (each SSRF DNS resolution that
// missed the cache, and each hop's GET) so the reserved orchestrator can meter real
// exposure consumption instead of projecting it.
export function makeReservedProbeFetch({ cache = null, maxHops = RESERVED_MAX_REDIRECT_HOPS, timeoutMs = 8_000, onOutbound = null } = {}) {
  const resolver = makeSsrfResolver(cache, onOutbound);
  return async function reservedProbeFetch(url) {
    let current = url;
    for (let hop = 0; ; hop++) {
      // (1) canonical synchronous guard: scheme, credentials, private/reserved literal.
      if (urlIsBlockedTarget(current)) return null;
      // (2) canonical DNS guard, re-run EVERY hop: reject if the host resolves to a
      //     private/reserved IP (DNS rebinding). Public → allowed.
      let hostname;
      try { hostname = new URL(current).hostname; } catch { return null; }
      if (await resolvesToPrivateIp(hostname, resolver)) return null;
      // (3) fetch this hop with manual redirect so the next hop is re-validated.
      onOutbound?.();
      const res = await fetch(current, { method: "GET", redirect: "manual", signal: AbortSignal.timeout(timeoutMs) });
      if (![301, 302, 303, 307, 308].includes(res.status) || hop >= maxHops) return res;
      const loc = res.headers.get("location");
      if (!loc) return res;
      try { current = new URL(loc, current).toString(); } catch { return res; }
    }
  };
}
