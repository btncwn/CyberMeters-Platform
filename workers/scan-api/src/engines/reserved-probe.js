// ── Reserved-mode SSRF-safe exposure fetcher ──────────────────────────────────
// Shared by the reserved path and default exposure prober. This follows redirects
// MANUALLY with a hard hop cap, and validates every
// hop with the CANONICAL SSRF validator (lib/ssrf.js) — no re-implemented guard logic:
//   • urlIsBlockedTarget: http(s) only, no credentials, reject loopback/RFC1918/
//     link-local/metadata/IPv6-loopback+ULA+link-local LITERALS, reject malformed.
//   • resolvePublicDnsTarget: require complete public A+AAAA evidence EVERY hop.
//     This is a DNS preflight, not connection-time address pinning.
// A blocked target returns null (the caller skips it). fetch() errors (including the
// "Too many subrequests" budget throw) propagate so probeAsset can classify them.
import { resolvePublicDnsTarget, STRICT_DNS_STATES, urlIsBlockedTarget } from "../lib/ssrf.js";
import { dnsQuery } from "./dns.js";

export const RESERVED_MAX_REDIRECT_HOPS = 3;   // follow up to 3 redirects; cap the 4th

function combineSignals(...signals) {
  const active = signals.filter(Boolean);
  if (active.length === 0) return undefined;
  if (active.length === 1) return active[0];
  if (typeof AbortSignal.any === "function") return AbortSignal.any(active);
  const controller = new AbortController();
  const abort = () => {
    const source = active.find((candidate) => candidate.aborted);
    if (!controller.signal.aborted) controller.abort(source?.reason);
  };
  for (const signal of active) {
    if (signal.aborted) { abort(); break; }
    signal.addEventListener("abort", abort, { once: true });
  }
  return controller.signal;
}

// BOTH A and AAAA use the shared per-scan cache. Physical cache misses are
// metered once; the strict resolver preserves unavailable and control errors.
function makeSsrfResolver(cache, onOutbound, accounting = null) {
  return async (name, type, opts = {}) => {
    const activeAccounting = opts.accounting || accounting;
    // Meter at the leaf's recordAttempt hook, which runs only for a physical
    // cache miss. Reading the Map directly would expose the cache's in-flight
    // entry wrapper instead of a DNS answer and could falsely bypass the SSRF
    // rebinding guard.
    const meteredAccounting = {
      signal: activeAccounting?.signal || null,
      assertCanIssue: () => activeAccounting?.assertCanIssue?.(),
      recordAttempt: () => {
        onOutbound?.();
        activeAccounting?.recordAttempt?.();
      },
      recordCompleted: () => activeAccounting?.recordCompleted?.(),
      recordError: (error) => activeAccounting?.recordError?.(error),
    };
    return dnsQuery(name, type, {
      accounting: meteredAccounting,
      cache,
      signal: opts.signal,
    });
  };
}

// Generic SSRF-safe manual-redirect probe fetcher core — the single implementation
// of the bounded-redirect contract, shared by the reserved path AND the legacy default
// prober (engines/asset-intel.js). Every hop is validated by the CANONICAL ssrf.js
// guards; NO guard logic is re-implemented here:
//   (1) urlIsBlockedTarget — scheme (http/https only), credentials, and private/
//       reserved LITERAL (loopback/RFC1918/link-local/metadata/multicast/IPv6
//       loopback+ULA+link-local + IPv4-mapped-private) + malformed URL.
//   (2) resolvePublicDnsTarget — require public terminal addresses and complete
//       A+AAAA evidence via `resolver` before EVERY hop.
// redirect:"manual" so the next Location is re-validated before it is followed; a hard
// hop cap bounds redirect loops; a blocked/malformed target returns null (fail closed —
// probeAsset treats null as a non-exposed negative, never assessed_healthy). fetch()
// errors (incl. the "Too many subrequests" budget throw) propagate so probeAsset can
// classify them (timeout/not-executed vs authoritative refusal).
// Unavailable DNS throws a typed error so probeAsset records an unassessed target.
// Budget/deadline errors remain observable. onOutbound() is invoked once per ACTUAL
// outbound GET so a caller can meter real subrequest consumption.
export function makeSsrfSafeProbeFetch({ resolver: baseResolver, maxHops = RESERVED_MAX_REDIRECT_HOPS, timeoutMs = 8_000, onOutbound = null, accounting = null } = {}) {
  return async function ssrfSafeProbeFetch(url, opts = {}) {
    const activeAccounting = opts?.accounting || accounting;
    const resolver = typeof baseResolver === "function"
      ? (name, type) => baseResolver(name, type, { accounting: activeAccounting, signal: opts?.signal })
      : baseResolver;
    let current = url;
    for (let hop = 0; ; hop++) {
      if (urlIsBlockedTarget(current)) return null;
      let hostname;
      try { hostname = new URL(current).hostname; } catch { return null; }
      const resolution = await resolvePublicDnsTarget(hostname, resolver, {
        accounting: activeAccounting, signal: opts?.signal,
      });
      if (resolution.state === STRICT_DNS_STATES.BLOCKED) return null;
      if (resolution.state !== STRICT_DNS_STATES.PUBLIC) {
        const error = new Error("Target DNS could not be safely assessed");
        error.code = "dns_resolution_unavailable";
        throw error;
      }
      onOutbound?.();
      activeAccounting?.recordAttempt?.();
      let res;
      try {
        res = await fetch(current, {
          method: "GET",
          redirect: "manual",
          signal: combineSignals(opts?.signal, activeAccounting?.signal, AbortSignal.timeout(timeoutMs)),
        });
        activeAccounting?.recordCompleted?.();
      } catch (err) {
        activeAccounting?.recordError?.(err);
        throw err;
      }
      if (![301, 302, 303, 307, 308].includes(res.status) || hop >= maxHops) return res;
      const loc = res.headers.get("location");
      if (!loc) return res;
      try { current = new URL(loc, current).toString(); } catch { return res; }
    }
  };
}

// Build a fetcher(url) → Response | null suitable for probeAsset({ fetcher }).
// onOutbound() is invoked once per ACTUAL outbound call (each SSRF DNS resolution that
// missed the cache — via makeSsrfResolver — and each hop's GET — via the shared core)
// so the reserved orchestrator can meter real exposure consumption instead of
// projecting it. Unavailable DNS never permits a target GET.
export function makeReservedProbeFetch({ cache = null, maxHops = RESERVED_MAX_REDIRECT_HOPS, timeoutMs = 8_000, onOutbound = null, accounting = null } = {}) {
  const resolver = makeSsrfResolver(cache, onOutbound, accounting);
  return makeSsrfSafeProbeFetch({ resolver, maxHops, timeoutMs, onOutbound, accounting });
}
