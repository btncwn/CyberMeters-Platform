// ── HTTP helpers ──
// Shared fetch utilities. safeFetch is now SSRF-aware (see below) — the single
// choke point every scan module already routes through.
import { urlIsBlockedTarget } from "./ssrf.js";

const MAX_REDIRECT_HOPS = 4;

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
//  • A blocked / errored / timed-out fetch returns null — the existing contract
//    every caller already handles (`if (!res) …`).
export async function safeFetch(url, options = {}) {
  const followManually = options.redirect !== "manual";
  const accounting = options.accounting || null;
  const fetchOptions = { ...options };
  delete fetchOptions.accounting;
  try {
    let current = url;
    for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
      if (urlIsBlockedTarget(current)) return null;
      accounting?.recordAttempt?.();
      const res = await fetch(current, {
        ...fetchOptions,
        redirect: "manual",
        signal: AbortSignal.timeout(10_000),
      });
      accounting?.recordCompleted?.();
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
    accounting?.recordError?.(err);
    return null;
  }
}

// Shared RDAP/WHOIS request User-Agent (identifies the CyberMeters scanner honestly).
export const RDAP_UA = "CyberMeters/1.0 (https://cybermeters.com)";
