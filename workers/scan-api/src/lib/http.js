// ── HTTP helpers ──
// Shared fetch utilities. Extracted verbatim from index.js (monolith decomposition,
// Phase 1b). Behavior-preserving — no logic change.
export async function safeFetch(url, options = {}) {
  try {
    return await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return null;
  }
}

// Shared RDAP/WHOIS request User-Agent (identifies the CyberMeters scanner honestly).
export const RDAP_UA = "CyberMeters/1.0 (https://cybermeters.com)";
