// ── Certificate Transparency provider policy ─────────────────────────────────
//
// Which CT search providers a scan queries. Production scans query CertSpotter
// (SSLMate) only: it has a documented, key-authenticated API with published rate
// limits. crt.sh has no API contract, no SLA and frequent 502/timeouts, and when
// it failed the whole scan was marked degraded — so production does not depend
// on it. The two-provider code paths stay intact and tested; a scan that does
// not declare its providers (historical records, fixtures) keeps the original
// two-provider meaning, so nothing historical is reinterpreted.
//
// What this costs, stated plainly: CertSpotter returns certificates that have
// not expired. Names that appeared only on expired certificates are not
// searched; DNS name checks, SRV records and on-site links still contribute.

export const CT_ALL_PROVIDERS = Object.freeze(["crt_sh", "certspotter"]);
export const CT_SCAN_PROVIDERS = Object.freeze(["certspotter"]);

// Canonical order, known providers only. Anything empty or unrecognised falls
// back to the original two-provider set rather than silently shrinking it.
export function normalizeCtProviders(list) {
  if (!Array.isArray(list)) return CT_ALL_PROVIDERS;
  const wanted = new Set(list.map((value) => String(value)));
  const providers = CT_ALL_PROVIDERS.filter((provider) => wanted.has(provider));
  return providers.length > 0 && providers.length === wanted.size
    ? Object.freeze(providers)
    : CT_ALL_PROVIDERS;
}

// The providers a recorded subdomains result actually used.
export function ctProvidersUsed(subdomainsModule) {
  return normalizeCtProviders(subdomainsModule?.ct_providers);
}

// Same-shape failure rows for exactly the providers a scan used.
export function ctFailedSources(providers, error) {
  return Object.fromEntries(normalizeCtProviders(providers).map((provider) => [provider, { count: 0, error }]));
}
