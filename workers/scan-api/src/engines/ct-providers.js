// ── Certificate Transparency provider policy ─────────────────────────────────
//
// CertSpotter (SSLMate) is the only Certificate Transparency search provider:
// a documented API with published rate limits. An optional SSLMate API key
// (Worker secret CERTSPOTTER_API_KEY) raises the quota; without it the free
// unauthenticated quota is used.
//
// What this costs, stated plainly: CertSpotter returns certificates that have
// not expired. Names that appeared only on expired certificates are not
// searched; DNS name checks, SRV records and on-site links still contribute.
//
// Stored records are never reinterpreted. Readers take a record's provider set
// from what the record itself declares or recorded, never from this constant.

export const CT_PROVIDERS = Object.freeze(["certspotter"]);

function providerNames(value) {
  if (Array.isArray(value)) return value.map((entry) => String(entry)).filter(Boolean);
  if (value && typeof value === "object") return Object.keys(value);
  return [];
}

// The CT providers a recorded module used: its declared `ct_providers`, else
// the provider keys it recorded under `sources` / `ct_sources`, else the
// current provider set.
export function ctProvidersUsed(module) {
  for (const candidate of [module?.ct_providers, module?.sources, module?.ct_sources]) {
    const names = providerNames(candidate);
    if (names.length > 0) return Object.freeze([...new Set(names)]);
  }
  return CT_PROVIDERS;
}

// Same-shape failure rows for the current provider set.
export function ctFailedSources(error) {
  return Object.fromEntries(CT_PROVIDERS.map((provider) => [provider, { count: 0, error }]));
}
