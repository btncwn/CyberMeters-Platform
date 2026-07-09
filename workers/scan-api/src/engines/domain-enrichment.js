// ── Domain security enrichment module ──
// Derives extra domain-security signals (CAA/HSTS/DNS posture) from data already collected
// by other modules — no additional subrequests (free-plan 50-subrequest budget). Extracted
// verbatim from index.js (monolith decomposition, Phase 1c).

/**
 * Pure computation — zero network I/O.
 *
 * Reads data already captured by earlier modules:
 *   CAA    ← modules.dns.caa        (added to runDnsModule in Phase 1)
 *   HSTS   ← modules.headers.values["strict-transport-security"]
 *   Cookies ← modules.headers.set_cookie_raw  (added to runHeadersModule)
 *
 * This design avoids consuming additional subrequests on Cloudflare Workers'
 * free-plan 50-subrequest budget.
 */
export function runDomainSecurityEnrichmentModule(domain, modules) {
  // ── 1. CAA — read from DNS module ────────────────────────────────────────
  const caa = modules?.dns?.caa ?? {
    present: false, records: [], issuers: [],
    wildcard_issuers: [], iodef: [],
    quality: {
      score: 0,
      status: "lookup_skipped",
      wildcard_issuer_usage: false,
      iodef_present: false,
      issuer_count: 0,
    },
    error: "skipped_due_to_subrequest_budget",
  };

  // ── 2. HSTS — read from headers module ───────────────────────────────────
  const hstsRaw = modules?.headers?.values?.["strict-transport-security"] || null;
  let hsts;
  if (hstsRaw) {
    const parts  = hstsRaw.toLowerCase().split(";").map((p) => p.trim());
    const maxDir = parts.find((p) => p.startsWith("max-age"));
    let maxAge   = null;
    if (maxDir) {
      const m = maxDir.match(/max-age\s*=\s*(\d+)/);
      if (m) maxAge = parseInt(m[1], 10);
    }
    const inclSub = parts.includes("includesubdomains");
    const preDir  = parts.includes("preload");
    hsts = {
      present:            true,
      value:              hstsRaw,
      max_age:            maxAge,
      include_subdomains: inclSub,
      preload_directive:  preDir,
      preload_eligible:   maxAge !== null && maxAge >= 31_536_000 && inclSub && preDir,
      error:              null,
    };
  } else {
    hsts = {
      present: false, value: null, max_age: null,
      include_subdomains: false, preload_directive: false,
      preload_eligible: false, error: null,
    };
  }

  // ── 3. Cookies — read from headers module ────────────────────────────────
  const rawCookies = modules?.headers?.set_cookie_raw || [];
  const parsed = rawCookies.map((raw) => {
    const parts  = raw.split(";").map((p) => p.trim());
    const name   = (parts[0] || "").split("=")[0].trim();
    const attrs  = parts.slice(1).map((p) => p.toLowerCase());
    const ss     = attrs.find((a) => a.startsWith("samesite="));
    return {
      name,
      secure:   attrs.includes("secure"),
      httponly: attrs.includes("httponly"),
      samesite: ss ? ss.split("=")[1] : null,
    };
  });
  const cookies = {
    found:          parsed.length,
    cookies:        parsed,
    insecure_count: parsed.filter((c) => !c.secure).length,
    no_httponly:    parsed.filter((c) => !c.httponly).length,
    no_samesite:    parsed.filter((c) => !c.samesite).length,
    error:          null,
  };

  return { caa, hsts, cookies, source: "dns_headers_analysis", error: null };
}
