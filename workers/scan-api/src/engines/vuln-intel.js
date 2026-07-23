// ── CVE / KEV vulnerability intelligence module ──
// NVD CVE correlation for detected technologies + CISA Known Exploited
// Vulnerabilities lookup. Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). Only runCveModule + runKevModule are public;
// the keyword maps, normalizeTechnology and lookupCvesForTechnology are
// module-internal.
import { safeFetch } from "../lib/http.js";
import { customerSafeFailure } from "../lib/errors.js";

// ── Intelligence Module: CVE Correlation ─────────────────────────────────────
// Ported from cve_lookup.py — queries NVD API for technologies detected by
// runTechModule.  Only queries technologies present in ALLOWED_CVE_TECHNOLOGIES.
// Limited to 3 technologies and 5 CVEs each to bound runtime inside ctx.waitUntil.
// Never throws; returns graceful empty results on failure.

/** Technologies we query the NVD for — mirrors cve_lookup.py ALLOWED_CVE_TECHNOLOGIES */
const ALLOWED_CVE_TECHNOLOGIES = new Set([
  "apache", "nginx", "iis", "wordpress", "drupal", "joomla", "php",
  "tomcat", "jetty", "node.js", "express", "django", "flask", "rails",
  "ruby", "python", "perl", "cgi", "asp.net", "openresty", "lighttpd",
  "caddy", "tengine",
]);

/** NVD keyword search terms — mirrors cve_lookup.py keyword_map */
const CVE_KEYWORD_MAP = {
  "apache":    "apache http server",
  "nginx":     "nginx",
  "iis":       "microsoft iis",
  "wordpress": "wordpress",
  "drupal":    "drupal",
  "joomla":    "joomla",
  "php":       "php",
  "tomcat":    "apache tomcat",
  "jetty":     "eclipse jetty",
  "node.js":   "node.js",
  "express":   "expressjs",
  "django":    "django",
  "flask":     "flask",
  "rails":     "ruby on rails",
  "asp.net":   "asp.net",
  "openresty": "openresty",
  "lighttpd":  "lighttpd",
};

/**
 * Normalise a raw header/technology string to a known canonical name.
 * Mirrors cve_lookup.py normalize_technology().
 */
function normalizeTechnology(tech) {
  if (!tech) return null;
  const t = tech.toLowerCase().trim();
  const map = {
    "apache": "apache",        "apache/": "apache",      "apache httpd": "apache",
    "nginx": "nginx",          "nginx/": "nginx",
    "iis": "iis",              "microsoft-iis": "iis",   "microsoft iis": "iis",
    "wordpress": "wordpress",  "wp": "wordpress",
    "drupal": "drupal",        "joomla": "joomla",
    "php": "php",              "php/": "php",
    "tomcat": "tomcat",        "apache-tomcat": "tomcat",
    "jetty": "jetty",          "eclipse-jetty": "jetty",
    "node.js": "node.js",      "nodejs": "node.js",
    "express": "express",      "expressjs": "express",
    "django": "django",        "flask": "flask",
    "rails": "rails",          "ruby on rails": "rails",
    "ruby": "ruby",            "python": "python",       "perl": "perl",
    "cgi": "cgi",              "asp.net": "asp.net",     "aspnet": "asp.net",
    "openresty": "openresty",  "lighttpd": "lighttpd",
    "caddy": "caddy",          "tengine": "tengine",
  };
  if (map[t]) return map[t];
  for (const [key, val] of Object.entries(map)) {
    if (t.includes(key)) return val;
  }
  return null;
}

/** Query NVD for HIGH+ CVEs for a single technology.  Returns [] on any failure. */
async function lookupCvesForTechnology(techName, maxResults = 5, opts = {}) {
  if (!ALLOWED_CVE_TECHNOLOGIES.has(techName)) return [];
  const accounting = opts.accounting || null;
  const keyword = CVE_KEYWORD_MAP[techName] || techName;
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("keywordSearch",   keyword);
  url.searchParams.set("resultsPerPage",  String(maxResults));
  url.searchParams.set("cvssV3Severity",  "HIGH");
  try {
    const res = await safeFetch(url.toString(), {
      headers: { "User-Agent": "CyberMeters-Scanner/1.0" },
      signal:  AbortSignal.timeout(10_000),
      accounting,
    });
    if (!res || res.status !== 200) return [];
    const data = await res.json();
    const cves = [];
    for (const item of (data.vulnerabilities || []).slice(0, maxResults)) {
      const cve  = item.cve || {};
      const cveId = cve.id;
      let description = "";
      for (const d of (cve.descriptions || [])) {
        if (d.lang === "en") { description = d.value || ""; break; }
      }
      const metrics = cve.metrics || {};
      let cvssScore = null, severity = "UNKNOWN";
      if (metrics.cvssMetricV31?.length) {
        const m = metrics.cvssMetricV31[0].cvssData || {};
        cvssScore = m.baseScore; severity = m.baseSeverity || "UNKNOWN";
      } else if (metrics.cvssMetricV30?.length) {
        const m = metrics.cvssMetricV30[0].cvssData || {};
        cvssScore = m.baseScore; severity = m.baseSeverity || "UNKNOWN";
      } else if (metrics.cvssMetricV2?.length) {
        const m = metrics.cvssMetricV2[0].cvssData || {};
        cvssScore = m.baseScore;
        severity = cvssScore >= 7 ? "HIGH" : cvssScore >= 4 ? "MEDIUM" : "LOW";
      }
      if (cveId) {
        cves.push({
          cve_id:      cveId,
          severity,
          cvss_score:  cvssScore,
          description: description.length > 300 ? description.slice(0, 297) + "..." : description,
          technology:  techName,
        });
      }
    }
    return cves;
  } catch {
    return [];
  }
}

/**
 * Run CVE correlation for detected technologies.
 * Ported from cve_lookup.correlate_cves() — limits to 3 technologies,
 * 300ms delay between NVD requests to respect free-tier rate limits,
 * skips exploit-db check (Worker network budget).
 */
export async function runCveModule(techModule, opts = {}) {
  const accounting = opts.accounting || null;
  if (!techModule || techModule.error) {
    return {
      technologies_checked: [], results: {}, total_cves: 0,
      critical_count: 0, high_count: 0, source: "nvd_api",
    };
  }

  // Collect candidates from inferred tech list + raw header values
  const candidates = new Set();
  for (const t of (techModule.technologies || [])) {
    const n = normalizeTechnology(t);
    if (n && ALLOWED_CVE_TECHNOLOGIES.has(n)) candidates.add(n);
  }
  for (const header of [techModule.server, techModule.x_powered_by]) {
    const n = normalizeTechnology(header || "");
    if (n && ALLOWED_CVE_TECHNOLOGIES.has(n)) candidates.add(n);
  }

  // Limit to 3 to bound runtime (NVD free tier: no API key → 5 req/30s)
  const toCheck = [...candidates].slice(0, 3);
  const results = {};
  let totalCves = 0, criticalCount = 0, highCount = 0;

  for (const tech of toCheck) {
    const cves = await lookupCvesForTechnology(tech, 5, { accounting });
    if (cves.length > 0) {
      results[tech] = cves;
      totalCves   += cves.length;
      for (const c of cves) {
        if (c.severity === "CRITICAL") criticalCount++;
        else if (c.severity === "HIGH") highCount++;
      }
    }
    // Respect NVD free-tier rate limit between requests
    if (toCheck.indexOf(tech) < toCheck.length - 1) {
      await new Promise(r => setTimeout(r, 300));
    }
  }

  return {
    technologies_checked: toCheck,
    results,
    total_cves:     totalCves,
    critical_count: criticalCount,
    high_count:     highCount,
    source:         "nvd_api",
  };
}

// ── Intelligence Module: CISA KEV Lookup ─────────────────────────────────────
// Ported from kev_lookup.py — fetches the CISA Known Exploited Vulnerabilities
// catalog and matches against detected technologies (keyword match on product /
// vendor fields) AND any CVE IDs returned by runCveModule (exact match).
// Runs in parallel with runCveModule; CVE ID cross-referencing is done inside
// runRiskModule after both complete.

const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

// The KEV catalogue is a multi-MB, DOMAIN-INDEPENDENT feed. Re-downloading it on
// every scan is the single heaviest external I/O in the pipeline and a prime
// contributor to the wall-clock that triggers waitUntil cancellation. Cache it in
// R2 (no KV binding exists) with a TTL so subsequent scans read it from R2 (a fast
// Cloudflare-internal GET, not an external subrequest) instead of hitting CISA.
export const KEV_CACHE_KEY    = "cache/cisa-kev.json";
export const KEV_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24h freshness window

/**
 * Resolve the CISA KEV catalogue, preferring a fresh R2 cache. Honest degradation:
 * a cache read/write failure never breaks the module — it falls back to a direct
 * fetch; if the origin also fails, a stale cache is used (flagged stale) and only
 * when nothing is available does it report unavailable. `fetcher`/`now` are
 * injectable for deterministic tests.
 *
 * Returns { vulnerabilities: Array|null, source, stale, age_ms }.
 */
export async function getKevCatalogue(env = null, { fetcher = safeFetch, now = Date.now, accounting = null } = {}) {
  const nowMs = now();
  let stale = null;

  // 1. Try the R2 cache.
  if (env?.cybermeters_reports?.get) {
    try {
      const obj = await env.cybermeters_reports.get(KEV_CACHE_KEY);
      if (obj) {
        const parsed = JSON.parse(await obj.text());
        if (parsed && Array.isArray(parsed.vulnerabilities) && typeof parsed.fetched_at_ms === "number") {
          const ageMs = nowMs - parsed.fetched_at_ms;
          if (ageMs >= 0 && ageMs < KEV_CACHE_TTL_MS) {
            return { vulnerabilities: parsed.vulnerabilities, source: "r2_cache", stale: false, age_ms: ageMs };
          }
          stale = parsed; // expired — retain as a fallback if the origin fetch fails
        }
      }
    } catch { /* cache read failure — degrade to an origin fetch */ }
  }

  // 2. Fetch fresh from CISA.
  try {
    const res = await fetcher(CISA_KEV_URL, { signal: AbortSignal.timeout(15_000), accounting });
    if (res && res.status === 200) {
      const data = await res.json();
      const vulnerabilities = data.vulnerabilities || [];
      if (env?.cybermeters_reports?.put) {
        try {
          await env.cybermeters_reports.put(
            KEV_CACHE_KEY,
            JSON.stringify({ fetched_at_ms: nowMs, vulnerabilities }),
            { httpMetadata: { contentType: "application/json" } }
          );
        } catch { /* cache write failure — non-fatal, we still return the data */ }
      }
      return { vulnerabilities, source: "origin", stale: false, age_ms: 0 };
    }
  } catch { /* origin fetch failed — fall through to stale/unavailable */ }

  // 3. Origin failed: use a stale cache if we have one, flagged honestly.
  if (stale) {
    return { vulnerabilities: stale.vulnerabilities, source: "r2_cache_stale", stale: true, age_ms: nowMs - stale.fetched_at_ms };
  }

  // 4. Nothing available — honest unavailable (never a fake clean result).
  return { vulnerabilities: null, source: "unavailable", stale: false, age_ms: null };
}

/**
 * Fetch CISA KEV catalog and match against detected technologies.
 * Ported from kev_lookup.correlate_kev() with added technology keyword matching.
 * `env` enables the R2 catalogue cache; `opts` injects fetcher/now for tests.
 */
export async function runKevModule(techModule, env = null, opts = {}) {
  const detectedTechs = (techModule?.technologies || []).map(t => t.toLowerCase());
  // Include normalised server/x-powered-by values as additional keyword hints
  for (const h of [techModule?.server, techModule?.x_powered_by]) {
    const n = normalizeTechnology(h || "");
    if (n && !detectedTechs.includes(n)) detectedTechs.push(n);
  }

  try {
    const catalogue = await getKevCatalogue(env, opts);
    if (!catalogue.vulnerabilities) {
      return { matches: [], checked: 0, matched: 0, source: "cisa_kev", catalogue_source: catalogue.source, error: "KEV catalog unavailable" };
    }
    const vulnerabilities = catalogue.vulnerabilities;
    const matches = [];

    for (const vuln of vulnerabilities) {
      const product = (vuln.product        || "").toLowerCase();
      const vendor  = (vuln.vendorProject   || "").toLowerCase();
      // Keyword match: does the KEV product/vendor mention any of our detected techs?
      const techMatch = detectedTechs.some(t => t.length >= 3 && (product.includes(t) || vendor.includes(t)));
      if (!techMatch) continue;
      matches.push({
        cve_id:              vuln.cveID,
        vendor_project:      vuln.vendorProject,
        product:             vuln.product,
        vulnerability_name:  vuln.vulnerabilityName,
        date_added:          vuln.dateAdded,
        required_action:     vuln.requiredAction,
        due_date:            vuln.dueDate,
        short_description:   vuln.shortDescription || "",
        match_type:          "technology_keyword",
      });
    }

    // Most recently added exploited vulns first
    matches.sort((a, b) => (b.date_added || "").localeCompare(a.date_added || ""));

    // Cap at 25 to avoid bloating the report JSON
    const capped = matches.slice(0, 25);

    return {
      matches:          capped,
      checked:          vulnerabilities.length,
      matched:          capped.length,
      source:           "cisa_kev",
      catalogue_source: catalogue.source,   // r2_cache | origin | r2_cache_stale
      catalogue_stale:  catalogue.stale,
    };
  } catch (err) {
    return {
      matches: [], checked: 0, matched: 0,
      source:  "cisa_kev",
      error:   customerSafeFailure("scan/kev", err, "KEV module failed"),
    };
  }
}
