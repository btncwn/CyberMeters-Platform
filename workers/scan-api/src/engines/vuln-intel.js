// ── CVE / KEV vulnerability intelligence module ──
// NVD CVE correlation for detected technologies + CISA Known Exploited
// Vulnerabilities lookup. Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). Only runCveModule + runKevModule are public;
// the keyword maps, normalizeTechnology and lookupCvesForTechnology are
// module-internal.
import { safeFetch } from "../lib/http.js";
import { customerSafeFailure } from "../lib/errors.js";
import { maySupportDefectConclusion } from "../lib/serviceability.js";

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

export const CVE_COVERAGE = Object.freeze({
  COMPLETE: "complete",
  PARTIAL: "partial",
  UNAVAILABLE: "unavailable",
  DEPENDENCY_UNAVAILABLE: "dependency_unavailable",
  NOT_APPLICABLE: "not_applicable",
});

function cveDependencyFailure(techModule) {
  if (!techModule || techModule.error) {
    return {
      outcome: "dependency_unavailable",
      reason: "technology_dependency_unavailable",
    };
  }
  if (techModule.skipped === true) {
    return {
      outcome: "dependency_budget_skipped",
      reason: techModule.skip_reason || "technology_dependency_skipped",
    };
  }
  if (techModule.executed === false || techModule.outcome === "deadline_exceeded") {
    return {
      outcome: "dependency_deadline_deferred",
      reason: techModule.reason || "technology_dependency_deferred",
    };
  }
  if (techModule.incomplete === true) {
    return {
      outcome: "dependency_unavailable",
      reason: techModule.incomplete_reason || techModule.reason || "technology_dependency_incomplete",
    };
  }
  return null;
}

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

function combineLookupSignals(...signals) {
  const active = signals.filter(Boolean);
  if (active.length === 0) return undefined;
  if (active.length === 1) return active[0];
  if (typeof AbortSignal.any === "function") return AbortSignal.any(active);
  const controller = new AbortController();
  const abort = () => controller.abort(active.find((signal) => signal.aborted)?.reason);
  for (const signal of active) {
    if (signal.aborted) { abort(); break; }
    signal.addEventListener("abort", abort, { once: true });
  }
  return controller.signal;
}

/** Query NVD for HIGH+ CVEs for one technology with an explicit provider outcome. */
async function lookupCvesForTechnology(techName, maxResults = 5, opts = {}) {
  if (!ALLOWED_CVE_TECHNOLOGIES.has(techName)) {
    return { status: "complete", cves: [] };
  }
  const accounting = opts.accounting || null;
  const keyword = CVE_KEYWORD_MAP[techName] || techName;
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("keywordSearch",   keyword);
  url.searchParams.set("resultsPerPage",  String(maxResults));
  url.searchParams.set("cvssV3Severity",  "HIGH");
  try {
    const res = await safeFetch(url.toString(), {
      headers: { "User-Agent": "CyberMeters-Scanner/1.0" },
      signal:  combineLookupSignals(opts.signal, AbortSignal.timeout(10_000)),
      accounting,
    });
    if (!res || res.status !== 200) {
      return { status: "unavailable", cves: [] };
    }
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
    return { status: "complete", cves };
  } catch {
    return { status: "unavailable", cves: [] };
  }
}

// ── Version-aware CVE correlation ────────────────────────────────────────────
// When a response header reports a product version (e.g. "nginx/1.18.0",
// "Apache/2.4.41 (Ubuntu)", "PHP/7.4.3"), NVD is asked for the CVEs that affect
// that exact CPE, and each returned record is re-checked locally against its
// own applicability statements. Only explicit applicability counts: an exact
// version match, or a version range with an upper bound that contains the
// reported version. NVD records that apply to "all versions" without a bound,
// and configurations that also require a specific platform (AND), are not
// counted — precision over recall. Everything stays honest about the source:
// the version is what the server REPORTS; distributions often backport fixes
// without changing it, so a match is "listed as affected", not "vulnerable".

export const CVE_VERSION_EVIDENCE_VERSION = "cve-version-evidence-v1";

const REPORTED_VERSION_PATTERNS = [
  { tech: "nginx",     re: /\bnginx\/(\d+\.\d+\.\d+)\b/i },
  { tech: "openresty", re: /\bopenresty\/(\d+\.\d+\.\d+(?:\.\d+)?)\b/i },
  { tech: "apache",    re: /\bApache\/(\d+\.\d+\.\d+)\b/i },
  { tech: "iis",       re: /\bMicrosoft-IIS\/(\d+\.\d+)\b/i },
  { tech: "php",       re: /\bPHP\/(\d+\.\d+\.\d+)\b/i },
  { tech: "lighttpd",  re: /\blighttpd\/(\d+\.\d+\.\d+)\b/i },
];

// NVD CPE vendor:product names, in lookup order. nginx moved to the f5 vendor
// in the CPE dictionary; older records remain under nginx:nginx.
const VERSION_CPE_CANDIDATES = {
  nginx:     ["f5:nginx", "nginx:nginx"],
  openresty: ["openresty:openresty"],
  apache:    ["apache:http_server"],
  iis:       ["microsoft:internet_information_services"],
  php:       ["php:php"],
  lighttpd:  ["lighttpd:lighttpd"],
};

export function parseReportedVersions(techModule) {
  const found = new Map();
  for (const [source, value] of [["server_header", techModule?.server], ["x_powered_by_header", techModule?.x_powered_by]]) {
    if (typeof value !== "string" || !value) continue;
    const platform = value.match(/\(([^)]{1,40})\)/)?.[1] || null;
    for (const { tech, re } of REPORTED_VERSION_PATTERNS) {
      const version = value.match(re)?.[1];
      if (version && !found.has(tech)) found.set(tech, { version, source, platform_hint: platform });
    }
  }
  return found;
}

// Numeric dotted comparison; null when either side is not purely numeric
// (then the record is not counted rather than guessed).
export function compareVersions(a, b) {
  const pa = String(a).split("."), pb = String(b).split(".");
  if (![...pa, ...pb].every((part) => /^\d+$/.test(part))) return null;
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = Number(pa[i] || 0), y = Number(pb[i] || 0);
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}

function withinBounds(match, version) {
  const checks = [
    [match.versionStartIncluding, (c) => c >= 0],
    [match.versionStartExcluding, (c) => c > 0],
    [match.versionEndIncluding,   (c) => c <= 0],
    [match.versionEndExcluding,   (c) => c < 0],
  ];
  for (const [bound, accept] of checks) {
    if (bound == null) continue;
    const cmp = compareVersions(version, bound);
    if (cmp === null || !accept(cmp)) return false;
  }
  return true;
}

export function cpeAppliesExplicitly(cve, vendorProduct, version) {
  const prefix = `cpe:2.3:a:${vendorProduct}:`;
  for (const config of cve?.configurations || []) {
    if (String(config?.operator || "OR").toUpperCase() === "AND") continue;
    for (const node of config?.nodes || []) {
      if (node?.negate) continue;
      for (const match of node?.cpeMatch || []) {
        if (match?.vulnerable !== true || typeof match.criteria !== "string" || !match.criteria.startsWith(prefix)) continue;
        const criteriaVersion = match.criteria.split(":")[5];
        const ranged = match.versionStartIncluding || match.versionStartExcluding || match.versionEndIncluding || match.versionEndExcluding;
        if (criteriaVersion && criteriaVersion !== "*" && criteriaVersion !== "-") {
          if (!ranged && compareVersions(criteriaVersion, version) === 0) return true;
          continue;
        }
        if (!(match.versionEndIncluding || match.versionEndExcluding)) continue;
        if (withinBounds(match, version)) return true;
      }
    }
  }
  return false;
}

function cvssOf(cve) {
  const metrics = cve?.metrics || {};
  const pick = metrics.cvssMetricV31?.[0]?.cvssData || metrics.cvssMetricV30?.[0]?.cvssData || null;
  if (pick) return { cvss_score: pick.baseScore ?? null, severity: pick.baseSeverity || "UNKNOWN" };
  const v2 = metrics.cvssMetricV2?.[0]?.cvssData;
  if (v2) {
    const score = v2.baseScore;
    return { cvss_score: score ?? null, severity: score >= 7 ? "HIGH" : score >= 4 ? "MEDIUM" : "LOW" };
  }
  return { cvss_score: null, severity: "UNKNOWN" };
}

async function lookupVersionCves(tech, version, opts, budget) {
  const candidates = VERSION_CPE_CANDIDATES[tech] || [];
  for (let i = 0; i < candidates.length; i++) {
    if (budget.calls <= budget.reserve) return { status: "budget_exhausted", cves: [], cpe: null };
    const vendorProduct = candidates[i];
    const cpe = `cpe:2.3:a:${vendorProduct}:${version}:*:*:*:*:*:*:*`;
    const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
    url.searchParams.set("cpeName", cpe);
    budget.calls -= 1;
    if (budget.made++ > 0) await new Promise((r) => setTimeout(r, 300));
    let data;
    try {
      const res = await safeFetch(url.toString(), {
        headers: { "User-Agent": "CyberMeters-Scanner/1.0" },
        signal: combineLookupSignals(opts.signal, AbortSignal.timeout(10_000)),
        accounting: opts.accounting || null,
      });
      if (!res || res.status !== 200) return { status: "unavailable", cves: [], cpe };
      data = await res.json();
    } catch {
      return { status: "unavailable", cves: [], cpe };
    }
    const records = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
    // An empty answer under one vendor name is not evidence of "no CVEs" while
    // another dictionary name remains; a non-empty one is authoritative.
    if (records.length === 0 && i < candidates.length - 1) continue;
    const cves = [];
    for (const item of records) {
      const cve = item?.cve || {};
      if (!cve.id || /reject/i.test(String(cve.vulnStatus || ""))) continue;
      if (!cpeAppliesExplicitly(cve, vendorProduct, version)) continue;
      const description = (cve.descriptions || []).find((d) => d.lang === "en")?.value || "";
      cves.push({
        cve_id: cve.id,
        ...cvssOf(cve),
        description: description.length > 300 ? description.slice(0, 297) + "..." : description,
        technology: tech,
        version_matched: true,
        matched_version: version,
        published: cve.published || null,
      });
    }
    return { status: "complete", cves, cpe };
  }
  return { status: "complete", cves: [], cpe: null };
}

const EPSS_URL = "https://api.first.org/data/v1/epss";

// One batched EPSS read inside the module's remaining time. Failure leaves
// epss null with an explicit status — never a fabricated probability.
async function fetchEpss(cveIds, opts, timeoutMs) {
  if (!cveIds.length) return { status: "not_applicable", scores: new Map() };
  if (timeoutMs < 500) return { status: "skipped_deadline", scores: new Map() };
  const ids = [];
  let length = 0;
  for (const id of cveIds) {
    if (length + id.length + 1 > 1_900) break;
    ids.push(id); length += id.length + 1;
  }
  const url = new URL(EPSS_URL);
  url.searchParams.set("cve", ids.join(","));
  try {
    const res = await safeFetch(url.toString(), {
      headers: { "User-Agent": "CyberMeters-Scanner/1.0" },
      signal: combineLookupSignals(opts.signal, AbortSignal.timeout(timeoutMs)),
      accounting: opts.accounting || null,
    });
    if (!res || res.status !== 200) return { status: "unavailable", scores: new Map() };
    const body = await res.json();
    const scores = new Map();
    for (const row of Array.isArray(body?.data) ? body.data : []) {
      const epss = Number(row?.epss), percentile = Number(row?.percentile);
      if (row?.cve && Number.isFinite(epss) && Number.isFinite(percentile)) {
        scores.set(row.cve, { epss, epss_percentile: percentile, epss_date: row.date || null });
      }
    }
    return { status: ids.length < cveIds.length ? "partial" : "complete", scores };
  } catch {
    return { status: "unavailable", scores: new Map() };
  }
}

// KEV membership from the R2 catalogue cache only (fresh or stale); the KEV
// module owns origin fetches. No cache → membership unknown, stated as such.
export async function readKevCatalogueIds(env) {
  if (!env?.cybermeters_reports?.get) return { status: "unavailable", ids: null };
  try {
    const obj = await env.cybermeters_reports.get(KEV_CACHE_KEY);
    if (!obj) return { status: "unavailable", ids: null };
    const parsed = JSON.parse(await obj.text());
    if (!Array.isArray(parsed?.vulnerabilities)) return { status: "unavailable", ids: null };
    return { status: "complete", ids: new Set(parsed.vulnerabilities.map((row) => row?.cveID).filter(Boolean)) };
  } catch {
    return { status: "unavailable", ids: null };
  }
}

function rankVersionCves(a, b) {
  return Number(b.kev === true) - Number(a.kev === true)
    || (b.epss ?? -1) - (a.epss ?? -1)
    || (b.cvss_score ?? -1) - (a.cvss_score ?? -1)
    || a.cve_id.localeCompare(b.cve_id);
}

/**
 * Run CVE correlation for detected technologies.
 * Ported from cve_lookup.correlate_cves() — limits to 3 technologies,
 * 300ms delay between NVD requests to respect free-tier rate limits,
 * skips exploit-db check (Worker network budget). A technology whose version
 * is reported in a response header uses the version-aware CPE lookup above;
 * the rest keep the version-blind keyword search. At most 3 NVD calls in
 * total, and the optional EPSS read only uses time left inside the module's
 * durable cap.
 */
export async function runCveModule(techModule, opts = {}) {
  const accounting = opts.accounting || null;
  const dependencyFailure = cveDependencyFailure(techModule);
  if (dependencyFailure) {
    return {
      technologies_checked: [], results: {}, total_cves: 0,
      critical_count: 0, high_count: 0, source: "nvd_api",
      cve_coverage: CVE_COVERAGE.DEPENDENCY_UNAVAILABLE,
      incomplete: true,
      outcome: dependencyFailure.outcome,
      incomplete_reason: dependencyFailure.reason,
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

  // Versioned technologies first: the bounded NVD budget goes to precise,
  // version-aware evidence before version-blind keyword searches.
  const reported = parseReportedVersions(techModule);
  for (const tech of reported.keys()) {
    if (ALLOWED_CVE_TECHNOLOGIES.has(tech)) candidates.add(tech);
  }
  // Limit to 3 to bound runtime (NVD free tier: no API key → 5 req/30s)
  const toCheck = [...candidates]
    .sort((a, b) => Number(reported.has(b)) - Number(reported.has(a)))
    .slice(0, 3);
  const results = {};
  const lookupStatuses = {};
  const versionResults = {};
  const versionEvidence = {};
  let totalCves = 0, criticalCount = 0, highCount = 0;

  if (toCheck.length === 0) {
    return {
      technologies_checked: [],
      lookup_statuses: {},
      results: {},
      total_cves: 0,
      critical_count: 0,
      high_count: 0,
      source: "nvd_api",
      cve_coverage: CVE_COVERAGE.NOT_APPLICABLE,
    };
  }

  const startedAt = Date.now();
  // Three NVD calls in total, shared by every technology; each later
  // technology keeps one call reserved so a vendor-name fallback can never
  // starve it.
  const budget = { calls: 3, reserve: 0, made: 0 };
  for (const [index, tech] of toCheck.entries()) {
    budget.reserve = toCheck.length - index - 1;
    const reportedVersion = reported.get(tech);
    if (reportedVersion) {
      const lookup = await lookupVersionCves(tech, reportedVersion.version, { accounting, signal: opts.signal || null }, budget);
      lookupStatuses[tech] = { status: lookup.status, mode: "reported_version" };
      versionEvidence[tech] = {
        version: reportedVersion.version,
        source: reportedVersion.source,
        platform_hint: reportedVersion.platform_hint,
        cpe: lookup.cpe,
        status: lookup.status,
        matched: lookup.cves.length,
      };
      if (lookup.cves.length > 0) versionResults[tech] = lookup.cves;
      continue;
    }
    budget.calls -= 1;
    // Respect NVD free-tier rate limit between requests
    if (budget.made++ > 0) await new Promise(r => setTimeout(r, 300));
    const lookup = await lookupCvesForTechnology(tech, 5, {
      accounting,
      signal: opts.signal || null,
    });
    const cves = lookup.cves;
    lookupStatuses[tech] = { status: lookup.status };
    if (cves.length > 0) {
      results[tech] = cves;
      totalCves   += cves.length;
      for (const c of cves) {
        if (c.severity === "CRITICAL") criticalCount++;
        else if (c.severity === "HIGH") highCount++;
      }
    }
  }

  let versionFields = {};
  if (Object.keys(versionEvidence).length > 0) {
    const versionIds = [...new Set(Object.values(versionResults).flat().map((c) => c.cve_id))];
    const kev = versionIds.length ? await readKevCatalogueIds(opts.env) : { status: "not_applicable", ids: null };
    const remainingMs = 31_000 - (Date.now() - startedAt);
    const epss = await fetchEpss(versionIds, { accounting, signal: opts.signal || null }, Math.min(4_000, remainingMs));
    let kevTotal = 0;
    for (const [tech, list] of Object.entries(versionResults)) {
      for (const cve of list) {
        cve.kev = kev.ids ? kev.ids.has(cve.cve_id) : null;
        const score = epss.scores.get(cve.cve_id);
        cve.epss = score?.epss ?? null;
        cve.epss_percentile = score?.epss_percentile ?? null;
        if (cve.kev === true) kevTotal++;
      }
      list.sort(rankVersionCves);
      versionEvidence[tech].matched = list.length;
      versionResults[tech] = list.slice(0, 25);
    }
    versionFields = {
      version_evidence_version: CVE_VERSION_EVIDENCE_VERSION,
      version_evidence: versionEvidence,
      version_results: versionResults,
      version_matched_total: versionIds.length,
      version_kev_total: kevTotal,
      kev_status: kev.status,
      epss_status: epss.status,
    };
  }

  const lookupRows = Object.values(lookupStatuses);
  const completedLookups = lookupRows.filter((row) => row.status === "complete").length;
  const cveCoverage = completedLookups === lookupRows.length
    ? CVE_COVERAGE.COMPLETE
    : completedLookups === 0
      ? CVE_COVERAGE.UNAVAILABLE
      : CVE_COVERAGE.PARTIAL;
  const incomplete = cveCoverage !== CVE_COVERAGE.COMPLETE;
  const outcome = cveCoverage === CVE_COVERAGE.UNAVAILABLE
    ? "provider_unavailable"
    : cveCoverage === CVE_COVERAGE.PARTIAL
      ? "provider_partial"
      : null;

  return {
    technologies_checked: toCheck,
    lookup_statuses: lookupStatuses,
    results,
    total_cves:     totalCves,
    critical_count: criticalCount,
    high_count:     highCount,
    source:         "nvd_api",
    cve_coverage:   cveCoverage,
    ...versionFields,
    ...(incomplete ? {
      incomplete: true,
      outcome,
      incomplete_reason: cveCoverage === CVE_COVERAGE.UNAVAILABLE
        ? "all_cve_lookups_unavailable"
        : "some_cve_lookups_unavailable",
    } : {}),
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
  // A KEV keyword hit is score-bearing only when the technology fingerprint came
  // from a canonical serviceable origin response. Reuse the shared authority;
  // never infer serviceability from a status code or from the presence of a
  // technology string.
  if (!maySupportDefectConclusion(techModule?.serviceability_contract)) {
    return {
      matches: [], checked: 0, matched: 0, source: "cisa_kev",
      incomplete: true,
      outcome: "dependency_unavailable",
      incomplete_reason: "technology_serviceability_unconfirmed",
    };
  }

  const fingerprints = Array.isArray(techModule?.technology_fingerprints)
    ? techModule.technology_fingerprints
    : [];
  const fingerprintByTech = new Map(
    fingerprints
      .filter((row) => row?.technology)
      .map((row) => [String(row.technology).toLowerCase(), row]),
  );
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
      const matchedTechnology = detectedTechs.find(
        (t) => t.length >= 3 && (product.includes(t) || vendor.includes(t)),
      );
      if (!matchedTechnology) continue;
      const fingerprint = fingerprintByTech.get(matchedTechnology) || null;
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
        matched_technology:  fingerprint?.technology || matchedTechnology,
        fingerprint_source:  fingerprint?.source || null,
        fingerprint_confidence: Number.isFinite(Number(fingerprint?.confidence))
          ? Number(fingerprint.confidence) : null,
        version_confirmed:   false,
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
