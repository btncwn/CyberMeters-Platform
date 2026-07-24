// ── Subdomain discovery + brute-force scan module ──
// CT-log + RDAP-based subdomain discovery, sensitive-label classification, and a bounded
// DNS brute-force pass with wildcard filtering. Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). Only the three run*/filter* entry points are public; the label
// sets, isSensitiveSubdomain and _subdomainsCoreWork are module-internal.
import { dnsQuery } from "./dns.js";
import { normalizeDiscoveredHostname } from "./hostnames.js";
import { customerSafeFailure } from "../lib/errors.js";
import { createCertificateTransparencyCache } from "./ct-provider-cache.js";

/**
 * Subdomain names whose presence suggests a development, staging, or
 * administrative asset — used for risk detection only, not for blocking.
 */
const SENSITIVE_LABELS = new Set([
  // Non-production environments
  "dev", "development", "develop",
  "staging", "stage", "stg", "stag",
  "test", "testing", "tests",
  "qa", "uat", "sandbox",
  "alpha", "beta",
  "preprod", "pre-prod", "pre",
  "demo",
  // Admin / control panels
  "admin", "administrator", "admins", "adm",
  "cp", "cpanel", "webmin", "plesk", "whm",
  "manager", "manage", "control", "panel",
  "dashboard", "portal",
  // Authentication / access
  "auth", "login", "sso", "oauth",
  "vpn", "remote", "rdp",
  // Data / storage
  "db", "database", "sql", "mysql", "mongo", "mongodb",
  "redis", "elastic", "elasticsearch",
  "kafka", "solr",
  "backup", "backups", "bak",
  // Observability / monitoring
  "monitor", "monitoring", "grafana", "kibana", "prometheus",
  // Source control / CI/CD
  "git", "gitlab", "bitbucket", "github",
  "jenkins", "ci", "cd", "build", "deploy",
  "sonar", "sonarqube", "nexus", "artifactory",
  // Apps / API / mobile
  "api", "app", "mobile",
  // Internal / sensitive
  "internal", "intranet", "corp", "private",
  "old", "legacy", "archive", "temp", "tmp",
  // Mail
  "mail", "webmail", "smtp", "mx",
  // Remote access
  "ftp", "ssh",
  // Collaboration
  "jira", "confluence", "wiki",
]);

function isSensitiveSubdomain(hostname, domain) {
  // Strip the root domain to get the subdomain part(s)
  const sub = hostname.endsWith("." + domain)
    ? hostname.slice(0, -(domain.length + 1))
    : hostname;

  // Split on dots and check each label
  return sub.split(".").some((label) => {
    const l = label.toLowerCase();
    if (SENSITIVE_LABELS.has(l)) return true;
    // Pattern variants like dev1, test2, stage-eu, etc.
    if (/^(dev|test|stage|stg|qa|uat|sandbox)\d*$/.test(l)) return true;
    if (/^(dev|test|stage|stg)-/.test(l) || /-(dev|test|stage|stg)$/.test(l)) return true;
    return false;
  });
}

// ── Subdomain Discovery v2 ────────────────────────────────────────────────────
// Two Certificate Transparency sources run in parallel:
//   1. crt.sh          — certificate search (wildcard query, large historical set)
//   2. CertSpotter     — issuance index (different index, no API key required)
// Results are merged and deduplicated into a single sorted list.
// If one source fails the other still contributes — scan never aborts.
// Per-source counts and errors are exposed in modules.subdomains.sources.

export async function runSubdomainsModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  const ctCache = opts.ctCache || createCertificateTransparencyCache({ signal: opts.signal });
  const SOURCE    = "certificate_transparency_multi_source";
  const PER_CAP   = 200;   // max unique names from each CT source
  const MERGE_CAP = 300;   // cap on the merged deduplicated set
  // Tier 1 (waitUntil-cancellation guard): the shared provider cache owns its leaf
  // deadlines; this outer 15s cap still bounds provider parsing plus wildcard DNS.
  // On cap the scan continues with an honest empty CT result (never fake clean).
  const HARD_CAP_MS = 15_000;

  // Graceful fallback — returned on hard-cap timeout or unexpected throw
  const emptyResult = (error, wildcardDns = false, wildcardHost = null) => ({
    count:              0,
    items:              [],
    sensitive:          [],
    source:             SOURCE,
    sources:            { crt_sh: { count: 0, error }, certspotter: { count: 0, error } },
    wildcard_dns:       wildcardDns,
    wildcard_dns_addresses: [],
    wildcard_test_host: wildcardHost,
    wildcard_warning:   null,
    error,
  });

  try {
    // Race the inner async work against a hard-cap timer.
    // If the hard cap fires first the scan continues with an empty result;
    // the inner work is abandoned (Cloudflare GC's the hanging fetch).
    return await Promise.race([
      _subdomainsCoreWork(domain, SOURCE, PER_CAP, MERGE_CAP, { accounting, ctCache }),
      new Promise((resolve) =>
        setTimeout(() =>
          resolve(emptyResult("Subdomain discovery timed out (15s hard cap)")),
          HARD_CAP_MS
        )
      ),
    ]);
  } catch (err) {
    return emptyResult(err?.message ?? "Subdomain module threw unexpectedly");
  }
}

/**
 * Inner implementation — separated so the hard-cap race wrapper stays clean.
 * All 4 network calls fire in parallel:
 *   • Wildcard DNS A  (6 s DoH timeout via dnsQuery)
 *   • Wildcard DNS AAAA
 *   • shared crt.sh provider promise
 *   • shared CertSpotter provider promise
 */
async function _subdomainsCoreWork(domain, SOURCE, PER_CAP, MERGE_CAP, opts = {}) {
  const accounting = opts.accounting || null;
  const ctCache = opts.ctCache;
  const wildcardLabel = `cybermeters-wildcard-check-${Math.random().toString(36).slice(2, 10)}`;
  const wildcardHost  = `${wildcardLabel}.${domain}`;

  // ── Fire all 4 network calls in parallel ────────────────────────────────
  const [wASettled, wAAAASettled, crtShSettled, certSpotterSettled] =
    await Promise.allSettled([
      dnsQuery(wildcardHost, "A", { accounting }),
      dnsQuery(wildcardHost, "AAAA", { accounting }),
      ctCache.get(domain, "crt_sh", { accounting }),
      ctCache.get(domain, "certspotter", { accounting }),
    ]);

  // ── Wildcard DNS result ─────────────────────────────────────────────────
  const aAnswers    = wASettled.status    === "fulfilled" ? (wASettled.value.Answer    || []) : [];
  const aaaaAnswers = wAAAASettled.status === "fulfilled" ? (wAAAASettled.value.Answer || []) : [];
  const wildcardDnsAnswers = [...new Set(
    [...aAnswers, ...aaaaAnswers]
      .filter((answer) => answer.type === 1 || answer.type === 28)
      .map((answer) => String(answer.data || "").toLowerCase())
      .filter(Boolean)
  )].sort();
  const wildcardDnsAddresses = [...new Set(
    aAnswers
      .filter((answer) => answer.type === 1)
      .map((answer) => String(answer.data || "").toLowerCase())
      .filter(Boolean)
  )].sort();
  const wildcardDns     = wildcardDnsAnswers.length > 0;
  const wildcardWarning = wildcardDns
    ? "Wildcard DNS detected. Subdomain discovery results may include false positives."
    : null;

  const seen    = new Set();
  const sources = { crt_sh: null, certspotter: null };

  // ── Source 1: crt.sh ───────────────────────────────────────────────────
  try {
    const result = crtShSettled.status === "fulfilled" ? crtShSettled.value : null;
    if (!result) {
      sources.crt_sh = { count: 0, error: customerSafeFailure("scan/ct/crt-sh", crtShSettled.reason, "fetch failed") };
    } else if (result.status === "unavailable") {
      sources.crt_sh = { count: 0, error: result.error };
    } else {
      const rootDomain = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
      const rawData = result.data.filter((entry) => [
        ...(entry.name_value || "").split(/\n/),
        entry.common_name || "",
      ].some((raw) => {
        const name = String(raw || "").trim().toLowerCase().replace(/\.$/, "");
        return name !== rootDomain && name.endsWith(`.${rootDomain}`);
      }));
      const before = seen.size;
      outer: for (const entry of rawData.slice(0, 2_000)) {
        const names = [
          ...(entry.name_value || "").split(/\n/),
          entry.common_name || "",
        ];
        for (const raw of names) {
          const name = normalizeDiscoveredHostname(raw, domain);
          if (!name) continue;
          seen.add(name);
          if (seen.size - before >= PER_CAP) break outer;
        }
      }
      sources.crt_sh = { count: seen.size - before, error: null };
    }
  } catch (err) {
    sources.crt_sh = { count: 0, error: customerSafeFailure("scan/ct/crt-sh-parse", err, "parse error") };
  }

  // ── Source 2: CertSpotter ─────────────────────────────────────────────
  // Response: [{ dns_names: ["sub.example.com", ...], ... }, ...]
  try {
    const result = certSpotterSettled.status === "fulfilled" ? certSpotterSettled.value : null;
    if (!result) {
      sources.certspotter = { count: 0, error: customerSafeFailure("scan/ct/certspotter", certSpotterSettled.reason, "fetch failed") };
    } else if (result.status === "unavailable") {
      sources.certspotter = { count: 0, error: result.error };
    } else {
      const before = seen.size;
      outer: for (const entry of result.data) {
        for (const name of entry.dns_names || []) {
          const n = normalizeDiscoveredHostname(name, domain);
          if (!n) continue;
          seen.add(n);
          if (seen.size - before >= PER_CAP) break outer;
        }
      }
      sources.certspotter = { count: seen.size - before, error: null };
    }
  } catch (err) {
    sources.certspotter = { count: 0, error: customerSafeFailure("scan/ct/certspotter-parse", err, "parse error") };
  }

  // ── Both CT sources failed ────────────────────────────────────────────
  // Sprint 10C: CT source failures (rate limits, timeouts, HTTP errors) are external
  // service issues — not a domain security failure.  Store the detail in ct_error
  // (available for diagnostics in modules.subdomains.ct_error) but do NOT set the
  // top-level error field.  scan_quality must stay "complete" for these cases.
  if (seen.size === 0 && sources.crt_sh?.error && sources.certspotter?.error) {
    return {
      count:              0,
      items:              [],
      sensitive:          [],
      source:             SOURCE,
      sources,
      wildcard_dns:       wildcardDns,
      wildcard_dns_addresses: wildcardDnsAddresses,
      wildcard_test_host: wildcardHost,
      wildcard_warning:   wildcardWarning,
      ct_error: `Both CT sources failed — crt.sh: ${sources.crt_sh.error}; certspotter: ${sources.certspotter.error}`,
      // Keep the external outage non-fatal to the overall scan, while making
      // this module ineligible to support a "no subdomains found" conclusion.
      // The canonical monitoring-state resolver carries the provider-specific
      // signal; this module-level flag is defence in depth for older consumers.
      incomplete: true,
      incomplete_reason: "ct_sources_unavailable",
      error:    null,   // never block core scan quality for external CT failures
    };
  }

  // ── Merge, cap, sort ─────────────────────────────────────────────────
  const items     = [...seen].slice(0, MERGE_CAP).sort();
  const sensitive = items.filter((h) => isSensitiveSubdomain(h, domain));
  const ctCoverageDegraded = !!(sources.crt_sh?.error || sources.certspotter?.error);

  return {
    count:              items.length,
    items,
    sensitive,
    source:             SOURCE,
    sources,
    wildcard_dns:       wildcardDns,
    wildcard_dns_addresses: wildcardDnsAddresses,
    wildcard_test_host: wildcardHost,
    wildcard_warning:   wildcardWarning,
    ...(ctCoverageDegraded
      ? { incomplete: true, incomplete_reason: "ct_source_degraded" }
      : {}),
    error:              null,
  };
}

// ── DNS Brute-Force Discovery ─────────────────────────────────────────────────
// High-value curated wordlist capped at BRUTEFORCE_MAX_NAMES to stay within
// the Cloudflare Worker free-plan 50-subrequest budget.
// Runs in parallel with Phase 1 modules; bounded by BRUTEFORCE_TIMEOUT_MS.
// Results are merged into modules.subdomains.items so takeover + exposure
// detection automatically benefit from the expanded list.

export const BRUTEFORCE_MAX_NAMES  = 15;
const BRUTEFORCE_TIMEOUT_MS = 6_000;

// High-value names only — exactly BRUTEFORCE_MAX_NAMES entries.
const BRUTE_FORCE_WORDLIST = [
  "www", "mail", "email", "webmail", "portal",
  "admin", "api", "app", "dev", "staging",
  "test", "vpn", "remote", "login", "dashboard",
];

// Mail-infrastructure subdomains often publish MX/TXT but no A record, so the
// A-only sweep above misses them (e.g. reports. for DMARC RUA ingestion, send.
// for a mail relay). A small MX pass surfaces this external footprint too.
// Bounded to keep well within the subrequest budget.
const MAIL_SUBDOMAIN_LABELS = [
  "reports", "send", "mx", "smtp", "mta", "mg", "bounce", "dmarc",
];

/**
 * Probe the wordlist against `domain` via DoH A-record lookups.
 * Returns any names that resolve, with source = "dns_bruteforce".
 * Hard-capped at BRUTEFORCE_TIMEOUT_MS — returns whatever has resolved by then.
 */
export async function runBruteforceModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  const HARD_CAP_MS = BRUTEFORCE_TIMEOUT_MS;

  const empty = (error = null) => ({
    checked: 0,
    found:   0,
    items:   [],
    source:  "dns_bruteforce",
    error,
  });

  try {
    const candidates = BRUTE_FORCE_WORDLIST.slice(0, BRUTEFORCE_MAX_NAMES).map((label) => `${label}.${domain}`);

    const settled = await Promise.race([
      Promise.allSettled(
        candidates.map((host) =>
          dnsQuery(host, "A", { accounting }).then((r) => ({ host, answers: r.Answer || [] }))
        )
      ),
      // Hard cap: resolve with an empty-array sentinel so the race always resolves
      new Promise((resolve) => setTimeout(() => resolve([]), HARD_CAP_MS)),
    ]);

    // If the timeout fired, `settled` is [] (not an allSettled array)
    if (!Array.isArray(settled) || settled.length === 0) {
      return { checked: candidates.length, found: 0, items: [], source: "dns_bruteforce", error: "timed out" };
    }

    const found = [];
    for (const s of settled) {
      if (s.status !== "fulfilled") continue;
      const { host, answers } = s.value;
      if (answers && answers.length > 0) {
        const ips = answers.filter((a) => a.type === 1).map((a) => a.data);
        found.push({ hostname: host, ip_addresses: ips, source: "dns_bruteforce" });
      }
    }

    // ── Mail-only subdomains (MX but no A) — bounded second pass ─────────────
    // Surfaces email infrastructure like reports. / send. that the A sweep
    // cannot see. Best-effort and time-capped; a failure never fails the module.
    const foundHosts = new Set(found.map((f) => f.hostname));
    const mailCandidates = MAIL_SUBDOMAIN_LABELS
      .map((label) => `${label}.${domain}`)
      .filter((host) => !foundHosts.has(host));
    try {
      const mxSettled = await Promise.race([
        Promise.allSettled(
          mailCandidates.map((host) =>
            dnsQuery(host, "MX", { accounting }).then((r) => ({ host, answers: r.Answer || [] }))
          )
        ),
        new Promise((resolve) => setTimeout(() => resolve([]), HARD_CAP_MS)),
      ]);
      if (Array.isArray(mxSettled)) {
        for (const s of mxSettled) {
          if (s.status !== "fulfilled") continue;
          const { host, answers } = s.value;
          if (answers && answers.length > 0) {
            found.push({ hostname: host, ip_addresses: [], source: "dns_mx", mail_only: true });
          }
        }
      }
    } catch { /* mail probe is best-effort */ }

    return {
      checked: candidates.length + mailCandidates.length,
      found:   found.length,
      items:   found,
      source:  "dns_bruteforce",
      error:   null,
    };
  } catch (err) {
    return empty(err?.message ?? "Brute-force module failed");
  }
}

export function filterWildcardBruteforceResults(result, wildcardAddresses = []) {
  const wildcardSet = new Set((wildcardAddresses || []).map((value) => String(value).toLowerCase()));
  if (wildcardSet.size === 0 || !Array.isArray(result?.items)) return result;

  const items = [];
  const wildcardObservations = [];
  for (const item of result.items) {
    const addresses = [...new Set((item.ip_addresses || []).map((value) => String(value).toLowerCase()))].sort();
    const exactWildcardMatch = addresses.length === wildcardSet.size &&
      addresses.every((address) => wildcardSet.has(address));
    if (!exactWildcardMatch) {
      items.push(item);
      continue;
    }
    wildcardObservations.push({
      ...item,
      wildcard_match: true,
      classification: "observation",
      confidence: 40,
      score_impact: 0,
    });
  }

  return {
    ...result,
    found: items.length,
    items,
    wildcard_observations: wildcardObservations,
    wildcard_filtered: wildcardObservations.length,
  };
}
