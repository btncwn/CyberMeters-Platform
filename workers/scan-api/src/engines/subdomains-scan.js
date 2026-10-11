// ── Subdomain discovery + brute-force scan module ──
// Certificate Transparency (CertSpotter) subdomain discovery,
// sensitive-label classification, and a bounded
// DNS brute-force pass with wildcard filtering. Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). Only the three run*/filter* entry points are public; the label
// sets, isSensitiveSubdomain and _subdomainsCoreWork are module-internal.
import { dnsQuery } from "./dns.js";
import { normalizeDiscoveredHostname } from "./hostnames.js";
import { customerSafeFailure } from "../lib/errors.js";
import { createCertificateTransparencyCache } from "./ct-provider-cache.js";
import { CT_PROVIDERS, ctFailedSources } from "./ct-providers.js";
import { CT_SIBLING_GRACE_MS, raceCertificateTransparencyFirstSuccess } from "./ct-first-success.js";
import { coverageStateFromTruncation } from "./bounded-coverage.js";

/**
 * Subdomain names whose presence suggests a development, staging, or
 * administrative asset — used for risk detection only, not for blocking.
 *
 * Only names that point AWAY from a normal production service belong here: a
 * reachable match is scored and told it "suggests development, staging, or
 * administrative use". Everyday production names (app, api, mobile, mail,
 * webmail, smtp, mx, portal, dashboard, auth, login, sso, oauth) are not on the
 * list — every business publishes them, and naming them a sensitive exposure
 * is a false positive. Real admin panels are found by content in the admin
 * surface module, and identity-facing hosts by Identity Exposure.
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
  // Remote access
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
  // Internal / sensitive
  "internal", "intranet", "corp", "private",
  "old", "legacy", "archive", "temp", "tmp",
  // Legacy remote file / shell access
  "ftp", "ssh",
  // Collaboration
  "jira", "confluence", "wiki",
]);

export function projectSubdomainCtSource(result, measuredCount = null) {
  return {
    count: result?.status === "available" && Number.isFinite(Number(measuredCount))
      ? Math.max(0, Number(measuredCount))
      : 0,
    error: result?.status === "unavailable" ? result.error : null,
  };
}

export function isSensitiveSubdomain(hostname, domain) {
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
// Certificate Transparency names come from CertSpotter's issuance index
// (ct-providers.js), deduplicated into a single sorted list. A CT failure never
// aborts the scan; it makes this module honestly incomplete. The source count
// and error are exposed in modules.subdomains.sources.

export async function runSubdomainsModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  const cache = opts.cache || null;
  const ctCache = opts.ctCache || createCertificateTransparencyCache({
    accounting: () => accounting,
    signal: opts.globalSignal || opts.signal,
    globalDeadlineProvenance: opts.globalDeadlineProvenance,
  });
  const SOURCE    = "certificate_transparency_multi_source";
  const PER_CAP   = 300;   // max unique names from the CT source (the discovery ceiling)
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
    sources:            ctFailedSources(error),
    ct_providers:       [...CT_PROVIDERS],
    wildcard_dns:       wildcardDns,
    wildcard_dns_addresses: [],
    wildcard_test_host: wildcardHost,
    wildcard_warning:   null,
    error,
  });

  // CONSUMER RELEASE belongs to whoever owns this module's budget — the reserved
  // CT consumer boundary or scan-engine's capped-module boundary. Releasing here
  // too would make the module a second release path, so whether "released"
  // precedes "globally aborted" would depend on which path happened to run
  // first. One boundary, one release.

  try {
    // Race the inner async work against a hard-cap timer.
    // If the hard cap fires first the scan continues with an empty result;
    // the inner work is abandoned (Cloudflare GC's the hanging fetch).
    const work = _subdomainsCoreWork(
      domain,
      SOURCE,
      PER_CAP,
      MERGE_CAP,
      {
        accounting,
        cache,
        ctCache,
        signal: opts.signal,
        subOps: opts.subOps,
      },
    );
    return await Promise.race([
      work,
      new Promise((resolve) =>
        setTimeout(() => {
          resolve(emptyResult("Subdomain discovery timed out (15s hard cap)"));
        }, HARD_CAP_MS)
      ),
    ]);
  } catch (err) {
    return emptyResult(err?.message ?? "Subdomain module threw unexpectedly");
  }
}

/**
 * Inner implementation — separated so the hard-cap race wrapper stays clean.
 * All network calls fire in parallel:
 *   • Wildcard DNS A  (6 s DoH timeout via dnsQuery)
 *   • Wildcard DNS AAAA
 *   • shared CertSpotter provider promise
 */
async function _subdomainsCoreWork(domain, SOURCE, PER_CAP, MERGE_CAP, opts = {}) {
  const accounting = opts.accounting || null;
  const cache = opts.cache || null;
  const ctCache = opts.ctCache;
  const wildcardLabel = `cybermeters-wildcard-check-${Math.random().toString(36).slice(2, 10)}`;
  const wildcardHost  = `${wildcardLabel}.${domain}`;

  // Track B sub-operation timing — observational only, guarded at every call so a
  // broken/absent collector can never alter the parallel network calls or their
  // Promise.allSettled semantics. The ct_wait_* rows time THIS consumer's wait on
  // the shared provider promise (module wall-time attribution); the per-provider
  // network attempts remain the ct_provider_telemetry rows.
  const timedSubOp = (name, promise) => {
    let token = null;
    // Never open a row once the module signal is aborted — a post-cap operation
    // never truly began, and no row is the honest record for a non-event.
    try {
      token = opts.signal?.aborted === true ? null : (opts.subOps?.begin?.("subdomains", name) ?? null);
    } catch { token = null; }
    if (token == null) return promise;
    const settle = (outcome) => {
      try {
        const aborted = outcome !== "ok" && opts.signal?.aborted === true;
        opts.subOps?.finish?.(token, { outcome: aborted ? "aborted" : outcome, aborted });
      } catch { /* observational only */ }
    };
    return promise.then(
      // A shared CT provider promise RESOLVES with status:"unavailable" on failure
      // (never rejects); record that honestly instead of "ok". dnsQuery results
      // carry no lowercase `status` field and stay "ok".
      (v) => { settle(v?.status === "unavailable" ? "unavailable" : "ok"); return v; },
      (e) => { settle("error"); throw e; },
    );
  };

  // The shared provider wait is consumed through the first-success orchestrator,
  // whose released projection is immutable; a later terminal attempt remains
  // CT-R1 telemetry only.
  const ctReleasePromise = raceCertificateTransparencyFirstSuccess({
    ctCache,
    domain,
    module: "subdomains",
    accounting,
    signal: opts.signal,
    wrapProviderWait: (provider, promise) => timedSubOp(`ct_wait_${provider}`, promise),
    siblingGraceMs: CT_SIBLING_GRACE_MS,
  });

  // ── Fire all network calls in parallel ──────────────────────────────────
  const [wASettled, wAAAASettled, ctReleaseSettled] =
    await Promise.allSettled([
      timedSubOp("wildcard_dns_a", dnsQuery(wildcardHost, "A", { accounting, cache })),
      timedSubOp("wildcard_dns_aaaa", dnsQuery(wildcardHost, "AAAA", { accounting, cache })),
      ctReleasePromise,
    ]);
  const ctRelease = ctReleaseSettled.status === "fulfilled" ? ctReleaseSettled.value : null;
  const certSpotterSettled = ctRelease
    ? { status: "fulfilled", value: ctRelease.providers.certspotter }
    : { status: "rejected", reason: ctReleaseSettled.reason };

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
  const sources = {};
  let certSpotterUniqueTotal = null;
  let certSpotterUniqueKept = null;
  let certSpotterUniqueDroppedCount = null;
  let certSpotterProviderCapReached = null;

  // ── CertSpotter ───────────────────────────────────────────────────────
  // Response: [{ dns_names: ["sub.example.com", ...], ... }, ...]
  try {
    const result = certSpotterSettled.status === "fulfilled" ? certSpotterSettled.value : null;
    if (!result) {
      sources.certspotter = { count: 0, error: customerSafeFailure("scan/ct/certspotter", certSpotterSettled.reason, "fetch failed") };
    } else if (result.status === "unavailable") {
      sources.certspotter = projectSubdomainCtSource(result);
    } else {
      const certSpotterCandidates = new Set();
      for (const entry of result.data) {
        for (const name of entry.dns_names || []) {
          const normalized = normalizeDiscoveredHostname(name, domain);
          if (normalized) certSpotterCandidates.add(normalized);
        }
      }
      certSpotterUniqueTotal = certSpotterCandidates.size;
      const before = seen.size;
      outer: for (const entry of result.data) {
        for (const name of entry.dns_names || []) {
          const n = normalizeDiscoveredHostname(name, domain);
          if (!n) continue;
          seen.add(n);
          if (seen.size - before >= PER_CAP) break outer;
        }
      }
      certSpotterUniqueKept = seen.size - before;
      certSpotterUniqueDroppedCount = Math.max(0, certSpotterUniqueTotal - certSpotterUniqueKept);
      certSpotterProviderCapReached = certSpotterUniqueTotal > certSpotterUniqueKept;
      sources.certspotter = projectSubdomainCtSource(result, certSpotterUniqueKept);
    }
  } catch (err) {
    sources.certspotter = { count: 0, error: customerSafeFailure("scan/ct/certspotter-parse", err, "parse error") };
  }

  // ── CT source failed ──────────────────────────────────────────────────
  // Sprint 10C: CT source failures (rate limits, timeouts, HTTP errors) are external
  // service issues — not a domain security failure. Store the detail in ct_error
  // (available for diagnostics in modules.subdomains.ct_error) but do NOT set the
  // top-level error field; the module is marked incomplete instead.
  const usedSources = CT_PROVIDERS.map((provider) => [provider, sources[provider]]);
  const allCtSourcesFailed = usedSources.every(([, row]) => row?.error);
  if (seen.size === 0 && allCtSourcesFailed) {
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
      ct_error: `CT source failed — ${usedSources.map(([provider, row]) => `${provider}: ${row.error}`).join("; ")}`,
      ct_providers: [...CT_PROVIDERS],
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
  const mergedCandidateTotal = seen.size;
  const mergedDroppedCount = Math.max(0, mergedCandidateTotal - items.length);
  const mergedCapReached = mergedCandidateTotal > items.length;
  const capReached = certSpotterProviderCapReached === true || mergedCapReached;
  const discoveryCoverage = {
    per_provider: {
      certspotter_unique_total: certSpotterUniqueTotal,
      certspotter_unique_kept: certSpotterUniqueKept,
      certspotter_dropped_count: certSpotterUniqueDroppedCount,
      certspotter_cap_reached: certSpotterProviderCapReached,
    },
    merged: {
      candidate_total: mergedCandidateTotal,
      kept: items.length,
      dropped_count: mergedDroppedCount,
      cap_reached: mergedCapReached,
      selection_order: "provider_response",
    },
    coverage_state: coverageStateFromTruncation(capReached),
  };

  return {
    count:              items.length,
    items,
    sensitive,
    source:             SOURCE,
    sources,
    ct_providers:       [...CT_PROVIDERS],
    discovery_coverage: discoveryCoverage,
    wildcard_dns:       wildcardDns,
    wildcard_dns_addresses: wildcardDnsAddresses,
    wildcard_test_host: wildcardHost,
    wildcard_warning:   wildcardWarning,
    error:              null,
  };
}

// ── DNS Brute-Force Discovery ─────────────────────────────────────────────────
// Curated wordlist of the names that carry most small-business external risk
// (admin and login surfaces, remote access, mail portals, dev/staging copies,
// self-hosted tooling). One DoH A lookup per name, all in parallel, bounded by
// BRUTEFORCE_TIMEOUT_MS. The Worker's provider ceiling is 10,000 subrequests;
// the named-variable envelope in validate-f026-capacity-completeness-truth.js
// pins the total. Results are merged into the discovered set so takeover and
// exposure detection benefit, and wildcard answers are filtered downstream.

export const BRUTEFORCE_MAX_NAMES  = 40;
const BRUTEFORCE_TIMEOUT_MS = 6_000;

// Exactly BRUTEFORCE_MAX_NAMES entries. Must contain every critical prefix in
// scan-budget.js (mandatory and optional) so the production path never misses
// a name the reserved path treats as critical.
export const BRUTE_FORCE_WORDLIST = Object.freeze([
  "www", "mail", "email", "webmail", "portal",
  "admin", "api", "app", "dev", "staging",
  "test", "vpn", "remote", "login", "dashboard",
  "manage", "management", "sso", "auth", "owa",
  "exchange", "autodiscover", "intranet", "cpanel", "citrix",
  "gateway", "rdp", "ftp", "sftp", "files",
  "backup", "git", "gitlab", "jenkins", "jira",
  "grafana", "uat", "beta", "old", "shop",
]);

// First labels whose exposure matters most: administration, authentication,
// remote access, pre-production copies and self-hosted tooling. Exposure
// probing is capped (asset-intel probes the first 50 targets), so these are
// ordered first and can never be crowded out by ordinary CT names.
export const HIGH_VALUE_EXPOSURE_LABELS = Object.freeze([
  "admin", "login", "portal", "dashboard", "manage", "management",
  "vpn", "remote", "rdp", "citrix", "gateway", "sso", "auth",
  "owa", "exchange", "webmail", "intranet", "cpanel",
  "api", "dev", "staging", "test", "uat", "beta", "old", "backup",
  "ftp", "sftp", "files", "git", "gitlab", "jenkins", "jira", "grafana",
]);
// High-value hosts take at most this many of the 50 exposure slots, so known
// assets that lifecycle re-checks keep the rest.
export const HIGH_VALUE_PRIORITY_SLOTS = 25;
const HIGH_VALUE_LABEL_SET = new Set(HIGH_VALUE_EXPOSURE_LABELS);

function firstLabelUnder(host, root) {
  if (!root || !host.endsWith(`.${root}`)) return null;
  return host.slice(0, -(root.length + 1)).split(".")[0] || null;
}

// Exposure candidate order: high-value names (bounded), then known assets the
// lifecycle re-checks, then everything else in discovery order. Hosts are
// lower-cased and de-duplicated exactly as before; nothing is added or dropped
// here — only the order changes, so the probe cap removes the least risky names.
export function prioritizeExposureTargets(domain, { knownHosts = [], discoveredHosts = [] } = {}) {
  const root = String(domain || "").toLowerCase();
  const all = [...new Set([...knownHosts, ...discoveredHosts]
    .map((host) => String(host || "").toLowerCase())
    .filter(Boolean))];
  const known = new Set(knownHosts.map((host) => String(host || "").toLowerCase()));
  const high = all
    .filter((host) => HIGH_VALUE_LABEL_SET.has(firstLabelUnder(host, root)))
    .slice(0, HIGH_VALUE_PRIORITY_SLOTS);
  const highSet = new Set(high);
  const rest = all.filter((host) => !highSet.has(host));
  return [
    ...high,
    ...rest.filter((host) => known.has(host)),
    ...rest.filter((host) => !known.has(host)),
  ];
}

// Mail-infrastructure subdomains often publish MX/TXT but no A record, so the
// A-only sweep above misses them (e.g. reports. for DMARC RUA ingestion, send.
// for a mail relay). A small MX pass surfaces this external footprint too.
// Bounded to keep well within the subrequest budget.
const MAIL_SUBDOMAIN_LABELS = [
  "reports", "send", "mx", "smtp", "mta", "mg", "bounce", "dmarc",
];

// Standard service-location records (RFC 2782 SRV). Their targets name real
// hosts — often ones a wildcard certificate keeps out of CT. Only targets
// under the scanned domain are kept; third-party targets (e.g. a hosted mail
// provider) are not the customer's surface. Queried in parallel with the MX
// pass, so the module's slowest path is unchanged.
export const SRV_DISCOVERY_LABELS = Object.freeze([
  "_autodiscover._tcp", "_sip._tls", "_sipfederationtls._tcp", "_xmpp-server._tcp",
  "_caldavs._tcp", "_carddavs._tcp", "_imaps._tcp", "_submission._tcp",
]);

export function srvTargetsUnder(domain, answers = []) {
  const root = String(domain || "").toLowerCase();
  const targets = new Set();
  for (const answer of answers) {
    if (answer?.type !== 33 || typeof answer.data !== "string") continue;
    const target = answer.data.trim().split(/\s+/)[3]?.toLowerCase().replace(/\.$/, "");
    if (target && target !== root && target.endsWith(`.${root}`) && /^[a-z0-9.-]+$/.test(target)) targets.add(target);
  }
  return [...targets];
}

// SRV targets and hosts the home page links to, appended after the names CT
// and the word list found. Discovery order is kept; nothing is duplicated.
export function withReferencedHostnames(discovered = [], { srvItems = [], linkedHostnames = [] } = {}) {
  const base = Array.isArray(discovered) ? discovered : [];
  const seen = new Set(base);
  const added = [];
  const referenced = [
    ...(Array.isArray(srvItems) ? srvItems : []).map((item) => item?.hostname),
    ...(Array.isArray(linkedHostnames) ? linkedHostnames : []),
  ];
  for (const host of referenced) {
    if (typeof host !== "string" || !host || seen.has(host)) continue;
    seen.add(host);
    added.push(host);
  }
  return [...base, ...added];
}

/**
 * Probe the wordlist against `domain` via DoH A-record lookups.
 * Returns any names that resolve, with source = "dns_bruteforce".
 * Hard-capped at BRUTEFORCE_TIMEOUT_MS — returns whatever has resolved by then.
 */
export async function runBruteforceModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  const cache = opts.cache || null;
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
          dnsQuery(host, "A", { accounting, cache }).then((r) => ({ host, answers: r.Answer || [] }))
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
    const srvNames = SRV_DISCOVERY_LABELS.map((label) => `${label}.${domain}`);
    const srvItems = [];
    let srvAnswered = 0;
    try {
      const secondPass = await Promise.race([
        Promise.allSettled([
          ...mailCandidates.map((host) =>
            dnsQuery(host, "MX", { accounting, cache }).then((r) => ({ kind: "mx", host, answers: r.Answer || [] }))
          ),
          ...srvNames.map((name) =>
            dnsQuery(name, "SRV", { accounting, cache }).then((r) => ({ kind: "srv", host: name, answers: r.Answer || [] }))
          ),
        ]),
        new Promise((resolve) => setTimeout(() => resolve([]), HARD_CAP_MS)),
      ]);
      if (Array.isArray(secondPass)) {
        const srvHosts = new Set();
        for (const s of secondPass) {
          if (s.status !== "fulfilled") continue;
          const { kind, host, answers } = s.value;
          if (kind === "mx") {
            if (answers && answers.length > 0) {
              found.push({ hostname: host, ip_addresses: [], source: "dns_mx", mail_only: true });
            }
            continue;
          }
          if ((answers || []).some((answer) => answer?.type === 33)) srvAnswered++;
          for (const target of srvTargetsUnder(domain, answers)) {
            if (srvHosts.has(target)) continue;
            srvHosts.add(target);
            srvItems.push({ hostname: target, source: "dns_srv", record: host });
          }
        }
      }
    } catch { /* second pass is best-effort */ }

    return {
      checked: candidates.length + mailCandidates.length + srvNames.length,
      found:   found.length,
      items:   found,
      // SRV targets are kept apart from `items` (whose sources downstream
      // consumers already classify); the engine merges them into discovery.
      srv_items: srvItems,
      srv_checked: srvNames.length,
      srv_answered: srvAnswered,
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
