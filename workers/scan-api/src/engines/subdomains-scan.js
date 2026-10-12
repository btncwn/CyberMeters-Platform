// ── Subdomain discovery + brute-force scan module ──
// Own-observation subdomain discovery (no third-party discovery service),
// sensitive-label classification, and a bounded
// DNS brute-force pass with wildcard filtering. Extracted verbatim from index.js (monolith
// decomposition, Phase 1c). Only the three run*/filter* entry points are public; the label
// sets, isSensitiveSubdomain and _subdomainsCoreWork are module-internal.
import { dnsQuery } from "./dns.js";

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

// ── Subdomain discovery: wildcard DNS check ──────────────────────────────────
// CyberMeters discovers subdomains with its own observations — the bounded DNS
// name checks and SRV records below, hosts the home page links to, and assets it
// already knows — and queries no third-party discovery service. This module asks
// one question first: does the zone answer for ANY name (wildcard DNS)? A
// wildcard answer means a name check that resolves is not, on its own, evidence
// that the name exists, so name-check results are filtered against it. The scan
// engine merges the discovered names into `items` afterwards.
export const SUBDOMAIN_DISCOVERY_SOURCE = "dns_discovery";
const WILDCARD_CHECK_CAP_MS = 10_000;

export async function runSubdomainsModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  const cache = opts.cache || null;
  const wildcardLabel = `cybermeters-wildcard-check-${Math.random().toString(36).slice(2, 10)}`;
  const wildcardHost  = `${wildcardLabel}.${domain}`;

  // Track B sub-operation timing — observational only, guarded at every call so a
  // broken/absent collector can never alter the DNS queries or their
  // Promise.allSettled semantics.
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
      (v) => { settle("ok"); return v; },
      (e) => { settle("error"); throw e; },
    );
  };

  // The wildcard check could not finish: name-check answers cannot be told
  // apart from wildcard answers, so discovery is honestly incomplete.
  const notCompleted = (reason) => ({
    count:              0,
    items:              [],
    sensitive:          [],
    source:             SUBDOMAIN_DISCOVERY_SOURCE,
    wildcard_dns:       false,
    wildcard_dns_addresses: [],
    wildcard_test_host: wildcardHost,
    wildcard_warning:   null,
    incomplete:         true,
    incomplete_reason:  reason,
    error:              null,
  });

  try {
    const work = Promise.allSettled([
      timedSubOp("wildcard_dns_a", dnsQuery(wildcardHost, "A", { accounting, cache })),
      timedSubOp("wildcard_dns_aaaa", dnsQuery(wildcardHost, "AAAA", { accounting, cache })),
    ]).then(([wASettled, wAAAASettled]) => {
      const aAnswers    = wASettled.status    === "fulfilled" ? (wASettled.value?.Answer    || []) : [];
      const aaaaAnswers = wAAAASettled.status === "fulfilled" ? (wAAAASettled.value?.Answer || []) : [];
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
      const wildcardDns = wildcardDnsAnswers.length > 0;
      return {
        count:              0,
        items:              [],
        sensitive:          [],
        source:             SUBDOMAIN_DISCOVERY_SOURCE,
        wildcard_dns:       wildcardDns,
        wildcard_dns_addresses: wildcardDnsAddresses,
        wildcard_test_host: wildcardHost,
        wildcard_warning:   wildcardDns
          ? "Wildcard DNS detected. Subdomain discovery results may include false positives."
          : null,
        error:              null,
      };
    });
    return await Promise.race([
      work,
      new Promise((resolve) =>
        setTimeout(() => resolve(notCompleted("wildcard_check_timed_out")), WILDCARD_CHECK_CAP_MS)
      ),
    ]);
  } catch {
    return notCompleted("wildcard_check_failed");
  }
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
// ordered first and can never be crowded out by ordinary discovered names.
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
// hosts a word list would miss. Only targets
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

// SRV targets and hosts the home page links to, appended after the names the
// word list found. Discovery order is kept; nothing is duplicated.
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
