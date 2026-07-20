// ── Brand passive discovery (Certificate Transparency) ────────────────────────
// PR-B of the Brand Protection blocker-remediation sprint. Closes the discovery
// gap the 2026-07-20 audit proved: generation alone can never enumerate arbitrary
// NESTED hosts on a lookalike base (the founder's example acme.com →
// office365password.acme.co). This module discovers them PASSIVELY from public
// Certificate Transparency logs, then hands them to the existing DNS-enrichment
// sweep for tri-state validation.
//
// Honesty boundary (identical discipline to brand-dns-enrichment):
//   - A CT observation means a certificate NAMING this host was logged. It does
//     NOT mean the host is live, serving, or malicious — DNS/HTTP remain separate,
//     later signals. The customer-facing evidence says exactly that.
//   - CyberMeters imports NO external verdict. crt.sh supplies candidate hostnames
//     only; every downstream state (dns_resolves, risk band) is CyberMeters' own.
//
// False-positive control (the load-bearing rule): a brand-token CT search returns
// every certificate mentioning the token anywhere in the world. A discovered FQDN
// is kept ONLY when its registrable base (eTLD+1) is one of the lookalike bases
// the PR-A generator already produces for this brand. So office365password.acme.co
// is kept (base acme.co IS a generated lookalike); an unrelated legitimate
// acme-widgets.com is dropped (its base is not a generated lookalike); and the
// customer's own acme.com is dropped (the generator never emits the own domain).

import { RDAP_UA } from "../lib/http.js";
import { createId } from "../lib/util.js";
import { getRegisteredDomain } from "./whois-scan.js";
import { normalizeHostname } from "./hostnames.js";
import {
  extractBrandParts, generateTyposquatCandidates,
} from "./brand-typosquat.js";
import {
  brandSimilarityScore, scoreBrandCandidateRisk, normalizeBrandVariantType,
  BRAND_SUSPICIOUS_TLDS,
} from "./brand-protection.js";

// Bounded work — deliberately small. The daily cron shares one Worker invocation
// with every other scheduled task, and crt.sh is a courtesy public service, so
// keep combined fan-out predictable and polite. NOT a plan subrequest limit.
export const BRAND_CT_WORKSPACES_PER_DAY = 3;   // workspaces swept per daily run
export const BRAND_CT_HOST_CAP           = 50;  // discovered hosts persisted per workspace per run
export const BRAND_CT_QUERY_TIMEOUT_MS   = 12_000;
export const BRAND_CT_MAX_CT_ENTRIES     = 5_000; // CT rows parsed per query (crt.sh can return many)

// Classifications the customer has closed — never resurrect them with a new row.
const CLOSED_CLASSIFICATIONS = "('owned','ignored','false_positive')";

/**
 * The crt.sh identity-search URL for a brand token, or null when the token is too
 * short to search safely (a 1–2 char token matches most of the internet). The `%`
 * wildcards make it a LIKE match so the token is found anywhere in a CN/SAN,
 * which is what surfaces nested hosts.
 */
export function brandCtQueryUrl(brand) {
  const token = String(brand || "").toLowerCase().replace(/[^a-z0-9-]/g, "");
  if (token.length < 3) return null;
  return `https://crt.sh/?q=${encodeURIComponent("%" + token + "%")}&output=json`;
}

/** Parse a crt.sh JSON body into a deduped list of bare hostnames (wildcards stripped). */
export function parseCtResponseHostnames(rawData) {
  if (!Array.isArray(rawData)) return [];
  const out = new Set();
  for (const entry of rawData.slice(0, BRAND_CT_MAX_CT_ENTRIES)) {
    const names = [
      ...String(entry?.name_value || "").split(/\n/),
      String(entry?.common_name || ""),
    ];
    for (const raw of names) {
      const h = normalizeHostname(String(raw || "").replace(/^\*\./, "")); // drop wildcard prefix
      if (h) out.add(h);
    }
  }
  return [...out];
}

/**
 * Build the set of registrable lookalike bases for a brand by reusing the PR-A
 * generator. These are the ONLY registrable bases a CT-discovered host may sit on
 * to be kept. Pure.
 */
export function buildLookalikeBaseSet(brand, tld) {
  const set = new Set();
  for (const c of generateTyposquatCandidates(brand, tld)) {
    // Generated candidates are registrable (sld.tld or brand.swaptld); their own
    // registrable form is themselves.
    set.add(getRegisteredDomain(c.candidate_domain));
  }
  return set;
}

/**
 * Strict membership filter. Keeps a discovered FQDN only when its registrable base
 * is a generated lookalike, tags nested vs bare, and drops the customer's own
 * domains. Pure and deterministic (sorted output).
 *
 * @param fqdns          discovered hostnames
 * @param brand,tld      the workspace brand parts
 * @param ownRegistrables Set of the workspace's own registrable domains (always dropped)
 * @param lookalikeBases  Set from buildLookalikeBaseSet
 */
export function filterDiscoveredHosts(fqdns, { brand, tld, ownRegistrables, lookalikeBases }) {
  const own = ownRegistrables instanceof Set ? ownRegistrables : new Set(ownRegistrables || []);
  const kept = [];
  const seen = new Set();
  for (const fqdn of fqdns) {
    if (seen.has(fqdn)) continue;
    const reg = getRegisteredDomain(fqdn);
    if (own.has(reg)) continue;              // the customer's own domain — never a lookalike
    if (!lookalikeBases.has(reg)) continue;  // strict: base must be a generated lookalike
    seen.add(fqdn);
    kept.push({
      candidate_domain: fqdn,
      registrable: reg,
      variant_type: fqdn === reg ? "tld_variation" : "nested_host",
      is_nested: fqdn !== reg,
    });
  }
  kept.sort((a, b) => a.candidate_domain.localeCompare(b.candidate_domain));
  return kept.slice(0, BRAND_CT_HOST_CAP);
}

/**
 * Compute the persisted risk + evidence for a CT-discovered host. Pure so a test
 * can pin the honesty contract. The ct_observed signal is real external evidence a
 * certificate exists, so it lifts the candidate out of the "unregistered
 * watchlist" cap — but WITHOUT a live DNS/MX confirmation it is capped at 'high',
 * never 'critical': a logged certificate is strong, but "critical" is reserved for
 * a lookalike confirmed live and mail/serving-capable.
 */
export function buildDiscoveredCandidateRisk(host, brand) {
  const sld = host.registrable.split(".")[0];
  const similarity = brandSimilarityScore(host.registrable, brand);
  const risk = scoreBrandCandidateRisk({
    variant_type: host.variant_type,
    similarity_score: similarity,
    contains_brand_keyword: sld.includes(brand) || host.candidate_domain.includes(brand),
    suspicious_tld: BRAND_SUSPICIOUS_TLDS.has(host.registrable.split(".").pop()),
    ct_observed: true,
    classification: "unreviewed",
  });
  const evidence = [
    { signal: "ct_observed", value: true },
    { signal: "variant_type", value: normalizeBrandVariantType(host.variant_type) },
    { signal: "similar_to_brand", value: similarity },
  ];
  if (host.is_nested) evidence.push({ signal: "nested_host", value: true });
  return { similarity, risk, evidence };
}

/**
 * Discover + persist nested/lookalike hosts for ONE workspace. Tenant-scoped:
 * every read and write is filtered by workspace_id. INSERT OR IGNORE never
 * clobbers a scan-, refresh- or customer-classified row; discovered candidates
 * arrive with dns_resolves NULL so the existing DNS sweep validates them.
 * Non-fatal per host. Returns bounded stats.
 */
export async function discoverBrandCandidatesForWorkspace(env, workspaceId, opts = {}) {
  const fetchImpl = opts.fetchImpl || fetch;
  const stats = { queried: false, discovered: 0, inserted: 0, dropped_out_of_scope: 0 };

  // Resolve the workspace's primary domain + all owned registrables (own domains
  // are always dropped from discovery).
  let primaryDomain = null;
  const ownRegistrables = new Set();
  try {
    const rows = await env.cybermeters_db.prepare(
      `SELECT d.domain AS domain, d.created_at AS created_at
         FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id
        WHERE wd.workspace_id = ? ORDER BY d.created_at ASC`
    ).bind(workspaceId).all();
    for (const r of (rows?.results || [])) {
      const dom = String(r.domain || "").toLowerCase();
      if (!dom) continue;
      if (!primaryDomain) primaryDomain = dom;
      ownRegistrables.add(getRegisteredDomain(dom));
    }
  } catch {
    return stats;
  }
  if (!primaryDomain) return stats;

  const { brand, tld } = extractBrandParts(primaryDomain);
  const url = brandCtQueryUrl(brand);
  if (!url) return stats;

  // Single bounded CT query (fixed host — no user-controlled host, no SSRF surface).
  let rawData;
  try {
    const res = await fetchImpl(url, {
      headers: { Accept: "application/json", "User-Agent": RDAP_UA },
      signal: AbortSignal.timeout(opts.timeoutMs || BRAND_CT_QUERY_TIMEOUT_MS),
    });
    stats.queried = true;
    if (!res || !res.ok) return stats;                         // transient — retry next run
    const ct = res.headers?.get?.("content-type") || "";
    if (ct && !ct.includes("json")) return stats;
    rawData = await res.json();
  } catch {
    stats.queried = true;
    return stats;                                              // network/parse error — non-fatal
  }

  const hosts = parseCtResponseHostnames(rawData);
  const lookalikeBases = buildLookalikeBaseSet(brand, tld);
  const kept = filterDiscoveredHosts(hosts, { brand, tld, ownRegistrables, lookalikeBases });
  stats.discovered = kept.length;
  stats.dropped_out_of_scope = hosts.length - kept.length;

  const now = new Date().toISOString();
  for (const host of kept) {
    const { similarity, risk, evidence } = buildDiscoveredCandidateRisk(host, brand);
    try {
      await env.cybermeters_db.prepare(
        `INSERT OR IGNORE INTO workspace_brand_assets
           (id, workspace_id, domain, candidate_domain, variant_type,
            similarity_score, risk_level, risk_reasons, evidence_json,
            dns_resolves, https_available, ip_address, status,
            first_seen, last_seen, last_checked_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'unverified', ?, ?, NULL, ?, ?)`
      ).bind(
        createId("bra"), workspaceId, primaryDomain, host.candidate_domain, host.variant_type,
        similarity, risk.risk_level, JSON.stringify(risk.reasons), JSON.stringify(evidence),
        now, now, now, now,
      ).run();
      // .changes is not reliably exposed on D1; count discovered as the honest metric.
      stats.inserted++;
    } catch { /* isolated — the batch continues */ }
  }
  return stats;
}

/**
 * Daily bounded discovery sweep. Selects a bounded number of workspaces that
 * already have brand candidates (a scan or refresh has run), most-populated first,
 * and runs one CT discovery per workspace. Bounded and self-limiting. Logs the
 * number of eligible workspaces skipped by the per-run cap so coverage truncation
 * is never silent (full multi-workspace coverage is a post-beta scaling item).
 */
export async function runBrandPassiveDiscoverySweep(env, opts = {}) {
  const perDay = Math.max(1, opts.workspacesPerDay || BRAND_CT_WORKSPACES_PER_DAY);
  let rows;
  try {
    rows = await env.cybermeters_db.prepare(
      `SELECT workspace_id, COUNT(*) AS candidates
         FROM workspace_brand_assets
        WHERE (classification IS NULL OR classification NOT IN ${CLOSED_CLASSIFICATIONS})
        GROUP BY workspace_id
        ORDER BY candidates DESC, workspace_id ASC`
    ).all();
  } catch {
    return { workspaces: 0, discovered: 0, inserted: 0, skipped_workspaces: 0 };
  }
  const all = rows?.results || [];
  const selected = all.slice(0, perDay);
  const skipped = Math.max(0, all.length - selected.length);

  let discovered = 0, inserted = 0;
  for (const w of selected) {
    const s = await discoverBrandCandidatesForWorkspace(env, w.workspace_id, opts);
    discovered += s.discovered;
    inserted += s.inserted;
  }
  return { workspaces: selected.length, discovered, inserted, skipped_workspaces: skipped };
}
