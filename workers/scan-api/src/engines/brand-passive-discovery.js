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
  BRAND_SUSPICIOUS_TLDS, buildBrandIdnEvidence,
} from "./brand-protection.js";
import { encodeIdnHostname, generateIdnHomographCandidates } from "./idn-homograph.js";

// Bounded work — deliberately small. The daily cron shares one Worker invocation
// with every other scheduled task, and crt.sh is a courtesy public service, so
// keep combined fan-out predictable and polite. NOT a plan subrequest limit.
export const BRAND_CT_WORKSPACES_PER_DAY = 3;   // workspaces swept per daily run
export const BRAND_CT_HOST_CAP           = 50;  // discovered hosts persisted per workspace per run
export const BRAND_CT_QUERY_TIMEOUT_MS   = 12_000;
export const BRAND_CT_MAX_CT_ENTRIES     = 5_000; // CT rows parsed per query (crt.sh can return many)
export const BRAND_CT_QUERY_CAP          = 4; // literal brand + at most three IDN A-label forms

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

/**
 * Bounded CT query plan. The literal token preserves the existing ASCII/nested
 * discovery path; exact generated A-label forms close the punycode blind spot.
 * No free-form Unicode is sent and crt.sh remains the fixed destination.
 */
export function brandCtQueryUrls(brand, tld) {
  const urls = [];
  const literal = brandCtQueryUrl(brand);
  if (literal) urls.push(literal);
  for (const candidate of generateIdnHomographCandidates(brand, tld)) {
    if (urls.length >= BRAND_CT_QUERY_CAP) break;
    urls.push(`https://crt.sh/?q=${encodeURIComponent("%" + candidate.candidate_domain + "%")}&output=json`);
  }
  return [...new Set(urls)].slice(0, BRAND_CT_QUERY_CAP);
}

/** Canonical A-label form used for dedupe and own-domain exclusion. */
export function canonicalBrandHostname(value) {
  const hostname = normalizeHostname(value);
  if (!hostname) return null;
  const encoded = encodeIdnHostname(hostname);
  return encoded.ok ? encoded.alabel : null;
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
      const h = canonicalBrandHostname(String(raw || "").replace(/^\*\./, "")); // drop wildcard prefix
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
    const canonical = canonicalBrandHostname(c.candidate_domain);
    if (canonical) set.add(getRegisteredDomain(canonical));
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
  const own = new Set();
  for (const domain of (ownRegistrables instanceof Set ? ownRegistrables : new Set(ownRegistrables || []))) {
    const canonical = canonicalBrandHostname(domain);
    if (canonical) own.add(getRegisteredDomain(canonical));
  }
  const bases = new Set();
  for (const domain of (lookalikeBases instanceof Set ? lookalikeBases : new Set(lookalikeBases || []))) {
    const canonical = canonicalBrandHostname(domain);
    if (canonical) bases.add(getRegisteredDomain(canonical));
  }
  const kept = [];
  const seen = new Set();
  for (const rawFqdn of fqdns) {
    const fqdn = canonicalBrandHostname(rawFqdn);
    if (!fqdn) continue;
    if (seen.has(fqdn)) continue;
    const reg = getRegisteredDomain(fqdn);
    if (own.has(reg)) continue;              // the customer's own domain — never a lookalike
    if (!bases.has(reg)) continue;            // strict: base must be a generated lookalike
    const idn = buildBrandIdnEvidence(reg, brand);
    seen.add(fqdn);
    kept.push({
      candidate_domain: fqdn,
      registrable: reg,
      variant_type: fqdn === reg
        ? (idn.analysis.is_homograph ? "homoglyph_idn" : "tld_variation")
        : "nested_host",
      is_nested: fqdn !== reg,
      idn_homograph: idn.analysis,
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
  const idn = buildBrandIdnEvidence(host.registrable, brand);
  const risk = scoreBrandCandidateRisk({
    variant_type: host.variant_type,
    similarity_score: similarity,
    contains_brand_keyword: sld.includes(brand) || host.candidate_domain.includes(brand),
    suspicious_tld: BRAND_SUSPICIOUS_TLDS.has(host.registrable.split(".").pop()),
    ct_observed: true,
    idn_visual_confusable: idn.analysis.is_homograph,
    mixed_script: idn.analysis.mixed_script,
    whole_script_confusable: idn.analysis.whole_script_confusable,
    classification: "unreviewed",
  });
  const evidence = [
    { signal: "ct_observed", value: true },
    { signal: "variant_type", value: normalizeBrandVariantType(host.variant_type) },
    { signal: "similar_to_brand", value: similarity },
    ...idn.evidence,
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
  const stats = {
    queried: false,
    queries_attempted: 0,
    queries_succeeded: 0,
    query_failures: 0,
    discovered: 0,
    inserted: 0,
    dropped_out_of_scope: 0,
  };

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
      const canonical = canonicalBrandHostname(dom);
      if (canonical) ownRegistrables.add(getRegisteredDomain(canonical));
    }
  } catch {
    return stats;
  }
  if (!primaryDomain) return stats;

  const { brand, tld } = extractBrandParts(primaryDomain);
  const urls = brandCtQueryUrls(brand, tld);
  if (urls.length === 0) return stats;

  // Bounded CT queries (fixed host — no user-controlled host, no SSRF surface).
  // A partial query failure does not discard successful observations.
  const discoveredHostnames = new Set();
  for (const url of urls) {
    stats.queried = true;
    stats.queries_attempted++;
    try {
      const res = await fetchImpl(url, {
        headers: { Accept: "application/json", "User-Agent": RDAP_UA },
        signal: AbortSignal.timeout(opts.timeoutMs || BRAND_CT_QUERY_TIMEOUT_MS),
      });
      if (!res || !res.ok) { stats.query_failures++; continue; }
      const ct = res.headers?.get?.("content-type") || "";
      if (ct && !ct.includes("json")) { stats.query_failures++; continue; }
      const body = await res.json();
      if (!Array.isArray(body)) { stats.query_failures++; continue; }
      stats.queries_succeeded++;
      // Parse each bounded response independently so a full literal-brand result
      // cannot crowd later IDN-query observations out of the global set.
      for (const hostname of parseCtResponseHostnames(body)) discoveredHostnames.add(hostname);
    } catch {
      stats.query_failures++;
    }
  }
  if (stats.queries_succeeded === 0) return stats;

  const hosts = [...discoveredHostnames];
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
