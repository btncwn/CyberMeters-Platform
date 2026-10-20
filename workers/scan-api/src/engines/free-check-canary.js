// ── Daily free-check canary ─────────────────────────────────────────────────
//
// Runs the production free-scan target check (lib/ssrf.js) and the DMARC and
// SPF free tools against a fixed list of public domains and compares each
// domain's short outcome with the day before. A change or an error is read by
// the founder's 08:00 email (lib/founder-digest.js), so a regression such as a
// target check refusing a public domain shows up before a customer reports it.
//
// Passive DNS only, bounded: one subrequest counter for the whole run and a
// per-domain deadline. The fingerprint holds outcomes, not raw records: the
// target state, the DMARC verdict and effective policy, the SPF verdict and
// resolution status. Lookup counts are left out because providers change their
// own includes without any change on the domain.
import { dnsQuery } from "./dns.js";
import { runDmarcCheck } from "./free-tools/dmarc-check.js";
import { runSpfCheck } from "./free-tools/spf-check.js";
import { makeDnsCache, PhysicalSubrequestCounter } from "./scan-budget.js";
import { resolvePublicDnsTargetWithRetry } from "../lib/ssrf.js";

// From scripts/lab/free-scan-corpus.txt: reported regressions, the suffix and
// SOA shapes that broke the target check before, large mail providers, small
// businesses, CyberMeters itself, and two controls that must never pass.
export const CANARY_DOMAINS = Object.freeze([
  "tesco.com", "ramblers.org.uk", "bbc.co.uk", "gov.uk", "nhs.uk", "ox.ac.uk",
  "google.com", "microsoft.com", "github.com", "cloudflare.com", "wikipedia.org",
  "oxfam.org.uk", "bettys.co.uk", "dishoom.com", "lush.com", "btinternet.com",
  "hotmail.co.uk", "cybermeters.com", "example.com", "cybermeters-corpus-nxdomain-control.co.uk",
]);

export const CANARY_LIMITS = Object.freeze({
  totalSubrequests: 1500,
  perDomainSubrequests: 140,
  perDomainDeadlineMs: 20_000,
});

export function canaryFingerprint({ target, dmarc, spf }) {
  return [
    `target:${target?.state ?? "error"}${target?.reason ? `/${target.reason}` : ""}`,
    `dmarc:${dmarc?.verdict?.level ?? "error"}/${dmarc?.ladder?.current ?? "none"}`,
    `spf:${spf?.verdict?.level ?? "error"}/${spf?.resolution_status ?? "none"}`,
  ].join("|");
}

/** Every part of the run is a value or "error"; nothing here throws. */
async function checkDomain(domain, { counter, runners, query }) {
  const deadline = new AbortController();
  const timer = setTimeout(() => deadline.abort("canary_deadline"), CANARY_LIMITS.perDomainDeadlineMs);
  const accounting = counter.contextFor(`canary_${domain}`, { signal: deadline.signal });
  const cache = makeDnsCache();
  const dns = (name, type) => query(name, type, { accounting, signal: deadline.signal, cache });
  const settle = (promise) => promise.then((value) => value, () => null);
  try {
    const target = await settle(runners.target(domain, query, { accounting, signal: deadline.signal }));
    const dmarc = await settle(runners.dmarc(domain, { accounting, signal: deadline.signal, cache }));
    const spf = await settle(runners.spf(domain, { dnsQuery: dns }));
    return { target, dmarc, spf };
  } finally {
    clearTimeout(timer);
  }
}

const DEFAULT_RUNNERS = Object.freeze({
  target: (domain, query, opts) => resolvePublicDnsTargetWithRetry(domain, query, opts),
  dmarc: (domain, opts) => runDmarcCheck(domain, opts),
  spf: (domain, opts) => runSpfCheck(domain, opts),
});

export async function runFreeCheckCanary(env, { nowMs = Date.now(), runners = {}, domains = CANARY_DOMAINS, query = dnsQuery, limits = CANARY_LIMITS } = {}) {
  const db = env.cybermeters_db;
  const all = { ...DEFAULT_RUNNERS, ...runners };
  const counter = new PhysicalSubrequestCounter({ limit: limits.totalSubrequests, safetyMargin: 0 });
  const checkedAt = new Date(nowMs).toISOString();
  const summary = { checked: 0, changed: [], errors: [], not_run: [] };
  for (const domain of domains) {
    if (counter.wouldExceed(limits.perDomainSubrequests)) { summary.not_run.push(domain); continue; }
    const parts = await checkDomain(domain, { counter, runners: all, query });
    const fingerprint = canaryFingerprint(parts);
    const outcome = fingerprint.includes("error") ? "error" : "ok";
    const prior = await db.prepare("SELECT fingerprint FROM ops_canary_results WHERE domain = ?").bind(domain).first();
    const changed = prior && prior.fingerprint !== fingerprint;
    await db.prepare(
      `INSERT INTO ops_canary_results (domain, checked_at, fingerprint, previous_fingerprint, changed_at, outcome)
       VALUES (?, ?, ?, NULL, NULL, ?)
       ON CONFLICT(domain) DO UPDATE SET
         checked_at = excluded.checked_at,
         previous_fingerprint = CASE WHEN ops_canary_results.fingerprint <> excluded.fingerprint
           THEN ops_canary_results.fingerprint ELSE ops_canary_results.previous_fingerprint END,
         changed_at = CASE WHEN ops_canary_results.fingerprint <> excluded.fingerprint
           THEN excluded.checked_at ELSE ops_canary_results.changed_at END,
         fingerprint = excluded.fingerprint,
         outcome = excluded.outcome`,
    ).bind(domain, checkedAt, fingerprint, outcome).run();
    summary.checked += 1;
    if (changed) summary.changed.push({ domain, from: prior.fingerprint, to: fingerprint });
    if (outcome === "error") summary.errors.push({ domain, fingerprint });
  }
  return summary;
}

/** Canary rows checked since `sinceIso`: what changed, what errored, what did not run. */
export async function readCanarySince(env, sinceIso) {
  const rows = await env.cybermeters_db.prepare(
    `SELECT domain, checked_at, fingerprint, previous_fingerprint, changed_at, outcome
       FROM ops_canary_results ORDER BY domain ASC LIMIT 100`,
  ).bind().all();
  const all = rows?.results || [];
  return {
    total: all.length,
    fresh: all.filter((row) => row.checked_at >= sinceIso).length,
    changed: all.filter((row) => row.changed_at && row.changed_at >= sinceIso),
    errors: all.filter((row) => row.checked_at >= sinceIso && row.outcome === "error"),
  };
}
