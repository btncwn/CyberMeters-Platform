// ── Subdomain-takeover scan module ──
// CNAME-based subdomain-takeover detection: checks discovered subdomains for dangling
// CNAMEs pointing to unclaimed resources on known hosting platforms, matched against a
// fingerprint table. Extracted verbatim from index.js (monolith decomposition, Phase 1c).
// TAKEOVER_FINGERPRINTS is module-internal.
import { dnsQuery } from "./dns.js";
import { classifyFetchObservation } from "../lib/fetch-observation.js";
import { classifyServiceability, maySupportHealthyConclusion } from "../lib/serviceability.js";
import { safeFetch } from "../lib/http.js";

// ── Module 6: Subdomain Takeover Detection ────────────────────────────────────

/**
 * Known vulnerable service fingerprints for CNAME-based subdomain takeover.
 * cname_suffix: what the CNAME target ends with (indicates unclaimed service)
 * body_pattern: text returned by the provider when the resource doesn't exist
 */
const TAKEOVER_FINGERPRINTS = [
  // ── Git hosting / Pages ───────────────────────────────────────────────────
  {
    service: "GitHub Pages", provider: "GitHub Pages",
    cname_suffix: "github.io",
    body_pattern: "There isn't a GitHub Pages site here.",
    risk: "high",
  },
  {
    service: "GitLab Pages", provider: "GitLab Pages",
    cname_suffix: "gitlab.io",
    body_pattern: "The page you're looking for could not be found",
    risk: "high",
  },
  {
    service: "Bitbucket Pages", provider: "Bitbucket Pages",
    cname_suffix: "bitbucket.io",
    body_pattern: "Repository not found",
    risk: "high",
  },
  // ── PaaS / hosting platforms ─────────────────────────────────────────────
  {
    service: "Heroku", provider: "Heroku",
    cname_suffix: "herokuapp.com",
    body_pattern: "No such app",
    risk: "high",
  },
  {
    service: "Azure App Service", provider: "Azure",
    cname_suffix: "azurewebsites.net",
    body_pattern: "404 Web Site not found",
    risk: "high",
  },
  {
    service: "Azure Traffic Manager", provider: "Azure",
    cname_suffix: "trafficmanager.net",
    body_pattern: "404 Not Found",
    risk: "high",
  },
  {
    service: "Netlify", provider: "Netlify",
    cname_suffix: "netlify.app",
    body_pattern: "Not Found - Request ID:",
    risk: "high",
  },
  {
    service: "Vercel", provider: "Vercel",
    cname_suffix: "vercel.app",
    body_pattern: "The deployment you are looking for",
    risk: "high",
  },
  {
    service: "Vercel (legacy)", provider: "Vercel",
    cname_suffix: "now.sh",
    body_pattern: "The deployment you are looking for",
    risk: "high",
  },
  {
    service: "Render", provider: "Render",
    cname_suffix: "onrender.com",
    body_pattern: "Not Found",
    risk: "high",
  },
  {
    service: "Fly.io", provider: "Fly.io",
    cname_suffix: "fly.dev",
    body_pattern: "404 Not Found",
    risk: "high",
  },
  {
    service: "Railway", provider: "Railway",
    cname_suffix: "railway.app",
    body_pattern: "Application not found",
    risk: "high",
  },
  {
    service: "Surge.sh", provider: "Surge.sh",
    cname_suffix: "surge.sh",
    body_pattern: "project not found",
    risk: "high",
  },
  // ── CDN ───────────────────────────────────────────────────────────────────
  {
    service: "Fastly", provider: "Fastly",
    cname_suffix: "fastly.net",
    body_pattern: "Fastly error: unknown domain",
    risk: "high",
  },
  // ── E-commerce / CMS ─────────────────────────────────────────────────────
  {
    service: "Shopify", provider: "Shopify",
    cname_suffix: "myshopify.com",
    body_pattern: "Sorry, this shop is currently unavailable",
    risk: "high",
  },
  {
    service: "Squarespace", provider: "Squarespace",
    cname_suffix: "squarespace.com",
    body_pattern: "No Such Account",
    risk: "high",
  },
  {
    service: "Ghost", provider: "Ghost",
    cname_suffix: "ghost.io",
    body_pattern: "The thing you were looking for is no longer here",
    risk: "high",
  },
  {
    service: "Tilda", provider: "Tilda",
    cname_suffix: "tilda.ws",
    body_pattern: "Please renew your subscription",
    risk: "medium",
  },
  {
    service: "Webflow", provider: "Webflow",
    cname_suffix: "webflow.io",
    body_pattern: "The page you are looking for doesn't exist",
    risk: "high",
  },
  {
    service: "Cargo", provider: "Cargo",
    cname_suffix: "cargocollective.com",
    body_pattern: "404 Not Found",
    risk: "medium",
  },
  // ── Managed WordPress ─────────────────────────────────────────────────────
  {
    service: "WP Engine", provider: "WP Engine",
    cname_suffix: "wpengine.com",
    body_pattern: "The site you were looking for couldn't be found",
    risk: "high",
  },
  {
    service: "Kinsta", provider: "Kinsta",
    cname_suffix: "kinsta.cloud",
    body_pattern: "No Site For Domain",
    risk: "high",
  },
  {
    service: "Pantheon", provider: "Pantheon",
    cname_suffix: "pantheonsite.io",
    body_pattern: "404 error unknown site!",
    risk: "high",
  },
  // ── Marketing / landing pages ─────────────────────────────────────────────
  {
    service: "Unbounce", provider: "Unbounce",
    cname_suffix: "unbouncepages.com",
    body_pattern: "The requested URL was not found",
    risk: "high",
  },
  {
    service: "Launchrock", provider: "Launchrock",
    cname_suffix: "launchrock.com",
    body_pattern: "It looks like you may have taken a wrong turn",
    risk: "medium",
  },
  // ── Support / docs platforms ───────────────────────────────────────────────
  {
    service: "Zendesk", provider: "Zendesk",
    cname_suffix: "zendesk.com",
    body_pattern: "Help Center Closed",
    risk: "high",
  },
  {
    service: "Intercom Help", provider: "Intercom",
    cname_suffix: "custom.intercom.help",
    body_pattern: "This page is reserved for artistic",
    risk: "high",
  },
  {
    service: "UserVoice", provider: "UserVoice",
    cname_suffix: "uservoice.com",
    body_pattern: "This UserVoice subdomain is currently available",
    risk: "high",
  },
  {
    service: "Helpjuice", provider: "Helpjuice",
    cname_suffix: "helpjuice.com",
    body_pattern: "We could not find what you're looking for",
    risk: "high",
  },
  {
    service: "ReadMe", provider: "ReadMe",
    cname_suffix: "readme.io",
    body_pattern: "Project doesnt exist",
    risk: "high",
  },
  // ── Social / blogs ─────────────────────────────────────────────────────────
  {
    service: "Tumblr", provider: "Tumblr",
    cname_suffix: "tumblr.com",
    body_pattern: "Whatever you were looking for doesn't currently exist",
    risk: "high",
  },
  // ── Object storage / static sites ─────────────────────────────────────────
  {
    service: "AWS S3 (us-east-1)", provider: "AWS S3",
    cname_suffix: "s3-website-us-east-1.amazonaws.com",
    body_pattern: "NoSuchBucket",
    risk: "high",
  },
  {
    service: "AWS S3 (us-west-2)", provider: "AWS S3",
    cname_suffix: "s3-website-us-west-2.amazonaws.com",
    body_pattern: "NoSuchBucket",
    risk: "high",
  },
  {
    service: "AWS S3 (eu-west-1)", provider: "AWS S3",
    cname_suffix: "s3-website-eu-west-1.amazonaws.com",
    body_pattern: "NoSuchBucket",
    risk: "high",
  },
  {
    service: "AWS S3 (ap-southeast-1)", provider: "AWS S3",
    cname_suffix: "s3-website-ap-southeast-1.amazonaws.com",
    body_pattern: "NoSuchBucket",
    risk: "high",
  },
  {
    service: "Azure Blob Storage", provider: "Azure",
    cname_suffix: "blob.core.windows.net",
    body_pattern: "The specified container does not exist",
    risk: "high",
  },
];

/**
 * Check discovered subdomains for dangling CNAME records pointing to
 * unclaimed resources on known hosting platforms.
 *
 * Requires modules.subdomains.items as input — always runs after subdomain
 * discovery so no extra CT lookups are needed.
 */
// ── Canonical takeover predicate (detector + verifier share this) ─────────────
// `risks` is the ONE authoritative statement of "a takeover risk is confirmed here":
// scoring.js raises subdomain_takeover from it, and the managed-verification profile
// asks the same question per host. Neither re-implements the condition.
export function hostHasConfirmedTakeoverRisk(mod, host) {
  const h = String(host || "").trim().toLowerCase();
  return (mod?.risks || []).some((r) => String(r.host || "").toLowerCase() === h);
}

// Whether the module reached a CONCLUSIVE answer for this host.
//
// This exists because "no confirmed risk" is not the same claim as "not vulnerable".
// The module reaches `risks=[]` for several very different reasons, and three of them
// are ignorance rather than evidence:
//   • cname_lookup_failed — DNS did not answer; nothing was observed.
//   • probe_unconfirmed   — the CNAME still points at a vulnerable provider, but the
//                           body fetch was refused/failed/unreadable, so we never saw
//                           whether the service is still unclaimed.
// Only these are conclusive absence:
//   • no_cname                     — nothing dangles any more.
//   • cname_not_vulnerable_provider— the CNAME no longer targets a takeover-prone provider.
//   • provider_claimed             — body fetched, the takeover fingerprint is gone.
// Returns { complete, status, reason }. A caller must never treat complete=false as fixed.
export function takeoverObservationFor(mod, host) {
  const h = String(host || "").trim().toLowerCase();
  if ((mod?.lookup_failed_hosts || []).some((x) => String(x).toLowerCase() === h)) {
    return { complete: false, status: "cname_lookup_failed", reason: "dns_indeterminate" };
  }
  if (hostHasConfirmedTakeoverRisk(mod, h)) {
    return { complete: true, status: "risk_confirmed", reason: null };
  }
  const unconfirmed = (mod?.unconfirmed || []).find((u) => String(u.host || "").toLowerCase() === h);
  if (unconfirmed) {
    return { complete: false, status: "probe_unconfirmed", reason: unconfirmed.reason || "probe_failed" };
  }
  if (!(mod?.checked_hosts || []).some((x) => String(x).toLowerCase() === h)) {
    return { complete: false, status: "not_checked", reason: "host_not_in_scope" };
  }
  return { complete: true, status: "no_takeover_surface", reason: null };
}

// opts.fetcher / opts.dnsQueryImpl are injectable so the managed-verification profile can
// re-run this EXACT detector for a single host through its SSRF-guarded reserved probe
// (house pattern, mirrors runExposureModule). Defaults preserve the scan's behaviour
// unchanged. An injected fetcher returning null means the SSRF guard REFUSED the target —
// that is recorded as unconfirmed, never as "no risk".
export async function runTakeoverModule(domain, subdomains, opts = {}) {
  const source = "subdomain_cname_fingerprint";
  const fetchImpl = typeof opts.fetcher === "function" ? opts.fetcher : null;
  const accounting = opts.accounting || null;
  const cache = opts.cache || null;
  const dnsImpl = typeof opts.dnsQueryImpl === "function"
    ? opts.dnsQueryImpl
    : (name, type) => dnsQuery(name, type, { accounting, cache });

  if (!subdomains || subdomains.length === 0) {
    return { checked: 0, potential_risks: 0, risks: [], checked_hosts: [], lookup_failed_hosts: [], unconfirmed: [], unconfirmed_hosts: [], source, error: null,
      totals: { requested: 0, checked: 0, omitted: 0, lookup_failed: 0, unconfirmed: 0 }, incomplete: false, incomplete_reason: null, incomplete_reasons: [] };
  }

  // Cap at 100 to bound concurrent I/O without sacrificing coverage.
  // F-026: the cap must be EXPLICIT — a truncated run states requested vs
  // checked and flags itself incomplete so a dropped host is never presented as
  // full coverage (unmeasured is never "healthy").
  const HOST_CAP = 100;
  // F-026 R1 #2 (delta): establish ONE canonical DNS host identity at the PRODUCER
  // BOUNDARY — before the cap and before every completeness door — so case,
  // surrounding whitespace, and one-or-more trailing dots collapse consistently and
  // requested/checked/lookup_failed/unconfirmed all count the SAME per-host basis,
  // never raw duplicate rows (which let one DNS host inflate the denominator or
  // occupy two cap slots). Mirrors the repository's hostname canonicalisation idiom
  // (hostnames.js normalizeDiscoveredHostname / parseCertificateSanNames:
  // trim -> lowercase -> strip trailing dot), generalised to collapse MULTIPLE
  // trailing dots. Unlike normalizeDiscoveredHostname it deliberately does NOT drop
  // out-of-domain or otherwise-rejected hosts, so no discovered host is silently
  // removed from coverage — only empty/whitespace inputs (never a host) fall away.
  const canonicalHost = (h) => String(h ?? "").trim().toLowerCase().replace(/\.+$/, "");
  const requestedHosts = [...new Set(subdomains.map(canonicalHost).filter(Boolean))];
  const requestedHostCount = requestedHosts.length;
  const targets = requestedHosts.slice(0, HOST_CAP);
  const omittedHostCount = Math.max(0, requestedHostCount - targets.length);
  // F-026 R1 (F1): a host is UNMEASURED whether it was truncated OR its CNAME
  // lookup failed — both must flag incomplete. Truncation is known now; the
  // lookup-failure count is only known after Step 1, so the completeness verdict
  // is finalized just before each return via resolveCoverage(). The two reasons
  // COEXIST (one never overwrites the other), and the two counts are orthogonal:
  // omitted hosts were never attempted, lookup-failed hosts were attempted and
  // got no answer — no double counting.
  //
  // F-026 R1 (#2): every total is a per-HOST count, never a per-candidate count.
  // Because targets are canonical-and-deduped (above), omitted/lookup_failed are
  // distinct canonical hosts by construction, and the caller passes a DISTINCT
  // canonical-host unconfirmed count (see unconfirmedHostCount below). A canonical
  // host reaches exactly one door, so the disjoint per-reason totals honour
  //   lookup_failed + unconfirmed <= checked
  // as a set relation, not merely as arithmetic on raw rows.
  const resolveCoverage = (lookupFailedCount, unconfirmedHostCount = 0) => {
    const reasons = [];
    if (omittedHostCount > 0) reasons.push("host_cap_truncation");
    if (lookupFailedCount > 0) reasons.push("host_lookup_failure");
    // A host whose probe was refused/failed/unreadable was ATTEMPTED but NOT
    // assessed — the same unmeasured class as a lookup failure, one stage later.
    // The per-CANDIDATE reason (probe_refused / fetch_failed / body_unreadable /
    // serviceability) is retained on the unconfirmed[] rows; this coverage reason
    // is raised per distinct host so the module never reads complete over it.
    if (unconfirmedHostCount > 0) reasons.push("host_probe_unconfirmed");
    return {
      totals: {
        requested: requestedHostCount,
        checked: targets.length,
        omitted: omittedHostCount,
        lookup_failed: lookupFailedCount,
        unconfirmed: unconfirmedHostCount,
      },
      incomplete: reasons.length > 0,
      // Backward-compatible primary reason (deterministic order); incomplete_reasons
      // carries EVERY applicable reason so none is hidden or overwritten.
      incomplete_reason: reasons[0] ?? null,
      incomplete_reasons: reasons,
    };
  };

  // Step 1: CNAME lookups for all targets in parallel
  const cnameResults = await Promise.allSettled(
    targets.map((host) => dnsImpl(host, "CNAME"))
  );

  // Step 2: collect candidates whose CNAME resolves to a known vulnerable provider
  const candidates = [];
  const cname_observations = [];
  // A CNAME lookup that never answered is ignorance, not evidence of safety — record it
  // so a verifier defers instead of reading the resulting risks=[] as "fixed".
  const lookup_failed_hosts = [];
  for (let i = 0; i < targets.length; i++) {
    const r = cnameResults[i];
    if (r.status !== "fulfilled") { lookup_failed_hosts.push(targets[i]); continue; }
    const answers = r.value.Answer || [];
    for (const answer of answers) {
      const cname = (answer.data || "").toLowerCase().replace(/\.$/, "");
      if (cname) cname_observations.push({ host: targets[i], cname, source: "dns_cname" });
      for (const fp of TAKEOVER_FINGERPRINTS) {
        if (cname === fp.cname_suffix || cname.endsWith("." + fp.cname_suffix)) {
          candidates.push({ host: targets[i], cname, fingerprint: fp });
          break;
        }
      }
    }
  }

  if (candidates.length === 0) {
    return {
      checked: targets.length, potential_risks: 0, risks: [], cname_observations,
      checked_hosts: targets, lookup_failed_hosts, unconfirmed: [], unconfirmed_hosts: [], source, error: null,
      ...resolveCoverage(lookup_failed_hosts.length, 0),
    };
  }

  // Step 3: fetch each candidate to confirm takeover via body fingerprint
  const bodyResults = await Promise.allSettled(
    candidates.map((c) => (fetchImpl
      ? fetchImpl(`https://${c.host}`)
      : safeFetch(`https://${c.host}`, { method: "GET", redirect: "follow", accounting })))
  );

  const risks = [];
  // Candidates whose CNAME still targets a takeover-prone provider but whose body we
  // could NOT read. Previously these were silently skipped and became indistinguishable
  // from "provider claimed" — i.e. a refused/failed probe looked exactly like a fix.
  const unconfirmed = [];
  for (let i = 0; i < candidates.length; i++) {
    const { host, cname, fingerprint } = candidates[i];
    const settled = bodyResults[i];
    // rejected = network/DNS/timeout; null value = SSRF guard refused the target.
    if (settled.status !== "fulfilled" || !settled.value) {
      unconfirmed.push({
        host, cname, provider: fingerprint.provider ?? fingerprint.service,
        reason: settled.status !== "fulfilled" ? "fetch_failed" : "probe_refused",
      });
      continue;
    }
    // P1.1: a provider 5xx (or any non-serviceable response) is NOT the provider
    // claiming the name. Concluding "no takeover surface" from it verifies a
    // dangling surface as FIXED during a provider outage — the gravest direction of
    // the I11A-ACC-P2-01 class. The body is only conclusive if the origin served it.
    const takeoverServiceability = classifyServiceability(
      classifyFetchObservation({ response: settled.value, executed: true }));
    if (!maySupportHealthyConclusion(takeoverServiceability)) {
      unconfirmed.push({
        host, cname, provider: fingerprint.provider ?? fingerprint.service,
        reason: takeoverServiceability.reason,
      });
      continue;
    }
    try {
      const text = await settled.value.text();
      if (text.includes(fingerprint.body_pattern)) {
        risks.push({
          host,
          service:  fingerprint.service,
          provider: fingerprint.provider ?? fingerprint.service,
          cname,
          evidence: fingerprint.body_pattern,
          severity: fingerprint.risk ?? "high",
        });
      }
      // else: body read, fingerprint absent → conclusively claimed. Not unconfirmed.
    } catch {
      // Body read error — we never saw the page, so we cannot claim anything.
      unconfirmed.push({
        host, cname, provider: fingerprint.provider ?? fingerprint.service,
        reason: "body_unreadable",
      });
    }
  }

  // F-026 R1 (#2): the coverage denominator counts DISTINCT unmeasured hosts, not
  // CNAME candidates. unconfirmed[] holds one row per vulnerable candidate, so a host
  // with a two-hop chain or duplicate CNAME answers appears more than once; collapse
  // to distinct canonical host identities before it becomes a total. Uses the SAME
  // canonicalHost boundary as targets, so unconfirmed_hosts shares the exact basis of
  // checked_hosts/lookup_failed_hosts (each host was already canonical from targets).
  // The candidate rows are preserved verbatim on unconfirmed[] as forensic detail
  // (never discarded); unconfirmed_hosts exposes the distinct basis for the denominator.
  const unconfirmed_hosts = [...new Set(unconfirmed.map((u) => canonicalHost(u.host)))];

  return {
    checked:         targets.length,
    potential_risks: candidates.length,
    risks,
    cname_observations,
    // Structured completeness — additive; existing consumers read only the fields above.
    checked_hosts:   targets,
    lookup_failed_hosts,
    unconfirmed,
    unconfirmed_hosts,
    source,
    error: null,
    // F-026 explicit coverage truth: truncation + lookup-failure + unconfirmed
    // probe (three orthogonal unmeasured axes, all flagged). Each axis is a
    // distinct-host count, so lookup_failed + unconfirmed <= checked holds.
    ...resolveCoverage(lookup_failed_hosts.length, unconfirmed_hosts.length),
  };
}
