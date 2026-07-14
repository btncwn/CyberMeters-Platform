// ── Subdomain-takeover scan module ──
// CNAME-based subdomain-takeover detection: checks discovered subdomains for dangling
// CNAMEs pointing to unclaimed resources on known hosting platforms, matched against a
// fingerprint table. Extracted verbatim from index.js (monolith decomposition, Phase 1c).
// TAKEOVER_FINGERPRINTS is module-internal.
import { dnsQuery } from "./dns.js";
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
  const dnsImpl = typeof opts.dnsQueryImpl === "function" ? opts.dnsQueryImpl : dnsQuery;

  if (!subdomains || subdomains.length === 0) {
    return { checked: 0, potential_risks: 0, risks: [], checked_hosts: [], lookup_failed_hosts: [], unconfirmed: [], source, error: null };
  }

  // Cap at 100 to bound concurrent I/O without sacrificing coverage
  const targets = subdomains.slice(0, 100);

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
      checked_hosts: targets, lookup_failed_hosts, unconfirmed: [], source, error: null,
    };
  }

  // Step 3: fetch each candidate to confirm takeover via body fingerprint
  const bodyResults = await Promise.allSettled(
    candidates.map((c) => (fetchImpl
      ? fetchImpl(`https://${c.host}`)
      : safeFetch(`https://${c.host}`, { method: "GET", redirect: "follow" })))
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

  return {
    checked:         targets.length,
    potential_risks: candidates.length,
    risks,
    cname_observations,
    // Structured completeness — additive; existing consumers read only the fields above.
    checked_hosts:   targets,
    lookup_failed_hosts,
    unconfirmed,
    source,
    error: null,
  };
}
