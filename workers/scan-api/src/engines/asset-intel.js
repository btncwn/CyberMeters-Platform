// ── Asset-exposure intelligence module (Module 7) ──
// Tech fingerprinting, per-asset probing, provider/infrastructure classification, exposure
// deduplication, admin-surface detection, and the risk + remediation roll-ups. Extracted
// verbatim from index.js (monolith decomposition, Phase 1c). The regex/table constants,
// detectTech and isCustomerHostname are module-internal.
import { hostnameFromValue } from "./cloud-storage-scan.js";
import { normalizeHostname } from "./hostnames.js";

// ── Module 7: Asset Exposure Engine ──────────────────────────────────────────

/**
 * Derive tech stack hints from response headers and a body snippet.
 * No remote lookups — purely from what the server returned.
 */
function detectTech(headers, body) {
  const tech = new Set();
  const b = body.toLowerCase();

  // Server header
  const server = (headers.get("server") || "").toLowerCase();
  if (server.includes("nginx"))      tech.add("Nginx");
  if (server.includes("apache"))     tech.add("Apache");
  if (server.includes("cloudflare")) tech.add("Cloudflare");
  if (server.includes("litespeed"))  tech.add("LiteSpeed");
  if (server.includes("iis"))        tech.add("IIS");
  if (server.includes("gunicorn"))   tech.add("Gunicorn");
  if (server.includes("caddy"))      tech.add("Caddy");
  if (server.includes("openresty"))  tech.add("OpenResty");

  // X-Powered-By header
  const powered = (headers.get("x-powered-by") || "").toLowerCase();
  if (powered.includes("php"))        tech.add("PHP");
  if (powered.includes("asp.net"))    tech.add("ASP.NET");
  if (powered.includes("express"))    tech.add("Express");
  if (powered.includes("next.js"))    tech.add("Next.js");

  // Cloudflare-specific headers
  if (headers.get("cf-ray"))          tech.add("Cloudflare");

  // Platform headers
  if (headers.get("x-shopify-shop-api-call-limit")) tech.add("Shopify");
  const xgen = headers.get("x-generator") || "";
  if (xgen.toLowerCase().includes("drupal"))  tech.add("Drupal");
  if (headers.get("x-drupal-cache"))          tech.add("Drupal");
  if (headers.get("x-pingback"))              tech.add("WordPress");

  // Body patterns — first 8 KB only
  if (b.includes("wp-content") || b.includes("wp-json") || b.includes("/wp-admin")) {
    tech.add("WordPress");
  }
  if (b.includes("__next_data__") || b.includes("/_next/static")) tech.add("Next.js");
  if (b.includes("data-reactroot") || b.includes("__reactrootcontainer")) tech.add("React");
  if (b.includes("ng-version=") || b.includes("ng-app") || b.includes("[ng-")) tech.add("Angular");
  if (b.includes("__vue_app__") || b.includes("vue.min.js"))                  tech.add("Vue.js");
  if (b.includes("jquery"))    tech.add("jQuery");
  if (b.includes("bootstrap")) tech.add("Bootstrap");
  if (!tech.has("Drupal") && b.includes("drupal"))  tech.add("Drupal");
  if (b.includes("joomla"))    tech.add("Joomla");
  if (b.includes("laravel"))   tech.add("Laravel");
  if (b.includes("django"))    tech.add("Django");

  return [...tech];
}

// When a Cloudflare Worker exhausts its per-invocation subrequest budget, EVERY
// remaining fetch throws "Too many subrequests by single Worker invocation." That is
// a property of the Worker run, not of the target host — the probe never actually
// executed. Reporting it as reachable:false would falsely read as "confirmed
// unreachable / no exposure", so it must be surfaced as not-checked instead.
function isSubrequestBudgetError(err) {
  return /too many subrequests/i.test(err?.message || "");
}

// Default probe fetcher — the exact pre-existing legacy behaviour: native
// redirect:"follow", GET, 8s timeout. Legacy callers (probeAsset(host)) get this
// unchanged. The reserved path injects an SSRF-safe capped-redirect fetcher instead.
function defaultProbeFetch(url) {
  return fetch(url, {
    method:   "GET",
    redirect: "follow",
    signal:   AbortSignal.timeout(8_000),
  });
}

/**
 * Probe a single host over HTTPS (with HTTP fallback) and return exposure metadata.
 * Never throws. Returns reachable:false on a genuine network failure, or a
 * not-executed record (reachable:null) when the Worker subrequest budget was
 * exhausted before the host could be probed.
 *
 * opts.fetcher (optional) overrides the outbound fetch. It must return a Response,
 * or null to signal the target was refused (e.g. reserved SSRF guard). Omit it and
 * behaviour is byte-identical to the legacy native fetch.
 */
export async function probeAsset(host, opts = {}) {
  const fetcher = typeof opts.fetcher === "function" ? opts.fetcher : defaultProbeFetch;
  let budgetExhausted = false;   // a probe attempt was starved, not genuinely failed
  for (const proto of ["https", "http"]) {
    const url = `${proto}://${host}`;
    let res = null;
    try {
      res = await fetcher(url);
    } catch (err) {
      // Timeout or network error — try HTTP fallback. Distinguish a genuine failure
      // from subrequest-budget exhaustion (the latter means we never really checked).
      if (isSubrequestBudgetError(err)) budgetExhausted = true;
      continue;
    }
    // A fetcher may return null to refuse a target (reserved SSRF guard); the legacy
    // defaultProbeFetch never returns null, so this is a no-op for legacy.
    if (!res) continue;

    const status      = res.status;
    const reachable   = status < 500;
    const server      = res.headers.get("server") || null;
    const rawCT       = res.headers.get("content-type") || null;
    const contentType = rawCT ? rawCT.split(";")[0].trim() : null;

    let title = null;
    let tech  = [];

    if (rawCT?.includes("text/html")) {
      try {
        const body    = await res.text();
        const snippet = body.slice(0, 8_192);
        const m       = snippet.match(/<title[^>]*>([^<]{1,200})<\/title>/i);
        title = m ? m[1].trim() : null;
        tech  = detectTech(res.headers, snippet);
      } catch {
        tech = detectTech(res.headers, "");
      }
    } else {
      tech = detectTech(res.headers, "");
    }

    return {
      host,
      url:          res.url || url,
      status,
      reachable,
      title,
      server,
      content_type: contentType,
      tech,
    };
  }

  // No protocol returned a response.
  if (budgetExhausted) {
    // The Worker ran out of subrequest budget before this host could be probed.
    // It was NOT checked — report it honestly as not-executed (reachable:null),
    // never as a confirmed-unreachable / clean result.
    return {
      host,
      url:          `https://${host}`,
      status:       null,
      reachable:    null,
      probe_status: "not_executed",
      reason:       "subrequest_budget_exhausted",
      title:        null,
      server:       null,
      content_type: null,
      tech:         [],
    };
  }

  // Genuine network failure / timeout — the host really did not respond.
  return {
    host,
    url:          `https://${host}`,
    status:       null,
    reachable:    false,
    title:        null,
    server:       null,
    content_type: null,
    tech:         [],
  };
}

const PROVIDER_INFRASTRUCTURE_PATTERNS = [
  { provider: "Cloudflare", service: "Cloudflare Edge", suffixes: ["cloudflare.net", "cdn.cloudflare.net", "pages.dev", "workers.dev"] },
  { provider: "AWS", service: "AWS Hosting", suffixes: ["amazonaws.com", "cloudfront.net", "elasticbeanstalk.com", "amplifyapp.com"] },
  { provider: "Microsoft Azure", service: "Azure Hosting", suffixes: ["azurewebsites.net", "azureedge.net", "trafficmanager.net", "blob.core.windows.net"] },
  { provider: "Google", service: "Google/Firebase Hosting", suffixes: ["googlehosted.com", "firebaseapp.com", "web.app"] },
  { provider: "Fastly", service: "Fastly Edge", suffixes: ["fastly.net", "fastlylb.net"] },
  { provider: "Akamai", service: "Akamai Edge", suffixes: ["akamaiedge.net", "akamai.net", "edgekey.net", "edgesuite.net"] },
  { provider: "GitHub Pages", service: "GitHub Pages", suffixes: ["github.io", "github.map.fastly.net"] },
  { provider: "GitLab Pages", service: "GitLab Pages", suffixes: ["gitlab.io"] },
  { provider: "Netlify", service: "Netlify Hosting", suffixes: ["netlify.app", "netlify.com"] },
  { provider: "Vercel", service: "Vercel Hosting", suffixes: ["vercel.app", "vercel-dns.com", "now.sh"] },
  { provider: "Heroku", service: "Heroku Hosting", suffixes: ["herokuapp.com", "herokudns.com"] },
  { provider: "Shopify", service: "Shopify", suffixes: ["myshopify.com"] },
  { provider: "Wix", service: "Wix Hosting", suffixes: ["wixdns.net", "wixsite.com"] },
  { provider: "Squarespace", service: "Squarespace Hosting", suffixes: ["squarespace.com", "squarespace.net"] },
  { provider: "Automattic", service: "WordPress.com Hosting", suffixes: ["wordpress.com"] },
  { provider: "Atlassian", service: "Atlassian Cloud", suffixes: ["atlassian.net"] },
  { provider: "Zendesk", service: "Zendesk", suffixes: ["zendesk.com"] },
  { provider: "Okta", service: "Okta Identity Cloud", suffixes: ["okta.com", "oktapreview.com"] },
  { provider: "Auth0", service: "Auth0", suffixes: ["auth0.com"] },
  { provider: "Microsoft", service: "Microsoft 365", suffixes: ["microsoftonline.com", "mail.protection.outlook.com", "sharepoint.com"] },
  { provider: "Google", service: "Google Hosted Service", suffixes: ["google.com"] },
];

export function providerMetadataForHostname(value) {
  const hostname = hostnameFromValue(value);
  if (!hostname) return null;
  for (const entry of PROVIDER_INFRASTRUCTURE_PATTERNS) {
    if (entry.suffixes.some((suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`))) {
      return { provider: entry.provider, service: entry.service, hostname };
    }
  }
  return null;
}

export function providerForInfrastructureHostname(value) {
  return providerMetadataForHostname(value)?.provider ?? null;
}

export function classifyProviderInfrastructure(asset, cname = null) {
  // Provider ASSET OWNERSHIP requires STRONG corroborating evidence, distinct from mere
  // edge/CDN technology in the path:
  //   • a CNAME whose target is a provider suffix, or
  //   • a redirect whose final host is a provider suffix, or
  //   • the provider's own DEFAULT/PARKED page served over that provider's edge.
  const cnameMetadata = providerMetadataForHostname(cname);
  const redirectMetadata = providerMetadataForHostname(asset?.url);

  // Edge/CDN technology signal (server: cloudflare, cf-ray → tech "Cloudflare") is NOT
  // proof of provider ownership. A customer's own admin panel is commonly served through
  // a CDN, and — critically — a Cloudflare Worker's OWN outbound fetch stamps
  // `server: cloudflare` onto responses from non-Cloudflare origins, so this header from
  // the scanner's vantage is a fetch-path artifact. It only corroborates provider
  // ownership when the response is the provider's DEFAULT/PARKED page (not customer content).
  const edgeCdnTech = (asset?.tech || []).includes("Cloudflare") || /cloudflare/i.test(asset?.server || "");
  const providerDefaultPage = edgeCdnTech && GENERIC_DEFAULT_PAGE_RE.test(asset?.title || "");

  const metadata = cnameMetadata || redirectMetadata || (providerDefaultPage
    ? { provider: "Cloudflare", service: "Cloudflare Edge", hostname: null }
    : null);
  if (!metadata) return { provider_owned_infrastructure: false, infrastructure_provider: null, infrastructure_evidence: null };
  return {
    provider_owned_infrastructure: true,
    infrastructure_provider: metadata.provider,
    infrastructure_service: metadata.service,
    infrastructure_relationship: "supporting_infrastructure",
    infrastructure_evidence: cnameMetadata ? "dns_cname" : redirectMetadata ? "http_redirect" : "provider_default_page",
  };
}

export function annotateExposureInfrastructure(exposureResult, cnameObservations = []) {
  if (!Array.isArray(exposureResult?.assets)) return exposureResult;
  const cnameByHost = new Map(
    (cnameObservations || []).filter((item) => item?.host && item?.cname).map((item) => [item.host, item.cname])
  );
  const assets = exposureResult.assets.map((asset) => {
    const cname = cnameByHost.get(asset.host) || null;
    return { ...asset, cname, ...classifyProviderInfrastructure(asset, cname) };
  });
  return { ...exposureResult, assets };
}

function isCustomerHostname(hostname, domain) {
  const host = normalizeHostname(hostname);
  const root = normalizeHostname(domain);
  return Boolean(host && root && (host === root || host.endsWith(`.${root}`)));
}

export function deduplicateExposureAssets(exposureResult, domain) {
  if (!Array.isArray(exposureResult?.assets)) return exposureResult;
  const groups = new Map();

  for (const asset of exposureResult.assets) {
    const host = normalizeHostname(asset.host || asset.hostname || asset.url);
    if (!host) continue;
    const finalHost = hostnameFromValue(asset.url);
    const cname = normalizeHostname(asset.cname);
    const key = finalHost && isCustomerHostname(finalHost, domain)
      ? `customer:${finalHost}`
      : asset.provider_owned_infrastructure && cname
        ? `provider:${cname}`
        : `host:${host}`;
    const aliases = new Set([host, ...(asset.aliases || [])].filter(Boolean));
    const providerTargets = new Set([cname, ...(asset.provider_targets || [])].filter(Boolean));
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, { ...asset, host, aliases: [...aliases], provider_targets: [...providerTargets] });
      continue;
    }

    const root = normalizeHostname(domain);
    const existingRank = existing.host === root ? 3 : existing.host === `www.${root}` ? 2 : 1;
    const assetRank = host === root ? 3 : host === `www.${root}` ? 2 : 1;
    if (assetRank > existingRank) {
      groups.set(key, {
        ...existing,
        ...asset,
        host,
        reachable: existing.reachable || asset.reachable,
        status: asset.status ?? existing.status,
        title: asset.title || existing.title,
        tech: [...new Set([...(existing.tech || []), ...(asset.tech || [])])],
        aliases: [...new Set([...existing.aliases, ...aliases])],
        provider_targets: [...new Set([...existing.provider_targets, ...providerTargets])],
      });
      continue;
    }

    for (const alias of aliases) existing.aliases.push(alias);
    for (const target of providerTargets) existing.provider_targets.push(target);
    existing.aliases = [...new Set(existing.aliases)];
    existing.provider_targets = [...new Set(existing.provider_targets)];
    existing.reachable = existing.reachable || asset.reachable;
    if (existing.status == null && asset.status != null) existing.status = asset.status;
    if (!existing.title && asset.title) existing.title = asset.title;
    existing.tech = [...new Set([...(existing.tech || []), ...(asset.tech || [])])];
  }

  const assets = [...groups.values()];
  return {
    ...exposureResult,
    assets,
    reachable: assets.filter((asset) => asset.reachable).length,
    representations_observed: exposureResult.assets.length,
    duplicates_collapsed: exposureResult.assets.length - assets.length,
  };
}

export function consolidateInventoryAssetAliases(assets, exposureAssets = []) {
  const canonicalByAlias = new Map();
  for (const exposure of exposureAssets) {
    const canonical = normalizeHostname(exposure.host);
    if (!canonical) continue;
    for (const alias of exposure.aliases || []) {
      const normalized = normalizeHostname(alias);
      if (normalized) canonicalByAlias.set(normalized, canonical);
    }
  }

  return (assets || []).map((asset) => {
    const original = normalizeHostname(asset.hostname);
    const canonical = canonicalByAlias.get(original) || original;
    if (!canonical || canonical === original) return asset;
    return {
      ...asset,
      hostname: canonical,
      aliases: [...new Set([...(asset.aliases || []), original])],
    };
  });
}

export function buildAssetInventoryMetadata(asset) {
  const metadata = {};
  if (asset?.aliases?.length) metadata.aliases = [...new Set(asset.aliases)];
  if (asset?.provider_targets?.length) metadata.provider_targets = [...new Set(asset.provider_targets)];
  if (asset?.cloud) metadata.infrastructure_provider = asset.cloud;
  return Object.keys(metadata).length > 0 ? JSON.stringify(metadata) : null;
}

const SENSITIVE_SERVICE_RE = /jenkins|grafana|kibana|phpmyadmin|portainer|prometheus|sonarqube|vault\s*ui|rancher/i;
const GENERIC_ADMIN_HOST_RE = /\b(admin|cp|cpanel|panel|portal|login|dashboard|manage|control)\b/i;
const GENERIC_ADMIN_TITLE_RE = /\b(login|admin|dashboard|control\s*panel|portal|management|sign[\s-]in)\b/i;
const DEV_ENV_HOST_RE = /\b(dev|develop|development|staging|stage|stg|test|testing|qa|uat|sandbox|alpha|beta|preprod)\b/i;
const DEV_ENV_TITLE_RE = /\b(dev(?:elopment)?|staging|test(?:ing)?|qa|uat|sandbox|preproduction|pre-prod)\b/i;
const GENERIC_DEFAULT_PAGE_RE = /welcome to nginx|apache2? (?:ubuntu )?default page|default web site page|domain (?:is )?parked|domain for sale|coming soon|site not configured|website coming soon/i;

export function assetFingerprintSignals(asset) {
  const title = asset?.title || "";
  const technology = (asset?.tech || []).join(" ");
  return {
    sensitive_service: SENSITIVE_SERVICE_RE.test(title) || SENSITIVE_SERVICE_RE.test(technology),
    admin_hostname: GENERIC_ADMIN_HOST_RE.test(asset?.host || ""),
    admin_title: GENERIC_ADMIN_TITLE_RE.test(title),
    dev_hostname: DEV_ENV_HOST_RE.test(asset?.host || ""),
    dev_title: DEV_ENV_TITLE_RE.test(title),
    generic_default_page: GENERIC_DEFAULT_PAGE_RE.test(title),
  };
}

/**
 * Probe all discovered subdomains for HTTP/HTTPS reachability and collect
 * lightweight exposure metadata (status, title, server header, tech stack).
 * Cap at 50 subdomains for v1.
 */
export async function runExposureModule(domain, subdomains, opts = {}) {
  const source = "http_probe";

  if (!subdomains || subdomains.length === 0) {
    return { checked: 0, reachable: 0, assets: [], source, error: null };
  }

  const targets = subdomains.slice(0, 50);

  // All probes run in parallel; individual failures return reachable:false records.
  // opts (e.g. opts.fetcher for the reserved SSRF-safe prober) is passed through; the
  // legacy caller passes nothing, so probeAsset uses its default native fetcher.
  const settled = await Promise.allSettled(targets.map((host) => probeAsset(host, opts)));

  const assets = settled
    .filter((r) => r.status === "fulfilled")
    .map((r) => r.value);

  const reachableCount = assets.filter((a) => a.reachable === true).length;

  // Trust: if any host could not be probed because the Worker subrequest budget was
  // exhausted, this module's evidence is incomplete. Absence of exposure here is NOT
  // proof of a clean surface — flag it so scan_quality goes partial and downstream
  // verification / managed-case resolution defers instead of treating 0 as verified.
  const notExecuted = assets.filter((a) => a.probe_status === "not_executed");
  const incomplete = notExecuted.length > 0;

  return {
    checked:   targets.length,
    reachable: reachableCount,
    assets,
    source,
    error: null,
    ...(incomplete ? {
      incomplete:        true,
      incomplete_reason: "subrequest_budget_exhausted",
      not_executed_count: notExecuted.length,
      // Customer-safe copy — never expose raw runtime error text.
      notice: "Some external exposure checks could not complete. Results may be incomplete.",
    } : {}),
  };
}

// ── Admin Surface Detection Module ───────────────────────────────────────────
//
// Pure function — reads existing asset_exposure probe results with no extra I/O.
// Fingerprints each reachable HTTP asset by title, Server header, and hostname
// pattern to identify exposed administrative interfaces and high-value services.
//
// Confidence rules:
//   "confirmed" — title + (host OR server) both match
//   "high"      — title alone, OR host + server both match
//   "medium"    — hostname alone matches a specific-enough pattern
//
// No I/O means this can run synchronously after the exposure module without
// consuming additional CPU budget or Worker timeout.

const ADMIN_SURFACE_SIGS = [
  // ── CI/CD ─────────────────────────────────────────────────────────────────
  { product: "Jenkins",                category: "admin_panel",    risk_level: "critical",
    title_re: /\bjenkins\b/i,          server_re: /\bjetty\b/i,    host_re: /\b(jenkins|hudson)\b/i },

  // ── Monitoring ────────────────────────────────────────────────────────────
  { product: "Grafana",                category: "monitoring",     risk_level: "high",
    title_re: /\bgrafana\b/i,          server_re: /\bgrafana\b/i,  host_re: /\bgrafana\b/i },

  { product: "Kibana",                 category: "monitoring",     risk_level: "critical",
    title_re: /\bkibana\b/i,           server_re: null,            host_re: /\bkibana\b/i },

  { product: "Elasticsearch",          category: "infrastructure", risk_level: "critical",
    title_re: /\belasticsearch\b/i,    server_re: /\belastic(search)?\b/i, host_re: /\b(elasticsearch|elastic)\b/i },

  { product: "Prometheus",             category: "monitoring",     risk_level: "high",
    title_re: /\bprometheus\b/i,       server_re: null,            host_re: /\b(prometheus|prom)\b/i },

  // ── Database Management UIs ───────────────────────────────────────────────
  { product: "phpMyAdmin",             category: "admin_panel",    risk_level: "critical",
    title_re: /\bphpmyadmin\b/i,       server_re: null,            host_re: /\b(phpmyadmin|pma)\b/i },

  { product: "Adminer",                category: "admin_panel",    risk_level: "high",
    title_re: /\badminer\b/i,          server_re: null,            host_re: /\badminer\b/i },

  // ── DevOps / Code Quality ─────────────────────────────────────────────────
  { product: "SonarQube",              category: "source_control", risk_level: "high",
    title_re: /\bsonarqube\b/i,        server_re: null,            host_re: /\b(sonarqube|sonar)\b/i },

  { product: "RabbitMQ",               category: "infrastructure", risk_level: "high",
    title_re: /\brabbitmq\b/i,         server_re: /\bcowboy\b/i,   host_re: /\b(rabbitmq|amqp|broker)\b/i },

  { product: "GitLab",                 category: "source_control", risk_level: "medium",
    title_re: /\bgitlab\b/i,           server_re: null,            host_re: /\bgitlab\b/i },

  // ── Collaboration / Issue Tracking ────────────────────────────────────────
  { product: "Jira",                   category: "collaboration",  risk_level: "medium",
    title_re: /\bjira\b/i,             server_re: null,            host_re: /\bjira\b/i },

  { product: "Confluence",             category: "collaboration",  risk_level: "medium",
    title_re: /\bconfluence\b/i,       server_re: null,            host_re: /\bconfluence\b/i },

  // ── VPN / Remote Access ───────────────────────────────────────────────────
  { product: "OpenVPN Access Server",  category: "vpn",            risk_level: "high",
    title_re: /\bopenvpn\b/i,          server_re: /\bopenvpn\b/i,  host_re: /\bopenvpn\b/i },

  { product: "Fortinet SSL VPN",       category: "vpn",            risk_level: "high",
    title_re: /ssl[\s-]?vpn|fortinet|forticlient/i,
    server_re: /\bfortinet\b|\bfortigate\b/i,
    host_re:   /\b(forti|fortigate|sslvpn)\b/i },

  { product: "Palo Alto GlobalProtect", category: "vpn",           risk_level: "high",
    title_re: /globalprotect|palo[\s-]?alto/i,
    server_re: /\bpanos\b/i,
    host_re:   /\b(globalprotect|paloalto)\b/i },

  { product: "Citrix Gateway",         category: "vpn",            risk_level: "high",
    title_re: /\bcitrix\b|\bnetscaler\b/i,
    server_re: /\bCitrix\b|\bNetScaler\b/i,
    host_re:   /\b(citrix|netscaler)\b/i },

  // ── Email Infrastructure ──────────────────────────────────────────────────
  { product: "Outlook Web Access",     category: "collaboration",  risk_level: "medium",
    title_re: /outlook\s*web\s*a(?:pp|ccess)|owa\b/i,
    server_re: /\bMicrosoft-IIS\b/i,
    host_re:   /\b(owa|webmail)\b/i },

  { product: "Exchange Admin Center",  category: "admin_panel",    risk_level: "high",
    title_re: /exchange\s*admin(?:\s*center)?/i,
    server_re: /\bMicrosoft-IIS\b/i,
    host_re:   /\b(exchange|eac)\b/i },

  // ── Virtualisation / Infrastructure Management ────────────────────────────
  { product: "VMware vCenter",         category: "infrastructure", risk_level: "critical",
    title_re: /\bvcenter\b|vmware\s+v(?:center|sphere)/i,
    server_re: /\bvmware\b/i,
    host_re:   /\b(vcenter|vsphere|vmware|esxi)\b/i },

  // ── Cisco VPN ─────────────────────────────────────────────────────────────
  { product: "Cisco AnyConnect",       category: "vpn",            risk_level: "high",
    title_re: /anyconnect|cisco\s+(?:secure\s+)?client|cisco\s+vpn/i,
    server_re: /\bcisco-anyconnect\b|\bcisco\b/i,
    host_re:   /\b(anyconnect|cisco(?:-vpn)?|asa)\b/i },

  // ── Monitoring / Alerting ─────────────────────────────────────────────────
  { product: "Zabbix",                 category: "monitoring",     risk_level: "high",
    title_re: /\bzabbix\b/i,
    server_re: null,
    host_re:   /\bzabbix\b/i },

  // ── Automation / Runbook ──────────────────────────────────────────────────
  { product: "Rundeck",                category: "admin_panel",    risk_level: "critical",
    title_re: /\brundeck\b/i,
    server_re: null,
    host_re:   /\brundeck\b/i },
];

/**
 * Detect exposed administrative interfaces from existing HTTP probe results.
 * Pure synchronous — no network I/O.  Called after runExposureModule completes.
 */
export function runAdminSurfaceModule(modules) {
  const exposure       = modules?.asset_exposure || null;
  const exposureAssets = exposure?.assets || [];
  const reachable      = exposureAssets.filter((a) => a.reachable);

  const seen     = new Set();   // deduplicate (hostname, product)
  const services = [];

  for (const asset of reachable) {
    for (const sig of ADMIN_SURFACE_SIGS) {
      const key = `${asset.host}::${sig.product}`;
      if (seen.has(key)) continue;

      const titleHit  = sig.title_re  ? sig.title_re.test(asset.title  || "") : false;
      const serverHit = sig.server_re ? sig.server_re.test(asset.server || "") : false;
      const hostHit   = sig.host_re   ? sig.host_re.test(asset.host    || "") : false;
      const defaultPage = assetFingerprintSignals(asset).generic_default_page;

      let confidence = null;
      let findingType = "observation";
      if (!defaultPage && titleHit && (hostHit || serverHit)) {
        confidence = "confirmed";
        findingType = "finding";
      } else if (!defaultPage && titleHit) {
        confidence = "high";
        findingType = "finding";
      } else if (!defaultPage && hostHit && serverHit && !asset.provider_owned_infrastructure) {
        confidence = "high";
        findingType = "finding";
      } else if (hostHit) {
        confidence = "low";
      }

      if (!confidence) continue;

      seen.add(key);

      // Build a probable URL from the asset's probed URL or hostname
      const url = asset.url || `https://${asset.host}`;

      services.push({
        hostname:   asset.host,
        url,
        product:    sig.product,
        category:   sig.category,
        severity:   sig.risk_level,   // human-readable alias used in UI / API
        confidence,
        finding_type: findingType,
        evidence_signals: [
          ...(titleHit ? ["product_title"] : []),
          ...(serverHit ? ["server_header"] : []),
          ...(hostHit ? ["hostname"] : []),
        ],
        risk_level: sig.risk_level,
        ip_address: asset.ip || null,
        server:     asset.server || null,
        title:      asset.title  || null,
        infrastructure_provider: asset.infrastructure_provider || null,
      });
    }
  }

  // Sort: confirmed+critical first, then by confidence desc, then severity desc
  const confOrder = { confirmed: 0, high: 1, medium: 2, low: 3 };
  const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  services.sort((a, b) => {
    const cd = (confOrder[a.confidence] ?? 4) - (confOrder[b.confidence] ?? 4);
    if (cd !== 0) return cd;
    return (riskOrder[a.risk_level] ?? 4) - (riskOrder[b.risk_level] ?? 4);
  });

  const actionable = services.filter((service) => service.finding_type === "finding");
  const observations = services.filter((service) => service.finding_type === "observation");
  const critical = actionable.filter((s) => s.risk_level === "critical").length;
  const high     = actionable.filter((s) => s.risk_level === "high").length;
  const medium   = actionable.filter((s) => s.risk_level === "medium").length;

  // A3: admin detection's ONLY evidence is asset_exposure. Reflect its availability so a
  // failed / incomplete / not-run probe pass can never read as a clean zero-admin verdict.
  // additive field — no existing field's value or meaning changes. Empty assets alone is
  // NOT healthy (nothing was probed → not_assessed).
  let evidence_status;
  if (actionable.length > 0) {
    evidence_status = "issue_detected";               // a verified admin surface ALWAYS surfaces first — never hidden by a gap
  } else if (!exposure) {
    evidence_status = "not_assessed";                 // asset_exposure never ran for this scan
  } else if (exposure.error || exposure.incomplete === true) {
    evidence_status = "unavailable";                  // ran, but probes/evidence incomplete or failed
  } else if (exposureAssets.length === 0) {
    evidence_status = "not_assessed";                 // no hosts were probed — empty ≠ observed-clean
  } else {
    evidence_status = "assessed_healthy";             // completed, hosts probed, zero verified admin surfaces
  }

  return {
    detected: actionable.length > 0,
    total:    actionable.length,
    observed_total: services.length,
    critical,
    high,
    medium,
    services,
    observations,
    evidence_status,
    source:   "asset_exposure_fingerprint",
    error:    null,
  };
}

// ── Intelligence Module: Risk Engine ─────────────────────────────────────────
// Ported from risk_engine.py — maps findings to business risk categories with
// improved business-impact language.  Pure computation, no I/O.
// Adds a KEV business-impact summary when kev matches are present.

/** Per-finding business-impact annotations keyed by finding id */
const RISK_CATEGORY_MAP = {
  "dns_no_resolution":                  { category: "Availability",    impact: "Domain resolution failure prevents all customer access and online business operations." },
  "ssl_expired":                        { category: "Data Security",   impact: "Expired certificate causes browser warnings and exposes users to man-in-the-middle attacks, risking loss of transaction integrity and customer trust." },
  "ssl_expiring_soon":                  { category: "Availability",    impact: "Certificate expiry within days will cause customer-facing service outages and potential data interception if not renewed." },
  "ssl_no_https":                       { category: "Data Security",   impact: "Unencrypted HTTP communications expose customer credentials and sensitive data to network-level interception." },
  "ssl_no_redirect":                    { category: "Data Security",   impact: "Missing HTTP→HTTPS redirect allows clients to transmit data unencrypted, creating data leakage risk and browser security warnings." },
  "headers_csp_missing":                { category: "Web Security",    impact: "Absence of Content-Security-Policy enables cross-site scripting attacks that can steal user sessions, inject malicious code, and exfiltrate data." },
  "headers_hsts_missing":               { category: "Data Security",   impact: "Without HSTS enforcement, users can be silently downgraded to unencrypted HTTP connections subject to credential theft." },
  "headers_xfo_missing":                { category: "Web Security",    impact: "Clickjacking attacks can deceive users into performing unintended actions, including credential submission and financial transactions." },
  "headers_referrer_missing":           { category: "Web Security",    impact: "Sensitive URL parameters and paths may be leaked to third-party services via the Referer header." },
  "headers_permissions_missing":        { category: "Web Security",    impact: "Unrestricted browser API access (camera, microphone, location) increases the blast radius of any XSS vulnerability." },
  "email_no_spf":                       { category: "Brand Risk",      impact: "Attackers can send phishing email impersonating your domain to customers and partners, undermining brand trust and enabling fraud." },
  "email_no_dmarc":                     { category: "Brand Risk",      impact: "Without a valid DMARC policy, receivers have no domain-owner instruction for handling messages that fail alignment." },
  "email_weak_dmarc":                   { category: "Brand Risk",      impact: "DMARC monitoring provides visibility, but receivers are not instructed to quarantine or reject alignment failures." },
  "email_no_dkim":                      { category: "Brand Risk",      impact: "DKIM could not be verified using common selectors; a signed email sample or known selector is needed for confirmation." },
  "subdomain_takeover_risk":            { category: "Data Security",   impact: "Attackers can claim unclaimed DNS targets and serve malicious content or phishing pages under your trusted domain, bypassing browser security controls." },
  "tech_xpoweredby_version_disclosure": { category: "Reconnaissance",  impact: "Version disclosure accelerates targeted exploitation by eliminating attacker reconnaissance time for known CVEs." },
  "tech_server_version_disclosure":     { category: "Reconnaissance",  impact: "Exposed server version enables immediate targeting of known CVEs specific to your software revision." },
};

/** Default business impact narratives by severity when no specific mapping exists */
const SEVERITY_DEFAULT_IMPACT = {
  critical: "Immediate threat to business continuity, customer data, or regulatory compliance. Executive escalation required.",
  high:     "Significant security risk with active exploitation potential. Remediation required within 30 days.",
  medium:   "Moderate risk that broadens the attack surface. Schedule remediation within 90 days.",
  low:      "Low-impact finding that improves defence-in-depth. Address in next maintenance cycle.",
};

/**
 * Enrich findings with business risk context and generate a risk narrative.
 * Ported from risk_engine.generate_findings() and calculate_attack_surface_score()
 * with enhanced business-impact language.
 */
export function runRiskModule(findings, modules) {
  const categories = {
    "Data Security":  [],
    "Web Security":   [],
    "Brand Risk":     [],
    "Availability":   [],
    "Reconnaissance": [],
    "Other":          [],
  };

  let criticalCount = 0, highCount = 0, mediumCount = 0, lowCount = 0;
  const enrichedFindings = [];

  for (const f of findings) {
    const sev = (f.severity || "").toLowerCase();
    if (sev === "critical")    criticalCount++;
    else if (sev === "high")   highCount++;
    else if (sev === "medium") mediumCount++;
    else if (sev === "low")    lowCount++;

    const mapped  = RISK_CATEGORY_MAP[f.id] || null;
    const category       = mapped?.category || "Other";
    const businessImpact = mapped?.impact   || SEVERITY_DEFAULT_IMPACT[sev] || "";

    const enriched = { ...f, business_impact: businessImpact, risk_category: category };
    enrichedFindings.push(enriched);
    categories[category].push(enriched);
  }

  // KEV matches warrant a board-level risk notice regardless of score
  const kevMatches = modules.known_exploited_vulnerabilities?.matches || [];
  if (kevMatches.length > 0) {
    const kevNote = {
      id:             "kev_active_exploitation",
      severity:       "critical",
      title:          `${kevMatches.length} CISA Known Exploited Vulnerabilit${kevMatches.length === 1 ? "y" : "ies"} detected in technology stack`,
      description:    "Vulnerabilities on the CISA KEV list carry confirmed active exploitation evidence. CISA mandates remediation for US federal systems; all organisations should treat these as immediate priorities.",
      business_impact:"Active exploitation confirmed. Material risk of ransomware, data breach, or regulatory penalty (GDPR breach notification obligation may apply). Board-level escalation warranted.",
      risk_category:  "Data Security",
      score_impact:   0,
    };
    enrichedFindings.unshift(kevNote);
    categories["Data Security"].unshift(kevNote);
    criticalCount++;
  }

  // CVE intelligence summary
  const cveIntel = modules.cve_intelligence || {};
  if ((cveIntel.critical_count || 0) > 0 || (cveIntel.high_count || 0) > 0) {
    const cveNote = {
      id:             "cve_high_severity_detected",
      severity:       cveIntel.critical_count > 0 ? "critical" : "high",
      title:          `${cveIntel.total_cves} known CVE${cveIntel.total_cves !== 1 ? "s" : ""} matched to detected technology stack`,
      description:    `NVD lookup matched ${cveIntel.total_cves} CVE(s) across ${(cveIntel.technologies_checked || []).join(", ")}. ${cveIntel.critical_count || 0} critical, ${cveIntel.high_count || 0} high severity.`,
      business_impact:"Known vulnerabilities in deployed technologies increase the likelihood of exploitation by automated scanners and targeted attacks. Immediate patching or compensating controls required.",
      risk_category:  "Data Security",
      score_impact:   0,
    };
    enrichedFindings.push(cveNote);
    categories["Data Security"].push(cveNote);
    if (cveNote.severity === "critical") criticalCount++;
    else highCount++;
  }

  // Build overall risk narrative
  let overallRisk, narrative;
  if (criticalCount > 0) {
    overallRisk = "Critical";
    narrative   = `${criticalCount} critical issue${criticalCount > 1 ? "s require" : " requires"} immediate executive attention. Business operations, customer data, or regulatory compliance are at direct risk.`;
  } else if (highCount > 0) {
    overallRisk = "High";
    narrative   = `${highCount} high-severity issue${highCount > 1 ? "s present" : " presents"} significant security risk. These should be addressed within 30 days to reduce exposure to active threat actors.`;
  } else if (mediumCount > 0) {
    overallRisk = "Moderate";
    narrative   = `${mediumCount} medium-severity issue${mediumCount > 1 ? "s have been" : " has been"} identified. These findings expand the attack surface and should be included in the next security roadmap cycle.`;
  } else {
    overallRisk = "Low";
    narrative   = "No critical or high-severity issues detected. Continue security monitoring and address any low-severity findings in the next maintenance cycle.";
  }

  // Drop empty categories before returning
  const populatedCategories = {};
  for (const [cat, items] of Object.entries(categories)) {
    if (items.length > 0) populatedCategories[cat] = items;
  }

  return {
    overall_risk_level: overallRisk,
    narrative,
    risk_categories:    populatedCategories,
    finding_counts:     { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
    enriched_findings:  enrichedFindings,
  };
}

// ── Intelligence Module: Remediation Prioritization ──────────────────────────
// Ported from remediation_prioritization.py — converts findings into a P1/P2/P3
// remediation roadmap keyed for the executive PDF report.
// KEV matches always become P1 regardless of CVSS.
// Subdomain takeover risks also escalate to P1 (attacker can serve content under
// the domain).

/**
 * Generate a prioritised remediation plan from findings, KEV matches, and
 * takeover risks.  Pure computation, no I/O.
 * Ported from remediation_prioritization.generate_remediation_plan().
 */
export function runRemediationModule(findings, kevModule, takeoverModule) {
  const p1 = [];  // Immediate — KEV + Critical + Takeover
  const p2 = [];  // High priority — High severity
  const p3 = [];  // Planned — Medium + Low

  // 1. KEV matches → always P1 (mirrors remediation_prioritization.py)
  for (const match of (kevModule?.matches || [])) {
    p1.push({
      title:    `Remediate ${match.cve_id} — ${match.vulnerability_name || match.product || "Known Exploited Vulnerability"}`,
      reason:   "Listed in CISA Known Exploited Vulnerabilities catalog with confirmed active exploitation in the wild.",
      action:   match.required_action || "Apply vendor security update per CISA advisory immediately.",
      source:   "cisa_kev",
      cve_id:   match.cve_id,
      due_date: match.due_date || null,
    });
  }

  // 2. Subdomain takeover risks → P1 (attacker-controlled content under your domain)
  for (const risk of (takeoverModule?.risks || [])) {
    const host = risk.subdomain || risk.hostname || risk.cname || "unknown";
    p1.push({
      title:  `Reclaim dangling DNS record for ${host}`,
      reason: risk.risk_reason || "Unclaimed subdomain CNAME target allows an attacker to take over this hostname.",
      action: "Delete the dangling CNAME record or re-register the cloud service the CNAME points to.",
      source: "subdomain_takeover",
    });
  }

  // 3. Scan findings by severity
  for (const f of findings) {
    const sev = (f.severity || "").toLowerCase();
    if (sev === "informational") continue;  // Informational items not actionable enough for roadmap

    const item = {
      title:  f.title || f.id,
      reason: `${f.severity} severity — ${f.description?.slice(0, 120) || ""}`.trim(),
      action: f.recommendation || "Review and remediate per security best practices.",
      source: f.module || "scan",
    };

    if (sev === "critical")                    p1.push(item);
    else if (sev === "high")                   p2.push(item);
    else if (sev === "medium" || sev === "low") p3.push(item);
  }

  // De-duplicate by title (KEV items may overlap with CVE findings from computeScore)
  const dedup = (list) => {
    const seen = new Set();
    return list.filter(item => {
      if (seen.has(item.title)) return false;
      seen.add(item.title);
      return true;
    });
  };

  const cleanP1 = dedup(p1);
  const cleanP2 = dedup(p2);
  const cleanP3 = dedup(p3);

  return {
    p1_immediate:  cleanP1,
    p2_high:       cleanP2,
    p3_medium_low: cleanP3,
    summary: {
      p1_count: cleanP1.length,
      p2_count: cleanP2.length,
      p3_count: cleanP3.length,
      total:    cleanP1.length + cleanP2.length + cleanP3.length,
    },
  };
}
