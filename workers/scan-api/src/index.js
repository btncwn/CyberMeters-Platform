// ─────────────────────────────────────────────────────────────────────────────
// CyberMeters Scan API — Cloudflare Worker
// ─────────────────────────────────────────────────────────────────────────────

// ── Utilities ────────────────────────────────────────────────────────────────

function createId(prefix) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function isValidDomain(domain) {
  return (
    typeof domain === "string" &&
    /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)
  );
}

/**
 * DNS-over-HTTPS query via Cloudflare (1.1.1.1).
 * Workers have no raw socket access; DoH is the Cloudflare-native approach.
 */
async function dnsQuery(name, type) {
  const res = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
    {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(6_000),
    }
  );
  if (!res.ok) throw new Error(`DoH ${res.status} for ${type} ${name}`);
  return res.json();
}

/**
 * HTTP fetch that never throws — returns null on timeout / network error.
 */
async function safeFetch(url, options = {}) {
  try {
    return await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    return null;
  }
}

// ── Security Headers Config ───────────────────────────────────────────────────

const SECURITY_HEADERS = [
  {
    name:         "strict-transport-security",
    label:        "HTTP Strict Transport Security (HSTS)",
    severity:     "high",
    score_impact: -5,
    recommendation:
      'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
  },
  {
    name:         "content-security-policy",
    label:        "Content Security Policy (CSP)",
    severity:     "medium",
    score_impact: -3,
    recommendation:
      "Add a Content-Security-Policy header to restrict which resources the browser may load.",
  },
  {
    name:         "x-frame-options",
    label:        "X-Frame-Options",
    severity:     "medium",
    score_impact: -2,
    recommendation: "Add: X-Frame-Options: DENY to prevent clickjacking attacks.",
  },
  {
    name:         "x-content-type-options",
    label:        "X-Content-Type-Options",
    severity:     "low",
    score_impact: -2,
    recommendation: "Add: X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
  },
  {
    name:         "referrer-policy",
    label:        "Referrer-Policy",
    severity:     "low",
    score_impact: -1,
    recommendation:
      "Add: Referrer-Policy: strict-origin-when-cross-origin",
  },
  {
    name:         "permissions-policy",
    label:        "Permissions-Policy",
    severity:     "info",
    score_impact: -1,
    recommendation:
      "Add a Permissions-Policy header to restrict access to browser APIs (camera, microphone, geolocation).",
  },
];

// ── Module 1: DNS Analysis ────────────────────────────────────────────────────

async function runDnsModule(domain) {
  // CAA runs here alongside A/AAAA/NS/MX — all parallel, no extra round-trip cost.
  // Placing CAA in the DNS module avoids adding subrequests to later phases
  // where the free-plan 50-subrequest budget may already be exhausted.
  const [aRes, aaaaRes, nsRes, mxRes, caaRes] = await Promise.allSettled([
    dnsQuery(domain, "A"),
    dnsQuery(domain, "AAAA"),
    dnsQuery(domain, "NS"),
    dnsQuery(domain, "MX"),
    dnsQuery(domain, "CAA"),
  ]);

  const pick = (r) =>
    r.status === "fulfilled" ? r.value.Answer || [] : [];

  const aRecords    = pick(aRes);
  const aaaaRecords = pick(aaaaRes);
  const nsRecords   = pick(nsRes);
  const mxRecords   = pick(mxRes);

  // ── CAA Record Analysis ─────────────────────────────────────────────────
  let caa;
  if (caaRes.status === "fulfilled") {
    const answers = caaRes.value.Answer || [];
    const records = answers.map((r) => (r.data || "").trim()).filter(Boolean);
    function extractCaaTag(tag) {
      return records
        .filter((r) => new RegExp(`^0\\s+${tag}\\s+`, "i").test(r))
        .map((r) => r.replace(new RegExp(`^0\\s+${tag}\\s+"?`, "i"), "").replace(/"$/, "").trim())
        .filter(Boolean);
    }
    caa = {
      present:          records.length > 0,
      records,
      issuers:          extractCaaTag("issue"),
      wildcard_issuers: extractCaaTag("issuewild"),
      iodef:            extractCaaTag("iodef"),
      error:            null,
    };
  } else {
    caa = {
      present: false, records: [], issuers: [],
      wildcard_issuers: [], iodef: [],
      error: caaRes.reason?.message ?? "CAA lookup failed",
    };
  }

  return {
    resolves:     aRecords.length > 0 || aaaaRecords.length > 0,
    has_ipv6:     aaaaRecords.length > 0,
    has_mx:       mxRecords.length > 0,
    nameservers:  nsRecords.map((r) => r.data).filter(Boolean),
    a_records:    aRecords.map((r) => ({ value: r.data, ttl: r.TTL })),
    aaaa_records: aaaaRecords.map((r) => ({ value: r.data, ttl: r.TTL })),
    mx_records:   mxRecords.map((r) => ({ value: r.data, ttl: r.TTL })),
    caa,
  };
}

// ── Module 2: SSL Detection ───────────────────────────────────────────────────

async function runSslModule(domain) {
  // Try HTTPS on the bare domain
  const httpsRes = await safeFetch(`https://${domain}`, {
    method: "HEAD",
    redirect: "manual",
  });
  const httpsOk = httpsRes !== null && httpsRes.status < 500;

  // Try www. fallback if bare domain HTTPS fails
  let wwwHttpsOk = false;
  if (!httpsOk && !domain.startsWith("www.")) {
    const wwwRes = await safeFetch(`https://www.${domain}`, {
      method: "HEAD",
      redirect: "manual",
    });
    wwwHttpsOk = wwwRes !== null && wwwRes.status < 500;
  }

  // Check whether plain HTTP redirects to HTTPS
  const httpRes = await safeFetch(`http://${domain}`, {
    method: "HEAD",
    redirect: "manual",
  });
  let httpRedirectsToHttps = false;
  if (httpRes) {
    const loc = httpRes.headers.get("location") || "";
    if (
      [301, 302, 307, 308].includes(httpRes.status) &&
      loc.startsWith("https://")
    ) {
      httpRedirectsToHttps = true;
    }
  }

  // ── SSL Certificate Expiry (via Certificate Transparency / crt.sh) ──────────
  // Workers cannot inspect TLS handshake details on outbound fetch() calls, so
  // we query crt.sh for the most recently issued valid certificate and compute
  // days until expiry.  Best-effort — failure leaves cert_expiry_days as null.
  let cert_expiry_days = null;
  let cert_not_after   = null;
  try {
    const crtRes = await fetch(
      `https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`,
      {
        headers: { Accept: "application/json", "User-Agent": "CyberMeters/1.0" },
        signal:  AbortSignal.timeout(8_000),
      }
    );
    if (crtRes.ok) {
      const ct = crtRes.headers.get("content-type") || "";
      if (ct.includes("json")) {
        const certs = await crtRes.json();
        if (Array.isArray(certs)) {
          const now = Date.now();
          // Keep only certs that are currently valid (not yet expired).
          // Sort by not_after descending so the longest-lived cert comes first —
          // that is the one most likely still active on the server.
          const valid = certs
            .filter(c => c.not_after && new Date(c.not_after).getTime() > now)
            .sort((a, b) => new Date(b.not_after).getTime() - new Date(a.not_after).getTime());
          if (valid.length > 0) {
            cert_not_after   = valid[0].not_after;
            cert_expiry_days = Math.floor(
              (new Date(cert_not_after).getTime() - now) / 86_400_000
            );
          }
        }
      }
    }
  } catch {
    // crt.sh unavailable — cert expiry data omitted, scan still completes
  }

  return {
    https_available:          httpsOk || wwwHttpsOk,
    http_redirects_to_https:  httpRedirectsToHttps,
    www_fallback_used:        !httpsOk && wwwHttpsOk,
    cert_expiry_days,
    cert_not_after,
  };
}

// ── Module 3: Security Headers Analysis ──────────────────────────────────────

async function runHeadersModule(domain) {
  let headerValues = {};
  let accessible   = false;
  let statusCode   = null;
  let responseUrl  = null;
  let setCookieRaw = [];   // captured here so enrichment module needs no extra fetch

  // Prefer HTTPS; fall back to HTTP
  for (const proto of ["https", "http"]) {
    const res = await safeFetch(`${proto}://${domain}`, {
      method: "GET",
      redirect: "follow",
    });
    if (res) {
      accessible  = true;
      statusCode  = res.status;
      responseUrl = res.url;
      for (const h of SECURITY_HEADERS) {
        headerValues[h.name] = res.headers.get(h.name) || null;
      }
      // Capture Set-Cookie — Cloudflare Workers supports getAll() for this header
      // because multiple Set-Cookie values cannot be safely comma-joined.
      try {
        setCookieRaw = typeof res.headers.getAll === "function"
          ? res.headers.getAll("set-cookie")
          : (res.headers.get("set-cookie") || "").split(/\r?\n/).filter(Boolean);
      } catch { setCookieRaw = []; }
      break;
    }
  }

  const present = SECURITY_HEADERS.filter((h) => !!headerValues[h.name]).map((h) => h.name);
  const missing = SECURITY_HEADERS.filter((h) => !headerValues[h.name]).map((h) => h.name);

  return {
    accessible,
    status_code:   statusCode,
    response_url:  responseUrl,
    present,
    missing,
    values:        headerValues,
    set_cookie_raw: setCookieRaw,   // raw Set-Cookie header values for enrichment module
  };
}

// ── Module 4: Email Security (SPF / DMARC / DKIM) ────────────────────────────

// Common DKIM selectors to probe — best-effort discovery
const DKIM_SELECTORS = [
  "default", "mail", "google", "k1", "selector1", "selector2",
  "dkim", "smtp", "email", "mailchimp", "sendgrid", "s1", "s2",
];

async function runEmailModule(domain) {
  // Fire all queries in parallel: SPF (TXT on root) + DMARC + DKIM selectors
  const [spfRes, dmarcRes, ...dkimResults] = await Promise.allSettled([
    dnsQuery(domain, "TXT"),
    dnsQuery(`_dmarc.${domain}`, "TXT"),
    ...DKIM_SELECTORS.map((sel) => dnsQuery(`${sel}._domainkey.${domain}`, "TXT")),
  ]);

  // SPF — look for v=spf1 in root TXT records
  const rootTxt  = spfRes.status === "fulfilled" ? (spfRes.value.Answer || []) : [];
  const spfRecs  = rootTxt.filter((r) => r.data?.includes("v=spf1"));
  const hasSPF   = spfRecs.length > 0;

  // DMARC — _dmarc.<domain> TXT
  const dmarcTxt  = dmarcRes.status === "fulfilled" ? (dmarcRes.value.Answer || []) : [];
  const dmarcRecs = dmarcTxt.filter((r) => r.data?.includes("v=DMARC1"));
  const hasDMARC  = dmarcRecs.length > 0;

  // Parse DMARC policy tag
  let dmarcPolicy = null;
  if (hasDMARC && dmarcRecs[0]?.data) {
    const m = dmarcRecs[0].data.match(/p=([^;"\s]+)/);
    dmarcPolicy = m ? m[1].trim().toLowerCase() : null;
  }

  // DKIM — first selector with a valid public key record
  let dkimSelector = null;
  for (let i = 0; i < DKIM_SELECTORS.length; i++) {
    const r = dkimResults[i];
    if (r.status === "fulfilled" && r.value.Answer?.length > 0) {
      const valid = r.value.Answer.filter(
        (a) => a.data?.includes("v=DKIM1") || a.data?.includes("p=")
      );
      if (valid.length > 0) {
        dkimSelector = DKIM_SELECTORS[i];
        break;
      }
    }
  }

  return {
    spf: {
      present: hasSPF,
      record:  hasSPF ? spfRecs[0].data : null,
    },
    dmarc: {
      present: hasDMARC,
      policy:  dmarcPolicy,
      record:  hasDMARC ? dmarcRecs[0].data : null,
    },
    dkim: {
      present:  dkimSelector !== null,
      selector: dkimSelector,
    },
  };
}

// ── Module: Domain Security Enrichment ───────────────────────────────────────
//
// Three low-cost checks that run in parallel during Phase 1:
//
//   CAA     — DNS CAA record lookup (DoH).  Detects missing CAA, lists allowed
//             CAs, wildcard issuers, and IODEF incident-report addresses.
//
//   HSTS    — Parses the Strict-Transport-Security header from the live HTTPS
//             response.  Computes preload eligibility (max-age >= 1 yr,
//             includeSubDomains, preload directive all required).
//
//   Cookies — Parses Set-Cookie headers from the same HTTPS response.
//             Flags cookies missing the Secure, HttpOnly, or SameSite attributes.
//
// All three sub-checks are internally parallel (Promise.allSettled). Individual
// sub-failures are non-fatal and leave only that sub-section errored.

/**
 * Pure computation — zero network I/O.
 *
 * Reads data already captured by earlier modules:
 *   CAA    ← modules.dns.caa        (added to runDnsModule in Phase 1)
 *   HSTS   ← modules.headers.values["strict-transport-security"]
 *   Cookies ← modules.headers.set_cookie_raw  (added to runHeadersModule)
 *
 * This design avoids consuming additional subrequests on Cloudflare Workers'
 * free-plan 50-subrequest budget.
 */
function runDomainSecurityEnrichmentModule(domain, modules) {
  // ── 1. CAA — read from DNS module ────────────────────────────────────────
  const caa = modules?.dns?.caa ?? {
    present: false, records: [], issuers: [],
    wildcard_issuers: [], iodef: [],
    error: "skipped_due_to_subrequest_budget",
  };

  // ── 2. HSTS — read from headers module ───────────────────────────────────
  const hstsRaw = modules?.headers?.values?.["strict-transport-security"] || null;
  let hsts;
  if (hstsRaw) {
    const parts  = hstsRaw.toLowerCase().split(";").map((p) => p.trim());
    const maxDir = parts.find((p) => p.startsWith("max-age"));
    let maxAge   = null;
    if (maxDir) {
      const m = maxDir.match(/max-age\s*=\s*(\d+)/);
      if (m) maxAge = parseInt(m[1], 10);
    }
    const inclSub = parts.includes("includesubdomains");
    const preDir  = parts.includes("preload");
    hsts = {
      present:            true,
      value:              hstsRaw,
      max_age:            maxAge,
      include_subdomains: inclSub,
      preload_directive:  preDir,
      preload_eligible:   maxAge !== null && maxAge >= 31_536_000 && inclSub && preDir,
      error:              null,
    };
  } else {
    hsts = {
      present: false, value: null, max_age: null,
      include_subdomains: false, preload_directive: false,
      preload_eligible: false, error: null,
    };
  }

  // ── 3. Cookies — read from headers module ────────────────────────────────
  const rawCookies = modules?.headers?.set_cookie_raw || [];
  const parsed = rawCookies.map((raw) => {
    const parts  = raw.split(";").map((p) => p.trim());
    const name   = (parts[0] || "").split("=")[0].trim();
    const attrs  = parts.slice(1).map((p) => p.toLowerCase());
    const ss     = attrs.find((a) => a.startsWith("samesite="));
    return {
      name,
      secure:   attrs.includes("secure"),
      httponly: attrs.includes("httponly"),
      samesite: ss ? ss.split("=")[1] : null,
    };
  });
  const cookies = {
    found:          parsed.length,
    cookies:        parsed,
    insecure_count: parsed.filter((c) => !c.secure).length,
    no_httponly:    parsed.filter((c) => !c.httponly).length,
    no_samesite:    parsed.filter((c) => !c.samesite).length,
    error:          null,
  };

  return { caa, hsts, cookies, source: "dns_headers_analysis", error: null };
}

// ── Module 5: Technology Detection ───────────────────────────────────────────
// Ported from tech_fingerprint.py — collects response headers and infers the
// technology stack.  Runs in Phase 1 parallel with the other core modules.
// Never throws; returns { error } on failure so the scan pipeline continues.

/** Return true if a string matches a version-like pattern (e.g. "PHP/8.1.2"). */
function looksVersioned(s) {
  if (!s) return false;
  // Matches "/1.2", "/ 2", "1.2.3", " v2.4" etc.
  return /[\/\s][0-9]+\.[0-9]/.test(s) || /[\/\s][0-9]{1,3}$/.test(s.trim());
}

async function runTechModule(domain) {
  let res = null;
  let bodySnippet = "";

  try {
    res = await safeFetch(`https://${domain}`, {
      method:   "GET",
      redirect: "follow",
    });
    if (res) {
      // Read first 4 KB of body — enough for <script src> / vite markers in <head>
      const reader = res.body?.getReader();
      if (reader) {
        const { value } = await reader.read();
        reader.cancel();
        if (value) bodySnippet = new TextDecoder().decode(value.slice(0, 4096));
      }
    }
  } catch {
    return { error: "Tech module fetch failed" };
  }

  if (!res) return { error: "Tech module: no response" };

  const h = (name) => res.headers.get(name) ?? null;

  const server     = h("server");
  const poweredBy  = h("x-powered-by");
  const ct         = h("content-type");
  const hsts       = h("strict-transport-security");
  const csp        = h("content-security-policy");
  const xfo        = h("x-frame-options");
  const xcto       = h("x-content-type-options");
  const cfRay      = h("cf-ray");
  const finalUrl   = res.url || `https://${domain}`;
  const statusCode = res.status;

  // ── Inferred technologies ────────────────────────────────────────────────
  const technologies = [];

  const serverLc    = (server    || "").toLowerCase();
  const poweredByLc = (poweredBy || "").toLowerCase();
  const bodyLc      = bodySnippet.toLowerCase();

  if (cfRay || serverLc.includes("cloudflare"))          technologies.push("Cloudflare");
  if (serverLc.includes("nginx"))                        technologies.push("nginx");
  if (serverLc.includes("apache"))                       technologies.push("Apache");
  if (serverLc.includes("iis"))                          technologies.push("Microsoft IIS");
  if (serverLc.includes("openresty"))                    technologies.push("OpenResty");
  if (serverLc.includes("litespeed"))                    technologies.push("LiteSpeed");
  if (poweredByLc.includes("express"))                   technologies.push("Express");
  if (poweredByLc.includes("php"))                       technologies.push("PHP");
  if (poweredByLc.includes("asp.net"))                   technologies.push("ASP.NET");
  if (poweredByLc.includes("next.js"))                   technologies.push("Next.js");
  if (poweredByLc.includes("django"))                    technologies.push("Django");
  if (bodyLc.includes("/assets/index-") ||
      bodyLc.includes("vite") ||
      bodyLc.includes("__vite_"))                        technologies.push("React/Vite");
  if (!technologies.some(t => t === "React/Vite") &&
      bodyLc.includes("_next/static"))                   technologies.push("Next.js");
  if (bodyLc.includes("wp-content") ||
      bodyLc.includes("wp-includes"))                    technologies.push("WordPress");
  if (bodyLc.includes("drupal"))                         technologies.push("Drupal");
  if (bodyLc.includes("joomla"))                         technologies.push("Joomla");

  // ── Informational findings (no score impact) ─────────────────────────────
  // Only raised when headers expose specific version strings — not for generic
  // server names.  "Do not penalize generic Server header yet."
  const infoFindings = [];

  if (poweredBy && looksVersioned(poweredBy)) {
    infoFindings.push({
      id:           "tech_xpoweredby_version_disclosure",
      severity:     "low",
      title:        "X-Powered-By header exposes technology version",
      description:  `The X-Powered-By header discloses a version string: "${poweredBy}". ` +
                    "Attackers can use version information to target known CVEs. Remove or mask this header.",
      score_impact: 0,
    });
  }

  if (server && looksVersioned(server)) {
    infoFindings.push({
      id:           "tech_server_version_disclosure",
      severity:     "low",
      title:        "Server header exposes software version",
      description:  `The Server header discloses a version string: "${server}". ` +
                    "Consider configuring your web server to return a generic or empty Server header.",
      score_impact: 0,
    });
  }

  return {
    final_url:                 finalUrl,
    status_code:               statusCode,
    server,
    x_powered_by:              poweredBy,
    content_type:              ct,
    strict_transport_security: hsts,
    content_security_policy:   csp,
    x_frame_options:           xfo,
    x_content_type_options:    xcto,
    technologies:              [...new Set(technologies)],  // deduplicate
    info_findings:             infoFindings,
  };
}

// ── Module 6: Subdomain Discovery (Certificate Transparency) ─────────────────

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

// ── Module 6: WHOIS Intelligence ─────────────────────────────────────────────
// Uses RDAP (Registration Data Access Protocol) — the modern HTTP+JSON
// replacement for port-43 WHOIS, which is blocked in Cloudflare Workers.
// Queries authoritative TLD registries first (Verisign, Nominet, PIR), then
// falls back to rdap.org as a universal aggregator.
// Never throws — returns { error } on any failure so the scan continues.

/**
 * Extract the registered (eTLD+1) domain from any hostname.
 * Handles two-label second-level domains under .uk so that
 * blackbullbarbers.co.uk is NOT reduced to co.uk.
 *
 * Rules (no external packages):
 *   .co.uk / .org.uk / .ac.uk / .gov.uk / .ltd.uk / .plc.uk / .me.uk / .net.uk
 *     → keep last 3 labels   (eTLD = 2 labels)
 *   everything else
 *     → keep last 2 labels   (eTLD = 1 label)
 *
 * Examples:
 *   app.blackbullbarbers.co.uk  → blackbullbarbers.co.uk
 *   blackbullbarbers.co.uk      → blackbullbarbers.co.uk  (no-op)
 *   sub.example.com             → example.com
 *   example.com                 → example.com             (no-op)
 */
function getRegisteredDomain(hostname) {
  const parts = hostname.toLowerCase().split(".");

  // Known two-label SLDs under .uk that act as effective TLDs
  const UK_SECOND_LEVELS = new Set([
    "co", "org", "ac", "gov", "ltd", "plc", "me", "net", "sch",
  ]);

  if (parts.length >= 3) {
    const tld     = parts[parts.length - 1];   // e.g. "uk"
    const sld     = parts[parts.length - 2];   // e.g. "co"
    if (tld === "uk" && UK_SECOND_LEVELS.has(sld)) {
      // eTLD is "co.uk" — registered domain is label + co.uk (3 parts total)
      return parts.slice(-3).join(".");
    }
  }

  // Default: eTLD is the single last label — registered domain is last 2 labels
  return parts.slice(-2).join(".");
}

/**
 * Return an ordered list of RDAP URLs to try for a given registered domain.
 * Authoritative registries are tried first to avoid aggregator blocks (403).
 * rdap.org is always the final fallback.
 */
function getRdapUrls(registeredDomain) {
  const enc  = encodeURIComponent(registeredDomain);
  const tld  = registeredDomain.split(".").pop().toLowerCase();
  const sld  = registeredDomain.split(".").slice(-2).join(".").toLowerCase();

  const urls = [];

  // TLD-specific authoritative endpoints
  if (tld === "com") {
    urls.push(`https://rdap.verisign.com/com/v1/domain/${enc}`);
  } else if (tld === "net") {
    urls.push(`https://rdap.verisign.com/net/v1/domain/${enc}`);
  } else if (tld === "org") {
    urls.push(`https://rdap.publicinterestregistry.org/rdap/org/domain/${enc}`);
  } else if (tld === "uk" || sld.endsWith(".uk")) {
    urls.push(`https://rdap.nominet.uk/uk/domain/${enc}`);
  } else if (tld === "io") {
    urls.push(`https://rdap.nic.io/domain/${enc}`);
  } else if (tld === "co") {
    urls.push(`https://rdap.nic.co/domain/${enc}`);
  } else if (tld === "app" || tld === "dev") {
    // Google Registry
    urls.push(`https://rdap.nic.google/domain/${enc}`);
  }

  // Universal aggregator as final fallback (always included)
  urls.push(`https://rdap.org/domain/${enc}`);

  return urls;
}

const RDAP_UA = "CyberMeters/1.0 (https://cybermeters.com)";

async function runWhoisModule(domain) {
  try {
    // Strip subdomains — WHOIS is authoritative at the registered domain level.
    // e.g. sub.example.com → example.com
    //      app.blackbullbarbers.co.uk → blackbullbarbers.co.uk
    const registeredDomain = getRegisteredDomain(domain);

    // Try each RDAP provider in order; stop at the first 200 response.
    // Skip on 403/404 and continue — only fail if every provider fails.
    const rdapUrls  = getRdapUrls(registeredDomain);
    let   data      = null;
    const errors    = [];

    for (const rdapUrl of rdapUrls) {
      let res;
      try {
        res = await safeFetch(rdapUrl, {
          headers: {
            Accept:       "application/rdap+json, application/json",
            "User-Agent": RDAP_UA,
          },
          signal: AbortSignal.timeout(12_000),
        });
      } catch (fetchErr) {
        errors.push(`${rdapUrl} → network error: ${fetchErr.message ?? "timeout"}`);
        continue;
      }

      if (res && res.ok) {
        try {
          data = await res.json();
        } catch {
          errors.push(`${rdapUrl} → JSON parse failed`);
          continue;
        }
        break; // success — stop trying further providers
      }

      // 404 = domain not in this registry (try next), 403 = blocked (try next)
      errors.push(`${rdapUrl} → HTTP ${res?.status ?? "unknown"}`);
    }

    if (!data) {
      return { error: `All RDAP providers failed: ${errors.join("; ")}` };
    }

    // ── Extract dates from the events array ───────────────────────────────────
    let creationDate    = null;
    let expirationDate  = null;
    let updatedDate     = null;

    for (const event of data.events || []) {
      const action = (event.eventAction || "").toLowerCase();
      if (action === "registration")          creationDate   = event.eventDate ?? null;
      else if (action === "expiration")       expirationDate = event.eventDate ?? null;
      else if (action === "last changed")     updatedDate    = event.eventDate ?? null;
      else if (action === "last update of rdap database") {
        // Some registries only publish this — fall back for updated_date
        if (!updatedDate) updatedDate = event.eventDate ?? null;
      }
    }

    // ── Extract registrar from entities ──────────────────────────────────────
    let registrar = null;
    for (const entity of data.entities || []) {
      if (!(entity.roles || []).includes("registrar")) continue;
      // Try vCard fn field first
      const vcard = entity.vcardArray?.[1] ?? [];
      for (const field of vcard) {
        if (field[0] === "fn" && field[3]) { registrar = field[3]; break; }
      }
      // Fallback: publicIds IANA registrar id
      if (!registrar && entity.publicIds?.length) {
        registrar = entity.publicIds[0].identifier ?? null;
      }
      if (registrar) break;
    }

    // ── Name servers ──────────────────────────────────────────────────────────
    const nameServers = (data.nameservers || [])
      .map(ns => (ns.ldhName || ns.unicodeName || "").toLowerCase())
      .filter(Boolean);

    // ── Registration status ───────────────────────────────────────────────────
    const registrationStatus = (data.status || []).join(", ") || null;

    // ── Derived temporal fields ───────────────────────────────────────────────
    const now = Date.now();

    const createdMs     = creationDate   ? new Date(creationDate).getTime()   : null;
    const expiresMs     = expirationDate ? new Date(expirationDate).getTime() : null;

    const domainAgeDays    = createdMs != null && !isNaN(createdMs)
      ? Math.max(0, Math.floor((now - createdMs) / 86_400_000))
      : null;
    const daysUntilExpiry  = expiresMs != null && !isNaN(expiresMs)
      ? Math.floor((expiresMs - now) / 86_400_000)
      : null;

    // ── Findings ──────────────────────────────────────────────────────────────
    // score_impact is 0 — WHOIS findings are informational/advisory only and
    // do NOT feed into computeScore to avoid double-counting.
    const findings = [];
    let riskLevel = "Low";

    if (daysUntilExpiry != null) {
      if (daysUntilExpiry <= 0) {
        riskLevel = "High";
        findings.push({
          id:             "whois_domain_expired",
          title:          "Domain has expired",
          description:    `Domain ${registeredDomain} expiration date has passed (${daysUntilExpiry === 0 ? "today" : `${Math.abs(daysUntilExpiry)} days ago`}). The domain may be available for registration by a third party.`,
          severity:       "high",
          score_impact:   0,
          module:         "whois_intelligence",
          recommendation: "Renew domain immediately through your registrar. Check whether the grace period is still active.",
        });
      } else if (daysUntilExpiry <= 30) {
        riskLevel = "High";
        findings.push({
          id:             "whois_expiry_critical",
          title:          "Domain expires within 30 days",
          description:    `Domain ${registeredDomain} expires in ${daysUntilExpiry} day${daysUntilExpiry !== 1 ? "s" : ""}. Without renewal, services will stop and the domain may be seized.`,
          severity:       "high",
          score_impact:   0,
          module:         "whois_intelligence",
          recommendation: "Renew domain immediately and enable auto-renew to eliminate expiry risk.",
        });
      } else if (daysUntilExpiry <= 90) {
        if (riskLevel === "Low") riskLevel = "Medium";
        findings.push({
          id:             "whois_expiry_warning",
          title:          "Domain expires within 90 days",
          description:    `Domain ${registeredDomain} expires in ${daysUntilExpiry} days. Proactive renewal avoids service disruption and domain-hijacking risk.`,
          severity:       "medium",
          score_impact:   0,
          module:         "whois_intelligence",
          recommendation: "Schedule domain renewal and enable auto-renew at your registrar.",
        });
      }
    }

    if (domainAgeDays != null && domainAgeDays < 180) {
      findings.push({
        id:             "whois_new_domain",
        title:          "Recently registered domain",
        description:    `Domain was registered ${domainAgeDays} day${domainAgeDays !== 1 ? "s" : ""} ago. Newly registered domains carry elevated phishing-association and fraud-signal risk in email and threat-intel systems.`,
        severity:       "low",
        score_impact:   0,
        module:         "whois_intelligence",
        recommendation: "Verify domain ownership and configure SPF/DMARC/DKIM to reduce spam-score impact. Monitor for unauthorised use.",
      });
    }

    if (registrar) {
      findings.push({
        id:             "whois_registrar_info",
        title:          "Registrar identified",
        description:    `Domain is registered through ${registrar}${registrationStatus ? ` (status: ${registrationStatus})` : ""}.`,
        severity:       "informational",
        score_impact:   0,
        module:         "whois_intelligence",
        recommendation: null,
      });
    }

    // ── Recommendations ───────────────────────────────────────────────────────
    const recommendations = [
      daysUntilExpiry != null && daysUntilExpiry <= 90
        ? "Renew domain before expiration to prevent service outages and domain-hijacking."
        : null,
      "Enable auto-renew with your registrar to eliminate accidental expiry risk.",
      "Monitor for unauthorised registrar or nameserver changes (auth-code theft).",
      registrar ? null : "Verify registrar details — RDAP returned no registrar entity.",
    ].filter(Boolean);

    return {
      domain:              registeredDomain,
      registrar:           registrar ?? null,
      creation_date:       creationDate ?? null,
      updated_date:        updatedDate  ?? null,
      expiration_date:     expirationDate ?? null,
      domain_age_days:     domainAgeDays,
      days_until_expiry:   daysUntilExpiry,
      name_servers:        nameServers,
      registration_status: registrationStatus,
      risk_level:          riskLevel,
      findings,
      recommendations,
      source:              "rdap",
    };
  } catch (err) {
    return { error: err?.message ?? "WHOIS/RDAP lookup failed" };
  }
}

// ── Subdomain Discovery v2 ────────────────────────────────────────────────────
// Two Certificate Transparency sources run in parallel:
//   1. crt.sh          — certificate search (wildcard query, large historical set)
//   2. CertSpotter     — issuance index (different index, no API key required)
// Results are merged and deduplicated into a single sorted list.
// If one source fails the other still contributes — scan never aborts.
// Per-source counts and errors are exposed in modules.subdomains.sources.

async function runSubdomainsModule(domain) {
  const SOURCE    = "certificate_transparency_multi_source";
  const PER_CAP   = 200;   // max unique names from each CT source
  const MERGE_CAP = 300;   // cap on the merged deduplicated set
  const HARD_CAP_MS = 15_000; // wall-clock hard cap for the whole module

  // Graceful fallback — returned on hard-cap timeout or unexpected throw
  const emptyResult = (error, wildcardDns = false, wildcardHost = null) => ({
    count:              0,
    items:              [],
    sensitive:          [],
    source:             SOURCE,
    sources:            { crt_sh: { count: 0, error }, certspotter: { count: 0, error } },
    wildcard_dns:       wildcardDns,
    wildcard_test_host: wildcardHost,
    wildcard_warning:   null,
    error,
  });

  try {
    // Race the inner async work against a hard-cap timer.
    // If the hard cap fires first the scan continues with an empty result;
    // the inner work is abandoned (Cloudflare GC's the hanging fetch).
    return await Promise.race([
      _subdomainsCoreWork(domain, SOURCE, PER_CAP, MERGE_CAP),
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
 *   • crt.sh          (12 s)
 *   • CertSpotter     ( 8 s)
 * Total worst-case I/O = max(6, 12) = 12 s (well under the 15 s hard cap).
 */
async function _subdomainsCoreWork(domain, SOURCE, PER_CAP, MERGE_CAP) {
  const wildcardLabel = `cybermeters-wildcard-check-${Math.random().toString(36).slice(2, 10)}`;
  const wildcardHost  = `${wildcardLabel}.${domain}`;

  // ── Fire all 4 network calls in parallel ────────────────────────────────
  const [wASettled, wAAAASettled, crtShSettled, certSpotterSettled] =
    await Promise.allSettled([
      dnsQuery(wildcardHost, "A"),
      dnsQuery(wildcardHost, "AAAA"),
      fetch(
        `https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`,
        {
          headers: { Accept: "application/json", "User-Agent": RDAP_UA },
          signal:  AbortSignal.timeout(12_000),
        }
      ),
      fetch(
        `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
        {
          headers: { Accept: "application/json", "User-Agent": RDAP_UA },
          signal:  AbortSignal.timeout(8_000),
        }
      ),
    ]);

  // ── Wildcard DNS result ─────────────────────────────────────────────────
  const aAnswers    = wASettled.status    === "fulfilled" ? (wASettled.value.Answer    || []) : [];
  const aaaaAnswers = wAAAASettled.status === "fulfilled" ? (wAAAASettled.value.Answer || []) : [];
  const wildcardDns     = aAnswers.length > 0 || aaaaAnswers.length > 0;
  const wildcardWarning = wildcardDns
    ? "Wildcard DNS detected. Subdomain discovery results may include false positives."
    : null;

  const seen    = new Set();
  const sources = { crt_sh: null, certspotter: null };

  // ── Source 1: crt.sh ───────────────────────────────────────────────────
  try {
    const res = crtShSettled.status === "fulfilled" ? crtShSettled.value : null;
    if (!res) {
      sources.crt_sh = { count: 0, error: crtShSettled.reason?.message ?? "fetch failed" };
    } else if (!res.ok) {
      sources.crt_sh = { count: 0, error: `HTTP ${res.status}` };
    } else {
      const ct = res.headers.get("content-type") || "";
      if (!ct.includes("json")) {
        sources.crt_sh = { count: 0, error: "non-JSON response" };
      } else {
        const rawData = await res.json();
        if (!Array.isArray(rawData)) {
          sources.crt_sh = { count: 0, error: "unexpected response shape" };
        } else {
          const before = seen.size;
          outer: for (const entry of rawData.slice(0, 2_000)) {
            const names = [
              ...(entry.name_value || "").split(/\n/),
              entry.common_name || "",
            ];
            for (const raw of names) {
              const name = raw.trim().toLowerCase();
              if (!name || name.startsWith("*")) continue;
              if (!name.endsWith("." + domain) && name !== domain) continue;
              seen.add(name);
              if (seen.size - before >= PER_CAP) break outer;
            }
          }
          sources.crt_sh = { count: seen.size - before, error: null };
        }
      }
    }
  } catch (err) {
    sources.crt_sh = { count: 0, error: err.message ?? "parse error" };
  }

  // ── Source 2: CertSpotter ─────────────────────────────────────────────
  // Response: [{ dns_names: ["sub.example.com", ...], ... }, ...]
  try {
    const res = certSpotterSettled.status === "fulfilled" ? certSpotterSettled.value : null;
    if (!res) {
      sources.certspotter = { count: 0, error: certSpotterSettled.reason?.message ?? "fetch failed" };
    } else if (!res.ok) {
      sources.certspotter = { count: 0, error: `HTTP ${res.status}` };
    } else {
      const rawData = await res.json();
      if (!Array.isArray(rawData)) {
        sources.certspotter = { count: 0, error: "unexpected response shape" };
      } else {
        const before = seen.size;
        outer: for (const entry of rawData) {
          for (const name of entry.dns_names || []) {
            const n = name.trim().toLowerCase();
            if (!n || n.startsWith("*")) continue;
            if (!n.endsWith("." + domain) && n !== domain) continue;
            seen.add(n);
            if (seen.size - before >= PER_CAP) break outer;
          }
        }
        sources.certspotter = { count: seen.size - before, error: null };
      }
    }
  } catch (err) {
    sources.certspotter = { count: 0, error: err.message ?? "parse error" };
  }

  // ── Both sources failed ───────────────────────────────────────────────
  if (seen.size === 0 && sources.crt_sh?.error && sources.certspotter?.error) {
    return {
      count:              0,
      items:              [],
      sensitive:          [],
      source:             SOURCE,
      sources,
      wildcard_dns:       wildcardDns,
      wildcard_test_host: wildcardHost,
      wildcard_warning:   wildcardWarning,
      error: `Both CT sources failed — crt.sh: ${sources.crt_sh.error}; certspotter: ${sources.certspotter.error}`,
    };
  }

  // ── Merge, cap, sort ─────────────────────────────────────────────────
  const items     = [...seen].slice(0, MERGE_CAP).sort();
  const sensitive = items.filter((h) => isSensitiveSubdomain(h, domain));

  return {
    count:              items.length,
    items,
    sensitive,
    source:             SOURCE,
    sources,
    wildcard_dns:       wildcardDns,
    wildcard_test_host: wildcardHost,
    wildcard_warning:   wildcardWarning,
    error:              null,
  };
}

// ── DNS Brute-Force Discovery ─────────────────────────────────────────────────
// High-value curated wordlist capped at BRUTEFORCE_MAX_NAMES to stay within
// the Cloudflare Worker free-plan 50-subrequest budget.
// Runs in parallel with Phase 1 modules; bounded by BRUTEFORCE_TIMEOUT_MS.
// Results are merged into modules.subdomains.items so takeover + exposure
// detection automatically benefit from the expanded list.

const BRUTEFORCE_MAX_NAMES  = 15;
const BRUTEFORCE_TIMEOUT_MS = 6_000;

// High-value names only — exactly BRUTEFORCE_MAX_NAMES entries.
const BRUTE_FORCE_WORDLIST = [
  "www", "mail", "email", "webmail", "portal",
  "admin", "api", "app", "dev", "staging",
  "test", "vpn", "remote", "login", "dashboard",
];

/**
 * Probe the wordlist against `domain` via DoH A-record lookups.
 * Returns any names that resolve, with source = "dns_bruteforce".
 * Hard-capped at BRUTEFORCE_TIMEOUT_MS — returns whatever has resolved by then.
 */
async function runBruteforceModule(domain) {
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
          dnsQuery(host, "A").then((r) => ({ host, answers: r.Answer || [] }))
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

    return {
      checked: candidates.length,
      found:   found.length,
      items:   found,
      source:  "dns_bruteforce",
      error:   null,
    };
  } catch (err) {
    return empty(err?.message ?? "Brute-force module failed");
  }
}

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
async function runTakeoverModule(domain, subdomains) {
  const source = "subdomain_cname_fingerprint";

  if (!subdomains || subdomains.length === 0) {
    return { checked: 0, potential_risks: 0, risks: [], source, error: null };
  }

  // Cap at 100 to bound concurrent I/O without sacrificing coverage
  const targets = subdomains.slice(0, 100);

  // Step 1: CNAME lookups for all targets in parallel
  const cnameResults = await Promise.allSettled(
    targets.map((host) => dnsQuery(host, "CNAME"))
  );

  // Step 2: collect candidates whose CNAME resolves to a known vulnerable provider
  const candidates = [];
  for (let i = 0; i < targets.length; i++) {
    const r = cnameResults[i];
    if (r.status !== "fulfilled") continue;
    const answers = r.value.Answer || [];
    for (const answer of answers) {
      const cname = (answer.data || "").toLowerCase().replace(/\.$/, "");
      for (const fp of TAKEOVER_FINGERPRINTS) {
        if (cname === fp.cname_suffix || cname.endsWith("." + fp.cname_suffix)) {
          candidates.push({ host: targets[i], cname, fingerprint: fp });
          break;
        }
      }
    }
  }

  if (candidates.length === 0) {
    return { checked: targets.length, potential_risks: 0, risks: [], source, error: null };
  }

  // Step 3: fetch each candidate to confirm takeover via body fingerprint
  const bodyResults = await Promise.allSettled(
    candidates.map((c) =>
      safeFetch(`https://${c.host}`, { method: "GET", redirect: "follow" })
    )
  );

  const risks = [];
  for (let i = 0; i < candidates.length; i++) {
    const { host, cname, fingerprint } = candidates[i];
    const settled = bodyResults[i];
    if (settled.status !== "fulfilled" || !settled.value) continue;
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
    } catch {
      // body read error — skip this candidate
    }
  }

  return {
    checked:         targets.length,
    potential_risks: candidates.length,
    risks,
    source,
    error: null,
  };
}

// ── Cloud Storage Discovery ───────────────────────────────────────────────────
// Pattern-based detection of cloud storage references across all discovered
// hostnames and exposure assets.  No additional HTTP calls — pure analysis of
// data already present in other modules.
//
// Risk labels:
//   "cloud_storage_reference"  — pattern match only (info/low)
//   "potentially_public_storage" — HTTP evidence of public access (medium)
//   Currently only pattern matching is implemented; HTTP confirmation is deferred.

const CLOUD_STORAGE_PATTERNS = [
  {
    provider:  "AWS S3",
    patterns:  ["s3.amazonaws.com", "s3-website", "s3-website-", ".amazonaws.com"],
    risk_level: "medium",
  },
  {
    provider:  "Azure Blob Storage",
    patterns:  ["blob.core.windows.net", "web.core.windows.net"],
    risk_level: "medium",
  },
  {
    provider:  "Google Cloud Storage",
    patterns:  ["storage.googleapis.com"],
    risk_level: "medium",
  },
  {
    provider:  "Firebase / GCP",
    patterns:  ["firebaseapp.com", "appspot.com"],
    risk_level: "low",
  },
];

function detectCloudProvider(value) {
  if (!value) return null;
  const v = value.toLowerCase();
  for (const def of CLOUD_STORAGE_PATTERNS) {
    for (const pat of def.patterns) {
      if (v.includes(pat)) return def;
    }
  }
  return null;
}

/**
 * Scan subdomains and exposure assets for cloud storage indicators.
 * Pure computation — zero additional network calls.
 */
function runCloudStorageModule(domain, modules) {
  try {
    const findings = [];
    const seen     = new Set();    // deduplicate by asset+provider

    // Helper to record a finding without duplicates
    function record(asset, provider, evidence, risk_level) {
      const key = `${asset}::${provider}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        asset,
        provider,
        type:       "cloud_storage_reference",
        evidence,
        risk_level,
      });
    }

    // ── 1. Scan subdomain hostnames ───────────────────────────────────────
    const subItems = modules?.subdomains?.items || [];
    for (const hostname of subItems) {
      const match = detectCloudProvider(hostname);
      if (match) {
        record(hostname, match.provider, `hostname contains "${match.patterns.find(p => hostname.toLowerCase().includes(p))}"`, match.risk_level);
      }
    }

    // ── 2. Scan brute-force finds ─────────────────────────────────────────
    const bruteItems = (modules?.dns_bruteforce?.items || []);
    for (const item of bruteItems) {
      const match = detectCloudProvider(item.hostname);
      if (match) {
        record(item.hostname, match.provider, `brute-force hostname contains cloud storage pattern`, match.risk_level);
      }
    }

    // ── 3. Scan exposure asset URLs, CNAMEs, redirect_to ─────────────────
    const exposureAssets = modules?.asset_exposure?.assets || [];
    for (const asset of exposureAssets) {
      const checks = [
        { value: asset.url,         label: "URL" },
        { value: asset.cname,       label: "CNAME" },
        { value: asset.redirect_to, label: "redirect" },
      ];
      for (const { value, label } of checks) {
        const match = detectCloudProvider(value);
        if (match) {
          record(
            asset.hostname || asset.url,
            match.provider,
            `${label} contains "${match.patterns.find(p => (value || "").toLowerCase().includes(p))}"`,
            match.risk_level
          );
        }
      }
    }

    return {
      checked:  subItems.length + bruteItems.length + exposureAssets.length,
      findings,
      source:   "hostname_pattern_match",
      error:    null,
    };
  } catch (err) {
    return {
      checked:  0,
      findings: [],
      source:   "hostname_pattern_match",
      error:    err?.message ?? "Cloud storage module failed",
    };
  }
}

// ── Vendor Risk Layer ─────────────────────────────────────────────────────────
// Pure computation — reads signals already captured in other modules.
// Zero network I/O.  All data is already in `modules` from Phases 1-6.
//
// Signal sources checked:
//   spf    → SPF record string (include:/redirect: tokens)
//   mx     → MX host values
//   ns     → nameserver host values
//   dkim   → DKIM selector name
//   csp    → Content-Security-Policy header value
//   server → Server header value (from headers or tech_detection)
//   cname  → CNAME targets (takeover risks + exposure probe + bruteforce items)
//   tech   → technology names from technology_detection module
//
// Each VENDOR_SIGNATURES entry declares:
//   name       - display name
//   category   - infrastructure | cloud | email_identity | hosting | saas |
//                support | collaboration | ecommerce
//   risk_level - low | medium | high
//   signals[]  - array of { source, test(value):bool }
//                Multiple sources give higher confidence.

const VENDOR_SIGNATURES = [

  // ── Infrastructure / CDN ──────────────────────────────────────────────────
  { name: "Cloudflare",     category: "infrastructure", risk_level: "low",
    signals: [
      { source: "ns",     test: (v) => /cloudflare\.com/.test(v) },
      { source: "server", test: (v) => /cloudflare/.test(v) },
      { source: "tech",   test: (v) => v === "Cloudflare" },
    ],
  },
  { name: "Akamai",         category: "infrastructure", risk_level: "low",
    signals: [
      { source: "cname",  test: (v) => /akamai(edge)?\.net|akamaized\.net/.test(v) },
      { source: "server", test: (v) => /akamai/.test(v) },
    ],
  },
  { name: "Fastly",         category: "infrastructure", risk_level: "low",
    signals: [
      { source: "cname",  test: (v) => /fastly\.net/.test(v) },
      { source: "server", test: (v) => /fastly/.test(v) },
    ],
  },

  // ── Cloud ─────────────────────────────────────────────────────────────────
  { name: "AWS",            category: "cloud",          risk_level: "low",
    signals: [
      { source: "ns",     test: (v) => /awsdns/.test(v) },
      { source: "cname",  test: (v) => /amazonaws\.com|cloudfront\.net/.test(v) },
      { source: "spf",    test: (v) => /amazonses\.com/.test(v) },
      { source: "mx",     test: (v) => /amazonses\.com/.test(v) },
    ],
  },
  { name: "Azure",          category: "cloud",          risk_level: "low",
    signals: [
      { source: "ns",     test: (v) => /azure-dns\.(com|net|org|info)/.test(v) },
      { source: "cname",  test: (v) => /azurewebsites\.net|trafficmanager\.net|azureedge\.net/.test(v) },
    ],
  },
  { name: "Google Cloud",   category: "cloud",          risk_level: "low",
    signals: [
      { source: "ns",     test: (v) => /googledomains\.com|dns\.google/.test(v) },
      { source: "cname",  test: (v) => /\.googleusercontent\.com|storage\.googleapis\.com|appspot\.com/.test(v) },
    ],
  },
  { name: "Firebase",       category: "cloud",          risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /web\.app|firebaseapp\.com/.test(v) },
      { source: "csp",    test: (v) => /firebase\.google\.com|firebaseapp\.com/.test(v) },
    ],
  },
  { name: "DigitalOcean",   category: "cloud",          risk_level: "medium",
    signals: [
      { source: "ns",     test: (v) => /digitalocean\.com/.test(v) },
      { source: "cname",  test: (v) => /digitalocean\.com|ondigitalocean\.app/.test(v) },
    ],
  },

  // ── Email / Identity ──────────────────────────────────────────────────────
  { name: "Microsoft 365",  category: "email_identity", risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /spf\.protection\.outlook\.com/.test(v) },
      { source: "mx",     test: (v) => /\.protection\.outlook\.com/.test(v) },
      { source: "dkim",   test: (v) => /^selector[12]$/.test(v) },
      { source: "csp",    test: (v) => /outlook\.com|office365\.com|microsoft\.com/.test(v) },
    ],
  },
  { name: "Google Workspace", category: "email_identity", risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /_spf\.google\.com/.test(v) },
      { source: "mx",     test: (v) => /aspmx\.l\.google\.com|smtp\.google\.com|googlemail\.com/.test(v) },
      { source: "dkim",   test: (v) => /^google$/.test(v) },
    ],
  },
  { name: "Zoho Mail",      category: "email_identity", risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /zoho\.com/.test(v) },
      { source: "mx",     test: (v) => /zoho\.com|zohomail\.com/.test(v) },
    ],
  },
  { name: "GoDaddy Email",  category: "email_identity", risk_level: "low",
    signals: [
      { source: "mx",     test: (v) => /secureserver\.net|godaddy\.com/.test(v) },
      { source: "ns",     test: (v) => /domaincontrol\.com/.test(v) },
    ],
  },
  { name: "Proton Mail",    category: "email_identity", risk_level: "low",
    signals: [
      { source: "mx",     test: (v) => /protonmail\.ch|proton\.me/.test(v) },
    ],
  },
  { name: "Proofpoint",     category: "email_identity", risk_level: "low",
    signals: [
      { source: "mx",     test: (v) => /pphosted\.com/.test(v) },
    ],
  },
  { name: "Mimecast",       category: "email_identity", risk_level: "low",
    signals: [
      { source: "mx",     test: (v) => /mimecast\.com/.test(v) },
    ],
  },
  { name: "Barracuda",      category: "email_identity", risk_level: "low",
    signals: [
      { source: "mx",     test: (v) => /barracudanetworks\.com/.test(v) },
    ],
  },

  // ── Hosting / Developer Platforms ─────────────────────────────────────────
  { name: "GitHub Pages",   category: "hosting",        risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /github\.io/.test(v) },
    ],
  },
  { name: "GitLab Pages",   category: "hosting",        risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /gitlab\.io/.test(v) },
    ],
  },
  { name: "Vercel",         category: "hosting",        risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /vercel\.app|vercel-dns\.com|\.vercel\.com|now\.sh/.test(v) },
    ],
  },
  { name: "Netlify",        category: "hosting",        risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /netlify\.app|netlify\.com/.test(v) },
    ],
  },
  { name: "Heroku",         category: "hosting",        risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /herokuapp\.com|herokussl\.com/.test(v) },
    ],
  },
  { name: "Render",         category: "hosting",        risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /onrender\.com/.test(v) },
    ],
  },
  { name: "Railway",        category: "hosting",        risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /railway\.app/.test(v) },
    ],
  },
  { name: "Fly.io",         category: "hosting",        risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /fly\.dev|flycast\.io|fly\.io/.test(v) },
    ],
  },

  // ── SaaS ─────────────────────────────────────────────────────────────────
  { name: "Atlassian",      category: "saas",           risk_level: "medium",
    signals: [
      { source: "spf",    test: (v) => /atlassian\.com/.test(v) },
      { source: "cname",  test: (v) => /atlassian\.com|atlassian\.net/.test(v) },
      { source: "mx",     test: (v) => /atlassian\.com/.test(v) },
    ],
  },
  { name: "HubSpot",        category: "saas",           risk_level: "medium",
    signals: [
      { source: "spf",    test: (v) => /hubspot\.com/.test(v) },
      { source: "cname",  test: (v) => /hubspotpagebuilder\.com|hs-sites\.com|hsforms\.net|hubspot\.net/.test(v) },
      { source: "csp",    test: (v) => /hubspot\.com/.test(v) },
    ],
  },
  { name: "Salesforce",     category: "saas",           risk_level: "medium",
    signals: [
      { source: "spf",    test: (v) => /salesforce\.com/.test(v) },
      { source: "cname",  test: (v) => /salesforce\.com|force\.com/.test(v) },
      { source: "csp",    test: (v) => /salesforce\.com/.test(v) },
    ],
  },
  { name: "Marketo",        category: "saas",           risk_level: "medium",
    signals: [
      { source: "spf",    test: (v) => /mktomail\.com/.test(v) },
      { source: "cname",  test: (v) => /marketo\.com|mktoweb\.com/.test(v) },
    ],
  },
  { name: "SendGrid",       category: "saas",           risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /sendgrid\.net/.test(v) },
      { source: "dkim",   test: (v) => /^sendgrid$/.test(v) },
    ],
  },
  { name: "Mailchimp",      category: "saas",           risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /servers\.mcsv\.net|mandrillapp\.com/.test(v) },
      { source: "dkim",   test: (v) => /^mailchimp$/.test(v) },
    ],
  },
  { name: "Mailgun",        category: "saas",           risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /mailgun\.org/.test(v) },
      { source: "mx",     test: (v) => /mailgun\.org/.test(v) },
    ],
  },
  { name: "Brevo",          category: "saas",           risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /sendinblue\.com|brevo\.com/.test(v) },
    ],
  },
  { name: "Klaviyo",        category: "saas",           risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /klaviyo\.com/.test(v) },
      { source: "dkim",   test: (v) => /^k1$/.test(v) },
    ],
  },
  { name: "Stripe",         category: "saas",           risk_level: "medium",
    signals: [
      { source: "csp",    test: (v) => /stripe\.com|js\.stripe\.com/.test(v) },
    ],
  },
  { name: "PayPal",         category: "saas",           risk_level: "medium",
    signals: [
      { source: "csp",    test: (v) => /paypal\.com|paypalobjects\.com/.test(v) },
    ],
  },

  // ── Support ───────────────────────────────────────────────────────────────
  { name: "Zendesk",        category: "support",        risk_level: "medium",
    signals: [
      { source: "spf",    test: (v) => /zendesk\.com/.test(v) },
      { source: "cname",  test: (v) => /zendesk\.com/.test(v) },
      { source: "mx",     test: (v) => /mail\.zendesk\.com/.test(v) },
      { source: "server", test: (v) => /zendesk/.test(v) },
    ],
  },
  { name: "Intercom",       category: "support",        risk_level: "medium",
    signals: [
      { source: "spf",    test: (v) => /intercommail\.com/.test(v) },
      { source: "cname",  test: (v) => /intercom\.io|intercomassets\.com/.test(v) },
    ],
  },
  { name: "Freshdesk",      category: "support",        risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /freshdesk\.com|freshworks\.com/.test(v) },
      { source: "cname",  test: (v) => /freshdesk\.com|freshworks\.com/.test(v) },
    ],
  },

  // ── E-commerce ────────────────────────────────────────────────────────────
  { name: "Shopify",        category: "ecommerce",      risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /myshopify\.com|shops\.myshopify\.com/.test(v) },
      { source: "server", test: (v) => /shopify/.test(v) },
    ],
  },
  { name: "Squarespace",    category: "ecommerce",      risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /squarespace\.com|squarespacedns\.com/.test(v) },
      { source: "ns",     test: (v) => /squarespace\.com/.test(v) },
    ],
  },
  { name: "Webflow",        category: "ecommerce",      risk_level: "medium",
    signals: [
      { source: "cname",  test: (v) => /webflow\.io|proxy\.webflow\.com/.test(v) },
    ],
  },
];

/**
 * detectVendorsFromModules — pure computation, zero network I/O.
 *
 * Reads signal strings already captured in `modules` during the scan phases
 * and matches them against VENDOR_SIGNATURES.
 *
 * Returns:
 *   { detected: bool, vendors: [{name, category, source, evidence, confidence, risk_level}],
 *     source: "module_correlation", error: null }
 *
 * `source`     — primary signal source that triggered the match (first evidence entry)
 * `confidence` — "high"   (≥3 independent sources matched)
 *                "medium" (2 sources matched)
 *                "low"    (1 source matched)
 */
function detectVendorsFromModules(modules) {
  try {
    // ── Collect signal strings from existing module data ───────────────────
    const signals = {
      spf:    [],
      mx:     [],
      ns:     [],
      dkim:   [],
      csp:    [],
      server: [],
      cname:  [],
      tech:   [],
    };

    // SPF record (covers include:/redirect:/exists: tokens)
    const spfRecord = (
      modules?.email_security?.spf?.record ||
      modules?.email_security_intelligence?.spf?.record || ""
    ).toLowerCase();
    if (spfRecord) signals.spf.push(spfRecord);

    // MX records
    for (const mx of (modules?.dns?.mx_records || [])) {
      if (mx?.value) signals.mx.push(mx.value.toLowerCase());
    }

    // Nameservers
    for (const ns of (modules?.dns?.nameservers || [])) {
      if (ns) signals.ns.push(ns.toLowerCase());
    }

    // DKIM selector
    const dkimSel = (
      modules?.email_security?.dkim?.selector ||
      modules?.email_security_intelligence?.dkim?.selector || ""
    ).toLowerCase();
    if (dkimSel) signals.dkim.push(dkimSel);

    // CSP header
    const csp = (modules?.headers?.values?.["content-security-policy"] || "").toLowerCase();
    if (csp) signals.csp.push(csp);

    // Server header (prefer technology_detection — more reliable than raw header)
    const srv = (
      modules?.technology_detection?.server ||
      modules?.headers?.values?.server || ""
    ).toLowerCase();
    if (srv) signals.server.push(srv);

    // CNAMEs from takeover risks
    for (const risk of (modules?.subdomain_takeover?.risks || [])) {
      if (risk?.cname) signals.cname.push(risk.cname.toLowerCase());
    }
    // CNAMEs from asset exposure probe
    for (const asset of (modules?.asset_exposure?.assets || [])) {
      if (asset?.cname) signals.cname.push(asset.cname.toLowerCase());
    }
    // CNAMEs from brute-force results
    for (const item of (modules?.dns_bruteforce?.items || [])) {
      if (item?.cname) signals.cname.push(item.cname.toLowerCase());
    }

    // Technology names (verbatim from technology_detection)
    for (const tech of (modules?.technology_detection?.technologies || [])) {
      if (tech) signals.tech.push(tech);
    }

    // ── Match signatures ──────────────────────────────────────────────────
    const vendors = [];

    for (const sig of VENDOR_SIGNATURES) {
      const evidence = [];

      for (const check of sig.signals) {
        const haystack = signals[check.source] || [];
        for (const val of haystack) {
          if (check.test(val)) {
            const detail = val.length > 120 ? val.slice(0, 120) + "…" : val;
            evidence.push({ source: check.source, detail });
            break;  // one hit per source type per vendor is enough
          }
        }
      }

      if (evidence.length === 0) continue;

      const confidence =
        evidence.length >= 3 ? "high" :
        evidence.length === 2 ? "medium" : "low";

      vendors.push({
        name:       sig.name,
        category:   sig.category,
        source:     evidence[0].source,   // primary signal source
        evidence,
        confidence,
        risk_level: sig.risk_level,
      });
    }

    return {
      detected: vendors.length > 0,
      vendors,
      source:   "module_correlation",
      error:    null,
    };
  } catch (err) {
    return {
      detected: false,
      vendors:  [],
      source:   "module_correlation",
      error:    err?.message ?? "Vendor detection failed",
    };
  }
}

// ── Third-Party Asset Discovery ───────────────────────────────────────────────
// Derives a focused, business-facing view of external SaaS dependencies from the
// already-computed vendor_risk module.  Excludes infrastructure/CDN/cloud/hosting
// vendors (those are not "third-party SaaS" in the customer-facing sense) and
// remaps the remaining vendors to a business-readable category taxonomy:
//
//   email         → Microsoft 365, Google Workspace, Zoho, GoDaddy Email, Proton,
//                   Proofpoint, Mimecast, Barracuda
//   crm           → HubSpot, Salesforce, Marketo
//   support       → Zendesk, Intercom, Freshdesk
//   collaboration → Atlassian
//   marketing     → Mailchimp, SendGrid, Klaviyo, Mailgun, Brevo
//   ecommerce     → Shopify, Squarespace, Webflow
//
// Zero network I/O — wraps detectVendorsFromModules.

/** Maps (vendorName, existingCategory) → third-party category, or null to exclude. */
function remapToThirdPartyCategory(vendorName, existingCategory) {
  // Skip infrastructure-layer vendors — not third-party SaaS
  if (
    existingCategory === "infrastructure" ||
    existingCategory === "cloud"          ||
    existingCategory === "hosting"
  ) return null;

  if (existingCategory === "email_identity") return "email";
  if (existingCategory === "support")        return "support";
  if (existingCategory === "ecommerce")      return "ecommerce";

  // saas category: per-vendor CRM / collaboration / marketing split
  if (existingCategory === "saas") {
    const lookup = {
      "HubSpot":    "crm",
      "Salesforce": "crm",
      "Marketo":    "crm",
      "Atlassian":  "collaboration",
      "SendGrid":   "marketing",
      "Mailchimp":  "marketing",
      "Mailgun":    "marketing",
      "Brevo":      "marketing",
      "Klaviyo":    "marketing",
      // Payment processors — present in vendor_risk but not surfaced as
      // "third-party assets" for the business discovery view.
      "Stripe":     null,
      "PayPal":     null,
    };
    return Object.prototype.hasOwnProperty.call(lookup, vendorName)
      ? lookup[vendorName]
      : null;
  }

  return null;
}

/**
 * runThirdPartyDiscoveryModule — pure computation, zero network I/O.
 *
 * Builds a business-readable third-party SaaS inventory from signals already
 * captured in other modules.  Reuses detectVendorsFromModules internally.
 *
 * Returns:
 *   { detected: bool, total: number,
 *     assets: [{name, category, source, evidence, confidence, risk_level}],
 *     source: "third_party_discovery", error: null }
 */
function runThirdPartyDiscoveryModule(modules) {
  try {
    const vendorResult = detectVendorsFromModules(modules);
    const assets = [];

    for (const v of vendorResult.vendors) {
      const tpCategory = remapToThirdPartyCategory(v.name, v.category);
      if (!tpCategory) continue;

      assets.push({
        name:       v.name,
        category:   tpCategory,
        source:     v.source,
        evidence:   v.evidence,
        confidence: v.confidence,
        risk_level: v.risk_level,
      });
    }

    // Sort: email → crm → collaboration → support → marketing → ecommerce
    const catOrder = { email: 0, crm: 1, collaboration: 2, support: 3, marketing: 4, ecommerce: 5 };
    assets.sort((a, b) => (catOrder[a.category] ?? 9) - (catOrder[b.category] ?? 9));

    return {
      detected: assets.length > 0,
      total:    assets.length,
      assets,
      source:   "third_party_discovery",
      error:    null,
    };
  } catch (err) {
    return {
      detected: false,
      total:    0,
      assets:   [],
      source:   "third_party_discovery",
      error:    err?.message ?? "Third-party discovery failed",
    };
  }
}

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

/**
 * Probe a single host over HTTPS (with HTTP fallback) and return exposure metadata.
 * Never throws — returns a reachable:false record on total failure.
 */
async function probeAsset(host) {
  for (const proto of ["https", "http"]) {
    const url = `${proto}://${host}`;
    let res = null;
    try {
      res = await fetch(url, {
        method:   "GET",
        redirect: "follow",
        signal:   AbortSignal.timeout(8_000),
      });
    } catch {
      // Timeout or network error — try HTTP fallback
      continue;
    }

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

  // Both HTTPS and HTTP unreachable
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

/**
 * Probe all discovered subdomains for HTTP/HTTPS reachability and collect
 * lightweight exposure metadata (status, title, server header, tech stack).
 * Cap at 50 subdomains for v1.
 */
async function runExposureModule(domain, subdomains) {
  const source = "http_probe";

  if (!subdomains || subdomains.length === 0) {
    return { checked: 0, reachable: 0, assets: [], source, error: null };
  }

  const targets = subdomains.slice(0, 50);

  // All probes run in parallel; individual failures return reachable:false records
  const settled = await Promise.allSettled(targets.map((host) => probeAsset(host)));

  const assets = settled
    .filter((r) => r.status === "fulfilled")
    .map((r) => r.value);

  const reachableCount = assets.filter((a) => a.reachable).length;

  return {
    checked:   targets.length,
    reachable: reachableCount,
    assets,
    source,
    error: null,
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
];

/**
 * Detect exposed administrative interfaces from existing HTTP probe results.
 * Pure synchronous — no network I/O.  Called after runExposureModule completes.
 */
function runAdminSurfaceModule(modules) {
  const exposureAssets = modules?.asset_exposure?.assets || [];
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

      let confidence = null;
      if      (titleHit && (hostHit || serverHit)) confidence = "confirmed";
      else if (titleHit)                            confidence = "high";
      else if (hostHit  && serverHit)               confidence = "high";
      else if (hostHit)                             confidence = "medium";

      if (!confidence) continue;

      seen.add(key);
      services.push({
        hostname:   asset.host,
        product:    sig.product,
        category:   sig.category,
        confidence,
        risk_level: sig.risk_level,
      });
    }
  }

  return {
    detected: services.length,
    services,
    source:   "asset_exposure_fingerprint",
    error:    null,
  };
}

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

/** Query NVD for HIGH+ CVEs for a single technology.  Returns [] on any failure. */
async function lookupCvesForTechnology(techName, maxResults = 5) {
  if (!ALLOWED_CVE_TECHNOLOGIES.has(techName)) return [];
  const keyword = CVE_KEYWORD_MAP[techName] || techName;
  const url = new URL("https://services.nvd.nist.gov/rest/json/cves/2.0");
  url.searchParams.set("keywordSearch",   keyword);
  url.searchParams.set("resultsPerPage",  String(maxResults));
  url.searchParams.set("cvssV3Severity",  "HIGH");
  try {
    const res = await safeFetch(url.toString(), {
      headers: { "User-Agent": "CyberMeters-Scanner/1.0" },
      signal:  AbortSignal.timeout(10_000),
    });
    if (!res || res.status !== 200) return [];
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
    return cves;
  } catch {
    return [];
  }
}

/**
 * Run CVE correlation for detected technologies.
 * Ported from cve_lookup.correlate_cves() — limits to 3 technologies,
 * 300ms delay between NVD requests to respect free-tier rate limits,
 * skips exploit-db check (Worker network budget).
 */
async function runCveModule(techModule) {
  if (!techModule || techModule.error) {
    return {
      technologies_checked: [], results: {}, total_cves: 0,
      critical_count: 0, high_count: 0, source: "nvd_api",
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

  // Limit to 3 to bound runtime (NVD free tier: no API key → 5 req/30s)
  const toCheck = [...candidates].slice(0, 3);
  const results = {};
  let totalCves = 0, criticalCount = 0, highCount = 0;

  for (const tech of toCheck) {
    const cves = await lookupCvesForTechnology(tech);
    if (cves.length > 0) {
      results[tech] = cves;
      totalCves   += cves.length;
      for (const c of cves) {
        if (c.severity === "CRITICAL") criticalCount++;
        else if (c.severity === "HIGH") highCount++;
      }
    }
    // Respect NVD free-tier rate limit between requests
    if (toCheck.indexOf(tech) < toCheck.length - 1) {
      await new Promise(r => setTimeout(r, 300));
    }
  }

  return {
    technologies_checked: toCheck,
    results,
    total_cves:     totalCves,
    critical_count: criticalCount,
    high_count:     highCount,
    source:         "nvd_api",
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

/**
 * Fetch CISA KEV catalog and match against detected technologies.
 * Ported from kev_lookup.correlate_kev() with added technology keyword matching.
 */
async function runKevModule(techModule) {
  const detectedTechs = (techModule?.technologies || []).map(t => t.toLowerCase());
  // Include normalised server/x-powered-by values as additional keyword hints
  for (const h of [techModule?.server, techModule?.x_powered_by]) {
    const n = normalizeTechnology(h || "");
    if (n && !detectedTechs.includes(n)) detectedTechs.push(n);
  }

  try {
    const res = await safeFetch(CISA_KEV_URL, { signal: AbortSignal.timeout(15_000) });
    if (!res || res.status !== 200) {
      return { matches: [], checked: 0, matched: 0, source: "cisa_kev", error: "KEV catalog fetch failed" };
    }
    const data = await res.json();
    const vulnerabilities = data.vulnerabilities || [];
    const matches = [];

    for (const vuln of vulnerabilities) {
      const product = (vuln.product        || "").toLowerCase();
      const vendor  = (vuln.vendorProject   || "").toLowerCase();
      // Keyword match: does the KEV product/vendor mention any of our detected techs?
      const techMatch = detectedTechs.some(t => t.length >= 3 && (product.includes(t) || vendor.includes(t)));
      if (!techMatch) continue;
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
      });
    }

    // Most recently added exploited vulns first
    matches.sort((a, b) => (b.date_added || "").localeCompare(a.date_added || ""));

    // Cap at 25 to avoid bloating the report JSON
    const capped = matches.slice(0, 25);

    return {
      matches:    capped,
      checked:    vulnerabilities.length,
      matched:    capped.length,
      source:     "cisa_kev",
    };
  } catch (err) {
    return {
      matches: [], checked: 0, matched: 0,
      source:  "cisa_kev",
      error:   err.message ?? "KEV module failed",
    };
  }
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
  "email_no_dmarc":                     { category: "Brand Risk",      impact: "Without DMARC, email spoofing is trivially exploitable. Creates regulatory exposure under GDPR/FCA where email fraud targeting customers is reportable." },
  "email_weak_dmarc":                   { category: "Brand Risk",      impact: "DMARC in monitoring-only mode provides visibility but no protection. Spoofed emails still reach recipients." },
  "email_no_dkim":                      { category: "Brand Risk",      impact: "Missing DKIM allows attackers to forge email content in transit without detection." },
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
function runRiskModule(findings, modules) {
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
function runRemediationModule(findings, kevModule, takeoverModule) {
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

// ── Intelligence Module: Email Security Intelligence ─────────────────────────
// Ported from email_security/ package:
//   spf.py, dmarc.py, mta_sts.py, tls_rpt.py, starttls.py,
//   scoring.py, intelligence.py, business_impact.py
//
// Design decisions vs. Python originals:
//   • SPF + DMARC + DKIM: reuses runEmailModule DNS results (no extra queries)
//   • MTA-STS: HTTP fetch to https://mta-sts.<domain>/.well-known/mta-sts.txt
//   • TLS-RPT: new DNS TXT query on _smtp._tls.<domain> via existing dnsQuery()
//   • STARTTLS: raw TCP port 25 is unavailable in Worker runtime → structured stub
//   • Score weights preserved exactly from scoring.py v1.1:
//       DMARC=50, SPF=20, DKIM=20, MTA-STS=5, TLS-RPT=5
//   • All failures are swallowed; no scan can fail because of this module

/** Parse a DMARC TXT record string into key→value pairs */
function parseDmarcRecord(record) {
  if (!record) return {};
  const out = {};
  for (const chunk of record.split(";")) {
    const part = chunk.trim();
    if (!part.includes("=")) continue;
    const eq  = part.indexOf("=");
    const key = part.slice(0, eq).trim().toLowerCase();
    const val = part.slice(eq + 1).trim().replace(/^"(.*)"$/, "$1");
    if (["p", "sp", "rua", "ruf", "adkim", "aspf"].includes(key)) {
      out[key] = val;
    } else if (key === "pct") {
      const n = parseInt(val, 10);
      out.pct = isNaN(n) ? 100 : Math.max(0, Math.min(100, n));
    } else {
      out[key] = val;
    }
  }
  return out;
}

/**
 * Enrich existing SPF result (from runEmailModule) with status/score/issue.
 * Ported from spf.py analyze_spf() — status enum: PASS / SOFTFAIL / FAIL / PARTIAL / MISSING.
 */
function enrichSpf(emailMod) {
  const spf    = emailMod?.spf || {};
  const record = spf.record || null;
  if (!spf.present || !record) {
    return { status: "MISSING", record: null, score: 0, issue: "No SPF record found." };
  }
  if (record.includes("+all")) {
    return { status: "FAIL",     record, score: 5,  issue: "SPF uses +all — any mail server is authorised to send on behalf of this domain." };
  }
  if (record.includes("-all")) {
    return { status: "PASS",     record, score: 20, issue: "" };
  }
  if (record.includes("~all")) {
    return { status: "SOFTFAIL", record, score: 15, issue: "SPF uses ~all (softfail) — not fully strict." };
  }
  return   { status: "PARTIAL", record, score: 10, issue: "SPF record present but does not end with -all." };
}

/**
 * Enrich existing DMARC result (from runEmailModule) with full policy breakdown.
 * Ported from dmarc.py DMARCScanner.scan() — parses pct, sp, rua, ruf from raw record.
 * Status enum: FULLY_PROTECTED / PARTIAL_PROTECTED / REPORTING_ONLY / MISSING / ERROR
 */
function enrichDmarc(emailMod) {
  const dmarc     = emailMod?.dmarc || {};
  const rawRecord = dmarc.record || null;

  if (!dmarc.present || !rawRecord) {
    return {
      status: "MISSING", policy: null, subdomain_policy: null, pct: 0,
      rua: null, ruf: null, risk_level: "CRITICAL",
      message: "DMARC record not found. Email spoofing risk is high.",
      record: null,
    };
  }

  const parsed = parseDmarcRecord(rawRecord);
  const policy = parsed.p    || "none";
  const sp     = parsed.sp   || null;
  const pct    = typeof parsed.pct === "number" ? parsed.pct : 100;
  const rua    = parsed.rua  || null;
  const ruf    = parsed.ruf  || null;

  let status, riskLevel, message;
  if (policy === "reject" && pct === 100) {
    status = "FULLY_PROTECTED";   riskLevel = "LOW";
    message = "Full DMARC protection active (p=reject, pct=100).";
  } else if (policy === "reject" && pct < 100) {
    status = "PARTIAL_PROTECTED"; riskLevel = "MEDIUM";
    message = `DMARC protection is partial (p=reject, pct=${pct}).`;
  } else if (policy === "quarantine" && pct === 100) {
    status = "PARTIAL_PROTECTED"; riskLevel = "MEDIUM";
    message = "Quarantine policy is active (pct=100). Move to p=reject for full protection.";
  } else if (policy === "quarantine" && pct < 100) {
    status = "PARTIAL_PROTECTED"; riskLevel = "HIGH";
    message = `Quarantine policy is partial (pct=${pct}).`;
  } else if (policy === "none") {
    status = "REPORTING_ONLY";    riskLevel = "HIGH";
    message = "DMARC is in reporting-only mode (p=none). Enforcement is not active.";
  } else {
    status = "ERROR";             riskLevel = "HIGH";
    message = `Unknown or unparseable DMARC policy: '${policy}'.`;
  }

  return { status, policy, subdomain_policy: sp, pct, rua, ruf, risk_level: riskLevel, message, record: rawRecord };
}

/**
 * Enrich existing DKIM result (from runEmailModule).
 * Status: VERIFIED (selector found) / NOT_VERIFIED (no selector found).
 */
function enrichDkim(emailMod) {
  const dkim = emailMod?.dkim || {};
  if (dkim.present && dkim.selector) {
    return { status: "VERIFIED",     selector: dkim.selector, issue: "" };
  }
  return   { status: "NOT_VERIFIED", selector: null,          issue: "No DKIM record found on common selectors." };
}

/**
 * Fetch and parse MTA-STS policy.
 * Ported from mta_sts.py analyze_mta_sts() — HTTP GET, not DNS.
 */
async function fetchMtaSts(domain) {
  const result = { enabled: false, policy_mode: null, mx_patterns: [], max_age: null, errors: [] };
  try {
    const res = await safeFetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`, {
      signal: AbortSignal.timeout(10_000),
    });
    if (!res || res.status !== 200) return result;
    result.enabled = true;
    const text = await res.text();
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (line.startsWith("mode:")) {
        result.policy_mode = line.split(":", 2)[1]?.trim() || null;
      } else if (line.startsWith("mx:")) {
        const mx = line.split(":", 2)[1]?.trim();
        if (mx) result.mx_patterns.push(mx);
      } else if (line.startsWith("max_age:")) {
        const n = parseInt((line.split(":", 2)[1] || "").trim(), 10);
        if (!isNaN(n)) result.max_age = n;
      }
    }
  } catch (e) {
    result.errors.push(e?.message ?? "MTA-STS fetch failed");
  }
  return result;
}

/**
 * Check TLS-RPT DNS record.
 * Ported from tls_rpt.py analyze_tls_rpt() — queries _smtp._tls.<domain> TXT.
 */
async function checkTlsRpt(domain) {
  const recordName = `_smtp._tls.${domain}`;
  const result = { enabled: false, record_name: recordName, record: null, reporting_uris: [], errors: [] };
  try {
    const res     = await dnsQuery(recordName, "TXT");
    const answers = res?.Answer || [];
    for (const ans of answers) {
      const txt = ans.data || "";
      if (txt.toLowerCase().startsWith("v=tlsrptv1")) {
        result.enabled = true;
        result.record  = txt;
        for (const part of txt.split(";")) {
          const p = part.trim();
          if (p.toLowerCase().startsWith("rua=")) {
            result.reporting_uris = p.slice(p.indexOf("=") + 1)
              .split(",").map(u => u.trim()).filter(Boolean);
          }
        }
        return result;
      }
    }
    if (answers.length > 0) result.errors.push("No valid TLS-RPT record found (missing v=TLSRPTv1).");
    else                    result.errors.push("No TXT record found at " + recordName + ".");
  } catch (e) {
    result.errors.push(e?.message ?? "TLS-RPT DNS query failed");
  }
  return result;
}

/**
 * STARTTLS — cannot open raw TCP sockets from Cloudflare Worker runtime.
 * Returns structured stub preserving starttls.py data model with MX records
 * from the existing DNS module so the data is still useful.
 */
function buildStarttlsStub(dnsModule) {
  const mxRecords = (dnsModule?.mx_records || []).map(r => {
    const raw    = (r.value || "").trim();
    const parts  = raw.split(/\s+/);
    const host   = parts[parts.length - 1].replace(/\.$/, "");
    const prio   = parts.length >= 2 ? parseInt(parts[0], 10) : 0;
    return { priority: isNaN(prio) ? 0 : prio, host };
  });
  return {
    method:                   "not_supported_in_worker_runtime",
    warning:                  "Raw SMTP connections to port 25 cannot be established from Cloudflare Worker runtime. STARTTLS support cannot be tested directly. Use a dedicated server-side probe for full STARTTLS validation.",
    mx_records:               mxRecords,
    starttls_supported_hosts: null,
    starttls_failed_hosts:    null,
    score:                    null,
  };
}

/**
 * Compute weighted email security score.
 * Ported from scoring.py EmailScoringEngine v1.1.
 * Weights: DMARC=50, SPF=20, DKIM=20, MTA-STS=5, TLS-RPT=5 (exact match).
 * DMARC interpolation bands preserved exactly (reject 75-100%, quarantine 37.5-62.5%).
 */
function computeEmailScore(spf, dmarc, dkim, mtaSts, tlsRpt) {
  const W = { spf: 20, dkim: 20, dmarc: 50, mta_sts: 5, tls_rpt: 5 };

  // SPF — mirrors _score_spf()
  let spfScore = 0;
  switch (spf.status) {
    case "PASS":     spfScore = W.spf; break;
    case "SOFTFAIL": spfScore = Math.round(W.spf * 0.75); break;
    case "PARTIAL":  spfScore = Math.round(W.spf * 0.50); break;
    case "FAIL":     spfScore = Math.round(W.spf * 0.25); break;
    // MISSING → 0
  }

  // DKIM — mirrors _score_dkim()
  let dkimScore = 0;
  if (dkim.status === "VERIFIED")     dkimScore = W.dkim;
  else if (dkim.status === "NOT_VERIFIED") dkimScore = Math.round(W.dkim * 0.5);

  // DMARC — mirrors _score_dmarc() with exact fraction bands
  let dmarcScore = 0;
  const dPolicy = dmarc.policy || "none";
  const dPct    = typeof dmarc.pct === "number" ? Math.max(0, Math.min(100, dmarc.pct)) : 100;
  if (dmarc.status === "MISSING") {
    dmarcScore = 0;
  } else if (dmarc.status === "ERROR") {
    dmarcScore = Math.round(W.dmarc * 0.125);                            // 6
  } else if (dPolicy === "reject") {
    // 75%→100% of weight interpolated by pct  (38 .. 50)
    dmarcScore = Math.round(W.dmarc * 0.75 + W.dmarc * 0.25 * (dPct / 100));
  } else if (dPolicy === "quarantine") {
    // 37.5%→62.5% of weight interpolated by pct  (19 .. 31)
    dmarcScore = Math.round(W.dmarc * 0.375 + W.dmarc * 0.25 * (dPct / 100));
  } else {
    // none or unknown — fixed at 25%  (13)
    dmarcScore = Math.round(W.dmarc * 0.25);
  }

  // MTA-STS — mirrors _score_mta_sts()
  let mtaScore = 0;
  if (mtaSts.enabled && mtaSts.policy_mode === "enforce") mtaScore = W.mta_sts;
  else if (mtaSts.enabled)                                mtaScore = Math.round(W.mta_sts * 0.6);

  // TLS-RPT — mirrors _score_tls_rpt()
  const tlsRptScore = tlsRpt.enabled ? W.tls_rpt : 0;

  const total = spfScore + dkimScore + dmarcScore + mtaScore + tlsRptScore;

  let status;
  if (total >= 90)      status = "EXCELLENT";
  else if (total >= 70) status = "GOOD";
  else if (total >= 50) status = "FAIR";
  else if (total >= 30) status = "POOR";
  else                  status = "CRITICAL";

  return { total, spf: spfScore, dkim: dkimScore, dmarc: dmarcScore, mta_sts: mtaScore, tls_rpt: tlsRptScore, status };
}

/**
 * Convert technical results to business impact statements.
 * Ported from business_impact.py BusinessImpactEngine.generate().
 */
function buildEmailBusinessImpacts(spf, dmarc, dkim, mtaSts, tlsRpt) {
  const impacts = [];

  // DMARC
  if (dmarc.status === "MISSING") {
    impacts.push({
      technical:        "DMARC Missing",
      risk_level:       "CRITICAL",
      business_impact:  "Attackers may impersonate your company and send fraudulent emails to customers, suppliers, or staff.",
      recommendation:   "Add a DMARC record and move towards p=reject after validating all legitimate email sources.",
    });
  } else if (dmarc.status === "REPORTING_ONLY") {
    impacts.push({
      technical:        "DMARC Reporting Only",
      risk_level:       "HIGH",
      business_impact:  "Your domain is collecting DMARC reports but is not actively blocking spoofed emails.",
      recommendation:   "Move from p=none to p=quarantine, then to p=reject once email flows are fully validated.",
    });
  } else if (dmarc.status === "PARTIAL_PROTECTED") {
    impacts.push({
      technical:        "DMARC Partial Protection",
      risk_level:       dmarc.risk_level || "MEDIUM",
      business_impact:  "Some spoofed emails may still reach recipients because DMARC is not fully enforced.",
      recommendation:   "Increase DMARC enforcement to p=reject with pct=100 where safe to do so.",
    });
  }

  // DKIM
  if (dkim.status === "NOT_VERIFIED") {
    impacts.push({
      technical:        "DKIM Not Verified",
      risk_level:       "MEDIUM",
      business_impact:  "Email authentication could not be confirmed from common DKIM selectors. This may affect deliverability and receiver trust.",
      recommendation:   "Verify DKIM signing with your email provider and publish the correct DKIM DNS records.",
    });
  }

  // SPF
  if (spf.status === "MISSING") {
    impacts.push({
      technical:        "SPF Missing",
      risk_level:       "HIGH",
      business_impact:  "Mail servers cannot verify which systems are authorised to send email on behalf of your domain, enabling impersonation.",
      recommendation:   "Publish an SPF TXT record listing all authorised sending services and end with -all.",
    });
  } else if (spf.status === "SOFTFAIL") {
    impacts.push({
      technical:        "SPF SoftFail",
      risk_level:       "MEDIUM",
      business_impact:  "Your SPF record uses softfail (~all) which is not fully strict, reducing protection against spoofed email.",
      recommendation:   "Consider changing ~all to -all after confirming all legitimate email sources are listed.",
    });
  } else if (spf.status === "FAIL") {
    impacts.push({
      technical:        "SPF Permissive Policy (+all)",
      risk_level:       "HIGH",
      business_impact:  "Your SPF policy allows any mail server to send email using your domain, providing no meaningful protection.",
      recommendation:   "Remove +all and replace with -all after enumerating all authorised sending IP ranges.",
    });
  }

  // MTA-STS
  if (!mtaSts.enabled) {
    impacts.push({
      technical:        "MTA-STS Missing",
      risk_level:       "LOW",
      business_impact:  "Inbound email transport encryption is not strictly enforced, reducing resilience against TLS downgrade attacks.",
      recommendation:   "Enable MTA-STS after SPF, DKIM, and DMARC are fully deployed and validated.",
    });
  }

  // TLS-RPT
  if (!tlsRpt.enabled) {
    impacts.push({
      technical:        "TLS-RPT Missing",
      risk_level:       "LOW",
      business_impact:  "You will not receive automated reports about email TLS delivery failures or configuration problems.",
      recommendation:   "Add a TLS-RPT DNS TXT record so email delivery security issues are monitored automatically.",
    });
  }

  return impacts;
}

/**
 * Build CyberMeters findings for the email intelligence module.
 * Only the 7 finding types specified in the sprint.  score_impact: 0 on all —
 * deductions are already handled by computeScore (modules.email_security path).
 * These findings live in modules.email_security_intelligence.findings only,
 * NOT in the main findings array, to avoid double-counting.
 */
function buildEmailIntelFindings(spf, dmarc, dkim, mtaSts, tlsRpt) {
  const findings = [];

  if (dmarc.status === "MISSING") {
    findings.push({
      id:             "email_intel_dmarc_missing",
      module:         "email_security_intelligence",
      severity:       "high",
      title:          "DMARC record is missing",
      description:    "No DMARC record was found at _dmarc.<domain>. Without DMARC, your domain can be trivially spoofed to send phishing emails to customers and business partners.",
      recommendation: "Publish a DMARC TXT record. Start with p=none to collect aggregate reports (rua=), then graduate to p=quarantine and p=reject.",
      score_impact:   0,
    });
  } else if (dmarc.status === "REPORTING_ONLY") {
    findings.push({
      id:             "email_intel_dmarc_reporting_only",
      module:         "email_security_intelligence",
      severity:       "medium",
      title:          "DMARC is in monitoring mode only (p=none)",
      description:    "A DMARC record exists but enforcement is disabled (p=none). Spoofed emails purporting to come from this domain will still reach recipients.",
      recommendation: "Review DMARC aggregate reports and migrate to p=quarantine, then p=reject once all email sources are validated.",
      score_impact:   0,
    });
  }

  if (spf.status === "MISSING") {
    findings.push({
      id:             "email_intel_spf_missing",
      module:         "email_security_intelligence",
      severity:       "high",
      title:          "SPF record is missing",
      description:    "No SPF TXT record was found. Receiving mail servers cannot verify which IP addresses are authorised to send email for this domain.",
      recommendation: "Publish an SPF TXT record listing all services that send email for this domain. End with -all to reject unauthorised senders.",
      score_impact:   0,
    });
  } else if (spf.status === "FAIL") {
    findings.push({
      id:             "email_intel_spf_permissive",
      module:         "email_security_intelligence",
      severity:       "high",
      title:          "SPF record uses +all (permits any sender)",
      description:    `The SPF record "${spf.record}" uses +all, meaning any IP address in the world is authorised to send email on behalf of this domain.`,
      recommendation: "Remove +all and replace with -all after listing all legitimate sending sources explicitly.",
      score_impact:   0,
    });
  }

  if (dkim.status === "NOT_VERIFIED") {
    findings.push({
      id:             "email_intel_dkim_not_found",
      module:         "email_security_intelligence",
      severity:       "medium",
      title:          "DKIM signing record not found on common selectors",
      description:    "No DKIM public key record was detected using common selector names. Without DKIM, email content signatures cannot be verified by recipients.",
      recommendation: "Configure DKIM signing with your email service provider and publish the DKIM public key as a TXT record at <selector>._domainkey.<domain>.",
      score_impact:   0,
    });
  }

  if (!mtaSts.enabled) {
    findings.push({
      id:             "email_intel_mta_sts_missing",
      module:         "email_security_intelligence",
      severity:       "low",
      title:          "MTA-STS policy not published",
      description:    "No MTA-STS policy was found at https://mta-sts.<domain>/.well-known/mta-sts.txt. MTA-STS instructs sending servers to require TLS for delivery to this domain.",
      recommendation: "Publish an MTA-STS policy file and a supporting _mta-sts.<domain> DNS TXT record once SPF, DKIM, and DMARC are fully deployed.",
      score_impact:   0,
    });
  }

  if (!tlsRpt.enabled) {
    findings.push({
      id:             "email_intel_tls_rpt_missing",
      module:         "email_security_intelligence",
      severity:       "low",
      title:          "TLS-RPT reporting not configured",
      description:    "No TLS-RPT record was found at _smtp._tls.<domain>. Without TLS-RPT you will not receive automated reports about email TLS delivery failures.",
      recommendation: "Add a TLS-RPT TXT record at _smtp._tls.<domain>: v=TLSRPTv1; rua=mailto:<address>",
      score_impact:   0,
    });
  }

  return findings;
}

/**
 * Main Email Security Intelligence orchestrator.
 * Ported from intelligence.py build_email_security_intelligence().
 *
 * Reuses runEmailModule results for SPF/DMARC/DKIM to avoid redundant DNS queries.
 * Adds MTA-STS (HTTP), TLS-RPT (DNS), STARTTLS stub, weighted score, business impacts.
 *
 * @param {string} domain    — domain under scan
 * @param {object} emailMod  — modules.email_security (from runEmailModule)
 * @param {object} dnsModule — modules.dns (from runDnsModule — supplies MX for STARTTLS stub)
 */
async function runEmailIntelModule(domain, emailMod, dnsModule) {
  // Step 1: Enrich existing results — no extra DNS calls needed
  const spf   = enrichSpf(emailMod);
  const dmarc = enrichDmarc(emailMod);
  const dkim  = enrichDkim(emailMod);

  // Step 2: MTA-STS + TLS-RPT in parallel (both are fast, independent)
  const [mtaStsSettled, tlsRptSettled] = await Promise.allSettled([
    fetchMtaSts(domain),
    checkTlsRpt(domain),
  ]);
  const mtaSts = mtaStsSettled.status === "fulfilled"
    ? mtaStsSettled.value
    : { enabled: false, policy_mode: null, mx_patterns: [], max_age: null, errors: ["MTA-STS fetch failed"] };
  const tlsRpt = tlsRptSettled.status === "fulfilled"
    ? tlsRptSettled.value
    : { enabled: false, record_name: `_smtp._tls.${domain}`, record: null, reporting_uris: [], errors: ["TLS-RPT lookup failed"] };

  // Step 3: STARTTLS stub (raw TCP port 25 not available in Worker)
  const starttls = buildStarttlsStub(dnsModule);

  // Step 4: Weighted email security score (scoring.py weights: DMARC=50,SPF=20,DKIM=20,MTA-STS=5,TLS-RPT=5)
  const scoreResult = computeEmailScore(spf, dmarc, dkim, mtaSts, tlsRpt);

  // Step 5: Business impact statements (business_impact.py)
  const businessImpacts = buildEmailBusinessImpacts(spf, dmarc, dkim, mtaSts, tlsRpt);

  // Step 6: Strengths (intelligence.py pattern)
  const strengths = [];
  if (spf.status === "PASS")               strengths.push("SPF record published with -all enforcement.");
  else if (spf.status === "SOFTFAIL")      strengths.push("SPF record is present (softfail mode).");
  if (dkim.status === "VERIFIED")          strengths.push(`DKIM signing configured (selector: ${dkim.selector}).`);
  if (dmarc.status === "FULLY_PROTECTED")  strengths.push("DMARC fully enforced (p=reject, pct=100).");
  else if (dmarc.status === "PARTIAL_PROTECTED") strengths.push(`DMARC enforcement partially active (${dmarc.policy}, pct=${dmarc.pct}).`);
  if (mtaSts.enabled && mtaSts.policy_mode === "enforce") strengths.push("MTA-STS enabled in enforce mode — inbound TLS delivery is required.");
  else if (mtaSts.enabled)                 strengths.push("MTA-STS policy is published.");
  if (tlsRpt.enabled)                      strengths.push("TLS-RPT configured — email TLS delivery problems will be reported.");
  if (dmarc.rua)                           strengths.push("DMARC aggregate reporting (rua) is configured.");

  // Step 7: Rating and business risk level
  const total = scoreResult.total;
  let rating, businessRisk;
  if (total >= 90)      { rating = "Excellent"; businessRisk = "Low"; }
  else if (total >= 70) { rating = "Good";      businessRisk = "Low"; }
  else if (total >= 50) { rating = "Fair";      businessRisk = "Moderate"; }
  else if (total >= 30) { rating = "Poor";      businessRisk = "High"; }
  else                  { rating = "Critical";  businessRisk = "Critical"; }

  // Step 8: Module-scoped findings (score_impact: 0 — not added to main findings array)
  const findings = buildEmailIntelFindings(spf, dmarc, dkim, mtaSts, tlsRpt);

  return {
    domain,
    spf,
    dkim,
    dmarc,
    mta_sts:              mtaSts,
    tls_rpt:              tlsRpt,
    starttls,
    email_security_score: scoreResult.total,
    email_score_breakdown: {
      spf:      scoreResult.spf,
      dkim:     scoreResult.dkim,
      dmarc:    scoreResult.dmarc,
      mta_sts:  scoreResult.mta_sts,
      tls_rpt:  scoreResult.tls_rpt,
      status:   scoreResult.status,
    },
    rating,
    business_email_risk:  businessRisk,
    strengths,
    findings,
    business_impacts:     businessImpacts,
  };
}

// ── Cyber Metrics Scoring Engine ──────────────────────────────────────────────

function computeScore(modules, domain) {
  let score = 100;
  const findings        = [];
  const recommendations = [];

  function finding(f) {
    score += f.score_impact; // negative number
    findings.push(f);
  }

  // ── DNS ────────────────────────────────────────────────────────────────
  if (!modules.dns?.resolves) {
    finding({
      id:           "dns_no_resolution",
      module:       "dns",
      severity:     "critical",
      title:        "Domain Does Not Resolve",
      description:  `No A or AAAA DNS records found for ${domain}. The domain cannot be reached.`,
      score_impact: -30,
    });
    recommendations.push({
      priority:    1,
      module:      "dns",
      title:       "Fix DNS Configuration",
      description: "Ensure A records are published for your domain pointing to your server's IP address.",
    });
  }

  // ── SSL ────────────────────────────────────────────────────────────────
  if (!modules.ssl?.https_available) {
    finding({
      id:           "ssl_not_available",
      module:       "ssl",
      severity:     "critical",
      title:        "HTTPS Not Available",
      description:  `${domain} does not serve content over HTTPS. All traffic is transmitted unencrypted.`,
      score_impact: -25,
    });
    recommendations.push({
      priority:    1,
      module:      "ssl",
      title:       "Install a TLS Certificate",
      description: "Enable HTTPS using a free certificate from Let's Encrypt via Certbot, or through your hosting provider.",
    });
  } else if (!modules.ssl?.http_redirects_to_https) {
    finding({
      id:           "ssl_no_http_redirect",
      module:       "ssl",
      severity:     "medium",
      title:        "HTTP Does Not Redirect to HTTPS",
      description:  `Plain HTTP (port 80) requests to ${domain} are not redirected to HTTPS, allowing unencrypted access.`,
      score_impact: -5,
    });
    recommendations.push({
      priority:    2,
      module:      "ssl",
      title:       "Enforce HTTPS Redirect",
      description: "Configure your web server or CDN to issue a 301 redirect from http:// to https:// for all requests.",
    });
  }

  // ── Security Headers ───────────────────────────────────────────────────
  if (modules.headers?.accessible) {
    for (const h of SECURITY_HEADERS) {
      if (!modules.headers.values?.[h.name]) {
        finding({
          id:           `header_missing_${h.name.replace(/-/g, "_")}`,
          module:       "headers",
          severity:     h.severity,
          title:        `Missing ${h.label} Header`,
          description:  `The ${h.label} header (${h.name}) was not returned in HTTP responses from ${domain}.`,
          score_impact: h.score_impact,
        });
        recommendations.push({
          priority:    h.severity === "high" ? 2 : 3,
          module:      "headers",
          title:       `Add ${h.label} Header`,
          description: h.recommendation,
        });
      }
    }
  }

  // ── Email Security ─────────────────────────────────────────────────────
  if (!modules.email_security?.dmarc?.present) {
    finding({
      id:           "email_missing_dmarc",
      module:       "email_security",
      severity:     "high",
      title:        "Missing DMARC Policy",
      description:  `No DMARC TXT record found at _dmarc.${domain}. Email spoofing of this domain is not prevented.`,
      score_impact: -15,
    });
    recommendations.push({
      priority:    1,
      module:      "email_security",
      title:       "Implement DMARC",
      description: `Create a TXT record at _dmarc.${domain}: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${domain}`,
    });
  } else if (modules.email_security.dmarc.policy === "none") {
    finding({
      id:           "email_dmarc_policy_none",
      module:       "email_security",
      severity:     "medium",
      title:        "DMARC Policy is Monitor-Only (p=none)",
      description:  `DMARC is configured at _dmarc.${domain} but the policy is p=none — emails are not quarantined or rejected.`,
      score_impact: -5,
    });
    recommendations.push({
      priority:    2,
      module:      "email_security",
      title:       "Strengthen DMARC Policy",
      description: "Change DMARC policy from p=none to p=quarantine or p=reject to actively block spoofed emails.",
    });
  }

  if (!modules.email_security?.spf?.present) {
    finding({
      id:           "email_missing_spf",
      module:       "email_security",
      severity:     "high",
      title:        "Missing SPF Record",
      description:  `No SPF TXT record found for ${domain}. Any mail server can send email claiming to originate from this domain.`,
      score_impact: -10,
    });
    recommendations.push({
      priority:    1,
      module:      "email_security",
      title:       "Add SPF Record",
      description: `Create a TXT record on ${domain}: v=spf1 include:your-mail-provider.com ~all`,
    });
  }

  if (!modules.email_security?.dkim?.present) {
    finding({
      id:           "email_dkim_not_detected",
      module:       "email_security",
      severity:     "medium",
      title:        "DKIM Not Detected",
      description:  `No DKIM public key record found for ${domain} using common selectors. DKIM may use a custom selector or may not be configured.`,
      score_impact: -5,
    });
    recommendations.push({
      priority:    2,
      module:      "email_security",
      title:       "Enable DKIM Signing",
      description: "Configure your email provider to sign outbound mail with DKIM and publish the public key as a TXT record.",
    });
  }

  // ── Subdomains ─────────────────────────────────────────────────────────
  const subMod = modules.subdomains;
  if (subMod && !subMod.error) {
    const sensitiveList = subMod.sensitive || [];

    // One finding + deduction per sensitive subdomain, capped at 4 findings / -20 pts
    const cappedSensitive = sensitiveList.slice(0, 4);
    for (const sub of cappedSensitive) {
      finding({
        id:           `subdomain_sensitive_${sub.replace(/\./g, "_")}`,
        module:       "subdomains",
        severity:     "medium",
        title:        "Potentially Sensitive Subdomain Discovered",
        description:  `The subdomain "${sub}" suggests a development, staging, or administrative asset may be publicly reachable. Verify this asset is intentional and properly secured.`,
        score_impact: -5,
      });
    }
    if (cappedSensitive.length > 0) {
      recommendations.push({
        priority:    2,
        module:      "subdomains",
        title:       "Review Sensitive Subdomains",
        description: `${sensitiveList.length} subdomain${sensitiveList.length !== 1 ? "s" : ""} with names suggesting development or administrative use were found in Certificate Transparency logs. Ensure these are either firewalled, require authentication, or are decommissioned if unused: ${sensitiveList.slice(0, 5).join(", ")}`,
      });
    }

    // Large attack surface
    if (subMod.count > 20) {
      finding({
        id:           "subdomains_large_attack_surface",
        module:       "subdomains",
        severity:     "low",
        title:        "Large Subdomain Attack Surface",
        description:  `${subMod.count} subdomains were found in Certificate Transparency logs for ${domain}. A larger attack surface increases exposure risk — ensure all subdomains are actively maintained.`,
        score_impact: -3,
      });
      recommendations.push({
        priority:    3,
        module:      "subdomains",
        title:       "Audit and Reduce Subdomain Attack Surface",
        description: `Review all ${subMod.count} discovered subdomains. Decommission unused ones and ensure each points to an actively maintained service.`,
      });
    }
  }

  // ── Subdomain Takeover ─────────────────────────────────────────────────
  const takeoverMod = modules.subdomain_takeover;
  if (takeoverMod && !takeoverMod.error && takeoverMod.risks?.length > 0) {
    const riskCount = takeoverMod.risks.length;
    // −15 for a single risk; −25 max for multiple
    const impact = riskCount === 1 ? -15 : -25;
    finding({
      id:           "subdomain_takeover",
      module:       "subdomain_takeover",
      severity:     "high",
      title:        `Subdomain Takeover Risk${riskCount > 1 ? "s" : ""} Detected`,
      description:  `${riskCount} subdomain${riskCount > 1 ? "s" : ""} with dangling CNAME records pointing to unclaimed services ${riskCount > 1 ? "were" : "was"} found: ${takeoverMod.risks.map((r) => r.host).join(", ")}. These may be vulnerable to hijacking by a third party.`,
      score_impact: impact,
    });
    recommendations.push({
      priority:    1,
      module:      "subdomain_takeover",
      title:       "Fix Dangling DNS Records",
      description: `Remove or update the CNAME records for: ${takeoverMod.risks.map((r) => `${r.host} → ${r.cname}`).join("; ")}. Either reclaim the service, point the CNAME to a valid endpoint, or delete the DNS record entirely.`,
    });
  }

  // ── Asset Exposure ─────────────────────────────────────────────────────
  const exposureMod = modules.asset_exposure;
  if (exposureMod && !exposureMod.error && exposureMod.assets?.length > 0) {
    // Only 200-status assets are considered risky; 401/403 are informational
    const ok200 = exposureMod.assets.filter((a) => a.status === 200);

    // Sensitive management / monitoring tools
    const TOOL_RE = /jenkins|grafana|kibana|phpmyadmin|portainer|prometheus|vault\s*ui|rancher/i;
    const toolAssets = ok200.filter(
      (a) => TOOL_RE.test(a.title || "") || (a.tech || []).some((t) => TOOL_RE.test(t))
    );
    if (toolAssets.length > 0) {
      finding({
        id:           "asset_exposure_sensitive_tool",
        module:       "asset_exposure",
        severity:     "high",
        title:        `Sensitive Management Tool${toolAssets.length > 1 ? "s" : ""} Exposed`,
        description:  `${toolAssets.length} management or monitoring tool${toolAssets.length > 1 ? "s are" : " is"} publicly reachable: ${toolAssets.map((a) => a.host).join(", ")}. These provide privileged access and should not be internet-facing.`,
        score_impact: -10,
      });
      recommendations.push({
        priority:    1,
        module:      "asset_exposure",
        title:       "Restrict Access to Management Tools",
        description: `Firewall or VPN-protect the following interfaces and allow only trusted IP ranges: ${toolAssets.map((a) => `${a.host}${a.title ? ` (${a.title})` : ""}`).join(", ")}.`,
      });
    }

    // Administrative / login interfaces (not already caught as tools)
    const ADMIN_HOST_RE  = /\b(admin|cp|cpanel|panel|portal|login|dashboard|manage|control)\b/;
    const ADMIN_TITLE_RE = /\b(login|admin|dashboard|control\s*panel|portal|management|sign[\s-]in)\b/i;
    const adminAssets = ok200.filter(
      (a) =>
        !toolAssets.includes(a) &&
        (ADMIN_HOST_RE.test(a.host) || ADMIN_TITLE_RE.test(a.title || ""))
    );
    if (adminAssets.length > 0) {
      finding({
        id:           "asset_exposure_admin_interface",
        module:       "asset_exposure",
        severity:     "medium",
        title:        `Administrative Interface${adminAssets.length > 1 ? "s" : ""} Publicly Reachable`,
        description:  `${adminAssets.length} administrative or login interface${adminAssets.length > 1 ? "s are" : " is"} publicly accessible: ${adminAssets.map((a) => a.host).join(", ")}. Restrict access to authorised IP ranges or enforce MFA.`,
        score_impact: -8,
      });
      recommendations.push({
        priority:    2,
        module:      "asset_exposure",
        title:       "Restrict Administrative Interfaces",
        description: `Limit the following admin interfaces to trusted IP ranges or protect with a VPN or MFA: ${adminAssets.map((a) => a.host).join(", ")}.`,
      });
    }

    // Development / staging environments
    const DEV_HOST_RE = /\b(dev|develop|development|staging|stage|stg|test|testing|qa|uat|sandbox|alpha|beta|preprod)\b/;
    const devAssets = ok200.filter((a) => DEV_HOST_RE.test(a.host));
    if (devAssets.length > 0) {
      finding({
        id:           "asset_exposure_dev_env",
        module:       "asset_exposure",
        severity:     "medium",
        title:        `Development Environment${devAssets.length > 1 ? "s" : ""} Publicly Reachable`,
        description:  `${devAssets.length} development or staging environment${devAssets.length > 1 ? "s are" : " is"} publicly accessible: ${devAssets.map((a) => a.host).join(", ")}. These often contain debug endpoints, test credentials, or reduced security controls.`,
        score_impact: -5,
      });
      recommendations.push({
        priority:    2,
        module:      "asset_exposure",
        title:       "Restrict Development Environments",
        description: `Development and staging environments should not be publicly accessible. Firewall or add authentication to: ${devAssets.map((a) => a.host).join(", ")}.`,
      });
    }
  }

  // Clamp and classify
  score = Math.max(0, Math.min(100, Math.round(score)));

  const risk_level =
    score >= 90 ? "excellent" :
    score >= 75 ? "good"      :
    score >= 50 ? "moderate"  :
    score >= 25 ? "high"      : "critical";

  // Deduplicate recommendations and sort by priority
  const seen = new Set();
  const uniqueRecs = recommendations.filter((r) => {
    const key = r.title;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  uniqueRecs.sort((a, b) => a.priority - b.priority);

  return { score, risk_level, findings, recommendations: uniqueRecs };
}

// ── Module 8: Historical Change Detection ─────────────────────────────────────

/**
 * Compare the current scan's results against the most recent previous completed
 * scan for the same domain. Requires D1 + R2 access via `env`.
 *
 * Must be called AFTER computeScore so current score and findings are available.
 * Never throws — all errors produce a safe fallback shape.
 */
async function runHistoricalModule(scanId, domain, currentScore, currentFindings, currentModules, env) {
  const source = "previous_scan_comparison";

  // Canonical empty result for any case where comparison is impossible
  const empty = (hasPrev, prevId, prevScore, error) => ({
    has_previous:       hasPrev,
    previous_scan_id:   prevId,
    previous_score:     prevScore,
    current_score:      currentScore,
    score_change:       prevScore != null ? currentScore - prevScore : null,
    new_subdomains:     [],
    removed_subdomains: [],
    new_findings:       [],
    resolved_findings:  [],
    new_takeover_risks: [],
    new_exposed_assets: [],
    source,
    error: error ?? null,
  });

  // Step 1: find the most recent previous completed scan for this domain in D1
  let prevScan;
  try {
    prevScan = await env.cybermeters_db
      .prepare(
        `SELECT id, score FROM scans
         WHERE domain = ? AND status = 'completed' AND id != ?
         ORDER BY created_at DESC LIMIT 1`
      )
      .bind(domain, scanId)
      .first();
  } catch (err) {
    return empty(false, null, null, `D1 query failed: ${err.message}`);
  }

  if (!prevScan) {
    // First completed scan for this domain — nothing to compare against
    return empty(false, null, null, null);
  }

  // Step 2: read previous report from R2
  let prevReport;
  try {
    const obj = await env.cybermeters_reports.get(`reports/${prevScan.id}.json`);
    if (!obj) {
      return empty(true, prevScan.id, prevScan.score ?? null, "Previous report not found in R2");
    }
    prevReport = await obj.json();
  } catch (err) {
    return empty(true, prevScan.id, prevScan.score ?? null, `R2 read failed: ${err.message}`);
  }

  // Resolve previous score — prefer D1 column (written on completion) then R2 field
  const prevScore = prevScan.score != null
    ? prevScan.score
    : (prevReport.cyber_metrics_score ?? null);

  // Step 3: Diff subdomains
  const currSubSet = new Set(currentModules.subdomains?.items || []);
  const prevSubSet = new Set(prevReport.modules?.subdomains?.items || []);
  const newSubdomains     = [...currSubSet].filter((h) => !prevSubSet.has(h));
  const removedSubdomains = [...prevSubSet].filter((h) => !currSubSet.has(h));

  // Step 4: Diff findings by ID
  const currFindingIds = new Set((currentFindings || []).map((f) => f.id));
  const prevFindingIds = new Set((prevReport.findings || []).map((f) => f.id));

  const currFindingMap = Object.fromEntries((currentFindings || []).map((f) => [f.id, f]));
  const prevFindingMap = Object.fromEntries((prevReport.findings || []).map((f) => [f.id, f]));

  const newFindings = [...currFindingIds]
    .filter((id) => !prevFindingIds.has(id))
    .map((id) => {
      const f = currFindingMap[id];
      return { id: f.id, module: f.module, severity: f.severity, title: f.title };
    });

  const resolvedFindings = [...prevFindingIds]
    .filter((id) => !currFindingIds.has(id))
    .map((id) => {
      const f = prevFindingMap[id];
      return { id: f.id, module: f.module, severity: f.severity, title: f.title };
    });

  // Step 5: Diff takeover risks by host
  const prevTakeoverHosts = new Set(
    (prevReport.modules?.subdomain_takeover?.risks || []).map((r) => r.host)
  );
  const newTakeoverRisks = (currentModules.subdomain_takeover?.risks || [])
    .filter((r) => !prevTakeoverHosts.has(r.host))
    .map(({ host, service, cname, severity }) => ({ host, service, cname, severity }));

  // Step 6: Diff reachable exposed assets by host
  const prevExposedHosts = new Set(
    (prevReport.modules?.asset_exposure?.assets || [])
      .filter((a) => a.reachable)
      .map((a) => a.host)
  );
  const newExposedAssets = (currentModules.asset_exposure?.assets || [])
    .filter((a) => a.reachable && !prevExposedHosts.has(a.host))
    .map(({ host, url, status, title, server, tech }) => ({ host, url, status, title, server, tech }));

  return {
    has_previous:       true,
    previous_scan_id:   prevScan.id,
    previous_score:     prevScore,
    current_score:      currentScore,
    score_change:       prevScore != null ? currentScore - prevScore : null,
    new_subdomains:     newSubdomains,
    removed_subdomains: removedSubdomains,
    new_findings:       newFindings,
    resolved_findings:  resolvedFindings,
    new_takeover_risks: newTakeoverRisks,
    new_exposed_assets: newExposedAssets,
    source,
    error: null,
  };
}

// ── normalizeHostname ─────────────────────────────────────────────────────────
// Returns a bare, lowercase hostname with no trailing dot.
// Accepts either a plain hostname ("api.example.com") or a full URL
// ("https://api.example.com/path") and extracts just the host part.
function normalizeHostname(value) {
  if (!value) return null;
  const s = String(value).trim();
  if (!s) return null;
  let host = s;
  if (/^https?:\/\//i.test(s)) {
    try {
      host = new URL(s).hostname;
    } catch {
      return null;
    }
  }
  host = host.toLowerCase().replace(/\.$/, "");
  // Must contain at least one dot and no spaces to be a valid hostname
  if (!host || host.includes(" ") || !host.includes(".")) return null;
  return host;
}

// ── Asset Inventory Upsert ────────────────────────────────────────────────────
// Persists cross-scan asset state into workspace_assets + asset_events.
// Called AFTER the scan completion status is written to D1 so a upsert failure
// can never leave a scan stuck in "running".
//
// One domain can belong to multiple workspaces — we upsert into each.
// Uses D1 batch() to minimise round-trips.

async function upsertAssetInventory(scanId, domainId, domain, modules, env) {
  const now = new Date().toISOString();

  // ── Collect all discovered hostnames from this scan ───────────────────────
  const wildcardDns = modules?.subdomains?.wildcard_dns === true;

  const allAssets = [];

  // Root domain is always an asset, even if CT/bruteforce finds nothing.
  // This prevents inventory from staying empty for domains with no discovered subdomains.
  const _rootHost = normalizeHostname(domain);
  if (_rootHost) allAssets.push({
    hostname:   _rootHost,
    asset_type: "root_domain",
    source:     "scan_root",
    wildcard:   0,
    risk_level: null,
    cloud:      null,
  });

  // CT-discovered subdomains
  for (const hostname of modules?.subdomains?.items || []) {
    const h = normalizeHostname(hostname);
    if (!h) continue;
    allAssets.push({
      hostname:   h,
      asset_type: "subdomain",
      source:     "certificate_transparency",
      wildcard:   wildcardDns ? 1 : 0,
      risk_level: null,
      cloud:      null,
    });
  }

  // DNS brute-force
  for (const item of modules?.dns_bruteforce?.items || []) {
    const h = normalizeHostname(item.hostname);
    if (!h) continue;
    allAssets.push({
      hostname:     h,
      asset_type:   "subdomain",
      source:       "dns_bruteforce",
      wildcard:     0,
      risk_level:   null,
      cloud:        null,
      ip_addresses: JSON.stringify(item.ip_addresses || []),
    });
  }

  // Cloud storage findings
  for (const finding of modules?.cloud_storage_discovery?.findings || []) {
    const h = normalizeHostname(finding.asset);
    if (!h) continue;
    const existing = allAssets.find((a) => a.hostname === h);
    if (existing) {
      existing.cloud      = finding.provider;
      existing.risk_level = finding.risk_level;
    } else {
      allAssets.push({
        hostname:   h,
        asset_type: "cloud_storage",
        source:     "hostname_pattern_match",
        wildcard:   0,
        cloud:      finding.provider,
        risk_level: finding.risk_level,
      });
    }
  }

  // Exposure-probed assets
  for (const asset of modules?.asset_exposure?.assets || []) {
    const h = normalizeHostname(asset.hostname || asset.url);
    if (!h) continue;
    const existing = allAssets.find((a) => a.hostname === h);
    if (existing) {
      existing.ip_addresses = existing.ip_addresses ?? JSON.stringify(asset.ip ? [asset.ip] : []);
      existing.redirect_to  = asset.redirect_to ?? null;
    } else {
      allAssets.push({
        hostname:     h,
        asset_type:   "exposed_service",
        source:       "exposure_probe",
        wildcard:     0,
        redirect_to:  asset.redirect_to ?? null,
        risk_level:   null,
        cloud:        null,
      });
    }
  }

  // ── Deduplicate allAssets by hostname ────────────────────────────────────
  // CT and DNS brute-force can both discover the same hostname.  Duplicate
  // entries would produce two INSERTs with the same (workspace_id, hostname),
  // violating the UNIQUE constraint and failing the entire D1 batch silently.
  // Keep first occurrence; merge extra fields (ip_addresses, cloud, risk_level)
  // from any subsequent occurrence of the same hostname.
  const assetMap = new Map();
  for (const asset of allAssets) {
    const existing = assetMap.get(asset.hostname);
    if (!existing) {
      assetMap.set(asset.hostname, { ...asset });
    } else {
      // Merge non-null fields from duplicate entry
      if (asset.ip_addresses != null) existing.ip_addresses = asset.ip_addresses;
      if (asset.cloud       != null) existing.cloud         = asset.cloud;
      if (asset.risk_level  != null) existing.risk_level    = asset.risk_level;
      if (asset.redirect_to != null) existing.redirect_to   = asset.redirect_to;
    }
  }
  const deduplicatedAssets = [...assetMap.values()];

  // Takeover risk annotations (applied to deduplicated list)
  const takeoverRiskMap = new Map(
    (modules?.subdomain_takeover?.risks || []).map((r) => [normalizeHostname(r.host), r])
  );
  for (const asset of deduplicatedAssets) {
    const risk = takeoverRiskMap.get(asset.hostname);
    if (risk) asset.risk_level = risk.severity ?? "high";
  }

  // Replace allAssets with deduplicated list from here on
  const finalAssets = deduplicatedAssets;

  console.log("[inventory]", JSON.stringify({
    domain,
    assets_found:  finalAssets.length,
    wildcard_dns:  wildcardDns,
  }));

  if (finalAssets.length === 0) return;

  // ── Look up workspaces linked to this domain ──────────────────────────────
  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare(`SELECT workspace_id FROM workspace_domains WHERE domain_id = ?`)
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch (e) {
    console.error("[inventory] workspace lookup failed:", e?.message);
    return;
  }

  console.log("[inventory]", JSON.stringify({
    domain,
    workspaces: wsRows.length,
    domain_id:  domainId,
  }));

  if (wsRows.length === 0) return;

  // ── For each workspace: diff against existing assets, batch-upsert ────────
  for (const { workspace_id } of wsRows) {
    try {
      // Fetch all existing assets for this workspace+domain in one query
      const existingResult = await env.cybermeters_db
        .prepare(
          `SELECT id, hostname, status FROM workspace_assets
           WHERE workspace_id = ? AND domain_id = ?`
        )
        .bind(workspace_id, domainId)
        .all();

      const existingMap = new Map(
        (existingResult.results || []).map((r) => [r.hostname, r])
      );

      const currentHostnames = new Set(finalAssets.map((a) => a.hostname));
      const stmts = [];

      // Upsert each discovered asset
      for (const asset of finalAssets) {
        const existing = existingMap.get(asset.hostname);
        if (!existing) {
          // New asset — INSERT OR IGNORE guards against any residual duplicates
          const assetId = createId("asset");
          stmts.push(
            env.cybermeters_db
              .prepare(
                `INSERT OR IGNORE INTO workspace_assets
                   (id, workspace_id, domain_id, hostname, asset_type, source,
                    first_seen, last_seen, status, wildcard_dns,
                    ip_addresses, cname, redirect_to, cloud_provider,
                    risk_level, metadata_json, created_at, updated_at)
                 VALUES (?,?,?,?,?,?,?,?,'active',?,?,?,?,?,?,?,?,?)`
              )
              .bind(
                assetId, workspace_id, domainId, asset.hostname,
                asset.asset_type ?? "subdomain",
                asset.source ?? "certificate_transparency",
                now, now,
                asset.wildcard ?? 0,
                asset.ip_addresses ?? null,
                asset.cname ?? null,
                asset.redirect_to ?? null,
                asset.cloud ?? null,
                asset.risk_level ?? null,
                null,    // metadata_json
                now, now
              )
          );
          stmts.push(
            env.cybermeters_db
              .prepare(
                `INSERT INTO asset_events
                   (id, workspace_id, domain_id, asset_id, scan_id,
                    event_type, hostname, severity, description, created_at)
                 VALUES (?,?,?,?,?,'new_asset_discovered',?,'info',?,?)`
              )
              .bind(
                createId("evt"), workspace_id, domainId, assetId, scanId,
                asset.hostname,
                `New asset discovered: ${asset.hostname} (${asset.source ?? "ct"})`,
                now
              )
          );
        } else {
          // Existing asset — update last_seen + status
          stmts.push(
            env.cybermeters_db
              .prepare(
                `UPDATE workspace_assets
                 SET last_seen = ?, status = 'active',
                     risk_level = COALESCE(?, risk_level),
                     cloud_provider = COALESCE(?, cloud_provider),
                     redirect_to = COALESCE(?, redirect_to),
                     updated_at = ?
                 WHERE workspace_id = ? AND hostname = ?`
              )
              .bind(
                now,
                asset.risk_level ?? null,
                asset.cloud ?? null,
                asset.redirect_to ?? null,
                now,
                workspace_id, asset.hostname
              )
          );
          // Asset reappeared after being inactive
          if (existing.status === "inactive") {
            stmts.push(
              env.cybermeters_db
                .prepare(
                  `INSERT INTO asset_events
                     (id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at)
                   VALUES (?,?,?,?,?,'asset_reappeared',?,'medium',?,?)`
                )
                .bind(
                  createId("evt"), workspace_id, domainId,
                  existing.id, scanId,
                  asset.hostname,
                  `Asset reappeared after being absent: ${asset.hostname}`,
                  now
                )
            );
          }
        }
      }

      // Mark assets from a previous scan that are no longer visible
      for (const [hostname, existing] of existingMap) {
        if (!currentHostnames.has(hostname) && existing.status === "active") {
          stmts.push(
            env.cybermeters_db
              .prepare(
                `UPDATE workspace_assets
                 SET status = 'inactive', updated_at = ?
                 WHERE workspace_id = ? AND hostname = ?`
              )
              .bind(now, workspace_id, hostname)
          );
          stmts.push(
            env.cybermeters_db
              .prepare(
                `INSERT INTO asset_events
                   (id, workspace_id, domain_id, asset_id, scan_id,
                    event_type, hostname, severity, description, created_at)
                 VALUES (?,?,?,?,?,'asset_no_longer_seen',?,'low',?,?)`
              )
              .bind(
                createId("evt"), workspace_id, domainId,
                existing.id, scanId,
                hostname,
                `Asset no longer seen in latest scan: ${hostname}`,
                now
              )
          );
        }
      }

      // Takeover risk events
      for (const risk of modules?.subdomain_takeover?.risks || []) {
        const existingAsset = existingMap.get(risk.host) ?? { id: null };
        stmts.push(
          env.cybermeters_db
            .prepare(
              `INSERT INTO asset_events
                 (id, workspace_id, domain_id, asset_id, scan_id,
                  event_type, hostname, severity, description, created_at)
               VALUES (?,?,?,?,?,'takeover_risk_detected',?,'high',?,?)`
            )
            .bind(
              createId("evt"), workspace_id, domainId,
              existingAsset.id ?? null, scanId,
              risk.host,
              `Subdomain takeover risk: ${risk.host} → ${risk.cname} (${risk.provider ?? risk.service})`,
              now
            )
        );
      }

      // Wildcard DNS event (once per scan per workspace, if detected)
      if (wildcardDns) {
        stmts.push(
          env.cybermeters_db
            .prepare(
              `INSERT INTO asset_events
                 (id, workspace_id, domain_id, asset_id, scan_id,
                  event_type, hostname, severity, description, created_at)
               VALUES (?,?,?,null,?,'wildcard_dns_detected',?,'info',?,?)`
            )
            .bind(
              createId("evt"), workspace_id, domainId,
              scanId, domain,
              `Wildcard DNS detected for ${domain} — CT results may include false positives`,
              now
            )
        );
      }

      // Execute all statements in a single D1 batch round-trip
      console.log("[inventory]", JSON.stringify({
        domain, workspace_id, stmts: stmts.length,
      }));

      if (stmts.length > 0) {
        try {
          await env.cybermeters_db.batch(stmts);
        } catch (batchErr) {
          // Surface the real error so it appears in Cloudflare Workers logs
          console.error("[inventory] D1 batch failed:", batchErr?.message, batchErr?.cause);
          throw batchErr;   // re-throw so the outer per-workspace catch sees it
        }
      }

    } catch (e) {
      // Per-workspace failure is non-fatal — continue with next workspace
      console.error("[inventory] workspace upsert error for", workspace_id, ":", e?.message);
    }
  }
}

// ── Scan Budget Tracking ──────────────────────────────────────────────────────
// Pure computation — estimates subrequest usage per module and warns when
// approaching the Cloudflare Worker free-plan 50-subrequest limit.

function computeScanBudget(bruteforceChecked) {
  // Approximate subrequest counts based on known module profiles:
  //   dns             — 5  (A + AAAA + NS + MX + CAA via DoH)
  //   ssl             — 4  (HTTPS + www-HTTPS fallback + HTTP + crt.sh)
  //   headers         — 2  (HTTPS + HTTP fallback)
  //   email_security  — 15 (TXT root + _dmarc + 13 DKIM selector probes)
  //   ct_discovery    — 4  (wildcard A + AAAA DoH + crt.sh + CertSpotter)
  //   dns_bruteforce  — actual checked count (capped at BRUTEFORCE_MAX_NAMES)
  //   asset_exposure  — 0  (variable; counted from HTTP probe results, not tracked here)
  //   admin_surface   — 0  (pure computation, zero I/O)
  //   cve_kev         — 2  (NVD 0-3 + CISA KEV 1; use 2 as conservative estimate)
  //   domain_security_enrichment — 0 (pure computation, zero I/O)
  const moduleEstimates = {
    dns:                        5,
    ssl:                        4,
    headers:                    2,
    email_security:             15,
    ct_discovery:               4,
    dns_bruteforce:             typeof bruteforceChecked === "number" ? bruteforceChecked : BRUTEFORCE_MAX_NAMES,
    asset_exposure:             0,
    admin_surface:              0,
    cve_kev:                    2,
    domain_security_enrichment: 0,
  };

  const total = Object.values(moduleEstimates).reduce((sum, n) => sum + n, 0);
  const warnings = [];
  if (total > 45) {
    warnings.push("Scan is close to Cloudflare Worker subrequest limit.");
  }

  return {
    estimated_subrequests_total: total,
    modules: moduleEstimates,
    warnings,
  };
}

// ── Main Scan Engine (runs via ctx.waitUntil) ─────────────────────────────────

async function runScanEngine(scanId, domainId, domain, env) {
  const startedAt = new Date().toISOString();

  try {
    // Mark scan as running in D1
    await env.cybermeters_db
      .prepare(`UPDATE scans SET status = 'running' WHERE id = ?`)
      .bind(scanId)
      .run();

    // Phase 1: Run the 8 core modules in parallel.
    // • Subdomain discovery: 15s hard cap (parallel crt.sh 12s + CertSpotter 8s + wildcard DNS)
    // • DNS brute-force: 8s hard cap, runs concurrently — results merged after phase completes
    // • WHOIS uses RDAP (HTTP+JSON) — 12s timeout, fully non-blocking.
    const [dnsSettled, sslSettled, headersSettled, emailSettled, subdomainsSettled, techSettled, whoisSettled, bruteforceSettled] =
      await Promise.allSettled([
        runDnsModule(domain),
        runSslModule(domain),
        runHeadersModule(domain),
        runEmailModule(domain),
        runSubdomainsModule(domain),
        runTechModule(domain),
        runWhoisModule(domain),
        runBruteforceModule(domain),
      ]);

    const subdomainsResult = subdomainsSettled.status === "fulfilled"
      ? subdomainsSettled.value
      : { count: 0, items: [], sensitive: [], source: "certificate_transparency_multi_source",
          sources: { crt_sh: { count: 0, error: "module rejected" }, certspotter: { count: 0, error: "module rejected" } },
          wildcard_dns: false, wildcard_test_host: null, wildcard_warning: null,
          error: subdomainsSettled.reason?.message ?? "Subdomain module failed" };

    const bruteforceResult = bruteforceSettled.status === "fulfilled"
      ? bruteforceSettled.value
      : { checked: 0, found: 0, items: [], source: "dns_bruteforce",
          error: bruteforceSettled.reason?.message ?? "Brute-force module failed" };

    // Merge brute-force finds into the subdomain item list (deduplicated).
    // Takeover and exposure modules receive the enriched list.
    const ctHostnames = new Set(subdomainsResult.items);
    const bruteNewItems = (bruteforceResult.items || [])
      .map((i) => i.hostname)
      .filter((h) => h && !ctHostnames.has(h));
    const mergedSubdomainItems = [...subdomainsResult.items, ...bruteNewItems];

    // Phase 2: Takeover detection — uses merged (CT + brute-force) subdomain list.
    let takeoverResult;
    try {
      takeoverResult = await runTakeoverModule(domain, mergedSubdomainItems);
    } catch (err) {
      takeoverResult = { checked: 0, potential_risks: 0, risks: [], source: "subdomain_cname_fingerprint", error: err.message };
    }

    // Phase 3: Asset exposure probing — HTTP/HTTPS reachability + metadata.
    // Runs after takeover (sequential) to bound total concurrent I/O.
    let assetExposureResult;
    try {
      assetExposureResult = await runExposureModule(domain, mergedSubdomainItems);
    } catch (err) {
      assetExposureResult = {
        checked:   0,
        reachable: 0,
        assets:    [],
        source:    "http_probe",
        error:     err.message ?? "Asset exposure module failed",
      };
    }

    const modules = {
      dns: dnsSettled.status === "fulfilled"
        ? dnsSettled.value
        : { error: dnsSettled.reason?.message ?? "DNS module failed" },

      ssl: sslSettled.status === "fulfilled"
        ? sslSettled.value
        : { error: sslSettled.reason?.message ?? "SSL module failed" },

      headers: headersSettled.status === "fulfilled"
        ? headersSettled.value
        : { error: headersSettled.reason?.message ?? "Headers module failed" },

      email_security: emailSettled.status === "fulfilled"
        ? emailSettled.value
        : { error: emailSettled.reason?.message ?? "Email module failed" },

      subdomains: subdomainsResult,

      subdomain_takeover: takeoverResult,

      asset_exposure: assetExposureResult,

      technology_detection: techSettled.status === "fulfilled"
        ? techSettled.value
        : { error: techSettled.reason?.message ?? "Technology module failed" },

      whois_intelligence: whoisSettled.status === "fulfilled"
        ? whoisSettled.value
        : { error: whoisSettled.reason?.message ?? "WHOIS module failed" },

      dns_bruteforce: bruteforceResult,
    };

    // Compute Cyber Metrics Score
    const { score, risk_level, findings, recommendations } = computeScore(modules, domain);

    // Append technology detection info-findings (score_impact: 0 — informational only)
    const techMod = modules.technology_detection;
    if (techMod && !techMod.error && Array.isArray(techMod.info_findings)) {
      for (const f of techMod.info_findings) {
        findings.push({
          module:      "technology_detection",
          ...f,
        });
      }
    }

    // Append admin surface detection findings (score_impact: 0 — no scoring changes in Phase 1)
    const adminMod = modules.admin_surface_detection;
    if (adminMod && !adminMod.error && adminMod.detected > 0) {
      const criticalSvcs = adminMod.services.filter((s) => s.risk_level === "critical");
      const highSvcs     = adminMod.services.filter((s) => s.risk_level === "high");
      const mediumSvcs   = adminMod.services.filter((s) => s.risk_level === "medium");

      if (criticalSvcs.length > 0) {
        findings.push({
          id:           "admin_surface_critical",
          module:       "admin_surface_detection",
          severity:     "critical",
          score_impact: 0,
          title:        `Critical Admin Interface${criticalSvcs.length > 1 ? "s" : ""} Exposed`,
          description:  `${criticalSvcs.length} critical administrative interface${criticalSvcs.length > 1 ? "s are" : " is"} publicly reachable: ${criticalSvcs.map((s) => `${s.hostname} (${s.product})`).join(", ")}. These provide direct access to sensitive systems and should never be internet-facing.`,
          recommendation: `Immediately restrict access to: ${criticalSvcs.map((s) => s.hostname).join(", ")}. Place behind VPN or allowlist-only firewall rules.`,
        });
      }
      if (highSvcs.length > 0) {
        findings.push({
          id:           "admin_surface_high",
          module:       "admin_surface_detection",
          severity:     "high",
          score_impact: 0,
          title:        `High-Risk Admin Interface${highSvcs.length > 1 ? "s" : ""} Exposed`,
          description:  `${highSvcs.length} high-risk administrative interface${highSvcs.length > 1 ? "s are" : " is"} publicly reachable: ${highSvcs.map((s) => `${s.hostname} (${s.product})`).join(", ")}.`,
          recommendation: `Restrict access to: ${highSvcs.map((s) => s.hostname).join(", ")} via VPN or IP allowlist.`,
        });
      }
      if (mediumSvcs.length > 0) {
        findings.push({
          id:           "admin_surface_medium",
          module:       "admin_surface_detection",
          severity:     "medium",
          score_impact: 0,
          title:        `Collaboration Tool${mediumSvcs.length > 1 ? "s" : ""} Publicly Accessible`,
          description:  `${mediumSvcs.length} collaboration or source-control service${mediumSvcs.length > 1 ? "s are" : " is"} publicly accessible: ${mediumSvcs.map((s) => `${s.hostname} (${s.product})`).join(", ")}. Verify these require authentication and enforce MFA.`,
          recommendation: `Ensure ${mediumSvcs.map((s) => s.hostname).join(", ")} enforce MFA and are patched to the latest version.`,
        });
      }
    }

    // Append domain security enrichment findings (score_impact: 0 — no major scoring changes)
    const enrichMod = modules.domain_security_enrichment;
    if (enrichMod && !enrichMod.error) {
      // ── CAA ──────────────────────────────────────────────────────────────
      if (enrichMod.caa && !enrichMod.caa.error) {
        if (!enrichMod.caa.present) {
          findings.push({
            id:             "dse_missing_caa",
            module:         "domain_security_enrichment",
            severity:       "medium",
            score_impact:   0,
            title:          "No CAA DNS Record",
            description:    "This domain has no CAA (Certification Authority Authorization) record. Without CAA, any publicly trusted CA can issue TLS certificates for this domain, increasing the risk of mis-issuance.",
            recommendation: `Add a DNS CAA record to restrict which CAs may issue certificates. Example: \`0 issue "letsencrypt.org"\`, \`0 issue "pki.goog"\`. Add \`0 iodef "mailto:security@${domain}"\` to receive mis-issuance reports.`,
          });
        } else if (enrichMod.caa.issuers.length === 0 && enrichMod.caa.records.length > 0) {
          findings.push({
            id:             "dse_caa_no_issuers",
            module:         "domain_security_enrichment",
            severity:       "low",
            score_impact:   0,
            title:          "CAA Record Present But No Issuers Listed",
            description:    `A CAA record exists but contains no \`issue\` or \`issuewild\` tags, which effectively blocks all certificate issuance for this domain.`,
            recommendation: `Add at least one \`0 issue "<ca>"\` tag to allow your CA to issue certificates.`,
          });
        }
      }

      // ── HSTS ─────────────────────────────────────────────────────────────
      if (enrichMod.hsts && !enrichMod.hsts.error && enrichMod.hsts.present) {
        const h = enrichMod.hsts;
        if (h.max_age !== null && h.max_age < 31_536_000) {
          findings.push({
            id:             "dse_hsts_short_maxage",
            module:         "domain_security_enrichment",
            severity:       "low",
            score_impact:   0,
            title:          "HSTS max-age Below Recommended Minimum",
            description:    `The HSTS header specifies max-age=${h.max_age} seconds (${Math.round(h.max_age / 86400)} days). The recommended minimum is 31,536,000 (365 days) to qualify for the HSTS preload list and ensure robust protection.`,
            recommendation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
          });
        }
        if (!h.preload_eligible && h.present) {
          const missing = [];
          if (!h.include_subdomains)   missing.push("includeSubDomains");
          if (!h.preload_directive)    missing.push("preload directive");
          if (h.max_age === null || h.max_age < 31_536_000) missing.push("max-age ≥ 31536000");
          if (missing.length > 0) {
            findings.push({
              id:             "dse_hsts_not_preload_eligible",
              module:         "domain_security_enrichment",
              severity:       "low",
              score_impact:   0,
              title:          "HSTS Not Eligible for Preload List",
              description:    `This domain's HSTS configuration is missing the following preload requirements: ${missing.join(", ")}. Preloaded HSTS protects users on their very first visit before any HSTS header is seen.`,
              recommendation: "Update to: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload — then submit to https://hstspreload.org",
            });
          }
        }
      }

      // ── Cookies ───────────────────────────────────────────────────────────
      if (enrichMod.cookies && !enrichMod.cookies.error && enrichMod.cookies.found > 0) {
        const c = enrichMod.cookies;
        if (c.insecure_count > 0) {
          findings.push({
            id:             "dse_cookie_no_secure",
            module:         "domain_security_enrichment",
            severity:       "high",
            score_impact:   0,
            title:          `${c.insecure_count} Cookie${c.insecure_count > 1 ? "s" : ""} Missing Secure Flag`,
            description:    `${c.insecure_count} of ${c.found} cookie${c.found > 1 ? "s" : ""} set by ${domain} lack the Secure flag. These cookies may be transmitted over unencrypted HTTP connections, exposing session tokens to network interception.`,
            recommendation: "Add the Secure attribute to all session and authentication cookies: Set-Cookie: name=value; Secure; HttpOnly; SameSite=Strict",
          });
        }
        if (c.no_httponly > 0) {
          findings.push({
            id:             "dse_cookie_no_httponly",
            module:         "domain_security_enrichment",
            severity:       "medium",
            score_impact:   0,
            title:          `${c.no_httponly} Cookie${c.no_httponly > 1 ? "s" : ""} Missing HttpOnly Flag`,
            description:    `${c.no_httponly} cookie${c.no_httponly > 1 ? "s are" : " is"} accessible via JavaScript. If an XSS vulnerability exists, these cookies can be exfiltrated by injected scripts.`,
            recommendation: "Add HttpOnly to all cookies that do not need to be accessed by JavaScript (session tokens, auth cookies).",
          });
        }
        if (c.no_samesite > 0) {
          findings.push({
            id:             "dse_cookie_no_samesite",
            module:         "domain_security_enrichment",
            severity:       "low",
            score_impact:   0,
            title:          `${c.no_samesite} Cookie${c.no_samesite > 1 ? "s" : ""} Missing SameSite Attribute`,
            description:    `${c.no_samesite} cookie${c.no_samesite > 1 ? "s do" : " does"} not specify a SameSite attribute. Without SameSite, browsers may send these cookies in cross-site requests, enabling CSRF attacks.`,
            recommendation: "Set SameSite=Strict or SameSite=Lax on all cookies. Use SameSite=None; Secure only for cookies that must be sent in cross-site contexts.",
          });
        }
      }
    }

    // Phase 4: Historical Change Detection — runs after computeScore so current
    // score and findings are known. Mutates modules in place before R2 write.
    try {
      modules.historical_changes = await runHistoricalModule(
        scanId, domain, score, findings, modules, env
      );
    } catch (err) {
      modules.historical_changes = {
        has_previous:       false,
        previous_scan_id:   null,
        previous_score:     null,
        current_score:      score,
        score_change:       null,
        new_subdomains:     [],
        removed_subdomains: [],
        new_findings:       [],
        resolved_findings:  [],
        new_takeover_risks: [],
        new_exposed_assets: [],
        source:             "previous_scan_comparison",
        error:              err.message ?? "Historical module failed",
      };
    }

    // Phase 5: CVE + KEV + Email Intelligence (all parallel)
    // • CVE: queries NVD for high/critical CVEs per detected technology
    // • KEV: fetches CISA catalog and matches by technology keyword
    // • EmailIntel: enriches SPF/DMARC/DKIM, adds MTA-STS + TLS-RPT, computes email score
    const [cveSettled, kevSettled, emailIntelSettled] = await Promise.allSettled([
      runCveModule(modules.technology_detection),
      runKevModule(modules.technology_detection),
      runEmailIntelModule(domain, modules.email_security, modules.dns),
    ]);

    modules.cve_intelligence = cveSettled.status === "fulfilled"
      ? cveSettled.value
      : { technologies_checked: [], results: {}, total_cves: 0, critical_count: 0, high_count: 0,
          source: "nvd_api", error: cveSettled.reason?.message ?? "CVE module failed" };

    modules.known_exploited_vulnerabilities = kevSettled.status === "fulfilled"
      ? kevSettled.value
      : { matches: [], checked: 0, matched: 0,
          source: "cisa_kev", error: kevSettled.reason?.message ?? "KEV module failed" };

    modules.email_security_intelligence = emailIntelSettled.status === "fulfilled"
      ? emailIntelSettled.value
      : { error: emailIntelSettled.reason?.message ?? "Email intelligence module failed" };

    // Phase 6: Risk intelligence + Remediation plan (pure computation — no I/O)
    // Risk module enriches all findings with business-impact language and risk categories.
    // Remediation module converts findings + KEV matches into P1/P2/P3 roadmap.
    modules.risk_intelligence = runRiskModule(findings, modules);
    modules.remediation_plan  = runRemediationModule(
      findings,
      modules.known_exploited_vulnerabilities,
      modules.subdomain_takeover,
    );

    // Phase 7: Cloud storage discovery — pure pattern analysis, zero I/O.
    // Needs subdomains + dns_bruteforce + asset_exposure to be complete first.
    modules.cloud_storage_discovery = runCloudStorageModule(domain, modules);

    // Phase 7b: Admin surface detection — pure fingerprint pass over HTTP probe
    // results already collected by runExposureModule.  Zero additional I/O.
    modules.admin_surface_detection = runAdminSurfaceModule(modules);

    // Phase 7c: Domain security enrichment — pure computation, zero network I/O.
    // Reads CAA from modules.dns.caa, HSTS from modules.headers, cookies from
    // modules.headers.set_cookie_raw.  All data was captured in Phase 1.
    try {
      modules.domain_security_enrichment = runDomainSecurityEnrichmentModule(domain, modules);
    } catch {
      modules.domain_security_enrichment = {
        caa:     { present: false, records: [], issuers: [], wildcard_issuers: [], iodef: [], error: "enrichment failed" },
        hsts:    { present: false, value: null, max_age: null, include_subdomains: false, preload_directive: false, preload_eligible: false, error: "enrichment failed" },
        cookies: { found: 0, cookies: [], insecure_count: 0, no_httponly: 0, no_samesite: 0, error: "enrichment failed" },
        source:  "dns_headers_analysis", error: "enrichment failed",
      };
    }

    // Phase 7d: Scan budget — pure computation, zero I/O.
    // Estimates subrequest usage across all modules and warns if close to the
    // Cloudflare Worker free-plan 50-subrequest limit.
    modules.scan_budget = computeScanBudget(bruteforceResult.checked);

    // Phase 7e: Vendor Risk — pure computation, zero I/O.
    // Detects third-party vendors from signals already captured in modules:
    // SPF, MX, NS, DKIM, CSP, Server header, CNAME targets, tech detection.
    modules.vendor_risk = detectVendorsFromModules(modules);

    // Phase 7f: Third-Party Asset Discovery — pure computation, zero I/O.
    // Business-focused SaaS inventory derived from vendor_risk.  Excludes
    // infrastructure/cloud/hosting; remaps to email/crm/collaboration/support/
    // marketing/ecommerce taxonomy.
    modules.third_party_assets = runThirdPartyDiscoveryModule(modules);

    const completedAt = new Date().toISOString();

    // Build full structured report
    const report = {
      scan_id:             scanId,
      domain_id:           domainId,
      domain,
      status:              "completed",
      cyber_metrics_score: score,
      risk_level,
      started_at:          startedAt,
      completed_at:        completedAt,
      findings,
      recommendations,
      modules,
    };

    // Write completed report to R2
    await env.cybermeters_reports.put(
      `reports/${scanId}.json`,
      JSON.stringify(report, null, 2),
      { httpMetadata: { contentType: "application/json" } }
    );

    // Update D1 scans row
    await env.cybermeters_db
      .prepare(`UPDATE scans SET status = 'completed', score = ?, rating = ? WHERE id = ?`)
      .bind(score, risk_level, scanId)
      .run();

    // Persist findings to D1
    for (const f of findings) {
      await env.cybermeters_db
        .prepare(
          `INSERT INTO findings (id, scan_id, severity, title, recommendation)
           VALUES (?, ?, ?, ?, ?)`
        )
        .bind(createId("finding"), scanId, f.severity, f.title, f.description)
        .run();
    }

    // Persist remediation items to D1
    for (const r of recommendations) {
      await env.cybermeters_db
        .prepare(
          `INSERT INTO remediation_items (id, scan_id, priority, title, reason, action)
           VALUES (?, ?, ?, ?, ?, ?)`
        )
        .bind(
          createId("rem"),
          scanId,
          String(r.priority),
          r.title,
          r.module,
          r.description
        )
        .run();
    }

    // Phase 8: Asset Inventory Upsert — runs AFTER completion status is written.
    // Failure here cannot leave the scan stuck in "running".
    // Uses D1 batch() to minimise round-trips.
    try {
      await upsertAssetInventory(scanId, domainId, domain, modules, env);
    } catch { /* non-fatal — inventory update will catch up on next scan */ }

    // Phase 8b: Admin Surface Events — one asset_event per detected service per workspace.
    // Runs after upsertAssetInventory so workspace_assets rows are already present,
    // allowing asset_id FK resolution.
    try {
      await insertAdminSurfaceEvents(scanId, domainId, modules.admin_surface_detection, env);
    } catch { /* non-fatal */ }

    // Phase 8c: Vendor Inventory Upsert — persists vendor_risk detections to D1.
    // Uses workspace lookup internally. Preserves first_seen; marks unseen vendors inactive.
    try {
      await upsertVendorInventory(domainId, modules.vendor_risk, env);
    } catch { /* non-fatal */ }

    // Phase 9: Asset Change Alert — one grouped email per workspace per scan.
    // Reads asset_events written by Phase 8, deduped via asset_alert_records.
    // Fully non-fatal — swallows all errors.
    try {
      await sendAssetChangeAlert(domainId, domain, scanId, env);
    } catch { /* non-fatal */ }

  } catch (err) {
    // Best-effort: write failure state to R2 and D1.
    // Each write is individually guarded so one failure cannot prevent the other.
    // The D1 status write is the most critical — it stops the UI polling loop.
    const failedAt = new Date().toISOString();

    try {
      await env.cybermeters_reports.put(
        `reports/${scanId}.json`,
        JSON.stringify({
          scan_id:             scanId,
          domain,
          status:              "failed",
          cyber_metrics_score: 0,
          risk_level:          "unknown",
          findings:            [],
          recommendations:     [],
          error:               err?.message ?? "Unknown scan engine error",
          started_at:          startedAt,
          failed_at:           failedAt,
        }, null, 2),
        { httpMetadata: { contentType: "application/json" } }
      );
    } catch { /* R2 write failure — non-fatal */ }

    try {
      await env.cybermeters_db
        .prepare(`UPDATE scans SET status = 'failed' WHERE id = ?`)
        .bind(scanId)
        .run();
    } catch { /* D1 write failure — scan will remain 'running' but we cannot do more */ }
  }
}

// ── Admin Surface Event Insertion ────────────────────────────────────────────
//
// Writes one asset_event per detected admin service per workspace per scan.
// Called after upsertAssetInventory so workspace_assets rows already exist.
// All errors are non-fatal — the scan is already marked completed by this point.

async function insertAdminSurfaceEvents(scanId, domainId, adminModule, env) {
  if (!adminModule || !adminModule.detected || adminModule.services.length === 0) return;

  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare(`SELECT workspace_id FROM workspace_domains WHERE domain_id = ?`)
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch {
    return;
  }
  if (wsRows.length === 0) return;

  const now = new Date().toISOString();

  for (const { workspace_id } of wsRows) {
    for (const svc of adminModule.services) {
      try {
        // Resolve asset_id if the asset was already upserted by upsertAssetInventory
        const assetRow = await env.cybermeters_db
          .prepare(`SELECT id FROM workspace_assets WHERE workspace_id = ? AND hostname = ?`)
          .bind(workspace_id, svc.hostname)
          .first();

        await env.cybermeters_db
          .prepare(
            `INSERT INTO asset_events
               (id, workspace_id, domain_id, asset_id, scan_id,
                event_type, hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            createId("evt"),
            workspace_id,
            domainId,
            assetRow?.id ?? null,
            scanId,
            "admin_surface_detected",
            svc.hostname,
            svc.risk_level,
            `${svc.product} (${svc.category}) detected on ${svc.hostname} — confidence: ${svc.confidence}`,
            now
          )
          .run();
      } catch { /* non-fatal per service */ }
    }
  }

  console.log("[admin-surface]", JSON.stringify({
    scan_id:      scanId,
    domain_id:    domainId,
    detected:     adminModule.detected,
    workspaces:   wsRows.length,
  }));
}

// ── Asset Change Alert Engine ─────────────────────────────────────────────────
//
// Fires once per workspace per scan, grouped into a single summary email.
// Dedup is enforced by asset_alert_records UNIQUE(workspace_id, scan_id):
//   INSERT OR IGNORE silently no-ops if an alert was already sent.
//
// Alert-worthy event types and their severity contribution:
//   takeover_risk_detected  → critical
//   new_asset_discovered    → high
//   wildcard_dns_detected   → medium
//   cloud_storage_detected  → medium
//   asset_reappeared        → medium
//   asset_no_longer_seen    → info  (included in summary but does not trigger alone)

const ASSET_ALERT_EVENTS = new Set([
  "new_asset_discovered",
  "asset_reappeared",
  "asset_no_longer_seen",
  "takeover_risk_detected",
  "cloud_storage_detected",
  "wildcard_dns_detected",
  "admin_surface_detected",
]);

// Severity thresholds — highest matching rule wins.
function assetAlertSeverity(counts) {
  if ((counts.takeover_risk_detected || 0) > 0) return "critical";
  if ((counts.admin_surface_detected || 0) > 0) return "high";
  if ((counts.new_asset_discovered   || 0) > 0) return "high";
  if ((counts.wildcard_dns_detected  || 0) > 0 ||
      (counts.cloud_storage_detected || 0) > 0 ||
      (counts.asset_reappeared       || 0) > 0)  return "medium";
  return "info";
}

// Returns true when there is something worth emailing about.
// asset_no_longer_seen alone is not alert-worthy.
function assetAlertWorthy(counts) {
  return (
    (counts.new_asset_discovered   || 0) > 0 ||
    (counts.asset_reappeared       || 0) > 0 ||
    (counts.takeover_risk_detected || 0) > 0 ||
    (counts.cloud_storage_detected || 0) > 0 ||
    (counts.wildcard_dns_detected  || 0) > 0 ||
    (counts.admin_surface_detected || 0) > 0
  );
}

function buildAssetAlertEmail(domain, workspaceId, scanId, counts, topHostnames, severity) {
  const assetsUrl = `https://cybermeters.pages.dev/assets`;

  const SEVERITY_COLOR = {
    critical: "#dc2626",
    high:     "#ea580c",
    medium:   "#d97706",
    info:     "#00876A",
  };
  const color = SEVERITY_COLOR[severity] || SEVERITY_COLOR.info;

  const LABELS = {
    new_asset_discovered:   "New assets discovered",
    asset_reappeared:       "Assets reappeared",
    asset_no_longer_seen:   "Assets no longer seen",
    takeover_risk_detected: "Subdomain takeover risks",
    cloud_storage_detected: "Cloud storage references",
    wildcard_dns_detected:  "Wildcard DNS events",
  };

  const lines = [];
  for (const [type, label] of Object.entries(LABELS)) {
    const n = counts[type] || 0;
    if (n > 0) lines.push(`${label}: ${n}`);
  }

  const hostList = (topHostnames || []).slice(0, 5);
  const hostLine = hostList.length > 0
    ? `Top affected hostnames: ${hostList.join(", ")}`
    : null;

  const subject = severity === "critical"
    ? `🚨 CyberMeters: Takeover risk on ${domain}`
    : severity === "high"
    ? `⚠ CyberMeters: New assets detected on ${domain}`
    : `CyberMeters: Asset changes on ${domain}`;

  const text = [
    `Asset change alert for ${domain} (workspace ${workspaceId})`,
    `Severity: ${severity.toUpperCase()}`,
    "",
    ...lines,
    ...(hostLine ? [hostLine] : []),
    "",
    `View asset inventory: ${assetsUrl}`,
  ].join("\n");

  const listItems = lines
    .map((l) => `<li style="margin-bottom:6px">${l}</li>`)
    .join("\n      ");

  const hostnameSection = hostList.length > 0
    ? `<p style="font-size:13px;color:#555;margin-top:12px;">
        <strong>Affected hostnames:</strong> ${hostList.map((h) => `<code style="background:#f3f4f6;padding:1px 5px;border-radius:4px;font-size:12px">${h}</code>`).join(" ")}
       </p>`
    : "";

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;max-width:600px;margin:0 auto;padding:24px;">
  <div style="border-left:4px solid ${color};padding-left:16px;margin-bottom:20px;">
    <h2 style="margin:0 0 4px;color:${color};font-size:18px;">Asset Change Alert</h2>
    <p style="margin:0;color:#555;font-size:14px;">
      Scan completed for <strong>${domain}</strong> &mdash;
      <span style="font-weight:600;color:${color};text-transform:uppercase;font-size:12px">${severity}</span>
    </p>
  </div>
  <ul style="padding-left:20px;line-height:1.8;font-size:14px;color:#333;">
    ${listItems}
  </ul>
  ${hostnameSection}
  <p style="margin-top:24px;">
    <a href="${assetsUrl}"
       style="background:${color};color:white;padding:10px 20px;border-radius:8px;
              text-decoration:none;font-size:14px;font-weight:600;display:inline-block;">
      View Asset Inventory
    </a>
  </p>
  <hr style="border:none;border-top:1px solid #eee;margin:28px 0;" />
  <p style="font-size:12px;color:#999;margin:0;">
    CyberMeters &mdash; Attack Surface Management<br>
    Scan ID: <code style="font-size:11px">${scanId}</code>
  </p>
</body>
</html>`;

  return { subject, text, html };
}

// ── Vendor Inventory Upsert ───────────────────────────────────────────────────
//
// Persists the vendor_risk module output to workspace_vendors (D1).
// Called after Phase 7e and after workspace lookup is available.
// All errors are non-fatal — failure here does not affect scan status.

/**
 * upsertVendorInventory
 *
 * For each workspace that owns `domainId`:
 *   1. Upsert active vendors from `vendorRisk.vendors` into workspace_vendors.
 *      - INSERT OR IGNORE to preserve first_seen.
 *      - UPDATE last_seen + status='active' + updated_at on every upsert.
 *   2. Mark any workspace_vendors rows NOT in the current detected set as inactive.
 */
async function upsertVendorInventory(domainId, vendorRisk, env) {
  if (!vendorRisk?.detected || !vendorRisk.vendors?.length) return;

  // Find all workspaces that own this domain
  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch {
    return;
  }
  if (wsRows.length === 0) return;

  const now = new Date().toISOString();
  const detectedNames = vendorRisk.vendors.map((v) => v.name);

  for (const { workspace_id } of wsRows) {
    // Upsert each detected vendor
    for (const v of vendorRisk.vendors) {
      try {
        const id = createId("vendor");
        const evidenceJson = JSON.stringify(v.evidence || []);

        // INSERT OR IGNORE preserves first_seen for existing rows
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO workspace_vendors
               (id, workspace_id, vendor_name, category, source, evidence,
                confidence, risk_level, first_seen, last_seen, status,
                created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)`
          )
          .bind(
            id, workspace_id, v.name, v.category, v.source, evidenceJson,
            v.confidence, v.risk_level, now, now, now, now
          )
          .run();

        // UPDATE existing row — refresh last_seen, evidence, confidence, status
        await env.cybermeters_db
          .prepare(
            `UPDATE workspace_vendors
             SET last_seen = ?, evidence = ?, confidence = ?, risk_level = ?,
                 status = 'active', updated_at = ?
             WHERE workspace_id = ? AND vendor_name = ? AND category = ?`
          )
          .bind(
            now, evidenceJson, v.confidence, v.risk_level, now,
            workspace_id, v.name, v.category
          )
          .run();
      } catch { /* non-fatal per-vendor failure */ }
    }

    // Mark previously-detected vendors that were not seen this scan as inactive.
    // Only touch rows in this workspace — preserve other workspaces.
    if (detectedNames.length > 0) {
      try {
        // D1 does not support parameterised IN lists of variable length, so
        // we build a literal list. Values are vendor names (strings) — safe to
        // embed as SQL string literals after escaping single-quotes.
        const escaped = detectedNames.map((n) => `'${n.replace(/'/g, "''")}'`).join(", ");
        await env.cybermeters_db
          .prepare(
            `UPDATE workspace_vendors
             SET status = 'inactive', updated_at = ?
             WHERE workspace_id = ? AND status = 'active'
               AND vendor_name NOT IN (${escaped})`
          )
          .bind(now, workspace_id)
          .run();
      } catch { /* non-fatal */ }
    }
  }
}

/**
 * sendAssetChangeAlert
 *
 * Called once per scan after upsertAssetInventory completes.
 * Looks up all workspaces that own this domain, queries asset_events for this
 * scan, builds a grouped summary, and sends one email per workspace.
 *
 * Dedup: INSERT OR IGNORE into asset_alert_records prevents re-sends.
 * The whole function is non-fatal — any error is swallowed.
 */
async function sendAssetChangeAlert(domainId, domain, scanId, env) {
  try {
    // Find all workspaces that own this domain
    const wsResult = await env.cybermeters_db
      .prepare(`SELECT workspace_id FROM workspace_domains WHERE domain_id = ?`)
      .bind(domainId)
      .all();
    const workspaceIds = (wsResult.results || []).map((r) => r.workspace_id);
    if (workspaceIds.length === 0) return;

    // Fetch all asset events for this scan (across all workspaces in one query)
    const eventsResult = await env.cybermeters_db
      .prepare(
        `SELECT workspace_id, event_type, hostname
         FROM asset_events
         WHERE scan_id = ?`
      )
      .bind(scanId)
      .all();
    const allEvents = eventsResult.results || [];

    // Group events by workspace_id
    const byWorkspace = new Map();
    for (const ev of allEvents) {
      if (!byWorkspace.has(ev.workspace_id)) byWorkspace.set(ev.workspace_id, []);
      byWorkspace.get(ev.workspace_id).push(ev);
    }

    for (const workspace_id of workspaceIds) {
      try {
        const events = byWorkspace.get(workspace_id) || [];
        if (events.length === 0) continue;

        // Count events by type
        const counts = {};
        const hostnamesByType = {};
        for (const ev of events) {
          if (!ASSET_ALERT_EVENTS.has(ev.event_type)) continue;
          counts[ev.event_type] = (counts[ev.event_type] || 0) + 1;
          if (ev.hostname) {
            if (!hostnamesByType[ev.event_type]) hostnamesByType[ev.event_type] = [];
            hostnamesByType[ev.event_type].push(ev.hostname);
          }
        }

        if (!assetAlertWorthy(counts)) continue;

        const severity = assetAlertSeverity(counts);

        // Collect top hostnames — prioritise high-severity event types
        const topHostnames = [
          ...(hostnamesByType.takeover_risk_detected || []),
          ...(hostnamesByType.new_asset_discovered   || []),
          ...(hostnamesByType.cloud_storage_detected || []),
          ...(hostnamesByType.wildcard_dns_detected  || []),
          ...(hostnamesByType.asset_reappeared       || []),
        ].filter((v, i, a) => a.indexOf(v) === i).slice(0, 5);

        // Dedup: INSERT OR IGNORE — if this (workspace_id, scan_id) already has a
        // record the insert is silently skipped and we don't send the email again.
        const now    = new Date().toISOString();
        const recId  = createId("aar");
        const insert = await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO asset_alert_records
               (id, workspace_id, scan_id, domain, severity, event_counts, top_hostnames, sent_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
          )
          .bind(
            recId,
            workspace_id,
            scanId,
            domain,
            severity,
            JSON.stringify(counts),
            JSON.stringify(topHostnames),
            now
          )
          .run();

        // meta.changes === 0 means the row already existed — skip email
        if (!insert.meta || insert.meta.changes === 0) continue;

        // Build + send email
        const { subject, text, html } = buildAssetAlertEmail(
          domain, workspace_id, scanId, counts, topHostnames, severity
        );
        await sendAlertEmail(subject, text, html, env, "ALERT_EMAIL_FROM");

        console.log("[asset-alert] sent", JSON.stringify({ workspace_id, scanId, severity, counts }));
      } catch (wsErr) {
        console.error("[asset-alert] workspace error", workspace_id, wsErr?.message);
      }
    }
  } catch (err) {
    console.error("[asset-alert] failed:", err?.message);
  }
}

// ── Email Alert Engine ────────────────────────────────────────────────────────

/**
 * Inspect historical_changes and findings from a completed scheduled scan.
 * Returns an array of trigger objects when an alert is warranted, or null
 * when nothing notable changed (or when there is no previous scan to compare).
 *
 * Alert conditions:
 *   • Score dropped by 10+ points
 *   • One or more new subdomain takeover risks
 *   • One or more new reachable exposed assets
 *   • One or more new findings with severity 'high' or 'critical'
 */
function shouldSendAlert(historicalChanges) {
  if (!historicalChanges || !historicalChanges.has_previous) return null;

  const triggers = [];

  if (historicalChanges.score_change != null && historicalChanges.score_change <= -10) {
    triggers.push({
      type:   "score_drop",
      detail: `Score dropped ${historicalChanges.score_change} points ` +
              `(${historicalChanges.previous_score} → ${historicalChanges.current_score})`,
    });
  }

  if (historicalChanges.new_takeover_risks?.length > 0) {
    triggers.push({
      type:  "takeover_risk",
      count: historicalChanges.new_takeover_risks.length,
      hosts: historicalChanges.new_takeover_risks.map((r) => r.host),
    });
  }

  if (historicalChanges.new_exposed_assets?.length > 0) {
    triggers.push({
      type:  "exposed_asset",
      count: historicalChanges.new_exposed_assets.length,
      hosts: historicalChanges.new_exposed_assets.map((a) => a.host),
    });
  }

  const criticalNew = (historicalChanges.new_findings || []).filter(
    (f) => f.severity === "high" || f.severity === "critical"
  );
  if (criticalNew.length > 0) {
    triggers.push({
      type:     "new_finding",
      findings: criticalNew.map((f) => ({ title: f.title, severity: f.severity })),
    });
  }

  return triggers.length > 0 ? triggers : null;
}

/**
 * Build a plain-text and HTML email body for a set of alert triggers.
 */
function buildAlertEmail(domain, scanId, triggers) {
  const count   = triggers.length;
  const subject = `⚠ CyberMeters Alert: ${domain} — ` +
                  `${count} issue${count !== 1 ? "s" : ""} detected`;

  // Plain-text summary lines
  const lines = [];
  for (const t of triggers) {
    if (t.type === "score_drop") {
      lines.push(`Score drop: ${t.detail}`);
    } else if (t.type === "takeover_risk") {
      lines.push(
        `${t.count} new subdomain takeover risk${t.count !== 1 ? "s" : ""}: ` +
        t.hosts.join(", ")
      );
    } else if (t.type === "exposed_asset") {
      lines.push(
        `${t.count} new exposed asset${t.count !== 1 ? "s" : ""}: ` +
        t.hosts.join(", ")
      );
    } else if (t.type === "new_finding") {
      const titles = t.findings.map((f) => `${f.severity}: ${f.title}`).join("; ");
      lines.push(
        `${t.findings.length} new high/critical finding${t.findings.length !== 1 ? "s" : ""}: ` +
        titles
      );
    }
  }

  const reportUrl = `https://cybermeters.pages.dev/scans/${scanId}`;

  const text =
    `CyberMeters scheduled scan alert for ${domain}\n\n` +
    lines.map((l) => `• ${l}`).join("\n") +
    `\n\nView full report: ${reportUrl}`;

  const listItems = lines
    .map((l) => `<li style="margin-bottom:8px">${l}</li>`)
    .join("\n      ");

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;max-width:600px;margin:0 auto;padding:24px;">
  <div style="border-left:4px solid #00876A;padding-left:16px;margin-bottom:20px;">
    <h2 style="margin:0 0 4px;color:#00876A;font-size:18px;">CyberMeters Alert</h2>
    <p style="margin:0;color:#555;font-size:14px;">
      Scheduled scan completed for <strong>${domain}</strong>
    </p>
  </div>
  <ul style="padding-left:20px;line-height:1.7;font-size:14px;color:#333;">
      ${listItems}
  </ul>
  <p style="margin-top:24px;">
    <a href="${reportUrl}"
       style="background:#00876A;color:white;padding:10px 20px;border-radius:8px;
              text-decoration:none;font-size:14px;font-weight:600;display:inline-block;">
      View Full Report
    </a>
  </p>
  <hr style="border:none;border-top:1px solid #eee;margin:28px 0;" />
  <p style="font-size:12px;color:#999;margin:0;">
    CyberMeters &mdash; Attack Surface Management<br>
    This alert fired because a scheduled scan detected security-relevant changes.
  </p>
</body>
</html>`;

  return { subject, text, html };
}

/**
 * POST an email via the Resend API.
 *
 * Requires:
 *   env.RESEND_API_KEY   — Wrangler secret  (wrangler secret put RESEND_API_KEY)
 *   env.ALERT_EMAIL_TO   — recipient address (wrangler.toml [vars])
 *   fromKey              — which env var to use for the sender address:
 *                            "ALERT_EMAIL_FROM"  alerts@cybermeters.com  (default)
 *                            "SAFE_EMAIL_FROM"   safe@cybermeters.com
 *                            "HELLO_EMAIL_FROM"  hello@cybermeters.com
 *
 * If RESEND_API_KEY is absent the function returns immediately — alerts are
 * silently skipped rather than crashing the scan pipeline.
 * All errors are swallowed for the same reason.
 */
async function sendAlertEmail(subject, text, html, env, fromKey = "ALERT_EMAIL_FROM") {
  if (!env.RESEND_API_KEY) return;

  const to   = env.ALERT_EMAIL_TO || "ttrnn47@gmail.com";
  const from = env[fromKey] || env.ALERT_EMAIL_FROM || "alerts@cybermeters.com";

  try {
    await fetch("https://api.resend.com/emails", {
      method:  "POST",
      headers: {
        "Content-Type":  "application/json",
        "Authorization": `Bearer ${env.RESEND_API_KEY}`,
      },
      body:   JSON.stringify({ from, to: [to], subject, text, html }),
      signal: AbortSignal.timeout(10_000),
    });
  } catch {
    // Email delivery errors must never affect scan completion or D1/R2 writes.
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Dedicated alert functions — each fires via the appropriate sender address
// and is swallowed on error so the scan pipeline is never interrupted.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * sendScoreDropAlert — fires when the Cyber Metrics Score drops ≥ 10 points
 * compared to the previous scan for the same domain.
 * Sender: ALERT_EMAIL_FROM (alerts@cybermeters.com)
 */
async function sendScoreDropAlert(domain, scanId, scoreDrop, prevScore, currScore, env) {
  const reportUrl = `https://cybermeters.pages.dev/scans/${scanId}`;
  const subject   = `⚠ CyberMeters: ${domain} score dropped ${Math.abs(scoreDrop)} points`;

  const text =
    `Security score drop detected for ${domain}\n\n` +
    `Previous score : ${prevScore}\n` +
    `Current score  : ${currScore}\n` +
    `Change         : ${scoreDrop} points\n\n` +
    `A score drop of this magnitude typically indicates new critical or high-severity\n` +
    `findings on your attack surface. Review the full report immediately.\n\n` +
    `View report: ${reportUrl}`;

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;max-width:600px;margin:0 auto;padding:24px;">
  <div style="border-left:4px solid #EF4444;padding-left:16px;margin-bottom:20px;">
    <h2 style="margin:0 0 4px;color:#EF4444;font-size:18px;">Score Drop Detected</h2>
    <p style="margin:0;color:#555;font-size:14px;">Scheduled scan for <strong>${domain}</strong></p>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:20px;">
    <tr>
      <td style="padding:8px 12px;background:#F9FAFB;border-radius:6px 6px 0 0;color:#555;width:50%;">Previous score</td>
      <td style="padding:8px 12px;background:#F9FAFB;border-radius:6px 6px 0 0;font-weight:700;">${prevScore}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;background:#FEF2F2;color:#555;">Current score</td>
      <td style="padding:8px 12px;background:#FEF2F2;font-weight:700;color:#EF4444;">${currScore}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;background:#F9FAFB;border-radius:0 0 6px 6px;color:#555;">Change</td>
      <td style="padding:8px 12px;background:#F9FAFB;border-radius:0 0 6px 6px;font-weight:700;color:#EF4444;">${scoreDrop} points</td>
    </tr>
  </table>
  <p style="font-size:14px;color:#555;line-height:1.6;">
    A drop of this magnitude typically indicates new critical or high-severity findings
    on your attack surface. Review the full report immediately.
  </p>
  <p style="margin-top:24px;">
    <a href="${reportUrl}" style="background:#EF4444;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;display:inline-block;">
      View Full Report
    </a>
  </p>
  <hr style="border:none;border-top:1px solid #eee;margin:28px 0;" />
  <p style="font-size:12px;color:#999;margin:0;">CyberMeters — Attack Surface Management</p>
</body>
</html>`;

  await sendAlertEmail(subject, text, html, env, "ALERT_EMAIL_FROM");
}

/**
 * sendTakeoverAlert — fires when new subdomain takeover risks are detected
 * that were not present in the previous scan.
 * Sender: SAFE_EMAIL_FROM (safe@cybermeters.com)
 */
async function sendTakeoverAlert(domain, scanId, risks, env) {
  const reportUrl = `https://cybermeters.pages.dev/scans/${scanId}`;
  const count     = risks.length;
  const subject   = `🚨 CyberMeters: ${count} new takeover risk${count !== 1 ? "s" : ""} on ${domain}`;

  const riskLines = risks.map(r => `• ${r.host} (${r.provider || "unknown provider"})`).join("\n");
  const text =
    `Subdomain takeover risk detected for ${domain}\n\n` +
    `${count} new takeover risk${count !== 1 ? "s" : ""} found:\n` +
    riskLines + "\n\n" +
    `These subdomains have dangling CNAME records pointing to unclaimed cloud\n` +
    `resources. An attacker could claim the target and serve malicious content\n` +
    `on your domain.\n\n` +
    `View report: ${reportUrl}`;

  const riskRows = risks
    .map(r => `<tr>
      <td style="padding:8px 12px;font-family:monospace;font-size:13px;">${r.host}</td>
      <td style="padding:8px 12px;color:#555;font-size:13px;">${r.provider || "—"}</td>
    </tr>`)
    .join("\n");

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;max-width:600px;margin:0 auto;padding:24px;">
  <div style="border-left:4px solid #F97316;padding-left:16px;margin-bottom:20px;">
    <h2 style="margin:0 0 4px;color:#F97316;font-size:18px;">Subdomain Takeover Risk</h2>
    <p style="margin:0;color:#555;font-size:14px;">
      ${count} new risk${count !== 1 ? "s" : ""} detected on <strong>${domain}</strong>
    </p>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:20px;">
    <thead>
      <tr style="background:#FFF7ED;">
        <th style="padding:8px 12px;text-align:left;color:#555;font-weight:600;">Subdomain</th>
        <th style="padding:8px 12px;text-align:left;color:#555;font-weight:600;">Provider</th>
      </tr>
    </thead>
    <tbody>${riskRows}</tbody>
  </table>
  <p style="font-size:14px;color:#555;line-height:1.6;">
    These subdomains have dangling CNAME records pointing to unclaimed cloud resources.
    An attacker could claim the target and serve malicious content on your domain.
    Remove or update the DNS records immediately.
  </p>
  <p style="margin-top:24px;">
    <a href="${reportUrl}" style="background:#F97316;color:white;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;display:inline-block;">
      View Full Report
    </a>
  </p>
  <hr style="border:none;border-top:1px solid #eee;margin:28px 0;" />
  <p style="font-size:12px;color:#999;margin:0;">CyberMeters — Attack Surface Management</p>
</body>
</html>`;

  await sendAlertEmail(subject, text, html, env, "SAFE_EMAIL_FROM");
}

/**
 * sendSslExpiryAlert — fires when the SSL certificate for a domain expires
 * within 30 days (cert_expiry_days from runSslModule).
 *
 * Sender selection:
 *   ≤ 14 days  → ALERT_EMAIL_FROM (alerts@)   — urgent security alert
 *   15–30 days → SAFE_EMAIL_FROM  (safe@)      — advance security warning
 *   HELLO_EMAIL_FROM is reserved for welcome/contact emails only.
 */
async function sendSslExpiryAlert(domain, scanId, daysUntilExpiry, certNotAfter, env) {
  const reportUrl = `https://cybermeters.pages.dev/scans/${scanId}`;
  const urgency   = daysUntilExpiry <= 7  ? "CRITICAL"
                  : daysUntilExpiry <= 14 ? "URGENT"
                  : "WARNING";
  // Route to appropriate sender based on urgency window
  const fromKey   = daysUntilExpiry <= 14 ? "ALERT_EMAIL_FROM" : "SAFE_EMAIL_FROM";
  const subject   = `[${urgency}] SSL certificate for ${domain} expires in ${daysUntilExpiry} day${daysUntilExpiry !== 1 ? "s" : ""}`;

  const expiryStr = certNotAfter
    ? new Date(certNotAfter).toUTCString().slice(0, 22) + " UTC"
    : "unknown";

  const text =
    `SSL certificate expiry warning for ${domain}\n\n` +
    `Days until expiry : ${daysUntilExpiry}\n` +
    `Certificate expires: ${expiryStr}\n\n` +
    `An expired SSL certificate will cause browsers to show security warnings\n` +
    `to all visitors, effectively taking your site offline. Renew immediately.\n\n` +
    `View report: ${reportUrl}`;

  const barColor  = daysUntilExpiry <= 7  ? "#EF4444"
                  : daysUntilExpiry <= 14 ? "#F97316"
                  : "#F59E0B";

  const html = `<!DOCTYPE html>
<html lang="en">
<body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#111;max-width:600px;margin:0 auto;padding:24px;">
  <div style="border-left:4px solid ${barColor};padding-left:16px;margin-bottom:20px;">
    <h2 style="margin:0 0 4px;color:${barColor};font-size:18px;">SSL Certificate Expiry — ${urgency}</h2>
    <p style="margin:0;color:#555;font-size:14px;"><strong>${domain}</strong></p>
  </div>
  <table style="width:100%;border-collapse:collapse;font-size:14px;margin-bottom:20px;">
    <tr>
      <td style="padding:8px 12px;background:#FFFBEB;color:#555;border-radius:6px 6px 0 0;width:50%;">Days remaining</td>
      <td style="padding:8px 12px;background:#FFFBEB;font-weight:700;color:${barColor};font-size:20px;">${daysUntilExpiry}</td>
    </tr>
    <tr>
      <td style="padding:8px 12px;background:#F9FAFB;color:#555;border-radius:0 0 6px 6px;">Expiry date</td>
      <td style="padding:8px 12px;background:#F9FAFB;font-weight:600;">${expiryStr}</td>
    </tr>
  </table>
  <p style="font-size:14px;color:#555;line-height:1.6;">
    An expired SSL certificate causes browsers to show security warnings to all visitors,
    effectively taking your site offline. Renew the certificate immediately via your
    hosting provider, Let's Encrypt, or your certificate authority.
  </p>
  <p style="margin-top:24px;">
    <a href="${reportUrl}" style="background:${barColor};color:white;padding:10px 20px;border-radius:8px;text-decoration:none;font-size:14px;font-weight:600;display:inline-block;">
      View Full Report
    </a>
  </p>
  <hr style="border:none;border-top:1px solid #eee;margin:28px 0;" />
  <p style="font-size:12px;color:#999;margin:0;">CyberMeters — Attack Surface Management</p>
</body>
</html>`;

  await sendAlertEmail(subject, text, html, env, fromKey);
}

// ─────────────────────────────────────────────────────────────────────────────
// Executive PDF Report Generator
// Pure-JS PDF/1.4 — no npm packages. Uses built-in Type1 fonts only.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Sanitise a value to printable ASCII and escape PDF literal string delimiters.
 */
function pdfEsc(v) {
  return String(v == null ? "" : v)
    .replace(/[^\x20-\x7E]/g, " ")
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)");
}

/** Return [r, g, b] as 0-1 floats from a #RRGGBB string. */
function hexToRgbF(hex) {
  const h = hex.replace("#", "");
  return [
    parseInt(h.slice(0, 2), 16) / 255,
    parseInt(h.slice(2, 4), 16) / 255,
    parseInt(h.slice(4, 6), 16) / 255,
  ];
}

/**
 * Assemble a PDF 1.4 document from an array of content-stream strings.
 *
 * Fixed object layout (1-indexed):
 *   1  = Catalog
 *   2  = Pages tree
 *   3  = /F1  Helvetica        (regular)
 *   4  = /F2  Helvetica-Bold   (bold)
 *   For page i (0-based):
 *     5 + i*2     = content stream object
 *     5 + i*2 + 1 = page object
 *
 * All stream content must be ASCII-only (guaranteed by pdfEsc) so
 * stream.length === byte length and TextEncoder output is identical.
 */
function assemblePdf(streams) {
  const n   = streams.length;
  const cId = (i) => 5 + i * 2;       // content stream object id
  const pId = (i) => 5 + i * 2 + 1;  // page object id
  const totalObjs = 4 + n * 2;

  let out      = "%PDF-1.4\n";
  const offsets = {};

  const addObj = (id, data) => {
    offsets[id] = out.length;
    out += `${id} 0 obj\n${data}\nendobj\n`;
  };

  addObj(1, "<< /Type /Catalog /Pages 2 0 R >>");
  addObj(
    2,
    `<< /Type /Pages /Kids [${Array.from({ length: n }, (_, i) => `${pId(i)} 0 R`).join(" ")}] /Count ${n} >>`
  );
  addObj(3, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>");
  addObj(4, "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>");

  for (let i = 0; i < n; i++) {
    const s = streams[i];
    addObj(cId(i), `<< /Length ${s.length} >>\nstream\n${s}\nendstream`);
    addObj(
      pId(i),
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] ` +
      `/Contents ${cId(i)} 0 R ` +
      `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> >>`
    );
  }

  // Cross-reference table — each entry is exactly 20 bytes
  const xrefPos = out.length;
  out += `xref\n0 ${totalObjs + 1}\n`;
  out += "0000000000 65535 f \n";
  for (let i = 1; i <= totalObjs; i++) {
    out += (offsets[i] || 0).toString().padStart(10, "0") + " 00000 n \n";
  }
  out +=
    `trailer\n<< /Size ${totalObjs + 1} /Root 1 0 R >>\n` +
    `startxref\n${xrefPos}\n%%EOF`;

  return out;
}

/**
 * Build PDF content streams for a workspace executive report.
 * Returns an array of strings (one per page) for assemblePdf().
 *
 * Pages:
 *   1  Cover — score, workspace name, date
 *   2  Executive Summary + Domain Inventory
 *   3  Security Findings (may overflow to additional pages automatically)
 *   last  Recommendations + Historical Trend
 */
function buildPdfStreams({ workspace, stats, domains, findings, recommendations, trend }) {
  const PW = 612, PH = 792;   // page width/height (pts, US Letter)
  const ML = 50;               // left margin
  const MR = 50;               // right margin
  const MT = 50;               // top margin for content
  const MB = 55;               // bottom margin (footer zone)
  const CW = PW - ML - MR;    // content width

  // Brand palette
  const BRAND   = "#00876A";
  const GRAY    = "#555555";
  const LGRAY   = "#888888";
  const XGRAY   = "#CCCCCC";
  const BG1     = "#F8F9FA";
  const BG2     = "#F3F4F6";

  const streams  = [];
  let   curStream = "";
  let   curY      = MT;        // y from top of page

  // ── Low-level drawing ops (all coordinates are "y from top") ─────────────

  const op = (s) => { curStream += s + "\n"; };

  // Draw text at absolute position.  fontId: 1=regular 2=bold.
  const txt = (x, yTop, str, fontId, sz, hex = "#000000") => {
    if (!str) return;
    const [r, g, b] = hexToRgbF(hex);
    const pdfY      = PH - yTop;
    op("BT");
    op(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} rg`);
    op(`/F${fontId} ${sz} Tf`);
    op(`1 0 0 1 ${x} ${pdfY} Tm`);
    op(`(${pdfEsc(str)}) Tj`);
    op("ET");
  };

  // Filled rectangle.  yTop = distance from page top to top edge of rect.
  const fillRect = (x, yTop, w, h, hex) => {
    const [r, g, b] = hexToRgbF(hex);
    const pdfY      = PH - yTop - h;   // PDF y = bottom-left of rect
    op("q");
    op(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} rg`);
    op(`${x} ${pdfY} ${w} ${h} re f`);
    op("Q");
  };

  // Horizontal rule.
  const hline = (x1, x2, yTop, lw = 0.5, hex = "#DDDDDD") => {
    const [r, g, b] = hexToRgbF(hex);
    const pdfY      = PH - yTop;
    op("q");
    op(`${r.toFixed(3)} ${g.toFixed(3)} ${b.toFixed(3)} RG`);
    op(`${lw} w`);
    op(`${x1} ${pdfY} m ${x2} ${pdfY} l S`);
    op("Q");
  };

  // ── Page management ───────────────────────────────────────────────────────

  const addFooter = () => {
    const pageNum = streams.length + 1;
    hline(ML, PW - MR, PH - MB + 8, 0.5, XGRAY);
    txt(ML, PH - MB + 22, "Generated by CyberMeters | app.cybermeters.com", 1, 7, LGRAY);
    txt(PW - MR - 40, PH - MB + 22, `Page ${pageNum}`, 1, 7, LGRAY);
  };

  const endPage = () => {
    addFooter();
    streams.push(curStream);
    curStream = "";
    curY      = MT;
  };

  // Start a new page if the next block of `needed` pts would overflow.
  const checkBreak = (needed) => {
    if (curY + needed > PH - MB) endPage();
  };

  // Coloured section header bar.
  const sectionBar = (label) => {
    checkBreak(30);
    fillRect(ML, curY, CW, 20, BRAND);
    txt(ML + 8, curY + 14, label, 2, 10, "#FFFFFF");
    curY += 26;
  };

  // ── Rating helpers ────────────────────────────────────────────────────────

  const scoreToRating = (s) =>
    s == null  ? "N/A"       :
    s >= 90    ? "Excellent" :
    s >= 75    ? "Good"      :
    s >= 50    ? "Moderate"  :
    s >= 25    ? "High Risk" : "Critical";

  const scoreToColor = (s) =>
    s == null ? LGRAY :
    s >= 75   ? BRAND :
    s >= 50   ? "#F59E0B" : "#EF4444";

  // ── Derived values ────────────────────────────────────────────────────────

  const avgScore = stats.cyber_score_average != null
    ? Math.round(stats.cyber_score_average)
    : null;

  const genDate = new Date().toLocaleDateString("en-US", {
    year: "numeric", month: "long", day: "numeric",
  });

  const latestDate = stats.latest_scan
    ? new Date(
        (stats.latest_scan.created_at || "").replace(" ", "T") + "Z"
      ).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })
    : "N/A";

  // ═══════════════════════════════════════════════════════════════════════════
  // PAGE 1 — COVER
  // ═══════════════════════════════════════════════════════════════════════════

  // Header banner
  fillRect(0, 0, PW, 64, BRAND);
  txt(ML, 22,  "CYBERMETERS",                 2, 18, "#FFFFFF");
  txt(ML, 44,  "Attack Surface Management",   1, 10, "#B2DFDB");
  txt(PW - MR - 160, 44, genDate,             1,  9, "#B2DFDB");

  curY = 106;

  txt(ML, curY, "EXECUTIVE SECURITY REPORT", 2, 9, BRAND);
  curY += 26;

  // Workspace name
  txt(ML, curY, (workspace.name || "Workspace").slice(0, 50), 2, 26, "#111111");
  curY += 44;

  hline(ML, PW - MR, curY, 1, "#E0E0E0");
  curY += 20;

  // Three KPI boxes
  const BOX_H = 82;
  const boxes = [
    { label: "CYBER SCORE",        value: avgScore != null ? String(avgScore) : "N/A", sub: scoreToRating(avgScore), valueHex: scoreToColor(avgScore), x: ML },
    { label: "DOMAINS MONITORED",  value: String(stats.total_domains  || 0), sub: "In workspace",      valueHex: "#111111", x: ML + 186 },
    { label: "TOTAL SCANS",        value: String(stats.total_scans    || 0), sub: "Completed",         valueHex: "#111111", x: ML + 372 },
  ];
  for (const box of boxes) {
    fillRect(box.x, curY, 166, BOX_H, BG1);
    txt(box.x + 10, curY + 18, box.label,    2,  8, LGRAY);
    txt(box.x + 10, curY + 52, box.value,    2, 30, box.valueHex);
    txt(box.x + 10, curY + 70, box.sub,      1,  8, GRAY);
  }
  curY += BOX_H + 20;

  hline(ML, PW - MR, curY, 0.5, "#E0E0E0");
  curY += 16;

  txt(ML, curY, "CONFIDENTIAL — For authorised distribution only.", 2, 8, LGRAY);
  curY += 14;
  txt(ML, curY, "This document contains sensitive information about your external attack surface.", 1, 8, LGRAY);

  endPage();   // page 1 done

  // ═══════════════════════════════════════════════════════════════════════════
  // PAGE 2 — EXECUTIVE SUMMARY + DOMAIN INVENTORY
  // ═══════════════════════════════════════════════════════════════════════════

  sectionBar("EXECUTIVE SUMMARY");

  const summaryRows = [
    ["Total Domains",       String(stats.total_domains  || 0)],
    ["Total Scans",         String(stats.total_scans    || 0)],
    ["Average Cyber Score", avgScore != null ? `${avgScore} / 100 — ${scoreToRating(avgScore)}` : "No completed scans"],
    ["Latest Assessment",   latestDate],
    ["Report Generated",    genDate],
  ];
  for (const [label, value] of summaryRows) {
    checkBreak(20);
    txt(ML,       curY, label + ":", 2,  9, GRAY);
    txt(ML + 180, curY, value,       1,  9, "#111111");
    curY += 18;
  }

  curY += 14;
  sectionBar("DOMAIN INVENTORY");

  // Table header row
  const DC = [ML, ML + 222, ML + 292, ML + 380];   // column x positions
  fillRect(ML, curY, CW, 18, BG2);
  txt(DC[0] + 4, curY + 13, "Domain",    2, 8, "#333333");
  txt(DC[1] + 4, curY + 13, "Score",     2, 8, "#333333");
  txt(DC[2] + 4, curY + 13, "Rating",    2, 8, "#333333");
  txt(DC[3] + 4, curY + 13, "Last Scan", 2, 8, "#333333");
  curY += 20;

  for (const d of (domains || [])) {
    checkBreak(17);
    const ds = d.latest_score;
    const domScore  = ds != null ? String(ds) : "—";
    const domRating = ds != null ? scoreToRating(ds) : "N/A";
    const domDate   = d.last_scanned_at
      ? new Date((d.last_scanned_at || "").replace(" ", "T") + "Z")
          .toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
      : "Never";

    hline(ML, PW - MR, curY, 0.3, "#EEEEEE");
    txt(DC[0] + 4, curY + 12, d.domain,  1, 8, "#111111");
    txt(DC[1] + 4, curY + 12, domScore,  1, 8, scoreToColor(ds));
    txt(DC[2] + 4, curY + 12, domRating, 1, 8, GRAY);
    txt(DC[3] + 4, curY + 12, domDate,   1, 8, GRAY);
    curY += 16;
  }
  if (!(domains || []).length) {
    txt(ML + 4, curY + 12, "No domains in this workspace.", 1, 8, LGRAY);
    curY += 16;
  }

  endPage();   // page 2 done

  // ═══════════════════════════════════════════════════════════════════════════
  // PAGE 3 — SECURITY FINDINGS (may overflow to extra pages)
  // ═══════════════════════════════════════════════════════════════════════════

  sectionBar("SECURITY FINDINGS");

  const SEV_ORDER  = ["critical", "high", "medium", "low"];
  const SEV_LABEL  = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW" };
  const SEV_COLOR  = { critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6" };
  const SEV_BGCOL  = { critical: "#FEE2E2", high: "#FFF0E6", medium: "#FFFBEB", low: "#EFF6FF" };

  const grouped = {};
  for (const sev of SEV_ORDER) grouped[sev] = [];
  for (const f of (findings || [])) {
    const s = (f.severity || "low").toLowerCase();
    if (grouped[s]) grouped[s].push(f);
  }

  let findingNum = 1;
  for (const sev of SEV_ORDER) {
    const items = grouped[sev];
    if (!items.length) continue;

    checkBreak(30);
    fillRect(ML, curY, CW, 18, SEV_BGCOL[sev]);
    txt(ML + 6, curY + 13, `${SEV_LABEL[sev]}  (${items.length})`, 2, 9, SEV_COLOR[sev]);
    curY += 22;

    for (const f of items) {
      checkBreak(44);

      // Finding title + domain on same line
      txt(ML + 8, curY, `${findingNum}.  ${(f.title || "Untitled").slice(0, 68)}`, 2, 9, "#111111");
      txt(PW - MR - 110, curY, (f.domain || "").slice(0, 28), 1, 7, LGRAY);
      curY += 14;

      // Description (truncated to fit one line ~95 chars)
      const desc = (f.recommendation || "").slice(0, 100);
      if (desc) {
        txt(ML + 14, curY, desc, 1, 8, GRAY);
        curY += 13;
      }

      hline(ML + 6, PW - MR, curY, 0.3, "#EEEEEE");
      curY += 7;
      findingNum++;
    }
    curY += 6;
  }

  if (!(findings || []).length) {
    txt(ML, curY, "No findings recorded for this workspace.", 1, 9, LGRAY);
    curY += 16;
  }

  endPage();   // findings page(s) done

  // ═══════════════════════════════════════════════════════════════════════════
  // FINAL PAGE — RECOMMENDATIONS + HISTORICAL TREND
  // ═══════════════════════════════════════════════════════════════════════════

  sectionBar("RECOMMENDATIONS");

  const recs = (recommendations || []).slice(0, 10);
  if (recs.length) {
    for (let i = 0; i < recs.length; i++) {
      const r = recs[i];
      checkBreak(52);

      // Priority badge
      fillRect(ML, curY, 20, 20, BRAND);
      txt(ML + 5, curY + 14, String(r.priority || i + 1), 2, 9, "#FFFFFF");

      txt(ML + 28, curY + 14, (r.title || "Action Required").slice(0, 70), 2, 9, "#111111");
      curY += 22;

      const action = (r.action || "").slice(0, 110);
      if (action) {
        txt(ML + 28, curY, action, 1, 8, GRAY);
        curY += 13;
      }
      if (r.domain) {
        txt(ML + 28, curY, `Domain: ${r.domain}`, 1, 7, LGRAY);
        curY += 12;
      }
      hline(ML, PW - MR, curY + 2, 0.3, "#EEEEEE");
      curY += 10;
    }
  } else {
    txt(ML, curY, "No recommendations available.", 1, 9, LGRAY);
    curY += 16;
  }

  curY += 14;
  checkBreak(80);
  sectionBar("HISTORICAL TREND");

  // Trend table header
  const TC = [ML, ML + 150, ML + 250, ML + 340, ML + 430];
  fillRect(ML, curY, CW, 18, BG2);
  txt(TC[0] + 4, curY + 13, "Domain",         2, 8, "#333333");
  txt(TC[1] + 4, curY + 13, "Date",           2, 8, "#333333");
  txt(TC[2] + 4, curY + 13, "Previous",       2, 8, "#333333");
  txt(TC[3] + 4, curY + 13, "Current",        2, 8, "#333333");
  txt(TC[4] + 4, curY + 13, "Change",         2, 8, "#333333");
  curY += 20;

  for (const t of (trend || [])) {
    checkBreak(17);
    const change      = t.score_change != null
      ? (t.score_change >= 0 ? `+${t.score_change}` : String(t.score_change))
      : "—";
    const changeColor = t.score_change == null  ? GRAY
      : t.score_change > 0  ? BRAND
      : t.score_change < 0  ? "#EF4444" : GRAY;

    hline(ML, PW - MR, curY, 0.3, "#EEEEEE");
    txt(TC[0] + 4, curY + 12, (t.domain           || "—").slice(0, 25), 1, 8, "#111111");
    txt(TC[1] + 4, curY + 12, (t.date             || "—"),               1, 8, GRAY);
    txt(TC[2] + 4, curY + 12, t.previous_score != null ? String(t.previous_score) : "—", 1, 8, GRAY);
    txt(TC[3] + 4, curY + 12, t.current_score  != null ? String(t.current_score)  : "—", 1, 8, GRAY);
    txt(TC[4] + 4, curY + 12, change, 2, 8, changeColor);
    curY += 16;
  }

  if (!(trend || []).length) {
    txt(ML, curY, "No trend data yet. Run multiple scans per domain to populate this section.", 1, 8, LGRAY);
    curY += 14;
  }

  endPage();   // final page done

  return streams;
}

// ── Scheduled Scan Helpers ────────────────────────────────────────────────────

/**
 * Return the ISO timestamp for the next run based on frequency.
 * Supported: 'daily' (24 h) and 'weekly' (7 days). Defaults to daily.
 */
function computeNextRunAt(frequency) {
  const hours = frequency === "weekly" ? 7 * 24 : 24;
  return new Date(Date.now() + hours * 60 * 60 * 1_000).toISOString();
}

/**
 * Create and run a scan for one scheduled_scans row.
 * This function is always called inside ctx.waitUntil() so it is safe to await
 * runScanEngine directly — we are already within the extended Worker lifetime.
 * Never throws — a failure on one schedule must not abort others.
 */
async function triggerScheduledScan(schedule, env) {
  const userId = "user_demo";
  const scanId = createId("scan");
  const now    = new Date().toISOString();

  try {
    // Ensure demo user exists
    await env.cybermeters_db
      .prepare(
        `INSERT INTO users (id, email, name, plan)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(id) DO NOTHING`
      )
      .bind(userId, "demo@cybermeters.com", "Demo User", "free")
      .run();

    // ── Reuse existing domain row so inventory stays on one domain_id ─────────
    // Creating a new row on every run fragments history and breaks workspace links.
    let domainId;
    const existingDomain = await env.cybermeters_db
      .prepare(`SELECT id FROM domains WHERE user_id = ? AND domain = ? LIMIT 1`)
      .bind(userId, schedule.domain)
      .first();

    if (existingDomain) {
      domainId = existingDomain.id;
    } else {
      domainId = createId("domain");
      await env.cybermeters_db
        .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
        .bind(domainId, userId, schedule.domain)
        .run();
    }

    // ── Ensure workspace_domains link exists (idempotent) ─────────────────────
    // This allows upsertAssetInventory and sendAssetChangeAlert to find the
    // workspace for this domain, even if the schedule was created before the
    // workspace link was set up.
    if (schedule.workspace_id) {
      await env.cybermeters_db
        .prepare(
          `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id)
           VALUES (?, ?)`
        )
        .bind(schedule.workspace_id, domainId)
        .run();
    }

    // Create scan row
    await env.cybermeters_db
      .prepare(`INSERT INTO scans (id, domain_id, domain, status) VALUES (?, ?, ?, ?)`)
      .bind(scanId, domainId, schedule.domain, "running")
      .run();

    // Write placeholder report so GET /report returns 200 immediately
    await env.cybermeters_reports.put(
      `reports/${scanId}.json`,
      JSON.stringify({
        scan_id:             scanId,
        domain_id:           domainId,
        domain:              schedule.domain,
        status:              "running",
        cyber_metrics_score: 0,
        risk_level:          "unknown",
        findings:            [],
        recommendations:     [],
        message:             "Scheduled scan in progress.",
      }, null, 2),
      { httpMetadata: { contentType: "application/json" } }
    );

    // Stamp last_run_at and compute next_run_at before starting the engine
    await env.cybermeters_db
      .prepare(
        `UPDATE scheduled_scans SET last_run_at = ?, next_run_at = ? WHERE id = ?`
      )
      .bind(now, computeNextRunAt(schedule.frequency), schedule.id)
      .run();

    console.log("[scheduled-monitoring]", JSON.stringify({
      schedule_id:  schedule.id,
      workspace_id: schedule.workspace_id ?? null,
      domain:       schedule.domain,
      scan_id:      scanId,
      domain_id:    domainId,
    }));

    // Run the full scan engine — awaited inside waitUntil context
    await runScanEngine(scanId, domainId, schedule.domain, env);

    // ── Update asset counts after scan completes ───────────────────────────────
    if (schedule.workspace_id) {
      try {
        const [eventsResult, totalResult] = await Promise.all([
          env.cybermeters_db
            .prepare(
              `SELECT event_type FROM asset_events
               WHERE scan_id = ? AND workspace_id = ?`
            )
            .bind(scanId, schedule.workspace_id)
            .all(),
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(*) AS n FROM workspace_assets
               WHERE workspace_id = ? AND status = 'active'`
            )
            .bind(schedule.workspace_id)
            .first(),
        ]);
        const changeCount = (eventsResult.results || []).filter(
          (e) => e.event_type === "new_asset_discovered" || e.event_type === "asset_reappeared"
        ).length;
        await env.cybermeters_db
          .prepare(
            `UPDATE scheduled_scans
             SET last_asset_count = ?, asset_change_count = ?
             WHERE id = ?`
          )
          .bind(totalResult?.n ?? 0, changeCount, schedule.id)
          .run();
        console.log("[scheduled-monitoring]", JSON.stringify({
          schedule_id:        schedule.id,
          workspace_id:       schedule.workspace_id,
          scan_id:            scanId,
          last_asset_count:   totalResult?.n ?? 0,
          asset_change_count: changeCount,
        }));
      } catch (e) {
        console.error("[scheduled-monitoring] asset count update failed:", e?.message);
      }
    }

    // ── Alert phase ──────────────────────────────────────────────────────────
    // Runs after runScanEngine so historical_changes and SSL data are fully
    // written to R2.  Each alert is fire-and-forget from its own try/catch so
    // one delivery failure never blocks the others, and no error ever surfaces
    // to callers or interrupts scan completion.
    try {
      const obj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
      if (obj) {
        const report = await obj.json();
        const hist   = report.modules?.historical_changes;
        const ssl    = report.modules?.ssl;

        // 1. Score drop ≥ 10 points
        if (hist?.has_previous && hist.score_change != null && hist.score_change <= -10) {
          try {
            await sendScoreDropAlert(
              schedule.domain, scanId,
              hist.score_change, hist.previous_score, hist.current_score,
              env
            );
          } catch { /* swallow */ }
        }

        // 2. New subdomain takeover risks
        if (hist?.new_takeover_risks?.length > 0) {
          try {
            await sendTakeoverAlert(schedule.domain, scanId, hist.new_takeover_risks, env);
          } catch { /* swallow */ }
        }

        // 3. SSL certificate expires within 30 days
        if (ssl?.cert_expiry_days != null && ssl.cert_expiry_days <= 30) {
          try {
            await sendSslExpiryAlert(
              schedule.domain, scanId,
              ssl.cert_expiry_days, ssl.cert_not_after,
              env
            );
          } catch { /* swallow */ }
        }

        // 4. New critical or high-severity findings (via generic alert path)
        if (hist?.has_previous) {
          const criticalNew = (hist.new_findings || []).filter(
            f => f.severity === "critical" || f.severity === "high"
          );
          if (criticalNew.length > 0) {
            try {
              const triggers = [{ type: "new_finding", findings: criticalNew.map(f => ({ title: f.title, severity: f.severity })) }];
              const { subject, text, html } = buildAlertEmail(schedule.domain, scanId, triggers);
              await sendAlertEmail(subject, text, html, env, "ALERT_EMAIL_FROM");
            } catch { /* swallow */ }
          }
        }
      }
    } catch {
      // Alert errors must not affect scan completion
    }
  } catch {
    // Graceful failure — one schedule erroring must not affect the others
  }
}

// ── CORS ──────────────────────────────────────────────────────────────────────

const corsHeaders = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

function json(data, status = 200) {
  return Response.json(data, { status, headers: corsHeaders });
}

// ── Worker Handler ────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // ── OPTIONS preflight ───────────────────────────────────────────────
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    // ── GET /health ─────────────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/health") {
      return json({
        status:  "ok",
        service: "cybermeters-scan-api",
      });
    }

    // ── POST /api/scan ──────────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/scan") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const domain      = body.domain?.trim().toLowerCase();
      const workspaceId = body.workspace_id ? String(body.workspace_id).trim() : null;

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }

      // Optional workspace validation — 404 early if supplied ID doesn't exist
      if (workspaceId) {
        const ws = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(workspaceId)
          .first();
        if (!ws) {
          return json({ error: "Workspace not found" }, 404);
        }
      }

      const userId   = "user_demo";
      const domainId = createId("domain");
      const scanId   = createId("scan");
      const reportKey = `reports/${scanId}.json`;

      // Ensure demo user exists
      await env.cybermeters_db
        .prepare(
          `INSERT INTO users (id, email, name, plan)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(id) DO NOTHING`
        )
        .bind(userId, "demo@cybermeters.com", "Demo User", "free")
        .run();

      // Register domain — reuse existing row for same domain string
      const existingDomain = await env.cybermeters_db
        .prepare(`SELECT id FROM domains WHERE domain = ? LIMIT 1`)
        .bind(domain)
        .first();

      const resolvedDomainId = existingDomain ? existingDomain.id : domainId;

      if (!existingDomain) {
        await env.cybermeters_db
          .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
          .bind(domainId, userId, domain)
          .run();
      }

      // Link domain to workspace if workspace_id was provided
      if (workspaceId) {
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id)
             VALUES (?, ?)`
          )
          .bind(workspaceId, resolvedDomainId)
          .run();
      }

      // Create scan row — status 'running' (engine starts immediately)
      await env.cybermeters_db
        .prepare(
          `INSERT INTO scans (id, domain_id, domain, status) VALUES (?, ?, ?, ?)`
        )
        .bind(scanId, resolvedDomainId, domain, "running")
        .run();

      // Write placeholder report to R2 so GET /report returns 200 immediately
      await env.cybermeters_reports.put(
        reportKey,
        JSON.stringify({
          scan_id:             scanId,
          domain_id:           resolvedDomainId,
          domain,
          status:              "running",
          cyber_metrics_score: 0,
          risk_level:          "unknown",
          findings:            [],
          recommendations:     [],
          message:             "Scan engine is running. Poll GET /api/scans/:id for completion.",
        }, null, 2),
        { httpMetadata: { contentType: "application/json" } }
      );

      // Fire the scan engine after the response is sent
      ctx.waitUntil(runScanEngine(scanId, resolvedDomainId, domain, env));

      return json(
        {
          status:       "running",
          scan_id:      scanId,
          domain_id:    resolvedDomainId,
          domain,
          report_key:   reportKey,
          ...(workspaceId ? { workspace_id: workspaceId } : {}),
          message:      "Scan engine started. Poll GET /api/scans/:id until status is completed, then GET /api/scans/:id/report.",
        },
        202
      );
    }

    // ── GET /api/scans ──────────────────────────────────────────────────
    // Supports optional ?workspace_id= to scope results to a single workspace.
    if (request.method === "GET" && url.pathname === "/api/scans") {
      const wsFilter = url.searchParams.get("workspace_id");

      let result;
      if (wsFilter) {
        // Return only scans whose domain is linked to the requested workspace
        result = await env.cybermeters_db
          .prepare(
            `SELECT s.id, s.domain, s.status, s.score, s.rating, s.created_at
             FROM scans s
             JOIN domains d ON d.id = s.domain_id
             JOIN workspace_domains wd ON wd.domain_id = d.id
             WHERE wd.workspace_id = ?
             ORDER BY s.created_at DESC
             LIMIT 20`
          )
          .bind(wsFilter)
          .all();
      } else {
        result = await env.cybermeters_db
          .prepare(
            `SELECT id, domain, status, score, rating, created_at
             FROM scans
             ORDER BY created_at DESC
             LIMIT 20`
          )
          .all();
      }

      return json({ scans: result.results, ...(wsFilter ? { workspace_id: wsFilter } : {}) });
    }

    // ── GET /api/scans/:id/report ───────────────────────────────────────
    // Must be checked BEFORE the generic /api/scans/:id route below.
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/report$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];

      const scan = await env.cybermeters_db
        .prepare(
          `SELECT id, domain_id, domain, status, score, rating, created_at
           FROM scans WHERE id = ?`
        )
        .bind(scanId)
        .first();

      if (!scan) {
        return json({ error: "Scan not found" }, 404);
      }

      const obj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
      if (!obj) {
        return json({ error: "Report not found" }, 404);
      }

      const raw = await obj.json();

      // Normalise modules — ensure every module key is present even for reports
      // stored before a module was introduced (backward-compatible defaults).
      const storedModules = raw.modules ?? {};
      const normalisedModules = {
        ...storedModules,
        asset_exposure: storedModules.asset_exposure ?? {
          checked:   0,
          reachable: 0,
          assets:    [],
          source:    "http_probe",
          error:     null,
        },
        subdomain_takeover: storedModules.subdomain_takeover ?? {
          checked:         0,
          potential_risks: 0,
          risks:           [],
          source:          "subdomain_cname_fingerprint",
          error:           null,
        },
        historical_changes: storedModules.historical_changes ?? {
          has_previous:       false,
          previous_scan_id:   null,
          previous_score:     null,
          current_score:      null,
          score_change:       null,
          new_subdomains:     [],
          removed_subdomains: [],
          new_findings:       [],
          resolved_findings:  [],
          new_takeover_risks: [],
          new_exposed_assets: [],
          source:             "previous_scan_comparison",
          error:              null,
        },
      };

      return json({
        scan_id:             scan.id,
        domain:              scan.domain,
        status:              scan.status,
        cyber_metrics_score: raw.cyber_metrics_score ?? 0,
        risk_level:          raw.risk_level          ?? "unknown",
        findings:            Array.isArray(raw.findings)        ? raw.findings        : [],
        recommendations:     Array.isArray(raw.recommendations) ? raw.recommendations : [],
        modules:             normalisedModules,
        ...(raw.started_at   ? { started_at:   raw.started_at   } : {}),
        ...(raw.completed_at ? { completed_at: raw.completed_at } : {}),
        ...(raw.failed_at    ? { failed_at:    raw.failed_at    } : {}),
        ...(raw.message      ? { message:      raw.message      } : {}),
        ...(raw.error        ? { error:        raw.error        } : {}),
      });
    }

    // ── GET /api/scans/:id ──────────────────────────────────────────────
    if (
      request.method === "GET" &&
      url.pathname.startsWith("/api/scans/")
    ) {
      const scanId = url.pathname.split("/").pop();

      const scan = await env.cybermeters_db
        .prepare(
          `SELECT id, domain_id, domain, status, score, rating, created_at
           FROM scans WHERE id = ?`
        )
        .bind(scanId)
        .first();

      if (!scan) {
        return json({ error: "Scan not found" }, 404);
      }

      return json({
        scan,
        report_key: `reports/${scan.id}.json`,
      });
    }

    // ── GET /api/domain/:domain/history ────────────────────────────────
    if (
      request.method === "GET" &&
      url.pathname.startsWith("/api/domain/") &&
      url.pathname.endsWith("/history")
    ) {
      const parts  = url.pathname.split("/");
      const domain = decodeURIComponent(parts[3]);

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }

      const history = await env.cybermeters_db
        .prepare(
          `SELECT id, domain_id, domain, status, score, rating, created_at
           FROM scans
           WHERE domain = ?
           ORDER BY created_at DESC`
        )
        .bind(domain)
        .all();

      return json({ domain, scans: history.results });
    }

    // ── POST /api/schedules ─────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/schedules") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const domain      = (body.domain || "").trim().toLowerCase();
      const frequency   = (body.frequency || "daily").trim().toLowerCase();
      const workspaceId = (body.workspace_id || "").trim() || null;

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }
      if (!["daily", "weekly"].includes(frequency)) {
        return json({ error: "frequency must be 'daily' or 'weekly'" }, 400);
      }

      // Create the table if it doesn't exist yet (idempotent — includes new columns)
      await env.cybermeters_db
        .prepare(
          `CREATE TABLE IF NOT EXISTS scheduled_scans (
             id TEXT PRIMARY KEY,
             domain TEXT NOT NULL,
             frequency TEXT NOT NULL DEFAULT 'daily',
             enabled INTEGER NOT NULL DEFAULT 1,
             last_run_at TEXT,
             next_run_at TEXT,
             workspace_id TEXT,
             last_asset_count INTEGER DEFAULT 0,
             asset_change_count INTEGER DEFAULT 0,
             created_at TEXT DEFAULT (datetime('now'))
           )`
        )
        .run();

      const schedId    = createId("sched");
      const nextRunAt  = computeNextRunAt(frequency);
      const createdAt  = new Date().toISOString();

      await env.cybermeters_db
        .prepare(
          `INSERT INTO scheduled_scans (id, domain, frequency, enabled, next_run_at, workspace_id, created_at)
           VALUES (?, ?, ?, 1, ?, ?, ?)`
        )
        .bind(schedId, domain, frequency, nextRunAt, workspaceId, createdAt)
        .run();

      return json({
        schedule: {
          id:                 schedId,
          domain,
          frequency,
          enabled:            1,
          workspace_id:       workspaceId,
          last_asset_count:   0,
          asset_change_count: 0,
          last_run_at:        null,
          next_run_at:        nextRunAt,
          created_at:         createdAt,
        },
      }, 201);
    }

    // ── GET /api/schedules ──────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/schedules") {
      // Return empty list if table doesn't exist yet
      try {
        const result = await env.cybermeters_db
          .prepare(
            `SELECT id, domain, frequency, enabled, workspace_id,
                    last_asset_count, asset_change_count,
                    last_run_at, next_run_at, created_at
             FROM scheduled_scans
             ORDER BY created_at DESC`
          )
          .all();
        return json({ schedules: result.results });
      } catch {
        return json({ schedules: [] });
      }
    }

    // ── DELETE /api/schedules/:id ───────────────────────────────────────
    if (
      request.method === "DELETE" &&
      url.pathname.startsWith("/api/schedules/")
    ) {
      const schedId = url.pathname.split("/").pop();
      if (!schedId) {
        return json({ error: "Missing schedule id" }, 400);
      }

      try {
        const result = await env.cybermeters_db
          .prepare(`DELETE FROM scheduled_scans WHERE id = ?`)
          .bind(schedId)
          .run();

        if (result.meta?.changes === 0) {
          return json({ error: "Schedule not found" }, 404);
        }
      } catch {
        return json({ error: "Schedule not found" }, 404);
      }

      return json({ deleted: schedId });
    }

    // ── Workspace Routes ──────────────────────────────────────────────────

    // GET /api/workspaces/:id/report — executive PDF report
    // Tested before the generic wsMatch so "/report" is never confused with a
    // domain ID.
    const reportMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/report$/);
    if (reportMatch && request.method === "GET") {
      const wsId = reportMatch[1];

      // 1. Workspace row
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare(`SELECT id, name, created_at FROM workspaces WHERE id = ?`)
          .bind(wsId).first();
      } catch { /* fall through */ }
      if (!ws) return json({ error: "Workspace not found" }, 404);

      // 2. Stats (4 parallel D1 queries)
      const [domRow, scanRow, avgRow, latestRow] = await Promise.all([
        env.cybermeters_db.prepare(
          `SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id = ?`
        ).bind(wsId).first(),
        env.cybermeters_db.prepare(
          `SELECT COUNT(DISTINCT s.id) AS n
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed'`
        ).bind(wsId).first(),
        env.cybermeters_db.prepare(
          `SELECT AVG(s.score) AS avg
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed' AND s.score IS NOT NULL`
        ).bind(wsId).first(),
        env.cybermeters_db.prepare(
          `SELECT s.id, s.domain, s.created_at
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed'
           ORDER BY s.created_at DESC LIMIT 1`
        ).bind(wsId).first(),
      ]).catch(() => [null, null, null, null]);

      const stats = {
        total_domains:        domRow?.n    ?? 0,
        total_scans:          scanRow?.n   ?? 0,
        cyber_score_average:  avgRow?.avg  ?? null,
        latest_scan:          latestRow    ?? null,
      };

      // 3. Domains enriched with latest scan
      let domains = [];
      try {
        const dr = await env.cybermeters_db.prepare(
          `SELECT d.id AS domain_id, d.domain,
                  s.id AS last_scan_id, s.score AS latest_score,
                  s.status AS latest_status, s.created_at AS last_scanned_at
           FROM workspace_domains wd
           JOIN domains d ON d.id = wd.domain_id
           LEFT JOIN scans s ON s.id = (
             SELECT id FROM scans WHERE domain_id = d.id ORDER BY created_at DESC LIMIT 1
           )
           WHERE wd.workspace_id = ?
           ORDER BY d.domain ASC`
        ).bind(wsId).all();
        domains = dr.results || [];
      } catch { /* tolerate */ }

      // 4. Top findings (ordered by severity then recency)
      let findings = [];
      try {
        const fr = await env.cybermeters_db.prepare(
          `SELECT f.title, f.severity, f.recommendation, s.domain
           FROM findings f
           JOIN scans s ON s.id = f.scan_id
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ?
           ORDER BY CASE f.severity
             WHEN 'critical' THEN 1 WHEN 'high' THEN 2
             WHEN 'medium'   THEN 3                ELSE 4 END,
             s.created_at DESC
           LIMIT 30`
        ).bind(wsId).all();
        findings = fr.results || [];
      } catch { /* tolerate */ }

      // 5. Recommendations
      let recommendations = [];
      try {
        const rr = await env.cybermeters_db.prepare(
          `SELECT r.title, r.priority, r.action, r.reason, s.domain
           FROM remediation_items r
           JOIN scans s ON s.id = r.scan_id
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ?
           ORDER BY r.priority ASC
           LIMIT 10`
        ).bind(wsId).all();
        recommendations = rr.results || [];
      } catch { /* tolerate */ }

      // 6. Historical trend — last 2 completed scans per domain
      let trend = [];
      try {
        const tr = await env.cybermeters_db.prepare(
          `SELECT s.domain, s.score AS current_score, s.created_at
           FROM scans s
           JOIN domains d ON d.id = s.domain_id
           JOIN workspace_domains wd ON wd.domain_id = d.id
           WHERE wd.workspace_id = ? AND s.status = 'completed' AND s.score IS NOT NULL
           ORDER BY s.created_at DESC
           LIMIT 20`
        ).bind(wsId).all();

        // Group by domain, keep newest two
        const byDomain = {};
        for (const row of (tr.results || [])) {
          if (!byDomain[row.domain]) byDomain[row.domain] = [];
          if (byDomain[row.domain].length < 2) byDomain[row.domain].push(row);
        }
        for (const [domain, rows] of Object.entries(byDomain)) {
          const cur  = rows[0];
          const prev = rows[1] ?? null;
          trend.push({
            domain,
            date: cur.created_at
              ? new Date((cur.created_at || "").replace(" ", "T") + "Z")
                  .toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })
              : "—",
            current_score:  cur.current_score,
            previous_score: prev?.current_score ?? null,
            score_change:   prev != null ? cur.current_score - prev.current_score : null,
          });
        }
      } catch { /* tolerate */ }

      // 7. Build PDF
      try {
        const streams = buildPdfStreams({ workspace: ws, stats, domains, findings, recommendations, trend });
        const pdfText = assemblePdf(streams);
        const pdfBytes = new TextEncoder().encode(pdfText);
        const safeName = (ws.name || "workspace").replace(/[^a-zA-Z0-9]+/g, "-").toLowerCase();

        return new Response(pdfBytes, {
          status: 200,
          headers: {
            ...corsHeaders,
            "Content-Type":        "application/pdf",
            "Content-Disposition": `attachment; filename="cybermeters-${safeName}-report.pdf"`,
            "Content-Length":      String(pdfBytes.length),
          },
        });
      } catch (e) {
        return json({ error: "PDF generation failed", detail: e.message }, 500);
      }
    }

    // GET /api/workspaces — list all workspaces
    if (request.method === "GET" && url.pathname === "/api/workspaces") {
      try {
        const result = await env.cybermeters_db
          .prepare(`SELECT id, name, created_at FROM workspaces ORDER BY created_at DESC`)
          .all();
        return json({ workspaces: result.results });
      } catch {
        return json({ error: "Database error" }, 500);
      }
    }

    // POST /api/workspaces — create a workspace
    if (request.method === "POST" && url.pathname === "/api/workspaces") {
      let body;
      try { body = await request.json(); } catch { body = {}; }
      const name = (body.name || "").trim();
      if (!name) {
        return json({ error: "name is required" }, 400);
      }
      const id         = `workspace_${crypto.randomUUID()}`;
      const created_at = new Date().toISOString();
      try {
        await env.cybermeters_db
          .prepare(`INSERT INTO workspaces (id, name, created_at) VALUES (?, ?, ?)`)
          .bind(id, name, created_at)
          .run();
        return json({ workspace: { id, name, created_at } }, 201);
      } catch {
        return json({ error: "Database error" }, 500);
      }
    }

    // ── /api/workspaces/:id/assets/* ────────────────────────────────────────
    // Handles list, events, summary, timeline, and per-asset detail.
    const assetsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/assets(\/[^/]*)?$/);
    if (assetsMatch && request.method === "GET") {
      const wsId  = assetsMatch[1];
      const sub   = assetsMatch[2] ?? "";   // "", "/events", "/summary", "/timeline", "/:assetId"

      // Verify workspace exists and enforce tenant isolation
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!ws) return json({ error: "Workspace not found" }, 404);

      // ── GET /api/workspaces/:id/assets ───────────────────────────────────
      if (sub === "") {
        const statusFilter = url.searchParams.get("status");
        const limit        = Math.min(parseInt(url.searchParams.get("limit") || "200", 10), 500);
        try {
          const where = statusFilter ? "AND status = ?" : "";
          const binds = statusFilter ? [wsId, statusFilter, limit] : [wsId, limit];
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, hostname, asset_type, source,
                      first_seen, last_seen, status, wildcard_dns,
                      ip_addresses, cname, redirect_to, cloud_provider,
                      risk_level, metadata_json, created_at, updated_at
               FROM workspace_assets
               WHERE workspace_id = ? ${where}
               ORDER BY last_seen DESC LIMIT ?`
            )
            .bind(...binds)
            .all();
          return json({ workspace_id: wsId, count: result.results.length, assets: result.results });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/events ────────────────────────────
      if (sub === "/events") {
        const limit = Math.min(parseInt(url.searchParams.get("limit") || "100", 10), 500);
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at
               FROM asset_events
               WHERE workspace_id = ?
               ORDER BY created_at DESC LIMIT ?`
            )
            .bind(wsId, limit)
            .all();
          return json({ workspace_id: wsId, count: result.results.length, events: result.results });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/summary ───────────────────────────
      if (sub === "/summary") {
        try {
          const [all, active, inactive, rootDomains, subdomains, exposedSvcs, cloudStorage, wildcardAssets, takeoverRisks] =
            await env.cybermeters_db.batch([
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ?`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'inactive'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'root_domain'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'subdomain'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'exposed_service'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'cloud_storage'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND wildcard_dns = 1`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND risk_level IN ('high','critical')`).bind(wsId),
            ]);
          return json({
            workspace_id:       wsId,
            total_assets:       all.results[0]?.n         ?? 0,
            active_assets:      active.results[0]?.n      ?? 0,
            inactive_assets:    inactive.results[0]?.n    ?? 0,
            root_domains:       rootDomains.results[0]?.n ?? 0,
            subdomains:         subdomains.results[0]?.n  ?? 0,
            exposed_services:   exposedSvcs.results[0]?.n ?? 0,
            cloud_storage_assets: cloudStorage.results[0]?.n ?? 0,
            wildcard_assets:    wildcardAssets.results[0]?.n ?? 0,
            takeover_risks:     takeoverRisks.results[0]?.n  ?? 0,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/timeline ──────────────────────────
      if (sub === "/timeline") {
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT date(created_at) AS day, event_type, COUNT(*) AS count
               FROM asset_events
               WHERE workspace_id = ?
               GROUP BY day, event_type
               ORDER BY day ASC`
            )
            .bind(wsId)
            .all();

          // Pivot rows into { day, new_asset_discovered, asset_reappeared, ... }
          const dayMap = new Map();
          const EVENT_TYPES = [
            "new_asset_discovered", "asset_reappeared", "asset_no_longer_seen",
            "takeover_risk_detected", "wildcard_dns_detected", "cloud_storage_detected",
          ];
          for (const row of result.results) {
            if (!dayMap.has(row.day)) {
              const entry = { day: row.day };
              for (const t of EVENT_TYPES) entry[t] = 0;
              dayMap.set(row.day, entry);
            }
            if (EVENT_TYPES.includes(row.event_type)) {
              dayMap.get(row.day)[row.event_type] = row.count;
            }
          }
          return json({ workspace_id: wsId, timeline: [...dayMap.values()] });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/:assetId ──────────────────────────
      {
        const assetId = sub.slice(1);   // strip leading "/"
        try {
          const asset = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, hostname, asset_type, source,
                      first_seen, last_seen, status, wildcard_dns,
                      ip_addresses, cname, redirect_to, cloud_provider,
                      risk_level, metadata_json, created_at, updated_at
               FROM workspace_assets
               WHERE id = ? AND workspace_id = ?`
            )
            .bind(assetId, wsId)
            .first();
          if (!asset) return json({ error: "Asset not found" }, 404);

          const eventsResult = await env.cybermeters_db
            .prepare(
              `SELECT id, scan_id, event_type, hostname, severity, description, created_at
               FROM asset_events
               WHERE asset_id = ? AND workspace_id = ?
               ORDER BY created_at DESC LIMIT 50`
            )
            .bind(assetId, wsId)
            .all();

          return json({ asset, events: eventsResult.results });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }
    }

    // ── /api/workspaces/:id/alerts/* ────────────────────────────────────────
    // GET /api/workspaces/:id/alerts          — list alerts, filterable by severity
    // GET /api/workspaces/:id/alerts/summary  — severity counts + last alert timestamp
    const alertsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/alerts(\/[^/]*)?$/);
    if (alertsMatch && request.method === "GET") {
      const wsId = alertsMatch[1];
      const sub  = alertsMatch[2] ?? "";   // "" or "/summary"

      // Tenant isolation — verify workspace exists
      let wsExists;
      try {
        wsExists = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!wsExists) return json({ error: "Workspace not found" }, 404);

      // ── GET /api/workspaces/:id/alerts/summary ─────────────────────────────
      if (sub === "/summary") {
        try {
          const [total, critical, high, medium, low, latest] =
            await env.cybermeters_db.batch([
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ?`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'critical'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'high'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'medium'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'low'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT sent_at FROM asset_alert_records WHERE workspace_id = ? ORDER BY sent_at DESC LIMIT 1`)
                .bind(wsId),
            ]);
          return json({
            workspace_id:       wsId,
            total:              total.results[0]?.n    ?? 0,
            critical:           critical.results[0]?.n ?? 0,
            high:               high.results[0]?.n     ?? 0,
            medium:             medium.results[0]?.n   ?? 0,
            low:                low.results[0]?.n      ?? 0,
            last_alert_at:      latest.results[0]?.sent_at ?? null,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/alerts ─────────────────────────────────────
      if (sub === "") {
        const severityFilter = url.searchParams.get("severity");
        const limit          = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 200);
        const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

        if (severityFilter && !VALID_SEVERITIES.has(severityFilter)) {
          return json({ error: "Invalid severity value" }, 400);
        }

        try {
          const where  = severityFilter ? "AND severity = ?" : "";
          const binds  = severityFilter ? [wsId, severityFilter, limit] : [wsId, limit];
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, scan_id, domain, severity,
                      event_counts, top_hostnames, sent_at
               FROM asset_alert_records
               WHERE workspace_id = ? ${where}
               ORDER BY sent_at DESC
               LIMIT ?`
            )
            .bind(...binds)
            .all();

          // Parse JSON columns so consumers don't have to
          const alerts = (result.results || []).map((row) => ({
            ...row,
            event_counts:  row.event_counts  ? JSON.parse(row.event_counts)  : {},
            top_hostnames: row.top_hostnames ? JSON.parse(row.top_hostnames) : [],
          }));

          return json({ workspace_id: wsId, count: alerts.length, alerts });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // Unknown sub-resource
      return json({ error: "Not found" }, 404);
    }

    // ── /api/workspaces/:id/posture[/timeline] ──────────────────────────────
    // GET /api/workspaces/:id/posture          — current attack surface posture snapshot
    // GET /api/workspaces/:id/posture/timeline — daily metric series (last 90 days)
    //
    // Both routes use existing data only (workspace_assets, asset_events, scans,
    // findings, workspace_domains).  No new scanning modules, no scoring changes.
    const postureMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/posture(\/timeline)?$/);
    if (postureMatch && request.method === "GET") {
      const wsId    = postureMatch[1];
      const isTimeline = !!postureMatch[2];   // true → /posture/timeline

      // Tenant isolation — verify workspace exists
      let wsExists;
      try {
        wsExists = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!wsExists) return json({ error: "Workspace not found" }, 404);

      // ── Attack Surface Size classification ────────────────────────────────
      // 0-10 = Small, 11-50 = Medium, 51-200 = Large, 201+ = Very Large
      function classifyAttackSurface(assetCount) {
        if (assetCount <= 10)  return "Small";
        if (assetCount <= 50)  return "Medium";
        if (assetCount <= 200) return "Large";
        return "Very Large";
      }

      // ── Risk trend helper ─────────────────────────────────────────────────
      // Higher score = safer. Score drop = risk going up.
      function scoreTrend(avgLast, avgPrev) {
        if (avgLast === null || avgPrev === null) return "stable";
        const delta = avgLast - avgPrev;
        if (delta >= 3)  return "down";   // score improved → risk down
        if (delta <= -3) return "up";     // score fell → risk up
        return "stable";
      }

      // ── GET /api/workspaces/:id/posture ───────────────────────────────────
      if (!isTimeline) {
        try {
          const [
            totalRow,
            activeRow,
            newAssets30dRow,
            removedAssets30dRow,
            criticalNow30dRow,
            criticalPrev30dRow,
            avgScoreLast30dRow,
            avgScorePrev30dRow,
          ] = await env.cybermeters_db.batch([

            // Total assets ever tracked in this workspace
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ?`)
              .bind(wsId),

            // Currently active assets
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
              .bind(wsId),

            // Assets first discovered in the last 30 days
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND first_seen >= datetime('now', '-30 days')`)
              .bind(wsId),

            // Assets removed (no-longer-seen events) in the last 30 days
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM asset_events WHERE workspace_id = ? AND event_type = 'asset_no_longer_seen' AND created_at >= datetime('now', '-30 days')`)
              .bind(wsId),

            // Critical findings from scans in the last 30 days (via workspace_domains join)
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(f.id) AS n
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND s.created_at >= datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Critical findings from scans in the preceding 30 days (days -60 to -30)
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(f.id) AS n
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND s.created_at >= datetime('now', '-60 days')
                   AND s.created_at <  datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Average scan score over the last 30 days (for risk trend)
            env.cybermeters_db
              .prepare(
                `SELECT AVG(s.score) AS avg_score
                 FROM scans s
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND s.status = 'completed'
                   AND s.score IS NOT NULL
                   AND s.created_at >= datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Average scan score over the preceding 30 days (days -60 to -30)
            env.cybermeters_db
              .prepare(
                `SELECT AVG(s.score) AS avg_score
                 FROM scans s
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND s.status = 'completed'
                   AND s.score IS NOT NULL
                   AND s.created_at >= datetime('now', '-60 days')
                   AND s.created_at <  datetime('now', '-30 days')`
              )
              .bind(wsId),
          ]);

          const totalAssets    = totalRow.results[0]?.n          ?? 0;
          const activeAssets   = activeRow.results[0]?.n         ?? 0;
          const newAssets30d   = newAssets30dRow.results[0]?.n   ?? 0;
          const removedAssets30d = removedAssets30dRow.results[0]?.n ?? 0;
          const criticalNow    = criticalNow30dRow.results[0]?.n    ?? 0;
          const criticalPrev   = criticalPrev30dRow.results[0]?.n   ?? 0;
          const avgScoreLast30d = avgScoreLast30dRow.results[0]?.avg_score ?? null;
          const avgScorePrev30d = avgScorePrev30dRow.results[0]?.avg_score ?? null;

          const trend = scoreTrend(avgScoreLast30d, avgScorePrev30d);

          return json({
            workspace_id:                wsId,
            attack_surface_size:         classifyAttackSurface(totalAssets),
            total_assets:                totalAssets,
            active_assets:               activeAssets,
            new_assets_30d:              newAssets30d,
            removed_assets_30d:          removedAssets30d,
            asset_growth_30d:            newAssets30d - removedAssets30d,
            critical_findings:           criticalNow,
            critical_findings_change_30d: criticalNow - criticalPrev,
            risk_trend:                  trend,
            score_trend:                 trend,   // same signal; both exposed for consumer flexibility
            avg_score_last_30d:          avgScoreLast30d !== null ? Math.round(avgScoreLast30d) : null,
            avg_score_prev_30d:          avgScorePrev30d !== null ? Math.round(avgScorePrev30d) : null,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/posture/timeline ──────────────────────────
      // Returns one entry per day for the last 90 days.
      // asset_count is derived by applying daily deltas backward from today's total.
      if (isTimeline) {
        try {
          const [totalActiveRow, eventRows, findingRows] = await env.cybermeters_db.batch([

            // Current active asset count — used as the anchor for backward derivation
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
              .bind(wsId),

            // Per-day new / removed event counts for the last 90 days
            env.cybermeters_db
              .prepare(
                `SELECT date(created_at) AS day,
                        SUM(CASE WHEN event_type = 'new_asset_discovered'   THEN 1 ELSE 0 END) AS new_assets,
                        SUM(CASE WHEN event_type = 'asset_no_longer_seen'   THEN 1 ELSE 0 END) AS removed_assets
                 FROM asset_events
                 WHERE workspace_id = ?
                   AND created_at >= datetime('now', '-90 days')
                 GROUP BY day
                 ORDER BY day ASC`
              )
              .bind(wsId),

            // Per-day critical findings count (from scans run that day)
            env.cybermeters_db
              .prepare(
                `SELECT date(s.created_at) AS day, COUNT(f.id) AS critical_findings
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND s.created_at >= datetime('now', '-90 days')
                 GROUP BY day
                 ORDER BY day ASC`
              )
              .bind(wsId),
          ]);

          // Build day-keyed maps from query results
          const eventMap    = new Map();
          const findingMap  = new Map();

          for (const row of (eventRows.results || [])) {
            eventMap.set(row.day, { new_assets: row.new_assets ?? 0, removed_assets: row.removed_assets ?? 0 });
          }
          for (const row of (findingRows.results || [])) {
            findingMap.set(row.day, row.critical_findings ?? 0);
          }

          // Collect every day that appears in either dataset
          const daySet = new Set([...eventMap.keys(), ...findingMap.keys()]);
          const days   = [...daySet].sort();

          // Derive asset_count by walking forward from the earliest day.
          // anchor = total active assets today; walk backward from end → start to seed the
          // starting count, then walk forward to fill in each day's snapshot.
          let runningCount = totalActiveRow.results[0]?.n ?? 0;

          // First pass: walk backward from today to compute the count at the start of `days`
          for (let i = days.length - 1; i >= 0; i--) {
            const d = days[i];
            const ev = eventMap.get(d) ?? { new_assets: 0, removed_assets: 0 };
            runningCount -= ev.new_assets;
            runningCount += ev.removed_assets;
          }

          // Second pass: walk forward, incrementally updating the running count per day
          const timeline = [];
          for (const day of days) {
            const ev = eventMap.get(day) ?? { new_assets: 0, removed_assets: 0 };
            runningCount += ev.new_assets;
            runningCount -= ev.removed_assets;
            timeline.push({
              day,
              asset_count:       Math.max(0, runningCount),
              new_assets:        ev.new_assets,
              removed_assets:    ev.removed_assets,
              critical_findings: findingMap.get(day) ?? 0,
            });
          }

          return json({ workspace_id: wsId, days: timeline.length, timeline });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }
    }

    // ── Third-Party Asset Discovery routes ────────────────────────────────
    // GET /api/workspaces/:id/third-party-assets
    //   Filters: ?category=email|crm|support|collaboration|marketing|ecommerce
    //            ?risk_level=low|medium|high
    //   Returns: { workspace_id, total, assets: [...] }
    //
    // GET /api/workspaces/:id/third-party-assets/summary
    //   Returns: { workspace_id, total, email, crm, support, collaboration,
    //              marketing, ecommerce, high_risk, medium_risk, low_risk }
    const tpaMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/third-party-assets(\/summary)?$/
    );
    if (tpaMatch && request.method === "GET") {
      const wsId      = tpaMatch[1];
      const isSummary = !!tpaMatch[2];

      // Read all workspace_vendors for this workspace; remap + filter in JS.
      // workspace_vendors uses the vendor-risk category taxonomy; we remap here.
      let rows;
      try {
        const r = await env.cybermeters_db
          .prepare(
            `SELECT vendor_name, category, source, evidence, confidence,
                    risk_level, status, first_seen, last_seen
             FROM workspace_vendors
             WHERE workspace_id = ? AND status = 'active'`
          )
          .bind(wsId)
          .all();
        rows = r.results || [];
      } catch {
        return json({ error: "Database error" }, 500);
      }

      // Remap to third-party taxonomy; skip infrastructure/cloud/hosting
      const assets = [];
      for (const row of rows) {
        const tpCategory = remapToThirdPartyCategory(row.vendor_name, row.category);
        if (!tpCategory) continue;

        let parsedEvidence = [];
        try { parsedEvidence = JSON.parse(row.evidence); } catch { /* ignore */ }

        assets.push({
          name:       row.vendor_name,
          category:   tpCategory,
          source:     row.source,
          evidence:   parsedEvidence,
          confidence: row.confidence,
          risk_level: row.risk_level,
          first_seen: row.first_seen,
          last_seen:  row.last_seen,
        });
      }

      // Sort: email → crm → collaboration → support → marketing → ecommerce
      const catOrder = {
        email: 0, crm: 1, collaboration: 2, support: 3, marketing: 4, ecommerce: 5,
      };
      assets.sort((a, b) => (catOrder[a.category] ?? 9) - (catOrder[b.category] ?? 9));

      if (isSummary) {
        const summary = {
          workspace_id:  wsId,
          total:         assets.length,
          email:         0,
          crm:           0,
          support:       0,
          collaboration: 0,
          marketing:     0,
          ecommerce:     0,
          high_risk:     0,
          medium_risk:   0,
          low_risk:      0,
        };
        for (const a of assets) {
          if (a.category in summary) summary[a.category]++;
          if (a.risk_level === "high")        summary.high_risk++;
          else if (a.risk_level === "medium") summary.medium_risk++;
          else if (a.risk_level === "low")    summary.low_risk++;
        }
        return json(summary);
      }

      // Apply optional filters from query string
      const filterCategory = url.searchParams.get("category");
      const filterRisk     = url.searchParams.get("risk_level");
      const filtered = assets.filter((a) => {
        if (filterCategory && a.category !== filterCategory) return false;
        if (filterRisk     && a.risk_level !== filterRisk)   return false;
        return true;
      });

      return json({ workspace_id: wsId, total: filtered.length, assets: filtered });
    }

    // ── Vendor Inventory routes ────────────────────────────────────────────
    // GET /api/workspaces/:id/vendors
    //   Filters: ?status=active|inactive  ?risk_level=low|medium|high
    //            ?category=infrastructure|cloud|email_identity|hosting|saas|
    //                      support|collaboration|ecommerce
    //   Returns: { workspace_id, count, vendors: [...] }
    //
    // GET /api/workspaces/:id/vendors/summary
    //   Returns: { total_vendors, active_vendors, inactive_vendors,
    //              infrastructure, cloud, email_identity, hosting, saas,
    //              support, ecommerce, high_risk, medium_risk, low_risk }
    const vendorsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/vendors(\/summary)?$/);
    if (vendorsMatch && request.method === "GET") {
      const wsId      = vendorsMatch[1];
      const isSummary = !!vendorsMatch[2];

      if (isSummary) {
        // Aggregate counts directly from D1 — one query
        let rows;
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT status, category, risk_level, COUNT(*) AS cnt
               FROM workspace_vendors
               WHERE workspace_id = ?
               GROUP BY status, category, risk_level`
            )
            .bind(wsId)
            .all();
          rows = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        const summary = {
          workspace_id:    wsId,
          total_vendors:   0,
          active_vendors:  0,
          inactive_vendors:0,
          infrastructure:  0,
          cloud:           0,
          email_identity:  0,
          hosting:         0,
          saas:            0,
          support:         0,
          ecommerce:       0,
          high_risk:       0,
          medium_risk:     0,
          low_risk:        0,
        };

        // We need unique vendor counts, not row counts (a vendor appears once).
        // First collect unique vendor names per bucket using a Set approach via JS.
        // Re-query for unique vendor names with their attributes.
        let vendorRows;
        try {
          const r2 = await env.cybermeters_db
            .prepare(
              `SELECT vendor_name, category, risk_level, status
               FROM workspace_vendors
               WHERE workspace_id = ?`
            )
            .bind(wsId)
            .all();
          vendorRows = r2.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        for (const v of vendorRows) {
          summary.total_vendors++;
          if (v.status === "active")   summary.active_vendors++;
          else                         summary.inactive_vendors++;
          const cat = v.category;
          if (cat in summary) summary[cat]++;
          const rl = v.risk_level;
          if (rl === "high")   summary.high_risk++;
          else if (rl === "medium") summary.medium_risk++;
          else if (rl === "low")    summary.low_risk++;
        }

        return json(summary);
      }

      // ── GET /api/workspaces/:id/vendors ──
      const params    = url.searchParams;
      const filterStatus   = params.get("status");
      const filterRisk     = params.get("risk_level");
      const filterCategory = params.get("category");

      // Build WHERE clause dynamically
      const whereClauses = ["workspace_id = ?"];
      const binds        = [wsId];

      if (filterStatus)   { whereClauses.push("status = ?");     binds.push(filterStatus); }
      if (filterRisk)     { whereClauses.push("risk_level = ?"); binds.push(filterRisk); }
      if (filterCategory) { whereClauses.push("category = ?");   binds.push(filterCategory); }

      const whereSQL = whereClauses.join(" AND ");

      let vendors;
      try {
        const r = await env.cybermeters_db
          .prepare(
            `SELECT vendor_name AS name, category, source, evidence, confidence,
                    risk_level, status, first_seen, last_seen
             FROM workspace_vendors
             WHERE ${whereSQL}
             ORDER BY
               CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
               vendor_name`
          )
          .bind(...binds)
          .all();
        vendors = (r.results || []).map((row) => ({
          ...row,
          evidence: (() => { try { return JSON.parse(row.evidence); } catch { return []; } })(),
        }));
      } catch {
        return json({ error: "Database error" }, 500);
      }

      return json({ workspace_id: wsId, count: vendors.length, vendors });
    }

    // Routes that carry a workspace ID
    // Matches:  /api/workspaces/:id
    //           /api/workspaces/:id/domains
    //           /api/workspaces/:id/domains/:domainId
    //           /api/workspaces/:id/stats
    const wsMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)(\/domains(?:\/([^/]+))?|\/stats)?$/
    );

    if (wsMatch) {
      const workspaceId   = wsMatch[1];
      const subResource   = wsMatch[2];          // "/domains", "/domains/:id", "/stats", or undefined
      const linkedDomainId = wsMatch[3];         // domain ID component if present

      // Verify workspace exists for all sub-routes
      let workspace;
      try {
        workspace = await env.cybermeters_db
          .prepare(`SELECT id, name, created_at FROM workspaces WHERE id = ?`)
          .bind(workspaceId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!workspace) {
        return json({ error: "Workspace not found" }, 404);
      }

      // ── GET /api/workspaces/:id ── (with inline statistics) ──────────
      if (request.method === "GET" && !subResource) {
        try {
          const [domainsRow, scansRow, avgRow, latestRow] = await Promise.all([
            // total_domains
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id = ?`)
              .bind(workspaceId).first(),

            // total_scans
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(DISTINCT s.id) AS n
                 FROM workspace_domains wd
                 JOIN domains d ON d.id = wd.domain_id
                 JOIN scans   s ON s.domain_id = d.id
                 WHERE wd.workspace_id = ?`
              )
              .bind(workspaceId).first(),

            // cyber_score_average (completed scans only)
            env.cybermeters_db
              .prepare(
                `SELECT ROUND(AVG(s.score), 1) AS avg
                 FROM workspace_domains wd
                 JOIN domains d ON d.id = wd.domain_id
                 JOIN scans   s ON s.domain_id = d.id
                 WHERE wd.workspace_id = ?
                   AND s.status = 'completed'
                   AND s.score  IS NOT NULL`
              )
              .bind(workspaceId).first(),

            // latest_scan
            env.cybermeters_db
              .prepare(
                `SELECT s.id, s.domain, s.status, s.score, s.rating, s.created_at
                 FROM workspace_domains wd
                 JOIN domains d ON d.id = wd.domain_id
                 JOIN scans   s ON s.domain_id = d.id
                 WHERE wd.workspace_id = ?
                 ORDER BY s.created_at DESC
                 LIMIT 1`
              )
              .bind(workspaceId).first(),
          ]);

          return json({
            workspace: {
              id:         workspace.id,
              name:       workspace.name,
              created_at: workspace.created_at,
            },
            stats: {
              total_domains:       domainsRow?.n ?? 0,
              total_scans:         scansRow?.n  ?? 0,
              cyber_score_average: avgRow?.avg   ?? null,
              latest_scan:         latestRow     ?? null,
            },
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── DELETE /api/workspaces/:id/domains/:domainId ──────────────────
      // Removes the workspace↔domain link only. Domain row is untouched.
      if (request.method === "DELETE" && subResource && linkedDomainId) {
        try {
          const del = await env.cybermeters_db
            .prepare(
              `DELETE FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?`
            )
            .bind(workspaceId, linkedDomainId)
            .run();
          if (del.meta.changes === 0) {
            return json({ error: "Domain link not found" }, 404);
          }
          return json({ success: true, workspace_id: workspaceId, domain_id: linkedDomainId });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/domains ───────────────────────────────
      // Returns linked domains enriched with latest scan data per domain.
      if (request.method === "GET" && subResource === "/domains") {
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT
                 d.id          AS domain_id,
                 d.domain,
                 s.id          AS last_scan_id,
                 s.score       AS latest_score,
                 s.status      AS latest_status,
                 s.created_at  AS last_scanned_at
               FROM workspace_domains wd
               JOIN   domains d ON d.id = wd.domain_id
               LEFT JOIN scans s ON s.id = (
                 SELECT id FROM scans
                 WHERE  domain_id = d.id
                 ORDER  BY created_at DESC LIMIT 1
               )
               WHERE wd.workspace_id = ?
               ORDER BY d.domain ASC`
            )
            .bind(workspaceId)
            .all();
          return json({ workspace_id: workspaceId, domains: result.results });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── POST /api/workspaces/:id/domains ─────────────────────────────
      // Reuse existing domain row if present; create new one otherwise.
      // Idempotent link via INSERT OR IGNORE.
      if (request.method === "POST" && subResource === "/domains") {
        let body;
        try { body = await request.json(); } catch { body = {}; }
        const raw = (body.domain || "").trim().toLowerCase();
        if (!isValidDomain(raw)) {
          return json(
            { error: "domain is required and must be a valid domain" },
            { status: 400 }
          );
        }
        try {
          let domainRow = await env.cybermeters_db
            .prepare(`SELECT id, domain FROM domains WHERE domain = ? LIMIT 1`)
            .bind(raw)
            .first();

          if (!domainRow) {
            const newId = createId("domain");
            await env.cybermeters_db
              .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
              .bind(newId, "user_demo", raw)
              .run();
            domainRow = { id: newId, domain: raw };
          }

          await env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)`
            )
            .bind(workspaceId, domainRow.id)
            .run();

          return json(
            { domain: { domain_id: domainRow.id, domain: domainRow.domain, workspace_id: workspaceId } },
            201
          );
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }
    }

    return json({ error: "Not found" }, 404);
  },

  // ── Cron Handler ──────────────────────────────────────────────────────
  async scheduled(event, env, ctx) {
    const now = new Date().toISOString();

    let result;
    try {
      result = await env.cybermeters_db
        .prepare(
          `SELECT id, domain, frequency, workspace_id
           FROM scheduled_scans
           WHERE enabled = 1
             AND (next_run_at IS NULL OR next_run_at <= ?)`
        )
        .bind(now)
        .all();
    } catch {
      // Table may not exist yet — nothing to process
      return;
    }

    for (const schedule of (result.results || [])) {
      // Each schedule runs independently so one failure cannot abort others
      ctx.waitUntil(triggerScheduledScan(schedule, env));
    }
  },
};
