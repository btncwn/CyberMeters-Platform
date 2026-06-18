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
  const [aRes, aaaaRes, nsRes, mxRes] = await Promise.allSettled([
    dnsQuery(domain, "A"),
    dnsQuery(domain, "AAAA"),
    dnsQuery(domain, "NS"),
    dnsQuery(domain, "MX"),
  ]);

  const pick = (r) =>
    r.status === "fulfilled" ? r.value.Answer || [] : [];

  const aRecords    = pick(aRes);
  const aaaaRecords = pick(aaaaRes);
  const nsRecords   = pick(nsRes);
  const mxRecords   = pick(mxRes);

  return {
    resolves:    aRecords.length > 0 || aaaaRecords.length > 0,
    has_ipv6:    aaaaRecords.length > 0,
    has_mx:      mxRecords.length > 0,
    nameservers: nsRecords.map((r) => r.data).filter(Boolean),
    a_records:   aRecords.map((r) => ({ value: r.data, ttl: r.TTL })),
    aaaa_records: aaaaRecords.map((r) => ({ value: r.data, ttl: r.TTL })),
    mx_records:  mxRecords.map((r) => ({ value: r.data, ttl: r.TTL })),
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

  return {
    https_available:       httpsOk || wwwHttpsOk,
    http_redirects_to_https: httpRedirectsToHttps,
    www_fallback_used:     !httpsOk && wwwHttpsOk,
  };
}

// ── Module 3: Security Headers Analysis ──────────────────────────────────────

async function runHeadersModule(domain) {
  let headerValues = {};
  let accessible   = false;
  let statusCode   = null;
  let responseUrl  = null;

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
      break;
    }
  }

  const present = SECURITY_HEADERS.filter((h) => !!headerValues[h.name]).map((h) => h.name);
  const missing = SECURITY_HEADERS.filter((h) => !headerValues[h.name]).map((h) => h.name);

  return {
    accessible,
    status_code:  statusCode,
    response_url: responseUrl,
    present,
    missing,
    values: headerValues,
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

// ── Module 5: Subdomain Discovery (Certificate Transparency) ─────────────────

/**
 * Subdomain names whose presence suggests a development, staging, or
 * administrative asset — used for risk detection only, not for blocking.
 */
const SENSITIVE_LABELS = new Set([
  "dev", "development", "develop",
  "staging", "stage", "stg", "stag",
  "test", "testing", "tests",
  "qa", "uat", "sandbox",
  "alpha", "beta",
  "preprod", "pre-prod", "pre",
  "demo",
  "admin", "administrator", "admins", "adm",
  "cp", "cpanel", "webmin", "plesk", "whm",
  "manager", "manage", "control", "panel",
  "backup", "backups", "bak",
  "old", "legacy", "archive", "temp", "tmp",
  "internal", "intranet", "corp", "private",
  "vpn", "ssh", "ftp",
  "db", "database", "sql", "mysql", "mongo",
  "jenkins", "ci", "cd", "build",
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

async function runSubdomainsModule(domain) {
  const source = "certificate_transparency";

  let rawData;
  try {
    const res = await fetch(
      `https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`,
      {
        headers: { Accept: "application/json", "User-Agent": "CyberMeters/1.0" },
        signal: AbortSignal.timeout(25_000),
      }
    );

    if (!res.ok) {
      return { count: 0, items: [], sensitive: [], source, error: `crt.sh HTTP ${res.status}` };
    }

    // Guard: check content-type — crt.sh sometimes returns HTML on errors
    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("json")) {
      return { count: 0, items: [], sensitive: [], source, error: "crt.sh returned non-JSON response" };
    }

    rawData = await res.json();
  } catch (err) {
    // Timeout, network error, or JSON parse failure — scan still completes
    return { count: 0, items: [], sensitive: [], source, error: err.message };
  }

  if (!Array.isArray(rawData)) {
    return { count: 0, items: [], sensitive: [], source, error: "Unexpected crt.sh response shape" };
  }

  // Extract unique hostnames from name_value and common_name fields.
  // Process first 2000 entries max to bound memory and CPU.
  const seen = new Set();
  const slice = rawData.slice(0, 2_000);

  for (const entry of slice) {
    const names = [
      ...(entry.name_value || "").split(/\n/),
      entry.common_name || "",
    ];
    for (const raw of names) {
      const name = raw.trim().toLowerCase();
      if (!name || name.startsWith("*")) continue;           // skip wildcards
      if (!name.endsWith("." + domain) && name !== domain) continue; // skip unrelated
      seen.add(name);
      if (seen.size >= 200) break;                           // cap at 200 unique
    }
    if (seen.size >= 200) break;
  }

  const items = [...seen].sort();

  // Classify sensitive subdomains
  const sensitive = items.filter((h) => isSensitiveSubdomain(h, domain));

  return { count: items.length, items, sensitive, source };
}

// ── Module 6: Subdomain Takeover Detection ────────────────────────────────────

/**
 * Known vulnerable service fingerprints for CNAME-based subdomain takeover.
 * cname_suffix: what the CNAME target ends with (indicates unclaimed service)
 * body_pattern: text returned by the provider when the resource doesn't exist
 */
const TAKEOVER_FINGERPRINTS = [
  {
    service:      "GitHub Pages",
    cname_suffix: "github.io",
    body_pattern: "There isn't a GitHub Pages site here.",
  },
  {
    service:      "Heroku",
    cname_suffix: "herokuapp.com",
    body_pattern: "No such app",
  },
  {
    service:      "Azure",
    cname_suffix: "azurewebsites.net",
    body_pattern: "404 Web Site not found",
  },
  {
    service:      "Netlify",
    cname_suffix: "netlify.app",
    body_pattern: "Not Found",
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
          cname,
          evidence: fingerprint.body_pattern,
          severity: "high",
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

// ── Main Scan Engine (runs via ctx.waitUntil) ─────────────────────────────────

async function runScanEngine(scanId, domainId, domain, env) {
  const startedAt = new Date().toISOString();

  try {
    // Mark scan as running in D1
    await env.cybermeters_db
      .prepare(`UPDATE scans SET status = 'running' WHERE id = ?`)
      .bind(scanId)
      .run();

    // Phase 1: Run the 5 core modules in parallel.
    // Subdomain discovery (crt.sh) has a 25s timeout but does not block the
    // other modules — all run concurrently via Promise.allSettled.
    const [dnsSettled, sslSettled, headersSettled, emailSettled, subdomainsSettled] =
      await Promise.allSettled([
        runDnsModule(domain),
        runSslModule(domain),
        runHeadersModule(domain),
        runEmailModule(domain),
        runSubdomainsModule(domain),
      ]);

    const subdomainsResult = subdomainsSettled.status === "fulfilled"
      ? subdomainsSettled.value
      : { count: 0, items: [], sensitive: [], source: "certificate_transparency",
          error: subdomainsSettled.reason?.message ?? "Subdomain module failed" };

    // Phase 2: Takeover detection — depends on discovered subdomains as input.
    let takeoverResult;
    try {
      takeoverResult = await runTakeoverModule(domain, subdomainsResult.items || []);
    } catch (err) {
      takeoverResult = { checked: 0, potential_risks: 0, risks: [], source: "subdomain_cname_fingerprint", error: err.message };
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
    };

    // Compute Cyber Metrics Score
    const { score, risk_level, findings, recommendations } = computeScore(modules, domain);

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

  } catch (err) {
    // Write failure state to both R2 and D1
    const failedAt = new Date().toISOString();

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
        error:               err.message,
        started_at:          startedAt,
        failed_at:           failedAt,
      }, null, 2),
      { httpMetadata: { contentType: "application/json" } }
    );

    await env.cybermeters_db
      .prepare(`UPDATE scans SET status = 'failed' WHERE id = ?`)
      .bind(scanId)
      .run();
  }
}

// ── CORS ──────────────────────────────────────────────────────────────────────

const corsHeaders = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
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
        return json({ error: "Invalid JSON body" }, { status: 400 });
      }

      const domain = body.domain?.trim().toLowerCase();

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, { status: 400 });
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

      // Register domain
      await env.cybermeters_db
        .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
        .bind(domainId, userId, domain)
        .run();

      // Create scan row — status 'running' (engine starts immediately)
      await env.cybermeters_db
        .prepare(
          `INSERT INTO scans (id, domain_id, domain, status) VALUES (?, ?, ?, ?)`
        )
        .bind(scanId, domainId, domain, "running")
        .run();

      // Write placeholder report to R2 so GET /report returns 200 immediately
      await env.cybermeters_reports.put(
        reportKey,
        JSON.stringify({
          scan_id:             scanId,
          domain_id:           domainId,
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
      ctx.waitUntil(runScanEngine(scanId, domainId, domain, env));

      return json(
        {
          status:     "running",
          scan_id:    scanId,
          domain_id:  domainId,
          domain,
          report_key: reportKey,
          message:    "Scan engine started. Poll GET /api/scans/:id until status is completed, then GET /api/scans/:id/report.",
        },
        202
      );
    }

    // ── GET /api/scans ──────────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/scans") {
      const result = await env.cybermeters_db
        .prepare(
          `SELECT id, domain, status, score, rating, created_at
           FROM scans
           ORDER BY created_at DESC
           LIMIT 20`
        )
        .all();

      return json({ scans: result.results });
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
        return json({ error: "Scan not found" }, { status: 404 });
      }

      const obj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
      if (!obj) {
        return json({ error: "Report not found" }, { status: 404 });
      }

      const raw = await obj.json();

      return json({
        scan_id:             scan.id,
        domain:              scan.domain,
        status:              scan.status,
        cyber_metrics_score: raw.cyber_metrics_score ?? 0,
        risk_level:          raw.risk_level          ?? "unknown",
        findings:            Array.isArray(raw.findings)        ? raw.findings        : [],
        recommendations:     Array.isArray(raw.recommendations) ? raw.recommendations : [],
        modules:             raw.modules ?? {},
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
        return json({ error: "Scan not found" }, { status: 404 });
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
        return json({ error: "Invalid domain" }, { status: 400 });
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

    return json({ error: "Not found" }, { status: 404 });
  },
};
