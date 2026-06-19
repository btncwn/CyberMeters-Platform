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

function isValidEmail(email) {
  return typeof email === "string" && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

// ── Auth Crypto Helpers ────────────────────────────────────────────────────────

/**
 * Hash a password using PBKDF2-SHA256 (100,000 iterations).
 * Returns a storable string: "pbkdf2:sha256:100000:<salt_hex>:<hash_hex>"
 */
async function hashPassword(password) {
  const encoder     = new TextEncoder();
  const salt        = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const hashBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: 100_000 },
    keyMaterial, 256
  );
  const toHex = (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  return `pbkdf2:sha256:100000:${toHex(salt.buffer)}:${toHex(hashBits)}`;
}

/**
 * Verify a password against a stored PBKDF2 hash.
 * Uses constant-time XOR comparison to prevent timing attacks.
 */
async function verifyPassword(password, stored) {
  const parts = stored.split(":");
  if (parts.length !== 5 || parts[0] !== "pbkdf2" || parts[1] !== "sha256") return false;
  const iterations  = parseInt(parts[2], 10);
  const saltBytes   = new Uint8Array(parts[3].match(/../g).map(h => parseInt(h, 16)));
  const storedHash  = parts[4];
  const encoder     = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const hashBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    keyMaterial, 256
  );
  const computed = Array.from(new Uint8Array(hashBits)).map(b => b.toString(16).padStart(2, "0")).join("");
  // Constant-time string comparison
  if (computed.length !== storedHash.length) return false;
  let diff = 0;
  for (let i = 0; i < computed.length; i++) {
    diff |= computed.charCodeAt(i) ^ storedHash.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Generate a 64-char hex bearer token and return both the raw token (for client)
 * and its SHA-256 hash (for D1 storage — raw token never persisted).
 */
async function generateSessionToken() {
  const raw     = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, "0")).join("");
  const hashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  const hash    = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
  return { raw, hash };
}

async function generateApiToken() {
  const secret = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, "0")).join("");
  const raw    = `cm_${secret}`;
  const hash   = await hashToken(raw);
  return { raw, hash };
}

async function generateInviteToken() {
  const secret = Array.from(crypto.getRandomValues(new Uint8Array(32))).map(b => b.toString(16).padStart(2, "0")).join("");
  const raw    = `cmi_${secret}`;
  const hash   = await hashToken(raw);
  return { raw, hash };
}

/**
 * Hash a bearer token string for D1 lookup (same as above but for incoming tokens).
 */
async function hashToken(raw) {
  const hashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(raw));
  return Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Extract and validate Bearer token from Authorization header.
 * Returns the user row on success, or null.
 */
async function requireAuth(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return null;
  const rawToken = authHeader.slice(7).trim();
  if (!rawToken) return null;
  try {
    const tokenHash = await hashToken(rawToken);
    const session   = await env.cybermeters_db
      .prepare(
        `SELECT s.user_id, u.id, u.email, u.name, u.plan, u.status
         FROM user_sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token_hash = ? AND s.expires_at > datetime('now')`
      )
      .bind(tokenHash)
      .first();
    if (!session || session.status === "suspended") return null;
    return session;
  } catch {
    return null;
  }
}

async function requireApiToken(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  if (!authHeader.startsWith("Bearer ")) return null;
  const rawToken = authHeader.slice(7).trim();
  if (!rawToken) return null;

  if (!rawToken.startsWith("cm_")) {
    return requireAuth(request, env);
  }

  try {
    const tokenHash = await hashToken(rawToken);
    const token = await env.cybermeters_db
      .prepare(
        `SELECT t.id AS api_token_id, t.user_id,
                u.id, u.email, u.name, u.plan, u.status
         FROM api_tokens t
         JOIN users u ON u.id = t.user_id
         WHERE t.token_hash = ?
           AND t.status = 'active'
           AND (t.expires_at IS NULL OR t.expires_at > datetime('now'))
         LIMIT 1`
      )
      .bind(tokenHash)
      .first();
    if (!token || token.status === "suspended") return null;

    await env.cybermeters_db
      .prepare("UPDATE api_tokens SET last_used_at = datetime('now') WHERE id = ?")
      .bind(token.api_token_id)
      .run();

    await createAuditEvent(env, {
      user_id:     token.user_id,
      event_type:  "api_token_used",
      entity_type: "api_token",
      entity_id:   token.api_token_id,
      description: "API token used for authentication",
    });

    return token;
  } catch {
    return null;
  }
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

// ── Enterprise Benchmark Dataset ─────────────────────────────────────────────
//
// Known-good enterprise domains.  Used by:
//   • GET /api/validation/benchmark  — regression check
//   • computeScore                   — enterprise edge uncertainty detection
//
// Enterprise CDN deployments (Cloudflare Workers, Google Front End, Akamai, etc.)
// often serve different responses to automated scanner IPs than to real browsers.
// We track these domains so the scoring engine can apply conservative confidence
// when the probe results are internally contradictory.

const ENTERPRISE_BENCHMARK = [
  { domain: "google.com",     max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
  { domain: "github.com",     max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
  { domain: "cloudflare.com", max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
  { domain: "microsoft.com",  max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
  { domain: "amazon.com",     max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
  { domain: "openai.com",     max_header_findings: 0, max_email_findings: 0, expect_https_redirect: true },
];

// Fast O(1) membership test used in computeScore
const ENTERPRISE_DOMAINS = new Set(ENTERPRISE_BENCHMARK.map(b => b.domain));

// Security posture category metadata — shared by computeSecurityPosture and
// the /scorecard/pdf-data route.  Defined at module scope so both can reference it.
const POSTURE_WEIGHTS = {
  email_security:   { label: 'Email Security',     pct: 20 },
  ssl_certificates: { label: 'SSL & Certificates', pct: 20 },
  attack_surface:   { label: 'Attack Surface',     pct: 25 },
  third_party_risk: { label: 'Third-Party Risk',   pct: 15 },
  admin_exposure:   { label: 'Admin Exposure',     pct: 20 },
};

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

  // Check whether plain HTTP redirects to HTTPS.
  // Follow up to 2 hops to handle intermediate http→http→https chains
  // (e.g. http://google.com → 301 → http://www.google.com → 301 → https://www.google.com).
  const httpOrigUrl = `http://${domain}`;
  const httpRes = await safeFetch(httpOrigUrl, { method: "HEAD", redirect: "manual" });
  let httpRedirectsToHttps = false;
  // http_redirect_validated starts false — only set true when safeFetch returns a
  // response (not null).  A null response means the fetch was blocked or timed out
  // (geo-routing, bot protection, firewall) and we cannot draw conclusions about
  // redirect behaviour.  The scoring engine skips ssl_no_http_redirect when this
  // stays false to avoid false positives on enterprise edge deployments.
  let http_redirect_chain = {
    original_url:            httpOrigUrl,
    final_url:               null,
    redirect_count:          0,
    http_redirect_validated: false,
  };

  if (httpRes) {
    // We got a response — the chain is at least partially observable.
    http_redirect_chain.http_redirect_validated = true;

    const status1 = httpRes.status;
    const rawLoc1 = httpRes.headers.get("location") || "";
    if ([301, 302, 307, 308].includes(status1) && rawLoc1) {
      let loc1;
      try { loc1 = new URL(rawLoc1, httpOrigUrl).href; } catch { loc1 = rawLoc1; }

      if (loc1.startsWith("https://")) {
        // Direct http→https — best case
        httpRedirectsToHttps = true;
        http_redirect_chain = { original_url: httpOrigUrl, final_url: loc1, redirect_count: 1, http_redirect_validated: true };
      } else {
        // First hop stayed on HTTP — follow one more hop to catch http→http→https
        const hop2 = await safeFetch(loc1, { method: "HEAD", redirect: "manual" });
        if (hop2) {
          const rawLoc2 = hop2.headers.get("location") || "";
          let loc2;
          try { loc2 = new URL(rawLoc2, loc1).href; } catch { loc2 = rawLoc2; }
          if ([301, 302, 307, 308].includes(hop2.status) && loc2.startsWith("https://")) {
            httpRedirectsToHttps = true;
            http_redirect_chain = { original_url: httpOrigUrl, final_url: loc2, redirect_count: 2, http_redirect_validated: true };
          }
        }
      }
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
    http_redirect_chain,
    www_fallback_used:        !httpsOk && wwwHttpsOk,
    cert_expiry_days,
    cert_not_after,
  };
}

// ── Bot Protection & Challenge Detection ─────────────────────────────────────
//
// Enterprise ASM scanners are regularly served challenge pages rather than the
// actual application.  Generating Missing-HSTS / Missing-CSP findings against a
// Cloudflare managed-challenge or a Google consent redirect produces embarrassing
// false positives.  detectBotProtection() identifies these responses so the
// scoring engine can emit informational observations instead of real findings.

const BOT_CHALLENGE_URL_PATTERNS = [
  "consent.google.com",
  "accounts.google.com/ServiceLogin",
  "accounts.google.com/o/oauth",
  "challenges.cloudflare.com",
  "/sorry/index",
  "/sorry/",
  "gateway.google.com",
  "/captcha",
  "bot-manager.",
  "perimeter81.",
];

// Scanner identification — honest UA, not impersonation
const HEADER_PROBE_INIT = {
  headers: {
    "User-Agent":      "Mozilla/5.0 (compatible; CyberMeters-Scanner/1.0; +https://cybermeters.com/scanner)",
    "Accept":          "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
  },
};

/**
 * Returns an array of signal strings describing detected bot/edge protection.
 * Empty array → no evidence of interception; non-empty → validation uncertain.
 *
 * @param {number}  statusCode   HTTP status of the response
 * @param {string}  responseUrl  Final URL after redirects (res.url)
 * @param {object}  headerMap    Lower-cased headers as { name: value } object
 */
function detectBotProtection(statusCode, responseUrl, headerMap) {
  const signals = [];

  // 1. Challenge / consent redirect — final URL ended up somewhere unexpected
  if (responseUrl) {
    for (const pat of BOT_CHALLENGE_URL_PATTERNS) {
      if (responseUrl.includes(pat)) {
        signals.push(`challenge_redirect:${pat}`);
        break;
      }
    }
  }

  // 2. Cloudflare managed challenge explicit header
  const cfMitigated = (headerMap["cf-mitigated"] || "").toLowerCase();
  if (cfMitigated === "challenge") signals.push("cf_managed_challenge");

  // 3. Imperva / Incapsula
  if (headerMap["x-iinfo"] || headerMap["x-cdn"] === "imperva") {
    signals.push("imperva_protection");
  }

  // 4. Hard rate-limit with Retry-After
  if ([429, 503].includes(statusCode) && headerMap["retry-after"]) {
    signals.push(`rate_limited_${statusCode}`);
  }

  // 5. 200 OK but no Content-Type AND no Server header → minimal/challenge response
  //    Real pages virtually always return Content-Type.
  if (statusCode === 200 && !headerMap["content-type"] && !headerMap["server"]) {
    signals.push("minimal_response_on_200");
  }

  return signals;
}

// ── Module 3: Security Headers Analysis ──────────────────────────────────────

async function runHeadersModule(domain) {
  let headerValues         = {};
  let accessible           = false;
  let statusCode           = null;
  let originalUrl          = null;
  let responseUrl          = null;
  let redirectCount        = 0;
  let setCookieRaw         = [];
  let botProtectionSignals = [];
  let rawHeaderSnapshot    = {};   // all response headers for diagnostics / bot detection

  // Prefer HTTPS; fall back to HTTP.
  // redirect:"follow" → res.url is the final URL after all redirects (Fetch API spec).
  for (const proto of ["https", "http"]) {
    const probeUrl = `${proto}://${domain}`;

    // ── Step 1: GET (primary) ─────────────────────────────────────────────
    const getRes = await safeFetch(probeUrl, {
      method:   "GET",
      redirect: "follow",
      ...HEADER_PROBE_INIT,
    });
    if (!getRes) continue;

    accessible    = true;
    statusCode    = getRes.status;
    originalUrl   = probeUrl;
    responseUrl   = getRes.url;
    redirectCount = (getRes.url && getRes.url !== probeUrl) ? 1 : 0;

    // Snapshot every response header (lower-cased) for bot-protection detection
    rawHeaderSnapshot = {};
    getRes.headers.forEach((v, k) => { rawHeaderSnapshot[k.toLowerCase()] = v; });

    // Read security headers from GET response
    for (const h of SECURITY_HEADERS) {
      headerValues[h.name] = getRes.headers.get(h.name) || null;
    }

    // Set-Cookie capture — Workers supports getAll() because multiple values
    // can't be safely comma-joined.
    try {
      setCookieRaw = typeof getRes.headers.getAll === "function"
        ? getRes.headers.getAll("set-cookie")
        : (getRes.headers.get("set-cookie") || "").split(/\r?\n/).filter(Boolean);
    } catch { setCookieRaw = []; }

    // ── Step 2: Bot protection detection ─────────────────────────────────
    botProtectionSignals = detectBotProtection(statusCode, responseUrl, rawHeaderSnapshot);

    if (botProtectionSignals.length > 0) {
      // GET was intercepted by an edge challenge.  Try HEAD — some WAFs skip
      // challenge injection on HEAD requests, potentially returning real headers.
      const headRes = await safeFetch(probeUrl, {
        method:   "HEAD",
        redirect: "follow",
        ...HEADER_PROBE_INIT,
      });
      if (headRes) {
        const headSnapshot = {};
        headRes.headers.forEach((v, k) => { headSnapshot[k.toLowerCase()] = v; });
        const headBotSignals = detectBotProtection(headRes.status, headRes.url, headSnapshot);

        // Count how many security headers each response provides
        const getSecCount  = SECURITY_HEADERS.filter(h => headerValues[h.name]).length;
        const headSecCount = SECURITY_HEADERS.filter(h => headRes.headers.get(h.name)).length;

        // Prefer the response with more security headers or fewer bot signals
        if (headSecCount > getSecCount || headBotSignals.length < botProtectionSignals.length) {
          for (const h of SECURITY_HEADERS) {
            headerValues[h.name] = headRes.headers.get(h.name) || null;
          }
          botProtectionSignals = headBotSignals;
          statusCode  = headRes.status;
          responseUrl = headRes.url;
          rawHeaderSnapshot = headSnapshot;
        }
      }
    }

    break;
  }

  // Whether the final response came over HTTPS.
  // HSTS is only meaningful on HTTPS — used in computeScore to avoid false positives
  // when we had to fall back to plain HTTP.
  const finalHttps = responseUrl ? responseUrl.startsWith("https://") : false;

  const present = SECURITY_HEADERS.filter((h) => !!headerValues[h.name]).map((h) => h.name);
  const missing = SECURITY_HEADERS.filter((h) => !headerValues[h.name]).map((h) => h.name);

  return {
    accessible,
    status_code:            statusCode,
    original_url:           originalUrl,
    response_url:           responseUrl,
    redirect_count:         redirectCount,
    final_https:            finalHttps,
    validation_uncertain:   botProtectionSignals.length > 0,
    bot_protection_signals: botProtectionSignals,
    raw_capture: {
      status:         statusCode,
      final_url:      responseUrl,
      redirect_chain: redirectCount > 0 ? [{ from: originalUrl, to: responseUrl }] : [],
      headers_snapshot: rawHeaderSnapshot,
    },
    present,
    missing,
    values:         headerValues,
    set_cookie_raw: setCookieRaw,
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

// ── Email Security Applicability ─────────────────────────────────────────────
//
// Determines whether SPF / DMARC / DKIM findings are meaningful for a domain.
// Subdomains with well-known non-mail prefixes (www, api, cdn, …) and domains
// with no MX records are not expected to send mail — producing Missing SPF /
// Missing DMARC findings against them is a false positive.
//
// Returns { applicable: boolean, reason?: string }

const NON_MAIL_PREFIXES = [
  "www.", "api.", "cdn.", "static.", "assets.",
  "img.", "docs.", "status.", "help.", "mail.",
];

function isEmailApplicable(domain, dnsMod) {
  // Subdomain prefix check — these hosts never send mail
  for (const pfx of NON_MAIL_PREFIXES) {
    if (domain.startsWith(pfx)) {
      return { applicable: false, reason: "No mail infrastructure detected" };
    }
  }
  // MX absence is a positive signal: the domain itself publishes no mail exchanger
  // (only skip when we have a successful DNS result — don't skip on DNS error)
  if (dnsMod && !dnsMod.error && dnsMod.has_mx === false) {
    return { applicable: false, reason: "No mail infrastructure detected" };
  }
  return { applicable: true };
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
// Cloud Asset Discovery — pattern-based detection of public cloud services
// across all discovered hostnames, CNAMEs, URLs and redirect targets.
// No additional HTTP calls — pure analysis of data already present in other modules.
//
// Covers: object storage, CDN, serverless functions, managed PaaS, static hosting.
//
// risk_level:
//   low    — CDN / static hosting (expected public exposure)
//   medium — managed PaaS / storage (may expose data if misconfigured)
//   high   — serverless endpoints (direct compute exposure)

const CLOUD_ASSET_PATTERNS = [

  // ── Object Storage ────────────────────────────────────────────────────────
  {
    provider:     "AWS S3",
    category:     "storage",
    service_type: "object_storage",
    patterns:     [".s3.amazonaws.com", "s3.amazonaws.com", "s3-website-", ".s3-website."],
    risk_level:   "medium",
  },
  {
    provider:     "Azure Blob Storage",
    category:     "storage",
    service_type: "object_storage",
    patterns:     ["blob.core.windows.net", "table.core.windows.net",
                   "queue.core.windows.net", "file.core.windows.net"],
    risk_level:   "medium",
  },
  {
    provider:     "Azure Static Website",
    category:     "storage",
    service_type: "static_website",
    patterns:     ["web.core.windows.net"],
    risk_level:   "low",
  },
  {
    provider:     "Google Cloud Storage",
    category:     "storage",
    service_type: "object_storage",
    patterns:     ["storage.googleapis.com"],
    risk_level:   "medium",
  },
  {
    provider:     "Firebase Storage",
    category:     "storage",
    service_type: "object_storage",
    patterns:     ["firebasestorage.googleapis.com"],
    risk_level:   "medium",
  },

  // ── CDN ───────────────────────────────────────────────────────────────────
  {
    provider:     "AWS CloudFront",
    category:     "cdn",
    service_type: "content_delivery",
    patterns:     [".cloudfront.net"],
    risk_level:   "low",
  },

  // ── Serverless / API ──────────────────────────────────────────────────────
  {
    provider:     "AWS Lambda URL",
    category:     "serverless",
    service_type: "function_url",
    patterns:     ["lambda-url.", ".on.aws"],
    risk_level:   "high",
  },
  {
    provider:     "AWS API Gateway",
    category:     "serverless",
    service_type: "api_gateway",
    patterns:     ["execute-api.", ".amazonaws.com/prod", ".amazonaws.com/v1",
                   ".amazonaws.com/v2", ".amazonaws.com/stage"],
    risk_level:   "high",
  },
  {
    provider:     "Azure Functions",
    category:     "serverless",
    service_type: "function_url",
    // Distinguished from App Service by common naming: func-* / *-function* / *-api*
    // Both use azurewebsites.net — we match by common function URL patterns
    patterns:     [".azurewebsites.net/api/"],
    risk_level:   "high",
  },

  // ── Managed PaaS / Hosting ────────────────────────────────────────────────
  {
    provider:     "Azure App Service",
    category:     "paas",
    service_type: "managed_app",
    patterns:     [".azurewebsites.net"],
    risk_level:   "medium",
  },
  {
    provider:     "AWS Elastic Beanstalk",
    category:     "paas",
    service_type: "managed_app",
    patterns:     [".elasticbeanstalk.com"],
    risk_level:   "medium",
  },
  {
    provider:     "AWS App Runner",
    category:     "paas",
    service_type: "managed_app",
    patterns:     [".awsapprunner.com"],
    risk_level:   "medium",
  },
  {
    provider:     "Firebase / Google App Engine",
    category:     "paas",
    service_type: "managed_app",
    patterns:     ["firebaseapp.com", "appspot.com", ".web.app"],
    risk_level:   "low",
  },

  // ── Static Hosting Platforms ──────────────────────────────────────────────
  {
    provider:     "Vercel",
    category:     "hosting",
    service_type: "static_hosting",
    patterns:     [".vercel.app", "vercel-dns.com", ".now.sh"],
    risk_level:   "low",
  },
  {
    provider:     "Netlify",
    category:     "hosting",
    service_type: "static_hosting",
    patterns:     [".netlify.app", ".netlify.com"],
    risk_level:   "low",
  },
];

/**
 * detectCloudAsset(value) → { provider, category, service_type, patterns, risk_level } | null
 * Returns the first matching CLOUD_ASSET_PATTERNS entry.
 */
function detectCloudAsset(value) {
  if (!value) return null;
  const v = value.toLowerCase();
  for (const def of CLOUD_ASSET_PATTERNS) {
    for (const pat of def.patterns) {
      if (v.includes(pat)) return { def, matchedPattern: pat };
    }
  }
  return null;
}

// Keep legacy alias so nothing else breaks if it's referenced elsewhere
const CLOUD_STORAGE_PATTERNS = CLOUD_ASSET_PATTERNS;
function detectCloudProvider(value) {
  const r = detectCloudAsset(value);
  return r ? r.def : null;
}

/**
 * Scan subdomains and exposure assets for cloud asset indicators.
 * Pure computation — zero additional network calls.
 *
 * Returns:
 *   { checked, findings: [{asset, provider, category, service_type,
 *     type, evidence, risk_level}], source, error }
 */
function runCloudStorageModule(domain, modules) {
  try {
    const findings = [];
    const seen     = new Set();    // deduplicate by asset+provider

    function record(asset, def, matchedPattern, evidence) {
      const key = `${asset}::${def.provider}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push({
        asset,
        provider:     def.provider,
        category:     def.category,
        service_type: def.service_type,
        type:         "cloud_asset_reference",
        evidence:     `${evidence} matched pattern "${matchedPattern}"`,
        risk_level:   def.risk_level,
      });
    }

    // ── 1. Scan subdomain hostnames ───────────────────────────────────────
    const subItems = modules?.subdomains?.items || [];
    for (const hostname of subItems) {
      const hit = detectCloudAsset(hostname);
      if (hit) record(hostname, hit.def, hit.matchedPattern, "hostname");
    }

    // ── 2. Scan brute-force finds ─────────────────────────────────────────
    const bruteItems = modules?.dns_bruteforce?.items || [];
    for (const item of bruteItems) {
      const hit = detectCloudAsset(item.hostname);
      if (hit) record(item.hostname, hit.def, hit.matchedPattern, "brute-force hostname");

      // Also check CNAMEs that brute-force may have resolved
      if (item.cname) {
        const cHit = detectCloudAsset(item.cname);
        if (cHit) record(item.hostname || item.cname, cHit.def, cHit.matchedPattern, "brute-force CNAME");
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
        const hit = detectCloudAsset(value);
        if (hit) {
          record(
            asset.hostname || asset.url,
            hit.def,
            hit.matchedPattern,
            label
          );
        }
      }
    }

    // ── 4. Scan takeover-risk CNAMEs ─────────────────────────────────────
    const takeoverRisks = modules?.subdomain_takeover?.risks || [];
    for (const risk of takeoverRisks) {
      if (risk.cname) {
        const hit = detectCloudAsset(risk.cname);
        if (hit) record(risk.hostname || risk.cname, hit.def, hit.matchedPattern, "takeover CNAME");
      }
    }

    // Sort: high risk first, then medium, then low
    const riskOrder = { high: 0, medium: 1, low: 2 };
    findings.sort((a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3));

    return {
      checked:  subItems.length + bruteItems.length + exposureAssets.length,
      total:    findings.length,
      findings,
      source:   "hostname_pattern_match",
      error:    null,
    };
  } catch (err) {
    return {
      checked:  0,
      total:    0,
      findings: [],
      source:   "hostname_pattern_match",
      error:    err?.message ?? "Cloud asset discovery failed",
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

// ── SaaS Exposure Discovery ───────────────────────────────────────────────────
// Builds an exposure-focused view on top of vendor_risk.
//
// Difference vs. vendor_risk / third_party_assets:
//   vendor_risk          → "do they use Salesforce?" (signal-level)
//   third_party_assets   → "what SaaS categories does this org depend on?"
//   saas_exposure        → "where exactly is the exposed portal/login surface?"
//                          (tenant URL, admin URL, exposure type, attack vector)
//
// For each detected vendor we:
//   1. Classify the exposure_type  (login_portal / email_gateway / saas_tenant /
//      support_portal / crm_portal / dev_portal / ecommerce_portal)
//   2. Extract the tenant-specific URL from CNAME records where possible
//   3. Attach the known public portal URL and admin URL for the service
//
// Zero network I/O — all CNAME data is already in modules from Phase 6.

const SAAS_EXPOSURE_SIGS = [
  // ── Identity / Email ──────────────────────────────────────────────────────
  {
    name:          "Microsoft 365",
    category:      "email_identity",
    exposure_type: "login_portal",
    risk_level:    "high",
    portal_url:    "https://login.microsoftonline.com",
    admin_url:     "https://admin.microsoft.com",
    // Tenant-specific CNAME: mail.company.com → company-com.mail.protection.outlook.com
    tenant_cname_re: /([^.]+)\.mail\.protection\.outlook\.com/i,
    attack_surface: "Credential stuffing, phishing, MFA bypass, password spray",
  },
  {
    name:          "Google Workspace",
    category:      "email_identity",
    exposure_type: "login_portal",
    risk_level:    "high",
    portal_url:    "https://mail.google.com",
    admin_url:     "https://admin.google.com",
    tenant_cname_re: null,
    attack_surface: "Credential stuffing, OAuth token theft, phishing",
  },
  {
    name:          "Proton Mail",
    category:      "email_identity",
    exposure_type: "email_gateway",
    risk_level:    "low",
    portal_url:    "https://mail.proton.me",
    admin_url:     "https://account.proton.me",
    tenant_cname_re: null,
    attack_surface: "End-to-end encrypted — low external attack surface",
  },
  {
    name:          "Zoho Mail",
    category:      "email_identity",
    exposure_type: "login_portal",
    risk_level:    "medium",
    portal_url:    "https://mail.zoho.com",
    admin_url:     "https://mailadmin.zoho.com",
    tenant_cname_re: null,
    attack_surface: "Credential stuffing, password spray",
  },

  // ── Collaboration / Dev ───────────────────────────────────────────────────
  {
    name:          "Atlassian",
    category:      "collaboration",
    exposure_type: "dev_portal",
    risk_level:    "high",
    portal_url:    null,
    admin_url:     "https://admin.atlassian.com",
    // Tenant: company.atlassian.net
    tenant_cname_re: /([^.]+)\.atlassian\.net/i,
    attack_surface: "Exposed Jira/Confluence issues, credential stuffing, project data leakage",
  },

  // ── CRM ───────────────────────────────────────────────────────────────────
  {
    name:          "Salesforce",
    category:      "crm",
    exposure_type: "crm_portal",
    risk_level:    "high",
    portal_url:    "https://login.salesforce.com",
    admin_url:     null,
    // Tenant: company.my.salesforce.com or company.salesforce.com
    tenant_cname_re: /([^.]+)(?:\.my)?\.salesforce\.com/i,
    attack_surface: "CRM data exposure, credential stuffing, OAuth abuse",
  },
  {
    name:          "HubSpot",
    category:      "crm",
    exposure_type: "crm_portal",
    risk_level:    "medium",
    portal_url:    "https://app.hubspot.com",
    admin_url:     null,
    // Tenant pages: tenant.hubspotpagebuilder.com or tenant.hs-sites.com
    tenant_cname_re: /([^.]+)\.(?:hubspotpagebuilder|hs-sites|hsforms)\.(?:com|net)/i,
    attack_surface: "Marketing data, contact lists, form submissions exposed",
  },
  {
    name:          "Marketo",
    category:      "crm",
    exposure_type: "crm_portal",
    risk_level:    "medium",
    portal_url:    "https://app.marketo.com",
    admin_url:     null,
    tenant_cname_re: /([^.]+)\.(?:marketo|mktoweb)\.com/i,
    attack_surface: "Marketing automation data, contact lists",
  },

  // ── Support ───────────────────────────────────────────────────────────────
  {
    name:          "Zendesk",
    category:      "support",
    exposure_type: "support_portal",
    risk_level:    "medium",
    portal_url:    null,
    admin_url:     null,
    // Tenant: company.zendesk.com
    tenant_cname_re: /([^.]+)\.zendesk\.com/i,
    attack_surface: "Customer ticket data, agent credential stuffing",
  },
  {
    name:          "Intercom",
    category:      "support",
    exposure_type: "support_portal",
    risk_level:    "low",
    portal_url:    "https://app.intercom.com",
    admin_url:     null,
    tenant_cname_re: /([^.]+)\.(?:intercom\.io|intercomassets\.com)/i,
    attack_surface: "Customer conversation data",
  },
  {
    name:          "Freshdesk",
    category:      "support",
    exposure_type: "support_portal",
    risk_level:    "low",
    portal_url:    null,
    admin_url:     null,
    tenant_cname_re: /([^.]+)\.(?:freshdesk|freshworks)\.com/i,
    attack_surface: "Customer ticket data",
  },

  // ── E-commerce ────────────────────────────────────────────────────────────
  {
    name:          "Shopify",
    category:      "ecommerce",
    exposure_type: "ecommerce_portal",
    risk_level:    "medium",
    portal_url:    "https://accounts.shopify.com",
    admin_url:     null,
    // Tenant: company.myshopify.com
    tenant_cname_re: /([^.]+)\.myshopify\.com/i,
    attack_surface: "Storefront credentials, order data, customer PII",
  },
  {
    name:          "Squarespace",
    category:      "ecommerce",
    exposure_type: "ecommerce_portal",
    risk_level:    "low",
    portal_url:    "https://account.squarespace.com",
    admin_url:     null,
    tenant_cname_re: /([^.]+)\.squarespace\.com/i,
    attack_surface: "Website admin, e-commerce data",
  },
  {
    name:          "Webflow",
    category:      "ecommerce",
    exposure_type: "ecommerce_portal",
    risk_level:    "low",
    portal_url:    "https://webflow.com/dashboard",
    admin_url:     null,
    tenant_cname_re: /([^.]+)\.(?:webflow\.io|proxy\.webflow\.com)/i,
    attack_surface: "Site admin, form submissions",
  },
];

/**
 * Collect all CNAME values from across the scan modules.
 * Reused from the vendor detection signal extraction logic.
 */
function collectAllCnames(modules) {
  const cnames = [];
  for (const risk of (modules?.subdomain_takeover?.risks || [])) {
    if (risk?.cname) cnames.push(risk.cname);
  }
  for (const asset of (modules?.asset_exposure?.assets || [])) {
    if (asset?.cname) cnames.push(asset.cname);
  }
  for (const item of (modules?.dns_bruteforce?.items || [])) {
    if (item?.cname) cnames.push(item.cname);
  }
  return cnames;
}

/**
 * runSaasExposureModule — pure computation, zero network I/O.
 *
 * Cross-references vendor_risk detections with SAAS_EXPOSURE_SIGS to produce
 * a portal-level exposure inventory: what portals are exposed, what the tenant
 * URL is (if discoverable), and what the attack surface looks like.
 *
 * Returns:
 *   { detected: bool, total: number,
 *     exposures: [{name, category, exposure_type, risk_level, portal_url,
 *       admin_url, tenant_hint, tenant_url, attack_surface, evidence, confidence}],
 *     source: "saas_exposure_analysis", error: null }
 */
function runSaasExposureModule(modules) {
  try {
    const detectedVendors = modules?.vendor_risk?.vendors || [];
    if (detectedVendors.length === 0) {
      return { detected: false, total: 0, exposures: [], source: "saas_exposure_analysis", error: null };
    }

    // Collect CNAME strings for tenant extraction
    const allCnames = collectAllCnames(modules);

    const exposures = [];
    const riskOrder = { high: 0, medium: 1, low: 2 };

    for (const vendor of detectedVendors) {
      const sig = SAAS_EXPOSURE_SIGS.find((s) => s.name === vendor.name);
      if (!sig) continue;

      // Try to extract tenant hint from any CNAME matching the sig's regex
      let tenant_hint = null;
      let tenant_url  = null;
      if (sig.tenant_cname_re) {
        for (const cname of allCnames) {
          const m = cname.match(sig.tenant_cname_re);
          if (m && m[1]) {
            tenant_hint = m[1];
            // Build tenant-specific portal URL if we have a template
            if (sig.name === "Atlassian") {
              tenant_url = `https://${tenant_hint}.atlassian.net`;
            } else if (sig.name === "Salesforce") {
              tenant_url = `https://${tenant_hint}.my.salesforce.com`;
            } else if (sig.name === "Zendesk") {
              tenant_url = `https://${tenant_hint}.zendesk.com`;
            } else if (sig.name === "Shopify") {
              tenant_url = `https://${tenant_hint}.myshopify.com/admin`;
            } else if (sig.name === "HubSpot" || sig.name === "Marketo") {
              tenant_url = sig.portal_url;
            } else {
              tenant_url = sig.portal_url;
            }
            break;
          }
        }
      }

      // Escalate risk if we found a tenant URL (confirmed direct access)
      const effective_risk = (tenant_url && riskOrder[sig.risk_level] > riskOrder["high"])
        ? "high"
        : sig.risk_level;

      exposures.push({
        name:           sig.name,
        category:       sig.category,
        exposure_type:  sig.exposure_type,
        risk_level:     effective_risk,
        portal_url:     tenant_url || sig.portal_url,
        admin_url:      sig.admin_url || null,
        tenant_hint:    tenant_hint,
        tenant_url:     tenant_url,
        attack_surface: sig.attack_surface,
        evidence:       vendor.evidence,
        confidence:     vendor.confidence,
      });
    }

    // Sort: high → medium → low, then by exposure_type
    const expTypeOrder = {
      login_portal: 0, crm_portal: 1, dev_portal: 2, support_portal: 3,
      ecommerce_portal: 4, email_gateway: 5,
    };
    exposures.sort((a, b) => {
      const rd = (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3);
      if (rd !== 0) return rd;
      return (expTypeOrder[a.exposure_type] ?? 9) - (expTypeOrder[b.exposure_type] ?? 9);
    });

    return {
      detected: exposures.length > 0,
      total:    exposures.length,
      exposures,
      source:   "saas_exposure_analysis",
      error:    null,
    };
  } catch (err) {
    return {
      detected:  false,
      total:     0,
      exposures: [],
      source:    "saas_exposure_analysis",
      error:     err?.message ?? "SaaS exposure module failed",
    };
  }
}

// ── Certificate Intelligence ─────────────────────────────────────────────────
// Correlates SSL certificate data with CT-discovered hostname inventory to
// produce a certificate-level intelligence view.
//
// Data sources (already in modules — zero new network calls):
//   modules.ssl          → cert_expiry_days, cert_not_after, https_available
//   modules.subdomains   → CT-sourced hostname list, sensitive[], wildcard_dns,
//                          sources (crt_sh + certspotter counts)
//   modules.dns_bruteforce → brute-forced hostnames
//   domain               → apex for sensitive-label checks
//
// Suspicious signals emitted:
//   certificate_expiring_soon    (< 30 days)
//   certificate_expiring_critical(< 14 days)
//   wildcard_dns_detected        (wildcard DNS ↔ likely wildcard cert)
//   sensitive_hosts_in_ct        (admin/vpn/portal/sso/login/mail/dev/staging etc.)
//   high_subdomain_growth        (CT count > 50 — large attack surface)
//   ct_source_discrepancy        (one source >> the other — may indicate stale CT log)
//   no_https                     (HTTPS unavailable)

/** Hostnames whose labels indicate certificate-relevant sensitivity */
const CERT_SENSITIVE_LABELS = new Set([
  "admin", "vpn", "portal", "login", "sso", "mail", "webmail",
  "dev", "staging", "stage", "test", "qa", "sandbox",
  "remote", "auth", "oauth", "api", "app", "dashboard",
]);

function isCertSensitiveHost(hostname, domain) {
  const sub = hostname.endsWith("." + domain)
    ? hostname.slice(0, -(domain.length + 1))
    : hostname;
  return sub.split(".").some((label) => CERT_SENSITIVE_LABELS.has(label.toLowerCase()));
}

/**
 * runCertificateIntelligenceModule(modules, domain) — pure computation, zero I/O.
 *
 * Returns:
 *   { total_certificates_seen, certificate_status, issuer, subject,
 *     expires_at, days_until_expiry, issued_for_sensitive_hosts,
 *     newly_observed_hosts, suspicious_certificate_signals,
 *     certificate_risk_level, source: "ssl_ct_correlation", error: null }
 */
function runCertificateIntelligenceModule(modules, domain) {
  try {
    const ssl      = modules?.ssl       || {};
    const subMod   = modules?.subdomains || {};
    const brute    = modules?.dns_bruteforce || {};

    // ── Certificate expiry data ───────────────────────────────────────────
    const days_until_expiry = ssl.cert_expiry_days ?? null;
    const expires_at        = ssl.cert_not_after   ?? null;
    const https_available   = ssl.https_available  ?? false;

    // ── CT hostname inventory ─────────────────────────────────────────────
    const ctHosts    = Array.isArray(subMod.items)    ? subMod.items    : [];
    const bruteHosts = Array.isArray(brute.items)     ? brute.items.map((i) => i.hostname || i).filter(Boolean) : [];
    const allHosts   = [...new Set([...ctHosts, ...bruteHosts])];

    const total_certificates_seen = allHosts.length;

    // ── Sensitive hosts in CT ─────────────────────────────────────────────
    const issued_for_sensitive_hosts = allHosts
      .filter((h) => isCertSensitiveHost(h, domain))
      .sort();

    // Also capture the pre-classified sensitive list from subdomains module
    const subSensitive = Array.isArray(subMod.sensitive) ? subMod.sensitive : [];
    const allSensitive = [...new Set([...issued_for_sensitive_hosts, ...subSensitive])].sort();

    // ── CT source health ──────────────────────────────────────────────────
    const crtShCount    = subMod.sources?.crt_sh?.count     ?? 0;
    const certSpotCount = subMod.sources?.certspotter?.count ?? 0;
    const crtShError    = subMod.sources?.crt_sh?.error     ?? null;
    const certSpotError = subMod.sources?.certspotter?.error ?? null;

    // ── Suspicious signal detection ───────────────────────────────────────
    const suspicious_certificate_signals = [];

    if (!https_available) {
      suspicious_certificate_signals.push({
        signal:      "no_https",
        severity:    "high",
        description: "HTTPS is not available on this domain. Certificate may be missing or misconfigured.",
      });
    }

    if (days_until_expiry !== null && days_until_expiry < 14) {
      suspicious_certificate_signals.push({
        signal:      "certificate_expiring_critical",
        severity:    "critical",
        description: `Certificate expires in ${days_until_expiry} day${days_until_expiry === 1 ? "" : "s"} (${expires_at}). Immediate renewal required to avoid service outage.`,
      });
    } else if (days_until_expiry !== null && days_until_expiry < 30) {
      suspicious_certificate_signals.push({
        signal:      "certificate_expiring_soon",
        severity:    "medium",
        description: `Certificate expires in ${days_until_expiry} day${days_until_expiry === 1 ? "" : "s"} (${expires_at}). Renewal recommended within the next week.`,
      });
    }

    if (subMod.wildcard_dns) {
      suspicious_certificate_signals.push({
        signal:      "wildcard_dns_detected",
        severity:    "medium",
        description: "Wildcard DNS is active on this domain. Any subdomain resolves — likely a wildcard certificate is in use, which expands the attack surface.",
      });
    }

    if (allSensitive.length > 0) {
      suspicious_certificate_signals.push({
        signal:      "sensitive_hosts_in_ct",
        severity:    allSensitive.length >= 5 ? "high" : "medium",
        description: `${allSensitive.length} certificate-issued hostname${allSensitive.length > 1 ? "s" : ""} with sensitive labels detected in Certificate Transparency logs: ${allSensitive.slice(0, 10).join(", ")}${allSensitive.length > 10 ? ` (+${allSensitive.length - 10} more)` : ""}.`,
        hostnames:   allSensitive,
      });
    }

    if (total_certificates_seen > 50) {
      suspicious_certificate_signals.push({
        signal:      "high_subdomain_growth",
        severity:    "medium",
        description: `${total_certificates_seen} unique hostnames found in CT logs — large certificate footprint that expands the potential attack surface.`,
      });
    }

    // CT discrepancy: one source returning 2× or more than the other
    if (crtShCount > 0 && certSpotCount > 0) {
      const ratio = Math.max(crtShCount, certSpotCount) / Math.min(crtShCount, certSpotCount);
      if (ratio >= 2) {
        suspicious_certificate_signals.push({
          signal:      "ct_source_discrepancy",
          severity:    "info",
          description: `CT sources returned different hostname counts — crt.sh: ${crtShCount}, CertSpotter: ${certSpotCount}. Some hostnames may only appear in one log.`,
        });
      }
    } else if (crtShError && certSpotError) {
      suspicious_certificate_signals.push({
        signal:      "ct_sources_unavailable",
        severity:    "info",
        description: "Both Certificate Transparency sources were unavailable during this scan. CT hostname inventory may be incomplete.",
      });
    }

    // ── Certificate risk level ────────────────────────────────────────────
    let certificate_risk_level = "low";
    const hasCritical = suspicious_certificate_signals.some((s) => s.severity === "critical");
    const hasHigh     = suspicious_certificate_signals.some((s) => s.severity === "high");
    const hasMedium   = suspicious_certificate_signals.some((s) => s.severity === "medium");

    if (hasCritical || !https_available) certificate_risk_level = "critical";
    else if (hasHigh)                    certificate_risk_level = "high";
    else if (hasMedium)                  certificate_risk_level = "medium";

    // ── Newly observed hosts (all CT hosts are "newly observed" relative to
    //    baseline — true delta tracking requires historical DB rows which are
    //    captured in asset_events via upsertAssetInventory) ─────────────────
    const newly_observed_hosts = allSensitive;   // surface the sensitive subset

    return {
      total_certificates_seen,
      certificate_status:    https_available ? "valid" : "unavailable",
      // Issuer/subject not available without a TLS handshake inspection;
      // Workers cannot inspect outbound TLS.  These fields are reserved for
      // future integration with a cert-inspection proxy.
      issuer:                null,
      subject:               domain,
      expires_at,
      days_until_expiry,
      issued_for_sensitive_hosts: allSensitive,
      newly_observed_hosts,
      ct_sources:            { crt_sh: crtShCount, certspotter: certSpotCount },
      wildcard_dns:          subMod.wildcard_dns ?? false,
      wildcard_warning:      subMod.wildcard_warning ?? null,
      suspicious_certificate_signals,
      certificate_risk_level,
      source:                "ssl_ct_correlation",
      error:                 null,
    };
  } catch (err) {
    return {
      total_certificates_seen:    0,
      certificate_status:         "unknown",
      issuer:                     null,
      subject:                    domain,
      expires_at:                 null,
      days_until_expiry:          null,
      issued_for_sensitive_hosts: [],
      newly_observed_hosts:       [],
      ct_sources:                 { crt_sh: 0, certspotter: 0 },
      wildcard_dns:               false,
      wildcard_warning:           null,
      suspicious_certificate_signals: [],
      certificate_risk_level:     "unknown",
      source:                     "ssl_ct_correlation",
      error:                      err?.message ?? "Certificate intelligence failed",
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

      // Build a probable URL from the asset's probed URL or hostname
      const url = asset.url || `https://${asset.host}`;

      services.push({
        hostname:   asset.host,
        url,
        product:    sig.product,
        category:   sig.category,
        severity:   sig.risk_level,   // human-readable alias used in UI / API
        confidence,
        risk_level: sig.risk_level,
        ip_address: asset.ip || null,
        server:     asset.server || null,
        title:      asset.title  || null,
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

  const critical = services.filter((s) => s.risk_level === "critical").length;
  const high     = services.filter((s) => s.risk_level === "high").length;
  const medium   = services.filter((s) => s.risk_level === "medium").length;

  return {
    detected: services.length > 0,
    total:    services.length,
    critical,
    high,
    medium,
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
      confidence:   "high",
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
      confidence:   "high",
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
    // Two situations suppress the scored finding:
    //
    // 1. http_redirect_validated === false: the HTTP fetch was blocked entirely
    //    (firewall, bot protection) — we cannot conclude anything.
    //
    // 2. Enterprise edge uncertainty: ENTERPRISE_DOMAINS that show no HTTPS
    //    redirect on the HTTP probe yet successfully serve HTTPS on the headers
    //    probe.  This contradiction is characteristic of large CDN edge deployments
    //    (Google Front End, Cloudflare Workers, etc.) that respond differently to
    //    scanner IPs than to real browsers.  We cannot confirm plaintext HTTP
    //    remains accessible, so we must not generate a scored finding.
    const redirectValidated       = modules.ssl?.http_redirect_chain?.http_redirect_validated !== false;
    const headersFinalHttps       = modules.headers?.final_https !== false;
    const enterpriseEdgeUncertain = ENTERPRISE_DOMAINS.has(domain)
      && redirectValidated
      && headersFinalHttps;   // redirect failed but HTTPS reachable → contradiction

    if (!redirectValidated || enterpriseEdgeUncertain) {
      findings.push({
        id:           "ssl_no_http_redirect",
        module:       "ssl",
        severity:     "info",
        confidence:   "low",
        title:        "HTTP Redirect — Validation Uncertain",
        description:  enterpriseEdgeUncertain
          ? `The HTTP probe of ${domain} returned a non-redirecting response, but the HTTPS headers probe succeeded — a contradiction typical of enterprise CDN edge behaviour where scanner IPs receive different treatment than real browsers. The scanner cannot confirm whether plain HTTP is actually accessible. This is an informational observation only.`
          : `Plain HTTP (port 80) connectivity to ${domain} could not be validated. The scanner's request may have been blocked by an edge firewall or bot-protection layer. This is an informational observation only.`,
        score_impact: 0,
      });
    } else {
      finding({
        id:           "ssl_no_http_redirect",
        module:       "ssl",
        severity:     "medium",
        confidence:   "high",
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
  }

  // ── Security Headers ───────────────────────────────────────────────────
  if (modules.headers?.accessible) {
    // Three conditions must ALL be true for any header finding to be scored:
    //   1. final_https: response came from an HTTPS endpoint (not HTTP fallback)
    //   2. validation_uncertain: false — no bot-protection / challenge interception
    //   3. status_code: 200 — a real application response, not an error or redirect
    //
    // Beyond that, only HSTS (severity "high") is treated as a confirmed/high-confidence
    // finding.  CSP, X-Frame-Options, XCTO, Referrer-Policy, and Permissions-Policy are
    // routinely delivered by CDN edges, per-path policies, or injected by frameworks
    // and are unreliable to validate remotely — they are downgraded to informational
    // (confidence: medium, score_impact: 0) even on clean responses.
    //
    // Additionally, for ENTERPRISE_BENCHMARK domains, any contradictory signal between
    // the SSL HTTP probe and the headers HTTPS probe (enterprise edge uncertainty)
    // prevents HSTS from being scored — the HTTPS response headers may come from the
    // CDN's edge node, not the canonical origin server.
    const finalHttps          = modules.headers.final_https !== false;
    const validationUncertain = !!modules.headers.validation_uncertain;
    const statusCode          = modules.headers.status_code ?? 0;
    // Enterprise edge uncertainty: see ssl_no_http_redirect gate above for rationale
    const sslNoHttpsRedirect        = !modules.ssl?.http_redirects_to_https;
    const sslRedirectWasObservable  = modules.ssl?.http_redirect_chain?.http_redirect_validated !== false;
    const headerEnterpriseUncertain = ENTERPRISE_DOMAINS.has(domain)
      && sslRedirectWasObservable
      && sslNoHttpsRedirect
      && finalHttps;
    // responseQualityOk requires all base conditions AND no enterprise edge contradiction
    const responseQualityOk = finalHttps && !validationUncertain && statusCode === 200 && !headerEnterpriseUncertain;

    for (const h of SECURITY_HEADERS) {
      // HSTS is only meaningful on HTTPS — skip entirely on HTTP fallback
      if (h.name === "strict-transport-security" && !finalHttps) continue;
      // Header is present — nothing to report
      if (modules.headers.values?.[h.name]) continue;

      if (!responseQualityOk) {
        // Response quality too low to make any finding — informational only
        findings.push({
          id:           `header_missing_${h.name.replace(/-/g, "_")}`,
          module:       "headers",
          severity:     "info",
          confidence:   "low",
          title:        `${h.label} — Validation Uncertain`,
          description:  `The ${h.label} header was not observed on ${domain}, but the scanner response may be from a bot-protection layer, edge cache, or non-canonical host. This is an informational observation only.`,
          score_impact: 0,
        });
      } else if (h.severity !== "high") {
        // Medium/low/info severity headers: confidence is medium — these are routinely
        // delivered by CDN layers, per-path policies, or injected client-side.  Remote
        // absence is not reliable evidence of a misconfiguration.
        findings.push({
          id:           `header_missing_${h.name.replace(/-/g, "_")}`,
          module:       "headers",
          severity:     "info",
          confidence:   "medium",
          title:        `Missing ${h.label} Header (Unverified)`,
          description:  `The ${h.label} header (${h.name}) was not returned in the scanner's HTTP probe of ${domain}. This may be delivered by the CDN, applied per-path, or injected at the framework layer. Verify manually on the canonical origin.`,
          score_impact: 0,
        });
      } else {
        // High-severity, high-confidence, verified HTTPS 200 response — score it
        finding({
          id:           `header_missing_${h.name.replace(/-/g, "_")}`,
          module:       "headers",
          severity:     "high",
          confidence:   "high",
          title:        `Missing ${h.label} Header`,
          description:  `The ${h.label} header (${h.name}) was not returned in HTTP responses from ${domain}. This was confirmed on a direct HTTPS 200 response.`,
          score_impact: h.score_impact,
        });
        recommendations.push({
          priority:    2,
          module:      "headers",
          title:       `Add ${h.label} Header`,
          description: h.recommendation,
        });
      }
    }
  }

  // ── Email Security ─────────────────────────────────────────────────────
  // Phase 4: Applicability gate — subdomains with non-mail prefixes and domains
  // without MX records do not send mail; skip SPF/DMARC/DKIM findings entirely.
  const emailApp = isEmailApplicable(domain, modules.dns);
  if (!emailApp.applicable) {
    // Informational observation only — no score deduction
    findings.push({
      id:           "email_not_applicable",
      module:       "email_security",
      severity:     "info",
      confidence:   "high",
      title:        "Email Security: Not Applicable",
      description:  `Email security checks were skipped for ${domain}: ${emailApp.reason}. Configure SPF, DMARC, and DKIM on the apex domain if this organisation sends mail.`,
      score_impact: 0,
    });
  } else {
    if (!modules.email_security?.dmarc?.present) {
      finding({
        id:           "email_missing_dmarc",
        module:       "email_security",
        severity:     "high",
        confidence:   "high",
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
        confidence:   "high",
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
        confidence:   "high",
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
      // Phase 5: DKIM confidence downgrade.
      // Common-selector probing is best-effort — enterprise domains often use custom
      // selectors not in our list. This is an informational observation, not a finding.
      // Never medium or high confidence; never deducts score.
      findings.push({
        id:           "email_dkim_not_detected",
        module:       "email_security",
        severity:     "info",
        confidence:   "low",
        title:        "DKIM Could Not Be Verified Using Common Selectors",
        description:  `No DKIM public key record was found for ${domain} using common selector names. DKIM may be configured with a custom selector not in our probe list, or may not be enabled.`,
        score_impact: 0,
      });
      recommendations.push({
        priority:    3,
        module:      "email_security",
        title:       "Verify DKIM Configuration",
        description: "Confirm that DKIM signing is enabled with your email provider and the public key is published as a DNS TXT record at <selector>._domainkey." + domain,
      });
    }
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
        confidence:   "medium",
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
        confidence:   "medium",
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
      confidence:   "high",
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
        confidence:   "high",
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
        confidence:   "medium",
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
        confidence:   "medium",
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
// Returns a bare, lowercase hostname with no trailing dot, port, path, query,
// or fragment.  Accepts:
//   • Plain hostname          "api.example.com"
//   • Hostname with port      "api.example.com:8443"
//   • Full URL                "https://api.example.com/path?x=1"
//   • URL without scheme      "//api.example.com/path"
//   • Hostname with path      "api.example.com/path"   (no scheme)
function normalizeHostname(value) {
  if (!value) return null;
  let s = String(value).trim();
  if (!s) return null;

  // Normalise scheme-relative URLs so the URL parser can handle them
  if (s.startsWith("//")) s = "https:" + s;

  if (/^https?:\/\//i.test(s)) {
    try {
      s = new URL(s).hostname;
    } catch {
      return null;
    }
  } else {
    // No scheme — strip any path/query/fragment that follows the first "/"
    const slashIdx = s.indexOf("/");
    if (slashIdx !== -1) s = s.slice(0, slashIdx);
    // Strip port number (":digits" at end)
    s = s.replace(/:\d+$/, "");
  }

  s = s.toLowerCase().replace(/\.$/, "");
  // Must contain at least one dot and no spaces to be a valid hostname
  if (!s || s.includes(" ") || !s.includes(".")) return null;
  return s;
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
  // probeAsset() returns { host, url, ... } — use .host (the probe target) as the
  // canonical key.  .url is the post-redirect URL and may resolve to a *different*
  // hostname (e.g. probing blackbullbarbers.co.uk → redirect → www.blackbullbarbers.co.uk).
  // Falling back to .url would create spurious separate asset rows for the same host.
  for (const asset of modules?.asset_exposure?.assets || []) {
    const h = normalizeHostname(asset.host || asset.hostname || asset.url);
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
      // Fetch existing assets + recent events in a single batch round-trip.
      // recent_events is used to suppress flip-flop alert noise:
      //   • asset_no_longer_seen is only emitted if last_seen was > 2 h ago
      //     AND no asset_no_longer_seen already fired for this hostname today.
      //   • asset_reappeared is only emitted if it hasn't fired today.
      const [existingResult, recentEvtResult] = await env.cybermeters_db.batch([
        env.cybermeters_db
          .prepare(
            `SELECT id, hostname, status, last_seen FROM workspace_assets
             WHERE workspace_id = ? AND domain_id = ?`
          )
          .bind(workspace_id, domainId),
        env.cybermeters_db
          .prepare(
            `SELECT event_type, hostname FROM asset_events
             WHERE workspace_id = ? AND domain_id = ?
               AND created_at >= datetime('now', '-24 hours')`
          )
          .bind(workspace_id, domainId),
      ]);

      const existingMap = new Map(
        (existingResult.results || []).map((r) => [r.hostname, r])
      );

      // Set of "event_type:hostname" pairs already fired in the last 24 h
      const recentEvtSet = new Set(
        (recentEvtResult.results || []).map((r) => `${r.event_type}:${r.hostname}`)
      );

      const TWO_HOURS_MS = 2 * 60 * 60 * 1000;

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
          // Asset reappeared after being inactive — suppress if already fired today
          if (existing.status === "inactive" &&
              !recentEvtSet.has(`asset_reappeared:${asset.hostname}`)) {
            recentEvtSet.add(`asset_reappeared:${asset.hostname}`);
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

      // Mark assets from a previous scan that are no longer visible.
      // Flip-flop noise reduction:
      //   • Only mark inactive (and emit event) if last_seen was > 2 h ago.
      //     This prevents CT-source flakiness from toggling asset state within
      //     the same scan day.
      //   • Skip the event if asset_no_longer_seen already fired for this
      //     hostname in the last 24 h.
      for (const [hostname, existing] of existingMap) {
        if (!currentHostnames.has(hostname) && existing.status === "active") {
          const lastSeenMs = existing.last_seen ? new Date(existing.last_seen).getTime() : 0;
          const ageMs = Date.now() - lastSeenMs;
          if (ageMs < TWO_HOURS_MS) continue; // Too recent — skip to avoid flip-flop

          stmts.push(
            env.cybermeters_db
              .prepare(
                `UPDATE workspace_assets
                 SET status = 'inactive', updated_at = ?
                 WHERE workspace_id = ? AND hostname = ?`
              )
              .bind(now, workspace_id, hostname)
          );

          if (!recentEvtSet.has(`asset_no_longer_seen:${hostname}`)) {
            recentEvtSet.add(`asset_no_longer_seen:${hostname}`);
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
    if (adminMod && !adminMod.error && adminMod.detected && adminMod.total > 0) {
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

    // Phase 7g: SaaS Exposure Discovery — pure computation, zero I/O.
    // Cross-references vendor_risk detections with known portal/tenant patterns to
    // identify externally accessible SaaS portals, admin interfaces and tenant URLs.
    modules.saas_exposure = runSaasExposureModule(modules);

    // Phase 7h: Certificate Intelligence — pure computation, zero I/O.
    // Correlates modules.ssl + modules.subdomains (CT data) to produce
    // expiry status, sensitive-host inventory, and suspicious signal list.
    modules.certificate_intelligence = runCertificateIntelligenceModule(modules, domain);

    // Phase 7i: Typosquat & Brand Monitoring — pure computation, zero network I/O.
    // Generates lookalike candidate domains for the brand name extracted from
    // `domain` (character substitution, omission, duplication, transposition,
    // keyword hyphenation).  DNS/HTTPS validation is deferred to the dedicated
    // POST /api/workspaces/:id/brand-monitoring/refresh endpoint so this module
    // does not consume any of the already-tight subrequest budget (~47/50 by here).
    modules.brand_monitoring = runTyposquatModule(domain);

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

    // Phase 8d: Certificate Events — fires asset_events for sensitive CT hosts,
    // expiry warnings, and growth signals.
    try {
      await insertCertificateEvents(scanId, domainId, modules.certificate_intelligence, env);
    } catch { /* non-fatal */ }

    // Phase 8e: Brand Asset Upsert — persists generated typosquat candidates to
    // workspace_brand_assets as 'unverified'.  DNS validation happens separately
    // via POST /brand-monitoring/refresh to stay within subrequest budget.
    try {
      await upsertBrandAssets(domainId, modules.brand_monitoring, env);
    } catch { /* non-fatal */ }

    // Phase 9: Asset Change Alert — one grouped email per workspace per scan.
    // Reads asset_events written by Phase 8, deduped via asset_alert_records.
    // Fully non-fatal — swallows all errors.
    try {
      await sendAssetChangeAlert(domainId, domain, scanId, env);
    } catch { /* non-fatal */ }

    // Phase 10: Notification Events — create in-app notifications for scan
    // completion and any critical/high findings. Non-fatal.
    try {
      await createNotificationsForDomain(domainId, domain, scanId, score, risk_level, findings, env);
    } catch { /* non-fatal */ }

    // Phase 11: Audit — scan completed. Fire per-workspace. Non-fatal.
    try {
      const wsRows = await env.cybermeters_db
        .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
        .bind(domainId)
        .all();
      for (const { workspace_id } of (wsRows.results || [])) {
        await createAuditEvent(env, {
          workspace_id,
          event_type:  "scan_completed",
          entity_type: "scan",
          entity_id:   scanId,
          description: `Scan completed for ${domain} — score ${score}, risk ${risk_level}`,
          metadata:    { scan_id: scanId, domain, domain_id: domainId, score, risk_level },
        });
      }
      // Also fire a workspace-agnostic event if domain has no workspaces
      if ((wsRows.results || []).length === 0) {
        await createAuditEvent(env, {
          event_type:  "scan_completed",
          entity_type: "scan",
          entity_id:   scanId,
          description: `Scan completed for ${domain} — score ${score}, risk ${risk_level}`,
          metadata:    { scan_id: scanId, domain, domain_id: domainId, score, risk_level },
        });
      }
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

// ── Certificate Event Insertion ──────────────────────────────────────────────
//
// Fires asset_events for certificate-level signals detected by
// runCertificateIntelligenceModule.  One event per signal type per scan.
// All errors are non-fatal.

/**
 * insertCertificateEvents(scanId, domainId, certMod, env)
 *
 * Event types written:
 *   certificate_sensitive_host_detected — sensitive hostnames in CT logs
 *   certificate_expiring_soon           — expiry < 30 days
 *   certificate_growth_detected         — CT count > 50 hostnames
 */
async function insertCertificateEvents(scanId, domainId, certMod, env) {
  if (!certMod || certMod.error) return;

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

  for (const { workspace_id } of wsRows) {
    // 1. Sensitive hosts detected in CT
    if (certMod.issued_for_sensitive_hosts?.length > 0) {
      try {
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO asset_events
               (id, workspace_id, domain_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, 'certificate_sensitive_host_detected',
                     ?, ?, ?, ?)`
          )
          .bind(
            createId("asev"),
            workspace_id,
            domainId,
            scanId,
            certMod.issued_for_sensitive_hosts[0],   // first / most notable
            certMod.issued_for_sensitive_hosts.length >= 5 ? "high" : "medium",
            `${certMod.issued_for_sensitive_hosts.length} sensitive hostname(s) found in CT logs: ` +
              certMod.issued_for_sensitive_hosts.slice(0, 5).join(", "),
            now
          )
          .run();
      } catch { /* non-fatal */ }
    }

    // 2. Certificate expiring soon
    const days = certMod.days_until_expiry;
    if (days !== null && days < 30) {
      try {
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO asset_events
               (id, workspace_id, domain_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, 'certificate_expiring_soon',
                     ?, ?, ?, ?)`
          )
          .bind(
            createId("asev"),
            workspace_id,
            domainId,
            scanId,
            null,
            days < 14 ? "critical" : "medium",
            `Certificate expires in ${days} day${days === 1 ? "" : "s"} (${certMod.expires_at}).`,
            now
          )
          .run();
      } catch { /* non-fatal */ }
    }

    // 3. Unusual certificate growth
    if (certMod.total_certificates_seen > 50) {
      try {
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO asset_events
               (id, workspace_id, domain_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, 'certificate_growth_detected',
                     ?, 'medium', ?, ?)`
          )
          .bind(
            createId("asev"),
            workspace_id,
            domainId,
            scanId,
            null,
            `${certMod.total_certificates_seen} unique hostnames found in CT logs.`,
            now
          )
          .run();
      } catch { /* non-fatal */ }
    }
  }
}

// ── Brand Monitoring — Typosquat & Brand Asset Tracking ──────────────────────
//
// Pure candidate generation (Phase 7i, zero network I/O) + deferred DNS
// validation via POST /brand-monitoring/refresh (separate request with its own
// 50-subrequest budget — scan already uses ~47 by the time Phase 7 runs).

/**
 * extractBrandParts(domain)
 * Returns { brand, tld } for a registered domain.
 * Strips www., takes the first label as brand, the rest as TLD.
 *   "tesla.com"              → { brand:"tesla",             tld:"com" }
 *   "blackbullbarbers.co.uk" → { brand:"blackbullbarbers",  tld:"co.uk" }
 */
function extractBrandParts(domain) {
  const clean  = domain.replace(/^www\./i, '').toLowerCase();
  const labels = clean.split('.');
  return { brand: labels[0], tld: labels.slice(1).join('.') };
}

// Keywords that lift candidate risk to 'high' (impersonation-focused)
const HIGH_RISK_BRAND_KEYWORDS = [
  'login', 'secure', 'account', 'verify', 'auth', 'portal', 'admin', 'support',
];
// Keywords that lift candidate risk to 'medium'
const MED_RISK_BRAND_KEYWORDS = [
  'help', 'service', 'online', 'my', 'app', 'customer', 'access', 'billing',
];

// Visual character substitutions commonly used in phishing / lookalike domains
const TYPOSQUAT_HOMOGLYPHS = {
  a: ['4'],
  e: ['3'],
  i: ['1', 'l'],
  l: ['1', 'i'],
  o: ['0'],
  s: ['5', 'z'],
  t: ['7'],
  g: ['9'],
  b: ['6'],
  n: ['m'],
  m: ['n'],
};

/** Score a candidate SLD and return { risk_level, risk_reasons, _score }. */
function _typosquatRisk(sld, variantType) {
  let score = 0;
  const reasons = [];
  const s = sld.toLowerCase();

  for (const kw of HIGH_RISK_BRAND_KEYWORDS) {
    if (s.includes(kw)) { score += 3; reasons.push(`contains '${kw}'`); }
  }
  for (const kw of MED_RISK_BRAND_KEYWORDS) {
    if (s.includes(kw) && !reasons.some(r => r.includes(`'${kw}'`))) {
      score += 1; reasons.push(`contains '${kw}'`);
    }
  }

  if (['omission', 'duplication', 'transposition'].includes(variantType)) {
    score += 2; reasons.push('single-character typo variant');
  } else if (variantType === 'substitution') {
    score += 2; reasons.push('homoglyph character substitution');
  }

  const risk_level = score >= 5 ? 'high' : score >= 2 ? 'medium' : 'low';
  return { risk_level, risk_reasons: reasons, _score: score };
}

/** Maximum candidates returned by generateTyposquatCandidates. */
const MAX_BRAND_CANDIDATES = 40;

/**
 * generateTyposquatCandidates(brand, tld)
 * Pure function. Generates lookalike domain candidates via:
 *   1. Homoglyph substitution  (l→1, o→0, …)
 *   2. Omission                (drop one character)
 *   3. Duplication             (double one character)
 *   4. Transposition           (swap adjacent characters)
 *   5. Hyphen keyword append   (brand-login.tld)
 *   6. Prefix keyword prepend  (login-brand.tld)
 * Returns up to MAX_BRAND_CANDIDATES items sorted by descending risk score.
 */
function generateTyposquatCandidates(brand, tld) {
  if (!brand || brand.length < 3) return [];

  const seen  = new Set();
  const items = [];

  function add(sld, variantType) {
    const candidate_domain = `${sld}.${tld}`;
    if (seen.has(candidate_domain)) return;
    if (sld === brand) return;
    if (sld.length < 2) return;
    seen.add(candidate_domain);
    const { risk_level, risk_reasons, _score } = _typosquatRisk(sld, variantType);
    items.push({ candidate_domain, variant_type: variantType, risk_level, risk_reasons, _score });
  }

  // 1. Homoglyph substitution
  for (let i = 0; i < brand.length; i++) {
    for (const sub of (TYPOSQUAT_HOMOGLYPHS[brand[i]] || [])) {
      add(brand.slice(0, i) + sub + brand.slice(i + 1), 'substitution');
    }
  }

  // 2. Omission
  for (let i = 0; i < brand.length; i++) {
    add(brand.slice(0, i) + brand.slice(i + 1), 'omission');
  }

  // 3. Duplication
  for (let i = 0; i < brand.length; i++) {
    add(brand.slice(0, i) + brand[i] + brand[i] + brand.slice(i + 1), 'duplication');
  }

  // 4. Transposition
  for (let i = 0; i < brand.length - 1; i++) {
    const arr = brand.split('');
    [arr[i], arr[i + 1]] = [arr[i + 1], arr[i]];
    add(arr.join(''), 'transposition');
  }

  // 5 & 6. Keyword variants (high-risk first, then medium-risk)
  for (const kw of [...HIGH_RISK_BRAND_KEYWORDS, ...MED_RISK_BRAND_KEYWORDS]) {
    add(`${brand}-${kw}`, 'hyphen_keyword');
    add(`${kw}-${brand}`, 'prefix_keyword');
  }

  // Sort by risk score desc, then alphabetically for determinism
  items.sort(
    (a, b) => b._score - a._score || a.candidate_domain.localeCompare(b.candidate_domain)
  );

  // Strip internal scoring field before returning
  return items.slice(0, MAX_BRAND_CANDIDATES).map(({ _score, ...rest }) => rest);
}

/**
 * runTyposquatModule(domain)
 * Phase 7i: pure computation, zero network I/O.
 *
 * Generates typosquat candidates for the brand name extracted from `domain`.
 * DNS/HTTPS validation is intentionally deferred to the dedicated
 * POST /api/workspaces/:id/brand-monitoring/refresh endpoint, which carries
 * its own 50-subrequest budget.  Inline DNS checks here would exceed the
 * budget already consumed by scan Phases 1–6 (~47 subrequests).
 */
function runTyposquatModule(domain) {
  try {
    const { brand, tld } = extractBrandParts(domain);
    const candidates = generateTyposquatCandidates(brand, tld);

    return {
      brand,
      total_candidates_generated: candidates.length,
      candidates_validated:       false,
      domains:                    candidates,
      risk_summary: {
        high:   candidates.filter(c => c.risk_level === 'high').length,
        medium: candidates.filter(c => c.risk_level === 'medium').length,
        low:    candidates.filter(c => c.risk_level === 'low').length,
      },
      source: 'typosquat_analysis',
      error:  null,
    };
  } catch (err) {
    return {
      brand:                      null,
      total_candidates_generated: 0,
      candidates_validated:       false,
      domains:                    [],
      risk_summary:               { high: 0, medium: 0, low: 0 },
      source:                     'typosquat_analysis',
      error:                      String(err),
    };
  }
}

/**
 * upsertBrandAssets(domainId, brandMod, env)
 * Phase 8e: Persists generated candidates as 'unverified' rows in
 * workspace_brand_assets.  INSERT OR IGNORE preserves first_seen and any
 * existing validation state; ON CONFLICT UPDATE refreshes last_seen and
 * risk fields so each scan re-asserts the candidate is still being watched.
 */
async function upsertBrandAssets(domainId, brandMod, env) {
  if (!brandMod || brandMod.error || !brandMod.domains?.length) return;

  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare('SELECT workspace_id FROM workspace_domains WHERE domain_id = ?')
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch { return; }
  if (wsRows.length === 0) return;

  // Resolve domain name (needed as FK / display column in workspace_brand_assets)
  // NOTE: domains table uses column 'domain', not 'name'.
  let domainName;
  try {
    const r = await env.cybermeters_db
      .prepare('SELECT domain FROM domains WHERE id = ?')
      .bind(domainId)
      .first();
    domainName = r?.domain;
  } catch { return; }
  if (!domainName) return;

  const now = new Date().toISOString();

  for (const { workspace_id } of wsRows) {
    for (const c of brandMod.domains) {
      try {
        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_brand_assets
               (id, workspace_id, domain, candidate_domain, variant_type,
                risk_level, risk_reasons, dns_resolves, https_available,
                ip_address, status, first_seen, last_seen, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'unverified',
                     ?, ?, ?, ?)
             ON CONFLICT (workspace_id, domain, candidate_domain) DO UPDATE SET
               risk_level   = excluded.risk_level,
               risk_reasons = excluded.risk_reasons,
               last_seen    = excluded.last_seen,
               updated_at   = excluded.updated_at`
          )
          .bind(
            createId('bra'),
            workspace_id,
            domainName,
            c.candidate_domain,
            c.variant_type,
            c.risk_level,
            JSON.stringify(c.risk_reasons),
            now,  // first_seen
            now,  // last_seen
            now,  // created_at
            now   // updated_at
          )
          .run();
      } catch { /* non-fatal per candidate */ }
    }
  }
}

// ── Executive Security Scorecard ─────────────────────────────────────────────
//
// Aggregates data from D1 (structured tables) + R2 (latest scan report modules)
// into a business-friendly security scorecard.  Shared by:
//   GET /api/workspaces/:id/scorecard
//   GET /api/workspaces/:id/scorecard/report

// ── Security Posture Scoring ──────────────────────────────────────────────────
//
// Computes five category scores (0-100) from existing scorecard + R2 report data.
// No new queries — pure function over already-loaded data.
//
// Weights (must sum to 1.0):
//   Email Security:    20%
//   SSL & Certs:       20%
//   Attack Surface:    25%
//   Third-Party Risk:  15%
//   Admin Exposure:    20%

function scoreStatus(s) {
  if (s === null)  return 'unknown';
  if (s >= 90)     return 'good';
  if (s >= 70)     return 'fair';
  if (s >= 50)     return 'warning';
  return 'critical';
}

function clamp(n, lo = 0, hi = 100) { return Math.max(lo, Math.min(hi, n)); }

/**
 * computeSecurityPosture(sc, report)
 *
 * @param {object} sc     — the scorecard object (all D1-derived fields)
 * @param {object|null} report — the R2 JSON report (may be null if no scan yet)
 * @returns {{ email_security, ssl_certificates, attack_surface,
 *             third_party_risk, admin_exposure, overall_score }}
 */
function computeSecurityPosture(sc, report) {
  const em   = report?.modules?.email_security   ?? null;
  const ssl  = report?.modules?.ssl              ?? null;
  const adm  = report?.modules?.admin_surface_detection ?? null;

  // ── 1. Email Security ────────────────────────────────────────────────────────
  let emailScore   = 100;
  const emailReasons = [];

  if (em === null) {
    emailScore = null;
  } else {
    if (!em.spf?.present) {
      emailScore -= 25;
      emailReasons.push('Missing SPF record — any server can send mail as this domain');
    }
    if (!em.dmarc?.present) {
      emailScore -= 30;
      emailReasons.push('Missing DMARC policy — email spoofing is not prevented');
    } else if (em.dmarc.policy === 'none') {
      emailScore -= 10;
      emailReasons.push('DMARC policy is p=none (monitor-only) — spoofed mail is not rejected');
    }
    if (!em.dkim?.present) {
      emailScore -= 10;
      emailReasons.push('DKIM not detected using common selectors — message signing unverified');
    }
    emailScore = clamp(emailScore);
  }

  // ── 2. SSL & Certificates ────────────────────────────────────────────────────
  let sslScore   = 100;
  const sslReasons = [];

  if (ssl === null && sc.certificate_risks.risk_level === null) {
    sslScore = null;
  } else {
    if (ssl !== null) {
      if (!ssl.https_available) {
        sslScore -= 40;
        sslReasons.push('HTTPS is not available — all traffic is unencrypted');
      }
      // Only deduct for missing redirect when the chain was confirmed observable
      // and there is no enterprise edge contradiction (same guard as scoring engine)
      const redirectValidated = ssl.http_redirect_chain?.http_redirect_validated !== false;
      const enterpriseContradiction = ENTERPRISE_DOMAINS.has(sc.last_scanned_domain ?? '')
        && redirectValidated
        && !ssl.http_redirects_to_https
        && (report?.modules?.headers?.final_https !== false);
      if (!ssl.http_redirects_to_https && redirectValidated && !enterpriseContradiction) {
        sslScore -= 15;
        sslReasons.push('HTTP does not redirect to HTTPS — unencrypted access is possible');
      }
    }
    // Certificate expiry
    const daysLeft = sc.certificate_risks.days_until_expiry;
    if (daysLeft !== null) {
      if (daysLeft < 0) {
        sslScore -= 35;
        sslReasons.push('Certificate has expired');
      } else if (daysLeft < 7) {
        sslScore -= 25;
        sslReasons.push(`Certificate expires in ${daysLeft} day${daysLeft !== 1 ? 's' : ''} — renewal is critical`);
      } else if (daysLeft < 30) {
        sslScore -= 15;
        sslReasons.push(`Certificate expires in ${daysLeft} days — renew soon`);
      }
    }
    // Certificate intelligence signals
    const certRisk = sc.certificate_risks.risk_level;
    if (certRisk === 'critical') {
      sslScore -= 20;
      sslReasons.push('Certificate intelligence: critical-risk signal detected');
    } else if (certRisk === 'high') {
      sslScore -= 10;
      sslReasons.push('Certificate intelligence: high-risk signal detected');
    }
    sslScore = clamp(sslScore);
  }

  // ── 3. Attack Surface ────────────────────────────────────────────────────────
  let asScore   = 100;
  const asReasons = [];

  const brandHigh = sc.brand_risks.high   ?? 0;
  const brandMed  = sc.brand_risks.medium ?? 0;
  const newA30    = sc.new_assets_30d     ?? 0;
  const cloudN    = Array.isArray(report?.modules?.cloud_storage_discovery?.assets)
    ? report.modules.cloud_storage_discovery.assets.length : 0;

  if (brandHigh > 0) {
    const cut = clamp(brandHigh * 12, 0, 35);
    asScore -= cut;
    asReasons.push(`${brandHigh} high-risk brand impersonation domain${brandHigh !== 1 ? 's' : ''} actively resolving`);
  }
  if (brandMed > 0) {
    const cut = clamp(brandMed * 5, 0, 15);
    asScore -= cut;
    asReasons.push(`${brandMed} medium-risk typosquat domain${brandMed !== 1 ? 's' : ''} detected`);
  }
  if (newA30 > 0) {
    const cut = clamp(newA30 * 4, 0, 20);
    asScore -= cut;
    asReasons.push(`${newA30} new asset${newA30 !== 1 ? 's' : ''} discovered in the last 30 days — surface is expanding`);
  }
  if (cloudN > 0) {
    asScore -= 10;
    asReasons.push(`${cloudN} cloud storage asset${cloudN !== 1 ? 's' : ''} exposed`);
  }
  asScore = clamp(asScore);

  // ── 4. Third-Party Risk ──────────────────────────────────────────────────────
  let tpScore   = 100;
  const tpReasons = [];

  const vHigh = sc.vendor_risk.high   ?? 0;
  const vMed  = sc.vendor_risk.medium ?? 0;
  const tpa   = sc.third_party_assets ?? 0;
  const saas  = sc.saas_exposures     ?? 0;

  if (vHigh > 0) {
    const cut = clamp(vHigh * 15, 0, 40);
    tpScore -= cut;
    tpReasons.push(`${vHigh} high-risk vendor${vHigh !== 1 ? 's' : ''} in the supply chain`);
  }
  if (vMed > 0) {
    const cut = clamp(vMed * 5, 0, 20);
    tpScore -= cut;
    tpReasons.push(`${vMed} medium-risk vendor${vMed !== 1 ? 's' : ''} detected`);
  }
  if (tpa > 0) {
    const cut = clamp(tpa * 3, 0, 15);
    tpScore -= cut;
    tpReasons.push(`${tpa} third-party service${tpa !== 1 ? 's' : ''} with external data access`);
  }
  if (saas > 0) {
    const cut = clamp(saas * 3, 0, 15);
    tpScore -= cut;
    tpReasons.push(`${saas} externally reachable SaaS portal${saas !== 1 ? 's' : ''}`);
  }
  tpScore = clamp(tpScore);

  // ── 5. Admin Exposure ────────────────────────────────────────────────────────
  let admScore   = 100;
  const admReasons = [];

  // adm.critical / adm.high come from admin_surface_detection module
  const admCritical = adm?.critical ?? 0;
  const admHigh     = adm?.high     ?? 0;
  const admOther    = (adm?.total ?? sc.admin_surfaces) - admCritical - admHigh;

  if (admCritical > 0) {
    const cut = clamp(admCritical * 20, 0, 60);
    admScore -= cut;
    admReasons.push(`${admCritical} critical admin surface${admCritical !== 1 ? 's' : ''} publicly exposed`);
  }
  if (admHigh > 0) {
    const cut = clamp(admHigh * 12, 0, 30);
    admScore -= cut;
    admReasons.push(`${admHigh} high-risk admin surface${admHigh !== 1 ? 's' : ''} publicly exposed`);
  }
  if (admOther > 0) {
    const cut = clamp(admOther * 6, 0, 20);
    admScore -= cut;
    admReasons.push(`${admOther} other management interface${admOther !== 1 ? 's' : ''} exposed`);
  }
  admScore = clamp(admScore);

  // ── Weighted overall ─────────────────────────────────────────────────────────
  // If any category is null (no scan data) it is excluded from the weighted average.
  const categories = [
    { key: 'email_security',    label: 'Email Security',     score: emailScore, weight: 0.20 },
    { key: 'ssl_certificates',  label: 'SSL & Certificates', score: sslScore,   weight: 0.20 },
    { key: 'attack_surface',    label: 'Attack Surface',     score: asScore,    weight: 0.25 },
    { key: 'third_party_risk',  label: 'Third-Party Risk',   score: tpScore,    weight: 0.15 },
    { key: 'admin_exposure',    label: 'Admin Exposure',     score: admScore,   weight: 0.20 },
  ];

  const known = categories.filter(c => c.score !== null);
  const weightSum = known.reduce((s, c) => s + c.weight, 0);
  const overall = weightSum > 0
    ? Math.round(known.reduce((s, c) => s + c.score * (c.weight / weightSum), 0))
    : null;

  // Build per-category objects
  const result = { overall_score: overall };
  const reasonsMap = {
    email_security:   emailReasons,
    ssl_certificates: sslReasons,
    attack_surface:   asReasons,
    third_party_risk: tpReasons,
    admin_exposure:   admReasons,
  };
  for (const { key, score } of categories) {
    const reasons = reasonsMap[key];
    result[key] = {
      score,
      status:  scoreStatus(score),
      reasons: reasons.length > 0 ? reasons : (score === null ? [] : ['No issues detected']),
    };
  }
  return result;
}

/**
 * buildScorecardData(wsId, env)
 *
 * Returns the full scorecard object for the workspace, or null on DB error.
 * Uses:
 *   - D1 batch 1  — workspace meta, asset / vendor / brand counts
 *   - D1 batch 2  — findings severity + top remediation (needs scan_id)
 *   - R2 (1 get)  — module-level data (saas_exposure, admin_surface_detection,
 *                    certificate_intelligence, third_party_assets, cloud assets)
 */
async function buildScorecardData(wsId, env) {
  const now30dAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

  // ── D1 Batch 1 ─────────────────────────────────────────────────────────────
  let b1;
  try {
    b1 = await env.cybermeters_db.batch([
      // 0. Latest completed scan
      env.cybermeters_db.prepare(
        `SELECT s.id, s.score, s.rating, s.domain, s.created_at
         FROM workspace_domains wd
         JOIN domains d ON d.id = wd.domain_id
         JOIN scans   s ON s.domain_id = d.id
         WHERE wd.workspace_id = ? AND s.status = 'completed'
         ORDER BY s.created_at DESC LIMIT 1`
      ).bind(wsId),

      // 1. Workspace name
      env.cybermeters_db.prepare(
        `SELECT name FROM workspaces WHERE id = ?`
      ).bind(wsId),

      // 2. Active asset count
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`
      ).bind(wsId),

      // 3. Asset type breakdown (admin_panel, cloud_storage, etc.)
      env.cybermeters_db.prepare(
        `SELECT asset_type, COUNT(*) AS n FROM workspace_assets
         WHERE workspace_id = ? AND status = 'active' GROUP BY asset_type`
      ).bind(wsId),

      // 4. Active vendor count
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM workspace_vendors WHERE workspace_id = ? AND status = 'active'`
      ).bind(wsId),

      // 5. Vendor risk breakdown
      env.cybermeters_db.prepare(
        `SELECT risk_level, COUNT(*) AS n FROM workspace_vendors
         WHERE workspace_id = ? AND status = 'active' GROUP BY risk_level`
      ).bind(wsId),

      // 6. Active brand risks (DNS-confirmed typosquats, status='active')
      env.cybermeters_db.prepare(
        `SELECT risk_level, COUNT(*) AS n FROM workspace_brand_assets
         WHERE workspace_id = ? AND status = 'active' GROUP BY risk_level`
      ).bind(wsId),

      // 7. Total brand candidates (any status)
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM workspace_brand_assets WHERE workspace_id = ?`
      ).bind(wsId),

      // 8. Asset events in last 30 days
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM asset_events WHERE workspace_id = ? AND created_at >= ?`
      ).bind(wsId, now30dAgo),

      // 9. New assets discovered in last 30 days (first_seen)
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM workspace_assets
         WHERE workspace_id = ? AND first_seen >= ?`
      ).bind(wsId, now30dAgo),

      // 10. Total domains in workspace
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS n FROM workspace_domains WHERE workspace_id = ?`
      ).bind(wsId),
    ]);
  } catch {
    return null;
  }

  const latestScan     = b1[0].results?.[0]  ?? null;
  const wsName         = b1[1].results?.[0]?.name ?? 'Unknown';
  const activeAssets   = b1[2].results?.[0]?.n    ?? 0;
  const assetTypeRows  = b1[3].results ?? [];
  const vendorsActive  = b1[4].results?.[0]?.n ?? 0;
  const vendorRiskRows = b1[5].results ?? [];
  const brandRiskRows  = b1[6].results ?? [];
  const brandTotal     = b1[7].results?.[0]?.n ?? 0;
  const events30d      = b1[8].results?.[0]?.n ?? 0;
  const newAssets30d   = b1[9].results?.[0]?.n ?? 0;
  const totalDomains   = b1[10].results?.[0]?.n ?? 0;

  // ── D1 Batch 2: scan-specific data ────────────────────────────────────────
  const scanId = latestScan?.id ?? null;
  let criticalFindings = 0, highFindings = 0, mediumFindings = 0, lowFindings = 0;
  let topRemediation   = [];

  if (scanId) {
    try {
      const b2 = await env.cybermeters_db.batch([
        env.cybermeters_db.prepare(
          `SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id = ? GROUP BY severity`
        ).bind(scanId),
        env.cybermeters_db.prepare(
          `SELECT title, priority, action FROM remediation_items
           WHERE scan_id = ? ORDER BY priority ASC LIMIT 5`
        ).bind(scanId),
      ]);
      const sevMap = Object.fromEntries((b2[0].results ?? []).map(r => [r.severity, r.n]));
      criticalFindings = sevMap.critical ?? 0;
      highFindings     = sevMap.high     ?? 0;
      mediumFindings   = sevMap.medium   ?? 0;
      lowFindings      = sevMap.low      ?? 0;
      topRemediation   = (b2[1].results ?? []).map(r => ({
        title:       r.title,
        priority:    Number(r.priority),
        description: r.action,
      }));
    } catch { /* non-fatal — findings unavailable */ }
  }

  // ── R2: latest scan report for module-level data (1 subrequest) ───────────
  let report = null;
  if (scanId) {
    try {
      const obj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
      if (obj) report = await obj.json();
    } catch { /* tolerate missing report */ }
  }

  // Derived values from R2 modules
  const saasTotal      = report?.modules?.saas_exposure?.total ?? 0;
  const adminTotal     = report?.modules?.admin_surface_detection?.total ?? 0;
  const certRiskLevel  = report?.modules?.certificate_intelligence?.certificate_risk_level ?? null;
  const certSignals    = report?.modules?.certificate_intelligence?.suspicious_certificate_signals ?? [];
  const certDaysLeft   = report?.modules?.certificate_intelligence?.days_until_expiry ?? null;
  const tpaTotal       = report?.modules?.third_party_assets?.total ?? 0;
  const cloudAssetList = report?.modules?.cloud_storage_discovery?.assets ?? [];

  // Computed helpers
  const assetTypeMap  = Object.fromEntries(assetTypeRows.map(r => [r.asset_type, r.n]));
  const vendorRiskMap = Object.fromEntries(vendorRiskRows.map(r => [r.risk_level, r.n]));
  const brandRiskMap  = Object.fromEntries(brandRiskRows.map(r => [r.risk_level, r.n]));
  const brandHighRisk = brandRiskMap.high   ?? 0;
  const brandMedRisk  = brandRiskMap.medium ?? 0;
  const activeBrands  = brandHighRisk + brandMedRisk + (brandRiskMap.low ?? 0);

  // ── Executive Summary ──────────────────────────────────────────────────────
  const good              = [];
  const attentionRequired = [];
  const urgent            = [];

  // ── Good signals ──────────────────────────────────────────────────────────
  if (activeAssets > 0) {
    good.push(
      `Asset inventory is active — ${activeAssets} asset${activeAssets !== 1 ? 's' : ''} monitored across ${totalDomains} domain${totalDomains !== 1 ? 's' : ''}.`
    );
  }
  if (!cloudAssetList.length && !assetTypeMap['cloud_storage']) {
    good.push('No cloud storage exposure was detected.');
  }
  if (vendorsActive > 0) {
    good.push(
      `Vendor dependencies are visible — ${vendorsActive} third-party vendor${vendorsActive !== 1 ? 's' : ''} detected.`
    );
  }
  if (criticalFindings === 0 && highFindings === 0) {
    good.push('No critical or high-severity findings in the latest scan.');
  }
  if (brandHighRisk === 0 && activeBrands === 0) {
    good.push('No active brand impersonation domains detected.');
  }
  if (adminTotal === 0) {
    good.push('No exposed admin or management surfaces detected.');
  }
  if (certRiskLevel === 'low' || (certRiskLevel === null && certSignals.length === 0)) {
    good.push('Certificate health looks normal — no suspicious signals detected.');
  }

  // ── Attention Required ────────────────────────────────────────────────────
  if (events30d > 0) {
    attentionRequired.push(
      `Attack surface changed in the last 30 days — ${events30d} asset event${events30d !== 1 ? 's' : ''} recorded.`
    );
  }
  if (newAssets30d > 0) {
    attentionRequired.push(
      `${newAssets30d} new asset${newAssets30d !== 1 ? 's' : ''} discovered in the last 30 days.`
    );
  }
  if (tpaTotal > 0) {
    attentionRequired.push(
      `${tpaTotal} third-party service${tpaTotal !== 1 ? 's' : ''} in use — email, support, or marketing tools with external data access.`
    );
  }
  if (certSignals.length > 0 && certRiskLevel !== 'critical') {
    const sigPreview = certSignals.slice(0, 2).join(', ');
    attentionRequired.push(
      `Certificate intelligence flagged ${certSignals.length} suspicious signal${certSignals.length !== 1 ? 's' : ''}: ${sigPreview}.`
    );
  }
  if (saasTotal > 0) {
    attentionRequired.push(
      `${saasTotal} SaaS portal${saasTotal !== 1 ? 's' : ''} exposed — login or admin access may be reachable externally.`
    );
  }
  if ((vendorRiskMap.medium ?? 0) > 0) {
    attentionRequired.push(
      `${vendorRiskMap.medium} medium-risk vendor${(vendorRiskMap.medium ?? 0) !== 1 ? 's' : ''} detected in the supply chain.`
    );
  }
  if (brandMedRisk > 0 && brandHighRisk === 0) {
    attentionRequired.push(
      `${brandMedRisk} medium-risk typosquat domain${brandMedRisk !== 1 ? 's' : ''} found actively resolving.`
    );
  }

  // ── Urgent ────────────────────────────────────────────────────────────────
  if (criticalFindings > 0) {
    urgent.push(
      `${criticalFindings} critical finding${criticalFindings !== 1 ? 's' : ''} require immediate remediation.`
    );
  }
  if (highFindings > 0) {
    urgent.push(
      `${highFindings} high-severity finding${highFindings !== 1 ? 's' : ''} should be addressed soon.`
    );
  }
  if (brandHighRisk > 0) {
    urgent.push(
      `${brandHighRisk} high-risk brand impersonation domain${brandHighRisk !== 1 ? 's' : ''} ${brandHighRisk === 1 ? 'is' : 'are'} actively resolving — phishing risk.`
    );
  }
  if (adminTotal > 0) {
    urgent.push(
      `${adminTotal} admin surface${adminTotal !== 1 ? 's' : ''} exposed to the internet — management interfaces should not be publicly accessible.`
    );
  }
  if ((vendorRiskMap.high ?? 0) > 0) {
    urgent.push(
      `${vendorRiskMap.high} high-risk vendor${(vendorRiskMap.high ?? 0) !== 1 ? 's' : ''} detected — supply chain exposure requires review.`
    );
  }
  if (certRiskLevel === 'critical') {
    const certDetail = certDaysLeft !== null
      ? `expires in ${certDaysLeft} day${certDaysLeft !== 1 ? 's' : ''}`
      : 'suspicious signals detected';
    urgent.push(`Certificate is at critical risk — ${certDetail}.`);
  }

  // ── Security Posture Breakdown ────────────────────────────────────────────
  const security_posture = computeSecurityPosture(
    // Pass a partial scorecard-like object — only the fields computeSecurityPosture reads
    {
      last_scanned_domain: latestScan?.domain ?? null,
      new_assets_30d:      newAssets30d,
      vendor_risk:         { high: vendorRiskMap.high ?? 0, medium: vendorRiskMap.medium ?? 0, low: vendorRiskMap.low ?? 0 },
      third_party_assets:  tpaTotal,
      saas_exposures:      saasTotal,
      admin_surfaces:      adminTotal,
      brand_risks:         { high: brandHighRisk, medium: brandMedRisk, low: brandRiskMap.low ?? 0 },
      certificate_risks:   { risk_level: certRiskLevel, signals: certSignals.length, days_until_expiry: certDaysLeft },
    },
    report
  );

  // ── Final scorecard object ─────────────────────────────────────────────────
  return {
    workspace_id:        wsId,
    workspace_name:      wsName,
    security_score:      latestScan?.score  ?? null,
    risk_rating:         latestScan?.rating ?? 'unknown',
    last_scan_at:        latestScan?.created_at ?? null,
    last_scanned_domain: latestScan?.domain     ?? null,
    attack_surface_size: activeAssets,
    active_assets:       activeAssets,
    new_assets_30d:      newAssets30d,
    vendors_detected:    vendorsActive,
    vendor_risk: {
      high:   vendorRiskMap.high   ?? 0,
      medium: vendorRiskMap.medium ?? 0,
      low:    vendorRiskMap.low    ?? 0,
    },
    third_party_assets: tpaTotal,
    saas_exposures:     saasTotal,
    admin_surfaces:     adminTotal,
    brand_risks: {
      total:  brandTotal,
      active: activeBrands,
      high:   brandHighRisk,
      medium: brandMedRisk,
      low:    brandRiskMap.low ?? 0,
    },
    certificate_risks: {
      risk_level:        certRiskLevel,
      signals:           certSignals.length,
      days_until_expiry: certDaysLeft,
    },
    critical_findings: criticalFindings,
    high_findings:     highFindings,
    medium_findings:   mediumFindings,
    low_findings:      lowFindings,
    asset_events_30d:  events30d,
    executive_summary: {
      good,
      attention_required: attentionRequired,
      urgent,
    },
    top_recommendations: topRemediation,
    security_posture,
  };
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
 * Compute next_run_at for a scheduled_reports row.
 * weekly   → next Monday 00:00 UTC
 * monthly  → 1st of next month 00:00 UTC
 * quarterly→ 1st of next calendar quarter 00:00 UTC
 */
function computeScheduledReportNextRunAt(frequency) {
  const now = new Date();
  const y   = now.getUTCFullYear();
  const m   = now.getUTCMonth(); // 0-based

  if (frequency === "weekly") {
    // Next Monday
    const d = new Date(Date.UTC(y, m, now.getUTCDate()));
    const dow = d.getUTCDay(); // 0=Sun
    const daysUntilMonday = dow === 0 ? 1 : (8 - dow);
    d.setUTCDate(d.getUTCDate() + daysUntilMonday);
    return d.toISOString();
  }
  if (frequency === "monthly") {
    // 1st of next month
    return new Date(Date.UTC(y, m + 1, 1)).toISOString();
  }
  if (frequency === "quarterly") {
    // 1st of next calendar quarter
    const nextQ = Math.floor(m / 3) + 1;
    const nextQYear  = y + Math.floor(nextQ / 4);
    const nextQMonth = (nextQ % 4) * 3; // 0, 3, 6, 9
    return new Date(Date.UTC(nextQYear, nextQMonth, 1)).toISOString();
  }
  // fallback: 30 days
  return new Date(Date.now() + 30 * 24 * 60 * 60 * 1_000).toISOString();
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

// ── PDF Generation Engine v1 ──────────────────────────────────────────────────
// Builds a US-Letter (612 × 792 pt) PDF from the pdf-data JSON payload.
// Uses PDF 1.4 built-in Type1 fonts (Helvetica, Helvetica-Bold) — no embedding.
// Pure JS — no external dependencies, Cloudflare Worker compatible.

function buildExecutivePdf(pdfData) {
  const W = 612, H = 792, ML = 50, MR = 50, CW = W - ML - MR;

  // Colours [R, G, B] in 0–1 range
  const C = {
    green:   [0.000, 0.529, 0.416],
    dkgreen: [0.024, 0.306, 0.231],
    white:   [1.000, 1.000, 1.000],
    dkgray:  [0.122, 0.161, 0.216],
    mgray:   [0.420, 0.447, 0.502],
    lgray:   [0.953, 0.957, 0.965],
    red:     [0.600, 0.110, 0.110],
    amber:   [0.854, 0.467, 0.024],
    blue:    [0.114, 0.306, 0.847],
    teal:    [0.820, 0.980, 0.910],
  };
  function rgb(c) { return c.map(v => v.toFixed(3)).join(' '); }
  function sevColor(s) {
    return { critical: C.red, high: C.amber, medium: C.blue, low: C.mgray }[s] ?? C.mgray;
  }

  // Escape text for PDF string literals — strict ASCII 0x20–0x7E only
  const REMAP = {
    '–':'-','—':'-','‘':"'",'’':"'",
    '“':'"','”':'"','•':'*','…':'...',
    '£':'GBP','€':'EUR',' ':' ',
  };
  function esc(v) {
    return String(v ?? '')
      .replace(/[^\x20-\x7E]/g, c => REMAP[c] ?? ' ')
      .replace(/\\/g,'\\\\').replace(/\(/g,'\\(').replace(/\)/g,'\\)');
  }

  // Word-wrap: split text into lines that fit within maxW pts at given size.
  // Helvetica average char width ≈ 0.55 × fontSize.
  function wrap(text, maxW, size) {
    const maxC  = Math.max(1, Math.floor(maxW / (size * 0.55)));
    const words = String(text ?? '').split(/\s+/).filter(Boolean);
    if (!words.length) return [''];
    const lines = [];
    let cur = '';
    for (const w of words) {
      if (!cur) { cur = w; continue; }
      if (cur.length + 1 + w.length <= maxC) { cur += ' ' + w; }
      else { lines.push(cur); cur = w; }
    }
    if (cur) lines.push(cur);
    return lines;
  }

  // ── PDF object store ─────────────────────────────────────────────────────
  // IDs 1–4 are reserved (catalog, pages, F1, F2) and injected at assembly.
  const _objs = [];
  let _nextId = 5;
  function addObj(body) { const id = _nextId++; _objs.push({ id, body }); return id; }

  // ── Page builder ─────────────────────────────────────────────────────────
  const _pageIds = [];
  function newPage() {
    const ops  = [];
    const emit = (...a) => ops.push(a.join(' '));
    const ctx  = {
      fillRect(x, y, w, h, col) {
        emit(rgb(col), `rg ${x.toFixed(1)} ${y.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)} re f`);
        emit('0 0 0 rg');
      },
      strokeRect(x, y, w, h, col, lw = 0.5) {
        emit(`${lw} w`, rgb(col), `RG ${x.toFixed(1)} ${y.toFixed(1)} ${w.toFixed(1)} ${h.toFixed(1)} re S`);
        emit('0 0 0 RG 0.5 w');
      },
      hline(x, y, w, col = C.lgray, lw = 0.5) {
        emit(`${lw} w`, rgb(col), `RG ${x.toFixed(1)} ${y.toFixed(1)} m ${(x+w).toFixed(1)} ${y.toFixed(1)} l S`);
        emit('0 0 0 RG 0.5 w');
      },
      text(str, x, y, size, font = 'R', col = C.dkgray) {
        const f = font === 'B' ? 'F2' : 'F1';
        emit(`BT /${f} ${size} Tf`, rgb(col), `rg ${x.toFixed(1)} ${y.toFixed(1)} Td (${esc(str)}) Tj ET`);
        emit('0 0 0 rg');
      },
      flush() {
        const stream = ops.join('\n');
        const csId   = addObj(`<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`);
        const pgId   = addObj(
          `<< /Type /Page /Parent 2 0 R\n` +
          `/MediaBox [0 0 ${W} ${H}]\n` +
          `/Contents ${csId} 0 R\n` +
          `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >>\n>>`
        );
        _pageIds.push(pgId);
      },
    };
    return ctx;
  }

  // ── Shared layout helpers ─────────────────────────────────────────────────
  function pgBanner(pg, section) {
    pg.fillRect(0, H - 28, W, 28, C.dkgreen);
    pg.text('CYBERMETERS', ML, H - 17, 9, 'B', C.white);
    pg.text('EXECUTIVE SECURITY REPORT', ML + 90, H - 17, 8, 'R', C.teal);
    if (section) pg.text(section.toUpperCase(), W - 60 - section.length * 4.5, H - 17, 7.5, 'R', C.teal);
  }
  function pgFooter(pg, n, total) {
    pg.hline(ML, 32, CW, C.mgray, 0.3);
    pg.text('CyberMeters Platform  |  Confidential', ML, 20, 7.5, 'R', C.mgray);
    pg.text(`Page ${n} of ${total}`, W - 80, 20, 7.5, 'R', C.mgray);
  }
  function secBar(pg, title, y) {
    pg.fillRect(ML, y - 2, CW, 19, C.green);
    pg.text(title, ML + 8, y + 3, 9.5, 'B', C.white);
    return y - 22;
  }

  // ── Extract fields ────────────────────────────────────────────────────────
  const ws   = pdfData.workspace            ?? {};
  const gd   = String(pdfData.generated_at ?? '').slice(0, 10) || new Date().toISOString().slice(0, 10);
  const sp   = pdfData.security_posture     ?? {};
  const es   = pdfData.executive_summary    ?? {};
  const fs   = pdfData.findings_summary     ?? {};
  const ai   = pdfData.asset_inventory      ?? {};
  const vr   = pdfData.vendor_risk          ?? {};
  const bm   = pdfData.brand_monitoring     ?? {};
  const ci   = pdfData.certificate_intelligence ?? {};
  const topR = pdfData.top_risks            ?? [];
  const topC = pdfData.top_recommendations  ?? [];
  const trnd = pdfData.risk_trend           ?? [];
  const ovr  = pdfData.overall_score;
  const rtng = String(pdfData.risk_rating   ?? 'Unknown');
  const NP   = 6;  // total pages

  // ── PAGE 1: COVER ─────────────────────────────────────────────────────────
  {
    const pg = newPage();
    pg.fillRect(0, 0, W, H, C.lgray);
    pg.fillRect(0, 0, 190, H, C.dkgreen);

    pg.text('CYBERMETERS', 16, H - 50, 14, 'B', C.white);
    pg.text('Platform',    16, H - 66,  9, 'R', C.teal);

    const scoreStr = ovr != null ? String(ovr) : '--';
    pg.fillRect(12, H/2 - 85, 166, 115, C.green);
    pg.text('SECURITY SCORE', 22, H/2 + 16, 7.5, 'B', C.white);
    const sX = scoreStr.length >= 3 ? 50 : scoreStr.length === 2 ? 65 : 80;
    pg.text(scoreStr, sX, H/2 - 38, 50, 'B', C.white);
    pg.text('/ 100', 60, H/2 - 60, 10, 'R', C.teal);
    pg.text('RISK RATING', 22, H/2 - 103, 7.5, 'B', C.teal);
    pg.text(rtng.toUpperCase(), 22, H/2 - 119, 12, 'B', C.white);
    pg.text('Generated:', 22, 85, 7.5, 'R', C.teal);
    pg.text(gd,           22, 71, 8.5, 'B', C.white);

    pg.fillRect(190, H - 120, W - 190, 120, C.green);
    pg.text('EXECUTIVE',       208, H - 55,  22, 'B', C.white);
    pg.text('SECURITY REPORT', 208, H - 80,  22, 'B', C.white);
    pg.text('Confidential - For authorised recipients only', 208, H - 100, 8, 'R', C.teal);

    let ry = H - 148;
    pg.text('Workspace',    208, ry, 8, 'R', C.mgray);
    pg.text(String(ws.name ?? 'Unknown'), 295, ry, 11, 'B', C.dkgray); ry -= 20;
    pg.text('Report Date',  208, ry, 8, 'R', C.mgray);
    pg.text(gd,             295, ry,  9, 'R', C.dkgray); ry -= 20;
    pg.text('Coverage',     208, ry, 8, 'R', C.mgray);
    pg.text('Last 30 days', 295, ry,  9, 'R', C.dkgray); ry -= 12;
    pg.hline(208, ry, W - 220, C.lgray, 0.8); ry -= 18;

    pg.text('SECURITY POSTURE OVERVIEW', 208, ry, 8, 'B', C.green); ry -= 15;
    for (const [name, cat] of [
      ['Email Security',     sp.email_security],
      ['SSL & Certificates', sp.ssl_certificates],
      ['Attack Surface',     sp.attack_surface],
      ['Third-Party Risk',   sp.third_party_risk],
      ['Admin Exposure',     sp.admin_exposure],
    ]) {
      const cs = cat?.score  ?? null;
      const st = cat?.status ?? 'unknown';
      const bc = st === 'good' ? C.green : st === 'fair' ? C.blue : st === 'warning' ? C.amber : st === 'critical' ? C.red : C.mgray;
      pg.text(name, 208, ry, 8.5, 'R', C.dkgray);
      pg.fillRect(315, ry - 2, 88, 9, C.lgray);
      if (cs != null) pg.fillRect(315, ry - 2, Math.max(1, Math.round(88 * cs / 100)), 9, bc);
      pg.text(cs != null ? String(cs) : '-', 408, ry, 8.5, 'B', bc);
      ry -= 15;
    }
    pg.hline(208, ry, W - 220, C.lgray, 0.5); ry -= 14;
    pg.text('FINDINGS SNAPSHOT', 208, ry, 8, 'B', C.green); ry -= 14;
    let fx = 208;
    for (const [lbl, cnt, col] of [['Critical', fs.critical ?? 0, C.red], ['High', fs.high ?? 0, C.amber], ['Medium', fs.medium ?? 0, C.blue], ['Low', fs.low ?? 0, C.mgray]]) {
      pg.fillRect(fx, ry - 24, 82, 30, col);
      pg.text(String(cnt), fx + (cnt >= 10 ? 24 : 30), ry - 7, 14, 'B', C.white);
      pg.text(lbl, fx + 5, ry - 23, 7, 'R', C.white);
      fx += 83;
    }
    pg.text('cybermeters.io', 208, 20, 7.5, 'R', C.mgray);
    pg.flush();
  }

  // ── PAGE 2: EXECUTIVE SUMMARY ─────────────────────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Executive Summary');
    pgFooter(pg, 2, NP);
    let y = H - 45;

    y = secBar(pg, 'Executive Summary', y); y -= 6;

    // Strengths
    pg.fillRect(ML, y - 18, CW, 18, [0.216, 0.580, 0.416]);
    pg.text('STRENGTHS', ML + 8, y - 12, 9, 'B', C.white); y -= 22;
    const strengths = es.strengths ?? [];
    if (!strengths.length) { pg.text('Security monitoring is active.', ML + 8, y - 10, 8.5, 'R', C.mgray); y -= 14; }
    for (const s of strengths.slice(0, 4)) {
      for (const ln of wrap(s, CW - 20, 8.5)) { if (y < 90) break; pg.text('* ' + ln, ML + 8, y - 10, 8.5, 'R', C.dkgray); y -= 13; }
    }
    y -= 6;

    // Weaknesses
    pg.fillRect(ML, y - 18, CW, 18, C.red);
    pg.text('WEAKNESSES', ML + 8, y - 12, 9, 'B', C.white); y -= 22;
    const weaknesses = es.weaknesses ?? [];
    if (!weaknesses.length) { pg.text('No significant weaknesses identified.', ML + 8, y - 10, 8.5, 'R', C.mgray); y -= 14; }
    for (const w of weaknesses.slice(0, 4)) {
      for (const ln of wrap(w, CW - 20, 8.5)) { if (y < 90) break; pg.text('* ' + ln, ML + 8, y - 10, 8.5, 'R', C.dkgray); y -= 13; }
    }
    y -= 6;

    // Priority actions
    pg.fillRect(ML, y - 18, CW, 18, C.amber);
    pg.text('PRIORITY ACTIONS', ML + 8, y - 12, 9, 'B', C.white); y -= 22;
    const actions = es.priority_actions ?? [];
    if (!actions.length) { pg.text('No priority actions at this time.', ML + 8, y - 10, 8.5, 'R', C.mgray); y -= 14; }
    for (let i = 0; i < actions.length && y > 90; i++) {
      pg.fillRect(ML + 6, y - 15, 16, 14, C.green);
      pg.text(String(i + 1), ML + 11, y - 10, 8, 'B', C.white);
      for (const ln of wrap(actions[i], CW - 36, 8.5)) {
        if (y < 90) break;
        pg.text(ln, ML + 28, y - 10, 8.5, 'R', C.dkgray); y -= 13;
      }
      y -= 4;
    }
    y -= 10;

    // Findings summary
    if (y > 120) {
      y = secBar(pg, 'Findings Summary', y); y -= 10;
      const bw2 = Math.floor(CW / 5);
      let sx = ML;
      for (const [lbl, cnt, col] of [['Critical', fs.critical ?? 0, C.red], ['High', fs.high ?? 0, C.amber], ['Medium', fs.medium ?? 0, C.blue], ['Low', fs.low ?? 0, C.mgray], ['Info', fs.info ?? 0, [0.6, 0.6, 0.6]]]) {
        pg.fillRect(sx, y - 42, bw2 - 3, 42, col);
        const ns = String(cnt);
        pg.text(ns, sx + Math.max(4, Math.floor((bw2 - 3) / 2) - ns.length * 7), y - 16, 20, 'B', C.white);
        pg.text(lbl, sx + 6, y - 40, 7.5, 'R', C.white);
        sx += bw2;
      }
      y -= 50;
      pg.text(`Total findings: ${fs.total ?? 0}`, ML, y - 8, 9, 'B', C.dkgray);
    }
    pg.flush();
  }

  // ── PAGE 3: SECURITY POSTURE ──────────────────────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Security Posture');
    pgFooter(pg, 3, NP);
    let y = H - 45;

    y = secBar(pg, 'Security Posture Breakdown', y); y -= 8;

    if (ovr != null) {
      pg.text('Overall Security Score:', ML, y - 10, 9.5, 'R', C.dkgray);
      pg.text(String(ovr), ML + 145, y - 10, 14, 'B', C.green);
      pg.text('/ 100', ML + 145 + (Number(ovr) >= 100 ? 22 : Number(ovr) >= 10 ? 14 : 8), y - 10, 9, 'R', C.mgray);
      y -= 26;
    }

    for (const [name, cat, wt] of [
      ['Email Security',     sp.email_security,   '20%'],
      ['SSL & Certificates', sp.ssl_certificates, '20%'],
      ['Attack Surface',     sp.attack_surface,   '25%'],
      ['Third-Party Risk',   sp.third_party_risk, '15%'],
      ['Admin Exposure',     sp.admin_exposure,   '20%'],
    ]) {
      if (y < 90) break;
      const cs  = cat?.score  ?? null;
      const st  = cat?.status ?? 'unknown';
      const rns = cat?.reasons ?? [];
      const bc  = st === 'good' ? C.green : st === 'fair' ? C.blue : st === 'warning' ? C.amber : st === 'critical' ? C.red : C.mgray;
      const bg  = st === 'good'     ? [0.937, 0.992, 0.969]
                : st === 'fair'     ? [0.929, 0.945, 0.996]
                : st === 'warning'  ? [0.996, 0.945, 0.863]
                : st === 'critical' ? [0.996, 0.882, 0.882]
                : C.lgray;
      const rowH = 38 + Math.min(rns.length, 3) * 13;
      pg.fillRect(ML, y - rowH, CW, rowH, bg);
      pg.strokeRect(ML, y - rowH, CW, rowH, bc, 0.5);

      pg.text(name, ML + 8, y - 13, 10, 'B', C.dkgray);
      pg.text(`(Weight: ${wt})`, ML + 8 + name.length * 6.2, y - 13, 8, 'R', C.mgray);
      const csStr = cs != null ? String(cs) : '--';
      pg.text(csStr, ML + CW - 55, y - 11, 14, 'B', bc);
      pg.text('/ 100', ML + CW - 55 + csStr.length * 9, y - 13, 8, 'R', C.mgray);
      pg.text(st.toUpperCase(), ML + CW - 55, y - 25, 7.5, 'B', bc);

      const barX = ML + 8, barY = y - 30, barW = CW - 80;
      pg.fillRect(barX, barY, barW, 7, C.lgray);
      if (cs != null) pg.fillRect(barX, barY, Math.max(1, Math.round(barW * cs / 100)), 7, bc);

      let ry3 = y - 38;
      for (const rsn of rns.slice(0, 3)) {
        if (ry3 < y - rowH + 4) break;
        pg.text('- ' + (wrap(rsn, CW - 28, 8)[0] ?? rsn.slice(0, 75)), ML + 14, ry3, 8, 'R', C.mgray);
        ry3 -= 13;
      }
      y = y - rowH - 6;
    }
    pg.flush();
  }

  // ── PAGE 4: TOP RISKS + TOP RECOMMENDATIONS ───────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Top Risks');
    pgFooter(pg, 4, NP);
    let y = H - 45;

    y = secBar(pg, 'Top Risks', y); y -= 4;

    if (!topR.length) {
      pg.text('No active risks identified.', ML + 8, y - 14, 9, 'R', C.mgray);
      y -= 24;
    } else {
      const RCOLS = [76, 168, 96, 70, 102];
      const RHDRS = ['Severity', 'Title', 'Domain', 'Date', 'Recommendation'];
      pg.fillRect(ML, y - 17, CW, 17, C.dkgray);
      let hx = ML;
      for (let i = 0; i < RHDRS.length; i++) {
        pg.text(RHDRS[i], hx + 4, y - 12, 7.5, 'B', C.white); hx += RCOLS[i];
      }
      y -= 19;
      for (let ri = 0; ri < topR.length && y > 90; ri++) {
        const r = topR[ri];
        pg.fillRect(ML, y - 17, CW, 17, ri % 2 === 0 ? C.lgray : C.white);
        let rx2 = ML;
        pg.fillRect(rx2 + 3, y - 14, RCOLS[0] - 10, 11, sevColor(r.severity));
        pg.text(String(r.severity ?? '').toUpperCase(), rx2 + 5, y - 8, 6.5, 'B', C.white); rx2 += RCOLS[0];
        pg.text(String(r.title  ?? '').slice(0, 26), rx2 + 4, y - 11, 8,   'R', C.dkgray); rx2 += RCOLS[1];
        pg.text(String(r.domain ?? '').slice(0, 15), rx2 + 4, y - 11, 8,   'R', C.dkgray); rx2 += RCOLS[2];
        pg.text(String(r.date   ?? '').slice(0, 10), rx2 + 4, y - 11, 8,   'R', C.dkgray); rx2 += RCOLS[3];
        pg.text(String(r.recommendation ?? '').slice(0, 15), rx2 + 4, y - 11, 7, 'R', C.mgray);
        pg.hline(ML, y - 17, CW, C.lgray, 0.2);
        y -= 18;
      }
    }
    y -= 8;

    if (y > 120) {
      y = secBar(pg, 'Top Recommendations', y); y -= 6;
      if (!topC.length) {
        pg.text('No recommendations at this time.', ML + 8, y - 12, 9, 'R', C.mgray);
      } else {
        for (let i = 0; i < Math.min(topC.length, 5) && y > 90; i++) {
          const rec = topC[i];
          const rh  = 16 + (rec.description ? 13 : 0);
          pg.fillRect(ML, y - rh, CW, rh, i % 2 === 0 ? C.lgray : C.white);
          pg.fillRect(ML + 4, y - rh + 3, 18, 14, C.green);
          pg.text(String(rec.priority ?? i + 1), ML + 8, y - rh + 7, 8, 'B', C.white);
          pg.text(String(rec.title ?? '').slice(0, 70), ML + 28, y - rh + 12, 9, 'B', C.dkgray);
          if (rec.description) pg.text(String(rec.description ?? '').slice(0, 90), ML + 28, y - rh + 1, 8, 'R', C.mgray);
          y -= rh + 3;
        }
      }
    }
    pg.flush();
  }

  // ── PAGE 5: RISK TREND + ASSET INVENTORY ─────────────────────────────────
  {
    const pg = newPage();
    pgBanner(pg, 'Risk Trend');
    pgFooter(pg, 5, NP);
    let y = H - 45;

    y = secBar(pg, 'Risk Trend (Last 30 Days)', y); y -= 4;

    if (!trnd.length) {
      pg.text('No trend data yet. Run scans to populate this section.', ML + 8, y - 14, 9, 'R', C.mgray);
      y -= 28;
    } else {
      const TCOLS = [88, 100, 100, 100, 124];
      const THDRS = ['Date', 'Avg Score', 'Low Score', 'High Score', 'Asset Count'];
      pg.fillRect(ML, y - 17, CW, 17, C.dkgray);
      let tx = ML;
      for (let i = 0; i < THDRS.length; i++) {
        pg.text(THDRS[i], tx + 4, y - 12, 7.5, 'B', C.white); tx += TCOLS[i];
      }
      y -= 19;
      for (let ti = 0; ti < trnd.length && y > 90; ti++) {
        const t   = trnd[ti];
        const avg = t.average_score;
        const ac  = avg == null ? C.dkgray : Number(avg) >= 80 ? C.green : Number(avg) >= 60 ? C.amber : C.red;
        pg.fillRect(ML, y - 16, CW, 16, ti % 2 === 0 ? C.lgray : C.white);
        const vals = [
          t.date             ?? '-',
          avg  != null ? String(avg)              : '-',
          t.lowest_score  != null ? String(t.lowest_score)  : '-',
          t.highest_score != null ? String(t.highest_score) : '-',
          t.asset_count   != null ? String(t.asset_count)   : '-',
        ];
        let vx = ML;
        for (let i = 0; i < vals.length; i++) {
          pg.text(vals[i], vx + 4, y - 11, 8, i === 1 ? 'B' : 'R', i === 1 ? ac : C.dkgray);
          vx += TCOLS[i];
        }
        pg.hline(ML, y - 16, CW, C.lgray, 0.2);
        y -= 17;
      }
    }
    y -= 10;

    if (y > 160) {
      y = secBar(pg, 'Asset Inventory', y); y -= 8;
      const colW = Math.floor(CW / 2) - 4;
      let ax = ML, ay = y - 12, ac2 = 0;
      for (const [k, v] of [
        ['Active Assets',        ai.assets?.current                  ?? '-'],
        ['New Assets (30d)',      ai.new_assets_30d                   ?? '-'],
        ['Asset Events (30d)',    ai.asset_events_30d                 ?? '-'],
        ['Vendors Detected',     ai.vendors?.current                 ?? '-'],
        ['Third-Party Services', ai.third_party_services?.current    ?? '-'],
        ['SaaS Exposures',       ai.saas_exposures?.current          ?? '-'],
        ['Brand Candidates',     ai.brand_candidates?.current        ?? '-'],
      ]) {
        if (ay < 90) break;
        pg.fillRect(ax, ay - 14, colW, 19, ac2 % 4 < 2 ? C.lgray : C.white);
        pg.text(k, ax + 8, ay - 8, 8, 'R', C.mgray);
        pg.text(String(v), ax + colW - 35, ay - 8, 9.5, 'B', C.dkgray);
        ac2++;
        if (ax === ML) { ax = ML + colW + 8; } else { ax = ML; ay -= 22; }
      }
    }
    pg.flush();
  }

  // ── PAGE 6: VENDOR / BRAND / CERTIFICATE INTELLIGENCE ────────────────────
  {
    const pg  = newPage();
    pgBanner(pg, 'Intelligence');
    pgFooter(pg, 6, NP);
    let y    = H - 45;
    const c2 = Math.floor(CW / 2) - 4;

    y = secBar(pg, 'Vendor Risk Summary', y); y -= 8;
    let vx2 = ML, vy = y - 12;
    for (let i = 0; i < 4; i++) {
      const [k, v] = [['Total Vendors', vr.total ?? '-'], ['High Risk', vr.high ?? '-'], ['Medium Risk', vr.medium ?? '-'], ['Low Risk', vr.low ?? '-']][i];
      pg.fillRect(vx2, vy - 14, c2, 19, i % 4 < 2 ? C.lgray : C.white);
      pg.text(k, vx2 + 8, vy - 8, 8, 'R', C.mgray);
      pg.text(String(v), vx2 + c2 - 35, vy - 8, 9.5, 'B', C.dkgray);
      if (vx2 === ML) { vx2 = ML + c2 + 8; } else { vx2 = ML; vy -= 22; }
    }
    y = vy - 20;

    y = secBar(pg, 'Brand Monitoring', y); y -= 8;
    let bx2 = ML, by2 = y - 12;
    for (let i = 0; i < 4; i++) {
      const [k, v] = [['Total Candidates', bm.total_candidates ?? '-'], ['Active Risks', bm.active_risks ?? '-'], ['High Risk', bm.high ?? '-'], ['Medium Risk', bm.medium ?? '-']][i];
      pg.fillRect(bx2, by2 - 14, c2, 19, i % 4 < 2 ? C.lgray : C.white);
      pg.text(k, bx2 + 8, by2 - 8, 8, 'R', C.mgray);
      pg.text(String(v), bx2 + c2 - 35, by2 - 8, 9.5, 'B', C.dkgray);
      if (bx2 === ML) { bx2 = ML + c2 + 8; } else { bx2 = ML; by2 -= 22; }
    }
    y = by2 - 20;

    y = secBar(pg, 'Certificate Intelligence', y); y -= 8;
    let cx3 = ML, cy3 = y - 12;
    for (let i = 0; i < 4; i++) {
      const [k, v] = [
        ['Risk Level',    ci.risk_level ?? '-'],
        ['Signal Count',  String(ci.signals ?? '-')],
        ['Days to Expiry',ci.days_until_expiry != null ? String(ci.days_until_expiry) : '-'],
        ['Status',        ci.status ?? '-'],
      ][i];
      const vc = k === 'Risk Level' && String(v).toLowerCase() === 'critical' ? C.red
               : k === 'Risk Level' && String(v).toLowerCase() === 'high'     ? C.amber
               : C.dkgray;
      pg.fillRect(cx3, cy3 - 14, c2, 19, i % 4 < 2 ? C.lgray : C.white);
      pg.text(k, cx3 + 8, cy3 - 8, 8, 'R', C.mgray);
      pg.text(String(v), cx3 + c2 - 35, cy3 - 8, 9.5, 'B', vc);
      if (cx3 === ML) { cx3 = ML + c2 + 8; } else { cx3 = ML; cy3 -= 22; }
    }
    y = cy3 - 20;

    if (y > 80) {
      pg.hline(ML, y, CW, C.mgray, 0.3); y -= 14;
      pg.text('This report was generated automatically by the CyberMeters Platform.', ML, y, 8, 'R', C.mgray); y -= 12;
      pg.text(`Data sourced from live scan engine results. Generated: ${gd}.`, ML, y, 8, 'R', C.mgray);
    }
    pg.flush();
  }

  // ── Assemble PDF bytes ────────────────────────────────────────────────────
  const kidsStr = _pageIds.map(id => `${id} 0 R`).join(' ');
  const allObjs = [
    { id: 1, body: '<< /Type /Catalog /Pages 2 0 R >>' },
    { id: 2, body: `<< /Type /Pages /Kids [${kidsStr}] /Count ${_pageIds.length} >>` },
    { id: 3, body: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>' },
    { id: 4, body: '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>' },
    ..._objs,
  ].sort((a, b) => a.id - b.id);

  const enc    = new TextEncoder();
  const chunks = [];
  let bPos     = 0;
  const xmap   = new Map();
  function wrt(s) { const b = enc.encode(s); chunks.push(b); bPos += b.length; }

  wrt('%PDF-1.4\n');
  for (const o of allObjs) {
    xmap.set(o.id, bPos);
    wrt(`${o.id} 0 obj\n${o.body}\nendobj\n\n`);
  }

  const xrefPos = bPos;
  const maxId   = allObjs[allObjs.length - 1].id;
  wrt('xref\n');
  wrt(`0 ${maxId + 1}\n`);
  wrt('0000000000 65535 f \n');
  for (let id = 1; id <= maxId; id++) {
    if (xmap.has(id)) wrt(`${String(xmap.get(id)).padStart(10, '0')} 00000 n \n`);
    else               wrt('0000000000 65535 f \n');
  }
  wrt('trailer\n');
  wrt(`<< /Size ${maxId + 1} /Root 1 0 R >>\n`);
  wrt('startxref\n');
  wrt(`${xrefPos}\n`);
  wrt('%%EOF\n');

  const total = chunks.reduce((s, b) => s + b.length, 0);
  const out   = new Uint8Array(total);
  let pos     = 0;
  for (const b of chunks) { out.set(b, pos); pos += b.length; }
  return out;
}

// ── collectPdfData ────────────────────────────────────────────────────────────
// Shared data layer for both /scorecard/pdf-data (JSON) and /scorecard/pdf (PDF).
// Returns the full data object on success, null if workspace not found.
// Throws on database or scorecard errors.

async function collectPdfData(wsId, env) {
  const ws = await env.cybermeters_db
    .prepare('SELECT id, name, created_at FROM workspaces WHERE id = ?')
    .bind(wsId).first();
  if (!ws) return null;

  const generatedAt = new Date().toISOString();
  const now30dAgo   = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString();

  const sc = await buildScorecardData(wsId, env);
  if (!sc) throw new Error('buildScorecardData returned null');

  const [trendR, topRisksR, infoCntR, assetDeltaR, vendorDeltaR] = await Promise.allSettled([
    env.cybermeters_db.prepare(
      `SELECT s.domain, s.score, s.created_at
       FROM scans s
       JOIN domains d ON d.id = s.domain_id
       JOIN workspace_domains wd ON wd.domain_id = d.id
       WHERE wd.workspace_id = ? AND s.status = 'completed'
         AND s.score IS NOT NULL AND s.created_at >= ?
       ORDER BY s.domain, s.created_at DESC
       LIMIT 1000`
    ).bind(wsId, now30dAgo).all(),

    env.cybermeters_db.prepare(
      `SELECT f.title, f.severity, f.recommendation, s.domain, s.created_at
       FROM findings f
       JOIN scans s ON s.id = f.scan_id
       JOIN domains d ON d.id = s.domain_id
       JOIN workspace_domains wd ON wd.domain_id = d.id
       WHERE wd.workspace_id = ?
       ORDER BY CASE f.severity
         WHEN 'critical' THEN 1 WHEN 'high' THEN 2
         WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4 ELSE 5 END,
         s.created_at DESC
       LIMIT 200`
    ).bind(wsId).all(),

    env.cybermeters_db.prepare(
      `SELECT COUNT(*) AS n FROM findings f
       JOIN scans s ON s.id = f.scan_id
       JOIN domains d ON d.id = s.domain_id
       JOIN workspace_domains wd ON wd.domain_id = d.id
       WHERE wd.workspace_id = ? AND f.severity = 'info'`
    ).bind(wsId).first(),

    env.cybermeters_db.prepare(
      `SELECT COUNT(*) AS n FROM workspace_assets
       WHERE workspace_id = ? AND status = 'active' AND first_seen < ?`
    ).bind(wsId, now30dAgo).first(),

    env.cybermeters_db.prepare(
      `SELECT COUNT(*) AS n FROM workspace_vendors
       WHERE workspace_id = ? AND status = 'active' AND first_seen < ?`
    ).bind(wsId, now30dAgo).first(),
  ]);

  // Risk trend — deduplicate to latest per (domain, date), then aggregate by date
  const trendRows     = (trendR.status === 'fulfilled' ? trendR.value?.results : null) ?? [];
  const _domainDayMap = new Map();
  for (const r of trendRows) {
    if (!r.created_at || r.score == null) continue;
    const date = r.created_at.slice(0, 10);
    const key  = `${r.domain ?? ''}|${date}`;
    if (!_domainDayMap.has(key)) {
      _domainDayMap.set(key, { date, domain: r.domain ?? null, score: Number(r.score) });
    }
  }
  const _dateAgg = new Map();
  for (const { date, domain, score } of _domainDayMap.values()) {
    if (!_dateAgg.has(date)) _dateAgg.set(date, { scores: [], domains: new Set() });
    const bucket = _dateAgg.get(date);
    bucket.scores.push(score);
    bucket.domains.add(domain ?? '');
  }
  const risk_trend = [..._dateAgg.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([date, { scores, domains }]) => ({
      date,
      average_score: Math.round(scores.reduce((s, n) => s + n, 0) / scores.length),
      lowest_score:  Math.min(...scores),
      highest_score: Math.max(...scores),
      asset_count:   domains.size,
    }));

  // Top risks — deduplicate, sort by severity, cap at 10
  const SEVERITY_ORDER = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
  const topRisksRows   = (topRisksR.status === 'fulfilled' ? topRisksR.value?.results : null) ?? [];
  const _seenRisks     = new Set();
  const top_risks      = topRisksRows
    .reduce((acc, r) => {
      const key = `${r.title ?? ''}|${r.domain ?? ''}|${r.recommendation ?? ''}`;
      if (!_seenRisks.has(key)) {
        _seenRisks.add(key);
        acc.push({
          title:          r.title          ?? '',
          severity:       r.severity       ?? 'medium',
          recommendation: r.recommendation ?? '',
          domain:         r.domain         ?? null,
          date:           typeof r.created_at === 'string' ? r.created_at.slice(0, 10) : null,
        });
      }
      return acc;
    }, [])
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5))
    .slice(0, 10);

  // Findings summary
  const infoCount        = (infoCntR.status === 'fulfilled' ? infoCntR.value?.n : null) ?? 0;
  const findings_summary = {
    critical: sc.critical_findings ?? 0,
    high:     sc.high_findings     ?? 0,
    medium:   sc.medium_findings   ?? 0,
    low:      sc.low_findings      ?? 0,
    info:     infoCount,
    total:    (sc.critical_findings ?? 0) + (sc.high_findings ?? 0) +
              (sc.medium_findings   ?? 0) + (sc.low_findings   ?? 0) + infoCount,
  };

  // Asset inventory with 30d deltas
  const assetsOld  = (assetDeltaR.status  === 'fulfilled' ? assetDeltaR.value?.n  : null) ?? null;
  const vendorsOld = (vendorDeltaR.status === 'fulfilled' ? vendorDeltaR.value?.n : null) ?? null;
  const asset_inventory = {
    assets:               { current: sc.active_assets   ?? 0, delta_30d: assetsOld  !== null ? (sc.active_assets    ?? 0) - assetsOld  : null },
    vendors:              { current: sc.vendors_detected ?? 0, delta_30d: vendorsOld !== null ? (sc.vendors_detected ?? 0) - vendorsOld : null },
    brand_candidates:     { current: sc.brand_risks?.total  ?? 0, delta_30d: null },
    third_party_services: { current: sc.third_party_assets  ?? 0, delta_30d: null },
    saas_exposures:       { current: sc.saas_exposures      ?? 0, delta_30d: null },
    new_assets_30d:   sc.new_assets_30d   ?? 0,
    asset_events_30d: sc.asset_events_30d ?? 0,
  };

  // Executive summary — strengths, weaknesses, priority actions
  const sp2 = sc.security_posture ?? null;
  const strengths = [], weaknesses = [], priority_actions = [];

  if ((sc.critical_findings ?? 0) === 0 && (sc.high_findings ?? 0) === 0)
    strengths.push('No critical or high-severity security findings detected.');
  if ((sc.brand_risks?.high ?? 0) === 0 && (sc.brand_risks?.active ?? 0) === 0)
    strengths.push('No active brand impersonation or typosquat domains detected.');
  if ((sc.admin_surfaces ?? 0) === 0)
    strengths.push('No exposed admin or management interfaces found.');
  if (sp2?.email_security?.status === 'good')
    strengths.push('Email security posture is strong - SPF, DMARC, and DKIM are in place.');
  if (sp2?.ssl_certificates?.status === 'good')
    strengths.push('SSL and certificate configuration is fully validated.');
  if ((sc.vendors_detected ?? 0) > 0 && (sc.vendor_risk?.high ?? 0) === 0)
    strengths.push(`${sc.vendors_detected} third-party vendors detected - none rated high-risk.`);
  if (strengths.length === 0)
    strengths.push('Security monitoring is active - run additional scans to build baseline.');

  if ((sc.critical_findings ?? 0) > 0)
    weaknesses.push(`${sc.critical_findings} critical finding${sc.critical_findings !== 1 ? 's' : ''} require immediate remediation.`);
  if ((sc.high_findings ?? 0) > 0)
    weaknesses.push(`${sc.high_findings} high-severity finding${sc.high_findings !== 1 ? 's' : ''} should be addressed urgently.`);
  if (sp2?.email_security?.score != null && sp2.email_security.score < 70)
    weaknesses.push('Email security posture is weak - spoofing risk remains elevated.');
  if ((sc.brand_risks?.high ?? 0) > 0)
    weaknesses.push(`${sc.brand_risks.high} high-risk typosquat domain${sc.brand_risks.high !== 1 ? 's' : ''} are actively resolving (phishing risk).`);
  if ((sc.admin_surfaces ?? 0) > 0)
    weaknesses.push(`${sc.admin_surfaces} admin surface${sc.admin_surfaces !== 1 ? 's' : ''} exposed to the public internet.`);
  if ((sc.vendor_risk?.high ?? 0) > 0)
    weaknesses.push(`${sc.vendor_risk.high} high-risk vendor${sc.vendor_risk.high !== 1 ? 's' : ''} in the supply chain.`);
  if (weaknesses.length === 0 && (sc.medium_findings ?? 0) > 0)
    weaknesses.push(`${sc.medium_findings} medium-severity finding${sc.medium_findings !== 1 ? 's' : ''} noted - review and remediate.`);

  for (const r of (sc.top_recommendations ?? []).slice(0, 3))
    priority_actions.push(r.title + (r.description ? ` - ${r.description}` : ''));
  if (sp2) {
    for (const catKey of ['email_security', 'ssl_certificates', 'admin_exposure']) {
      const cat = sp2[catKey];
      if ((cat?.status === 'critical' || cat?.status === 'warning') && cat.reasons?.[0] && priority_actions.length < 5)
        priority_actions.push(`[${POSTURE_WEIGHTS[catKey]?.label ?? catKey}] ${cat.reasons[0]}`);
    }
  }

  const executive_summary = {
    strengths:        strengths.slice(0, 5),
    weaknesses:       weaknesses.slice(0, 5),
    priority_actions: priority_actions.slice(0, 5),
  };

  // Top recommendations
  const top_recommendations = (sc.top_recommendations ?? []).map(r => ({
    title:       r.title       ?? '',
    description: r.description ?? '',
    priority:    r.priority    ?? 3,
  }));
  if (sp2 && top_recommendations.length < 10) {
    for (const catKey of Object.keys(POSTURE_WEIGHTS)) {
      const cat = sp2[catKey];
      if (!cat || cat.score === null || (cat.score ?? 100) >= 90) continue;
      for (const reason of (cat.reasons ?? [])) {
        if (top_recommendations.length >= 10) break;
        top_recommendations.push({
          title:       `Improve ${POSTURE_WEIGHTS[catKey].label}`,
          description: reason,
          priority:    cat.status === 'critical' ? 1 : cat.status === 'warning' ? 2 : 3,
        });
      }
      if (top_recommendations.length >= 10) break;
    }
  }

  // Vendor risk, brand monitoring, certificate intelligence
  const vendor_risk = {
    total:  sc.vendors_detected    ?? 0,
    high:   sc.vendor_risk?.high   ?? 0,
    medium: sc.vendor_risk?.medium ?? 0,
    low:    sc.vendor_risk?.low    ?? 0,
  };
  const brand_monitoring = {
    total_candidates: sc.brand_risks?.total  ?? 0,
    active_risks:     sc.brand_risks?.active ?? 0,
    high:             sc.brand_risks?.high   ?? 0,
    medium:           sc.brand_risks?.medium ?? 0,
    low:              sc.brand_risks?.low    ?? 0,
  };
  const certR = sc.certificate_risks ?? {};
  const certificate_intelligence = {
    risk_level:        certR.risk_level        ?? null,
    signals:           certR.signals           ?? 0,
    days_until_expiry: certR.days_until_expiry ?? null,
    status: certR.risk_level === 'critical' ? 'critical'
          : certR.risk_level === 'high'     ? 'warning'
          : (certR.signals   ?? 0) > 0      ? 'warning'
          : certR.risk_level === null        ? 'unknown' : 'ok',
  };

  return {
    workspace:               { id: ws.id, name: ws.name, created_at: ws.created_at },
    generated_at:            generatedAt,
    overall_score:           sc.security_score    ?? null,
    risk_rating:             sc.risk_rating       ?? 'unknown',
    security_posture:        sc.security_posture  ?? null,
    executive_summary,
    findings_summary,
    top_risks,
    top_recommendations:     top_recommendations.slice(0, 10),
    risk_trend,
    asset_inventory,
    vendor_risk,
    brand_monitoring,
    certificate_intelligence,
    last_scan_at:            sc.last_scan_at        ?? null,
    last_scanned_domain:     sc.last_scanned_domain ?? null,
  };
}

// ── Executive Report Archive ──────────────────────────────────────────────────
// generateWorkspaceExecutiveReport — collect data, build PDF, upload to R2,
// write a workspace_reports row.  Returns the completed row on success.
// Throws on fatal error (the row is marked failed before throwing).

async function generateWorkspaceExecutiveReport(workspaceId, env, options = {}) {
  const {
    report_type   = 'manual',
    report_period = null,
    scan_id       = null,
  } = options;

  const now = new Date();

  // ── Derive report_period when not supplied ────────────────────────────────
  const period = report_period ?? (() => {
    if (report_type === 'weekly_executive') {
      // ISO 8601 week: YYYY-Www (Thursday-anchored)
      const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
      d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));  // move to Thursday
      const year = d.getUTCFullYear();
      const wk   = Math.ceil((((d - Date.UTC(year, 0, 1)) / 86400000) + 1) / 7);
      return `${year}-W${String(wk).padStart(2, '0')}`;
    }
    if (report_type === 'monthly_executive') {
      return `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, '0')}`;
    }
    if (report_type === 'scan_snapshot' && scan_id) {
      return `scan-${scan_id}`;
    }
    // manual: timestamp-based period so re-runs don't collide
    const ts = now.toISOString().replace(/[-:T]/g, '').slice(0, 14);
    return `manual-${ts}`;
  })();

  const reportId  = createId('rpt');
  const createdAt = now.toISOString();
  const r2Key     = `reports/executive/${workspaceId}/${report_type}/${period}/executive-report.pdf`;

  // Insert a pending row first so we can always flip it to failed on error
  await env.cybermeters_db.prepare(
    `INSERT INTO workspace_reports
       (id, workspace_id, report_type, report_period, report_key, status, created_at)
     VALUES (?, ?, ?, ?, ?, 'pending', ?)`
  ).bind(reportId, workspaceId, report_type, period, r2Key, createdAt).run();

  let pdfData, bytes;
  try {
    pdfData = await collectPdfData(workspaceId, env);
    if (!pdfData) throw new Error('Workspace not found');
    bytes   = buildExecutivePdf(pdfData);
  } catch (genErr) {
    await env.cybermeters_db.prepare(
      `UPDATE workspace_reports
         SET status = 'failed', generated_at = ?, metadata_json = ?
       WHERE id = ?`
    ).bind(new Date().toISOString(), JSON.stringify({ error: String(genErr?.message ?? genErr) }), reportId).run();
    throw genErr;
  }

  const generatedAt = new Date().toISOString();

  await env.cybermeters_reports.put(r2Key, bytes, {
    httpMetadata: { contentType: 'application/pdf' },
    customMetadata: {
      workspace_id:  workspaceId,
      report_type,
      report_period: period,
      generated_at:  generatedAt,
    },
  });

  await env.cybermeters_db.prepare(
    `UPDATE workspace_reports SET status = 'completed', generated_at = ? WHERE id = ?`
  ).bind(generatedAt, reportId).run();

  // Notification + audit — report generated. Non-fatal: report generation must not fail
  // if notification or audit persistence is unavailable.
  try {
    await createNotificationEvent(env, workspaceId, {
      type:     "report_generated",
      severity: "info",
      title:    `Executive report ready`,
      message:  `${report_type.replace(/_/g, " ")} report for period ${period} is available for download.`,
      metadata: { report_id: reportId, report_type, report_period: period },
    });
    await createAuditEvent(env, {
      workspace_id: workspaceId,
      event_type:   "report_generated",
      entity_type:  "report",
      entity_id:    reportId,
      description:  `Executive report generated (${report_type}, period ${period})`,
      metadata:     { report_id: reportId, report_type, report_period: period },
    });
  } catch { /* non-fatal */ }

  return {
    id:            reportId,
    workspace_id:  workspaceId,
    report_type,
    report_period: period,
    report_key:    r2Key,
    status:        'completed',
    generated_at:  generatedAt,
    created_at:    createdAt,
  };
}

// processScheduledReports — called from scheduled() via ctx.waitUntil().
// Checks the scheduled_reports table for due rows, generates reports, updates timestamps.
async function processScheduledReports(now, env) {
  let rows;
  try {
    const r = await env.cybermeters_db
      .prepare(
        `SELECT id, workspace_id, report_type, frequency
         FROM scheduled_reports
         WHERE enabled = 1
           AND (next_run_at IS NULL OR next_run_at <= ?)
         ORDER BY next_run_at ASC
         LIMIT 20`
      )
      .bind(now)
      .all();
    rows = r.results ?? [];
  } catch {
    // Table may not exist yet
    return;
  }

  for (const sr of rows) {
    try {
      const reportRow = await generateWorkspaceExecutiveReport(sr.workspace_id, env, {
        report_type: sr.report_type,
      });

      const nextRunAt = computeScheduledReportNextRunAt(sr.frequency);
      await env.cybermeters_db
        .prepare(
          `UPDATE scheduled_reports
           SET last_run_at = ?, next_run_at = ?
           WHERE id = ?`
        )
        .bind(now, nextRunAt, sr.id)
        .run();

      // Notification
      try {
        await createNotificationEvent(env, sr.workspace_id, {
          type:     "report_schedule_executed",
          severity: "info",
          title:    `Scheduled report generated`,
          message:  `${sr.report_type.replace(/_/g, ' ')} report generated automatically (${sr.frequency})`,
          metadata: { scheduled_report_id: sr.id, report_id: reportRow?.id, report_type: sr.report_type },
        });
      } catch { /* non-fatal */ }

      // Audit
      try {
        await createAuditEvent(env, {
          workspace_id: sr.workspace_id,
          event_type:   "scheduled_report_executed",
          entity_type:  "scheduled_report",
          entity_id:    sr.id,
          description:  `Scheduled ${sr.report_type} report generated automatically (${sr.frequency})`,
          metadata:     { scheduled_report_id: sr.id, report_id: reportRow?.id, report_type: sr.report_type, next_run_at: nextRunAt },
        });
      } catch { /* non-fatal */ }

    } catch {
      // One workspace failing must not abort others
    }
  }
}

// generateScheduledReports — called from scheduled() via ctx.waitUntil().
// Generates weekly reports on Mondays, monthly reports on the 1st of the month.
// Skips if a report for the same (workspace, type, period) already exists.

async function generateScheduledReports(now, env) {
  const d   = new Date(now);
  const dow = d.getUTCDay();   // 0=Sun … 6=Sat
  const dom = d.getUTCDate();  // 1–31

  const doWeekly  = dow === 1;  // Monday
  const doMonthly = dom === 1;  // 1st of month

  if (!doWeekly && !doMonthly) return;

  let workspaces;
  try {
    const r = await env.cybermeters_db.prepare('SELECT id FROM workspaces').all();
    workspaces = r.results ?? [];
  } catch { return; }

  for (const ws of workspaces) {
    if (doWeekly) {
      try {
        const td = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()));
        td.setUTCDate(td.getUTCDate() + 4 - (td.getUTCDay() || 7));
        const year = td.getUTCFullYear();
        const wk   = Math.ceil((((td - Date.UTC(year, 0, 1)) / 86400000) + 1) / 7);
        const period = `${year}-W${String(wk).padStart(2, '0')}`;

        const exists = await env.cybermeters_db.prepare(
          `SELECT id FROM workspace_reports
           WHERE workspace_id = ? AND report_type = ? AND report_period = ? LIMIT 1`
        ).bind(ws.id, 'weekly_executive', period).first();
        if (exists) continue;

        await generateWorkspaceExecutiveReport(ws.id, env, {
          report_type:   'weekly_executive',
          report_period: period,
        });
      } catch { /* one workspace failing must not abort others */ }
    }

    if (doMonthly) {
      try {
        const period = `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}`;

        const exists = await env.cybermeters_db.prepare(
          `SELECT id FROM workspace_reports
           WHERE workspace_id = ? AND report_type = ? AND report_period = ? LIMIT 1`
        ).bind(ws.id, 'monthly_executive', period).first();
        if (exists) continue;

        await generateWorkspaceExecutiveReport(ws.id, env, {
          report_type:   'monthly_executive',
          report_period: period,
        });
      } catch { /* one workspace failing must not abort others */ }
    }
  }
}

// ── CORS ──────────────────────────────────────────────────────────────────────

// ── RBAC Helpers ─────────────────────────────────────────────────────────────

/**
 * Role hierarchy (higher index = more access).
 * A role satisfies any permission level at or below it.
 */
const ROLE_RANK = { viewer: 0, analyst: 1, admin: 2, owner: 3 };

/**
 * Permission → minimum role required.
 */
const PERMISSION_MIN_ROLE = {
  // Workspace management
  "workspace:read":            "viewer",
  "workspace:invite":          "admin",
  "workspace:manage_members":  "owner",
  "workspace:delete":          "owner",
  "workspace:transfer":        "owner",
  // Domain management
  "domain:add":                "admin",
  "domain:remove":             "admin",
  "domain:import":             "admin",
  "domain:verify":             "admin",
  // Scans
  "scan:create":               "analyst",
  // Reports
  "report:generate":           "admin",
  "schedule:manage":            "admin",
  // Notifications
  "notification:mark_read":    "viewer",
  // Members (read)
  "member:read":               "viewer",
};

/**
 * requireWorkspaceAccess(user, workspaceId, env)
 *
 * Resolves the caller's membership in a workspace.
 * Returns { role } if the user is a member or is the workspace owner, null otherwise.
 *
 * Legacy workspaces (created before RBAC, no member rows) are accessible ONLY
 * to the user whose id matches owner_user_id — never to all authenticated users.
 */
async function requireWorkspaceAccess(user, workspaceId, env) {
  if (!user || !workspaceId) return null;
  try {
    const member = await env.cybermeters_db
      .prepare(
        `SELECT role FROM workspace_members
         WHERE workspace_id = ? AND user_id = ? LIMIT 1`
      )
      .bind(workspaceId, user.id)
      .first();

    if (member) return { role: member.role };

    // Legacy fallback: if no members exist, allow only the workspace owner.
    const ws = await env.cybermeters_db
      .prepare(
        `SELECT w.owner_user_id, COUNT(wm.id) AS member_count
         FROM workspaces w
         LEFT JOIN workspace_members wm ON wm.workspace_id = w.id
         WHERE w.id = ?
         GROUP BY w.id, w.owner_user_id`
      )
      .bind(workspaceId)
      .first();

    if ((ws?.member_count ?? 0) === 0 && ws?.owner_user_id && ws.owner_user_id === user.id) {
      return { role: "owner" };
    }

    return null; // not a member and not the owner
  } catch {
    return null;
  }
}

/**
 * requireWorkspaceRole(user, workspaceId, permission, env)
 *
 * Returns the member's role if the user has the minimum role required for
 * the given permission, or null otherwise.
 *
 * Usage:
 *   const access = await requireWorkspaceRole(user, wsId, "report:generate", env);
 *   if (!access) return json({ error: "Forbidden" }, 403);
 */
async function requireWorkspaceRole(user, workspaceId, permission, env) {
  const membership = await requireWorkspaceAccess(user, workspaceId, env);
  if (!membership) return null;

  const minRole  = PERMISSION_MIN_ROLE[permission];
  if (!minRole) return membership; // permission not restricted — any member passes

  const userRank = ROLE_RANK[membership.role] ?? -1;
  const minRank  = ROLE_RANK[minRole]         ?? 99;

  return userRank >= minRank ? membership : null;
}

async function getAccessibleWorkspaceIds(user, env) {
  if (!user) return [];
  try {
    const rows = await env.cybermeters_db
      .prepare(
        `SELECT DISTINCT w.id
         FROM workspaces w
         LEFT JOIN workspace_members wm
           ON wm.workspace_id = w.id AND wm.user_id = ?
         WHERE wm.user_id IS NOT NULL
            OR (
              w.owner_user_id = ?
              AND NOT EXISTS (
                SELECT 1 FROM workspace_members any_wm
                WHERE any_wm.workspace_id = w.id
              )
            )`
      )
      .bind(user.id, user.id)
      .all();
    return (rows.results || []).map((row) => row.id).filter(Boolean);
  } catch {
    return [];
  }
}

async function requireDomainRole(user, domainId, permission, env) {
  if (!user || !domainId) return null;
  try {
    const rows = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    for (const row of (rows.results || [])) {
      const access = await requireWorkspaceRole(user, row.workspace_id, permission, env);
      if (access) return { ...access, workspace_id: row.workspace_id };
    }
    return null;
  } catch {
    return null;
  }
}

async function requireScanReadAccess(user, scanId, env) {
  if (!user || !scanId) return null;
  try {
    const rows = await env.cybermeters_db
      .prepare(
        `SELECT DISTINCT wd.workspace_id
         FROM scans s
         JOIN workspace_domains wd ON wd.domain_id = s.domain_id
         WHERE s.id = ?`
      )
      .bind(scanId)
      .all();
    for (const row of (rows.results || [])) {
      const access = await requireWorkspaceRole(user, row.workspace_id, "workspace:read", env);
      if (access) return { ...access, workspace_id: row.workspace_id };
    }
    return null;
  } catch {
    return null;
  }
}

// ── Notification Helpers ─────────────────────────────────────────────────────

/**
 * createNotificationEvent — inserts one row into notification_events.
 *
 * @param {object} env          - Worker env bindings
 * @param {string} workspace_id - Target workspace
 * @param {object} opts         - { type, severity, title, message, metadata, user_id }
 *
 * Always non-fatal — swallows all errors so callers never need try/catch.
 */
async function createNotificationEvent(env, workspace_id, { type, severity = "info", title, message = null, metadata = null, user_id = null } = {}) {
  if (!workspace_id || !type || !title) return;
  try {
    const id           = createId("notif");
    const metaJson     = metadata ? JSON.stringify(metadata) : null;
    await env.cybermeters_db
      .prepare(
        `INSERT INTO notification_events
           (id, workspace_id, user_id, type, severity, title, message, metadata_json, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unread', datetime('now'))`
      )
      .bind(id, workspace_id, user_id, type, severity, title, message, metaJson)
      .run();
  } catch { /* non-fatal */ }
}

// ── Audit Trail Helper ───────────────────────────────────────────────────────

/**
 * createAuditEvent — inserts one row into audit_events.
 *
 * Always non-fatal. Audit failures must never break business logic.
 *
 * @param {object} env              - Worker env bindings
 * @param {object} opts
 *   workspace_id  {string|null}   - Workspace context (null for auth events)
 *   user_id       {string|null}   - Acting user (null for system events)
 *   event_type    {string}        - e.g. 'domain_verified', 'scan_completed'
 *   entity_type   {string|null}   - e.g. 'domain', 'scan', 'member', 'report'
 *   entity_id     {string|null}   - ID of the affected entity
 *   description   {string|null}   - Human-readable summary
 *   metadata      {object|null}   - Arbitrary JSON context
 */
async function createAuditEvent(env, {
  workspace_id  = null,
  user_id       = null,
  event_type,
  entity_type   = null,
  entity_id     = null,
  description   = null,
  metadata      = null,
} = {}) {
  if (!event_type) return;
  try {
    const id       = createId("audit");
    const metaJson = metadata ? JSON.stringify(metadata) : null;
    await env.cybermeters_db
      .prepare(
        `INSERT INTO audit_events
           (id, workspace_id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(id, workspace_id, user_id, event_type, entity_type, entity_id, description, metaJson)
      .run();
  } catch { /* non-fatal */ }
}

/**
 * createNotificationsForDomain — fires workspace-level notifications for a
 * completed scan. Looks up all workspace_ids associated with the domain,
 * then creates one notification per workspace.
 *
 * @param {string} domainId     - Domain row ID
 * @param {string} domain       - Domain name (for display)
 * @param {string} scanId       - Completed scan ID
 * @param {number} score        - Final security score
 * @param {string} risk_level   - Risk rating (critical/high/medium/low/info)
 * @param {Array}  findings     - All findings from the scan
 * @param {object} env          - Worker env bindings
 */
async function createNotificationsForDomain(domainId, domain, scanId, score, risk_level, findings, env) {
  try {
    const wsResult = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    const workspaceIds = (wsResult.results || []).map(r => r.workspace_id);
    if (workspaceIds.length === 0) return;

    const criticalCount = findings.filter(f => f.severity === "critical").length;
    const highCount     = findings.filter(f => f.severity === "high").length;
    const meta          = { scan_id: scanId, domain, score, risk_level };

    for (const wsId of workspaceIds) {
      // Scan completed notification
      await createNotificationEvent(env, wsId, {
        type:     "scan_completed",
        severity: criticalCount > 0 ? "critical" : highCount > 0 ? "high" : "info",
        title:    `Scan completed for ${domain}`,
        message:  `Score: ${score} · ${risk_level} risk${criticalCount > 0 ? ` · ${criticalCount} critical finding${criticalCount !== 1 ? "s" : ""}` : ""}${highCount > 0 ? ` · ${highCount} high finding${highCount !== 1 ? "s" : ""}` : ""}`,
        metadata: meta,
      });

      // Critical findings notification (separate, higher urgency)
      if (criticalCount > 0) {
        await createNotificationEvent(env, wsId, {
          type:     "critical_finding",
          severity: "critical",
          title:    `${criticalCount} critical finding${criticalCount !== 1 ? "s" : ""} on ${domain}`,
          message:  `A scan of ${domain} detected ${criticalCount} critical severity issue${criticalCount !== 1 ? "s" : ""} requiring immediate attention.`,
          metadata: meta,
        });
      }

      // High findings notification. Aggregated separately from critical findings
      // so mixed critical/high scans still surface both counts without per-finding spam.
      if (highCount > 0) {
        await createNotificationEvent(env, wsId, {
          type:     "high_finding",
          severity: "high",
          title:    `${highCount} high-severity finding${highCount !== 1 ? "s" : ""} on ${domain}`,
          message:  `A scan of ${domain} detected ${highCount} high-severity issue${highCount !== 1 ? "s" : ""}.`,
          metadata: meta,
        });
      }
    }
  } catch { /* non-fatal */ }
}

const corsHeaders = {
  "Access-Control-Allow-Origin":  "*",
  "Access-Control-Allow-Methods": "GET, POST, PATCH, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
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

    // ── POST /api/auth/signup ────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/signup") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email    = (body.email    || "").trim().toLowerCase();
      const password = (body.password || "").trim();
      const name     = (body.name     || "").trim();

      if (!isValidEmail(email))        return json({ error: "A valid email address is required" }, 400);
      if (password.length < 8)         return json({ error: "Password must be at least 8 characters" }, 400);
      if (password.length > 128)       return json({ error: "Password is too long" }, 400);

      try {
        // Check for duplicate email
        const existing = await env.cybermeters_db
          .prepare("SELECT id FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();
        if (existing) return json({ error: "An account with this email already exists" }, 409);

        const userId      = createId("usr");
        const passwordHash = await hashPassword(password);

        await env.cybermeters_db
          .prepare(
            `INSERT INTO users (id, email, name, plan, password_hash, status, created_at)
             VALUES (?, ?, ?, 'free', ?, 'active', datetime('now'))`
          )
          .bind(userId, email, name || null, passwordHash)
          .run();

        return json({ user_id: userId, email }, 201);
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── POST /api/auth/login ─────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/login") {
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email    = (body.email    || "").trim().toLowerCase();
      const password = (body.password || "").trim();

      if (!email || !password) return json({ error: "Email and password are required" }, 400);

      try {
        const user = await env.cybermeters_db
          .prepare("SELECT id, email, name, plan, password_hash, status FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();

        // Always run verifyPassword even if user not found to prevent user-enumeration via timing
        const storedHash  = user?.password_hash ?? "pbkdf2:sha256:100000:0000000000000000000000000000000000:0000000000000000000000000000000000000000000000000000000000000000";
        const passwordOk  = await verifyPassword(password, storedHash);

        if (!user || !passwordOk || !user.password_hash) {
          return json({ error: "Invalid email or password" }, 401);
        }
        if (user.status === "suspended") {
          return json({ error: "Account suspended. Contact support." }, 403);
        }

        // Generate session token — raw sent to client, hash stored in D1
        const { raw: token, hash: tokenHash } = await generateSessionToken();
        const sessionId  = createId("sess");
        const expiresAt  = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

        await env.cybermeters_db
          .prepare(
            `INSERT INTO user_sessions (id, user_id, token_hash, expires_at)
             VALUES (?, ?, ?, ?)`
          )
          .bind(sessionId, user.id, tokenHash, expiresAt)
          .run();

        // Update last_login_at
        await env.cybermeters_db
          .prepare("UPDATE users SET last_login_at = datetime('now') WHERE id = ?")
          .bind(user.id)
          .run();

        // Audit: login
        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "login",
          entity_type: "user",
          entity_id:   user.id,
          description: `${user.email} signed in`,
        });

        return json({
          token,
          user: {
            id:    user.id,
            email: user.email,
            name:  user.name,
            plan:  user.plan,
          },
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/auth/me ─────────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/auth/me") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      return json({
        id:    user.id,
        email: user.email,
        name:  user.name,
        plan:  user.plan,
      });
    }

    // ── POST /api/auth/logout ────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/auth/logout") {
      const authHeader = request.headers.get("Authorization") || "";
      if (authHeader.startsWith("Bearer ")) {
        const rawToken = authHeader.slice(7).trim();
        if (rawToken) {
          try {
            const tokenHash = await hashToken(rawToken);
            // Resolve user before deleting session so we can audit
            const sessionRow = await env.cybermeters_db
              .prepare("SELECT user_id FROM user_sessions WHERE token_hash = ?")
              .bind(tokenHash)
              .first();
            await env.cybermeters_db
              .prepare("DELETE FROM user_sessions WHERE token_hash = ?")
              .bind(tokenHash)
              .run();
            if (sessionRow?.user_id) {
              await createAuditEvent(env, {
                user_id:     sessionRow.user_id,
                event_type:  "logout",
                entity_type: "user",
                entity_id:   sessionRow.user_id,
                description: "User signed out",
              });
            }
          } catch { /* silent — token may already be expired */ }
        }
      }
      return json({ success: true });
    }

    // ── GET /api/account/profile ─────────────────────────────────────────
    // Returns the authenticated account, company profile, and subscription foundation.
    if (request.method === "GET" && url.pathname === "/api/account/profile") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const [profile, subscription] = await Promise.all([
          env.cybermeters_db
            .prepare(
              `SELECT id, company_name, website, industry, company_size,
                      contact_email, contact_name, created_at, updated_at
               FROM customer_profiles
               WHERE owner_user_id = ?`
            )
            .bind(user.id)
            .first(),
          env.cybermeters_db
            .prepare(
              `SELECT id, plan, status, billing_provider, billing_email,
                      trial_ends_at, current_period_end, created_at, updated_at
               FROM subscription_accounts
               WHERE owner_user_id = ?`
            )
            .bind(user.id)
            .first(),
        ]);
        return json({
          user: {
            id:    user.id,
            email: user.email,
            name:  user.name,
            plan:  user.plan,
          },
          company: profile ?? null,
          subscription: subscription ?? {
            plan:             user.plan || "free",
            status:           "active",
            billing_provider: "manual",
            billing_email:    user.email,
          },
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── PATCH /api/account/profile ───────────────────────────────────────
    // Updates account profile fields only. Email remains read-only in v1.
    if (request.method === "PATCH" && url.pathname === "/api/account/profile") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const name = typeof body.name === "string" ? body.name.trim() : "";
      if (!name) return json({ error: "name is required" }, 400);
      if (name.length > 120) return json({ error: "name is too long" }, 400);

      try {
        await env.cybermeters_db
          .prepare("UPDATE users SET name = ? WHERE id = ?")
          .bind(name, user.id)
          .run();

        return json({
          user: {
            id:    user.id,
            email: user.email,
            name,
            plan:  user.plan,
          },
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/account/company ─────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/account/company") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const company = await env.cybermeters_db
          .prepare(
            `SELECT id, company_name, website, industry, company_size,
                    contact_email, contact_name, created_at, updated_at
             FROM customer_profiles
             WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();
        return json({ company: company ?? null });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── PUT /api/account/company ─────────────────────────────────────────
    if (request.method === "PUT" && url.pathname === "/api/account/company") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const company_name  = (body.company_name  || "").trim();
      const website       = (body.website       || "").trim() || null;
      const industry      = (body.industry      || "").trim() || null;
      const company_size  = (body.company_size  || "").trim() || null;
      const contact_name  = (body.contact_name  || "").trim() || null;
      const contact_email = (body.contact_email || "").trim().toLowerCase() || null;

      if (!company_name) return json({ error: "company_name is required" }, 400);
      if (company_name.length > 200) return json({ error: "company_name is too long" }, 400);
      if (website && website.length > 300) return json({ error: "website is too long" }, 400);
      if (contact_email && !isValidEmail(contact_email)) {
        return json({ error: "contact_email must be a valid email address" }, 400);
      }

      const VALID_SIZES = ["1-10", "11-50", "51-200", "201-1000", "1000+"];
      if (company_size && !VALID_SIZES.includes(company_size)) {
        return json({ error: `company_size must be one of: ${VALID_SIZES.join(", ")}` }, 400);
      }

      try {
        const companyId = createId("cust");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO customer_profiles
               (id, owner_user_id, company_name, website, industry, company_size,
                contact_email, contact_name, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
             ON CONFLICT(owner_user_id) DO UPDATE SET
               company_name  = excluded.company_name,
               website       = excluded.website,
               industry      = excluded.industry,
               company_size  = excluded.company_size,
               contact_email = excluded.contact_email,
               contact_name  = excluded.contact_name,
               updated_at    = datetime('now')`
          )
          .bind(companyId, user.id, company_name, website, industry, company_size, contact_email, contact_name)
          .run();

        const company = await env.cybermeters_db
          .prepare(
            `SELECT id, company_name, website, industry, company_size,
                    contact_email, contact_name, created_at, updated_at
             FROM customer_profiles
             WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();

        return json({ company });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

// ── Subscription Entitlements ────────────────────────────────────────────────

/**
 * Hard limits per plan.
 * domains_per_workspace and scheduled_reports_per_workspace are workspace-scoped.
 * workspaces and api_tokens are user-scoped.
 * enterprise values are intentionally high to avoid special-casing.
 */
const PLAN_LIMITS = {
  free:         { workspaces: 1,   domains_per_workspace: 3,    scheduled_reports_per_workspace: 1,   api_tokens: 1   },
  starter:      { workspaces: 3,   domains_per_workspace: 25,   scheduled_reports_per_workspace: 5,   api_tokens: 5   },
  professional: { workspaces: 10,  domains_per_workspace: 100,  scheduled_reports_per_workspace: 25,  api_tokens: 25  },
  enterprise:   { workspaces: 999, domains_per_workspace: 9999, scheduled_reports_per_workspace: 999, api_tokens: 999 },
};

/**
 * Return the limit object for a user's plan.
 * Defaults to 'free' for unknown/null plan values.
 */
function getPlanLimits(plan) {
  return PLAN_LIMITS[plan] ?? PLAN_LIMITS.free;
}

/**
 * Return current usage counts for a user, used both for enforcement
 * and for the /limits display endpoint.
 *
 * @param {object} user
 * @param {string|null} workspaceId  — if provided, also returns workspace-scoped counts
 * @param {object} env
 */
async function getEntitlementUsage(user, env, workspaceId = null) {
  const queries = [
    // workspace count: workspaces owned by or member of
    env.cybermeters_db.prepare(
      `SELECT COUNT(DISTINCT w.id) AS cnt
       FROM workspaces w
       WHERE w.owner_user_id = ?
          OR EXISTS (SELECT 1 FROM workspace_members wm WHERE wm.workspace_id = w.id AND wm.user_id = ?)`
    ).bind(user.id, user.id).first(),

    // active api token count
    env.cybermeters_db.prepare(
      `SELECT COUNT(*) AS cnt FROM api_tokens WHERE user_id = ? AND status = 'active'`
    ).bind(user.id).first(),
  ];

  const [wsRow, tokRow] = await Promise.all(queries);

  const usage = {
    workspaces: wsRow?.cnt ?? 0,
    api_tokens: tokRow?.cnt ?? 0,
    domains_in_workspace:           null,
    scheduled_reports_in_workspace: null,
  };

  if (workspaceId) {
    const [domRow, srRow] = await Promise.all([
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS cnt FROM workspace_domains WHERE workspace_id = ?`
      ).bind(workspaceId).first(),
      env.cybermeters_db.prepare(
        `SELECT COUNT(*) AS cnt FROM scheduled_reports WHERE workspace_id = ? AND enabled = 1`
      ).bind(workspaceId).first(),
    ]);
    usage.domains_in_workspace           = domRow?.cnt ?? 0;
    usage.scheduled_reports_in_workspace = srRow?.cnt  ?? 0;
  }

  return usage;
}

    // ── GET /api/account/subscription ────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/account/subscription") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const subscription = await env.cybermeters_db
          .prepare(
            `SELECT id, plan, status, billing_provider, billing_email,
                    trial_ends_at, current_period_end, created_at, updated_at
             FROM subscription_accounts
             WHERE owner_user_id = ?`
          )
          .bind(user.id)
          .first();

        return json({
          subscription: subscription ?? {
            plan:             user.plan || "free",
            status:           "active",
            billing_provider: "manual",
            billing_email:    user.email,
            trial_ends_at:    null,
            current_period_end: null,
          },
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/account/subscription/limits ─────────────────────────────
    // Returns current plan limits and usage counts for the authenticated user.
    if (request.method === "GET" && url.pathname === "/api/account/subscription/limits") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const plan   = user.plan || "free";
        const limits = getPlanLimits(plan);

        // Workspace-scoped: return max domain/schedule count across the user's workspaces
        const wsRows = await env.cybermeters_db.prepare(
          `SELECT DISTINCT w.id
           FROM workspaces w
           WHERE w.owner_user_id = ?
              OR EXISTS (SELECT 1 FROM workspace_members wm WHERE wm.workspace_id = w.id AND wm.user_id = ?)`
        ).bind(user.id, user.id).all();
        const wsIds = (wsRows.results ?? []).map(r => r.id);

        let maxDomains = 0;
        let maxScheduledReports = 0;

        if (wsIds.length > 0) {
          const placeholder = wsIds.map(() => '?').join(',');
          const [domRow, srRow] = await Promise.all([
            env.cybermeters_db.prepare(
              `SELECT MAX(cnt) AS mx FROM (
                 SELECT COUNT(*) AS cnt FROM workspace_domains
                 WHERE workspace_id IN (${placeholder})
                 GROUP BY workspace_id
               )`
            ).bind(...wsIds).first(),
            env.cybermeters_db.prepare(
              `SELECT MAX(cnt) AS mx FROM (
                 SELECT COUNT(*) AS cnt FROM scheduled_reports
                 WHERE workspace_id IN (${placeholder}) AND enabled = 1
                 GROUP BY workspace_id
               )`
            ).bind(...wsIds).first(),
          ]);
          maxDomains          = domRow?.mx ?? 0;
          maxScheduledReports = srRow?.mx  ?? 0;
        }

        const tokRow = await env.cybermeters_db.prepare(
          `SELECT COUNT(*) AS cnt FROM api_tokens WHERE user_id = ? AND status = 'active'`
        ).bind(user.id).first();

        return json({
          plan,
          limits,
          usage: {
            workspaces:                      wsIds.length,
            api_tokens:                      tokRow?.cnt ?? 0,
            max_domains_in_workspace:        maxDomains,
            max_scheduled_reports_in_workspace: maxScheduledReports,
          },
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/account/api-tokens ─────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/account/api-tokens") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const rows = await env.cybermeters_db
          .prepare(
            `SELECT id, user_id, name, last_used_at, created_at, expires_at, status
             FROM api_tokens
             WHERE user_id = ?
             ORDER BY created_at DESC`
          )
          .bind(user.id)
          .all();
        return json({ tokens: rows.results || [] });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── POST /api/account/api-tokens ────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/account/api-tokens") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const name = (body.name || "").trim();
      if (!name) return json({ error: "name is required" }, 400);
      if (name.length > 120) return json({ error: "name is too long" }, 400);

      try {
        // Entitlement: API token limit
        const tokUsage  = await getEntitlementUsage(user, env);
        const tokLimits = getPlanLimits(user.plan);
        if (tokUsage.api_tokens >= tokLimits.api_tokens) {
          return json({
            error: `API token limit reached. Your ${user.plan || "free"} plan allows ${tokLimits.api_tokens} active API token${tokLimits.api_tokens === 1 ? "" : "s"}. Revoke an existing token or upgrade your plan.`,
            code:  "LIMIT_API_TOKENS",
            limit: tokLimits.api_tokens,
            usage: tokUsage.api_tokens,
          }, 403);
        }

        const { raw, hash } = await generateApiToken();
        const tokenId = createId("apitok");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO api_tokens
               (id, user_id, name, token_hash, status, created_at)
             VALUES (?, ?, ?, ?, 'active', datetime('now'))`
          )
          .bind(tokenId, user.id, name, hash)
          .run();

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "api_token_created",
          entity_type: "api_token",
          entity_id:   tokenId,
          description: `API token "${name}" created`,
          metadata:    { name },
        });

        return json({ token: raw }, 201);
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── DELETE /api/account/api-tokens/:id ──────────────────────────────
    const apiTokenDeleteMatch = url.pathname.match(/^\/api\/account\/api-tokens\/([^/]+)$/);
    if (apiTokenDeleteMatch && request.method === "DELETE") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const tokenId = apiTokenDeleteMatch[1];

      try {
        const tokenRow = await env.cybermeters_db
          .prepare("SELECT id, name FROM api_tokens WHERE id = ? AND user_id = ?")
          .bind(tokenId, user.id)
          .first();
        if (!tokenRow) return json({ error: "Token not found" }, 404);

        const result = await env.cybermeters_db
          .prepare("UPDATE api_tokens SET status = 'revoked' WHERE id = ? AND user_id = ?")
          .bind(tokenId, user.id)
          .run();
        if (result.meta?.changes === 0) return json({ error: "Token not found" }, 404);

        await createAuditEvent(env, {
          user_id:     user.id,
          event_type:  "api_token_revoked",
          entity_type: "api_token",
          entity_id:   tokenId,
          description: `API token "${tokenRow.name}" revoked`,
          metadata:    { name: tokenRow.name },
        });

        return json({ success: true });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── POST /api/scan ──────────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/scan") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const domain = body.domain?.trim().toLowerCase();
      let workspaceId = body.workspace_id ? String(body.workspace_id).trim() : null;

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }
      if (!workspaceId) {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        for (const id of workspaceIds) {
          const access = await requireWorkspaceRole(user, id, "scan:create", env);
          if (access) {
            workspaceId = id;
            break;
          }
        }
        if (!workspaceId) {
          return json({ error: "No workspace available for scan creation" }, 403);
        }
      }

      const scanAccess = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
      if (!scanAccess) return json({ error: "Forbidden — analyst role required to create scans" }, 403);

      const ws = await env.cybermeters_db
        .prepare(`SELECT id FROM workspaces WHERE id = ?`)
        .bind(workspaceId)
        .first();
      if (!ws) {
        return json({ error: "Workspace not found" }, 404);
      }

      const userId   = user.id;
      const domainId = createId("domain");
      const scanId   = createId("scan");
      const reportKey = `reports/${scanId}.json`;

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

      await env.cybermeters_db
        .prepare(
          `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id)
           VALUES (?, ?)`
        )
        .bind(workspaceId, resolvedDomainId)
        .run();

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

      // Audit — scan started. Non-fatal.
      try {
        await createAuditEvent(env, {
          workspace_id: workspaceId ?? null,
          user_id:      userId ?? null,
          event_type:   "scan_started",
          entity_type:  "scan",
          entity_id:    scanId,
          description:  `Scan started for ${domain}`,
          metadata:     { scan_id: scanId, domain, domain_id: resolvedDomainId, workspace_id: workspaceId ?? null },
        });
      } catch { /* non-fatal */ }

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
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const wsFilter = url.searchParams.get("workspace_id");

      // If caller scoped the request to a workspace, verify membership first.
      if (wsFilter) {
        const wsAccess = await requireWorkspaceRole(user, wsFilter, "workspace:read", env);
        if (!wsAccess) return json({ error: "Forbidden" }, 403);
      }

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
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) {
          return json({ scans: [] });
        }
        const placeholders = workspaceIds.map(() => "?").join(",");
        result = await env.cybermeters_db
          .prepare(
            `SELECT DISTINCT s.id, s.domain, s.status, s.score, s.rating, s.created_at
             FROM scans s
             JOIN domains d ON d.id = s.domain_id
             JOIN workspace_domains wd ON wd.domain_id = d.id
             WHERE wd.workspace_id IN (${placeholders})
             ORDER BY s.created_at DESC
             LIMIT 20`
          )
          .bind(...workspaceIds)
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

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);

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

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);

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

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const workspaceIds = await getAccessibleWorkspaceIds(user, env);
      if (workspaceIds.length === 0) return json({ error: "Forbidden" }, 403);
      const placeholders = workspaceIds.map(() => "?").join(",");

      const history = await env.cybermeters_db
        .prepare(
          `SELECT DISTINCT s.id, s.domain_id, s.domain, s.status, s.score, s.rating, s.created_at
           FROM scans s
           JOIN workspace_domains wd ON wd.domain_id = s.domain_id
           WHERE s.domain = ? AND wd.workspace_id IN (${placeholders})
           ORDER BY s.created_at DESC`
        )
        .bind(domain, ...workspaceIds)
        .all();

      return json({ domain, scans: history.results });
    }

    // ── POST /api/schedules ─────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/schedules") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const domain      = (body.domain || "").trim().toLowerCase();
      const frequency   = (body.frequency || "daily").trim().toLowerCase();
      let workspaceId = (body.workspace_id || "").trim() || null;

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }
      if (!["daily", "weekly"].includes(frequency)) {
        return json({ error: "frequency must be 'daily' or 'weekly'" }, 400);
      }
      if (!workspaceId) {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        for (const id of workspaceIds) {
          const access = await requireWorkspaceRole(user, id, "scan:create", env);
          if (access) {
            workspaceId = id;
            break;
          }
        }
        if (!workspaceId) {
          return json({ error: "No workspace available for scheduled scans" }, 403);
        }
      }
      const scheduleAccess = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
      if (!scheduleAccess) return json({ error: "Forbidden — analyst role required to manage scheduled scans" }, 403);

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
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const workspaceIds = await getAccessibleWorkspaceIds(user, env);
      if (workspaceIds.length === 0) return json({ schedules: [] });
      const placeholders = workspaceIds.map(() => "?").join(",");

      // Return empty list if table doesn't exist yet
      try {
        const result = await env.cybermeters_db
          .prepare(
            `SELECT id, domain, frequency, enabled, workspace_id,
                    last_asset_count, asset_change_count,
                    last_run_at, next_run_at, created_at
             FROM scheduled_scans
             WHERE workspace_id IN (${placeholders})
             ORDER BY created_at DESC`
          )
          .bind(...workspaceIds)
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
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const schedule = await env.cybermeters_db
          .prepare("SELECT id, workspace_id FROM scheduled_scans WHERE id = ?")
          .bind(schedId)
          .first();
        if (!schedule) return json({ error: "Schedule not found" }, 404);
        if (!schedule.workspace_id) return json({ error: "Forbidden" }, 403);
        const scheduleAccess = await requireWorkspaceRole(user, schedule.workspace_id, "scan:create", env);
        if (!scheduleAccess) return json({ error: "Forbidden — analyst role required to manage scheduled scans" }, 403);

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
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

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

    // ── Portfolio APIs ────────────────────────────────────────────────────────
    // GET /api/portfolio/overview   — aggregate stats across all workspaces
    // GET /api/portfolio/workspaces — per-workspace risk rows, sorted by risk
    // GET /api/portfolio/alerts     — cross-workspace alert feed
    // GET /api/portfolio/trends     — 30-day daily aggregate trend
    // ─────────────────────────────────────────────────────────────────────────

    if (request.method === "GET" && url.pathname === "/api/portfolio/overview") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const db = env.cybermeters_db;
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) {
          return json({
            total_workspaces: 0, total_domains: 0, total_assets: 0,
            total_vendors: 0, total_brand_candidates: 0, total_reports: 0,
            critical_findings: 0, high_findings: 0, new_assets_7d: 0,
            new_reports_30d: 0, average_score: null,
            highest_risk_workspace: null, generated_at: new Date().toISOString(),
          });
        }
        const wsIn = workspaceIds.map(() => "?").join(",");
        const [
          wsRes, domRes, assetRes, vendorRes, brandRes, rptRes,
          findingsRes, newAssetsRes, newRptsRes, avgScoreRes, highRiskRes,
        ] = await Promise.allSettled([
          db.prepare(`SELECT COUNT(*) AS count FROM workspaces WHERE id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_domains WHERE workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_assets WHERE status='active' AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_vendors WHERE status='active' AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_brand_assets WHERE status='active' AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_reports WHERE status='completed' AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          // Critical + high findings from the latest completed scan per domain
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN lpd   ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE f.severity IN ('critical','high')
              AND wd.workspace_id IN (${wsIn})
            GROUP BY f.severity
          `).bind(...workspaceIds).all(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_assets WHERE first_seen >= datetime('now','-7 days') AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          db.prepare(`SELECT COUNT(*) AS count FROM workspace_reports WHERE status='completed' AND generated_at >= datetime('now','-30 days') AND workspace_id IN (${wsIn})`).bind(...workspaceIds).first(),
          // Average score across latest scan per domain
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT AVG(s.score) AS avg_score
            FROM scans s
            JOIN lpd ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.score IS NOT NULL
              AND wd.workspace_id IN (${wsIn})
          `).bind(...workspaceIds).first(),
          // Workspace with most critical findings from latest scans
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            ),
            crit AS (
              SELECT s.domain_id, COUNT(*) AS cnt
              FROM findings f
              JOIN scans s ON f.scan_id = s.id
              JOIN lpd ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
              WHERE f.severity = 'critical'
              GROUP BY s.domain_id
            ),
            ws_crit AS (
              SELECT wd.workspace_id, SUM(c.cnt) AS total_crit
              FROM crit c
              JOIN workspace_domains wd ON c.domain_id = wd.domain_id
              WHERE wd.workspace_id IN (${wsIn})
              GROUP BY wd.workspace_id
            )
            SELECT w.id, w.name, wc.total_crit
            FROM ws_crit wc
            JOIN workspaces w ON w.id = wc.workspace_id
            ORDER BY wc.total_crit DESC
            LIMIT 1
          `).bind(...workspaceIds).first(),
        ]);

        const findingsBySev = {};
        for (const r of (findingsRes.status === 'fulfilled' ? (findingsRes.value?.results ?? []) : [])) {
          findingsBySev[r.severity] = r.cnt;
        }

        const avgRaw = avgScoreRes.status === 'fulfilled' ? avgScoreRes.value?.avg_score : null;
        const hrw    = highRiskRes.status === 'fulfilled'  ? highRiskRes.value : null;

        return json({
          total_workspaces:       wsRes.status === 'fulfilled'    ? (wsRes.value?.count    ?? 0) : 0,
          total_domains:          domRes.status === 'fulfilled'   ? (domRes.value?.count   ?? 0) : 0,
          total_assets:           assetRes.status === 'fulfilled' ? (assetRes.value?.count ?? 0) : 0,
          total_vendors:          vendorRes.status === 'fulfilled'? (vendorRes.value?.count?? 0) : 0,
          total_brand_candidates: brandRes.status === 'fulfilled' ? (brandRes.value?.count ?? 0) : 0,
          total_reports:          rptRes.status === 'fulfilled'   ? (rptRes.value?.count   ?? 0) : 0,
          critical_findings:      findingsBySev['critical'] ?? 0,
          high_findings:          findingsBySev['high']     ?? 0,
          new_assets_7d:          newAssetsRes.status === 'fulfilled' ? (newAssetsRes.value?.count ?? 0) : 0,
          new_reports_30d:        newRptsRes.status === 'fulfilled'   ? (newRptsRes.value?.count   ?? 0) : 0,
          average_score:          avgRaw != null ? Math.round(avgRaw) : null,
          highest_risk_workspace: hrw ? { id: hrw.id, name: hrw.name, critical_findings: hrw.total_crit } : null,
          generated_at:           new Date().toISOString(),
        });
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/workspaces") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const db = env.cybermeters_db;
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ workspaces: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");
        const [
          wsRes, domCountRes, assetCountRes, vendorCountRes, brandCountRes,
          findingsRes, scanRes, rptRes,
        ] = await Promise.allSettled([
          db.prepare(`SELECT id, name, created_at FROM workspaces WHERE id IN (${wsIn}) ORDER BY created_at`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_domains WHERE workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_assets WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_vendors WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          db.prepare(`SELECT workspace_id, COUNT(*) AS count FROM workspace_brand_assets WHERE status='active' AND workspace_id IN (${wsIn}) GROUP BY workspace_id`).bind(...workspaceIds).all(),
          // Critical + high per workspace from latest scan per domain
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT wd.workspace_id, f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN lpd   ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON s.domain_id = wd.domain_id
            WHERE f.severity IN ('critical','high')
              AND wd.workspace_id IN (${wsIn})
            GROUP BY wd.workspace_id, f.severity
          `).bind(...workspaceIds).all(),
          // Latest scan avg score + last_scan_at per workspace
          db.prepare(`
            WITH lpd AS (
              SELECT domain_id, MAX(created_at) AS mx
              FROM scans WHERE status='completed' GROUP BY domain_id
            )
            SELECT wd.workspace_id,
                   AVG(s.score)      AS avg_score,
                   MAX(s.created_at) AS last_scan_at
            FROM scans s
            JOIN lpd              ON s.domain_id = lpd.domain_id AND s.created_at = lpd.mx
            JOIN workspace_domains wd ON s.domain_id = wd.domain_id
            WHERE s.score IS NOT NULL
              AND wd.workspace_id IN (${wsIn})
            GROUP BY wd.workspace_id
          `).bind(...workspaceIds).all(),
          db.prepare(`
            SELECT workspace_id, MAX(generated_at) AS last_report_at
            FROM workspace_reports WHERE status='completed' AND workspace_id IN (${wsIn})
            GROUP BY workspace_id
          `).bind(...workspaceIds).all(),
        ]);

        const workspaces = wsRes.status === 'fulfilled' ? (wsRes.value?.results ?? []) : [];

        // Build lookup maps
        const domMap    = {};
        for (const r of (domCountRes.status    === 'fulfilled' ? (domCountRes.value?.results    ?? []) : [])) domMap[r.workspace_id]    = r.count;
        const assetMap  = {};
        for (const r of (assetCountRes.status  === 'fulfilled' ? (assetCountRes.value?.results  ?? []) : [])) assetMap[r.workspace_id]  = r.count;
        const vendorMap = {};
        for (const r of (vendorCountRes.status === 'fulfilled' ? (vendorCountRes.value?.results ?? []) : [])) vendorMap[r.workspace_id] = r.count;
        const brandMap  = {};
        for (const r of (brandCountRes.status  === 'fulfilled' ? (brandCountRes.value?.results  ?? []) : [])) brandMap[r.workspace_id]  = r.count;

        const findingsMap = {};
        for (const r of (findingsRes.status === 'fulfilled' ? (findingsRes.value?.results ?? []) : [])) {
          if (!findingsMap[r.workspace_id]) findingsMap[r.workspace_id] = { critical: 0, high: 0 };
          findingsMap[r.workspace_id][r.severity] = r.cnt;
        }

        const scanMap = {};
        for (const r of (scanRes.status === 'fulfilled' ? (scanRes.value?.results ?? []) : [])) scanMap[r.workspace_id] = r;

        const rptMap = {};
        for (const r of (rptRes.status === 'fulfilled' ? (rptRes.value?.results ?? []) : [])) rptMap[r.workspace_id] = r.last_report_at;

        const now = Date.now();
        const rows = workspaces.map(ws => {
          const scan    = scanMap[ws.id]    ?? {};
          const findings = findingsMap[ws.id] ?? {};
          const avgScore = scan.avg_score != null ? Math.round(scan.avg_score) : null;

          let risk_rating = null;
          if (avgScore !== null) {
            if      (avgScore >= 80) risk_rating = 'Low';
            else if (avgScore >= 60) risk_rating = 'Medium';
            else if (avgScore >= 40) risk_rating = 'High';
            else                     risk_rating = 'Critical';
          }

          const lastScanAt = scan.last_scan_at ?? null;
          const status = lastScanAt && (now - new Date(lastScanAt).getTime()) < 30 * 24 * 3600 * 1000
            ? 'active' : 'inactive';

          return {
            workspace_id:          ws.id,
            workspace_name:        ws.name,
            domains:               domMap[ws.id]    ?? 0,
            active_assets:         assetMap[ws.id]  ?? 0,
            vendors:               vendorMap[ws.id] ?? 0,
            brand_candidates:      brandMap[ws.id]  ?? 0,
            latest_score:          avgScore,
            security_posture_score: avgScore,
            risk_rating,
            critical_findings:     findings.critical ?? 0,
            high_findings:         findings.high     ?? 0,
            last_scan_at:          lastScanAt,
            last_report_at:        rptMap[ws.id] ?? null,
            status,
          };
        });

        // Sort: critical desc → high desc → score asc (lowest=most risk) → last_scan desc
        rows.sort((a, b) => {
          if (b.critical_findings !== a.critical_findings) return b.critical_findings - a.critical_findings;
          if (b.high_findings     !== a.high_findings)     return b.high_findings     - a.high_findings;
          const sa = a.latest_score ?? 999, sb = b.latest_score ?? 999;
          if (sa !== sb) return sa - sb;
          return (b.last_scan_at ?? '').localeCompare(a.last_scan_at ?? '');
        });

        return json({ workspaces: rows });
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/alerts") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const db    = env.cybermeters_db;
        const limit = Math.min(parseInt(url.searchParams.get('limit') ?? '50', 10) || 50, 200);
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ alerts: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");

        const [eventsRes, brandRes, failedRptsRes] = await Promise.allSettled([
          // Asset events — deduplicated to one row per (workspace, event_type, hostname, day)
          // Uses MAX(created_at) to keep the most recent occurrence of each group.
          db.prepare(`
            SELECT ae.workspace_id, w.name AS workspace_name,
                   ae.event_type,
                   MAX(ae.severity)    AS severity,
                   ae.hostname,
                   ae.description,
                   MAX(ae.created_at) AS created_at
            FROM asset_events ae
            JOIN workspaces w ON w.id = ae.workspace_id
            WHERE ae.workspace_id IN (${wsIn})
            GROUP BY ae.workspace_id, ae.event_type, ae.hostname, date(ae.created_at)
            ORDER BY MAX(ae.created_at) DESC
            LIMIT ?
          `).bind(...workspaceIds, limit).all(),
          // Active brand risks that resolve via DNS
          db.prepare(`
            SELECT ba.workspace_id, w.name AS workspace_name,
                   ba.candidate_domain, ba.risk_level, ba.variant_type, ba.updated_at
            FROM workspace_brand_assets ba
            JOIN workspaces w ON w.id = ba.workspace_id
            WHERE ba.status = 'active' AND ba.dns_resolves = 1
              AND ba.workspace_id IN (${wsIn})
            ORDER BY ba.updated_at DESC
            LIMIT ?
          `).bind(...workspaceIds, Math.ceil(limit / 3)).all(),
          // Failed report generations
          db.prepare(`
            SELECT wr.workspace_id, w.name AS workspace_name,
                   wr.report_type, wr.metadata_json, wr.created_at
            FROM workspace_reports wr
            JOIN workspaces w ON w.id = wr.workspace_id
            WHERE wr.status = 'failed'
              AND wr.workspace_id IN (${wsIn})
            ORDER BY wr.created_at DESC
            LIMIT ?
          `).bind(...workspaceIds, Math.ceil(limit / 5)).all(),
        ]);

        const alerts = [];

        for (const r of (eventsRes.status === 'fulfilled' ? (eventsRes.value?.results ?? []) : [])) {
          let title = (r.event_type ?? '').replace(/_/g, ' ');
          const et = r.event_type;
          if      (et === 'new_asset_discovered')      title = `New asset: ${r.hostname ?? ''}`;
          else if (et === 'takeover_risk_detected')    title = `Takeover risk: ${r.hostname ?? ''}`;
          else if (et === 'wildcard_dns_detected')     title = `Wildcard DNS: ${r.hostname ?? ''}`;
          else if (et === 'cloud_storage_detected')    title = `Cloud storage exposed: ${r.hostname ?? ''}`;
          else if (et === 'certificate_expiry_warning')title = `Certificate expiring: ${r.hostname ?? ''}`;
          else if (et === 'certificate_expired')       title = `Certificate expired: ${r.hostname ?? ''}`;
          alerts.push({
            workspace_id:   r.workspace_id,
            workspace_name: r.workspace_name,
            type:           et ?? 'unknown',
            severity:       r.severity ?? 'info',
            title,
            description:    r.description ?? null,
            created_at:     r.created_at,
          });
        }

        for (const r of (brandRes.status === 'fulfilled' ? (brandRes.value?.results ?? []) : [])) {
          const sev = (r.risk_level === 'critical' || r.risk_level === 'high') ? r.risk_level : 'medium';
          alerts.push({
            workspace_id:   r.workspace_id,
            workspace_name: r.workspace_name,
            type:           'brand_risk',
            severity:       sev,
            title:          `Brand risk: ${r.candidate_domain}`,
            description:    `Active typosquat candidate (${r.variant_type ?? 'unknown variant'}) resolving via DNS`,
            created_at:     r.updated_at,
          });
        }

        for (const r of (failedRptsRes.status === 'fulfilled' ? (failedRptsRes.value?.results ?? []) : [])) {
          let errMsg = null;
          try { errMsg = JSON.parse(r.metadata_json)?.error ?? null; } catch {}
          alerts.push({
            workspace_id:   r.workspace_id,
            workspace_name: r.workspace_name,
            type:           'report_generation_failed',
            severity:       'high',
            title:          `Report generation failed (${r.report_type})`,
            description:    errMsg ?? 'Report generation failed',
            created_at:     r.created_at,
          });
        }

        // Unified sort by created_at desc, then trim to limit
        alerts.sort((a, b) => (b.created_at ?? '').localeCompare(a.created_at ?? ''));

        return json({ alerts: alerts.slice(0, limit) });
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    if (request.method === "GET" && url.pathname === "/api/portfolio/trends") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        const db = env.cybermeters_db;
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) return json({ trend: [] });
        const wsIn = workspaceIds.map(() => "?").join(",");

        const [scanTrendRes, findingsTrendRes, assetTrendRes] = await Promise.allSettled([
          // Score aggregates per day from all completed scans in last 30 days
          db.prepare(`
            SELECT date(s.created_at)     AS day,
                   COUNT(DISTINCT s.id)   AS scans,
                   ROUND(AVG(s.score), 1) AS average_score,
                   MIN(s.score)           AS lowest_score,
                   MAX(s.score)           AS highest_score
            FROM scans s
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.status = 'completed'
              AND s.created_at >= datetime('now', '-30 days')
              AND s.score IS NOT NULL
              AND wd.workspace_id IN (${wsIn})
            GROUP BY date(s.created_at)
            ORDER BY day
          `).bind(...workspaceIds).all(),
          // Critical + high finding counts per day from scans in last 30 days
          db.prepare(`
            SELECT date(s.created_at) AS day, f.severity, COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON f.scan_id = s.id
            JOIN workspace_domains wd ON wd.domain_id = s.domain_id
            WHERE s.status = 'completed'
              AND s.created_at >= datetime('now', '-30 days')
              AND f.severity IN ('critical', 'high')
              AND wd.workspace_id IN (${wsIn})
            GROUP BY date(s.created_at), f.severity
            ORDER BY day
          `).bind(...workspaceIds).all(),
          // New assets discovered per day in last 30 days
          db.prepare(`
            SELECT date(first_seen) AS day, COUNT(*) AS new_assets
            FROM workspace_assets
            WHERE first_seen >= datetime('now', '-30 days')
              AND workspace_id IN (${wsIn})
            GROUP BY date(first_seen)
            ORDER BY day
          `).bind(...workspaceIds).all(),
        ]);

        // Merge into a single map keyed by day
        const dayMap = {};

        for (const r of (scanTrendRes.status === 'fulfilled' ? (scanTrendRes.value?.results ?? []) : [])) {
          dayMap[r.day] = {
            date:             r.day,
            scans:            r.scans,
            average_score:    r.average_score,
            lowest_score:     r.lowest_score,
            highest_score:    r.highest_score,
            critical_findings: 0,
            high_findings:    0,
            new_assets:       0,
          };
        }

        for (const r of (findingsTrendRes.status === 'fulfilled' ? (findingsTrendRes.value?.results ?? []) : [])) {
          if (!dayMap[r.day]) dayMap[r.day] = { date: r.day, scans: 0, average_score: null, lowest_score: null, highest_score: null, critical_findings: 0, high_findings: 0, new_assets: 0 };
          if (r.severity === 'critical') dayMap[r.day].critical_findings = r.cnt;
          else if (r.severity === 'high') dayMap[r.day].high_findings   = r.cnt;
        }

        for (const r of (assetTrendRes.status === 'fulfilled' ? (assetTrendRes.value?.results ?? []) : [])) {
          if (!dayMap[r.day]) dayMap[r.day] = { date: r.day, scans: 0, average_score: null, lowest_score: null, highest_score: null, critical_findings: 0, high_findings: 0, new_assets: 0 };
          dayMap[r.day].new_assets = r.new_assets;
        }

        const trend = Object.values(dayMap).sort((a, b) => a.date.localeCompare(b.date));
        return json({ trend });
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    // GET /api/workspaces — list all workspaces
    if (request.method === "GET" && url.pathname === "/api/workspaces") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      try {
        // Return only workspaces the caller owns or is a member of.
        const result = await env.cybermeters_db
          .prepare(
            `SELECT DISTINCT w.id, w.name, w.created_at
             FROM workspaces w
             WHERE (
                     w.owner_user_id = ?
                     AND NOT EXISTS (
                       SELECT 1 FROM workspace_members any_wm
                       WHERE any_wm.workspace_id = w.id
                     )
                   )
                OR EXISTS (
                     SELECT 1 FROM workspace_members wm
                     WHERE wm.workspace_id = w.id AND wm.user_id = ?
                   )
             ORDER BY w.created_at DESC`
          )
          .bind(user.id, user.id)
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
        // Creator must be authenticated — no anonymous workspace creation.
        const creator = await requireAuth(request, env);
        if (!creator) return json({ error: "Unauthorized" }, 401);

        // Entitlement: workspace limit
        const wsUsage = await getEntitlementUsage(creator, env);
        const wsLimits = getPlanLimits(creator.plan);
        if (wsUsage.workspaces >= wsLimits.workspaces) {
          return json({
            error: `Workspace limit reached. Your ${creator.plan || "free"} plan allows ${wsLimits.workspaces} workspace${wsLimits.workspaces === 1 ? "" : "s"}. Upgrade your plan to create more.`,
            code:  "LIMIT_WORKSPACES",
            limit: wsLimits.workspaces,
            usage: wsUsage.workspaces,
          }, 403);
        }

        await env.cybermeters_db
          .prepare(`INSERT INTO workspaces (id, name, owner_user_id, created_at) VALUES (?, ?, ?, ?)`)
          .bind(id, name, creator?.id ?? null, created_at)
          .run();
        // Seed owner membership row if creator is authenticated
        if (creator) {
          await env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO workspace_members (id, workspace_id, user_id, role, created_at)
               VALUES (?, ?, ?, 'owner', datetime('now'))`
            )
            .bind(createId("wm"), id, creator.id)
            .run();
        }
        // Audit: workspace created
        await createAuditEvent(env, {
          workspace_id: id,
          user_id:      creator?.id ?? null,
          event_type:   "workspace_created",
          entity_type:  "workspace",
          entity_id:    id,
          description:  `Workspace "${name}" created`,
          metadata:     { workspace_name: name },
        });
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

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
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

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
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

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
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

    // ── Certificate Intelligence routes ────────────────────────────────────
    // GET /api/workspaces/:id/certificates
    //   Returns latest certificate_intelligence per domain in workspace.
    //   Each entry: { domain, certificate_risk_level, days_until_expiry,
    //     expires_at, total_certificates_seen, issued_for_sensitive_hosts,
    //     wildcard_dns, suspicious_certificate_signals, ct_sources }
    //
    // GET /api/workspaces/:id/certificates/timeline
    //   Returns certificate-related asset_events from the last 90 days,
    //   grouped by day: [{ day, events:[{event_type, severity, description}] }]
    const certMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/certificates(\/timeline)?$/
    );
    if (certMatch && request.method === "GET") {
      const wsId        = certMatch[1];
      const isTimeline  = !!certMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      // ── /certificates/timeline ──────────────────────────────────────────
      if (isTimeline) {
        if (domainIds.length === 0) {
          return json({ workspace_id: wsId, days: 90, timeline: [] });
        }

        // Query asset_events for cert-related event types in this workspace
        let events;
        try {
          const cutoff = new Date(Date.now() - 90 * 86_400_000).toISOString();
          const r = await env.cybermeters_db
            .prepare(
              `SELECT event_type, severity, description, hostname,
                      DATE(created_at) AS day
               FROM asset_events
               WHERE workspace_id = ?
                 AND event_type IN (
                       'certificate_sensitive_host_detected',
                       'certificate_expiring_soon',
                       'certificate_growth_detected'
                     )
                 AND created_at >= ?
               ORDER BY created_at DESC`
            )
            .bind(wsId, cutoff)
            .all();
          events = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        // Group by day
        const dayMap = new Map();
        for (const ev of events) {
          if (!dayMap.has(ev.day)) dayMap.set(ev.day, []);
          dayMap.get(ev.day).push({
            event_type:  ev.event_type,
            severity:    ev.severity,
            description: ev.description,
            hostname:    ev.hostname || null,
          });
        }

        const timeline = [...dayMap.entries()]
          .sort(([a], [b]) => b.localeCompare(a))
          .map(([day, evts]) => ({ day, events: evts }));

        return json({ workspace_id: wsId, days: 90, timeline });
      }

      // ── /certificates ───────────────────────────────────────────────────
      if (domainIds.length === 0) {
        return json({ workspace_id: wsId, total: 0, certificates: [] });
      }

      // Latest completed scan per domain
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id, domain_id FROM scans WHERE domain_id = ? " +
              "AND status = 'completed' ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanRows = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value : null))
        .filter(Boolean);

      // Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanRows.map((s) => env.cybermeters_reports.get(`reports/${s.id}.json`))
      );

      const certificates = [];
      for (let i = 0; i < r2Results.length; i++) {
        if (r2Results[i].status !== "fulfilled" || !r2Results[i].value) continue;
        let report;
        try { report = await r2Results[i].value.json(); } catch { continue; }

        const ci = report?.modules?.certificate_intelligence;
        if (!ci) continue;

        certificates.push({
          domain:                       report.domain || null,
          certificate_risk_level:       ci.certificate_risk_level,
          certificate_status:           ci.certificate_status,
          days_until_expiry:            ci.days_until_expiry,
          expires_at:                   ci.expires_at,
          total_certificates_seen:      ci.total_certificates_seen,
          issued_for_sensitive_hosts:   ci.issued_for_sensitive_hosts || [],
          wildcard_dns:                 ci.wildcard_dns,
          wildcard_warning:             ci.wildcard_warning || null,
          ct_sources:                   ci.ct_sources || {},
          suspicious_certificate_signals: ci.suspicious_certificate_signals || [],
          scan_id:                      scanRows[i]?.id || null,
        });
      }

      // Sort: critical first, then high, medium, low
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
      certificates.sort(
        (a, b) => (riskOrder[a.certificate_risk_level] ?? 5) - (riskOrder[b.certificate_risk_level] ?? 5)
      );

      return json({
        workspace_id: wsId,
        total:        certificates.length,
        certificates,
      });
    }

    // ── SaaS Exposure Discovery route ─────────────────────────────────────
    // GET /api/workspaces/:id/saas-exposure
    //   Filters: ?exposure_type=login_portal|email_gateway|saas_tenant|
    //                           support_portal|crm_portal|dev_portal|ecommerce_portal
    //            ?risk_level=low|medium|high
    //            ?category=email_identity|collaboration|crm|support|ecommerce
    //   Returns: { workspace_id, total, high_risk, exposures: [...] }
    const saasExpMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/saas-exposure$/
    );
    if (saasExpMatch && request.method === "GET") {
      const wsId = saasExpMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        return json({ workspace_id: wsId, total: 0, high_risk: 0, exposures: [] });
      }

      // 2. Latest completed scan per domain
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id FROM scans WHERE domain_id = ? AND status = 'completed' " +
              "ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanIds = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value.id : null))
        .filter(Boolean);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Merge saas_exposure.exposures across all reports (dedup by name)
      const seen      = new Set();
      const exposures = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const mod = report?.modules?.saas_exposure;
        if (!mod?.exposures?.length) continue;

        for (const exp of mod.exposures) {
          if (seen.has(exp.name)) continue;
          seen.add(exp.name);
          exposures.push({
            name:           exp.name,
            category:       exp.category,
            exposure_type:  exp.exposure_type,
            risk_level:     exp.risk_level,
            portal_url:     exp.portal_url     || null,
            admin_url:      exp.admin_url      || null,
            tenant_hint:    exp.tenant_hint    || null,
            tenant_url:     exp.tenant_url     || null,
            attack_surface: exp.attack_surface || null,
            confidence:     exp.confidence,
            domain:         report.domain      || null,
          });
        }
      }

      // Sort high → medium → low
      const riskOrder = { high: 0, medium: 1, low: 2 };
      exposures.sort((a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3));

      // Apply filters
      const filterExpType  = url.searchParams.get("exposure_type");
      const filterRisk     = url.searchParams.get("risk_level");
      const filterCategory = url.searchParams.get("category");

      const filtered = exposures.filter((e) => {
        if (filterExpType  && e.exposure_type !== filterExpType)  return false;
        if (filterRisk     && e.risk_level    !== filterRisk)     return false;
        if (filterCategory && e.category      !== filterCategory) return false;
        return true;
      });

      return json({
        workspace_id: wsId,
        total:     filtered.length,
        high_risk: filtered.filter((e) => e.risk_level === "high").length,
        exposures: filtered,
      });
    }

    // ── Cloud Asset Discovery routes ───────────────────────────────────────
    // GET /api/workspaces/:id/cloud-assets
    //   Filters: ?category=storage|cdn|serverless|paas|hosting
    //            ?provider=<name>  ?risk_level=low|medium|high
    //   Returns: { workspace_id, total, assets: [...] }
    //
    // GET /api/workspaces/:id/cloud-assets/summary
    //   Returns: { workspace_id, total, by_category:{storage,cdn,serverless,paas,hosting},
    //              high_risk, medium_risk, low_risk, providers:[{name,count}] }
    const cloudAssetsMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/cloud-assets(\/summary)?$/
    );
    if (cloudAssetsMatch && request.method === "GET") {
      const wsId      = cloudAssetsMatch[1];
      const isSummary = !!cloudAssetsMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        const empty = isSummary
          ? { workspace_id: wsId, total: 0,
              by_category: { storage: 0, cdn: 0, serverless: 0, paas: 0, hosting: 0 },
              high_risk: 0, medium_risk: 0, low_risk: 0, providers: [] }
          : { workspace_id: wsId, total: 0, assets: [] };
        return json(empty);
      }

      // 2. Latest completed scan per domain
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id FROM scans WHERE domain_id = ? AND status = 'completed' " +
              "ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanIds = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value.id : null))
        .filter(Boolean);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Merge cloud_storage_discovery.findings across all reports (dedup by asset+provider)
      const seen   = new Set();
      const assets = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const cloudMod = report?.modules?.cloud_storage_discovery;
        if (!cloudMod?.findings?.length) continue;

        for (const f of cloudMod.findings) {
          const key = `${f.asset}::${f.provider}`;
          if (seen.has(key)) continue;
          seen.add(key);
          assets.push({
            asset:        f.asset,
            provider:     f.provider,
            category:     f.category     || "storage",  // backward-compat for old reports
            service_type: f.service_type || "unknown",
            evidence:     f.evidence,
            risk_level:   f.risk_level,
            domain:       report.domain  || null,
          });
        }
      }

      // Sort: high first
      const riskOrder = { high: 0, medium: 1, low: 2 };
      assets.sort((a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3));

      if (isSummary) {
        const by_category = { storage: 0, cdn: 0, serverless: 0, paas: 0, hosting: 0 };
        const providerCount = {};
        let high_risk = 0, medium_risk = 0, low_risk = 0;

        for (const a of assets) {
          const cat = a.category;
          if (cat in by_category) by_category[cat]++;
          if (a.risk_level === "high")        high_risk++;
          else if (a.risk_level === "medium") medium_risk++;
          else if (a.risk_level === "low")    low_risk++;
          providerCount[a.provider] = (providerCount[a.provider] || 0) + 1;
        }

        const providers = Object.entries(providerCount)
          .map(([name, count]) => ({ name, count }))
          .sort((a, b) => b.count - a.count);

        return json({
          workspace_id: wsId,
          total: assets.length,
          by_category,
          high_risk,
          medium_risk,
          low_risk,
          providers,
        });
      }

      // Apply optional filters
      const filterCategory = url.searchParams.get("category");
      const filterProvider = url.searchParams.get("provider");
      const filterRisk     = url.searchParams.get("risk_level");

      const filtered = assets.filter((a) => {
        if (filterCategory && a.category   !== filterCategory) return false;
        if (filterProvider && a.provider   !== filterProvider) return false;
        if (filterRisk     && a.risk_level !== filterRisk)     return false;
        return true;
      });

      return json({ workspace_id: wsId, total: filtered.length, assets: filtered });
    }

    // ── Admin Surfaces route ───────────────────────────────────────────────
    // GET /api/workspaces/:id/admin-surfaces
    //   Filters: ?severity=critical|high|medium|low
    //            ?category=admin_panel|monitoring|vpn|collaboration|infrastructure|source_control
    //            ?confidence=confirmed|high|medium
    //   Returns: { workspace_id, total, critical, high, medium, services: [...] }
    //
    // Reads the admin_surface_detection module from the latest completed scan
    // R2 report for each domain in the workspace, then merges and deduplicates.
    const adminSurfacesMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/admin-surfaces$/
    );
    if (adminSurfacesMatch && request.method === "GET") {
      const wsId = adminSurfacesMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get all domain IDs for this workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        return json({
          workspace_id: wsId,
          total: 0, critical: 0, high: 0, medium: 0, services: [],
        });
      }

      // 2. Latest completed scan per domain (parallel D1 queries)
      const scanResults = await Promise.allSettled(
        domainIds.map((did) =>
          env.cybermeters_db
            .prepare(
              "SELECT id FROM scans WHERE domain_id = ? AND status = 'completed' " +
              "ORDER BY created_at DESC LIMIT 1"
            )
            .bind(did)
            .first()
        )
      );
      const scanIds = scanResults
        .map((r) => (r.status === "fulfilled" && r.value ? r.value.id : null))
        .filter(Boolean);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Extract and merge admin_surface_detection.services across reports
      const seen     = new Set();
      const services = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const adminMod = report?.modules?.admin_surface_detection;
        if (!adminMod?.services?.length) continue;

        for (const svc of adminMod.services) {
          const key = `${svc.hostname}::${svc.product}`;
          if (seen.has(key)) continue;
          seen.add(key);
          services.push({
            hostname:   svc.hostname,
            url:        svc.url        || `https://${svc.hostname}`,
            product:    svc.product,
            category:   svc.category,
            severity:   svc.severity   || svc.risk_level,
            confidence: svc.confidence,
            risk_level: svc.risk_level,
            ip_address: svc.ip_address || null,
            server:     svc.server     || null,
            title:      svc.title      || null,
            domain:     report.domain  || null,
          });
        }
      }

      // 5. Apply query-string filters
      const filterSeverity   = url.searchParams.get("severity");
      const filterCategory   = url.searchParams.get("category");
      const filterConfidence = url.searchParams.get("confidence");

      const filtered = services.filter((s) => {
        if (filterSeverity   && s.severity   !== filterSeverity)   return false;
        if (filterCategory   && s.category   !== filterCategory)   return false;
        if (filterConfidence && s.confidence !== filterConfidence)  return false;
        return true;
      });

      // Sort: confirmed+critical first
      const confOrder = { confirmed: 0, high: 1, medium: 2, low: 3 };
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      filtered.sort((a, b) => {
        const cd = (confOrder[a.confidence] ?? 4) - (confOrder[b.confidence] ?? 4);
        if (cd !== 0) return cd;
        return (riskOrder[a.risk_level] ?? 4) - (riskOrder[b.risk_level] ?? 4);
      });

      return json({
        workspace_id: wsId,
        total:    filtered.length,
        critical: filtered.filter((s) => s.risk_level === "critical").length,
        high:     filtered.filter((s) => s.risk_level === "high").length,
        medium:   filtered.filter((s) => s.risk_level === "medium").length,
        services: filtered,
      });
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

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

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

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

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

    // ── GET /api/workspaces/:id/scorecard/pdf ─────────────────────────────────
    // Returns a downloadable PDF executive security report.
    // Uses the same data as /scorecard/pdf-data via collectPdfData().
    const pdfMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scorecard\/pdf$/);
    if (pdfMatch && request.method === 'GET') {
      const wsId = pdfMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const pdfData = await collectPdfData(wsId, env);
        if (!pdfData) return json({ error: 'Workspace not found' }, 404);
        const bytes    = buildExecutivePdf(pdfData);
        const wsSlug   = String(pdfData.workspace?.name ?? 'report')
          .toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
        const dateSlug = pdfData.generated_at.slice(0, 10);
        const filename = `cybermeters-executive-report-${wsSlug}-${dateSlug}.pdf`;
        return new Response(bytes, {
          status: 200,
          headers: {
            ...corsHeaders,
            'Content-Type':        'application/pdf',
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length':      String(bytes.length),
          },
        });
      } catch (err) {
        return json({
          error:     'PDF generation failed',
          message:   String(err?.message ?? err),
          endpoint:  url.pathname,
          timestamp: new Date().toISOString(),
        }, 500);
      }
    }

    // ── GET /api/workspaces/:id/scorecard/pdf-data ──────────────────────────
    // Board-level executive security report — pure JSON for frontend / export.
    const pdfDataMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scorecard\/pdf-data$/);
    if (pdfDataMatch && request.method === 'GET') {
      const wsId = pdfDataMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const pdfData = await collectPdfData(wsId, env);
        if (!pdfData) return json({ error: 'Workspace not found' }, 404);
        return json(pdfData);
      } catch (err) {
        return json({
          error:  'PDF data failed',
          detail: String(err?.message ?? err),
          stack:  String(err?.stack   ?? '').slice(0, 1000),
        }, 500);
      }
    }

    // ── Executive Security Scorecard Routes ──────────────────────────────────
    // GET /api/workspaces/:id/scorecard         — business scorecard
    // GET /api/workspaces/:id/scorecard/report  — PDF-ready structured JSON
    const scorecardMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/scorecard(\/report)?$/
    );
    if (scorecardMatch && request.method === 'GET') {
      const wsId     = scorecardMatch[1];
      const isReport = !!scorecardMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare('SELECT id, name FROM workspaces WHERE id = ?')
          .bind(wsId)
          .first();
      } catch {
        return json({ error: 'Database error' }, 500);
      }
      if (!ws) return json({ error: 'Workspace not found' }, 404);

      const scorecard = await buildScorecardData(wsId, env);
      if (!scorecard) return json({ error: 'Database error' }, 500);

      // ── GET /scorecard ────────────────────────────────────────────────────
      if (!isReport) return json(scorecard);

      // ── GET /scorecard/report — structured for PDF rendering ─────────────
      const generatedAt = new Date().toISOString();

      // Derive per-section status: 'ok' | 'warning' | 'critical' | 'unknown'
      const sections = [
        {
          title:   'Asset Inventory',
          status:  scorecard.active_assets === 0 ? 'unknown'
                 : scorecard.new_assets_30d > 0  ? 'warning' : 'ok',
          summary: scorecard.active_assets > 0
            ? `${scorecard.active_assets} active assets monitored.` +
              (scorecard.new_assets_30d > 0
                ? ` ${scorecard.new_assets_30d} new in the last 30 days.`
                : ' No new assets in the last 30 days.')
            : 'No assets have been inventoried yet. Run a scan to begin discovery.',
          data: {
            active_assets:    scorecard.active_assets,
            new_assets_30d:   scorecard.new_assets_30d,
            asset_events_30d: scorecard.asset_events_30d,
          },
        },
        {
          title:   'Vendor Risk',
          status:  scorecard.vendor_risk.high   > 0 ? 'critical'
                 : scorecard.vendor_risk.medium > 0 ? 'warning' : 'ok',
          summary: scorecard.vendors_detected > 0
            ? `${scorecard.vendors_detected} vendor${scorecard.vendors_detected !== 1 ? 's' : ''} detected.` +
              (scorecard.vendor_risk.high > 0
                ? ` ${scorecard.vendor_risk.high} high-risk.`
                : ' No high-risk vendors.')
            : 'No third-party vendors detected in this scan.',
          data: {
            total:  scorecard.vendors_detected,
            ...scorecard.vendor_risk,
          },
        },
        {
          title:   'Third-Party Assets',
          status:  scorecard.third_party_assets > 0 ? 'warning' : 'ok',
          summary: scorecard.third_party_assets > 0
            ? `${scorecard.third_party_assets} third-party SaaS service${scorecard.third_party_assets !== 1 ? 's' : ''} in use (email, CRM, support, marketing).`
            : 'No third-party SaaS dependencies detected.',
          data: { count: scorecard.third_party_assets },
        },
        {
          title:   'SaaS Exposure',
          status:  scorecard.saas_exposures > 0 ? 'warning' : 'ok',
          summary: scorecard.saas_exposures > 0
            ? `${scorecard.saas_exposures} exposed SaaS portal${scorecard.saas_exposures !== 1 ? 's' : ''} or login surface${scorecard.saas_exposures !== 1 ? 's' : ''} detected.`
            : 'No externally exposed SaaS portals detected.',
          data: { count: scorecard.saas_exposures },
        },
        {
          title:   'Admin Surfaces',
          status:  scorecard.admin_surfaces > 0 ? 'critical' : 'ok',
          summary: scorecard.admin_surfaces > 0
            ? `${scorecard.admin_surfaces} admin or management interface${scorecard.admin_surfaces !== 1 ? 's' : ''} publicly exposed.`
            : 'No exposed admin surfaces detected.',
          data: { count: scorecard.admin_surfaces },
        },
        {
          title:   'Brand Monitoring',
          status:  scorecard.brand_risks.high   > 0 ? 'critical'
                 : scorecard.brand_risks.active > 0 ? 'warning' : 'ok',
          summary: scorecard.brand_risks.active > 0
            ? `${scorecard.brand_risks.active} active typosquat domain${scorecard.brand_risks.active !== 1 ? 's' : ''} detected.` +
              (scorecard.brand_risks.high > 0
                ? ` ${scorecard.brand_risks.high} high-risk.`
                : '')
            : `${scorecard.brand_risks.total} candidate domain${scorecard.brand_risks.total !== 1 ? 's' : ''} generated — none currently resolving.`,
          data: scorecard.brand_risks,
        },
        {
          title:   'Certificate Intelligence',
          status:  scorecard.certificate_risks.risk_level === 'critical' ? 'critical'
                 : scorecard.certificate_risks.risk_level === 'high'     ? 'warning'
                 : scorecard.certificate_risks.signals > 0               ? 'warning'
                 : scorecard.certificate_risks.risk_level === null        ? 'unknown' : 'ok',
          summary: scorecard.certificate_risks.risk_level
            ? `Certificate risk is ${scorecard.certificate_risks.risk_level}.` +
              (scorecard.certificate_risks.signals > 0
                ? ` ${scorecard.certificate_risks.signals} suspicious signal${scorecard.certificate_risks.signals !== 1 ? 's' : ''} detected.`
                : ' No suspicious signals.')
            : 'Certificate data not yet available from the latest scan.',
          data: scorecard.certificate_risks,
        },
        {
          title:   'Security Findings',
          status:  scorecard.critical_findings > 0 ? 'critical'
                 : scorecard.high_findings     > 0 ? 'warning' : 'ok',
          summary: (scorecard.critical_findings + scorecard.high_findings) === 0
            ? `No critical or high findings.` +
              (scorecard.medium_findings + scorecard.low_findings > 0
                ? ` ${scorecard.medium_findings + scorecard.low_findings} lower-severity finding${(scorecard.medium_findings + scorecard.low_findings) !== 1 ? 's' : ''} noted.`
                : ' Clean scan.')
            : `${scorecard.critical_findings} critical, ${scorecard.high_findings} high, ${scorecard.medium_findings} medium, ${scorecard.low_findings} low findings.`,
          data: {
            critical: scorecard.critical_findings,
            high:     scorecard.high_findings,
            medium:   scorecard.medium_findings,
            low:      scorecard.low_findings,
          },
        },
      ];

      // security_posture_chart — flat array for radar/bar chart rendering
      const sp = scorecard.security_posture;
      const security_posture_chart = sp
        ? [
            { category: 'Email Security',    score: sp.email_security?.score    ?? null, status: sp.email_security?.status    ?? 'unknown' },
            { category: 'SSL & Certificates',score: sp.ssl_certificates?.score  ?? null, status: sp.ssl_certificates?.status  ?? 'unknown' },
            { category: 'Attack Surface',    score: sp.attack_surface?.score    ?? null, status: sp.attack_surface?.status    ?? 'unknown' },
            { category: 'Third-Party Risk',  score: sp.third_party_risk?.score  ?? null, status: sp.third_party_risk?.status  ?? 'unknown' },
            { category: 'Admin Exposure',    score: sp.admin_exposure?.score    ?? null, status: sp.admin_exposure?.status    ?? 'unknown' },
          ]
        : [];

      return json({
        generated_at:           generatedAt,
        workspace:              { id: wsId, name: scorecard.workspace_name },
        scorecard,
        executive_summary:      scorecard.executive_summary,
        recommendations:        scorecard.top_recommendations,
        sections,
        security_posture:       scorecard.security_posture ?? null,
        security_posture_chart,
      });
    }

    // ── Brand Monitoring Routes ───────────────────────────────────────────────
    // GET  /api/workspaces/:id/brand-monitoring              — candidate list
    // GET  /api/workspaces/:id/brand-monitoring/summary      — risk summary
    // POST /api/workspaces/:id/brand-monitoring/refresh      — DNS validation pass
    //      (runs DoH A-record checks on top candidates; separate subrequest budget)
    const brandMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/brand-monitoring(\/summary|\/refresh)?$/
    );
    if (brandMatch && (request.method === 'GET' || request.method === 'POST')) {
      const wsId      = brandMatch[1];
      const subPath   = brandMatch[2];       // undefined | '/summary' | '/refresh'
      const isSummary = subPath === '/summary';
      const isRefresh = subPath === '/refresh';

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // refresh requires analyst+; plain read requires viewer
      const minPerm = isRefresh ? "domain:add" : "workspace:read";
      const access = await requireWorkspaceRole(user, wsId, minPerm, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare('SELECT id FROM workspaces WHERE id = ?')
          .bind(wsId)
          .first();
      } catch {
        return json({ error: 'Database error' }, 500);
      }
      if (!ws) return json({ error: 'Workspace not found' }, 404);

      // ── POST /brand-monitoring/refresh ─────────────────────────────────────
      // Validates candidates via DNS (DoH A-record). Capped at 20 lookups
      // so this endpoint's own subrequest budget stays well within 50.
      if (isRefresh && request.method === 'POST') {
        const MAX_BRAND_DNS_CHECKS = 20;

        // Get primary (oldest-added) domain for this workspace
        let primaryDomain;
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT d.domain FROM workspace_domains wd
               JOIN domains d ON d.id = wd.domain_id
               WHERE wd.workspace_id = ?
               ORDER BY d.created_at ASC LIMIT 1`
            )
            .bind(wsId)
            .first();
          primaryDomain = r?.domain;
        } catch {
          return json({ error: 'Database error' }, 500);
        }
        if (!primaryDomain) return json({ error: 'No domains in workspace' }, 404);

        const { brand, tld } = extractBrandParts(primaryDomain);
        const allCandidates   = generateTyposquatCandidates(brand, tld);
        const toValidate      = allCandidates.slice(0, MAX_BRAND_DNS_CHECKS);

        const now               = new Date().toISOString();
        const validationResults = [];

        for (const c of toValidate) {
          let dnsResolves = false;
          let ipAddress   = null;

          try {
            const dohResp = await dnsQuery(c.candidate_domain, 'A');
            if (dohResp.Answer?.length > 0) {
              dnsResolves = true;
              ipAddress   = dohResp.Answer[0]?.data || null;
            }
          } catch { /* treat as not resolving */ }

          const status = dnsResolves ? 'active' : 'inactive';
          validationResults.push({ ...c, dns_resolves: dnsResolves, ip_address: ipAddress, status });

          // Upsert validated result into D1
          try {
            await env.cybermeters_db
              .prepare(
                `INSERT INTO workspace_brand_assets
                   (id, workspace_id, domain, candidate_domain, variant_type,
                    risk_level, risk_reasons, dns_resolves, https_available,
                    ip_address, status, first_seen, last_seen, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (workspace_id, domain, candidate_domain) DO UPDATE SET
                   dns_resolves = excluded.dns_resolves,
                   ip_address   = excluded.ip_address,
                   status       = excluded.status,
                   last_seen    = excluded.last_seen,
                   updated_at   = excluded.updated_at`
              )
              .bind(
                createId('bra'),
                wsId,
                primaryDomain,
                c.candidate_domain,
                c.variant_type,
                c.risk_level,
                JSON.stringify(c.risk_reasons),
                dnsResolves ? 1 : 0,
                ipAddress,
                status,
                now,  // first_seen
                now,  // last_seen
                now,  // created_at
                now   // updated_at
              )
              .run();
          } catch { /* non-fatal */ }

          // Fire asset events for resolving (active) typosquat domains
          if (dnsResolves) {
            try {
              const domRows = await env.cybermeters_db
                .prepare('SELECT domain_id FROM workspace_domains WHERE workspace_id = ? LIMIT 1')
                .bind(wsId)
                .first();
              const evDomainId = domRows?.domain_id || null;

              const evType = c.risk_level === 'high'
                ? 'high_risk_typosquat_detected'
                : 'brand_domain_detected';

              await env.cybermeters_db
                .prepare(
                  `INSERT OR IGNORE INTO asset_events
                     (id, workspace_id, domain_id, scan_id, event_type,
                      hostname, severity, description, created_at)
                   VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)`
                )
                .bind(
                  createId('asev'),
                  wsId,
                  evDomainId,
                  evType,
                  c.candidate_domain,
                  c.risk_level === 'high' ? 'high' : 'medium',
                  `Typosquat domain ${c.candidate_domain} resolves (${c.variant_type}).` +
                    (c.risk_reasons.length > 0 ? ' ' + c.risk_reasons.join('; ') + '.' : ''),
                  now
                )
                .run();
            } catch { /* non-fatal */ }
          }
        }

        const activeResults  = validationResults.filter(v => v.dns_resolves);
        const highRiskActive = activeResults.filter(v => v.risk_level === 'high').length;

        return json({
          workspace_id:       wsId,
          brand,
          primary_domain:     primaryDomain,
          candidates_checked: toValidate.length,
          active_domains:     activeResults.length,
          high_risk_active:   highRiskActive,
          validated_at:       now,
          results:            activeResults,
        });
      }

      // ── GET /brand-monitoring/summary ───────────────────────────────────────
      if (isSummary && request.method === 'GET') {
        try {
          const [totalRow, byRiskRows, byStatusRows, highActiveRows] = await Promise.all([
            env.cybermeters_db
              .prepare('SELECT COUNT(*) AS n FROM workspace_brand_assets WHERE workspace_id = ?')
              .bind(wsId).first(),

            env.cybermeters_db
              .prepare(
                `SELECT risk_level, COUNT(*) AS n
                 FROM workspace_brand_assets WHERE workspace_id = ?
                 GROUP BY risk_level`
              )
              .bind(wsId).all(),

            env.cybermeters_db
              .prepare(
                `SELECT status, COUNT(*) AS n
                 FROM workspace_brand_assets WHERE workspace_id = ?
                 GROUP BY status`
              )
              .bind(wsId).all(),

            env.cybermeters_db
              .prepare(
                `SELECT candidate_domain, variant_type, risk_level, risk_reasons,
                        ip_address, status, first_seen, last_seen
                 FROM workspace_brand_assets
                 WHERE workspace_id = ? AND risk_level = 'high' AND status = 'active'
                 ORDER BY last_seen DESC LIMIT 10`
              )
              .bind(wsId).all(),
          ]);

          const byRisk   = Object.fromEntries((byRiskRows.results   || []).map(r => [r.risk_level, r.n]));
          const byStatus = Object.fromEntries((byStatusRows.results || []).map(r => [r.status, r.n]));

          return json({
            workspace_id:     wsId,
            total_candidates: totalRow?.n ?? 0,
            by_risk_level:    { high: byRisk.high ?? 0, medium: byRisk.medium ?? 0, low: byRisk.low ?? 0 },
            by_status:        { active: byStatus.active ?? 0, inactive: byStatus.inactive ?? 0, unverified: byStatus.unverified ?? 0 },
            high_risk_active: (highActiveRows.results || []).map(r => ({
              ...r,
              risk_reasons: (() => { try { return JSON.parse(r.risk_reasons); } catch { return []; } })(),
            })),
          });
        } catch {
          return json({ error: 'Database error' }, 500);
        }
      }

      // ── GET /brand-monitoring ────────────────────────────────────────────────
      if (!isSummary && !isRefresh && request.method === 'GET') {
        const filterStatus = url.searchParams.get('status');       // active|inactive|unverified
        const filterRisk   = url.searchParams.get('risk_level');   // high|medium|low
        const filterType   = url.searchParams.get('variant_type'); // substitution|omission|…

        const whereClauses = ['workspace_id = ?'];
        const binds        = [wsId];

        if (filterStatus) { whereClauses.push('status = ?');       binds.push(filterStatus); }
        if (filterRisk)   { whereClauses.push('risk_level = ?');   binds.push(filterRisk); }
        if (filterType)   { whereClauses.push('variant_type = ?'); binds.push(filterType); }

        const whereSQL = whereClauses.join(' AND ');

        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT candidate_domain, domain, variant_type, risk_level, risk_reasons,
                      dns_resolves, https_available, ip_address, status, first_seen, last_seen
               FROM workspace_brand_assets
               WHERE ${whereSQL}
               ORDER BY
                 CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                 CASE status     WHEN 'active' THEN 0 WHEN 'unverified' THEN 1 ELSE 2 END,
                 candidate_domain`
            )
            .bind(...binds)
            .all();

          const assets = (r.results || []).map(row => ({
            ...row,
            dns_resolves:    row.dns_resolves    !== null ? Boolean(row.dns_resolves)    : null,
            https_available: row.https_available !== null ? Boolean(row.https_available) : null,
            risk_reasons:    (() => { try { return JSON.parse(row.risk_reasons); } catch { return []; } })(),
          }));

          return json({ workspace_id: wsId, count: assets.length, assets });
        } catch {
          return json({ error: 'Database error' }, 500);
        }
      }
    }

    // ── GET /api/validation/benchmark — QA-only, no frontend ────────────
    //
    // Enterprise Validation Dataset — expected behaviour for mature domains.
    // Used as regression check: if header or email scoring findings appear
    // on these domains, validation_status = "regression_detected".
    //
    // Subrequest budget: headers module may use 2 subrequests (GET + HEAD
    // fallback) when bot protection is detected, so limit to 1 domain per call.
    //   1 domain × (5 DNS + 3 SSL + 2 headers + 15 email) ≈ 25 subrequests.
    //
    // Usage:
    //   GET /api/validation/benchmark              → test google.com (default)
    //   GET /api/validation/benchmark?domain=X     → test domain X
    //   GET /api/validation/benchmark?all=1        → meta: list all benchmark domains

    // ENTERPRISE_BENCHMARK and ENTERPRISE_DOMAINS are module-level constants
    // (defined near the top of this file, after SECURITY_HEADERS).

    if (url.pathname === "/api/validation/benchmark" && request.method === "GET") {
      try {
        // ?all=1 → return the benchmark domain list without running scans
        if (url.searchParams.get("all") === "1") {
          return json({ benchmark_domains: ENTERPRISE_BENCHMARK, note: "Use ?domain=X to test a specific domain." });
        }

        const targetDomain = url.searchParams.get("domain") ?? "google.com";
        const baseline     = ENTERPRISE_BENCHMARK.find(b => b.domain === targetDomain) ?? null;

        // Run core modules — parallel, within subrequest budget
        const [dnsR, sslR, headersR, emailR] = await Promise.allSettled([
          runDnsModule(targetDomain),
          runSslModule(targetDomain),
          runHeadersModule(targetDomain),
          runEmailModule(targetDomain),
        ]);

        const mods = {
          dns:            dnsR.status     === "fulfilled" ? dnsR.value     : { error: "module failed" },
          ssl:            sslR.status     === "fulfilled" ? sslR.value     : { error: "module failed" },
          headers:        headersR.status === "fulfilled" ? headersR.value : { error: "module failed" },
          email_security: emailR.status   === "fulfilled" ? emailR.value   : { error: "module failed" },
        };

        const { score, risk_level, findings } = computeScore(mods, targetDomain);

        const scoringFindings  = findings.filter(f => f.score_impact < 0);
        const headerFindings   = scoringFindings.filter(f => f.module === "headers");
        const emailFindings    = scoringFindings.filter(f => f.module === "email_security");
        const infoFindings     = findings.filter(f => f.score_impact === 0);
        const emailApp         = isEmailApplicable(targetDomain, mods.dns);

        // ── Regression check ─────────────────────────────────────────────
        const regressionViolations = [];
        if (baseline) {
          if (headerFindings.length > baseline.max_header_findings) {
            regressionViolations.push(
              `header_findings: got ${headerFindings.length}, max allowed ${baseline.max_header_findings}`
            );
          }
          if (emailFindings.length > baseline.max_email_findings) {
            regressionViolations.push(
              `email_findings: got ${emailFindings.length}, max allowed ${baseline.max_email_findings}`
            );
          }
          // Only fail the redirect check when:
          //   • the redirect chain was observable (not blocked by firewall/bot protection)
          //   • the scoring engine did NOT downgrade the finding to info/low-confidence
          //     (which happens for enterprise edge uncertain domains where the HTTP probe
          //     returned a non-redirecting response but HTTPS headers probed successfully)
          //   • validation_uncertain is false
          // If any of these conditions apply, we cannot conclude the redirect is missing.
          const redirectValidated   = mods.ssl?.http_redirect_chain?.http_redirect_validated !== false;
          const redirectDowngraded  = findings.some(f =>
            f.id           === "ssl_no_http_redirect" &&
            f.severity     === "info"                 &&
            f.confidence   === "low"                  &&
            Number(f.score_impact ?? 0) === 0
          );
          const validationUncertain = !!mods.headers?.validation_uncertain;
          if (
            baseline.expect_https_redirect &&
            redirectValidated              &&
            !mods.ssl?.http_redirects_to_https &&
            !redirectDowngraded            &&
            !validationUncertain
          ) {
            regressionViolations.push("expected http_redirects_to_https = true (chain was observable)");
          }
        }

        const passed             = regressionViolations.length === 0;
        const regressionDetected = !passed;

        return json({
          domain:                     targetDomain,
          score,
          risk_level,
          passed,
          regression_detected:        regressionDetected,
          regression_violations:      regressionViolations,
          baseline:                   baseline ?? "no baseline — custom domain",
          email_applicable:           emailApp.applicable,
          email_applicability_reason: emailApp.reason ?? null,
          http_redirects_to_https:    mods.ssl?.http_redirects_to_https ?? null,
          http_redirect_chain:        mods.ssl?.http_redirect_chain ?? null,
          http_redirect_validated:    mods.ssl?.http_redirect_chain?.http_redirect_validated ?? null,
          headers_final_https:        mods.headers?.final_https ?? null,
          headers_status_code:        mods.headers?.status_code ?? null,
          validation_uncertain:       mods.headers?.validation_uncertain ?? false,
          bot_protection_signals:     mods.headers?.bot_protection_signals ?? [],
          raw_capture:                mods.headers?.raw_capture ?? null,
          finding_count:              scoringFindings.length,
          header_findings:            headerFindings.length,   // renamed from header_finding_count
          email_findings:             emailFindings.length,    // renamed from email_finding_count
          info_count:                 infoFindings.length,
          findings: findings.map(f => ({
            id:           f.id,
            module:       f.module,
            severity:     f.severity,
            confidence:   f.confidence ?? null,
            title:        f.title,
            score_impact: f.score_impact,
          })),
          note: "One domain per call (subrequest budget). Use ?domain=X to target a specific domain.",
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/workspaces/:id/summary ──────────────────────────────────────
    const summaryMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/summary$/);
    if (summaryMatch && request.method === "GET") {
      const workspaceId = summaryMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id, name FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        const [
          domainsResult,
          assetsResult,
          vendorsResult,
          scoreResult,
          findingsResult,
          lastScanResult,
          lastReportResult,
          reportsCountResult,
        ] = await Promise.allSettled([
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_domains WHERE workspace_id = ?")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_assets WHERE workspace_id = ? AND status = 'active'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(DISTINCT vendor_name) AS cnt FROM vendor_findings WHERE workspace_id = ?")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare(`
              WITH lpd AS (
                SELECT domain_id, MAX(created_at) AS mx
                FROM scans
                WHERE workspace_id = ? AND status = 'completed'
                GROUP BY domain_id
              )
              SELECT AVG(s.score) AS avg_score
              FROM scans s JOIN lpd ON lpd.domain_id = s.domain_id AND lpd.mx = s.created_at
            `)
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare(`
              WITH lpd AS (
                SELECT domain_id, MAX(created_at) AS mx
                FROM scans
                WHERE workspace_id = ? AND status = 'completed'
                GROUP BY domain_id
              )
              SELECT
                SUM(CASE WHEN f.severity = 'critical' THEN 1 ELSE 0 END) AS critical_findings,
                SUM(CASE WHEN f.severity = 'high'     THEN 1 ELSE 0 END) AS high_findings
              FROM findings f
              JOIN scans s ON s.id = f.scan_id
              JOIN lpd ON lpd.domain_id = s.domain_id AND lpd.mx = s.created_at
            `)
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT MAX(created_at) AS last_scan_at FROM scans WHERE workspace_id = ? AND status = 'completed'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT MAX(generated_at) AS last_report_at FROM workspace_reports WHERE workspace_id = ? AND status = 'completed'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_reports WHERE workspace_id = ?")
            .bind(workspaceId)
            .first(),
        ]);

        const v = (r) => (r.status === "fulfilled" ? r.value : null);

        return json({
          workspace_id:      ws.id,
          workspace_name:    ws.name,
          domains:           v(domainsResult)?.cnt          ?? 0,
          active_assets:     v(assetsResult)?.cnt           ?? 0,
          vendors:           v(vendorsResult)?.cnt          ?? 0,
          latest_score:      v(scoreResult)?.avg_score != null ? Math.round(v(scoreResult).avg_score) : null,
          critical_findings: v(findingsResult)?.critical_findings ?? 0,
          high_findings:     v(findingsResult)?.high_findings     ?? 0,
          last_scan_at:      v(lastScanResult)?.last_scan_at      ?? null,
          last_report_at:    v(lastReportResult)?.last_report_at  ?? null,
          reports_count:     v(reportsCountResult)?.cnt           ?? 0,
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/workspaces/:id/health ────────────────────────────────────────
    const healthMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/health$/);
    if (healthMatch && request.method === "GET") {
      const workspaceId = healthMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        const [domR, assetR, reportR, scanR] = await Promise.allSettled([
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_domains WHERE workspace_id = ?")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_assets WHERE workspace_id = ? AND status = 'active'")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_reports WHERE workspace_id = ?")
            .bind(workspaceId)
            .first(),
          env.cybermeters_db
            .prepare("SELECT MAX(created_at) AS last_scan_at FROM scans WHERE workspace_id = ? AND status = 'completed'")
            .bind(workspaceId)
            .first(),
        ]);

        const v = (r) => (r.status === "fulfilled" ? r.value : null);

        const domains_monitored  = v(domR)?.cnt    ?? 0;
        const assets_discovered  = v(assetR)?.cnt  ?? 0;
        const reports_generated  = v(reportR)?.cnt ?? 0;
        const lastScanAt         = v(scanR)?.last_scan_at ?? null;

        let latest_scan_age_hours = null;
        if (lastScanAt) {
          const ageMs = Date.now() - new Date(lastScanAt.includes("T") ? lastScanAt : lastScanAt + "Z").getTime();
          latest_scan_age_hours = Math.round(ageMs / 3_600_000);
        }

        // workspace_status
        let workspace_status;
        if (domains_monitored === 0) {
          workspace_status = "no_domains";
        } else if (!lastScanAt) {
          workspace_status = "no_scans";
        } else if (latest_scan_age_hours !== null && latest_scan_age_hours > 168) {
          workspace_status = "stale"; // older than 7 days
        } else {
          workspace_status = "active";
        }

        // monitoring_health
        let monitoring_health;
        if (workspace_status === "no_domains" || workspace_status === "no_scans") {
          monitoring_health = "stale";
        } else if (latest_scan_age_hours !== null && latest_scan_age_hours > 72) {
          monitoring_health = "warning";
        } else {
          monitoring_health = "healthy";
        }

        return json({
          workspace_status,
          domains_monitored,
          assets_discovered,
          reports_generated,
          latest_scan_age_hours,
          latest_report_age_hours: null, // reserved — not critical path
          monitoring_health,
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/workspaces/:id/invitations ─────────────────────────────────
    const invitationsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/invitations$/);
    if (invitationsMatch && request.method === "GET") {
      const workspaceId = invitationsMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage invitations" }, 403);
      try {
        const result = await env.cybermeters_db
          .prepare(
            `SELECT wi.id, wi.workspace_id, wi.email, wi.role, wi.invited_by,
                    wi.status, wi.expires_at, wi.accepted_at, wi.created_at,
                    u.email AS invited_by_email, u.name AS invited_by_name
             FROM workspace_invitations wi
             LEFT JOIN users u ON u.id = wi.invited_by
             WHERE wi.workspace_id = ?
             ORDER BY wi.created_at DESC
             LIMIT 100`
          )
          .bind(workspaceId)
          .all();
        return json({ invitations: result.results || [] });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── POST /api/workspaces/:id/invitations ────────────────────────────────
    if (invitationsMatch && request.method === "POST") {
      const workspaceId = invitationsMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:invite", env);
      if (!access) return json({ error: "Forbidden — admin role required to invite members" }, 403);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email = (body.email || "").trim().toLowerCase();
      const role  = (body.role || "viewer").trim().toLowerCase();
      const VALID_INVITE_ROLES = new Set(["viewer", "analyst", "admin"]);

      if (!email) return json({ error: "email is required" }, 400);
      if (!isValidEmail(email)) return json({ error: "email must be valid" }, 400);
      if (!VALID_INVITE_ROLES.has(role)) return json({ error: "role must be one of: viewer, analyst, admin" }, 400);

      try {
        const workspace = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!workspace) return json({ error: "Workspace not found" }, 404);

        const existingUser = await env.cybermeters_db
          .prepare("SELECT id FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();
        if (existingUser) {
          const existingMember = await env.cybermeters_db
            .prepare("SELECT id FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1")
            .bind(workspaceId, existingUser.id)
            .first();
          if (existingMember) return json({ error: "User is already a workspace member" }, 409);
        }

        const existingInvite = await env.cybermeters_db
          .prepare(
            `SELECT id FROM workspace_invitations
             WHERE workspace_id = ? AND email = ? AND status = 'pending'
               AND expires_at > datetime('now')
             LIMIT 1`
          )
          .bind(workspaceId, email)
          .first();
        if (existingInvite) return json({ error: "A pending invitation already exists for this email" }, 409);

        const { raw: token, hash: tokenHash } = await generateInviteToken();
        const inviteId  = createId("wsi");
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_invitations
               (id, workspace_id, email, role, token_hash, invited_by, status, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, datetime('now'))`
          )
          .bind(inviteId, workspaceId, email, role, tokenHash, user.id, expiresAt)
          .run();

        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_invitation_created",
          entity_type:  "workspace_invitation",
          entity_id:    inviteId,
          description:  `${user.email} invited ${email} as ${role}`,
          metadata:     { invitation_id: inviteId, email, role, expires_at: expiresAt },
        });

        return json({
          invitation: {
            id: inviteId, workspace_id: workspaceId, email, role,
            status: "pending", expires_at: expiresAt,
          },
          token,
        }, 201);
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/workspaces/:id/members ──────────────────────────────────────
    const membersListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/members$/);
    if (membersListMatch && request.method === "GET") {
      const workspaceId = membersListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "member:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const result = await env.cybermeters_db
          .prepare(
            `SELECT wm.id, wm.workspace_id, wm.user_id, wm.role, wm.created_at,
                    u.email, u.name
             FROM workspace_members wm
             JOIN users u ON u.id = wm.user_id
             WHERE wm.workspace_id = ?
             ORDER BY
               CASE wm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'analyst' THEN 2 ELSE 3 END,
               wm.created_at ASC`
          )
          .bind(workspaceId)
          .all();
        return json({
          workspace_id: workspaceId,
          caller_role:  access.role,
          members:      result.results || [],
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── POST /api/workspaces/:id/members — add member ─────────────────────────
    if (membersListMatch && request.method === "POST") {
      const workspaceId = membersListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:manage_members", env);
      if (!access) return json({ error: "Forbidden — owner role required to manage members" }, 403);

      let body;
      try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

      const email   = (body.email || "").trim().toLowerCase();
      const rawRole = (body.role  || "viewer").trim().toLowerCase();

      if (!email)                          return json({ error: "email is required" }, 400);
      if (!ROLE_RANK.hasOwnProperty(rawRole)) return json({ error: `role must be one of: ${Object.keys(ROLE_RANK).join(", ")}` }, 400);
      if (rawRole === "owner")             return json({ error: "Cannot assign owner role via invite. Transfer ownership instead." }, 400);

      try {
        // Resolve target user by email
        const target = await env.cybermeters_db
          .prepare("SELECT id, email, name FROM users WHERE email = ? LIMIT 1")
          .bind(email)
          .first();
        if (!target) return json({ error: `No account found for ${email}. The user must sign up first.` }, 404);

        // Prevent demoting an owner via this route
        const existing = await env.cybermeters_db
          .prepare("SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ? LIMIT 1")
          .bind(workspaceId, target.id)
          .first();
        if (existing?.role === "owner") return json({ error: "Cannot change the owner's role via this endpoint." }, 409);

        const memberId = createId("wm");
        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_members (id, workspace_id, user_id, role, invited_by, created_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = excluded.role`
          )
          .bind(memberId, workspaceId, target.id, rawRole, user.id)
          .run();

        // Audit: member added
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_member_added",
          entity_type:  "member",
          entity_id:    target.id,
          description:  `${user.email} added ${target.email} as ${rawRole}`,
          metadata:     { added_user_id: target.id, added_email: target.email, role: rawRole },
        });

        return json({
          member: {
            workspace_id: workspaceId,
            user_id:      target.id,
            email:        target.email,
            name:         target.name,
            role:         rawRole,
          },
        }, 201);
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── DELETE /api/workspaces/:id/members/:memberId ──────────────────────────
    const memberDeleteMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/members\/([^/]+)$/);
    if (memberDeleteMatch && request.method === "DELETE") {
      const workspaceId = memberDeleteMatch[1];
      const memberId    = memberDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:manage_members", env);
      if (!access) return json({ error: "Forbidden — owner role required to manage members" }, 403);

      try {
        const row = await env.cybermeters_db
          .prepare("SELECT id, user_id, role FROM workspace_members WHERE id = ? AND workspace_id = ?")
          .bind(memberId, workspaceId)
          .first();
        if (!row) return json({ error: "Member not found" }, 404);

        // Owner cannot remove themselves
        if (row.role === "owner" && row.user_id === user.id) {
          return json({ error: "Owner cannot remove themselves. Transfer ownership first." }, 409);
        }
        // Cannot remove the last owner
        if (row.role === "owner") {
          const ownerCount = await env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM workspace_members WHERE workspace_id = ? AND role = 'owner'")
            .bind(workspaceId)
            .first();
          if ((ownerCount?.cnt ?? 0) <= 1) {
            return json({ error: "Cannot remove the only owner of a workspace." }, 409);
          }
        }

        await env.cybermeters_db
          .prepare("DELETE FROM workspace_members WHERE id = ?")
          .bind(memberId)
          .run();

        // Audit: member removed
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      user.id,
          event_type:   "workspace_member_removed",
          entity_type:  "member",
          entity_id:    row.user_id,
          description:  `${user.email} removed member with role ${row.role}`,
          metadata:     { removed_member_id: memberId, removed_user_id: row.user_id, role: row.role },
        });

        return json({ success: true, removed_id: memberId });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── POST /api/invitations/:token/accept ─────────────────────────────────
    const invitationAcceptMatch = url.pathname.match(/^\/api\/invitations\/([^/]+)\/accept$/);
    if (invitationAcceptMatch && request.method === "POST") {
      const rawToken = invitationAcceptMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      try {
        const tokenHash = await hashToken(rawToken);
        const invite = await env.cybermeters_db
          .prepare(
            `SELECT id, workspace_id, email, role, invited_by, status, expires_at
             FROM workspace_invitations
             WHERE token_hash = ?
             LIMIT 1`
          )
          .bind(tokenHash)
          .first();

        if (!invite) return json({ error: "Invitation not found" }, 404);
        if (invite.status !== "pending") return json({ error: `Invitation is ${invite.status}` }, 409);

        const expiresAt = new Date(invite.expires_at);
        if (!invite.expires_at || Number.isNaN(expiresAt.getTime()) || expiresAt.getTime() <= Date.now()) {
          await env.cybermeters_db
            .prepare("UPDATE workspace_invitations SET status = 'expired' WHERE id = ?")
            .bind(invite.id)
            .run();
          return json({ error: "Invitation expired" }, 410);
        }

        if ((user.email || "").trim().toLowerCase() !== invite.email) {
          return json({ error: "Invitation email does not match authenticated user" }, 403);
        }

        await env.cybermeters_db
          .prepare(
            `INSERT INTO workspace_members (id, workspace_id, user_id, role, invited_by, created_at)
             VALUES (?, ?, ?, ?, ?, datetime('now'))
             ON CONFLICT(workspace_id, user_id) DO UPDATE SET role = excluded.role`
          )
          .bind(createId("wm"), invite.workspace_id, user.id, invite.role, invite.invited_by)
          .run();

        await env.cybermeters_db
          .prepare(
            `UPDATE workspace_invitations
             SET status = 'accepted', accepted_at = datetime('now')
             WHERE id = ?`
          )
          .bind(invite.id)
          .run();

        await createAuditEvent(env, {
          workspace_id: invite.workspace_id,
          user_id:      user.id,
          event_type:   "workspace_invitation_accepted",
          entity_type:  "workspace_invitation",
          entity_id:    invite.id,
          description:  `${user.email} accepted workspace invitation as ${invite.role}`,
          metadata:     { invitation_id: invite.id, invited_email: invite.email, role: invite.role },
        });

        return json({
          success: true,
          workspace_id: invite.workspace_id,
          role: invite.role,
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/workspaces/:id/activity ─────────────────────────────────────
    // Returns paginated audit events for a workspace.
    // Query params: ?limit=N (max 100) &event_type=X &offset=N
    const activityMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/activity$/);
    if (activityMatch && request.method === "GET") {
      const workspaceId = activityMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const limit     = Math.min(parseInt(url.searchParams.get("limit")  || "50", 10), 100);
        const offset    = Math.max(parseInt(url.searchParams.get("offset") || "0",  10), 0);
        const eventType = url.searchParams.get("event_type") || null;

        let query, binds;
        if (eventType) {
          query = `SELECT id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at
                   FROM audit_events
                   WHERE workspace_id = ? AND event_type = ?
                   ORDER BY created_at DESC LIMIT ? OFFSET ?`;
          binds = [workspaceId, eventType, limit, offset];
        } else {
          query = `SELECT id, user_id, event_type, entity_type, entity_id, description, metadata_json, created_at
                   FROM audit_events
                   WHERE workspace_id = ?
                   ORDER BY created_at DESC LIMIT ? OFFSET ?`;
          binds = [workspaceId, limit, offset];
        }

        const result = await env.cybermeters_db.prepare(query).bind(...binds).all();
        const events = (result.results || []).map(r => ({
          ...r,
          metadata: r.metadata_json ? JSON.parse(r.metadata_json) : null,
          metadata_json: undefined,
        }));

        // Enrich with actor email from users table (best-effort JOIN avoided via batch)
        const userIds = [...new Set(events.map(e => e.user_id).filter(Boolean))];
        let userMap = {};
        if (userIds.length) {
          const placeholders = userIds.map(() => "?").join(",");
          const usersR = await env.cybermeters_db
            .prepare(`SELECT id, name, email FROM users WHERE id IN (${placeholders})`)
            .bind(...userIds)
            .all();
          for (const u of (usersR.results || [])) userMap[u.id] = { name: u.name, email: u.email };
        }

        const enriched = events.map(e => ({
          ...e,
          actor: e.user_id ? (userMap[e.user_id] ?? { name: null, email: null }) : null,
        }));

        return json({ events: enriched, limit, offset, count: enriched.length });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── GET /api/workspaces/:id/notifications ────────────────────────────────
    const notifListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/notifications$/);
    if (notifListMatch && request.method === "GET") {
      const workspaceId = notifListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const limit  = Math.min(parseInt(url.searchParams.get("limit")  || "50",  10), 200);
        const status = url.searchParams.get("status") || null; // 'unread' | 'read' | null (all)
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        let query, binds;
        if (status) {
          query  = `SELECT id, type, severity, title, message, metadata_json, status, created_at, read_at
                    FROM notification_events
                    WHERE workspace_id = ? AND status = ?
                    ORDER BY created_at DESC LIMIT ?`;
          binds  = [workspaceId, status, limit];
        } else {
          query  = `SELECT id, type, severity, title, message, metadata_json, status, created_at, read_at
                    FROM notification_events
                    WHERE workspace_id = ?
                    ORDER BY created_at DESC LIMIT ?`;
          binds  = [workspaceId, limit];
        }

        const [rows, unreadRow] = await env.cybermeters_db.batch([
          env.cybermeters_db.prepare(query).bind(...binds),
          env.cybermeters_db
            .prepare("SELECT COUNT(*) AS cnt FROM notification_events WHERE workspace_id = ? AND status = 'unread'")
            .bind(workspaceId),
        ]);

        const notifications = (rows.results || []).map(n => ({
          ...n,
          metadata: n.metadata_json ? (() => { try { return JSON.parse(n.metadata_json); } catch { return null; } })() : null,
          metadata_json: undefined,
        }));

        return json({
          workspace_id:   workspaceId,
          unread_count:   unreadRow.results?.[0]?.cnt ?? 0,
          count:          notifications.length,
          notifications,
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── POST /api/workspaces/:id/notifications/:notifId/read ─────────────────
    const notifReadMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/notifications\/([^/]+)\/read$/);
    if (notifReadMatch && request.method === "POST") {
      const workspaceId  = notifReadMatch[1];
      const notifId      = notifReadMatch[2];
      const notifUser = await requireAuth(request, env);
      if (!notifUser) return json({ error: "Unauthorized" }, 401);
      const notifAccess = await requireWorkspaceRole(notifUser, workspaceId, "notification:mark_read", env);
      if (!notifAccess) return json({ error: "Forbidden" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        if (notifId === "all") {
          // Mark all unread notifications for this workspace as read
          await env.cybermeters_db
            .prepare(`UPDATE notification_events SET status = 'read', read_at = datetime('now')
                      WHERE workspace_id = ? AND status = 'unread'`)
            .bind(workspaceId)
            .run();
          // Audit: bulk mark read
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      notifUser?.id ?? null,
            event_type:   "notification_read",
            entity_type:  "notification",
            description:  "All notifications marked as read",
            metadata:     { bulk: true },
          });
          return json({ success: true, marked: "all" });
        }
        // Mark a specific notification as read
        const row = await env.cybermeters_db
          .prepare("SELECT id FROM notification_events WHERE id = ? AND workspace_id = ?")
          .bind(notifId, workspaceId)
          .first();
        if (!row) return json({ error: "Notification not found" }, 404);
        await env.cybermeters_db
          .prepare(`UPDATE notification_events SET status = 'read', read_at = datetime('now') WHERE id = ?`)
          .bind(notifId)
          .run();
        // Audit: single notification read
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      notifUser?.id ?? null,
          event_type:   "notification_read",
          entity_type:  "notification",
          entity_id:    notifId,
          description:  "Notification marked as read",
        });
        return json({ success: true, id: notifId });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── POST /api/workspaces/:id/domains/import ───────────────────────────────
    const importMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/import$/);
    if (importMatch && request.method === "POST") {
      const workspaceId = importMatch[1];
      // RBAC: admin or above required to import domains
      const importUser = await requireAuth(request, env);
      if (!importUser) return json({ error: "Unauthorized" }, 401);
      const importAccess = await requireWorkspaceRole(importUser, workspaceId, "domain:import", env);
      if (!importAccess) return json({ error: "Forbidden — admin role required to import domains" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

        const rawList = Array.isArray(body.domains) ? body.domains : [];
        if (rawList.length === 0) return json({ error: "domains array is required and must not be empty" }, 400);
        if (rawList.length > 500) return json({ error: "Maximum 500 domains per import" }, 400);

        // Normalize + validate
        const invalid  = [];
        const valid    = [];
        const seen     = new Set();
        for (const raw of rawList) {
          if (typeof raw !== "string") { invalid.push(String(raw)); continue; }
          const d = normalizeHostname(raw.trim().toLowerCase());
          if (!d || !isValidDomain(d)) { invalid.push(raw.trim()); continue; }
          if (seen.has(d)) continue; // input-level dup
          seen.add(d);
          valid.push(d);
        }

        if (valid.length === 0) {
          return json({ imported: 0, skipped: 0, invalid: invalid.length, total: rawList.length });
        }

        // Entitlement: domain-per-workspace limit — check before touching DB
        const impUsage  = await getEntitlementUsage(importUser, env, workspaceId);
        const impLimits = getPlanLimits(importUser.plan);
        const remaining = impLimits.domains_per_workspace - impUsage.domains_in_workspace;
        if (remaining <= 0) {
          return json({
            error: `Domain limit reached. Your ${importUser.plan || "free"} plan allows ${impLimits.domains_per_workspace} domain${impLimits.domains_per_workspace === 1 ? "" : "s"} per workspace. Upgrade your plan to import more.`,
            code:  "LIMIT_DOMAINS",
            limit: impLimits.domains_per_workspace,
            usage: impUsage.domains_in_workspace,
          }, 403);
        }
        // Trim valid list to what fits
        const validTrimmed = valid.slice(0, remaining);
        const trimmedCount = valid.length - validTrimmed.length;
        const validToImport = validTrimmed;

        // Find existing domains in this workspace
        const existingRows = await env.cybermeters_db
          .prepare("SELECT d.domain FROM domains d JOIN workspace_domains wd ON wd.domain_id = d.id WHERE wd.workspace_id = ?")
          .bind(workspaceId)
          .all();
        const existingSet = new Set((existingRows.results || []).map((r) => r.domain));

        let imported = 0;
        let skipped  = 0;

        for (const domain of validToImport) {
          if (existingSet.has(domain)) { skipped++; continue; }

          // Upsert into domains table
          await env.cybermeters_db
            .prepare("INSERT INTO domains (id, domain, first_seen) VALUES (?, ?, datetime('now')) ON CONFLICT(domain) DO NOTHING")
            .bind(createId("dom"), domain)
            .run();

          const domRow = await env.cybermeters_db
            .prepare("SELECT id FROM domains WHERE domain = ?")
            .bind(domain)
            .first();
          if (!domRow) { skipped++; continue; }

          // Link to workspace
          const already = await env.cybermeters_db
            .prepare("SELECT id FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?")
            .bind(workspaceId, domRow.id)
            .first();

          if (already) { skipped++; continue; }

          await env.cybermeters_db
            .prepare("INSERT INTO workspace_domains (id, workspace_id, domain_id, added_at) VALUES (?, ?, ?, datetime('now'))")
            .bind(createId("wsd"), workspaceId, domRow.id)
            .run();

          imported++;
        }

        // Audit: domain import completed
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      importUser?.id ?? null,
          event_type:   "domain_imported",
          entity_type:  "domain",
          description:  `Imported ${imported} domain${imported !== 1 ? "s" : ""} (${skipped} skipped, ${invalid.length} invalid)`,
          metadata:     { imported, skipped, invalid: invalid.length, total: rawList.length },
        });

        return json({ imported, skipped, invalid: invalid.length, trimmed: trimmedCount, total: rawList.length }, 200);
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── POST /api/domains/:id/verification ───────────────────────────────────
    // Generate a cryptographically secure token and return DNS + HTML instructions.
    // Idempotent: calling again resets to a new pending token.
    const domVerInitMatch = url.pathname.match(/^\/api\/domains\/([^/]+)\/verification$/);
    if (domVerInitMatch && request.method === "POST") {
      const domainId = domVerInitMatch[1];
      try {
        const domRow = await env.cybermeters_db
          .prepare("SELECT id, domain, verification_status FROM domains WHERE id = ?")
          .bind(domainId)
          .first();
        if (!domRow) return json({ error: "Domain not found" }, 404);

        // RBAC: resolve all linked workspaces for this domain, then check domain:verify permission
        const dviUser = await requireAuth(request, env);
        if (!dviUser) return json({ error: "Unauthorized" }, 401);
        const dviAccess = await requireDomainRole(dviUser, domainId, "domain:verify", env);
        if (!dviAccess) return json({ error: "Forbidden — admin role required to initiate domain verification" }, 403);

        // Already verified — don't reset
        if (domRow.verification_status === "verified") {
          return json({
            already_verified: true,
            domain: domRow.domain,
            verification_status: "verified",
          });
        }

        // Generate a cryptographically secure 48-char hex token
        const tokenBytes = new Uint8Array(24);
        crypto.getRandomValues(tokenBytes);
        const token = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, "0")).join("");

        await env.cybermeters_db
          .prepare(`UPDATE domains
                    SET verification_status = 'pending',
                        verification_token  = ?,
                        verification_method = NULL,
                        verified_at         = NULL,
                        verification_initiated_at = datetime('now')
                    WHERE id = ?`)
          .bind(token, domainId)
          .run();

        const domain = domRow.domain;
        return json({
          domain,
          domain_id:          domainId,
          verification_status: "pending",
          token,
          dns: {
            record_type: "TXT",
            host:        `_cybermeters.${domain}`,
            value:       `cybermeters-verification=${token}`,
            instructions: [
              `Add a DNS TXT record to your domain:`,
              `  Host:  _cybermeters.${domain}`,
              `  Type:  TXT`,
              `  Value: cybermeters-verification=${token}`,
              `DNS changes can take up to 48 hours to propagate globally.`,
            ],
          },
          html: {
            url:      `https://${domain}/cybermeters-verification-${token}.html`,
            content:  token,
            instructions: [
              `Create a publicly accessible HTML file at your domain:`,
              `  URL:     https://${domain}/cybermeters-verification-${token}.html`,
              `  Content: ${token}`,
              `The file must be accessible without authentication.`,
            ],
          },
        });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ── POST /api/domains/:id/verify ─────────────────────────────────────────
    // Perform the actual check: DNS TXT or HTML file.
    // Tries DNS first, then HTML. First passing method wins.
    const domVerCheckMatch = url.pathname.match(/^\/api\/domains\/([^/]+)\/verify$/);
    if (domVerCheckMatch && request.method === "POST") {
      const domainId = domVerCheckMatch[1];
      try {
        const domRow = await env.cybermeters_db
          .prepare("SELECT id, domain, verification_status, verification_token FROM domains WHERE id = ?")
          .bind(domainId)
          .first();
        if (!domRow) return json({ error: "Domain not found" }, 404);

        // RBAC: resolve all linked workspaces for this domain, then check domain:verify permission
        const dvcUser = await requireAuth(request, env);
        if (!dvcUser) return json({ error: "Unauthorized" }, 401);
        const dvcAccess = await requireDomainRole(dvcUser, domainId, "domain:verify", env);
        if (!dvcAccess) return json({ error: "Forbidden — admin role required to verify domain ownership" }, 403);

        if (domRow.verification_status === "verified") {
          return json({
            success: true,
            domain: domRow.domain,
            verification_status: "verified",
            verification_method: "already_verified",
            message: "Domain is already verified.",
          });
        }

        if (!domRow.verification_token) {
          return json({
            error: "No verification token found. Call POST /api/domains/:id/verification first.",
          }, 400);
        }

        const domain = domRow.domain;
        const token  = domRow.verification_token;
        const expectedTxtValue = `cybermeters-verification=${token}`;
        const htmlUrl          = `https://${domain}/cybermeters-verification-${token}.html`;

        // ── Method 1: DNS TXT ─────────────────────────────────────────────
        let dnsVerified = false;
        let dnsError    = null;
        try {
          const txtHost = `_cybermeters.${domain}`;
          const dnsResult = await dnsQuery(txtHost, "TXT");
          const answers = dnsResult.Answer || [];
          dnsVerified = answers.some(a => {
            // RFC 1035: TXT data arrives with surrounding quotes stripped by DoH JSON
            const val = String(a.data || "").replace(/^"|"$/g, "").trim();
            return val === expectedTxtValue;
          });
        } catch (e) {
          dnsError = e.message;
        }

        if (dnsVerified) {
          await env.cybermeters_db
            .prepare(`UPDATE domains
                      SET verification_status = 'verified',
                          verification_method = 'dns_txt',
                          verified_at = datetime('now')
                      WHERE id = ?`)
            .bind(domainId)
            .run();
          // Notifications + audit — fire-and-forget for all linked workspaces
          try {
            const wsR = await env.cybermeters_db
              .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
              .bind(domainId).all();
            for (const { workspace_id } of (wsR.results || [])) {
              await createNotificationEvent(env, workspace_id, {
                type: "domain_verified", severity: "info",
                title: `${domain} ownership verified`,
                message: `Domain verified via DNS TXT record at _cybermeters.${domain}.`,
                metadata: { domain, domain_id: domainId, method: "dns_txt" },
              });
              await createAuditEvent(env, {
                workspace_id,
                user_id:     dvcUser?.id ?? null,
                event_type:  "domain_verified",
                entity_type: "domain",
                entity_id:   domainId,
                description: `${domain} ownership verified via DNS TXT`,
                metadata:    { domain, domain_id: domainId, method: "dns_txt" },
              });
            }
          } catch { /* non-fatal */ }
          return json({
            success: true,
            domain,
            verification_status: "verified",
            verification_method: "dns_txt",
            message: `DNS TXT record verified at _cybermeters.${domain}.`,
          });
        }

        // ── Method 2: HTML file ───────────────────────────────────────────
        let htmlVerified = false;
        let htmlError    = null;
        try {
          const htmlRes = await fetch(htmlUrl, {
            headers: { "User-Agent": "CyberMeters-Verification/1.0" },
            signal: AbortSignal.timeout(8_000),
            redirect: "follow",
          });
          if (htmlRes.ok) {
            const body = (await htmlRes.text()).trim();
            htmlVerified = body === token;
          } else {
            htmlError = `HTTP ${htmlRes.status}`;
          }
        } catch (e) {
          htmlError = e.message;
        }

        if (htmlVerified) {
          await env.cybermeters_db
            .prepare(`UPDATE domains
                      SET verification_status = 'verified',
                          verification_method = 'html_file',
                          verified_at = datetime('now')
                      WHERE id = ?`)
            .bind(domainId)
            .run();
          // Notifications + audit — fire-and-forget for all linked workspaces
          try {
            const wsR = await env.cybermeters_db
              .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
              .bind(domainId).all();
            for (const { workspace_id } of (wsR.results || [])) {
              await createNotificationEvent(env, workspace_id, {
                type: "domain_verified", severity: "info",
                title: `${domain} ownership verified`,
                message: `Domain verified via HTML file at ${htmlUrl}.`,
                metadata: { domain, domain_id: domainId, method: "html_file" },
              });
              await createAuditEvent(env, {
                workspace_id,
                user_id:     dvcUser?.id ?? null,
                event_type:  "domain_verified",
                entity_type: "domain",
                entity_id:   domainId,
                description: `${domain} ownership verified via HTML file`,
                metadata:    { domain, domain_id: domainId, method: "html_file" },
              });
            }
          } catch { /* non-fatal */ }
          return json({
            success: true,
            domain,
            verification_status: "verified",
            verification_method: "html_file",
            message: `HTML verification file found at ${htmlUrl}.`,
          });
        }

        // ── Both failed ───────────────────────────────────────────────────
        await env.cybermeters_db
          .prepare(`UPDATE domains SET verification_status = 'failed' WHERE id = ?`)
          .bind(domainId)
          .run();

        return json({
          success: false,
          domain,
          verification_status: "failed",
          token,
          checks: {
            dns_txt: {
              checked: true,
              host:    `_cybermeters.${domain}`,
              expected: expectedTxtValue,
              result: dnsVerified ? "found" : "not_found",
              error:  dnsError || null,
            },
            html_file: {
              checked: true,
              url:    htmlUrl,
              result: htmlVerified ? "found" : "not_found",
              error:  htmlError || null,
            },
          },
          message: "Verification failed. Ensure the DNS TXT record or HTML file is in place and try again.",
        }, 200);
      } catch (e) {
        return json({ error: e.message }, 500);
      }
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

      // RBAC: all workspace sub-routes require membership or owner
      const wsUser = await requireAuth(request, env);
      if (!wsUser) return json({ error: "Unauthorized" }, 401);
      const wsAccess = await requireWorkspaceRole(wsUser, workspaceId, "workspace:read", env);
      if (!wsAccess) return json({ error: "Forbidden" }, 403);

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
        const delAccess = await requireWorkspaceRole(wsUser, workspaceId, "domain:remove", env);
        if (!delAccess) return json({ error: "Forbidden — admin role required to remove domains" }, 403);
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
                 d.id                        AS domain_id,
                 d.domain,
                 d.verification_status,
                 d.verification_method,
                 d.verification_token,
                 d.verified_at,
                 d.verification_initiated_at,
                 s.id                        AS last_scan_id,
                 s.score                     AS latest_score,
                 s.status                    AS latest_status,
                 s.created_at               AS last_scanned_at
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
        // RBAC: admin or above required to add domains
        // wsUser is already authenticated by the wsMatch guard above
        const addDomAccess = await requireWorkspaceRole(wsUser, workspaceId, "domain:add", env);
        if (!addDomAccess) return json({ error: "Forbidden — admin role required to add domains" }, 403);
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
          // Entitlement: domain-per-workspace limit
          const domUsage  = await getEntitlementUsage(wsUser, env, workspaceId);
          const domLimits = getPlanLimits(wsUser.plan);
          if (domUsage.domains_in_workspace >= domLimits.domains_per_workspace) {
            return json({
              error: `Domain limit reached. Your ${wsUser.plan || "free"} plan allows ${domLimits.domains_per_workspace} domain${domLimits.domains_per_workspace === 1 ? "" : "s"} per workspace. Upgrade your plan to add more.`,
              code:  "LIMIT_DOMAINS",
              limit: domLimits.domains_per_workspace,
              usage: domUsage.domains_in_workspace,
            }, 403);
          }

          let domainRow = await env.cybermeters_db
            .prepare(`SELECT id, domain FROM domains WHERE domain = ? LIMIT 1`)
            .bind(raw)
            .first();

          if (!domainRow) {
            const newId = createId("domain");
            await env.cybermeters_db
              .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
              .bind(newId, wsUser.id, raw)
              .run();
            domainRow = { id: newId, domain: raw };
          }

          await env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)`
            )
            .bind(workspaceId, domainRow.id)
            .run();

          // Audit: domain added
          await createAuditEvent(env, {
            workspace_id: workspaceId,
            user_id:      wsUser?.id ?? null,
            event_type:   "domain_added",
            entity_type:  "domain",
            entity_id:    domainRow.id,
            description:  `Domain ${domainRow.domain} added to workspace`,
            metadata:     { domain: domainRow.domain, domain_id: domainRow.id },
          });

          return json(
            { domain: { domain_id: domainRow.id, domain: domainRow.domain, workspace_id: workspaceId } },
            201
          );
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }
    }

    // ── POST /api/workspaces/:id/reports/generate ────────────────────────────
    // Generates a new executive PDF report and stores it in R2 + workspace_reports.
    // Body: { "report_type": "manual" | "weekly_executive" | "monthly_executive" | "scan_snapshot" }
    //       Optional: { "report_period": "...", "scan_id": "..." }
    const rptGenMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/generate$/);
    if (rptGenMatch && request.method === 'POST') {
      const wsId = rptGenMatch[1];
      // RBAC: admin or above required to generate reports — auth is mandatory
      const rptUser = await requireAuth(request, env);
      if (!rptUser) return json({ error: "Unauthorized" }, 401);
      const rptAccess = await requireWorkspaceRole(rptUser, wsId, "report:generate", env);
      if (!rptAccess) return json({ error: "Forbidden — admin role required to generate reports" }, 403);
      try {
        let body = {};
        try { body = await request.json(); } catch { /* body is optional */ }
        const VALID_TYPES = ['manual', 'scan_snapshot', 'weekly_executive', 'monthly_executive'];
        const report_type = VALID_TYPES.includes(body.report_type) ? body.report_type : 'manual';
        const row = await generateWorkspaceExecutiveReport(wsId, env, {
          report_type,
          report_period: body.report_period ?? null,
          scan_id:       body.scan_id       ?? null,
        });
        return json({ report: row }, 201);
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    // ── GET /api/workspaces/:id/reports ──────────────────────────────────────
    // List archived reports for a workspace.
    // Query params: ?report_type=  ?status=
    const rptListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports$/);
    if (rptListMatch && request.method === 'GET') {
      const wsId         = rptListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      const typeFilter   = url.searchParams.get('report_type');
      const statusFilter = url.searchParams.get('status');
      try {
        let sql    = `SELECT id, workspace_id, report_type, report_period, report_key,
                             status, generated_at, created_at, metadata_json
                      FROM workspace_reports WHERE workspace_id = ?`;
        const params = [wsId];
        if (typeFilter)   { sql += ' AND report_type = ?'; params.push(typeFilter); }
        if (statusFilter) { sql += ' AND status = ?';      params.push(statusFilter); }
        sql += ' ORDER BY created_at DESC LIMIT 100';
        const { results } = await env.cybermeters_db.prepare(sql).bind(...params).all();
        return json({ reports: results ?? [] });
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    // ── GET /api/workspaces/:id/reports/:reportId/download ────────────────────
    // Stream the PDF from R2.  Must be tested before the bare /:reportId route.
    const rptDownloadMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/([^/]+)\/download$/);
    if (rptDownloadMatch && request.method === 'GET') {
      const wsId     = rptDownloadMatch[1];
      const reportId = rptDownloadMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const row = await env.cybermeters_db.prepare(
          `SELECT report_key, report_type, report_period, status
           FROM workspace_reports WHERE id = ? AND workspace_id = ?`
        ).bind(reportId, wsId).first();
        if (!row)                       return json({ error: 'Report not found' }, 404);
        if (row.status !== 'completed') return json({ error: `Report not ready: ${row.status}` }, 409);

        const obj = await env.cybermeters_reports.get(row.report_key);
        if (!obj) return json({ error: 'Report file missing from storage' }, 404);

        const slug     = `${row.report_type}-${row.report_period ?? reportId}`;
        const filename = `cybermeters-report-${slug}.pdf`;
        return new Response(obj.body, {
          status: 200,
          headers: {
            ...corsHeaders,
            'Content-Type':        'application/pdf',
            'Content-Disposition': `attachment; filename="${filename}"`,
          },
        });
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    // ── GET /api/workspaces/:id/reports/:reportId ─────────────────────────────
    // Fetch metadata for a single report.
    const rptGetMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/reports\/([^/]+)$/);
    if (rptGetMatch && request.method === 'GET') {
      const wsId     = rptGetMatch[1];
      const reportId = rptGetMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const row = await env.cybermeters_db.prepare(
          `SELECT id, workspace_id, report_type, report_period, report_key,
                  status, generated_at, created_at, metadata_json
           FROM workspace_reports WHERE id = ? AND workspace_id = ?`
        ).bind(reportId, wsId).first();
        if (!row) return json({ error: 'Report not found' }, 404);
        return json({ report: row });
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    // ── GET /api/workspaces/:id/scheduled-reports ────────────────────────────
    // List all scheduled report configs for a workspace.
    const srListMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scheduled-reports$/);
    if (srListMatch && request.method === 'GET') {
      const wsId = srListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const { results } = await env.cybermeters_db
          .prepare(
            `SELECT id, workspace_id, report_type, frequency, enabled, last_run_at, next_run_at, created_at
             FROM scheduled_reports
             WHERE workspace_id = ?
             ORDER BY created_at DESC`
          )
          .bind(wsId)
          .all();
        return json({ scheduled_reports: results ?? [] });
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    // ── POST /api/workspaces/:id/scheduled-reports ────────────────────────────
    // Create a new scheduled report. Body: { report_type, frequency }
    // Frequencies: weekly | monthly | quarterly
    if (srListMatch && request.method === 'POST') {
      const wsId = srListMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
      try {
        let body = {};
        try { body = await request.json(); } catch { /* optional */ }

        const VALID_TYPES = ['weekly_executive', 'monthly_executive', 'quarterly_executive', 'manual'];
        const VALID_FREQS = ['weekly', 'monthly', 'quarterly'];
        const report_type = VALID_TYPES.includes(body.report_type) ? body.report_type : 'monthly_executive';
        const frequency   = VALID_FREQS.includes(body.frequency)   ? body.frequency   : 'monthly';

        // Prevent duplicate active schedules for same type+frequency
        const existing = await env.cybermeters_db
          .prepare(
            `SELECT id FROM scheduled_reports
             WHERE workspace_id = ? AND report_type = ? AND frequency = ? AND enabled = 1 LIMIT 1`
          )
          .bind(wsId, report_type, frequency)
          .first();
        if (existing) return json({ error: "A schedule for this report type and frequency already exists" }, 409);

        // Entitlement: scheduled report limit per workspace
        const srUsage  = await getEntitlementUsage(user, env, wsId);
        const srLimits = getPlanLimits(user.plan);
        if (srUsage.scheduled_reports_in_workspace >= srLimits.scheduled_reports_per_workspace) {
          return json({
            error: `Scheduled report limit reached. Your ${user.plan || "free"} plan allows ${srLimits.scheduled_reports_per_workspace} scheduled report${srLimits.scheduled_reports_per_workspace === 1 ? "" : "s"} per workspace. Upgrade your plan to add more.`,
            code:  "LIMIT_SCHEDULED_REPORTS",
            limit: srLimits.scheduled_reports_per_workspace,
            usage: srUsage.scheduled_reports_in_workspace,
          }, 403);
        }

        const srId      = createId("sr");
        const nextRunAt = computeScheduledReportNextRunAt(frequency);
        const now       = new Date().toISOString();

        await env.cybermeters_db
          .prepare(
            `INSERT INTO scheduled_reports (id, workspace_id, report_type, frequency, enabled, next_run_at, created_at)
             VALUES (?, ?, ?, ?, 1, ?, ?)`
          )
          .bind(srId, wsId, report_type, frequency, nextRunAt, now)
          .run();

        // Audit
        try {
          await createAuditEvent(env, {
            workspace_id: wsId,
            user_id:      user.id,
            event_type:   "scheduled_report_created",
            entity_type:  "scheduled_report",
            entity_id:    srId,
            description:  `Scheduled report created: ${report_type} (${frequency})`,
            metadata:     { scheduled_report_id: srId, report_type, frequency },
          });
        } catch { /* non-fatal */ }

        return json({
          scheduled_report: { id: srId, workspace_id: wsId, report_type, frequency, enabled: 1, next_run_at: nextRunAt, created_at: now }
        }, 201);
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    // ── DELETE /api/workspaces/:id/scheduled-reports/:srId ───────────────────
    const srDeleteMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scheduled-reports\/([^/]+)$/);
    if (srDeleteMatch && request.method === 'DELETE') {
      const wsId = srDeleteMatch[1];
      const srId = srDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
      try {
        const row = await env.cybermeters_db
          .prepare("SELECT id FROM scheduled_reports WHERE id = ? AND workspace_id = ? LIMIT 1")
          .bind(srId, wsId)
          .first();
        if (!row) return json({ error: "Schedule not found" }, 404);

        await env.cybermeters_db
          .prepare("DELETE FROM scheduled_reports WHERE id = ?")
          .bind(srId)
          .run();

        try {
          await createAuditEvent(env, {
            workspace_id: wsId,
            user_id:      user.id,
            event_type:   "scheduled_report_deleted",
            entity_type:  "scheduled_report",
            entity_id:    srId,
            description:  "Scheduled report deleted",
            metadata:     { scheduled_report_id: srId },
          });
        } catch { /* non-fatal */ }

        return json({ deleted: true });
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    // ── PATCH /api/workspaces/:id/scheduled-reports/:srId ────────────────────
    // Toggle enabled. Body: { enabled: true|false }
    if (srDeleteMatch && request.method === 'PATCH') {
      const wsId = srDeleteMatch[1];
      const srId = srDeleteMatch[2];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "schedule:manage", env);
      if (!access) return json({ error: "Forbidden — admin role required to manage schedules" }, 403);
      try {
        let body = {};
        try { body = await request.json(); } catch { /* optional */ }
        const enabled = body.enabled === false ? 0 : 1;
        await env.cybermeters_db
          .prepare("UPDATE scheduled_reports SET enabled = ? WHERE id = ? AND workspace_id = ?")
          .bind(enabled, srId, wsId)
          .run();
        return json({ updated: true, enabled: enabled === 1 });
      } catch (err) {
        return json({ error: String(err?.message ?? err) }, 500);
      }
    }

    return json({ error: "Not found" }, 404);
  },

  // ── Cron Handler ──────────────────────────────────────────────────────
  async scheduled(event, env, ctx) {
    const now = new Date().toISOString();

    // ── Scheduled scans ────────────────────────────────────────────────────
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
    }

    for (const schedule of (result?.results || [])) {
      // Each schedule runs independently so one failure cannot abort others
      ctx.waitUntil(triggerScheduledScan(schedule, env));
    }

    // ── Scheduled executive reports ────────────────────────────────────────
    // Weekly on Mondays, monthly on the 1st of the month.
    // generateScheduledReports is a no-op on all other days.
    ctx.waitUntil(generateScheduledReports(now, env));

    // ── User-configured scheduled reports ─────────────────────────────────
    // Runs every tick; processScheduledReports checks next_run_at internally.
    ctx.waitUntil(processScheduledReports(now, env));
  },
};
