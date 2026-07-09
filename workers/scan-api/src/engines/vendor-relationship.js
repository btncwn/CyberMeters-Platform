// ── Vendor relationship discovery module ──
// Maps third-party vendor relationships from CSP directives + vendor signatures + a
// re-run of tech detection (pure computation, zero network I/O). Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). parseCspDirectives + VENDOR_RELATIONSHIP_SIGS
// are module-internal.
import { VENDOR_SIGNATURES } from "./vendor-signatures.js";
import { runTechModule } from "./tech-scan.js";

// ── Vendor Relationship Discovery ────────────────────────────────────────────
//
// Phase 7k: Pure computation — zero network I/O.
// Identifies third-party vendor relationships from CSP directive analysis,
// CNAME signals, subdomain patterns, and SaaS hostname matching against the
// already-captured scan module data.
//
// Uses a distinct vendor-risk taxonomy from the existing VENDOR_SIGNATURES:
//   analytics | payments | crm | support | identity | collaboration |
//   cloud | cdn | security | certificate_authority
//
// Confidence scoring:
//   high   — CNAME/MX/SPF DNS-level confirmation
//   medium — CSP directive hostname match (script-src, connect-src, frame-src)
//   low    — generic or single weak signal

/**
 * parseCspDirectives(csp)
 * Splits a CSP string into per-directive hostname arrays.
 * Returns { 'script-src': ['cdn.example.com', ...], 'connect-src': [...], ... }
 * Skips keyword values ('nonce-...', 'unsafe-inline', '*', 'data:', etc.).
 */
function parseCspDirectives(csp) {
  const directives = {};
  if (!csp) return directives;
  for (const part of csp.split(";")) {
    const tokens = part.trim().split(/\s+/);
    if (tokens.length < 2) continue;
    const directive = tokens[0].toLowerCase();
    const hostnames = [];
    for (const v of tokens.slice(1)) {
      if (v.startsWith("'") || v === "*" || v === "data:" || v === "blob:" || v === "https:" || v === "http:") continue;
      try {
        const url = v.includes("://") ? new URL(v) : new URL("https://" + v);
        const host = url.hostname.replace(/^\*\./, "");
        if (host && host.includes(".")) hostnames.push(host.toLowerCase());
      } catch { /* skip malformed */ }
    }
    if (hostnames.length) {
      directives[directive] = (directives[directive] || []).concat(hostnames);
    }
  }
  return directives;
}

// Vendor Relationship Signatures — keyed to the 10-category taxonomy.
// `signals` array: { source, test(hostname):bool }
// source values: 'csp:script-src' | 'csp:connect-src' | 'csp:frame-src' |
//                'csp:img-src' | 'csp:font-src' | 'csp:any' | 'script' |
//                'cname'
const VENDOR_RELATIONSHIP_SIGS = [

  // ── Analytics ──────────────────────────────────────────────────────────────
  { name: "Google Analytics",       category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /google-analytics\.com|googletagmanager\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /google-analytics\.com|analytics\.google\.com/.test(h) },
      { source: "csp:img-src",     test: (h) => /google-analytics\.com/.test(h) },
      { source: "script",          test: (h) => /google-analytics\.com|googletagmanager\.com/.test(h) },
    ],
  },
  { name: "Google Tag Manager",     category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /googletagmanager\.com/.test(h) },
      { source: "csp:any",         test: (h) => /googletagmanager\.com/.test(h) },
      { source: "script",          test: (h) => /googletagmanager\.com/.test(h) },
    ],
  },
  { name: "Mixpanel",               category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /cdn\.mxpnl\.com|cdn\.mixpanel\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /api\.mixpanel\.com/.test(h) },
      { source: "script",          test: (h) => /cdn\.mxpnl\.com|cdn\.mixpanel\.com/.test(h) },
    ],
  },
  { name: "Segment",                category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /cdn\.segment\.com|cdn\.segment\.io/.test(h) },
      { source: "csp:connect-src", test: (h) => /api\.segment\.io|api\.segment\.com/.test(h) },
      { source: "script",          test: (h) => /cdn\.segment\.com|cdn\.segment\.io/.test(h) },
    ],
  },
  { name: "Amplitude",              category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /cdn\.amplitude\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /api\.amplitude\.com/.test(h) },
      { source: "script",          test: (h) => /cdn\.amplitude\.com/.test(h) },
    ],
  },
  { name: "Hotjar",                 category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /static\.hotjar\.com|script\.hotjar\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /insights\.hotjar\.com|vc\.hotjar\.io/.test(h) },
      { source: "script",          test: (h) => /static\.hotjar\.com|script\.hotjar\.com/.test(h) },
    ],
  },
  { name: "Heap",                   category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /cdn\.heapanalytics\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /heapanalytics\.com/.test(h) },
    ],
  },
  { name: "PostHog",                category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /app\.posthog\.com|eu\.posthog\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /app\.posthog\.com|eu\.posthog\.com/.test(h) },
    ],
  },
  { name: "Plausible",              category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /plausible\.io/.test(h) },
      { source: "csp:connect-src", test: (h) => /plausible\.io/.test(h) },
    ],
  },
  { name: "Microsoft Clarity",      category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /clarity\.ms/.test(h) },
      { source: "csp:connect-src", test: (h) => /clarity\.ms/.test(h) },
    ],
  },
  { name: "Datadog RUM",            category: "analytics",   risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /datadoghq-browser-agent\.com|rum\.browser-intake-datadoghq\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /datadoghq\.com/.test(h) },
    ],
  },

  // ── Payments ───────────────────────────────────────────────────────────────
  { name: "Stripe",                 category: "payments",    risk_level: "medium",
    signals: [
      { source: "csp:script-src",  test: (h) => /js\.stripe\.com/.test(h) },
      { source: "csp:frame-src",   test: (h) => /stripe\.com|hooks\.stripe\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /api\.stripe\.com/.test(h) },
      { source: "script",          test: (h) => /js\.stripe\.com|assets\.stripe\.com/.test(h) },
      { source: "cname",           test: (h) => /stripe\.com/.test(h) },
    ],
  },
  { name: "PayPal",                 category: "payments",    risk_level: "medium",
    signals: [
      { source: "csp:script-src",  test: (h) => /paypal\.com|paypalobjects\.com/.test(h) },
      { source: "csp:frame-src",   test: (h) => /paypal\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /paypal\.com/.test(h) },
      { source: "script",          test: (h) => /paypal\.com|paypalobjects\.com/.test(h) },
    ],
  },
  { name: "Braintree",              category: "payments",    risk_level: "medium",
    signals: [
      { source: "csp:script-src",  test: (h) => /braintreegateway\.com|braintree-api\.com/.test(h) },
      { source: "csp:frame-src",   test: (h) => /braintreegateway\.com/.test(h) },
    ],
  },
  { name: "Square",                 category: "payments",    risk_level: "medium",
    signals: [
      { source: "csp:script-src",  test: (h) => /squareup\.com|squareupsandbox\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /squareup\.com/.test(h) },
    ],
  },
  { name: "Adyen",                  category: "payments",    risk_level: "medium",
    signals: [
      { source: "csp:script-src",  test: (h) => /adyen\.com|checkoutshopper-live\.adyen\.com/.test(h) },
      { source: "csp:frame-src",   test: (h) => /adyen\.com/.test(h) },
    ],
  },
  { name: "Klarna",                 category: "payments",    risk_level: "medium",
    signals: [
      { source: "csp:script-src",  test: (h) => /klarna\.com/.test(h) },
      { source: "csp:frame-src",   test: (h) => /klarna\.com/.test(h) },
    ],
  },
  { name: "Paddle",                 category: "payments",    risk_level: "medium",
    signals: [
      { source: "csp:script-src",  test: (h) => /cdn\.paddle\.com|sandbox-cdn\.paddle\.com/.test(h) },
      { source: "csp:frame-src",   test: (h) => /paddle\.com/.test(h) },
    ],
  },

  // ── CRM ────────────────────────────────────────────────────────────────────
  { name: "Salesforce",             category: "crm",         risk_level: "medium",
    signals: [
      { source: "csp:any",         test: (h) => /salesforce\.com|force\.com/.test(h) },
      { source: "cname",           test: (h) => /salesforce\.com|force\.com/.test(h) },
    ],
  },
  { name: "HubSpot",                category: "crm",         risk_level: "medium",
    signals: [
      { source: "csp:script-src",  test: (h) => /js\.hs-scripts\.com|js\.hsforms\.net|js\.hubspot\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /api\.hubapi\.com|forms\.hubspot\.com/.test(h) },
      { source: "cname",           test: (h) => /hubspotpagebuilder\.com|hs-sites\.com/.test(h) },
    ],
  },
  { name: "Pipedrive",              category: "crm",         risk_level: "low",
    signals: [
      { source: "csp:any",         test: (h) => /pipedrive\.com/.test(h) },
      { source: "cname",           test: (h) => /pipedrive\.com/.test(h) },
    ],
  },
  { name: "Zoho CRM",               category: "crm",         risk_level: "low",
    signals: [
      { source: "csp:any",         test: (h) => /zohocrm\.com|crm\.zoho\.com/.test(h) },
    ],
  },

  // ── Support ────────────────────────────────────────────────────────────────
  { name: "Zendesk",                category: "support",     risk_level: "medium",
    signals: [
      { source: "csp:script-src",  test: (h) => /static\.zdassets\.com|ekr\.zdassets\.com/.test(h) },
      { source: "csp:frame-src",   test: (h) => /zendesk\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /zendesk\.com/.test(h) },
      { source: "cname",           test: (h) => /zendesk\.com/.test(h) },
    ],
  },
  { name: "Intercom",               category: "support",     risk_level: "medium",
    signals: [
      { source: "csp:script-src",  test: (h) => /widget\.intercom\.io|js\.intercomcdn\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /api-iam\.intercom\.io|nexus-websocket-a\.intercom\.io/.test(h) },
      { source: "script",          test: (h) => /widget\.intercom\.io|js\.intercomcdn\.com/.test(h) },
      { source: "cname",           test: (h) => /intercom\.io|intercomassets\.com/.test(h) },
    ],
  },
  { name: "Freshdesk",              category: "support",     risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /widget\.freshworks\.com/.test(h) },
      { source: "cname",           test: (h) => /freshdesk\.com|freshworks\.com/.test(h) },
    ],
  },
  { name: "Crisp",                  category: "support",     risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /client\.crisp\.chat/.test(h) },
      { source: "csp:connect-src", test: (h) => /crisp\.chat/.test(h) },
    ],
  },
  { name: "Drift",                  category: "support",     risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /js\.driftt\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /driftt\.com|drift\.com/.test(h) },
    ],
  },
  { name: "Tawk.to",                category: "support",     risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /embed\.tawk\.to/.test(h) },
      { source: "csp:connect-src", test: (h) => /tawk\.to/.test(h) },
    ],
  },

  // ── Identity ───────────────────────────────────────────────────────────────
  { name: "Okta",                   category: "identity",    risk_level: "high",
    signals: [
      { source: "csp:any",         test: (h) => /okta\.com|oktapreview\.com|okta-emea\.com/.test(h) },
      { source: "cname",           test: (h) => /okta\.com|oktapreview\.com/.test(h) },
    ],
  },
  { name: "Auth0",                  category: "identity",    risk_level: "high",
    signals: [
      { source: "csp:any",         test: (h) => /auth0\.com|us\.auth0\.com|eu\.auth0\.com/.test(h) },
      { source: "cname",           test: (h) => /auth0\.com/.test(h) },
    ],
  },
  { name: "Microsoft Entra ID",     category: "identity",    risk_level: "high",
    signals: [
      { source: "csp:any",         test: (h) => /login\.microsoftonline\.com|login\.live\.com/.test(h) },
      { source: "cname",           test: (h) => /microsoftonline\.com|sts\.windows\.net/.test(h) },
    ],
  },
  { name: "Ping Identity",          category: "identity",    risk_level: "high",
    signals: [
      { source: "csp:any",         test: (h) => /pingone\.com|pingidentity\.com/.test(h) },
      { source: "cname",           test: (h) => /pingone\.com|ping\.com/.test(h) },
    ],
  },
  { name: "OneLogin",               category: "identity",    risk_level: "high",
    signals: [
      { source: "csp:any",         test: (h) => /onelogin\.com/.test(h) },
      { source: "cname",           test: (h) => /onelogin\.com/.test(h) },
    ],
  },

  // ── Collaboration ──────────────────────────────────────────────────────────
  { name: "Atlassian",              category: "collaboration", risk_level: "low",
    signals: [
      { source: "csp:any",         test: (h) => /atlassian\.com|atlassian\.net/.test(h) },
      { source: "cname",           test: (h) => /atlassian\.net|atlassian\.com/.test(h) },
    ],
  },
  { name: "Slack",                  category: "collaboration", risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /slack\.com|slack-edge\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /slack\.com/.test(h) },
    ],
  },
  { name: "Notion",                 category: "collaboration", risk_level: "low",
    signals: [
      { source: "csp:frame-src",   test: (h) => /notion\.so/.test(h) },
      { source: "csp:any",         test: (h) => /notion\.so/.test(h) },
    ],
  },
  { name: "Linear",                 category: "collaboration", risk_level: "low",
    signals: [
      { source: "csp:any",         test: (h) => /linear\.app/.test(h) },
    ],
  },

  // ── CDN ────────────────────────────────────────────────────────────────────
  { name: "jsDelivr",               category: "cdn",         risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /cdn\.jsdelivr\.net/.test(h) },
      { source: "script",          test: (h) => /cdn\.jsdelivr\.net/.test(h) },
    ],
  },
  { name: "unpkg",                  category: "cdn",         risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /unpkg\.com/.test(h) },
      { source: "script",          test: (h) => /unpkg\.com/.test(h) },
    ],
  },
  { name: "cdnjs",                  category: "cdn",         risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /cdnjs\.cloudflare\.com/.test(h) },
      { source: "script",          test: (h) => /cdnjs\.cloudflare\.com/.test(h) },
    ],
  },
  { name: "Cloudflare CDN",         category: "cdn",         risk_level: "low",
    signals: [
      { source: "cname",           test: (h) => /\.cdn\.cloudflare\.net/.test(h) },
    ],
  },

  // ── Cloud ──────────────────────────────────────────────────────────────────
  { name: "AWS S3 / CloudFront",    category: "cloud",       risk_level: "low",
    signals: [
      { source: "csp:any",         test: (h) => /amazonaws\.com|cloudfront\.net/.test(h) },
      { source: "cname",           test: (h) => /amazonaws\.com|cloudfront\.net/.test(h) },
    ],
  },
  { name: "Google Cloud Storage",   category: "cloud",       risk_level: "low",
    signals: [
      { source: "csp:any",         test: (h) => /storage\.googleapis\.com|googleusercontent\.com/.test(h) },
    ],
  },
  { name: "Azure Blob / CDN",       category: "cloud",       risk_level: "low",
    signals: [
      { source: "csp:any",         test: (h) => /azureedge\.net|blob\.core\.windows\.net/.test(h) },
      { source: "cname",           test: (h) => /azureedge\.net/.test(h) },
    ],
  },

  // ── Security ───────────────────────────────────────────────────────────────
  { name: "Sentry",                 category: "security",    risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /browser\.sentry-cdn\.com|js\.sentry\.io/.test(h) },
      { source: "csp:connect-src", test: (h) => /sentry\.io/.test(h) },
    ],
  },
  { name: "Datadog",                category: "security",    risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /datadoghq-browser-agent\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /datadoghq\.com/.test(h) },
    ],
  },
  { name: "New Relic",              category: "security",    risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /js-agent\.newrelic\.com/.test(h) },
      { source: "csp:connect-src", test: (h) => /bam\.nr-data\.net/.test(h) },
    ],
  },
  { name: "Cloudflare Insights",    category: "security",    risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /static\.cloudflareinsights\.com/.test(h) },
    ],
  },
  { name: "reCAPTCHA",              category: "security",    risk_level: "low",
    signals: [
      { source: "csp:script-src",  test: (h) => /www\.google\.com|recaptcha\.net/.test(h) },
      { source: "csp:frame-src",   test: (h) => /recaptcha\.net|www\.google\.com/.test(h) },
    ],
  },
];

/**
 * runVendorRelationshipModule(modules)
 * Phase 7k — pure computation, zero network I/O.
 *
 * Parses CSP header per-directive, extracts hostnames from script-src,
 * connect-src, frame-src, img-src, and font-src; also uses CNAME signals
 * for high-confidence DNS-level matches.
 *
 * Confidence:
 *   high   — CNAME match or ≥2 independent CSP directives
 *   medium — single specific CSP directive match
 *   low    — csp:any (full-string fallback) only
 */
export function runVendorRelationshipModule(modules) {
  try {
    // ── Build signal sets ────────────────────────────────────────────────────
    const rawCsp = (modules?.headers?.values?.["content-security-policy"] || "").toLowerCase();
    const directives = parseCspDirectives(rawCsp);

    // Script hosts from the first HTML body chunk read by runTechModule.
    const scriptHosts = Array.isArray(modules?.technology_detection?.external_scripts)
      ? modules.technology_detection.external_scripts.map((h) => String(h).toLowerCase())
      : [];

    // CNAME targets for DNS-level high-confidence signals
    const cnames = [];
    for (const risk of (modules?.subdomain_takeover?.risks || [])) {
      if (risk?.cname) cnames.push(risk.cname.toLowerCase());
    }
    for (const asset of (modules?.asset_exposure?.assets || [])) {
      if (asset?.cname) cnames.push(asset.cname.toLowerCase());
    }
    for (const item of (modules?.dns_bruteforce?.items || [])) {
      if (item?.cname) cnames.push(item.cname.toLowerCase());
    }

    // ── Signal tester ────────────────────────────────────────────────────────
    function testSignal(signal) {
      if (signal.source.startsWith("csp:")) {
        const directive = signal.source.slice(4);
        if (directive === "any") {
          for (const hosts of Object.values(directives)) {
            if (hosts.some(h => signal.test(h))) return true;
          }
          return false;
        }
        const hosts = directives[directive] || [];
        return hosts.some(h => signal.test(h));
      }
      if (signal.source === "cname") {
        return cnames.some(h => signal.test(h));
      }
      if (signal.source === "script") {
        return scriptHosts.some(h => signal.test(h));
      }
      return false;
    }

    // ── Match signatures ─────────────────────────────────────────────────────
    const vendors = [];

    for (const sig of VENDOR_RELATIONSHIP_SIGS) {
      const matchedSources = [];
      for (const check of sig.signals) {
        if (testSignal(check)) matchedSources.push(check.source);
      }
      if (matchedSources.length === 0) continue;

      // Confidence rules
      const hasCname       = matchedSources.includes("cname");
      const hasScript      = matchedSources.includes("script");
      const specificDirs   = matchedSources.filter(s => s.startsWith("csp:") && s !== "csp:any");
      const hasAnyOnly     = matchedSources.every(s => s === "csp:any");

      let confidence;
      if (hasCname || specificDirs.length >= 2) confidence = "high";
      else if (hasScript || specificDirs.length === 1) confidence = "medium";
      else                                        confidence = "low";

      vendors.push({
        name:           sig.name,
        category:       sig.category,
        risk_level:     sig.risk_level,
        confidence,
        source:         matchedSources[0],
        source_signals: matchedSources,
      });
    }

    const byCategory = {};
    for (const v of vendors) {
      byCategory[v.category] = (byCategory[v.category] || 0) + 1;
    }

    const highConfidenceCount = vendors.filter(v => v.confidence === "high").length;

    return {
      detected:        vendors.length > 0,
      vendors,
      total:           vendors.length,
      high_confidence: highConfidenceCount,
      by_category:     byCategory,
      source:          "csp_relationship_analysis",
      error:           null,
    };
  } catch (err) {
    return {
      detected:        false,
      vendors:         [],
      total:           0,
      high_confidence: 0,
      by_category:     {},
      source:          "csp_relationship_analysis",
      error:           err?.message ?? "Vendor relationship analysis failed",
    };
  }
}
