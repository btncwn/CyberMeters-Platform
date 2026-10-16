// ── Vendor signature detection ──
// Curated third-party-vendor signature table + evidence-based detection of vendors from
// scan modules (SPF/CNAME/header signals with confidence). Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). Both symbols are shared across the app.

// ── Vendor Risk Layer ─────────────────────────────────────────────────────────
// Pure computation — reads signals already captured in other modules.
// Zero network I/O.  All data is already in `modules` from Phases 1-6.
//
// Signal sources checked:
//   spf    → SPF record string (include:/redirect: tokens)
//   mx     → MX host values
//   ns     → nameserver host values
//   dkim   → DKIM selector name (every selector found, not only the first)
//   txt    → root TXT records already fetched by the DNS module: SaaS domain
//            verification tokens (google-site-verification=…, MS=ms…, …). No
//            extra DNS query — the records travel on modules.dns.txt_records.
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

export const VENDOR_SIGNATURES = [

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
      { source: "txt",    test: (v) => /^amazonses:/.test(v) },
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
      { source: "txt",    test: (v) => /^ms=ms\d+/.test(v) },
      { source: "csp",    test: (v) => /outlook\.com|office365\.com|microsoft\.com/.test(v) },
    ],
  },
  { name: "Google Workspace", category: "email_identity", risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /_spf\.google\.com/.test(v) },
      { source: "mx",     test: (v) => /aspmx\.l\.google\.com|smtp\.google\.com|googlemail\.com/.test(v) },
      { source: "dkim",   test: (v) => /^google$/.test(v) },
      { source: "txt",    test: (v) => /^google-site-verification=/.test(v) },
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
      { source: "txt",    test: (v) => /^atlassian-domain-verification=|^status-page-domain-verification=/.test(v) },
      { source: "cname",  test: (v) => /atlassian\.com|atlassian\.net/.test(v) },
      { source: "mx",     test: (v) => /atlassian\.com/.test(v) },
    ],
  },
  { name: "HubSpot",        category: "saas",           risk_level: "medium",
    signals: [
      { source: "spf",    test: (v) => /hubspot\.com/.test(v) },
      { source: "txt",    test: (v) => /^hubspot-developer-verification=/.test(v) },
      { source: "cname",  test: (v) => /hubspotpagebuilder\.com|hs-sites\.com|hsforms\.net|hubspot\.net/.test(v) },
      { source: "csp",    test: (v) => /hubspot\.com/.test(v) },
    ],
  },
  { name: "Salesforce",     category: "saas",           risk_level: "medium",
    signals: [
      { source: "spf",    test: (v) => /salesforce\.com/.test(v) },
      { source: "txt",    test: (v) => /^pardot_?\w*=|^pardot\d*_/.test(v) },
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
      { source: "txt",    test: (v) => /^mailgun-verification=/.test(v) },
    ],
  },
  { name: "Brevo",          category: "saas",           risk_level: "low",
    signals: [
      { source: "spf",    test: (v) => /sendinblue\.com|brevo\.com/.test(v) },
      { source: "txt",    test: (v) => /^brevo-code:|^sendinblue-code:/.test(v) },
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
      { source: "txt",    test: (v) => /^stripe-verification=/.test(v) },
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
      { source: "txt",    test: (v) => /^zendesk-verification=/.test(v) },
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
      { source: "txt",    test: (v) => /^shopify-verification=/.test(v) },
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

  // ── SaaS domain-verification tokens (root TXT, already fetched by the DNS module) ──
  // Each token is the service's own published verification string. Observing one
  // is evidence the organisation registered this domain with that service — an
  // observation of a relationship, never a statement about how it is used.
  { name: "Meta Business",       category: "saas",           risk_level: "low",
    signals: [
      { source: "txt",    test: (v) => /^facebook-domain-verification=|^workplace-domain-verification=/.test(v) },
    ],
  },
  { name: "Apple Business",      category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^apple-domain-verification=/.test(v) } ],
  },
  { name: "DocuSign",            category: "saas",           risk_level: "medium",
    signals: [ { source: "txt", test: (v) => /^docusign=/.test(v) } ],
  },
  { name: "Adobe",               category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^adobe-idp-site-verification=|^adobe-sign-verification=/.test(v) } ],
  },
  { name: "Dropbox",             category: "saas",           risk_level: "medium",
    signals: [ { source: "txt", test: (v) => /^dropbox-domain-verify=/.test(v) } ],
  },
  { name: "Zoom",                category: "collaboration",  risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^zoom_verify_|^zoom-domain-verification=/.test(v) } ],
  },
  { name: "Slack",               category: "collaboration",  risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^slack-domain-verification=/.test(v) } ],
  },
  { name: "Miro",                category: "collaboration",  risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^miro-verification=/.test(v) } ],
  },
  { name: "Notion",              category: "collaboration",  risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^notion-domain-verification=/.test(v) } ],
  },
  { name: "Canva",               category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^canva-site-verification=/.test(v) } ],
  },
  { name: "Cisco Webex",         category: "collaboration",  risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^webexdomainverification\.|^cisco-ci-domain-verification=/.test(v) } ],
  },
  { name: "GoTo (LogMeIn)",      category: "saas",           risk_level: "medium",
    signals: [ { source: "txt", test: (v) => /^logmein-verification-code=/.test(v) } ],
  },
  { name: "GlobalSign",          category: "infrastructure", risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^_?globalsign-domain-verification=/.test(v) } ],
  },
  { name: "MongoDB Atlas",       category: "cloud",          risk_level: "medium",
    signals: [ { source: "txt", test: (v) => /^mongodb-site-verification=/.test(v) } ],
  },
  { name: "Twilio",              category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^twilio-domain-verification=/.test(v) } ],
  },
  { name: "Postman",             category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^postman-domain-verification=/.test(v) } ],
  },
  { name: "OpenAI",              category: "saas",           risk_level: "medium",
    signals: [ { source: "txt", test: (v) => /^openai-domain-verification=/.test(v) } ],
  },
  { name: "OneTrust",            category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^onetrust-domain-verification=/.test(v) } ],
  },
  { name: "KnowBe4",             category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^knowbe4-site-verification=/.test(v) } ],
  },
  { name: "Wrike",               category: "collaboration",  risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^wrike-verification=/.test(v) } ],
  },
  { name: "Pinterest Business",  category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^pinterest-site-verification=/.test(v) } ],
  },
  { name: "Yandex",              category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^yandex-verification=/.test(v) } ],
  },
  { name: "Smartsheet",          category: "collaboration",  risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^smartsheet-site-validation=/.test(v) } ],
  },
  { name: "Citrix",              category: "saas",           risk_level: "medium",
    signals: [ { source: "txt", test: (v) => /^citrix-verification-code=/.test(v) } ],
  },
  { name: "1Password",           category: "saas",           risk_level: "medium",
    signals: [ { source: "txt", test: (v) => /^1password-site-verification=/.test(v) } ],
  },
  { name: "Have I Been Pwned",   category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^have-i-been-pwned-verification=/.test(v) } ],
  },
  { name: "Segment",             category: "saas",           risk_level: "low",
    signals: [ { source: "txt", test: (v) => /^segment-site-verification=/.test(v) } ],
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
export function detectVendorsFromModules(modules) {
  try {
    // ── Collect signal strings from existing module data ───────────────────
    const signals = {
      spf:    [],
      mx:     [],
      ns:     [],
      dkim:   [],
      txt:    [],
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
    // The SPF include tree the resolver already walked (include:/redirect= targets,
    // nested): a service authorised through an intermediary's include is still a
    // service the domain sends through. Read, never re-resolved.
    for (const target of (
      modules?.email_security?.spf?.resolved_include_targets ||
      modules?.email_security_intelligence?.spf?.resolved_include_targets || []
    )) {
      if (target) signals.spf.push(String(target).toLowerCase());
    }

    // MX records
    for (const mx of (modules?.dns?.mx_records || [])) {
      if (mx?.value) signals.mx.push(mx.value.toLowerCase());
    }

    // Nameservers
    for (const ns of (modules?.dns?.nameservers || [])) {
      if (ns) signals.ns.push(ns.toLowerCase());
    }

    // DKIM selectors — every selector that answered with a key, plus the primary.
    const dkimModule = modules?.email_security?.dkim || modules?.email_security_intelligence?.dkim || {};
    for (const sel of [...(Array.isArray(dkimModule.selectors_found) ? dkimModule.selectors_found : []), dkimModule.selector]) {
      const value = String(sel || "").toLowerCase();
      if (value && !signals.dkim.includes(value)) signals.dkim.push(value);
    }

    // Root TXT records (already fetched by the DNS module — no additional query):
    // SaaS domain-verification tokens, compared lower-cased.
    for (const rec of (modules?.dns?.txt_records || [])) {
      const value = String(rec?.value ?? rec ?? "").trim().toLowerCase();
      if (value) signals.txt.push(value);
    }

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
