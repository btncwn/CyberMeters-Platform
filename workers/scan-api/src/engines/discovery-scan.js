// ── Third-party + SaaS exposure discovery module ──
// Vendor-relationship categorisation (third-party asset discovery) and CNAME-based SaaS
// exposure detection. Extracted verbatim from index.js (monolith decomposition, Phase 1c).
// SAAS_EXPOSURE_SIGS + collectAllCnames are module-internal.
import { detectVendorsFromModules } from "./vendor-signatures.js";

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
export function remapToThirdPartyCategory(vendorName, existingCategory) {
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
export function runThirdPartyDiscoveryModule(modules) {
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

// Reference metadata only. These catalogue constants describe public service
// portals; they are not evidence that a customer hostname was observed. The
// exported closed list is used solely by the bounded mutable-row compatibility
// correction in shadow-it-inventory.js. Exact equality is mandatory there.
export const SAAS_EXPOSURE_CATALOGUE_URLS = Object.freeze([
  ...new Set(SAAS_EXPOSURE_SIGS.flatMap((sig) => [sig.portal_url, sig.admin_url]).filter(Boolean)),
]);

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
 *       admin_url, tenant_hint, tenant_url, observed_tenant_url,
 *       attack_surface, evidence, confidence}],
 *     source: "saas_exposure_analysis", error: null }
 */
export function runSaasExposureModule(modules) {
  try {
    const detectedVendors = modules?.vendor_risk?.vendors || [];
    if (detectedVendors.length === 0) {
      return { detected: false, dependency_detected: false, total: 0, observed_total: 0, exposures: [], dependencies: [], source: "saas_exposure_analysis", error: null };
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

      // Only a tenant-specific URL derived from a customer CNAME is an observed
      // hostname. HubSpot/Marketo and the default branch reuse the catalogue
      // portal URL, so equality with sig.portal_url is deliberately excluded.
      const observed_tenant_url = tenant_hint && tenant_url && tenant_url !== sig.portal_url
        ? tenant_url
        : null;

      exposures.push({
        name:           sig.name,
        category:       sig.category,
        exposure_type:  sig.exposure_type,
        risk_level:     sig.risk_level,
        dependency_criticality: sig.risk_level,
        classification: "provider_dependency",
        finding_type:   "observation",
        score_impact:   0,
        customer_exposure_confirmed: false,
        portal_url:     tenant_url || sig.portal_url,
        admin_url:      sig.admin_url || null,
        tenant_hint:    tenant_hint,
        tenant_url:     tenant_url,
        observed_tenant_url,
        attack_surface: "Third-party service dependency observed; no vulnerable configuration or customer data exposure was confirmed.",
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
      detected: false,
      dependency_detected: exposures.length > 0,
      total:    0,
      observed_total: exposures.length,
      exposures,
      dependencies: exposures,
      source:   "saas_exposure_analysis",
      error:    null,
    };
  } catch (err) {
    return {
      detected:  false,
      dependency_detected: false,
      total:     0,
      observed_total: 0,
      exposures: [],
      dependencies: [],
      source:    "saas_exposure_analysis",
      error:     err?.message ?? "SaaS exposure module failed",
    };
  }
}
