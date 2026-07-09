// ── WHOIS / RDAP scan module ──
// Module 6 scan phase: registered-domain (eTLD+1) extraction, RDAP URL resolution, and
// RDAP registration lookup (authoritative TLD registries → rdap.org fallback). Extracted
// verbatim from index.js (monolith decomposition, Phase 1c). getRegisteredDomain and
// getRdapUrls are module-internal.
import { RDAP_UA, safeFetch } from "../lib/http.js";

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


export async function runWhoisModule(domain) {
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
