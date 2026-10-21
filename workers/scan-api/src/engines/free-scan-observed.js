// What the public Free Cyber MOT checks DID observe, per domain card (19 Oct 2026).
//
// The preview used to show only problems, so a well-configured domain got
// "0 findings" and an empty card everywhere. These statements report the
// records and settings the completed checks actually saw, in the words of the
// record ("DMARC policy p=reject observed"). They are evidence, never a verdict:
// no statement says secure, protected or healthy, and none is made from a
// module or signal that did not complete. The backend owns them; the page only
// renders the text it is given.

import { FREE_SCAN_MODULE_STATES } from "./free-scan-evidence.js";

const USABLE = new Set([FREE_SCAN_MODULE_STATES.COMPLETED, FREE_SCAN_MODULE_STATES.PARTIAL]);
const MAX_PER_DOMAIN = 6;

function statement(id, text, module) {
  return { id, text, module };
}

function headerValue(headers, name) {
  const value = headers?.values?.[name];
  return typeof value === "string" ? value.trim() : null;
}

function headerValid(headers, name) {
  return headers?.header_strength?.[name]?.status === "valid";
}

function emailStatements(email) {
  const out = [];
  const dmarcState = email?.dmarc_state || {};
  const dmarc = email?.dmarc_detail || {};
  const policy = String(dmarcState.policy || dmarc.policy || "").toLowerCase();
  if (dmarcState.evidence_status === "observed" && dmarcState.record_validity === "valid"
      && (policy === "reject" || policy === "quarantine")) {
    const pct = Number(dmarc.pct ?? dmarc.percentage ?? dmarcState.pct ?? 100);
    const sp = String(dmarc.subdomain_policy || "").toLowerCase();
    const parts = [`DMARC policy p=${policy} observed`];
    if (sp === "reject" || sp === "quarantine") parts.push(`with sp=${sp} for subdomains`);
    if (Number.isFinite(pct) && pct < 100) parts.push(`with a legacy pct=${pct} tag (removed by RFC 9989)`);
    out.push(statement("dmarc_enforcing_policy", parts.join(", "), "email_security"));
    if (dmarc.has_reporting === true) {
      out.push(statement("dmarc_aggregate_reporting", "DMARC aggregate reports requested (rua)", "email_security"));
    }
  }
  const spf = email?.spf_detail || {};
  const all = String(spf.all_mechanism || "");
  if (email?.spf_evidence_status === "observed" && spf.valid === true && spf.record_count === 1
      && (all === "-all" || all === "~all")) {
    out.push(statement(
      "spf_single_record",
      all === "-all"
        ? "SPF record observed, ending in -all (unlisted senders fail)"
        : "SPF record observed, ending in ~all (unlisted senders soft-fail)",
      "email_security",
    ));
  }
  const dkim = email?.dkim || {};
  if (email?.dkim_evidence_status === "observed" && dkim.present === true) {
    const selectors = [...new Set([...(dkim.selectors_found || []), dkim.selector].filter(Boolean))];
    const named = selectors.slice(0, 3).map((s) => `"${s}"`).join(", ");
    out.push(statement(
      "dkim_key_observed",
      selectors.length > 1 ? `DKIM keys observed at selectors ${named}` : `DKIM key observed at selector ${named}`,
      "email_security",
    ));
  }
  return out;
}

function httpsStatements(ssl) {
  const out = [];
  if (ssl?.https_available === true) {
    out.push(statement("https_answered", "Site answered over HTTPS", "ssl"));
  }
  if (ssl?.http_redirects_to_https === true) {
    out.push(statement("http_redirects_to_https", "Plain HTTP redirects to HTTPS", "ssl"));
  }
  return out;
}

function headerStatements(headers) {
  if (headers?.headers_assessed !== true) return [];
  const out = [];
  const hsts = headerValue(headers, "strict-transport-security");
  if (hsts && headerValid(headers, "strict-transport-security")) {
    const maxAge = Number((hsts.match(/max-age\s*=\s*(\d+)/i) || [])[1]);
    const flags = [
      /includesubdomains/i.test(hsts) ? "includeSubDomains" : null,
      /(^|;)\s*preload\b/i.test(hsts) ? "preload" : null,
    ].filter(Boolean);
    const days = Number.isFinite(maxAge) ? Math.floor(maxAge / 86_400) : null;
    out.push(statement(
      "hsts_set",
      `HSTS set: max-age=${maxAge}${days ? ` (${days} days)` : ""}${flags.length ? `, ${flags.join(", ")}` : ""}`,
      "headers",
    ));
  }
  const csp = headers?.header_strength?.["content-security-policy"];
  if (headerValue(headers, "content-security-policy") && csp?.parsed === true && csp.actionable_weakness === false) {
    out.push(statement(
      "csp_no_unsafe_script",
      csp.style_only_weakness
        ? "Content-Security-Policy set with no unsafe script source (inline styles allowed)"
        : "Content-Security-Policy set with no unsafe script source",
      "headers",
    ));
  }
  const xfo = headerValue(headers, "x-frame-options");
  if (xfo && headerValid(headers, "x-frame-options")) {
    out.push(statement("framing_restricted", `Framing restricted (X-Frame-Options: ${xfo.toUpperCase()})`, "headers"));
  }
  if (headerValid(headers, "x-content-type-options")) {
    out.push(statement("nosniff_set", "MIME sniffing disabled (X-Content-Type-Options: nosniff)", "headers"));
  }
  const referrer = headerValue(headers, "referrer-policy");
  if (referrer && headerValid(headers, "referrer-policy")) {
    out.push(statement("referrer_policy_set", `Referrer-Policy set (${referrer})`, "headers"));
  }
  return out;
}

function dnsStatements(dns) {
  if (dns?.resolution_assessed !== true) return [];
  const out = [];
  if (dns.resolves === true) out.push(statement("dns_resolves", "Domain resolves in public DNS", "dns"));
  if (dns.has_mx === true) out.push(statement("mx_published", "Mail servers (MX) published", "dns"));
  const dnssec = dns.dnssec || {};
  if (dnssec.enabled === true && dnssec.ds?.present === true && dnssec.dnskey?.present === true) {
    out.push(statement("dnssec_signed", "DNSSEC signing observed (DS and DNSKEY records)", "dns"));
  }
  return out;
}

/**
 * The positive evidence for each card, keyed by domain_key. A module that did
 * not complete (or partly complete) contributes nothing; nor does a signal whose
 * own lookup was not observed.
 */
export function buildFreeScanObserved(modules, evidenceByModule) {
  const usable = (module) => USABLE.has(evidenceByModule.get(module));
  const ssl = usable("ssl") ? modules.ssl : null;
  const headers = usable("headers") ? modules.headers : null;
  const email = usable("email_security") ? modules.email_security : null;
  const dns = usable("dns") ? modules.dns : null;
  const byDomain = {
    email_protection: emailStatements(email),
    website_security: [...httpsStatements(ssl), ...headerStatements(headers)],
    // The preview does not inspect the certificate (see the limitation): a
    // completed HTTPS answer is the only certificate-related fact it has.
    certificates_trust: ssl?.https_available === true
      ? [statement("tls_handshake_completed", "TLS handshake completed: the site answered over HTTPS", "ssl")]
      : [],
    attack_surface: dnsStatements(dns),
  };
  return Object.fromEntries(
    Object.entries(byDomain).map(([key, list]) => [key, list.slice(0, MAX_PER_DOMAIN)]),
  );
}
