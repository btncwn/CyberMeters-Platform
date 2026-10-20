// ── Free SSL/TLS checker (public /tools/ssl-checker) ─────────────────────────
//
// Turns the network-probe free_tool receipt (free-tool-tls-receipt-v1: one TLS
// handshake to port 443 on one pinned public address, certificate and the
// negotiated protocol only) into the public result. Pure: no network. The
// collector call itself (tls-certificate-check.js runFreeToolTlsCheck) lives
// in routes/free-tools.js, after the gate, and is its only allowed importer.
//
// Honesty rules:
//  • The receipt's four limitations are always shown as "not checked": one
//    address and one handshake, the chain is the issuer chain the collector
//    built (not necessarily what the server sends), revocation is not
//    assessed, and older protocols and ciphers are not enumerated.
//  • A busy collector, no address, or a connection that did not complete is
//    "could not check", never a certificate verdict, and is never cached.

export const SSL_TOOL_SCHEMA = "free-tool-ssl.v1";

const DAY_MS = 86_400_000;
const EXPIRY_ATTENTION_DAYS = 14;

const LIMITATION_TEXT = Object.freeze({
  one_pinned_address_one_handshake: {
    label: "Other server addresses",
    reason: "One address was tested with one connection. Other addresses behind the same name can serve a different certificate.",
  },
  runtime_issuer_chain_not_wire_chain: {
    label: "The chain your server sends",
    reason: "The chain shown is the one we built from our trust store, not necessarily the certificates your server sends.",
  },
  revocation_not_assessed: {
    label: "Revocation",
    reason: "Whether the certificate has been revoked was not checked.",
  },
  protocol_and_cipher_enumeration_not_assessed: {
    label: "Older TLS versions and ciphers",
    reason: "Only the version this connection agreed was recorded. The full scan tests which older versions and ciphers the server still accepts.",
  },
});

// Why nothing could be concluded, in plain words, by receipt reason or client error.
const UNAVAILABLE_TEXT = Object.freeze({
  collector_busy: "The certificate checker is busy right now. Please try again in a minute.",
  dns_unavailable: "The name could not be looked up just now.",
  dns_no_address: "The name has no address to connect to.",
  dns_non_public_answer: "The name points at a private or reserved address, which we do not connect to.",
  dns_address_limit: "The name has more addresses than this check handles.",
  deadline_exhausted: "The check ran out of time.",
  tls_timeout: "The server did not finish the secure connection in time.",
  tls_handshake_failed: "The server did not complete a secure connection on port 443.",
  tls_connection_failed: "Nothing answered on port 443.",
  peer_certificate_unavailable: "The server did not present a certificate.",
  certificate_too_large: "The certificate was larger than this check reads.",
  handshake_too_large: "The secure connection was larger than this check reads.",
  certificate_parse_failed: "The certificate could not be read.",
});

// OpenSSL/Node verification codes a small business might see, in plain words.
const TRUST_REASON_TEXT = Object.freeze({
  CERT_HAS_EXPIRED: "The certificate has expired.",
  CERT_NOT_YET_VALID: "The certificate is not valid yet.",
  DEPTH_ZERO_SELF_SIGNED_CERT: "The certificate is self-signed, so browsers do not trust it.",
  SELF_SIGNED_CERT_IN_CHAIN: "The chain ends in a self-signed certificate that browsers do not trust.",
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: "The certificate could not be linked to a trusted authority, often because an intermediate certificate is missing from the server.",
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: "The issuing authority is not one browsers trust, or an intermediate certificate is missing from the server.",
  UNABLE_TO_GET_ISSUER_CERT: "The issuing authority could not be found, often because an intermediate certificate is missing from the server.",
  CERT_REVOKED: "The certificate has been revoked.",
  ERR_TLS_CERT_ALTNAME_INVALID: "The certificate is not for this name.",
});

const NOT_CHECKED_ALWAYS = Object.freeze([
  { label: "Your website's other settings", reason: "Security headers, the HTTP to HTTPS redirect and the rest of the site are checked by the headers checker and the full scan." },
]);

const WHY_IT_MATTERS = "The certificate is what lets a browser show your site as secure. If it expires, does not cover your name, or comes from an authority browsers do not trust, visitors see a full-page warning and many leave. Renewals are easy to forget because they happen once a year or less.";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
// "29 Oct 2026", in UTC: the same day the page shows for the certificate.
function day(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`;
}

function limitationsFrom(receipt) {
  return (Array.isArray(receipt?.limitations) ? receipt.limitations : [])
    .map((code) => LIMITATION_TEXT[code])
    .filter(Boolean);
}

function unavailableResult(base, code, receipt) {
  const why = UNAVAILABLE_TEXT[code] || "The check could not reach the server.";
  const busy = code === "collector_busy";
  return {
    ...base,
    code: code || null,
    verdict: {
      level: "unknown",
      headline: busy ? "Busy right now — try again in a minute" : "Could not check the certificate",
      summary: busy ? why : `${why} Nothing was concluded about this site's certificate.`,
    },
    endpoint: receipt?.endpoint ? { hostname: receipt.endpoint.hostname, address: receipt.endpoint.address, port: 443 } : null,
    certificate: null,
    chain: [],
    checked: [{ label: "Secure connection on port 443", state: "unknown", detail: why }],
    not_checked: [...limitationsFrom(receipt), ...NOT_CHECKED_ALWAYS],
    why_it_matters: WHY_IT_MATTERS,
    next_step: { title: busy ? "Try again in a minute" : "Try again shortly", explanation: busy ? "The checker handles one site at a time." : "If your site normally opens in a browser over https://, try again in a few minutes.", record: null },
  };
}

/**
 * The public result. outcome = { receipt, error } from runFreeToolTlsCheck.
 * Pure: the clock is passed in.
 */
export function buildSslToolResult(domain, { receipt = null, error = null } = {}, { now = Date.now() } = {}) {
  const base = { schema: SSL_TOOL_SCHEMA, tool: "ssl", domain, checked_at: new Date(now).toISOString() };
  if (error || !receipt) return unavailableResult(base, error || "collector_unavailable", null);
  if (receipt.outcome !== "observed") return unavailableResult(base, receipt.reason, receipt);

  const cert = receipt.certificate;
  const trusted = receipt.trust?.result === "valid";
  const matched = receipt.hostname_match === "matched";
  const notAfter = Date.parse(cert.not_after);
  const notBefore = Date.parse(cert.not_before);
  const daysLeft = Math.floor((notAfter - now) / DAY_MS);
  const expired = notAfter <= now;
  const notYet = notBefore > now;
  const trustText = trusted ? null : (TRUST_REASON_TEXT[receipt.trust?.reason] || "Browsers would not trust this certificate.");

  const problems = [];
  if (expired) problems.push("expired");
  else if (notYet) problems.push("not_yet_valid");
  if (!matched) problems.push("name");
  if (!trusted && !expired && !notYet) problems.push("trust");
  const expiringSoon = !expired && !notYet && daysLeft <= EXPIRY_ATTENTION_DAYS;

  // A certificate a browser would refuse is a real outage for visitors; that,
  // and only that, is "at risk". Expiring soon is "needs attention".
  const level = problems.length ? "risk" : expiringSoon ? "attention" : "good";
  const headline = expired ? "The certificate has expired"
    : notYet ? "The certificate is not valid yet"
      : !matched ? `The certificate does not cover ${domain}`
        : !trusted ? "Browsers would not trust this certificate"
          : expiringSoon ? `The certificate expires in ${daysLeft} day${daysLeft === 1 ? "" : "s"}`
            : "The certificate is valid and trusted";
  const summary = problems.length
    ? "Visitors would see a browser warning instead of your site. The next step below says what to change."
    : expiringSoon
      ? "It is valid and trusted today. Renew it now so visitors never see a warning."
      : `It covers ${domain}, is trusted by browsers and is valid for another ${daysLeft} days.`;

  const checked = [
    { label: "Secure connection on port 443", state: "pass", detail: `${receipt.protocol.replace("TLSv", "TLS ")} agreed with ${receipt.endpoint.address}.` },
    { label: "Certificate covers the name", state: matched ? "pass" : "fail", detail: matched ? `Valid for ${domain}.` : `Not valid for ${domain}. It covers ${cert.dns_names.slice(0, 5).join(", ") || cert.subject}${cert.dns_names.length > 5 ? " and others" : ""}.` },
    { label: "Trusted by browsers", state: trusted ? "pass" : "fail", detail: trusted ? `Chains to a trusted authority in ${receipt.trust.trust_store}.` : trustText },
    { label: "Validity dates", state: expired || notYet ? "fail" : expiringSoon ? "warn" : "pass",
      detail: expired ? `Expired on ${day(cert.not_after)}.` : notYet ? `Valid from ${day(cert.not_before)}.` : `Valid until ${day(cert.not_after)}, ${daysLeft} days from now.` },
  ];

  const next = problems.includes("expired") || problems.includes("not_yet_valid") || expiringSoon
    ? { title: "Renew the certificate", explanation: "Renew it with your certificate provider or host, then install it on the server. Many hosts can renew automatically: switch that on if you can." }
    : problems.includes("name")
      ? { title: "Use a certificate that covers this name", explanation: `Ask your host or certificate provider for a certificate that includes ${domain} (and www.${domain} if you use it), then install it.` }
      : problems.includes("trust")
        ? { title: "Install a trusted certificate with its full chain", explanation: "Use a certificate from a public authority and install the intermediate certificates your provider supplies alongside it." }
        : { title: "No change needed", explanation: `Renew before ${day(cert.not_after)}. CyberMeters Certificates & Trust watches expiry and alerts you before it lapses.` };

  return {
    ...base,
    code: null,
    verdict: { level, headline, summary },
    endpoint: { hostname: receipt.endpoint.hostname, address: receipt.endpoint.address, port: 443 },
    protocol: receipt.protocol,
    trust: { result: receipt.trust.result, reason: trustText, trust_store: receipt.trust.trust_store },
    hostname_match: receipt.hostname_match,
    certificate: {
      subject: cert.subject, issuer: cert.issuer, not_before: cert.not_before, not_after: cert.not_after,
      days_left: daysLeft, dns_names: cert.dns_names, sha256: cert.sha256,
    },
    // The issuer chain the collector built, never claimed as the server's own.
    chain: (receipt.chain || []).map((c) => ({ subject: c.subject, issuer: c.issuer, not_after: c.not_after })),
    checked,
    not_checked: [...limitationsFrom(receipt), ...NOT_CHECKED_ALWAYS],
    why_it_matters: WHY_IT_MATTERS,
    next_step: { ...next, record: null },
  };
}
