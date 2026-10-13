// ── CyberMeters check pack ───────────────────────────────────────────────────
// What a scan checks, written down and versioned. Every check is something
// CyberMeters observes itself — a DNS answer, an HTTP response, the certificate
// a live endpoint presents — and every new report states the pack version that
// produced it, so a result can always be read against the rules in force when
// it was measured. Older reports keep their own results untouched.
//
// The pack holds the observation side of each check: what is looked at, what
// counts as the condition, what evidence is kept and what cannot be seen. What
// to do about a finding and how its fix is re-measured stay in the canonical
// remediation registry; a check points at its registry entry, never copies it.
//
// No check depends on an outside vulnerability or exploit-likelihood database.
// A software version a server reports is a fact about the response, not a
// confirmed vulnerability: it can be patched without changing, or be false.
import { findingRemediation } from "./remediation-registry.js";
import { EXPOSURE_RULES } from "../../../../shared/exposure/catalog.js";

export const CHECK_PACK_VERSION = "2026.10.13.1";

// Services outside the scanned domain that a scan still talks to. Both speak a
// public protocol about the customer's own domain; neither is a data broker.
export const OUTSIDE_SOURCES = Object.freeze([
  Object.freeze({
    id: "public_dns_resolver",
    what: "DNS questions about the scanned domain are asked over HTTPS to a public resolver; a second and third resolver answer a few apex questions as a cross-check.",
    feeds: "DNS, email protection, discovery, attack surface and the address checks before every web request",
    on_failure: "The answer is unknown for that name; it is never read as the name not existing.",
    required: true,
  }),
  Object.freeze({
    id: "registry_rdap",
    what: "The domain's registration and expiry dates are read from the registry's RDAP service.",
    feeds: "Domain registration and expiry notes only",
    on_failure: "The registration notes are left out of this scan; no other result, the score or the scan's completeness changes.",
    required: false,
  }),
]);

// Things this pack deliberately does not do, so no surface implies them.
export const NOT_IN_CHECK_PACK = Object.freeze([
  Object.freeze({
    id: "vulnerability_database_matching",
    statement: "Reported software versions are not matched against outside vulnerability databases. A version the server reports is shown as a disclosure, never as a confirmed vulnerability.",
  }),
  Object.freeze({
    id: "exploited_vulnerability_data",
    statement: "Outside lists of exploited vulnerabilities and exploit-likelihood scores are not used, shown or counted in the score.",
  }),
  Object.freeze({
    id: "certificate_history",
    statement: "Only certificates live endpoints present during a scan are read; past certificates and certificates for names that were not checked are not discovered.",
  }),
]);

// Checks whose observation rule is stated here. Every other finding a scan can
// raise reads its observation from its registry entry (see checkForFinding).
const CHECKS = Object.freeze([
  ...EXPOSURE_RULES.map((rule) => Object.freeze({
    id: `public_content.${rule.id}`,
    finding_types: [`external_exposure_${rule.id}`],
    observation: rule.evidence.positive,
    evidence: "Safe affected URL, rule version, cleaned structural indicators and observation time. No raw response or secret value is retained.",
    limitation: rule.evidence.uncertain,
    recheck: "Repeat the same rule at the exact original URL. Only a successful comparable response can establish that the condition is no longer observed.",
  })),
  Object.freeze({
    id: "discovery.dns_name",
    finding_types: [],
    observation: "A candidate name is listed when DNS answers for it: an address for either family (A or AAAA), an alias with no address at its end, or an alias whose target no longer exists. Candidates come from the certificate the site serves, the domain's mail, name-server, SPF, DMARC and BIMI records, security and link headers, redirects, SRV records, home-page links, robots.txt, sitemaps and scripts, the customer's own list, a fixed list of common names, a rotating word list, variants of found names and the zone's own NSEC records.",
    evidence: "Where the name was seen, and the A and AAAA outcomes with the addresses and any alias chain, at the time asked.",
    limitation: "A name nothing points to is not found. In a zone that answers every name, guessed names are not listed. Answers come from a public resolver, so names visible only inside a network are not seen. Every scan spends a fixed number of DNS questions.",
    recheck: "The same questions on later scans; a name is only treated as gone after repeated negative answers spread over days.",
  }),
  Object.freeze({
    id: "exposure.admin_interface",
    finding_types: ["asset_exposure_admin_interface", "admin_surface_critical", "admin_surface_high", "admin_surface_medium"],
    observation: "A request over HTTPS (then HTTP) to the host returns a page whose title and content match a known administration sign-in.",
    evidence: "The URL requested, the response status, the signature matched and the time.",
    limitation: "Seen from one place on the internet. No credentials are tried. A service that only answers some networks can look closed from here.",
    recheck: "The same URL is requested again. It counts as closed only when DNS says the name no longer exists, or the URL answers without the sign-in page. A timeout, a refused or blocked connection, or an access-denied answer is not proof it closed.",
  }),
  Object.freeze({
    id: "exposure.sensitive_tool",
    finding_types: ["asset_exposure_sensitive_tool"],
    observation: "A request to the host returns the interface of a known management or monitoring tool.",
    evidence: "The URL requested, the response status, the tool recognised and the time.",
    limitation: "Seen from one place on the internet; no credentials are tried.",
    recheck: "The same URL is requested again, with the same closed rule as an administration sign-in.",
  }),
  Object.freeze({
    id: "exposure.development_environment",
    finding_types: ["asset_exposure_dev_env"],
    observation: "A host whose name marks it as development, staging or test answers on the web.",
    evidence: "The host, the URL requested, the response status and the time.",
    limitation: "The name suggests the purpose; the content is not inspected for sensitive data.",
    recheck: "The same URL is requested again on a later scan.",
  }),
  Object.freeze({
    id: "takeover.unclaimed_alias",
    finding_types: ["subdomain_takeover"],
    observation: "An alias (CNAME) under the domain points at a hosting provider, and the provider answers with its own message for an unclaimed resource.",
    evidence: "The name, the alias target, the provider recognised and the response that matched.",
    limitation: "Only providers with a known unclaimed-resource message are recognised; the resource is never claimed to prove it.",
    recheck: "The alias is resolved and the target requested again on a later scan.",
  }),
  Object.freeze({
    id: "tls.certificate_expired",
    finding_types: ["certificate_expired", "ssl_expired"],
    observation: "The certificate an endpoint of the domain presents in a live TLS handshake (port 443, server name = the domain) has a not-after date before the handshake.",
    evidence: "The address and port, the server name sent, the leaf certificate's fingerprint, its validity dates and the handshake time.",
    limitation: "The domain's own name on port 443, each of its addresses (at most four) separately. Revocation is not checked.",
    recheck: "A new handshake to the same endpoint presents a different leaf that is in date.",
  }),
  Object.freeze({
    id: "tls.certificate_expiring",
    finding_types: ["certificate_expiring_soon", "certificate_expiring_critical", "ssl_certificate_expiring_soon", "ssl_expiring_soon"],
    observation: "The live certificate's not-after date is within 30 days of the handshake (within 14 days is critical).",
    evidence: "The endpoint, the leaf fingerprint, the not-after date and the handshake time.",
    limitation: "The same endpoints as the expiry check.",
    recheck: "A new handshake presents a leaf with a later not-after date.",
  }),
  Object.freeze({
    id: "tls.hostname_mismatch",
    finding_types: ["certificate_hostname_mismatch"],
    observation: "The live certificate does not cover the name that was asked for (TLS server-identity check).",
    evidence: "The endpoint, the server name sent, the names the certificate covers and the leaf fingerprint.",
    limitation: "Checks the domain's own name only.",
    recheck: "A new handshake presents a certificate that covers the name.",
  }),
  Object.freeze({
    id: "tls.untrusted_chain",
    finding_types: ["certificate_untrusted"],
    observation: "The live certificate does not validate against a widely used public trust store (the Mozilla roots bundled with Node.js).",
    evidence: "The endpoint, the leaf fingerprint, the trust store and its fingerprint, and the validation error.",
    limitation: "One trust store; the exact chain the server sent is not recorded.",
    recheck: "A new handshake presents a certificate that validates.",
  }),
  Object.freeze({
    id: "disclosure.software_version",
    finding_types: ["tech_server_version_disclosure", "tech_xpoweredby_version_disclosure"],
    observation: "A response header (Server or X-Powered-By) names a product with a version number.",
    evidence: "The header name and value as received.",
    limitation: "The version is what the server says. It is not matched against vulnerability databases, it can be patched without changing, and it can be false.",
    recheck: "The headers are read again on a later scan.",
  }),
]);

const BY_FINDING_TYPE = new Map(CHECKS.flatMap((check) => check.finding_types.map((type) => [type, check])));
const BY_ID = new Map(CHECKS.map((check) => [check.id, check]));

export function listChecks() {
  return CHECKS.map((check) => ({ ...check, version: CHECK_PACK_VERSION }));
}

export function getCheck(id) {
  const check = BY_ID.get(String(id || ""));
  return check ? { ...check, version: CHECK_PACK_VERSION } : null;
}

/**
 * The check that produced a finding: its stated rule when this pack has one,
 * otherwise the registry entry's own explanation, evidence requirement and
 * limitations. A finding with no rule here and no registry entry is still a
 * check — it says so instead of inventing a rule.
 */
export function checkForFinding(finding) {
  const type = String(finding?.id ?? finding?.finding_type ?? "");
  const canonicalType = type.replace(/(__[a-f0-9]{64})$/, "");
  const stated = BY_FINDING_TYPE.get(canonicalType);
  const remediation = findingRemediation(finding);
  if (stated) {
    return {
      check_id: stated.id,
      version: CHECK_PACK_VERSION,
      remediation_id: remediation?.remediation_id ?? null,
      recheck_method: remediation?.verification_method ?? null,
    };
  }
  return {
    check_id: type ? `finding.${type}` : "finding.unknown",
    version: CHECK_PACK_VERSION,
    remediation_id: remediation?.remediation_id ?? null,
    recheck_method: remediation?.verification_method ?? null,
  };
}

// The full description of a check for a reader, by finding.
export function describeCheckForFinding(finding) {
  const stamp = checkForFinding(finding);
  const stated = BY_ID.get(stamp.check_id);
  if (stated) return { ...stamp, observation: stated.observation, evidence: stated.evidence, limitation: stated.limitation, recheck: stated.recheck };
  const remediation = findingRemediation(finding);
  return {
    ...stamp,
    observation: remediation?.technical_explanation ?? null,
    evidence: remediation?.verification_evidence_requirements ?? null,
    limitation: Array.isArray(remediation?.limitations) && remediation.limitations.length ? remediation.limitations.join(" ") : null,
    recheck: remediation?.verification_method ?? null,
  };
}

// A module this pack no longer runs. It stays in the report, stating why, so
// no reader mistakes its absence for a failure or an outage.
export const NOT_IN_CHECK_PACK_OUTCOME = "not_in_check_pack";

export function moduleNotInCheckPack(source, reason) {
  const statement = NOT_IN_CHECK_PACK.find((item) => item.id === source)?.statement ?? null;
  return {
    executed: false,
    outcome: NOT_IN_CHECK_PACK_OUTCOME,
    reason,
    source,
    check_pack_version: CHECK_PACK_VERSION,
    customer_message: statement,
    findings: [],
  };
}

export function isNotInCheckPack(moduleResult) {
  return moduleResult?.outcome === NOT_IN_CHECK_PACK_OUTCOME;
}

// What a report states about the checks that produced it.
export function checkPackSummary() {
  return {
    version: CHECK_PACK_VERSION,
    stated_checks: CHECKS.map((check) => check.id),
    outside_sources: OUTSIDE_SOURCES.map(({ id, what, required }) => ({ id, what, required })),
    not_in_check_pack: NOT_IN_CHECK_PACK.map(({ id }) => id),
  };
}
