// DANE / TLSA (S3-C, 22 Oct 2026): whether the domain's mail servers and
// website publish TLSA records that sending servers and clients can actually
// rely on. Passive DNS only, every scan, no consent: one DNSSEC-OK TLSA
// question per endpoint to the same resolver the DNS module uses.
//
// A TLSA record does nothing unless its answer validates under DNSSEC
// (RFC 7672 section 2.2; RFC 6698 section 4): the resolver's AD flag is the
// validation evidence. For SMTP only usages DANE-TA(2) and DANE-EE(3) are
// usable; PKIX-TA(0) and PKIX-EE(1) are ignored by senders (RFC 7672 3.1.3).
//
// Not claimed: that the published TLSA matches the certificate the server
// presents (that needs the live certificate and is a later increment), or
// anything about a domain whose zone is not signed: with no DNSSEC, DANE is
// not assessable, never "missing".
import { dnsQueryDnssec } from "./dns.js";
import { mailMxPlan } from "./mail-transport.js";

export const DANE_VERSION = "dane-tlsa-v1";
const TLSA_TYPE = 52;

/** Pure: TLSA rdata "3 1 1 ( ABCD … )" -> {usage, selector, matching_type}. */
export function parseTlsaRecord(data) {
  const parts = String(data || "").replace(/[()]/g, " ").trim().split(/\s+/);
  const [usage, selector, matchingType] = parts.slice(0, 3).map(Number);
  if (![usage, selector, matchingType].every((n) => Number.isInteger(n) && n >= 0 && n <= 255)) return null;
  return { usage, selector, matching_type: matchingType };
}

/**
 * Pure: one DNSSEC-OK TLSA answer -> the endpoint's DANE state.
 * service "smtp" applies the RFC 7672 usage rule; "https" accepts any usage.
 */
export function classifyTlsaAnswer(answer, { service }) {
  if (!answer || typeof answer !== "object" || ![0, 3].includes(answer.Status) || answer.TC === true) {
    return { state: "unavailable", reason: "tlsa_lookup_failed", records: [], dnssec_validated: null };
  }
  const validated = answer.AD === true;
  const records = (Array.isArray(answer.Answer) ? answer.Answer : [])
    .filter((row) => row?.type === TLSA_TYPE).map((row) => parseTlsaRecord(row.data)).filter(Boolean);
  if (!records.length) {
    return validated
      ? { state: "not_published", reason: null, records, dnssec_validated: true }
      : { state: "not_assessable", reason: "dnssec_not_validated", records, dnssec_validated: false };
  }
  if (!validated) return { state: "not_validated", reason: "tlsa_without_dnssec", records, dnssec_validated: false };
  const usable = service === "smtp" ? records.filter((row) => row.usage === 2 || row.usage === 3) : records;
  return usable.length
    ? { state: "active", reason: null, records, dnssec_validated: true }
    : { state: "unusable", reason: "pkix_usage_only", records, dnssec_validated: true };
}

export async function runDaneModule(domain, dnsModule, {
  accounting = null, lookup = (name) => dnsQueryDnssec(name, "TLSA", { accounting }), now = Date.now,
} = {}) {
  const endpoints = [
    ...mailMxPlan(dnsModule).map((mx) => ({ service: "smtp", host: mx.host, port: 25 })),
    { service: "https", host: String(domain || "").toLowerCase(), port: 443 },
  ];
  const results = await Promise.all(endpoints.map(async (endpoint) => {
    let answer = null;
    try { answer = await lookup(`_${endpoint.port}._tcp.${endpoint.host}`); } catch { answer = null; }
    return { ...endpoint, ...classifyTlsaAnswer(answer, endpoint) };
  }));
  const failed = results.filter((row) => row.state === "unavailable").length;
  return {
    source: "dane", version: DANE_VERSION,
    mail: results.filter((row) => row.service === "smtp"),
    web: results.find((row) => row.service === "https") || null,
    incomplete: failed > 0, incomplete_reason: failed > 0 ? "tlsa_lookup_failed" : null,
    error: null, observed_at: new Date(now()).toISOString(),
  };
}
