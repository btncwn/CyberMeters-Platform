// ── Hostname / certificate-SAN normalisation ──
// Pure leaf helpers: validate & normalise discovered hostnames against a root domain,
// and parse/normalise certificate SubjectAltName lists. Used by the SSL scan module and
// subdomain discovery. Extracted verbatim from index.js (monolith decomposition, Phase 1c).
import { isValidDomain } from "../lib/util.js";

export function normalizeDiscoveredHostname(value, domain) {
  const hostname = String(value || "").trim().toLowerCase().replace(/\.$/, "");
  const root = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
  if (!hostname || !root || hostname.includes("*")) return null;
  if (!isValidDomain(hostname)) return null;
  return hostname === root || hostname.endsWith(`.${root}`) ? hostname : null;
}

export function normalizeCertificateSanNames(value, domain) {
  return [...new Set(
    parseCertificateSanNames(value)
      .map((name) => normalizeDiscoveredHostname(name, domain))
      .filter(Boolean)
  )];
}

export function parseCertificateSanNames(value) {
  return [...new Set(
    String(value || "")
      .split(/\s+/)
      .map((name) => name.trim().toLowerCase().replace(/\.$/, ""))
      .filter(Boolean)
  )];
}
