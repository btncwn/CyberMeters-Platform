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

// URL/value → bare lowercased hostname (strips scheme/path/port; null if not a hostname).
export function normalizeHostname(value) {
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
