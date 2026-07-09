// ── Certificate analysis primitives ──
// Certificate issuer/DN parsing, CA-owner + vendor mapping, crypto-metadata extraction,
// self-signed detection, lifecycle intelligence, and CA-concentration analytics. Extracted
// verbatim from index.js (monolith decomposition, Phase 1c). The vendor-pattern table and
// the DN/name-part helpers (normalizeCertificateNamePart, parseCertificateDistinguishedName,
// unknownIfEmpty) are module-internal.

const CERTIFICATE_AUTHORITY_VENDOR_PATTERNS = [
  { vendor_name: "Let's Encrypt",          owner: "ISRG",                  test: (v) => /\bisrg\b|\blet'?s encrypt\b/.test(v) },
  { vendor_name: "DigiCert",               owner: "DigiCert",              test: (v) => /\bdigicert\b|\bsymantec\b|\bgeotrust\b|\bthawte\b|\brapidssl\b/.test(v) },
  { vendor_name: "Sectigo",                test: (v) => /\bsectigo\b|\bcomodo\b|\busertrust\b/.test(v) },
  { vendor_name: "Cloudflare",             test: (v) => /\bcloudflare\b/.test(v) },
  { vendor_name: "Google Trust Services",  test: (v) => /\bgoogle trust services\b|\bgts\b/.test(v) },
  { vendor_name: "GlobalSign",             test: (v) => /\bglobalsign\b/.test(v) },
  { vendor_name: "Amazon Trust Services",  test: (v) => /\bamazon\b|\bamazon trust services\b/.test(v) },
  { vendor_name: "Microsoft",              test: (v) => /\bmicrosoft\b|\bazure tls\b/.test(v) },
  { vendor_name: "Entrust",                test: (v) => /\bentrust\b/.test(v) },
  { vendor_name: "GoDaddy",                test: (v) => /\bgodaddy\b|\bstarfield\b/.test(v) },
  { vendor_name: "ZeroSSL",                test: (v) => /\bzerossl\b/.test(v) },
];

function normalizeCertificateNamePart(value) {
  return typeof value === "string"
    ? value
        .normalize("NFKD")
        .replace(/[\u0300-\u036f]/g, "")
        .toLowerCase()
        .replace(/[^\w\s'.-]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
    : "";
}

function parseCertificateDistinguishedName(rawName) {
  const raw = typeof rawName === "string" ? rawName.trim() : "";
  const out = { common_name: null, organization: null, country: null };
  if (!raw) return out;

  const parts = raw.split(/\s*,\s*/);
  for (const part of parts) {
    const match = part.match(/^([A-Za-z]+)\s*=\s*(.+)$/);
    if (!match) continue;
    const key = match[1].toUpperCase();
    const value = match[2].trim();
    if (key === "CN") out.common_name = value;
    else if (key === "O") out.organization = value;
    else if (key === "C") out.country = value;
  }
  return out;
}

export function normalizeCertificateIssuer(rawIssuer) {
  const raw = typeof rawIssuer === "string" ? rawIssuer.trim() : "";
  if (!raw || raw.toLowerCase() === "unknown") {
    return {
      raw: raw || null,
      normalized_name: "unknown",
      common_name: null,
      organization: null,
      country: null,
    };
  }

  const dn = parseCertificateDistinguishedName(raw);
  const display = dn.organization || dn.common_name || raw;
  return {
    raw,
    normalized_name: normalizeCertificateNamePart(display) || "unknown",
    common_name: dn.common_name,
    organization: dn.organization,
    country: dn.country,
  };
}

export function mapCertificateAuthorityOwner(normalizedIssuer) {
  const normalizedName = typeof normalizedIssuer === "string"
    ? normalizeCertificateNamePart(normalizedIssuer)
    : normalizeCertificateNamePart([
        normalizedIssuer?.normalized_name,
        normalizedIssuer?.organization,
        normalizedIssuer?.common_name,
        normalizedIssuer?.raw,
      ].filter(Boolean).join(" "));

  if (!normalizedName || normalizedName === "unknown") {
    return {
      owner: "unknown",
      ca_family: "unknown",
      confidence: "unknown",
      source: "certificate_issuer",
    };
  }

  for (const pattern of CERTIFICATE_AUTHORITY_VENDOR_PATTERNS) {
    if (!pattern.test(normalizedName)) continue;
    return {
      owner: pattern.owner || pattern.vendor_name,
      ca_family: pattern.vendor_name,
      confidence: "high",
      source: "certificate_issuer",
    };
  }

  return {
    owner: "unknown",
    ca_family: "unknown",
    confidence: "unknown",
    source: "certificate_issuer",
  };
}

function unknownIfEmpty(value) {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value !== "string") return "unknown";
  const trimmed = value.trim();
  return trimmed ? trimmed : "unknown";
}

export function extractCertificateCryptoMetadata(ssl) {
  const source = ssl || {};
  return {
    key_algorithm: unknownIfEmpty(source.cert_key_algorithm ?? source.key_algorithm ?? source.public_key_algorithm),
    key_size_bits: unknownIfEmpty(source.cert_key_size_bits ?? source.key_size_bits ?? source.public_key_size),
    signature_algorithm: unknownIfEmpty(source.cert_signature_algorithm ?? source.signature_algorithm),
  };
}

export function detectSelfSignedCertificate(issuer, subject) {
  const issuerRaw = typeof issuer === "string" ? issuer.trim() : "";
  const subjectRaw = typeof subject === "string" ? subject.trim() : "";
  if (!issuerRaw || !subjectRaw) return "unknown";

  const issuerDn = parseCertificateDistinguishedName(issuerRaw);
  const subjectComparable = normalizeCertificateNamePart(subjectRaw);
  const issuerComparable = normalizeCertificateNamePart(issuerRaw);
  const issuerCnComparable = normalizeCertificateNamePart(issuerDn.common_name || "");

  if (
    issuerComparable &&
    subjectComparable &&
    (issuerComparable === subjectComparable || issuerCnComparable === subjectComparable)
  ) {
    return true;
  }

  return false;
}

export function buildCertificateLifecycleIntelligence(certMod) {
  const rawDays = certMod?.days_until_expiry ?? certMod?.cert_expiry_days ?? null;
  const days = Number.isFinite(rawDays) ? Number(rawDays) : null;

  if (days === null) {
    return {
      days_to_expiry: null,
      expiry_band: "unknown",
      renewal_urgency: "unknown",
    };
  }

  let expiry_band = "healthy";
  let renewal_urgency = "normal";
  if (days < 0) {
    expiry_band = "expired";
    renewal_urgency = "urgent";
  } else if (days < 7) {
    expiry_band = "under_7_days";
    renewal_urgency = "urgent";
  } else if (days < 30) {
    expiry_band = "under_30_days";
    renewal_urgency = "soon";
  } else if (days < 90) {
    expiry_band = "under_90_days";
    renewal_urgency = "monitor";
  }

  return {
    days_to_expiry: days,
    expiry_band,
    renewal_urgency,
  };
}

export function buildCaConcentrationAnalytics(observations, options = {}) {
  const source = options.source || "current_certificate_intelligence";
  const rows = Array.isArray(observations) ? observations : [];
  const normalizedRows = rows
    .map((entry) => {
      if (typeof entry === "string") {
        const issuer = entry.trim();
        return issuer ? { issuer, first_seen: null, last_seen: null } : null;
      }
      const issuer = String(entry?.issuer || "").trim();
      if (!issuer) return null;
      return {
        issuer,
        first_seen: entry?.first_seen || null,
        last_seen: entry?.last_seen || null,
      };
    })
    .filter(Boolean);
  const issuerList = normalizedRows.map((row) => row.issuer);
  const uniqueIssuers = [...new Set(issuerList)];

  if (uniqueIssuers.length === 0) {
    return {
      dependency: "unknown",
      issuers: [],
      issuer_count: 0,
      ca_owner_count: 0,
      dominant_ca_owner: "unknown",
      dominant_ca_share: 0,
      concentration_level: "unknown",
      first_observed: null,
      last_observed: null,
      source,
      observations: ["No certificate issuer was available from certificate intelligence."],
      recommendations: [],
    };
  }

  const ownerCounts = new Map();
  for (const issuer of issuerList) {
    const owner = mapCertificateAuthorityOwner(normalizeCertificateIssuer(issuer)).owner;
    const ownerKey = owner && owner !== "unknown" ? owner : "unknown";
    ownerCounts.set(ownerKey, (ownerCounts.get(ownerKey) || 0) + 1);
  }

  const sortedOwners = [...ownerCounts.entries()].sort((a, b) => b[1] - a[1]);
  const [dominantOwner, dominantCount] = sortedOwners[0] || ["unknown", 0];
  const dominantShare = issuerList.length > 0 ? Number((dominantCount / issuerList.length).toFixed(2)) : 0;
  const caOwnerCount = [...ownerCounts.keys()].filter((o) => o !== "unknown").length;
  const concentrationLevel =
    issuerList.length === 1 || dominantShare >= 0.8 ? "high" :
    dominantShare >= 0.5 ? "medium" : "low";

  const observationMessages = [
    uniqueIssuers.length === 1
      ? `Current certificate data shows a single observed issuer: ${uniqueIssuers[0]}.`
      : `Current certificate data shows ${uniqueIssuers.length} observed issuers.`,
  ];
  if (dominantOwner !== "unknown") {
    observationMessages.push(`${dominantOwner} is the dominant certificate authority owner in observed certificate data.`);
  }

  const firstObservedValues = normalizedRows.map((row) => row.first_seen).filter(Boolean).sort();
  const lastObservedValues = normalizedRows.map((row) => row.last_seen).filter(Boolean).sort();

  const recommendations = concentrationLevel === "high"
    ? ["Track CA dependency as an operational resilience risk and ensure renewal runbooks cover issuer outages or account issues."]
    : [];

  return {
    dependency: concentrationLevel === "high" ? "single_ca_dependency" : "multi_ca_dependency",
    issuers: uniqueIssuers,
    issuer_count: uniqueIssuers.length,
    ca_owner_count: caOwnerCount,
    dominant_ca_owner: dominantOwner,
    dominant_ca_share: dominantShare,
    concentration_level: concentrationLevel,
    first_observed: firstObservedValues[0] || null,
    last_observed: lastObservedValues[lastObservedValues.length - 1] || null,
    source,
    observations: observationMessages,
    recommendations,
  };
}

/**
 * normalizeCertificateAuthorityVendor(issuer)
 *
 * Maps certificate issuer strings to stable vendor inventory rows.
 * Returns null for unknown or empty issuers to avoid polluting vendor risk with
 * intermediate CA names that cannot be confidently mapped to an organisation.
 */
export function normalizeCertificateAuthorityVendor(issuer) {
  const raw = typeof issuer === "string" ? issuer.trim() : "";
  if (!raw || raw.toLowerCase() === "unknown") return null;

  const normalizedIssuer = normalizeCertificateIssuer(raw);
  const normalized = normalizeCertificateNamePart([
    normalizedIssuer.normalized_name,
    normalizedIssuer.organization,
    normalizedIssuer.common_name,
    normalizedIssuer.raw,
  ].filter(Boolean).join(" "));

  for (const pattern of CERTIFICATE_AUTHORITY_VENDOR_PATTERNS) {
    if (!pattern.test(normalized)) continue;
    return {
      vendor_name: pattern.vendor_name,
      vendor_type: "certificate_authority",
      confidence: "high",
      source: "certificate_issuer",
    };
  }

  return null;
}
