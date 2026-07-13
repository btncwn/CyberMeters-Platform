// ── DNS resolution engine ─────────────────────────────────────────────────────
// DoH resolvers (Cloudflare / Google / Quad9) + resolver cross-check.
// Pure module: depends only on global fetch/AbortSignal. Extracted verbatim from
// index.js (monolith decomposition, Phase 1). Behavior-preserving — no logic change.

export async function dnsQuery(name, type) {
  const res = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
    {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(6_000),
    }
  );
  if (!res.ok) throw new Error(`DoH ${res.status} for ${type} ${name}`);
  return res.json();
}

// Single-resolver A lookup with an optional per-scan cache (dnsCacheKey format
// "name|A"). Used by the critical-prefix discovery pass: strict — one resolver,
// A-only, no cross-check — and budget-safe (never throws; returns null on failure).
// The cache guarantees each (name,"A") is resolved at most once per scan.
export async function dnsResolveACached(name, cache = null) {
  const key = `${String(name).toLowerCase()}|A`;
  if (cache && cache.has(key)) return cache.get(key);
  let answer = null;
  try {
    answer = await dnsQuery(name, "A");
  } catch {
    answer = null;
  }
  if (cache) cache.set(key, answer);
  return answer;
}

export async function dnsQueryDnssec(name, type) {
  const res = await fetch(
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}&do=1`,
    {
      headers: { Accept: "application/dns-json" },
      signal: AbortSignal.timeout(6_000),
    }
  );
  if (!res.ok) throw new Error(`DoH DNSSEC ${res.status} for ${type} ${name}`);
  return res.json();
}

export async function dnsQueryGoogle(name, type) {
  const res = await fetch(
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
    { signal: AbortSignal.timeout(6_000) }
  );
  if (!res.ok) throw new Error(`Google DoH ${res.status} for ${type} ${name}`);
  return res.json();
}

export async function dnsQueryQuad9(name, type) {
  // Quad9 DoH — optional third resolver for A/AAAA agreement checks.
  // Never throws: failure returns null so budget-safe.
  try {
    const res = await fetch(
      `https://dns.quad9.net/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`,
      {
        headers: { Accept: "application/dns-json" },
        signal: AbortSignal.timeout(5_000),
      }
    );
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export function dnsAnswerValues(response) {
  return (response?.Answer || [])
    .map((r) => r.data)
    .filter(Boolean)
    .sort();
}

/**
 * computeResolverAgreementScore(resolvers)
 *
 * Given an array of { status, returned_records } resolver objects,
 * returns a 0–100 score:
 *   100 = all available resolvers agree
 *   50  = partial disagreement among available resolvers
 *   0   = all available resolvers disagree
 *   null = fewer than 2 resolvers available (insufficient data)
 */
export function computeResolverAgreementScore(resolvers) {
  const available = resolvers.filter((r) => r.status === "ok");
  if (available.length < 2) return null;
  const reference = available[0].returned_records;
  const agreements = available.filter(
    (r) => r.returned_records.length === reference.length
      && r.returned_records.every((v, i) => v === reference[i])
  ).length;
  return Math.round((agreements / available.length) * 100);
}

export function buildDnsCrossCheck(name, type, primaryResult, googleResult, quad9Result) {
  const primaryRecords = dnsAnswerValues(primaryResult);
  const googleAvailable = googleResult?.status === "fulfilled";
  const quad9Available  = quad9Result != null;
  const googleRecords   = googleAvailable ? dnsAnswerValues(googleResult.value) : [];
  const quad9Records    = quad9Available  ? dnsAnswerValues(quad9Result)         : [];

  const resolvers = [
    { resolver: "cloudflare", status: primaryResult ? "ok" : "unavailable", returned_records: primaryRecords },
    googleAvailable
      ? { resolver: "google",  status: "ok",          returned_records: googleRecords }
      : { resolver: "google",  status: "unavailable", returned_records: [] },
  ];
  if (quad9Result !== undefined) {
    resolvers.push(
      quad9Available
        ? { resolver: "quad9",  status: "ok",          returned_records: quad9Records }
        : { resolver: "quad9",  status: "unavailable", returned_records: [] }
    );
  }

  const agreementScore = computeResolverAgreementScore(resolvers.filter((r) => r.status === "ok").length >= 2 ? resolvers : resolvers.slice(0, 2));
  const googleRec = googleAvailable ? dnsAnswerValues(googleResult.value) : [];
  const sameRecords = googleAvailable
    && primaryRecords.length === googleRec.length
    && primaryRecords.every((v, i) => v === googleRec[i]);

  return {
    query: { name, type },
    primary_resolver: {
      resolver: "cloudflare",
      status: primaryResult ? "ok" : "unavailable",
      returned_records: primaryRecords,
    },
    cloudflare_resolver: {
      resolver: "cloudflare",
      status: primaryResult ? "ok" : "unavailable",
      returned_records: primaryRecords,
    },
    google_resolver: googleAvailable
      ? { resolver: "google", status: "ok", returned_records: googleRecords }
      : { resolver: "google", status: "unavailable", returned_records: [] },
    ...(quad9Result !== undefined ? {
      quad9_resolver: quad9Available
        ? { resolver: "quad9", status: "ok", returned_records: quad9Records }
        : { resolver: "quad9", status: "unavailable", returned_records: [] },
    } : {}),
    authoritative_nameserver: {
      status: "unavailable",
      reason: "Raw authoritative DNS queries are not available from Cloudflare Workers.",
      returned_records: [],
    },
    resolver_agreement_score: agreementScore,
    resolver_disagreement: googleAvailable ? !sameRecords : false,
  };
}
