// ── DNS scan module ──
// External-scan DNS phase: A/AAAA/NS/MX/TXT(SPF+DMARC)/CAA/DNSSEC resolution with
// multi-resolver (Cloudflare/Google/Quad9) cross-checks and operational-resilience
// scoring. Extracted verbatim from index.js (monolith decomposition, Phase 1c) — no
// logic change. Nested helpers (pick/extractCaaTag/parseDs/parseDnskeyFlags) travel with it.
import { dnsQuery, dnsQueryDnssec, dnsQueryGoogle, dnsQueryQuad9, buildDnsCrossCheck } from "./dns.js";
import { buildDnsOperationalResilience } from "./dns-resilience.js";
import { customerSafeFailure } from "../lib/errors.js";

// ── CAA parsing (canonical) ──────────────────────────────────────────────────
// Pure: DoH CAA answers → the caa module shape. Exported so the managed verification
// profile can re-observe CAA with EXACTLY the parsing the scan used, rather than a
// second implementation that could disagree with the finding it is verifying.
export function buildCaaFromAnswers(answers) {
  const records = (answers || []).map((r) => (r.data || "").trim()).filter(Boolean);
  const caaEntries = records.map((record) => {
    const m = record.match(/^(\d+)\s+([A-Za-z0-9_-]+)\s+"?(.+?)"?$/);
    return m ? { flags: Number(m[1]), tag: m[2].toLowerCase(), value: m[3].replace(/"$/, "").trim() } : null;
  }).filter(Boolean);
  const extractCaaTag = (tag) => caaEntries.filter((r) => r.tag === tag).map((r) => r.value).filter(Boolean);
  const issuers = extractCaaTag("issue");
  const wildcardIssuers = extractCaaTag("issuewild");
  const iodef = extractCaaTag("iodef");
  const uniqueIssuers = new Set([...issuers, ...wildcardIssuers]);
  const qualityScore =
    records.length === 0 ? 0 :
    uniqueIssuers.size === 0 ? 30 :
    uniqueIssuers.size === 1 && wildcardIssuers.length === 0 && iodef.length > 0 ? 100 :
    uniqueIssuers.size === 1 ? 85 :
    wildcardIssuers.length > 0 && iodef.length > 0 ? 75 :
    wildcardIssuers.length > 0 ? 60 :
    iodef.length > 0 ? 80 : 70;
  return {
    present:          records.length > 0,
    records,
    issuers,
    wildcard_issuers: wildcardIssuers,
    iodef,
    quality: {
      score: qualityScore,
      status:
        records.length === 0 ? "no_caa" :
        uniqueIssuers.size === 0 ? "no_issuers" :
        uniqueIssuers.size === 1 ? "single_ca" : "multiple_ca",
      wildcard_issuer_usage: wildcardIssuers.length > 0,
      iodef_present: iodef.length > 0,
      issuer_count: uniqueIssuers.size,
    },
    error:            null,
  };
}

export async function runDnsModule(domain) {
  // CAA and DNSSEC trust evidence run here alongside A/AAAA/NS/MX.
  // Placing CAA in the DNS module avoids adding subrequests to later phases
  // where the free-plan 50-subrequest budget may already be exhausted.
  //
  // v4: Added cross-checks for MX and TXT (SPF + DMARC) via Google DoH.
  //     Added Quad9 DoH cross-check for A records.
  //     Budget: 7 → 11 (+ googleMX, googleTxtBase, googleTxtDmarc, quad9A)
  const [
    aRes, aaaaRes, nsRes, mxRes, caaRes,
    googleARes, googleAaaaRes,
    googleMxRes, googleTxtBaseRes, googleTxtDmarcRes,
    quad9ARes,
    cloudflareTxtBaseRes, cloudflareTxtDmarcRes,
    googleCaaRes,
    dsRes, dnskeyRes, rrsigARes,
  ] = await Promise.allSettled([
    dnsQuery(domain, "A"),
    dnsQuery(domain, "AAAA"),
    dnsQuery(domain, "NS"),
    dnsQuery(domain, "MX"),
    dnsQuery(domain, "CAA"),
    dnsQueryGoogle(domain, "A"),
    dnsQueryGoogle(domain, "AAAA"),
    dnsQueryGoogle(domain, "MX"),
    dnsQueryGoogle(domain, "TXT"),
    dnsQueryGoogle(`_dmarc.${domain}`, "TXT"),
    dnsQueryQuad9(domain, "A").then((r) => ({ status: "fulfilled", value: r })).catch(() => ({ status: "rejected" })),
    dnsQuery(domain, "TXT"),
    dnsQuery(`_dmarc.${domain}`, "TXT"),
    dnsQueryGoogle(domain, "CAA"),
    dnsQueryDnssec(domain, "DS"),
    dnsQueryDnssec(domain, "DNSKEY"),
    dnsQueryDnssec(domain, "A"),
  ]);

  const pick = (r) =>
    r.status === "fulfilled" ? r.value.Answer || [] : [];

  const aRecords    = pick(aRes);
  const aaaaRecords = pick(aaaaRes);
  const nsRecords   = pick(nsRes);
  const mxRecords   = pick(mxRes);

  // ── CAA Record Analysis ─────────────────────────────────────────────────
  let caa;
  if (caaRes.status === "fulfilled") {
    caa = buildCaaFromAnswers(caaRes.value.Answer || []);
  } else {
    caa = {
      present: false, records: [], issuers: [],
      wildcard_issuers: [], iodef: [],
      quality: {
        score: 0,
        status: "lookup_failed",
        wildcard_issuer_usage: false,
        iodef_present: false,
        issuer_count: 0,
      },
      error: customerSafeFailure("scan/dns/caa", caaRes.reason, "CAA lookup failed"),
    };
  }

  // ── DNSSEC Trust Evidence ────────────────────────────────────────────────
  const dsAnswers = dsRes.status === "fulfilled" ? (dsRes.value.Answer || []) : [];
  const dnskeyAnswers = dnskeyRes.status === "fulfilled" ? (dnskeyRes.value.Answer || []) : [];
  const rrsigAnswers = rrsigARes.status === "fulfilled" ? (rrsigARes.value.Answer || []) : [];
  const dsRecords = dsAnswers.filter((r) => r.type === 43);
  const dnskeyRecords = dnskeyAnswers.filter((r) => r.type === 48);
  const rrsigRecords = rrsigAnswers.filter((r) => r.type === 46);
  const parseDs = (record) => {
    const parts = String(record.data || "").trim().split(/\s+/);
    return {
      key_tag: Number(parts[0]) || null,
      algorithm: parts[1] || null,
      digest_type: parts[2] || null,
    };
  };
  const parseDnskeyFlags = (record) => {
    const flags = Number(String(record.data || "").trim().split(/\s+/)[0]);
    return Number.isFinite(flags) ? flags : null;
  };
  const kskCount = dnskeyRecords.filter((r) => parseDnskeyFlags(r) === 257).length;
  const zskCount = dnskeyRecords.filter((r) => parseDnskeyFlags(r) === 256).length;
  const dnssec = {
    enabled: dsRecords.length > 0 && dnskeyRecords.length > 0 && rrsigRecords.length > 0,
    ds: {
      present: dsRecords.length > 0,
      key_tags: dsRecords.map((r) => parseDs(r).key_tag).filter((v) => v !== null),
      digest_algorithms: [...new Set(dsRecords.map((r) => parseDs(r).algorithm).filter(Boolean))],
      digest_types: [...new Set(dsRecords.map((r) => parseDs(r).digest_type).filter(Boolean))],
    },
    dnskey: {
      present: dnskeyRecords.length > 0,
      ksk_count: kskCount,
      zsk_count: zskCount,
      key_count: dnskeyRecords.length,
    },
    rrsig: {
      present: rrsigRecords.length > 0,
      covered_types: [...new Set(rrsigRecords.map((r) => String(r.data || "").split(/\s+/)[0]).filter(Boolean))],
    },
    evidence_source: "cloudflare_doh_dnssec_ok",
    errors: {
      ds: dsRes.status === "rejected" ? customerSafeFailure("scan/dns/ds", dsRes.reason, "DS lookup failed") : null,
      dnskey: dnskeyRes.status === "rejected" ? customerSafeFailure("scan/dns/dnskey", dnskeyRes.reason, "DNSKEY lookup failed") : null,
      rrsig: rrsigARes.status === "rejected" ? customerSafeFailure("scan/dns/rrsig", rrsigARes.reason, "RRSIG lookup failed") : null,
    },
  };
  const nameservers = nsRecords.map((r) => r.data).filter(Boolean);
  const operationalResilience = buildDnsOperationalResilience({ nameservers, dnssec });

  // App-probe reliability (DNS-before-HTTP): `resolves` above is derived from the
  // Cloudflare A/AAAA lookups only, so a single DoH timeout collapses to
  // `resolves:false` and reads as "domain does not resolve" — a failed probe, not an
  // authoritative absence. Aggregate the independent A/AAAA resolvers that ALREADY ran
  // (Cloudflare + Google) to separate the two: `resolution_assessed` is true iff at
  // least one resolver authoritatively answered; `resolves_any` is true iff any of them
  // returned a record. When no A/AAAA resolver answered at all (resolution_assessed
  // false), the module is incomplete — a total resolution outage must never read as a
  // clean/complete verdict. Additive only: `resolves` and every existing field are
  // unchanged for backward compatibility.
  // A resolver only AUTHORITATIVELY answered on an authoritative rcode: NOERROR (0) or
  // NXDOMAIN (3). SERVFAIL (2) / REFUSED (5) / a DoH transport failure (rejected) are
  // resolver failures, NOT proof the domain has no records — those leave resolution
  // unassessed (→ incomplete), never a false "does not resolve".
  const DNS_AUTHORITATIVE_RCODES = new Set([0, 3]);
  const aAaaaResults = [aRes, aaaaRes, googleARes, googleAaaaRes];
  const resolutionAssessed = aAaaaResults.some(
    (r) => r.status === "fulfilled" && DNS_AUTHORITATIVE_RCODES.has(r.value?.Status)
  );
  const resolvesAny = aAaaaResults.some(
    (r) => r.status === "fulfilled" && r.value?.Status === 0 && ((r.value?.Answer?.length ?? 0) > 0)
  );

  return {
    resolves:     aRecords.length > 0 || aaaaRecords.length > 0,
    resolves_any: resolvesAny,
    resolution_assessed: resolutionAssessed,
    ...(resolutionAssessed ? {} : { incomplete: true, incomplete_reason: "dns_resolution_unavailable" }),
    has_ipv6:     aaaaRecords.length > 0,
    has_mx:       mxRecords.length > 0,
    nameservers,
    a_records:    aRecords.map((r) => ({ value: r.data, ttl: r.TTL })),
    aaaa_records: aaaaRecords.map((r) => ({ value: r.data, ttl: r.TTL })),
    mx_records:   mxRecords.map((r) => ({ value: r.data, ttl: r.TTL })),
    caa,
    dnssec,
    operational_resilience: operationalResilience,
    cross_checks: (function() {
      const aCross    = buildDnsCrossCheck(domain, "A",    aRes.status    === "fulfilled" ? aRes.value    : null, googleARes,    quad9ARes.status === "fulfilled" ? quad9ARes.value?.value : null);
      const aaaaCross = buildDnsCrossCheck(domain, "AAAA", aaaaRes.status === "fulfilled" ? aaaaRes.value : null, googleAaaaRes, undefined);
      const mxCross   = buildDnsCrossCheck(domain, "MX",   mxRes.status   === "fulfilled" ? mxRes.value   : null, googleMxRes,   undefined);
      // v5 fix: pass Cloudflare TXT result as primary resolver (was null in v4)
      const txtBase   = buildDnsCrossCheck(domain, "TXT",  cloudflareTxtBaseRes.status  === "fulfilled" ? cloudflareTxtBaseRes.value  : null, googleTxtBaseRes,  undefined);
      const txtDmarc  = buildDnsCrossCheck(`_dmarc.${domain}`, "TXT", cloudflareTxtDmarcRes.status === "fulfilled" ? cloudflareTxtDmarcRes.value : null, googleTxtDmarcRes, undefined);
      // v5 new: CAA cross-check
      const caaCross  = buildDnsCrossCheck(domain, "CAA",  caaRes.status  === "fulfilled" ? caaRes.value  : null, googleCaaRes,  undefined);

      // Overall resolver_agreement_score: average of per-type scores where available.
      const typeScores = [aCross, aaaaCross, mxCross, txtBase, txtDmarc, caaCross]
        .map((c) => c.resolver_agreement_score)
        .filter((s) => s !== null);
      const overallScore = typeScores.length > 0
        ? Math.round(typeScores.reduce((s, n) => s + n, 0) / typeScores.length)
        : null;

      return {
        a:                        aCross,
        aaaa:                     aaaaCross,
        mx:                       mxCross,
        txt_spf:                  txtBase,
        txt_dmarc:                txtDmarc,
        caa:                      caaCross,
        resolver_agreement_score: overallScore,
        cross_checked_at:         new Date().toISOString(),
      };
    })(),
  };
}
