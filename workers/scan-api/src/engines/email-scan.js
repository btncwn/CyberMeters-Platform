// ── Email Security scan module (SPF / DMARC / DKIM / BIMI) ──
// Module 4 scan phase: probes SPF/DMARC/BIMI + generic & provider-specific DKIM selectors
// via DoH, then delegates parsing/analysis to email-analysis.js. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c) — no logic change.
import { dnsQuery } from "./dns.js";
import { deriveDmarcState } from "./dmarc-state.js";
import { DKIM_PROVIDER_SELECTORS, DKIM_SELECTORS, buildDkimDetail, buildDmarcPolicyJourney, buildEmailRemediationActions, findDkimInResults, inferEmailProvider, normalizeDnsTxtValue, parseBimiRecord, parseDmarcRecord, parseSpfRecord } from "./email-analysis.js";
import { makeDohSpfLookup, resolveSpfAuthorization } from "./spf-resolver.js";

export const DMARC_OBSERVATION_STATUS = Object.freeze({
  OBSERVED: "observed",
  UNAVAILABLE: "unavailable",
  NOT_YET_ASSESSED: "not_yet_assessed",
});

const DNS_STATUS_NOERROR = 0;
const DNS_STATUS_NXDOMAIN = 3;

function isNotExecutedDmarcLookup(settledResult) {
  return !settledResult
    || settledResult.status === "not_executed"
    || settledResult.status === "not_yet_assessed"
    || settledResult.skipped === true;
}

function hasResolverDisagreement(response) {
  if (response?.resolver_disagreement === true) return true;
  if (["disagreement", "insufficient", "unavailable"].includes(String(response?.resolver_agreement || "").toLowerCase())) return true;
  if (Object.prototype.hasOwnProperty.call(response || {}, "resolver_agreement_score")) {
    return response.resolver_agreement_score !== 100;
  }
  return false;
}

export function dmarcObservationStatusFromDnsResult(settledResult) {
  if (isNotExecutedDmarcLookup(settledResult)) return DMARC_OBSERVATION_STATUS.NOT_YET_ASSESSED;
  if (settledResult.status !== "fulfilled") return DMARC_OBSERVATION_STATUS.UNAVAILABLE;

  const response = settledResult.value;
  if (!response || typeof response !== "object") return DMARC_OBSERVATION_STATUS.UNAVAILABLE;
  if (hasResolverDisagreement(response)) return DMARC_OBSERVATION_STATUS.UNAVAILABLE;

  const dnsStatus = Number(response.Status);
  if (dnsStatus === DNS_STATUS_NOERROR || dnsStatus === DNS_STATUS_NXDOMAIN) {
    return DMARC_OBSERVATION_STATUS.OBSERVED;
  }
  return DMARC_OBSERVATION_STATUS.UNAVAILABLE;
}

// A1: aggregate the DKIM selector probes into ONE observation status. DKIM probes
// many selectors; the domain's DKIM is "observed" if ANY probe completed (a
// non-match is an observed absence, never proof of failure), "unavailable" only if
// EVERY probe failed (DNS error/timeout), and "not_yet_assessed" if none ran.
// Reuses the single-result classifier so SPF and DKIM share one "unobserved"
// definition (isEmailProbeUnobserved lives in email-analysis.js).
export function dkimObservationStatusFromResults(results = []) {
  const statuses = (Array.isArray(results) ? results : []).map(dmarcObservationStatusFromDnsResult);
  if (statuses.includes(DMARC_OBSERVATION_STATUS.OBSERVED)) return DMARC_OBSERVATION_STATUS.OBSERVED;
  if (statuses.includes(DMARC_OBSERVATION_STATUS.UNAVAILABLE)) return DMARC_OBSERVATION_STATUS.UNAVAILABLE;
  return DMARC_OBSERVATION_STATUS.NOT_YET_ASSESSED;
}

export function buildDmarcEvidenceFromDnsResult(settledResult, options = {}) {
  const observationStatus = dmarcObservationStatusFromDnsResult(settledResult);
  const observed = observationStatus === DMARC_OBSERVATION_STATUS.OBSERVED;
  const answers = observed ? (settledResult.value.Answer || []) : [];
  const dmarcRecords = answers.filter((r) => normalizeDnsTxtValue(r.data).toLowerCase().startsWith("v=dmarc1"));
  const dmarcRecord = dmarcRecords.length > 0 ? normalizeDnsTxtValue(dmarcRecords[0].data) : null;
  const dmarcDetail = parseDmarcRecord(dmarcRecord, dmarcRecords.length);
  const dmarcState = deriveDmarcState({
    evidence_status: observationStatus,
    dmarc: dmarcDetail,
    policy_source: "observed_dns",
    last_observed: options.last_observed ?? options.lastObserved ?? null,
  });

  return {
    observation_status: observationStatus,
    dmarc_records: dmarcRecords,
    dmarc_record: dmarcRecord,
    dmarc_detail: dmarcDetail,
    dmarc_state: dmarcState,
  };
}

export async function runEmailModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  // Phase 1 — fire SPF + DMARC + BIMI + generic DKIM selectors in parallel.
  const [spfRes, dmarcRes, bimiRes, ...dkimPhase1] = await Promise.allSettled([
    dnsQuery(domain, "TXT", { accounting }),
    dnsQuery(`_dmarc.${domain}`, "TXT", { accounting }),
    dnsQuery(`default._bimi.${domain}`, "TXT", { accounting }),
    ...DKIM_SELECTORS.map((sel) => dnsQuery(`${sel}._domainkey.${domain}`, "TXT", { accounting })),
  ]);

  // SPF — look for v=spf1 in root TXT records
  const rootTxt  = spfRes.status === "fulfilled" ? (spfRes.value.Answer || []) : [];
  const spfRecs  = rootTxt.filter((r) => normalizeDnsTxtValue(r.data).toLowerCase().startsWith("v=spf1"));
  const hasSPF   = spfRecs.length > 0;

  // DMARC — _dmarc.<domain> TXT. ADR-003 requires failed/unexecuted lookups to
  // remain distinct from an observed zero-record result before canonical state derivation.
  const dmarcEvidence = buildDmarcEvidenceFromDnsResult(dmarcRes);
  const dmarcRecs = dmarcEvidence.dmarc_records;
  const hasDMARC = dmarcRecs.length > 0;

  // Infer email provider from SPF record
  const spfRecord    = hasSPF ? normalizeDnsTxtValue(spfRecs[0].data) : null;
  const emailProvider = inferEmailProvider(spfRecord);

  // Check phase 1 DKIM results
  let dkimSelector = findDkimInResults(DKIM_SELECTORS, dkimPhase1);
  const dkimSettled = [...dkimPhase1];   // A1: track every probe outcome for observation status

  // Phase 2 — provider-specific additional selectors (only if provider known and
  // no DKIM found yet). Only probe selectors not already covered by phase 1.
  let phase2Selectors = [];
  if (!dkimSelector && emailProvider) {
    const providerExtras = (DKIM_PROVIDER_SELECTORS[emailProvider] || []).filter(
      (s) => !DKIM_SELECTORS.includes(s)
    );
    if (providerExtras.length > 0) {
      phase2Selectors = providerExtras;
      const phase2Results = await Promise.allSettled(
        phase2Selectors.map((sel) => dnsQuery(`${sel}._domainkey.${domain}`, "TXT", { accounting }))
      );
      dkimSettled.push(...phase2Results);
      dkimSelector = findDkimInResults(phase2Selectors, phase2Results);
    }
  }
  // A1 evidence status — a failed SPF/DKIM probe must not collapse into "missing".
  const spfObservationStatus = dmarcObservationStatusFromDnsResult(spfRes);
  const dkimObservationStatus = dkimObservationStatusFromResults(dkimSettled);

  const dmarcRecord = dmarcEvidence.dmarc_record;
  const spfDetail = parseSpfRecord(spfRecord, spfRecs.length);
  // Statically-resolvable PASS-authorisation set (recursive include/redirect/a/mx).
  // Reuses the already-fetched root record (no redundant root lookup); the resolver
  // enforces RFC 7208 lookup/void limits and fails SAFE (temperror) on any transient
  // DNS error. resolution_status is recorded SEPARATELY so a partial/temperror set is
  // never treated as exhaustive by the posture-events comparator.
  const spfAuthorization = await resolveSpfAuthorization({
    domain,
    rootRecord: spfRecord,
    recordCount: spfRecs.length,
    lookup: makeDohSpfLookup((name, type) => dnsQuery(name, type, { accounting }), normalizeDnsTxtValue),
    nowIso: new Date().toISOString(),
  }).catch(() => null);
  const dmarcDetail = dmarcEvidence.dmarc_detail;
  const dkim = {
    present:          dkimSelector !== null,
    selector:         dkimSelector,
    provider:         emailProvider,
    selectors_probed: [...DKIM_SELECTORS, ...phase2Selectors],
  };
  const bimiAnswers = bimiRes.status === "fulfilled" ? (bimiRes.value.Answer || []) : [];
  const bimiRecord = bimiAnswers
    .map((answer) => normalizeDnsTxtValue(answer.data))
    .find((value) => value.toLowerCase().startsWith("v=bimi1")) || null;
  const bimiReadiness = parseBimiRecord(bimiRecord, dmarcDetail);
  const details = {
    spf_detail: spfDetail,
    dmarc_detail: dmarcDetail,
    dkim_detail: buildDkimDetail(dkim),
    bimi_readiness: bimiReadiness,
    policy_journey: buildDmarcPolicyJourney(dmarcDetail),
  };
  const result = {
    spf: {
      present: hasSPF,
      record:  spfRecord,
      record_count: spfRecs.length,
      // Additive resolved-authorisation snapshot (PR-A). Null only if the resolver
      // threw unexpectedly; a transient DNS error is represented HONESTLY as
      // resolution_status="temperror" with resolved_pass_authorisations=null, not
      // as a silent failure. The posture-events comparator only diffs two
      // "complete" snapshots, so partial/temperror can never produce a false change.
      resolution_status: spfAuthorization?.resolution_status ?? null,
      resolved_pass_authorisations: spfAuthorization?.resolved_pass_authorisations ?? null,
      unresolved_mechanisms: spfAuthorization?.unresolved_mechanisms ?? [],
      lookup_count: spfAuthorization?.lookup_count ?? null,
      void_lookup_count: spfAuthorization?.void_lookup_count ?? null,
      resolved_at: spfAuthorization?.resolved_at ?? null,
    },
    dmarc: {
      present: hasDMARC,
      policy:  dmarcDetail.policy,
      record:  dmarcRecord,
      record_count: dmarcRecs.length,
    },
    dkim,
    ...details,
  };
  Object.defineProperty(result, "dmarc_state", {
    value: dmarcEvidence.dmarc_state,
    enumerable: false,
  });
  // A1: SPF/DKIM observation status as NON-ENUMERABLE backend evidence — read
  // directly by the in-memory truth consumers (scoring, email-intel). Kept off the
  // enumerable module so the customer API response shape (routes/scans.js serves
  // modules.email_security verbatim) is unchanged.
  Object.defineProperty(result, "spf_evidence_status", { value: spfObservationStatus, enumerable: false });
  Object.defineProperty(result, "dkim_evidence_status", { value: dkimObservationStatus, enumerable: false });
  result.remediation_actions = buildEmailRemediationActions(domain, details);
  return result;
}
