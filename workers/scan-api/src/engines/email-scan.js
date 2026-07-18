// ── Email Security scan module (SPF / DMARC / DKIM / BIMI) ──
// Module 4 scan phase: probes SPF/DMARC/BIMI + generic & provider-specific DKIM selectors
// via DoH, then delegates parsing/analysis to email-analysis.js. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c) — no logic change.
import { dnsQuery } from "./dns.js";
import { deriveDmarcState } from "./dmarc-state.js";
import { DKIM_PROVIDER_SELECTORS, DKIM_SELECTORS, buildDkimDetail, buildDmarcPolicyJourney, buildEmailRemediationActions, findDkimInResults, inferEmailProvider, normalizeDnsTxtValue, parseBimiRecord, parseDmarcRecord, parseSpfRecord } from "./email-analysis.js";

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

export async function runEmailModule(domain) {
  // Phase 1 — fire SPF + DMARC + BIMI + generic DKIM selectors in parallel.
  const [spfRes, dmarcRes, bimiRes, ...dkimPhase1] = await Promise.allSettled([
    dnsQuery(domain, "TXT"),
    dnsQuery(`_dmarc.${domain}`, "TXT"),
    dnsQuery(`default._bimi.${domain}`, "TXT"),
    ...DKIM_SELECTORS.map((sel) => dnsQuery(`${sel}._domainkey.${domain}`, "TXT")),
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
        phase2Selectors.map((sel) => dnsQuery(`${sel}._domainkey.${domain}`, "TXT"))
      );
      dkimSelector = findDkimInResults(phase2Selectors, phase2Results);
    }
  }

  const dmarcRecord = dmarcEvidence.dmarc_record;
  const spfDetail = parseSpfRecord(spfRecord, spfRecs.length);
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
  result.remediation_actions = buildEmailRemediationActions(domain, details);
  return result;
}
