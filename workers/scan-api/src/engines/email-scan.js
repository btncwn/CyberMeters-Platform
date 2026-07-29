// ── Email Security scan module (SPF / DMARC / DKIM / BIMI) ──
// Module 4 scan phase: probes SPF/DMARC/BIMI + generic & provider-specific DKIM selectors
// via DoH, then delegates parsing/analysis to email-analysis.js. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c) — no logic change.
import { dnsQuery } from "./dns.js";
import { deriveDmarcState } from "./dmarc-state.js";
import { DKIM_PROVIDER_SELECTORS, DKIM_SELECTORS, buildDkimDetail, buildDmarcPolicyJourney, buildEmailRemediationActions, findDkimInResults, inferEmailProvider, normalizeDnsTxtValue, parseBimiRecord, parseDmarcRecord, parseSpfRecord } from "./email-analysis.js";
import { makeDohSpfLookup, resolveSpfAuthorization, SPF_RESOLUTION_STATUS } from "./spf-resolver.js";
import { markDeadlineDeferred } from "./scan-budget.js";

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

// The deadline fallback for the primary email module, owned HERE by the module
// that owns the completed contract. It conforms to the runEmailModule result
// shape with NOTHING observed:
//   • presence is the tri-state null — never false, because "not measured" must
//     never read as "measured absent";
//   • the canonical detail contract (spf/dmarc/dkim detail, bimi, journey) is
//     explicitly null, which every remediation consumer treats as
//     non-publishable evidence (isPublishableEmailEvidence fails closed);
//   • the A1 evidence statuses are not_yet_assessed (non-enumerable, matching
//     the completed result), so the existing honesty gates in scoring,
//     email-intel and the remediation builder all read this module as
//     unobserved rather than as authoritative absence;
//   • markDeadlineDeferred stamps executed:false / incomplete:true /
//     outcome:"deadline_exceeded", which classifies the scan "partial" and
//     blocks lifecycle verification, exactly as for every other module.
export function deadlineDeferredEmailModuleResult() {
  const result = markDeadlineDeferred({
    spf: {
      present: null, record: null, record_count: null,
      resolution_status: null, resolved_pass_authorisations: null,
      unresolved_mechanisms: [], lookup_count: null, void_lookup_count: null,
      resolved_at: null,
    },
    dmarc: { present: null, policy: null, record: null, record_count: null },
    dkim: { present: null, selector: null, provider: null, selectors_probed: [] },
    spf_detail: null,
    dmarc_detail: null,
    dkim_detail: null,
    bimi_readiness: null,
    policy_journey: null,
    remediation_actions: [],
    source: "email_security",
  });
  Object.defineProperty(result, "spf_evidence_status", { value: DMARC_OBSERVATION_STATUS.NOT_YET_ASSESSED, enumerable: false, configurable: true });
  Object.defineProperty(result, "dkim_evidence_status", { value: DMARC_OBSERVATION_STATUS.NOT_YET_ASSESSED, enumerable: false, configurable: true });
  return result;
}

export async function runEmailModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  const cache = opts.cache || null;
  // A runScanEngine caller sets dmarcOwnedByCore only after launching P2's
  // independently capped canonical peer. The legacy exact lookup remains the
  // compatibility fallback for the two lightweight direct callers (free domain
  // preview and authenticated benchmark), whose separate budgets are outside
  // this PR. This prevents a third scan-engine lookup without silently changing
  // those existing response contracts.
  const dmarcOwnedByCore = opts.dmarcOwnedByCore === true;
  const dmarcLookup = dmarcOwnedByCore
    ? Promise.resolve(null)
    : dnsQuery(`_dmarc.${domain}`, "TXT", { accounting, cache });
  const [spfRes, dmarcRes, bimiRes, ...dkimPhase1] = await Promise.allSettled([
    dnsQuery(domain, "TXT", { accounting, cache }),
    dmarcLookup,
    dnsQuery(`default._bimi.${domain}`, "TXT", { accounting, cache }),
    ...DKIM_SELECTORS.map((sel) => dnsQuery(`${sel}._domainkey.${domain}`, "TXT", { accounting, cache })),
  ]);

  // SPF — look for v=spf1 in root TXT records
  const rootTxt  = spfRes.status === "fulfilled" ? (spfRes.value.Answer || []) : [];
  const spfRecs  = rootTxt.filter((r) => normalizeDnsTxtValue(r.data).toLowerCase().startsWith("v=spf1"));
  const hasSPF   = spfRecs.length > 0;

  // DMARC — _dmarc.<domain> TXT. ADR-003 requires failed/unexecuted lookups to
  // remain distinct from an observed zero-record result before canonical state derivation.
  const dmarcEvidence = dmarcOwnedByCore
    ? buildDmarcEvidenceFromDnsResult({ status: "not_yet_assessed" })
    : buildDmarcEvidenceFromDnsResult(dmarcRes);
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
        phase2Selectors.map((sel) => dnsQuery(`${sel}._domainkey.${domain}`, "TXT", { accounting, cache }))
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
  const spfAuthorization = spfObservationStatus === DMARC_OBSERVATION_STATUS.OBSERVED
    ? await resolveSpfAuthorization({
      domain,
      rootRecord: spfRecord,
      recordCount: spfRecs.length,
      lookup: makeDohSpfLookup((name, type) => dnsQuery(name, type, { accounting, cache }), normalizeDnsTxtValue),
      nowIso: new Date().toISOString(),
    }).catch(() => null)
    : {
      resolution_status: SPF_RESOLUTION_STATUS.TEMPERROR,
      resolved_pass_authorisations: null,
      unresolved_mechanisms: [],
      lookup_count: null,
      void_lookup_count: null,
      resolved_at: new Date().toISOString(),
    };
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
  // Per-signal observation statuses travel with the details NON-ENUMERABLY (the
  // `...details` spread below copies only enumerable keys, so the customer API
  // shape is unchanged). The remediation builder reads them so a failed or
  // unexecuted probe is never converted into a missing-record action.
  Object.defineProperty(details, "spf_evidence_status", { value: spfObservationStatus, enumerable: false });
  Object.defineProperty(details, "dkim_evidence_status", { value: dkimObservationStatus, enumerable: false });
  Object.defineProperty(details, "dmarc_evidence_status", { value: dmarcEvidence.observation_status, enumerable: false });
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
    configurable: true,
  });
  Object.defineProperty(result, "_bimi_record", {
    value: bimiRecord,
    enumerable: false,
    configurable: true,
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

function exactPolicyRecordSet(policyEvidence) {
  return policyEvidence?.lookup_path?.find(
    (entry) =>
      entry?.question?.ordinal === 1 &&
      entry?.question?.purpose === "policy_tree_walk" &&
      entry?.question?.resolver === "primary",
  )?.record_set ?? null;
}

// Apply the legacy exact-record fields and ADR-003 consumer state from one
// canonical DMARCbis result. Inherited values never populate `dmarc.policy`.
// Multiple records retain their count but no arbitrary record is selected.
export function applyDmarcbisEmailCompatibilityProjection(
  domain,
  emailResult,
  policyEvidence,
) {
  const result = emailResult && typeof emailResult === "object"
    ? emailResult
    : { spf: {}, dkim: {} };
  const alreadyProjected = Object.prototype.hasOwnProperty.call(
    result,
    "dmarc_policy_evidence",
  );
  const exactSet = exactPolicyRecordSet(policyEvidence);
  const candidates = Array.isArray(exactSet?.candidates) ? exactSet.candidates : [];
  const sole = candidates.length === 1 ? candidates[0] : null;
  const exactRecord = sole?.value || null;
  const exactDetail = parseDmarcRecord(exactRecord, candidates.length);
  // The compatibility policy remains the exact record's p. A parent p/sp/np is
  // available only in dmarc_core until the additive v2 API lands in P3.
  result.dmarc = {
    present: candidates.length > 0,
    policy: exactSet?.selected?.p?.normalized ?? null,
    record: candidates.length === 1 ? exactRecord : null,
    record_count: candidates.length,
  };
  result.dmarc_detail = exactDetail;
  result.policy_journey = buildDmarcPolicyJourney(exactDetail);
  result.bimi_readiness = parseBimiRecord(result._bimi_record || null, exactDetail);
  Object.defineProperty(result, "dmarc_state", {
    // Preserve the shipped exact-record ADR-003 projection until P6 migrates
    // customer wording. Inherited DMARCbis values remain only in dmarc_core;
    // they never backfill legacy exact fields or silently change old scoring.
    value: policyEvidence?.core_completeness === "complete"
      ? deriveDmarcState({
        assessed: true,
        evidence_status: "observed",
        dmarc: exactDetail,
        policy_source: "observed_dns",
        last_observed: policyEvidence?.observed_at ?? null,
      })
      : deriveDmarcState({
        assessed: true,
        evidence_status: "unavailable",
        dmarc: exactDetail,
        policy_source: "observed_dns",
        last_observed: policyEvidence?.observed_at ?? null,
      }),
    enumerable: false,
    configurable: true,
  });
  Object.defineProperty(result, "dmarc_policy_evidence", {
    value: policyEvidence,
    enumerable: false,
    configurable: true,
  });
  // A budget-deferred Email peer has no SPF/DKIM detail. Keep that deferral
  // honest instead of fabricating missing-SPF/DKIM remediation from absent
  // module output; DMARC's canonical technical evidence still remains present.
  if (!alreadyProjected && result.spf_detail && result.dkim_detail) {
    const rebuildDetails = {
      spf_detail: result.spf_detail,
      dmarc_detail: exactDetail,
      dkim_detail: result.dkim_detail,
      bimi_readiness: result.bimi_readiness,
      policy_journey: result.policy_journey,
    };
    // Observation statuses travel with the rebuild (non-enumerable, as on the
    // live result). DMARC's status comes from the canonical core observation:
    // only a complete tree walk is "observed"; anything less is unavailable, so
    // an unobserved policy can never rebuild into a "publish DMARC" action.
    Object.defineProperty(rebuildDetails, "spf_evidence_status", { value: result.spf_evidence_status, enumerable: false });
    Object.defineProperty(rebuildDetails, "dkim_evidence_status", { value: result.dkim_evidence_status, enumerable: false });
    Object.defineProperty(rebuildDetails, "dmarc_evidence_status", {
      value: policyEvidence?.core_completeness === "complete"
        ? DMARC_OBSERVATION_STATUS.OBSERVED
        : DMARC_OBSERVATION_STATUS.UNAVAILABLE,
      enumerable: false,
    });
    result.remediation_actions = buildEmailRemediationActions(domain, rebuildDetails);
  }
  return result;
}
