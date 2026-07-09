// ── Email Security scan module (SPF / DMARC / DKIM / BIMI) ──
// Module 4 scan phase: probes SPF/DMARC/BIMI + generic & provider-specific DKIM selectors
// via DoH, then delegates parsing/analysis to email-analysis.js. Extracted verbatim from
// index.js (monolith decomposition, Phase 1c) — no logic change.
import { dnsQuery } from "./dns.js";
import { DKIM_PROVIDER_SELECTORS, DKIM_SELECTORS, buildDkimDetail, buildDmarcPolicyJourney, buildEmailRemediationActions, findDkimInResults, inferEmailProvider, normalizeDnsTxtValue, parseBimiRecord, parseDmarcRecord, parseSpfRecord } from "./email-analysis.js";

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

  // DMARC — _dmarc.<domain> TXT
  const dmarcTxt  = dmarcRes.status === "fulfilled" ? (dmarcRes.value.Answer || []) : [];
  const dmarcRecs = dmarcTxt.filter((r) => normalizeDnsTxtValue(r.data).toLowerCase().startsWith("v=dmarc1"));
  const hasDMARC  = dmarcRecs.length > 0;

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

  const dmarcRecord = hasDMARC ? normalizeDnsTxtValue(dmarcRecs[0].data) : null;
  const spfDetail = parseSpfRecord(spfRecord, spfRecs.length);
  const dmarcDetail = parseDmarcRecord(dmarcRecord, dmarcRecs.length);
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
  result.remediation_actions = buildEmailRemediationActions(domain, details);
  return result;
}
