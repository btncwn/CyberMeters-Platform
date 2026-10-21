// Replay stored scan reports through the TLS refusal rule (classifyTlsRefusals)
// and the real scan-quality builder, without touching production. Pass local
// report JSON files (for example ones fetched read-only from R2); nothing is
// written and no network is used.
//
//   node scripts/lab/tls-refusal-replay.mjs reports/scan_a.json reports/scan_b.json
import fs from "node:fs";
import path from "node:path";
import { buildScanQuality } from "../../workers/scan-api/src/engines/scan-engine.js";
import { blockingTlsUnexecutable, classifyTlsRefusals } from "../../workers/scan-api/src/engines/tls-quality.js";
import { resolveSecurityCheckDomainStates } from "../../workers/scan-api/src/engines/security-check-domains.js";
import { tlsAssessmentFindings } from "../../workers/scan-api/src/engines/tls-findings.js";

// Same counting as readTlsAssessmentForScan in exposure-jobs.js.
function recountCoverage(previous, checks) {
  const coverage = { ...previous, completed: 0, uncertain: 0, unexecutable: 0, not_authorized: 0, not_applicable: 0 };
  for (const item of checks) {
    if (["accepted", "rejected"].includes(item.state)) coverage.completed++;
    else if (item.state === "not_authorized") coverage.not_authorized++;
    else if (item.state === "not_applicable") coverage.not_applicable++;
    else if (item.state === "unexecutable") coverage.unexecutable++;
    else coverage.uncertain++;
  }
  return coverage;
}

export function replayTlsAssessment(assessment) {
  if (!assessment || assessment.source !== "tls_assessment") return assessment;
  const indexed = (assessment.endpoints || []).flatMap((endpoint, index) =>
    (endpoint.checks || []).map((check) => ({ ...check, endpoint_index: index })));
  const classified = classifyTlsRefusals(indexed);
  const endpoints = (assessment.endpoints || []).map((endpoint, index) => ({
    ...endpoint,
    checks: classified.filter((check) => check.endpoint_index === index)
      .map(({ endpoint_index, ...rest }) => rest),
  }));
  const coverage = recountCoverage(assessment.coverage || {}, classified);
  const complete = assessment.phase_state === "complete" && coverage.completed > 0 && coverage.uncertain === 0 && blockingTlsUnexecutable(classified) === 0
    && coverage.not_authorized === 0 && !coverage.omitted_checks && !coverage.omitted_services && !coverage.endpoint_gaps;
  return { ...assessment, endpoints, coverage, quality: complete ? "complete" : "partial" };
}

if (process.argv[1] === new URL(import.meta.url).pathname) {
  for (const file of process.argv.slice(2)) {
    const report = JSON.parse(fs.readFileSync(file, "utf8"));
    const modules = report.modules || {};
    const replayed = { ...modules, tls_assessment: replayTlsAssessment(modules.tls_assessment) };
    const before = buildScanQuality(modules);
    const after = buildScanQuality(replayed);
    const ids = (assessment) => tlsAssessmentFindings(assessment || {}).map((f) => f.id).sort().join(",");
    const refused = (replayed.tls_assessment?.endpoints || []).flatMap((e) => e.checks || [])
      .filter((c) => c.rejection_basis === "refused_without_version_alert").length;
    console.log([
      path.basename(file, ".json"),
      `stored=${report.scan_quality?.status}`,
      `rebuilt_before=${before.status}`,
      `after=${after.status}`,
      `refused_without_alert=${refused}`,
      `tls_uncertain=${modules.tls_assessment?.coverage?.uncertain}->${replayed.tls_assessment?.coverage?.uncertain}`,
      `still_incomplete=${after.modules_incomplete.map((m) => `${m.module}:${m.incomplete_reason}`).join("|") || "none"}`,
      `tls_findings_unchanged=${ids(modules.tls_assessment) === ids(replayed.tls_assessment)}`,
      `certificates_trust=${resolveSecurityCheckDomainStates({ ...report, modules: replayed, scan_quality: after }).find((d) => d.domain_key === "certificates_trust")?.state}`,
    ].join("  "));
  }
}
