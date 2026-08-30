#!/usr/bin/env node
//
// Eight-domain Cyber MOT coverage-state honesty — behavioural proof that the
// canonical resolver (engines/cyber-mot-domains.js) always returns exactly eight
// domains in a fixed order, that missing evidence never renders as healthy, that no
// domain disappears, and that Identity/Shadow-IT stay within their honest scopes.
// Node 24+. CI-blocking.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { resolveCyberMotDomainStates, CYBER_MOT_DOMAINS, CYBER_MOT_STATES } =
  await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "cyber-mot-domains.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const byKey = (arr, k) => arr.find((x) => x.domain_key === k);
const KEYS = ["email_protection","brand_protection","attack_surface","certificates_trust","cyber_essentials_readiness","website_security","identity_exposure","shadow_it_unmanaged_technology"];
const HEALTHY = CYBER_MOT_STATES.ASSESSED_HEALTHY;
const healthyCtMonitoring = () => ({
  version: "signal-monitoring-state-v1",
  signals: {
    certificate_transparency: {
      state: "monitoring_healthy",
      message: "Certificate transparency checks completed normally in this run.",
      evidence: {
        modules: ["subdomains"],
        incomplete_modules: [],
        providers: { crt_sh: "available", certspotter: "available" },
      },
    },
  },
});

// A complete scan, all core+relevant modules assessed cleanly, no findings.
const cleanComplete = () => ({
  scan_id: "scan_x", completed_at: "2026-07-14T10:00:00Z",
  scan_quality: { status: "complete", warnings: [], modules_skipped: [] },
  modules: {
    email_security: {}, dns: {},
    ssl: { https_available: true, https_probe_executed: true },
    headers: {},
    subdomains: { count: 3 }, admin_surface_detection: {}, cloud_storage_discovery: {},
    certificate_intelligence: {}, identity_discovery: {},
    saas_exposure: { count: 2 }, technology_detection: { count: 5 },
  },
  monitoring_states: healthyCtMonitoring(),
  findings: [],
});

// 1-3. Always eight, deterministic order, stable keys + display names.
{
  const r = resolveCyberMotDomainStates(cleanComplete());
  ok("1: resolver returns exactly eight domains", r.length === 8);
  ok("2: order is deterministic + canonical", r.map((x) => x.domain_key).join(",") === KEYS.join(","));
  ok("3: keys + display names stable, keys not derived from copy",
    byKey(r, "identity_exposure").display_name === "Identity Exposure" &&
    byKey(r, "shadow_it_unmanaged_technology").display_name === "Shadow IT & Unmanaged Technology" &&
    CYBER_MOT_DOMAINS.length === 8);
}

// 4. No scan → nothing healthy, explicit not-yet-assessed.
{
  const r = resolveCyberMotDomainStates(null);
  ok("4: no scan → zero domains healthy", r.every((x) => x.state !== HEALTHY));
  ok("4: no scan → all eight still returned with explicit state", r.length === 8 && r.every((x) => x.state === CYBER_MOT_STATES.NOT_YET_ASSESSED));
}

// 5. Complete + successful evidence + no findings → only genuinely assessed domains healthy.
{
  const r = resolveCyberMotDomainStates(cleanComplete());
  ok("5: email/attack/website/certs assessed_healthy on clean complete scan",
    ["email_protection","attack_surface","website_security","certificates_trust"].every((k) => byKey(r, k).state === HEALTHY));
  const website = byKey(r, "website_security");
  ok("5: clean complete Website base control has no finding authority",
    website.state === HEALTHY && website.coverage === "complete" &&
    website.finding_count === 0 && JSON.stringify(website.finding_ids) === "[]");
  ok("5: Identity without a supported reachability producer is evidence_insufficient, never healthy",
    byKey(r, "identity_exposure").state === CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT &&
    /not evaluated|producer/i.test(byKey(r, "identity_exposure").summary));
  // Non-scan domains never fabricate healthy.
  ok("5: cyber_essentials is customer_input_required (needs questionnaire), not healthy",
    byKey(r, "cyber_essentials_readiness").state === CYBER_MOT_STATES.CUSTOMER_INPUT_REQUIRED);
  ok("5: shadow_it is monitoring_only, never healthy", byKey(r, "shadow_it_unmanaged_technology").state === CYBER_MOT_STATES.MONITORING_ONLY);
}

// 6. Complete + a finding → correct domain issue_detected.
{
  const rep = cleanComplete();
  rep.findings = [{ id: "email_dmarc_missing", finding_type: "finding", severity: "high", score_impact: -8, module: "email_security", recommendation: "Add DMARC" }];
  const r = resolveCyberMotDomainStates(rep);
  ok("6: finding maps to the correct domain (email) as issue_detected",
    byKey(r, "email_protection").state === CYBER_MOT_STATES.ISSUE_DETECTED && byKey(r, "email_protection").finding_count === 1 && byKey(r, "email_protection").highest_severity === "high");
  ok("6: unrelated domains not falsely issue_detected", byKey(r, "brand_protection").state !== CYBER_MOT_STATES.ISSUE_DETECTED);
}

// 7. Partial scan → provisional state, real findings still visible.
{
  const rep = cleanComplete();
  rep.scan_quality = { status: "partial", warnings: ["Core module incomplete: headers"], modules_skipped: ["headers"] };
  rep.findings = [{ id: "email_dmarc_missing", finding_type: "finding", severity: "high", score_impact: -8, module: "email_security" }];
  const r = resolveCyberMotDomainStates(rep);
  ok("7: partial scan keeps the real finding visible (issue_detected, coverage partial)",
    byKey(r, "email_protection").state === CYBER_MOT_STATES.ISSUE_DETECTED && byKey(r, "email_protection").coverage === "partial");
  ok("7: a finding-free assessed domain becomes provisional (not healthy) on a partial scan",
    byKey(r, "certificates_trust").state === CYBER_MOT_STATES.PROVISIONAL);
}

// 8. Degraded scan → affected domains do not appear healthy.
{
  const rep = cleanComplete();
  rep.scan_quality = { status: "degraded", warnings: ["Module skipped"], modules_skipped: [] };
  const r = resolveCyberMotDomainStates(rep);
  ok("8: degraded scan → no assessed domain is healthy", ["email_protection","website_security","certificates_trust","attack_surface"].every((k) => byKey(r, k).state !== HEALTHY));
}

// 9. Legacy unknown-quality scan → coverage remains explicitly unknown, not healthy.
{
  const rep = cleanComplete();
  rep.scan_quality = { status: "unknown" };
  const r = resolveCyberMotDomainStates(rep);
  ok("9: unknown-quality scan → provisional/coverage unknown, not healthy",
    byKey(r, "email_protection").state === CYBER_MOT_STATES.PROVISIONAL && byKey(r, "website_security").state !== HEALTHY);
}

// 10. Missing domain module → not healthy.
{
  const rep = cleanComplete();
  delete rep.modules.certificate_intelligence;
  const r = resolveCyberMotDomainStates(rep);
  ok("10: missing certificate module → certificates not healthy (not_yet_assessed)",
    byKey(r, "certificates_trust").state === CYBER_MOT_STATES.NOT_YET_ASSESSED);
}

// 11. Missing R2 report but scan exists → treat as no report → not healthy.
{
  const r = resolveCyberMotDomainStates(undefined);
  ok("11: absent report → all not_yet_assessed, none healthy", r.length === 8 && r.every((x) => x.state !== HEALTHY));
}

// 12. Email DKIM common-selector uncertainty stays an explicit observation.
{
  const rep = cleanComplete();
  rep.findings = [{ id: "dkim_not_verified", finding_type: "observation", severity: "info", score_impact: 0, module: "email_security" }];
  const r = resolveCyberMotDomainStates(rep);
  ok("12: DKIM common-selector info finding does not force issue_detected",
    byKey(r, "email_protection").state === HEALTHY);
}

// 12b. Explicit actionability, not severity, owns the positive-first state.
{
  const hsts = {
    id: "dse_hsts_short_maxage", finding_type: "finding", severity: "low",
    score_impact: 0, module: "domain_security_enrichment", recommendation: "Increase HSTS max-age.",
  };
  const complete = cleanComplete();
  complete.findings = [hsts];
  const completeWebsite = byKey(resolveCyberMotDomainStates(complete), "website_security");
  ok("12b: low score-neutral actionable Website finding owns complete issue state and identity",
    completeWebsite.state === CYBER_MOT_STATES.ISSUE_DETECTED &&
    completeWebsite.coverage === "complete" && completeWebsite.finding_count === 1 &&
    JSON.stringify(completeWebsite.finding_ids) === '["dse_hsts_short_maxage"]' &&
    completeWebsite.highest_severity === "low");

  const partial = cleanComplete();
  partial.scan_quality = { status: "partial", warnings: [], modules_skipped: [] };
  partial.findings = [hsts];
  const partialWebsite = byKey(resolveCyberMotDomainStates(partial), "website_security");
  ok("12b: actionable finding outranks global partial while retaining the coverage caveat",
    partialWebsite.state === CYBER_MOT_STATES.ISSUE_DETECTED &&
    partialWebsite.coverage === "partial" && partialWebsite.finding_count === 1 &&
    JSON.stringify(partialWebsite.finding_ids) === '["dse_hsts_short_maxage"]');

  const incomplete = cleanComplete();
  incomplete.modules.headers = { incomplete: true, incomplete_reason: "origin_error_no_serviceable_response" };
  incomplete.findings = [hsts];
  const incompleteWebsite = byKey(resolveCyberMotDomainStates(incomplete), "website_security");
  ok("12b: actionable finding outranks required-evidence failure while retaining identity",
    incompleteWebsite.state === CYBER_MOT_STATES.ISSUE_DETECTED &&
    incompleteWebsite.coverage === "partial" && incompleteWebsite.finding_count === 1 &&
    JSON.stringify(incompleteWebsite.finding_ids) === '["dse_hsts_short_maxage"]');

  const observation = cleanComplete();
  observation.findings = [{
    id: "csp_weak_policy", finding_type: "observation", severity: "critical",
    score_impact: -100, module: "headers",
  }];
  const observationWebsite = byKey(resolveCyberMotDomainStates(observation), "website_security");
  ok("12b: critical explicit observation cannot own issue state, count or identity",
    observationWebsite.state === HEALTHY && observationWebsite.finding_count === 0 &&
    JSON.stringify(observationWebsite.finding_ids) === "[]");
}

// 12c. Finding-free evidence coverage keeps the canonical absence/failure/partial ladder.
{
  const absent = cleanComplete();
  delete absent.modules.headers;
  const absentWebsite = byKey(resolveCyberMotDomainStates(absent), "website_security");
  ok("12c: absent required evidence stays not_yet_assessed",
    absentWebsite.state === CYBER_MOT_STATES.NOT_YET_ASSESSED && absentWebsite.finding_count === 0);

  const incomplete = cleanComplete();
  incomplete.modules.headers = { incomplete: true, incomplete_reason: "origin_error_no_serviceable_response" };
  const incompleteWebsite = byKey(resolveCyberMotDomainStates(incomplete), "website_security");
  ok("12c: attempted incomplete evidence stays evidence_insufficient/degraded with exact reason",
    incompleteWebsite.state === CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT &&
    incompleteWebsite.coverage === "degraded" && incompleteWebsite.finding_count === 0 &&
    /origin error no serviceable response/.test(incompleteWebsite.summary));

  const partial = cleanComplete();
  partial.scan_quality = { status: "partial", warnings: [], modules_skipped: [] };
  const partialWebsite = byKey(resolveCyberMotDomainStates(partial), "website_security");
  ok("12c: assessed finding-free partial evidence stays provisional with backend quality",
    partialWebsite.state === CYBER_MOT_STATES.PROVISIONAL &&
    partialWebsite.coverage === "partial" && partialWebsite.finding_count === 0);
}

// 13. Brand watchlist-only candidates (no material finding) do not become active abuse.
{
  const rep = cleanComplete();
  rep.modules.brand_monitoring = { candidates: 12 };
  rep.findings = []; // watchlist permutations produce no material finding
  const r = resolveCyberMotDomainStates(rep);
  ok("13: brand with only watchlist candidates → healthy, not issue_detected",
    byKey(r, "brand_protection").state !== CYBER_MOT_STATES.ISSUE_DETECTED);
}

// 14. Attack Surface — CT/subdomain incomplete cannot produce an unqualified healthy.
{
  const rep = cleanComplete();
  rep.modules.subdomains = { incomplete: true };
  rep.modules.admin_surface_detection = { error: "timed out" };
  rep.modules.cloud_storage_discovery = { skipped: true };
  rep.modules.dns = { error: "x" };
  rep.scan_quality = { status: "complete", warnings: [], modules_skipped: ["subdomains"] };
  const r = resolveCyberMotDomainStates(rep);
  ok("14: attack surface with all relevant modules insufficient → evidence_insufficient (not healthy)",
    byKey(r, "attack_surface").state === CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT);
}

// 15. Certificates — HTTPS reachability does not imply trusted chain (limitation present, unknown preserved).
{
  const r = resolveCyberMotDomainStates(cleanComplete());
  const certs = byKey(r, "certificates_trust");
  ok("15: certificates carries the trust/OCSP/revocation-unknown limitation",
    certs.limitations.some((l) => /revocation/i.test(l) && /unknown/i.test(l)));
}

// 16. Cyber Essentials — missing answers → customer_input_required.
{
  const r = resolveCyberMotDomainStates(cleanComplete()); // no cyberEssentials passed
  ok("16: no CE answers → customer_input_required", byKey(r, "cyber_essentials_readiness").state === CYBER_MOT_STATES.CUSTOMER_INPUT_REQUIRED);
  // A CE snapshot WITHOUT answers → still customer_input_required (external signals alone never assess CE).
  const rNoAns = resolveCyberMotDomainStates(cleanComplete(), { cyberEssentials: { has_answers: false, complete: false, status: "likely_ready", top_gaps: [] } });
  ok("16: CE snapshot with no answers → customer_input_required", byKey(rNoAns, "cyber_essentials_readiness").state === CYBER_MOT_STATES.CUSTOMER_INPUT_REQUIRED);
  // PARTIAL answers (has_answers but not complete) → customer_input_required, never healthy.
  const rPartial = resolveCyberMotDomainStates(cleanComplete(), { cyberEssentials: { has_answers: true, complete: false, status: "likely_ready", top_gaps: [] } });
  ok("16: CE with PARTIAL answers → customer_input_required (never healthy)", byKey(rPartial, "cyber_essentials_readiness").state === CYBER_MOT_STATES.CUSTOMER_INPUT_REQUIRED);
  // COMPLETE questionnaire + gaps → issue_detected; a favourable 2-of-5
  // external indicator still leaves the full five-control domain insufficient.
  const r2 = resolveCyberMotDomainStates(cleanComplete(), { cyberEssentials: { has_answers: true, complete: true, status: "not_ready", top_gaps: [{},{}] } });
  ok("16: CE complete + gaps → issue_detected", byKey(r2, "cyber_essentials_readiness").state === CYBER_MOT_STATES.ISSUE_DETECTED);
  const r3 = resolveCyberMotDomainStates(cleanComplete(), { cyberEssentials: { has_answers: true, complete: true, status: "likely_ready", top_gaps: [] } });
  ok("16: CE complete + favourable 2-of-5 indicator → evidence_insufficient",
    byKey(r3, "cyber_essentials_readiness").state === CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT &&
    byKey(r3, "cyber_essentials_readiness").coverage === "partial");
}

// 17. Website Security — no web evidence does not produce healthy.
{
  const rep = cleanComplete();
  delete rep.modules.headers; delete rep.modules.ssl; delete rep.modules.dns;
  const r = resolveCyberMotDomainStates(rep);
  ok("17: website security with no web modules → not healthy", byKey(r, "website_security").state !== HEALTHY);
}

// 18. Identity — maps spoofing/login evidence; no breach/dark-web claim in copy.
{
  const rep = cleanComplete();
  rep.findings = [{ id: "identity_admin_login_exposed", finding_type: "finding", severity: "medium", score_impact: 0, module: "identity_discovery" }];
  const r = resolveCyberMotDomainStates(rep);
  const idn = byKey(r, "identity_exposure");
  ok("18: identity finding maps to identity_exposure issue_detected", idn.state === CYBER_MOT_STATES.ISSUE_DETECTED);
  ok("18: identity description never positively claims breach/credential/dark-web, and disclaims it",
    !/breach|credential|dark.?web|leaked|stealer|hibp/i.test(idn.description) &&
    /does not[\s\S]*include leaked-credential/i.test(idn.limitations.join(" ")));
}

// 19. Shadow IT — observed tech without inventory is monitoring_only, never "unauthorised".
{
  const r = resolveCyberMotDomainStates(cleanComplete());
  const s = byKey(r, "shadow_it_unmanaged_technology");
  ok("19: shadow IT is monitoring_only with observed count, never unauthorised",
    s.state === CYBER_MOT_STATES.MONITORING_ONLY && s.evidence_count > 0 &&
    !/unauthoris|unauthoriz|internal.network|endpoint|casb|edr/i.test(s.summary + " " + s.description) &&
    /approved-inventory comparison is not yet configured/i.test(s.limitations.join(" ")));
}

// 20. Zero findings → all eight still render.
{
  const r = resolveCyberMotDomainStates(cleanComplete());
  ok("20: zero findings → all eight domains still present", r.length === 8 && r.every((x) => x.domain_key && x.state));
}

console.log(`\neight-domain-coverage-state: ${pass} passed, ${fail} failed`);
if (fail) { console.error("eight-domain-coverage-state validation FAILED"); process.exit(1); }
console.log("eight-domain-coverage-state validation passed");
