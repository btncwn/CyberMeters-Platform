#!/usr/bin/env node
// Each correction is removed in turn; its named fixture must then fail.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const suite = path.join(root, "scripts/validate-launch-state-accuracy-b.js");
const cases = [
  {
    name: "CM-P1-003 live decision omitted from JSON",
    file: "workers/scan-api/src/engines/email-scan.js",
    from: 'value: dmarcEvidence.dmarc_state,\n    enumerable: true,',
    to: 'value: dmarcEvidence.dmarc_state,\n    enumerable: false,',
    failure: "CM-P1-003 decision survives JSON storage",
  },
  {
    name: "CM-P1-003 projected decision omitted from JSON",
    file: "workers/scan-api/src/engines/email-scan.js",
    from: 'value: compatibilityState,\n    enumerable: true,',
    to: 'value: compatibilityState,\n    enumerable: false,',
    failure: "CM-P1-003 projected decision survives JSON storage",
  },
  {
    name: "CM-P1-003 legacy report credited as healthy",
    file: "workers/scan-api/src/engines/security-check-domains.js",
    from: 'if (!dmarcState && moduleAssessed(report, "email_security", skippedSet)) {',
    to: 'if (false && !dmarcState && moduleAssessed(report, "email_security", skippedSet)) {',
    failure: "CM-P1-003 legacy missing decision is insufficient",
  },
  {
    name: "CM-P1-006 unvalidated candidate scored as threat",
    file: "workers/scan-api/src/engines/scoring.js",
    from: '    if (brandMod?.candidates_validated === false && !openAbuseCase) continue;\n',
    to: "",
    failure: "CM-P1-006 unvalidated candidate is not a scored threat",
  },
  // CM-P1-007: ignoring the enrichment state must break the brand decision.
  {
    name: "CM-P1-007 enrichment rows ignored when deriving the brand decision",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '    const row = rowByCandidate.get(key) || null;',
    to: '    const row = null;',
    failure: "CM-P1-007 live high-risk candidate is a scored finding",
  },
  {
    name: "CM-P1-007 unchecked candidates scored as live",
    file: "workers/scan-api/src/engines/scoring.js",
    from: '    if (!brandCandidateIsLive(c)) continue;\n',
    to: "",
    failure: "CM-P1-007 inactive critical candidate is not a finding",
  },
  {
    name: "CM-P1-007 DNS result ignored by the live test",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '  return triState(candidate.dns_resolves) === 1;',
    to: '  return true;',
    failure: "CM-P1-007 inactive critical candidate is not a finding",
  },
  {
    name: "CM-P1-007 unchecked watchlist declared validated",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '    candidates_validated: checked > 0 || openAbuseCandidates.length > 0,',
    to: '    candidates_validated: true,',
    failure: "CM-P1-007 unchecked watchlist stays unvalidated",
  },
  {
    name: "CM-P1-007 unfinished checks read as a clean watchlist",
    file: "workers/scan-api/src/engines/security-check-domains.js",
    from: '    if (brandValidation && brandPendingChecks > 0) {',
    to: '    if (false && brandValidation && brandPendingChecks > 0) {',
    failure: "CM-P1-007 partially validated watchlist stays provisional",
  },
  {
    name: "CM-P1-007 open confirmed-abuse cases ignored",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '  for (const row of caseRows) {',
    to: '  for (const row of []) {',
    failure: "CM-P1-007 open confirmed-abuse case is a finding",
  },
  {
    name: "CM-P1-007 customer-closed candidate scored",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '  if (BRAND_CLOSED_CLASSIFICATIONS.includes(String(candidate.classification || ""))) return false;',
    to: '',
    failure: "CM-P1-007 customer-closed live candidate is not a finding",
  },
  {
    name: "CM-P1-007 unreadable enrichment state trusted",
    file: "workers/scan-api/src/engines/brand-validation-state.js",
    from: '    return deriveBrandValidation(brandModule, { checkedAt, unavailable: true, reason: "enrichment_state_read_failed" });',
    to: '    return deriveBrandValidation(brandModule, { checkedAt });',
    failure: "CM-P1-007 read failure, missing database and missing workspace all fail closed",
  },
  {
    name: "CM-P1-007 case-only entries persisted as generated candidates",
    file: "workers/scan-api/src/engines/asset-persistence.js",
    from: '      if (c?.generated_this_scan === false) continue;\n',
    to: "",
    failure: "CM-P1-007 case-only entries are never re-persisted as generated candidates",
  },
  {
    name: "CM-P1-007 scan no longer merges the enrichment state",
    file: "workers/scan-api/src/engines/scan-engine.js",
    from: '    modules.brand_monitoring = await loadBrandValidationState(env, {',
    to: '    modules.brand_monitoring_enriched = await loadBrandValidationState(env, {',
    failure: "CM-P1-007 scan merges enrichment state before scoring and before the report freezes",
  },
  {
    name: "CM-P1-006 unvalidated domain declared healthy",
    file: "workers/scan-api/src/engines/security-check-domains.js",
    from: '    if (brandUnvalidated) {',
    to: '    if (false && brandUnvalidated) {',
    failure: "CM-P1-006 dashboard marks watchlist provisional",
  },
  {
    name: "CM-P1-006 absent validation decision credited as a brand finding",
    file: "workers/scan-api/src/engines/security-check-domains.js",
    from: '    if (brandValidationUnknown) {',
    to: '    if (false && brandValidationUnknown) {',
    failure: "CM-P1-006 missing candidate validation is insufficient",
  },
  {
    name: "CM-P1-006 stored report presents candidate as threat",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: 'if (!report || report?.modules?.brand_monitoring?.candidates_validated === true) return report;',
    to: 'if (true || report?.modules?.brand_monitoring?.candidates_validated === true) return report;',
    failure: "CM-P1-006 raw report candidate presented as observation",
  },
  {
    name: "CM-P1-006 stored snapshot retains candidate action",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: 'if (candidateValidation === true) return snapshot;',
    to: 'if (true || candidateValidation === true) return snapshot;',
    failure: "CM-P1-006 frozen snapshot candidate demoted without changing raw bytes",
  },
  {
    name: "CM-P1-006 repaired snapshot preserves a scored guess",
    file: "workers/scan-api/src/engines/report-snapshot.js",
    from: 'const brandScoreUnreliable = hasUnvalidatedBrandFinding(report);',
    to: 'const brandScoreUnreliable = false;',
    failure: "CM-P1-006 new snapshot withholds old candidate score",
  },
  {
    name: "CM-P1-006 old snapshot score survives the customer projection",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: '...((!sourceReport || (sourceUnavailable && converted.length > 0) || hasUnvalidatedBrandFinding(sourceReport)) ? {',
    to: '...(false ? {',
    failure: "CM-P1-006 frozen snapshot candidate demoted without changing raw bytes",
  },
  {
    name: "CM-P1-006 missing report leaves a frozen candidate threat visible",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: '  const candidateValidation = sourceReport?.modules?.brand_monitoring?.candidates_validated;',
    to: '  const candidateValidation = sourceReport ? sourceReport?.modules?.brand_monitoring?.candidates_validated : true;',
    failure: "CM-P1-006 unavailable source cannot publish old candidate threat",
  },
  {
    name: "CM-P1-006 incomplete source trusted as validated",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: '  const sourceUnavailable = candidateValidation !== true && candidateValidation !== false;',
    to: '  const sourceUnavailable = false;',
    failure: "CM-P1-006 incomplete source cannot publish old candidate threat",
  },
  {
    name: "CM-P1-006 historical scan row retains candidate score",
    file: "workers/scan-api/src/engines/phase5-evidence.js",
    from: '      brand_score_unreliable: hasUnvalidatedBrandFinding(report),',
    to: '      brand_score_unreliable: false,',
    failure: "CM-P1-006 historical candidate score withheld across scan rows",
  },
  {
    name: "CM-P1-006 missing validation decision trusted for scan score",
    file: "workers/scan-api/src/engines/brand-candidate-presentation.js",
    from: '  return report?.modules?.brand_monitoring?.candidates_validated !== true &&',
    to: '  return report?.modules?.brand_monitoring?.candidates_validated === false &&',
    failure: "CM-P1-006 historical row without validation withholds score",
  },
  // CM-P1-008: identity inventory counts.
  {
    name: "CM-P1-008 identity evidence_count reverts to the module count",
    file: "workers/scan-api/src/engines/security-check-domains.js",
    from: '      base.evidence_count = identityTotal;\n',
    to: "",
    failure: "CM-P1-008 identity inventory counts reach the summary without changing the state",
  },
  {
    name: "CM-P1-008 identity counts dropped from the summary",
    file: "workers/scan-api/src/engines/security-check-domains.js",
    from: '      const identitySummary = observed.length\n',
    to: '      const identitySummary = false\n',
    failure: "CM-P1-008 identity inventory counts reach the summary without changing the state",
  },
  // CM-P1-009: registration expiry findings.
  {
    name: "CM-P1-009 Attack Surface stops owning registration findings",
    file: "workers/scan-api/src/engines/security-check-domains.js",
    from: '|cloud_|dns_|dnssec_|whois_)/.test(f?.id || ""),',
    to: '|cloud_|dns_|dnssec_)/.test(f?.id || ""),',
    failure: "CM-P1-009 expiring registration turns Attack Surface to issue_detected",
  },
  {
    name: "CM-P1-009 registration findings never reach the report",
    file: "workers/scan-api/src/engines/whois-scan.js",
    from: '  for (const finding of whoisModule.findings) {',
    to: '  for (const finding of []) {',
    failure: "CM-P1-009 only the expiry finding reaches the report, with finding authority and no score weight",
  },
  {
    name: "CM-P1-009 unavailable registry data treated as findings",
    file: "workers/scan-api/src/engines/whois-scan.js",
    from: 'if (whoisModule.error || whoisModule.unavailable === true || whoisModule.incomplete === true',
    to: 'if (whoisModule.error || whoisModule.incomplete === true',
    failure: "CM-P1-009 unavailable, deferred or errored registries add nothing",
  },
  {
    name: "CM-P1-009 report findings lose explicit finding authority",
    file: "workers/scan-api/src/engines/whois-scan.js",
    from: '      module: "whois_intelligence",\n      finding_type: "finding",\n      score_impact: 0,',
    to: '      module: "whois_intelligence",\n      score_impact: 0,',
    failure: "CM-P1-009 only the expiry finding reaches the report, with finding authority and no score weight",
  },
  {
    name: "CM-P1-009 scan no longer appends registration findings",
    file: "workers/scan-api/src/engines/scan-engine.js",
    from: '    for (const f of whoisReportFindings(modules.whois_intelligence)) {',
    to: '    for (const f of []) {',
    failure: "CM-P1-009 scan appends registration findings to the one report array with explicit authority",
  },
  // CM-P1-010: open unauthorised-sending-source alert.
  {
    name: "CM-P1-010 email caveat disabled",
    file: "workers/scan-api/src/engines/security-check-domains.js",
    from: '  if (count <= 0) return entry;\n',
    to: '  return entry;\n',
    failure: "CM-P1-010 healthy decision is unchanged but coverage and summary name the open alert",
  },
  {
    name: "CM-P1-010 unreadable alert ledger treated as an open alert",
    file: "workers/scan-api/src/engines/security-check-domains.js",
    from: '  if (!alerts || typeof alerts !== "object" || alerts.state !== "read") return entry;',
    to: '  if (!alerts || typeof alerts !== "object") return entry;',
    failure: "CM-P1-010 zero alerts, an unreadable ledger and legacy reports stay as before",
  },
  {
    name: "CM-P1-010 alert window dropped",
    file: "workers/scan-api/src/engines/spf-corroboration.js",
    from: "             AND n.created_at >= datetime('now', '-${SPF_UNAUTHORISED_ALERT_WINDOW_DAYS} days')\n",
    to: "",
    failure: "CM-P1-010 sender alerts are read per source, tenant-scoped, within the corroboration window",
  },
  {
    name: "CM-P1-010 live-workspace guard dropped",
    file: "workers/scan-api/src/engines/spf-corroboration.js",
    from: "            JOIN workspaces w ON w.id = n.workspace_id AND w.deleted_at IS NULL\n",
    to: "",
    failure: "CM-P1-010 sender alerts are read per source, tenant-scoped, within the corroboration window",
  },
  {
    name: "CM-P1-010 read failure presented as a clean ledger",
    file: "workers/scan-api/src/engines/spf-corroboration.js",
    from: '    return unavailable("alert_read_failed");',
    to: '    return { ...base, state: "read", reason: null, count: 0, source_ips: [], latest_at: null, highest_severity: null, outside_authorisation: 0, comparison_unavailable: 0 };',
    failure: "CM-P1-010 read failure, missing database and missing workspace never fabricate an alert",
  },
  {
    name: "CM-P1-010 uncompared sources claimed as outside the authorisation",
    file: "workers/scan-api/src/engines/spf-corroboration.js",
    from: '    const outside = ips.filter((ip) => [SPF_CORROBORATION_TIER.UNAUTHORISED_CONFIRMED, SPF_CORROBORATION_TIER.UNAUTHORISED_SOFT_POLICY].includes(latestTierByIp.get(ip))).length;',
    to: '    const outside = ips.length;',
    failure: "CM-P1-010 sender alerts are read per source, tenant-scoped, within the corroboration window",
  },
  {
    name: "CM-P1-010 caveat wording ignores the comparison tier",
    file: "workers/scan-api/src/engines/security-check-domains.js",
    from: '  if (outside > 0) detail.push(`${outside} outside your resolved SPF authorisation`);',
    to: '  detail.push(`${count} outside your resolved SPF authorisation`);',
    failure: "CM-P1-010 a source whose comparison was unavailable is never called unauthorised",
  },
  {
    name: "CM-P1-010 scan no longer attaches the alert summary",
    file: "workers/scan-api/src/engines/scan-engine.js",
    from: '      modules.email_security.unauthorised_sending_sources = await loadUnauthorisedSendingSourceAlerts(env, {',
    to: '      modules.email_security.unauthorised_sending_sources_unused = await loadUnauthorisedSendingSourceAlerts(env, {',
    failure: "CM-P1-010 scan attaches the alert summary before the report freezes",
  },
  {
    name: "Shadow IT CNAME inputs excluded from absence gate",
    file: "workers/scan-api/src/engines/vendor-relationship.js",
    from: '  return headersOk && techOk && cnameSourcesOk;',
    to: '  return headersOk && techOk;',
    failure: "Shadow IT subdomain_takeover absent preserves CNAME supplier",
  },
  {
    name: "Shadow IT partial DNS lookup credited as complete",
    file: "workers/scan-api/src/engines/vendor-relationship.js",
    from: '          !(source.not_asked > 0 || source.lookup_failed > 0)) &&',
    to: '          true) &&',
    failure: "Shadow IT dns_bruteforce partial coverage preserves CNAME supplier",
  },
  {
    name: "Shadow IT capped exposure credited as complete",
    file: "workers/scan-api/src/engines/vendor-relationship.js",
    from: '          !(source.probe_coverage?.cap_reached === true || source.probe_coverage?.dropped_count > 0));',
    to: '          true);',
    failure: "Shadow IT asset_exposure partial coverage preserves CNAME supplier",
  },
  {
    name: "Shadow IT takeover CNAME observations ignored",
    file: "workers/scan-api/src/engines/vendor-relationship.js",
    from: '    for (const observation of (modules?.subdomain_takeover?.cname_observations || [])) {\n      if (observation?.cname) cnames.push(observation.cname.toLowerCase());\n    }\n',
    to: '',
    failure: "Shadow IT takeover CNAME observation preserves supplier detection",
  },
  {
    name: "Shadow IT discovered CNAME chain ignored",
    file: "workers/scan-api/src/engines/vendor-relationship.js",
    from: '      for (const hop of (item?.dns?.cname_chain || [])) {\n        if (hop?.target) cnames.push(hop.target.toLowerCase());\n      }\n',
    to: '',
    failure: "Shadow IT discovered DNS CNAME chain preserves supplier detection",
  },
  {
    name: "CM-P1-011 missing HSTS ignores the observed redirect",
    file: "workers/scan-api/src/engines/scoring.js",
    from: "        const redirectObserved = modules.ssl?.http_redirects_to_https === true;",
    to: "        const redirectObserved = false;",
    failure: "CM-P1-011 missing HSTS with an observed redirect is medium",
  },
  {
    name: "CM-P1-012 weak-CSP description repeats the classifier detail",
    file: "workers/scan-api/src/engines/scoring.js",
    from: "does little to stop injected scripts.`",
    to: "does little to stop injected scripts. ${csp.details}.`",
    failure: "CM-P1-012 weak CSP description names the directive once",
  },
  {
    name: "CM-P1-013 BRI ignores the HSTS finding's severity",
    file: "workers/scan-api/src/engines/business-risk.js",
    from: "  brsModuleData.hstsMissingSeverity = hstsMissingSeverity(findings.filter(isActionableFinding));\n",
    to: "",
    failure: "CM-P1-013 missing HSTS with an observed redirect deducts 10 from Website Trust",
  },
  {
    name: "C21 verified scan scope bypassed",
    file: "workers/scan-api/src/engines/brand-dns-enrichment.js",
    from: '  if (verified !== true || brandModule?.error || brandModule?.validation?.state === "unavailable"',
    to: '  if (false || brandModule?.error || brandModule?.validation?.state === "unavailable"',
    failure: "C21 unverified scope publishes no DNS observations",
  },
  {
    name: "C21 MX resolver failure treated as absence",
    file: "workers/scan-api/src/engines/brand-dns-enrichment.js",
    from: '    if (![0, 3].includes(mx?.Status)) return null;', to: '',
    failure: "C21 DNS failures stay unavailable",
  },
  {
    name: "C21 Null MX treated as mail capability",
    file: "workers/scan-api/src/engines/brand-dns-enrichment.js",
    from: '      if (parts[1] === "0" && parts[2] === ".") { nullMx = true; continue; }',
    to: '      if (parts[1] === "0" && parts[2] === ".") { present = true; continue; }',
    failure: "C21 Null MX is never mail capability",
  },
  {
    name: "C21 expired DNS receipts treated as current",
    file: "workers/scan-api/src/engines/brand-dns-enrichment.js",
    from: '|| at - observed > BRAND_DNS_RECHECK_AFTER_MS', to: '|| false',
    failure: "C21 stale DNS receipts cannot become current facts",
  },
  {
    name: "C21 foreign protected domain admitted",
    file: "workers/scan-api/src/engines/brand-dns-enrichment.js",
    from: 'receipt.protected_domain !== scope ||', to: '',
    failure: "C21 foreign scope publishes no DNS observations",
  },
  {
    name: "C21 observation becomes an actionable finding",
    file: "workers/scan-api/src/engines/brand-dns-enrichment.js",
    from: 'title: "Live lookalike DNS observations", finding_type: "observation", severity: "info", score_impact: 0,',
    to: 'title: "Live lookalike DNS observations", finding_type: "finding", severity: "info", score_impact: 0,',
    failure: "C21 DNS observations are qualified and non-scored",
  },
  {
    name: "C21 observation output cap removed",
    file: "workers/scan-api/src/engines/brand-dns-enrichment.js",
    from: 'for (const receipt of brandModule.watchlist_dns.slice(0, 20))',
    to: 'for (const receipt of brandModule.watchlist_dns)',
    failure: "C21 report observations stay bounded",
  },
  {
    name: "C22 unverified workspace metadata request admitted", file: "workers/scan-api/src/engines/identity-oidc-observation.js",
    from: 'if (!root || opts.verified !== true)', to: 'if (!root)', failure: "C22 unverified scope issues no requests",
  },
  {
    name: "C22 mismatched issuer accepted", file: "workers/scan-api/src/engines/identity-oidc-observation.js",
    from: '![`https://${host}`, `https://${host}/`].includes(document.issuer)', to: 'false', failure: "C22 issuer identity must match the requested root issuer",
  },
  {
    name: "C22 own-host request cap removed", file: "workers/scan-api/src/engines/identity-oidc-observation.js",
    from: '.slice(0, OIDC_LIMITS.hosts);', to: ';', failure: "C22 requests stay on two own hosts and never visit advertised endpoints",
  },
  {
    name: "C22 endpoint query values retained", file: "workers/scan-api/src/engines/identity-oidc-observation.js",
    from: '  authorization.search = "";', to: '', failure: "C22 endpoint query values are never retained",
  },
  {
    name: "C22 metadata body limit removed", file: "workers/scan-api/src/engines/identity-oidc-observation.js",
    from: 'if (bytes > OIDC_LIMITS.bytes) return null;', to: '', failure: "C22 oversized metadata is rejected before publication",
  },
  {
    name: "C22 redirects followed off-domain", file: "workers/scan-api/src/engines/identity-oidc-observation.js",
    from: 'maxHops: 0, timeoutMs: 1000', to: 'maxHops: 3, timeoutMs: 1000', failure: "C22 canonical safe fetch never follows an off-domain redirect",
  },
  {
    name: "C22 observed metadata becomes actionable finding", file: "workers/scan-api/src/engines/identity-oidc-observation.js",
    from: 'finding_type: "observation", score_impact: 0, confidence: 90,', to: 'finding_type: "finding", score_impact: 0, confidence: 90,',
    failure: "C22 published issuer and sign-in metadata are qualified non-scored facts",
  },
  {
    name: "C23 unverified script publication admitted", file: "workers/scan-api/src/engines/website-script-observations.js",
    from: 'if (verified !== true || tech?.error', to: 'if (tech?.error', failure: "C23 unverified foreign or incomplete observations never publish",
  },
  {
    name: "C23 owned child host declared external", file: "workers/scan-api/src/engines/website-script-observations.js",
    from: 'outside_domain: !ownHost(url.hostname, root)', to: 'outside_domain: true', failure: "C23 same-domain child hosts are not asserted external",
  },
  {
    name: "C23 integrity declarations ignored", file: "workers/scan-api/src/engines/website-script-observations.js",
    from: 'integrity_declared: Boolean(attrs.get("integrity")?.trim())', to: 'integrity_declared: false', failure: "C23 actual first attributes win and ambiguous quoted tags are omitted",
  },
  {
    name: "C23 advisory fixed release included", file: "workers/scan-api/src/engines/website-script-observations.js",
    from: 'compare(versionParts(library.version), versionParts(row.fixed)) < 0', to: 'compare(versionParts(library.version), versionParts(row.fixed)) <= 0', failure: "C23 advisory fixed boundaries are excluded",
  },
  {
    name: "C23 advisory lower boundary removed", file: "workers/scan-api/src/engines/website-script-observations.js",
    from: 'compare(versionParts(library.version), versionParts(row.introduced)) >= 0', to: 'true', failure: "C23 advisory lower boundaries are respected",
  },
  {
    name: "C23 script output cap removed", file: "workers/scan-api/src/engines/website-script-observations.js",
    from: 'return scripts.length < SCRIPT_LIMITS.scripts;', to: 'return true;', failure: "C23 script output is capped",
  },
  {
    name: "C23 HTML analysis cap removed", file: "workers/scan-api/src/engines/website-script-observations.js",
    from: '.slice(0, SCRIPT_LIMITS.html_chars)', to: '', failure: "C23 HTML analysis window is capped",
  },
  {
    name: "C23 duplicate final attribute replaces browser first attribute", file: "workers/scan-api/src/engines/website-script-observations.js",
    from: 'if (!out.has(key)) out.set(key, value);', to: 'out.set(key, value);', failure: "C23 actual first attributes win and ambiguous quoted tags are omitted",
  },
  {
    name: "C23 script observations become actionable findings", file: "workers/scan-api/src/engines/website-script-observations.js",
    from: 'finding_type: "observation", score_impact: 0, confidence: 75,', to: 'finding_type: "finding", score_impact: 0, confidence: 75,', failure: "C23 script hosts integrity and advisory labels produce three zero-impact observations",
  },
  {
    name: "C23 raw-text context protection bypassed", file: "workers/scan-api/src/engines/page-discovery.js",
    from: '(quotedAttributes ? STRICT_RAW_TEXT_TAGS : RAW_TEXT_TAGS).has(name)',
    to: 'RAW_TEXT_TAGS.has(name)', failure: "C23 raw-text and RCDATA strings cannot invent script elements",
  },
  {
    name: "C23 quote-aware traversal bypassed", file: "workers/scan-api/src/engines/website-script-observations.js",
    from: '    return scripts.length < SCRIPT_LIMITS.scripts;\n  }, { quotedAttributes: true });',
    to: '    return scripts.length < SCRIPT_LIMITS.scripts;\n  });', failure: "C23 quoted outer attributes cannot invent script facts",
  },
];

function run() {
  try {
    return { passed: true, output: execFileSync(process.execPath, [suite], {
      cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    }) };
  } catch (error) {
    return { passed: false, output: String(error.stdout ?? "") + String(error.stderr ?? "") };
  }
}
const baseline = run();
if (!baseline.passed) {
  console.error("Baseline fixture failed:\n" + baseline.output);
  process.exit(1);
}
let killed = 0;
for (const mutant of cases) {
  const filename = path.join(root, mutant.file);
  const original = fs.readFileSync(filename, "utf8");
  const matches = original.split(mutant.from).length - 1;
  if (matches !== 1) {
    console.error(`ANCHOR FAILURE ${mutant.name}: ${matches} matches`);
    continue;
  }
  let result;
  try {
    fs.writeFileSync(filename, original.replace(mutant.from, mutant.to));
    result = run();
  } finally {
    fs.writeFileSync(filename, original);
  }
  const namedFailure = result.output.split("\n").some((line) => line.startsWith(`FAIL ${mutant.failure}`));
  const complete = /Launch state accuracy fixtures: \d+\/\d+ passed/.test(result.output);
  const success = !result.passed && namedFailure && complete && fs.readFileSync(filename, "utf8") === original;
  console.log(`${success ? "KILLED" : "SURVIVED"} ${mutant.name}`);
  if (!success) console.error(result.output.slice(-1200));
  if (success) killed++;
}
console.log(`Launch state accuracy mutations: ${killed}/${cases.length} killed`);
if (killed !== cases.length) process.exit(1);
