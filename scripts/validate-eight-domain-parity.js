#!/usr/bin/env node
//
// Eight-domain Cyber MOT PARITY — behavioural + static proof of the parity patch:
// (A) Cyber Essentials shows the SAME state on every surface because all four
//     producers (scan /report, executive-report-v2, executive PDF, dashboard
//     /cyber-mot-domains) pass the SAME canonical CE snapshot
//     (getCyberEssentialsSnapshot) into the SAME resolver;
// (B) the Dashboard renders all eight domains even with NO scan (no-scan states,
//     unconditional <CyberMotDomains> render, endpoint no-scan fallback);
// (C) per-domain healthy-eligibility — a domain is assessed_healthy ONLY when its
//     own required evidence was collected on a complete scan; insufficient/absent
//     required evidence or a provisional scan never renders healthy.
// Node 24+. CI-blocking.
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { healthyMonitoringStates } from "./lib/monitoring-fixture.mjs";
// CI carries the cross-page honesty regressions through this existing validator.
import "./honesty-contradictions-regression.js";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginesDir = path.join(root, "workers", "scan-api", "src", "engines");
const routesDir = path.join(root, "workers", "scan-api", "src", "routes");
const { resolveCyberMotDomainStates, CYBER_MOT_DOMAINS, CYBER_MOT_STATES } =
  await import(pathToFileURL(path.join(enginesDir, "cyber-mot-domains.js")).href);
const { getCyberEssentialsSnapshot } =
  await import(pathToFileURL(path.join(enginesDir, "ce-readiness.js")).href);
const { executiveDashboardRoutes } =
  await import(pathToFileURL(path.join(routesDir, "executive-dashboard.js")).href);
const { getCurrentPosturePresentation } =
  await import(pathToFileURL(path.join(enginesDir, "current-posture.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const byKey = (arr, k) => arr.find((x) => x.domain_key === k);
const KEYS = ["email_protection","brand_protection","attack_surface","certificates_trust","cyber_essentials_readiness","website_security","identity_exposure","shadow_it_unmanaged_technology"];
const HEALTHY = CYBER_MOT_STATES.ASSESSED_HEALTHY;
const healthyMonitoring = () => healthyMonitoringStates();

// A complete scan, all required+relevant modules assessed cleanly, no findings.
const cleanComplete = () => ({
  scan_id: "scan_parity", completed_at: "2026-07-14T10:00:00Z",
  scan_quality: { status: "complete", warnings: [], modules_skipped: [] },
  modules: {
    email_security: { dmarc_state: { enforcement_level: "reject_enforced" } }, dns: {},
    brand_monitoring: { candidates_validated: true, candidates: [] },
    ssl: { https_available: true, https_probe_executed: true },
    headers: {},
    subdomains: { count: 2 }, admin_surface_detection: {}, cloud_storage_discovery: {},
    certificate_intelligence: {}, identity_discovery: {},
    saas_exposure: { count: 1 }, technology_detection: { count: 3 },
  },
  monitoring_states: healthyMonitoring(),
  findings: [],
});

// ════ SECTION A — Cyber Essentials cross-surface parity ═══════════════════════

// A1. Workspace WITHOUT answers → customer_input_required on every surface.
{
  const r = resolveCyberMotDomainStates(cleanComplete(), { cyberEssentials: { has_answers: false, status: null, top_gaps: [] } });
  ok("A1: CE snapshot without answers → customer_input_required",
    byKey(r, "cyber_essentials_readiness").state === CYBER_MOT_STATES.CUSTOMER_INPUT_REQUIRED);
}

// A2. Workspace with a COMPLETE questionnaire → gaps remain issues; a
// favourable 2-of-5 external indicator cannot make the full domain healthy.
{
  const ready = resolveCyberMotDomainStates(cleanComplete(), { cyberEssentials: { has_answers: true, complete: true, status: "likely_ready", top_gaps: [] } });
  ok("A2: CE complete + favourable 2-of-5 indicator → evidence_insufficient",
    byKey(ready, "cyber_essentials_readiness").state === CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT &&
    byKey(ready, "cyber_essentials_readiness").coverage === "partial");
  const gaps = resolveCyberMotDomainStates(cleanComplete(), { cyberEssentials: { has_answers: true, complete: true, status: "not_ready", top_gaps: [{}, {}] } });
  ok("A2: CE complete + not_ready + gaps → issue_detected",
    byKey(gaps, "cyber_essentials_readiness").state === CYBER_MOT_STATES.ISSUE_DETECTED &&
    byKey(gaps, "cyber_essentials_readiness").finding_count === 2);
}

// A2b. A PARTIAL questionnaire (answers present but not complete) → customer_input_required,
// NEVER healthy — a single/partial answer set must not permit assessed_healthy.
{
  const partialReady = resolveCyberMotDomainStates(cleanComplete(), { cyberEssentials: { has_answers: true, complete: false, status: "likely_ready", top_gaps: [] } });
  ok("A2b: CE partial answers + likely_ready → customer_input_required (never healthy)",
    byKey(partialReady, "cyber_essentials_readiness").state === CYBER_MOT_STATES.CUSTOMER_INPUT_REQUIRED);
}

// A3. Determinism/parity — four surfaces passing the SAME snapshot get the SAME CE state.
{
  const snapshot = { has_answers: true, complete: true, status: "likely_ready", top_gaps: [] };
  const states = [1, 2, 3, 4].map(() =>
    byKey(resolveCyberMotDomainStates(cleanComplete(), { cyberEssentials: snapshot }), "cyber_essentials_readiness").state);
  ok("A3: four surfaces with the same CE snapshot resolve the same CE state",
    states.every((s) => s === states[0]), `got [${states.join(", ")}]`);
}

// A4. STATIC — all four surface producers pass a canonical CE snapshot into the resolver.
{
  // M5.d: the scan report routes and PDF builders render the canonical
  // SNAPSHOT, whose builder passes the ONE CE snapshot into the resolver
  // (report-snapshot.js). The parity guarantee moved up a level: all report
  // surfaces render the same frozen resolver output by construction.
  const scansSrc = await fs.readFile(path.join(routesDir, "scans.js"), "utf8");
  ok("A4: scans.js report surfaces consume the canonical snapshot (no live resolver)",
    scansSrc.includes("readScanReportSnapshot") && !scansSrc.includes("resolveCyberMotDomainStates"));

  const pdfSrc = await fs.readFile(path.join(enginesDir, "pdf.js"), "utf8");
  ok("A4: pdf.js renders snapshot domains (no live resolver, no CE fetch)",
    pdfSrc.includes("sectionDomains") && !pdfSrc.includes("resolveCyberMotDomainStates") && !pdfSrc.includes("getCyberEssentialsSnapshot"));

  const rsSrc = await fs.readFile(path.join(enginesDir, "report-snapshot.js"), "utf8");
  ok("A4: the snapshot builder passes cyberEssentials: into the resolver (the one place)",
    rsSrc.includes("cyberEssentials:") && rsSrc.includes("resolveCyberMotDomainStates("));

  const dashSrc = await fs.readFile(path.join(routesDir, "executive-dashboard.js"), "utf8");
  ok("A4: executive-dashboard.js uses getCyberEssentialsSnapshot", dashSrc.includes("getCyberEssentialsSnapshot"));
  ok("A4: executive-dashboard.js /cyber-mot-domains endpoint passes cyberEssentials: into the resolver",
    dashSrc.includes("cyber-mot-domains") && dashSrc.includes("cyberEssentials:") && dashSrc.includes("resolveCyberMotDomainStates("));
}

// A5. BEHAVIOURAL — getCyberEssentialsSnapshot gates on real answer rows in D1.
{
  const db = new DatabaseSync(":memory:");
  db.exec(`CREATE TABLE cyber_essentials_answers (
    workspace_id TEXT, control_key TEXT, question_key TEXT, answer TEXT
  )`);
  db.prepare("INSERT INTO cyber_essentials_answers VALUES (?, ?, ?, ?)")
    .run("ws_with_answers", "boundary_protection", "q1", "yes");
  db.prepare("INSERT INTO cyber_essentials_answers VALUES (?, ?, ?, ?)")
    .run("ws_with_answers", "access_control", "q2", "no");
  const env = {
    cybermeters_db: {
      prepare(sql) {
        return {
          bind(...a) {
            return {
              first: async () => db.prepare(sql).get(...a) ?? null,
              all: async () => ({ results: db.prepare(sql).all(...a) }),
            };
          },
        };
      },
    },
  };
  const none = await getCyberEssentialsSnapshot("ws_no_answers", env);
  ok("A5: workspace with 0 answer rows → has_answers === false && complete === false", none.has_answers === false && none.complete === false);
  const some = await getCyberEssentialsSnapshot("ws_with_answers", env);
  ok("A5: workspace with a PARTIAL answer set → has_answers true but complete === false",
    some.has_answers === true && some.complete === false);

  // Seed a COMPLETE questionnaire (every real CE question answered non-'unknown').
  const { CE_QUESTIONS } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "cyber-essentials.js")).href);
  for (const ctrl of CE_QUESTIONS) {
    for (const q of ctrl.questions) {
      db.prepare("INSERT INTO cyber_essentials_answers VALUES (?, ?, ?, ?)").run("ws_complete", ctrl.control_key, q.key, "yes");
    }
  }
  const full = await getCyberEssentialsSnapshot("ws_complete", env);
  ok("A5: workspace with a COMPLETE questionnaire → complete === true", full.complete === true);
  // Remove ONE answer → no longer complete.
  db.prepare("DELETE FROM cyber_essentials_answers WHERE workspace_id = ? AND control_key = ? AND question_key = ?")
    .run("ws_complete", CE_QUESTIONS[0].control_key, CE_QUESTIONS[0].questions[0].key);
  const minusOne = await getCyberEssentialsSnapshot("ws_complete", env);
  ok("A5: removing one answer makes complete === false", minusOne.complete === false);
  db.close();
}

// ════ SECTION B — Dashboard no-scan visibility ═════════════════════════════════

// B1. resolver(null) → all eight, explicit non-null states, none healthy, canonical order.
{
  const r = resolveCyberMotDomainStates(null);
  ok("B1: no scan → exactly eight entries", r.length === 8);
  ok("B1: no scan → every entry has non-null domain_key + state", r.every((x) => x.domain_key && x.state));
  ok("B1: no scan → zero domains assessed_healthy", r.every((x) => x.state !== HEALTHY));
  ok("B1: no scan → order matches the canonical key order", r.map((x) => x.domain_key).join(",") === KEYS.join(","));
}

// B2. STATIC — the endpoint exists and falls back to resolver(null) on failure.
{
  const dashSrc = await fs.readFile(path.join(routesDir, "executive-dashboard.js"), "utf8");
  ok("B2: /api/workspaces/:id/cyber-mot-domains endpoint exists",
    /cyber-mot-domains/.test(dashSrc) && /url\.pathname\.match\([\s\S]{0,120}?cyber-mot-domains/.test(dashSrc));
  ok("B2: endpoint catch path returns resolveCyberMotDomainStates(null)",
    /catch[\s\S]{0,300}resolveCyberMotDomainStates\(null\)/.test(dashSrc));
}

// B3. STATIC — Dashboard.jsx renders the eight-area PostureCard UNCONDITIONALLY
// (clean app shell, 16 Oct 2026: the home screen's eight-area surface); the
// workspace overview still renders <CyberMotDomains unconditionally.
{
  const jsx = await fs.readFile(path.join(root, "frontend", "src", "pages", "Dashboard.jsx"), "utf8");
  ok("B3: Dashboard.jsx renders <PostureCard", jsx.includes("<PostureCard"));
  ok("B3: Dashboard.jsx does NOT gate the panel behind report?.cyber_mot_domains &&",
    !jsx.includes("report?.cyber_mot_domains &&"));
  // One home per thing (17 Oct 2026): the separate workspace overview is dissolved;
  // /ws/dashboard redirects and Overview's PostureCard is the one eight-area surface.
  const app = await fs.readFile(path.join(root, "frontend", "src", "App.jsx"), "utf8");
  ok("B3: the workspace overview is dissolved — /ws/dashboard redirects to /ws/members", /path="ws\/dashboard"\s+element=\{<Navigate to="\/ws\/members" replace \/>\}/.test(app));
  ok("B3: no second workspace overview page exists", !app.includes("WorkspaceDashboard"));
}

// B4. A newer provisional TLS assessment must supply the grid's evidence even
// when an older complete scan still supplies the last authoritative score.
{
  const older = { scan_id: "scan-older", score: 82, rating: "good",
    scan_quality: "complete", created_at: "2026-10-12T22:32:00Z" };
  const newer = { scan_id: "scan-newer", score: 100, rating: "excellent",
    scan_quality: "partial", created_at: "2026-10-14T01:48:00Z" };
  const oldReport = cleanComplete();
  oldReport.scan_id = older.scan_id;
  oldReport.modules = {
    ...oldReport.modules,
    technology_detection: {
      technologies: ["nginx"],
      technology_fingerprints: [{ technology: "nginx", source: "server", confidence: 90 }],
      serviceability_contract: { serviceable: true, conclusion_class: "conclusive", reason: "origin_response_serviceable" },
    },
    cve_intelligence: { technologies_checked: ["nginx"], lookup_statuses: { nginx: { status: "complete" } },
      results: {}, total_cves: 0, critical_count: 0, high_count: 0, cve_coverage: "complete", source: "nvd_api" },
    known_exploited_vulnerabilities: { matches: [] },
    email_security_intelligence: { email_security_score: 100 },
  };
  const newReport = { ...cleanComplete(), scan_id: newer.scan_id,
    scan_quality: { status: "partial", modules_skipped: [] },
    modules: { ...cleanComplete().modules,
      tls_assessment: { quality: "partial", coverage: { completed: 1, uncertain: 1 } } } };
  const reportById = { [older.scan_id]: oldReport, [newer.scan_id]: newReport };
  const env = {
    cybermeters_db: { prepare(sql) { return { bind() { return {
      all: async () => ({ results: sql.includes("s.scan_quality='complete'") ? [older] : [] }),
      first: async () => sql.includes("FROM scans s") ? newer
        : sql.includes("FROM shadow_it_inventory") ? { n: 1 } : null,
    }; } }; } },
    cybermeters_reports: { get: async (key) => {
      const id = key.match(/^reports\/(.+)\.json$/)?.[1];
      return reportById[id] ? { json: async () => reportById[id] } : null;
    } },
  };
  const posture = await getCurrentPosturePresentation(env, { workspaceId: "ws-parity" });
  ok("B4 fixture keeps the older score authoritative and the newer scan provisional",
    posture.authoritative_scan_id === older.scan_id && posture.latest_provisional_scan_id === newer.scan_id);
  const url = new URL("https://api.cybermeters.com/api/workspaces/ws-parity/cyber-mot-domains");
  const response = await executiveDashboardRoutes({ request: new Request(url), env, url,
    json: (body, status = 200) => Response.json(body, { status }),
    requireAuth: async () => ({ id: "founder" }), requireWorkspaceRole: async () => true,
    serverError: (_area, error) => { throw error; },
  });
  const body = await response.json();
  ok("B4 grid selects the newer provisional scan's evidence", body.source_scan_id === newer.scan_id);
  ok("B4 incomplete TLS cannot read Healthy from the older complete scan",
    byKey(body.cyber_mot_domains, "certificates_trust")?.state === CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT);
}

// ════ SECTION C — Per-domain healthy-eligibility matrix ════════════════════════

const SCAN_DOMAINS = ["email_protection","brand_protection","attack_surface","certificates_trust","website_security","identity_exposure"];
const ACTIONABLE_FIXTURES = Object.freeze({
  email_protection: { id: "email_dmarc_missing", module: "email_security" },
  brand_protection: { id: "brand_candidate_active", module: "brand_monitoring" },
  attack_surface: { id: "admin_surface_critical", module: "admin_surface_detection" },
  certificates_trust: { id: "certificate_expiring_soon", module: "certificate_intelligence" },
  website_security: { id: "dse_hsts_short_maxage", module: "domain_security_enrichment" },
  identity_exposure: { id: "identity_admin_login_exposed", module: "identity_discovery" },
});
for (const key of SCAN_DOMAINS) {
  const cfg = CYBER_MOT_DOMAINS.find((d) => d.domain_key === key);
  ok(`C ${key}: domain config has a non-empty required list`, Array.isArray(cfg?.required) && cfg.required.length > 0);
  const required = cfg?.required || [];
  // Fixture with every required module for THIS domain present (brand_monitoring is
  // not in the base fixture, so ensure it here for brand_protection).
  const withRequired = () => {
    const rep = cleanComplete();
    for (const m of required) if (!rep.modules[m]) rep.modules[m] = {};
    return rep;
  };

  // Healthy path: complete scan + required evidence + no finding → assessed_healthy.
  {
    const r = resolveCyberMotDomainStates(withRequired());
    const expected = key === "identity_exposure" ? CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT : HEALTHY;
    ok(`C ${key}: clean complete scan → ${expected}`, byKey(r, key).state === expected,
      `got ${byKey(r, key).state}`);
  }

  // Insufficient path: one required module errored → never healthy (evidence_insufficient).
  {
    const rep = withRequired();
    rep.modules[required[0]] = { error: "x" };
    const s = byKey(resolveCyberMotDomainStates(rep), key).state;
    ok(`C ${key}: required module '${required[0]}' errored → not healthy`, s !== HEALTHY, `got ${s}`);
    ok(`C ${key}: required module '${required[0]}' errored → evidence_insufficient`,
      s === CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT, `got ${s}`);
  }

  // Absent path: one required module never ran → never healthy (not_yet_assessed).
  {
    const rep = withRequired();
    delete rep.modules[required[0]];
    const s = byKey(resolveCyberMotDomainStates(rep), key).state;
    ok(`C ${key}: required module '${required[0]}' absent → not healthy`, s !== HEALTHY, `got ${s}`);
    const expected = key === "identity_exposure"
      ? CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT
      : CYBER_MOT_STATES.NOT_YET_ASSESSED;
    ok(`C ${key}: required module '${required[0]}' absent → ${expected}`,
      s === expected, `got ${s}`);
  }

  // Partial-quality scan: all required evidence present, no finding → provisional, never healthy.
  {
    const rep = withRequired();
    rep.scan_quality = { status: "partial", warnings: [], modules_skipped: [] };
    const s = byKey(resolveCyberMotDomainStates(rep), key).state;
    const expected = key === "identity_exposure"
      ? CYBER_MOT_STATES.EVIDENCE_INSUFFICIENT
      : CYBER_MOT_STATES.PROVISIONAL;
    ok(`C ${key}: partial-quality scan → ${expected}, never healthy`,
      s === expected && s !== HEALTHY, `got ${s}`);
  }

  // Explicit low, score-neutral findings are authoritative in every scan-evidenced
  // domain. Severity never substitutes for the producer-owned finding type.
  {
    const fixture = ACTIONABLE_FIXTURES[key];
    const row = {
      ...fixture, finding_type: "finding", severity: "low", score_impact: 0,
      recommendation: "Use the canonical remediation.",
    };
    const rep = withRequired();
    rep.findings = [row];
    const state = byKey(resolveCyberMotDomainStates(rep), key);
    ok(`C ${key}: explicit low score-neutral finding owns issue state/count/identity`,
      state.state === CYBER_MOT_STATES.ISSUE_DETECTED && state.coverage === "complete" &&
      state.finding_count === 1 && JSON.stringify(state.finding_ids) === JSON.stringify([fixture.id]),
      `got ${JSON.stringify(state)}`);

    const incomplete = withRequired();
    incomplete.modules[required[0]] = {
      ...incomplete.modules[required[0]], incomplete: true, incomplete_reason: "focused_incomplete",
    };
    incomplete.findings = [row];
    const caveated = byKey(resolveCyberMotDomainStates(incomplete), key);
    ok(`C ${key}: actionable finding stays positive-first under required-evidence failure`,
      caveated.state === CYBER_MOT_STATES.ISSUE_DETECTED && caveated.coverage === "partial" &&
      caveated.finding_count === 1 && JSON.stringify(caveated.finding_ids) === JSON.stringify([fixture.id]),
      `got ${JSON.stringify(caveated)}`);

    const observation = withRequired();
    observation.findings = [{
      ...fixture, finding_type: "observation", severity: "critical", score_impact: -100,
    }];
    const refused = byKey(resolveCyberMotDomainStates(observation), key);
    ok(`C ${key}: critical explicit observation owns no issue/count/identity`,
      refused.state !== CYBER_MOT_STATES.ISSUE_DETECTED && refused.finding_count === 0 &&
      JSON.stringify(refused.finding_ids) === "[]", `got ${JSON.stringify(refused)}`);
  }
}

// C-final. Certificates healthy still carries the honest revocation/unknown limitation.
{
  const r = resolveCyberMotDomainStates(cleanComplete());
  const certs = byKey(r, "certificates_trust");
  ok("C certificates_trust: healthy verdict retains the revocation-unknown limitation",
    certs.state === HEALTHY && certs.limitations.some((l) => /revocation/i.test(l) && /unknown/i.test(l)));
}

// ── SECTION D — Dashboard endpoint-FAILURE resilience (never fewer than eight) ──
// When the /cyber-mot-domains request fails or returns malformed data, the frontend
// display helper must still render all eight canonical domains in a non-healthy
// "unavailable" state — no domain disappears and none becomes healthy.
{
  const { resolveDisplayDomains, CYBER_MOT_DISPLAY_ORDER } =
    await import(pathToFileURL(path.join(root, "frontend", "src", "lib", "cyberMotDisplay.js")).href);

  const displayKeys = ['email_protection', 'attack_surface', 'website_security', 'identity_exposure', 'shadow_it_unmanaged_technology', 'certificates_trust', 'brand_protection', 'cyber_essentials_readiness'];
  ok("D: display order has all eight canonical domain keys",
    CYBER_MOT_DISPLAY_ORDER.length === 8 && [...CYBER_MOT_DISPLAY_ORDER.map((d) => d.domain_key)].sort().join(",") === [...KEYS].sort().join(","));
  ok("D: display order follows the founder service order",
    CYBER_MOT_DISPLAY_ORDER.map((d) => d.domain_key).join(",") === displayKeys.join(","));

  for (const [label, input] of [["null", null], ["undefined", undefined], ["empty array", []], ["malformed (missing state)", [{ domain_key: "email_protection" }]], ["short array", [{ domain_key: "email_protection", state: "assessed_healthy" }]]]) {
    const out = resolveDisplayDomains(input);
    ok(`D: endpoint failure (${label}) → exactly eight domains`, Array.isArray(out) && out.length === 8);
    ok(`D: endpoint failure (${label}) → no domain is assessed_healthy`, out.every((d) => d.state !== HEALTHY));
    ok(`D: endpoint failure (${label}) → presentation order + every key present`, out.map((d) => d.domain_key).join(",") === displayKeys.join(","));
  }

  // Reorder the view only: every server object and the original array remain unchanged.
  const valid = resolveCyberMotDomainStates(cleanComplete());
  const original = JSON.stringify(valid);
  const passthrough = resolveDisplayDomains(valid);
  ok("D: a valid eight-entry server set follows presentation order", passthrough.map((d) => d.domain_key).join(",") === displayKeys.join(","));
  ok("D: reordering preserves every server object and leaves input untouched",
    JSON.stringify(valid) === original && passthrough.every((d) => d === valid.find((entry) => entry.domain_key === d.domain_key)));
}

console.log(`\neight-domain-parity: ${pass} passed, ${fail} failed`);
if (fail) { console.error("eight-domain-parity validation FAILED"); process.exit(1); }
console.log("eight-domain-parity validation passed");
