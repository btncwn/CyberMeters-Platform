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

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const enginesDir = path.join(root, "workers", "scan-api", "src", "engines");
const routesDir = path.join(root, "workers", "scan-api", "src", "routes");
const { resolveCyberMotDomainStates, CYBER_MOT_DOMAINS, CYBER_MOT_STATES } =
  await import(pathToFileURL(path.join(enginesDir, "cyber-mot-domains.js")).href);
const { getCyberEssentialsSnapshot } =
  await import(pathToFileURL(path.join(enginesDir, "ce-readiness.js")).href);

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

// A complete scan, all required+relevant modules assessed cleanly, no findings.
const cleanComplete = () => ({
  scan_id: "scan_parity", completed_at: "2026-07-14T10:00:00Z",
  scan_quality: { status: "complete", warnings: [], modules_skipped: [] },
  modules: {
    email_security: {}, dns: {},
    ssl: { https_available: true, https_probe_executed: true },
    headers: {},
    subdomains: { count: 2 }, admin_surface_detection: {}, cloud_storage_discovery: {},
    certificate_intelligence: {}, identity_discovery: {},
    saas_exposure: { count: 1 }, technology_detection: { count: 3 },
  },
  monitoring_states: healthyCtMonitoring(),
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

// B3. STATIC — Dashboard.jsx renders <CyberMotDomains UNCONDITIONALLY.
{
  const jsx = await fs.readFile(path.join(root, "frontend", "src", "pages", "Dashboard.jsx"), "utf8");
  ok("B3: Dashboard.jsx renders <CyberMotDomains", jsx.includes("<CyberMotDomains"));
  ok("B3: Dashboard.jsx does NOT gate the panel behind report?.cyber_mot_domains &&",
    !jsx.includes("report?.cyber_mot_domains &&"));
}

// ════ SECTION C — Per-domain healthy-eligibility matrix ════════════════════════

const SCAN_DOMAINS = ["email_protection","brand_protection","attack_surface","certificates_trust","website_security","identity_exposure"];
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
    ok(`C ${key}: clean complete scan → assessed_healthy`, byKey(r, key).state === HEALTHY,
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
    ok(`C ${key}: required module '${required[0]}' absent → not_yet_assessed`,
      s === CYBER_MOT_STATES.NOT_YET_ASSESSED, `got ${s}`);
  }

  // Partial-quality scan: all required evidence present, no finding → provisional, never healthy.
  {
    const rep = withRequired();
    rep.scan_quality = { status: "partial", warnings: [], modules_skipped: [] };
    const s = byKey(resolveCyberMotDomainStates(rep), key).state;
    ok(`C ${key}: partial-quality scan → provisional, never healthy`,
      s === CYBER_MOT_STATES.PROVISIONAL && s !== HEALTHY, `got ${s}`);
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

  ok("D: display order has all eight canonical domain keys",
    CYBER_MOT_DISPLAY_ORDER.length === 8 && CYBER_MOT_DISPLAY_ORDER.map((d) => d.domain_key).join(",") === KEYS.join(","));

  for (const [label, input] of [["null", null], ["undefined", undefined], ["empty array", []], ["malformed (missing state)", [{ domain_key: "email_protection" }]], ["short array", [{ domain_key: "email_protection", state: "assessed_healthy" }]]]) {
    const out = resolveDisplayDomains(input);
    ok(`D: endpoint failure (${label}) → exactly eight domains`, Array.isArray(out) && out.length === 8);
    ok(`D: endpoint failure (${label}) → no domain is assessed_healthy`, out.every((d) => d.state !== HEALTHY));
    ok(`D: endpoint failure (${label}) → canonical order + every key present`, out.map((d) => d.domain_key).join(",") === KEYS.join(","));
  }

  // A valid server-resolved eight-entry set passes straight through unchanged.
  const valid = resolveCyberMotDomainStates(cleanComplete());
  const passthrough = resolveDisplayDomains(valid);
  ok("D: a valid eight-entry server set passes through unchanged", passthrough === valid && passthrough.length === 8);
}

console.log(`\neight-domain-parity: ${pass} passed, ${fail} failed`);
if (fail) { console.error("eight-domain-parity validation FAILED"); process.exit(1); }
console.log("eight-domain-parity validation passed");
