#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-email-deadline-evidence.js  (CI-blocking)
//
// Email Deadline → Whole-Scan Failure P1.
//
// THE HARM (reproduced end-to-end before the fix, base da8b1f3e). The primary
// email module's deadline fallback was `markDeadlineDeferred({ spf:{}, dmarc:{},
// dkim:{} })` — a shape that does not match the completed runEmailModule
// contract. When ONLY email_security exceeded its 750ms hard cap under the
// normal 19000ms budget:
//
//   • scoring read the ABSENT spf_evidence_status as "observed" and fabricated
//     the high "Missing SPF Record" finding (-10) from a probe that never ran,
//     plus a DKIM observation claiming selectors were probed;
//   • the remediation gate checked ONLY email_security_intelligence (and a
//     deadline-deferred intelligence result passed it too) — never the primary
//     module actually handed to the builder;
//   • buildEmailRemediationActions dereferenced the missing spf_detail
//     (`Cannot read properties of undefined (reading 'raw')`), the TypeError
//     escaped to the engine's outer catch, and the ENTIRE scan finalized
//     "failed" with findings:[] — every sibling module's completed evidence
//     was discarded.
//
// THE FIX. The fallback is the canonical unassessed email result owned by
// email-scan.js (tri-state nulls, null detail contract, not_yet_assessed A1
// evidence statuses); remediation generation is gated on the PRIMARY module's
// publishable evidence (isPublishableEmailEvidence) while the intelligence
// module proves its OWN completion; the builder itself refuses non-publishable
// evidence and never converts an unobserved probe into "SPF missing" /
// "DMARC missing" / "publish this record".
//
// Production carries eight failed scans. No causal attribution to this defect
// has been proven; they are recorded as UNATTRIBUTED and are not relabelled.
//
// Sections: A contract + refusal matrix · B real-engine traces (deferred email,
// positive no-SPF control, deferred intelligence) · L lifecycle/case
// non-progression · M pinned mutations (killed via fresh-process engine /
// customer-output traces, never a source regex).
// Real modules, real D1 (schema + migrations), real R2 shim, no network. Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const selfPath = fileURLToPath(import.meta.url);
const root = path.join(path.dirname(selfPath), "..");
const engUrl = (f) => pathToFileURL(path.join(root, "workers/scan-api/src/engines", f)).href;
const scanEngineUrl = process.env.EMAIL_DEADLINE_SCAN_ENGINE_MODULE_URL || engUrl("scan-engine.js");
const loadedScanEngineSha256 = () => crypto.createHash("sha256")
  .update(fs.readFileSync(fileURLToPath(scanEngineUrl)))
  .digest("hex");
const loadedModule = (url) => ({
  url,
  sha256: crypto.createHash("sha256")
    .update(fs.readFileSync(fileURLToPath(url)))
    .digest("hex"),
});
const { computeScore } = await import(engUrl("scoring.js"));
const { runScanEngine } = await import(scanEngineUrl);
const { isPublishableModuleEvidence, markDeadlineDeferred, skippedModuleResult } = await import(engUrl("scan-budget.js"));
const { deadlineDeferredEmailModuleResult, runEmailModule, applyDmarcbisEmailCompatibilityProjection } = await import(engUrl("email-scan.js"));
const {
  buildDkimDetail, buildDmarcPolicyJourney, buildEmailRemediationActions,
  hasCanonicalEmailDetailContract, isPublishableEmailEvidence,
  parseBimiRecord, parseDmarcRecord, parseSpfRecord,
} = await import(engUrl("email-analysis.js"));
const { enrichSpf, enrichDkim } = await import(engUrl("email-intel.js"));
const { moduleCompletionGate } = await import(engUrl("asm-cases.js"));
const { CYBER_MOT_DOMAINS } = await import(engUrl("cyber-mot-domains.js"));
const { buildExecutiveReportV2 } = await import(engUrl("executive-report.js"));
const pdfModuleUrl = process.env.EMAIL_DEADLINE_PDF_MODULE_URL || engUrl("pdf.js");
const { buildScanReportPdf } = await import(pdfModuleUrl);

const NOW = "2026-07-29T09:00:00.000Z";
const NOW_MS = Date.parse(NOW);
const EXPECTED_MUTANTS = 20;

const SPF_RECORD = "v=spf1 include:_spf.google.com -all";
const DMARC_REJECT = "v=DMARC1; p=reject; rua=mailto:dmarc-reports@example.com";
const DMARC_NONE = "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com";

const pdfPlainText = (bytes) => {
  const source = new TextDecoder("latin1").decode(bytes);
  return [...source.matchAll(/\((.*?)\) Tj/g)]
    .map((match) => match[1].replace(/\\([\\()])/g, "$1"))
    .join("\n");
};

// ── shared harness ───────────────────────────────────────────────────────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (f) => { try { db.exec(fs.readFileSync(f, "utf8")); } catch { /* overlap */ } };
  apply(path.join(root, "database/schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database/migrations")).filter((n) => n.endsWith(".sql")).sort()) {
    apply(path.join(root, "database/migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db, onRun = null) {
  const stmt = (sql, args = []) => ({
    __sql: sql, bind: (...b) => stmt(sql, b),
    first: async (c) => { const r = db.prepare(sql).get(...args) ?? null; return c && r ? r[c] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const r = db.prepare(sql).run(...args);
      onRun?.(sql, args);
      return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid || 0) } };
    },
  });
  return {
    prepare: (s) => stmt(s),
    batch: async (l) => { const o = []; db.exec("BEGIN"); try { for (const s of l) o.push(/^\s*select/i.test(s.__sql) ? await s.all() : await s.run()); db.exec("COMMIT"); return o; } catch (e) { db.exec("ROLLBACK"); throw e; } },
    exec: async (s) => { db.exec(s); return { count: 0, duration: 0 }; },
  };
}
function makeR2(store) {
  return {
    get: async (k) => { const b = store.get(String(k)); return b == null ? null : { text: async () => b, json: async () => JSON.parse(b) }; },
    put: async (k, b) => { store.set(String(k), String(b)); return {}; },
    delete: async (k) => { store.delete(String(k)); return {}; },
    head: async () => null, list: async () => ({ objects: [] }),
  };
}
const json = (b, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { "content-type": "application/json" } });

// One mock per trace variant. Every module's lookups answer normally; the
// variant delays ONLY what drives its specific deadline:
//   deferred-email — DKIM selector + BIMI probes hang past email's 750ms hard
//     cap, so email_security (and email_security alone) takes its fallback.
//   no-spf         — everything fast; the root TXT has NO SPF record and DMARC
//     is p=none: the genuine completed positive controls.
//   deferred-intel — email probes fast; the MTA-STS policy fetch hangs past the
//     Queue/Cron Email Intelligence source-envelope cap. CVE + KEV finish and
//     remain publishable; only Email Intelligence defers.
// The delayed fetch observes AbortSignal so an abandoned test promise cannot
// keep the process alive past its production-owned cap.
function delayedResponse(ms, response, signal) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => resolve(response), ms);
    const abort = () => {
      clearTimeout(timer);
      reject(new DOMException("The operation was aborted", "AbortError"));
    };
    if (signal?.aborted) abort();
    else signal?.addEventListener("abort", abort, { once: true });
  });
}
function delayedUnrefResponse(ms, response) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(response), ms);
    timer.unref?.();
  });
}
function mockFetch(variant, { onLateResolve = null } = {}) {
  const dmarcRecord = variant === "no-spf" ? DMARC_NONE : DMARC_REJECT;
  const includeSpf = variant !== "no-spf";
  const certificateExpiryDays = new Map([
    ["cert-expiry-13", 13],
    ["cert-expiry-14", 14],
    ["cert-expiry-29", 29],
    ["cert-expiry-30", 30],
    ["cert-tls-unavailable", 13],
    ["cert-expiry-13-deferred-intel", 13],
  ]).get(variant);
  const b2bAdminHosts = new Set({
    "b2b-admin": [
      "phpmyadmin.example.com",
      "vcenter-gitlab.example.com",
      "openvpn.example.com",
      "admin.example.com",
    ],
    "b2b-vcenter": ["vcenter.example.com"],
    "b2b-hostname-only": ["gitlab.example.com", "openvpn.example.com"],
    "b2b-openvpn-only": ["openvpn.example.com"],
  }[variant] || []);
  return async (input, init = {}) => {
    const url = new URL(String(input)); const host = url.hostname;
    if ((variant === "deferred-intel" || variant === "late-email-completes" ||
        variant === "cert-expiry-13-deferred-intel")
        && host.startsWith("mta-sts.")) {
      // Match the production trace: the outbound request completes, but work
      // after the response (body consumption/parsing) outlives the module cap.
      return {
        status: 200,
        ok: true,
        url: url.toString(),
        headers: new Headers(),
        text: () => delayedUnrefResponse(
          variant === "late-email-completes" ? 250 : 20_000,
          "version: STSv1\nmode: enforce\nmax_age: 86400\n",
        ).then((value) => {
          onLateResolve?.();
          return value;
        }),
      };
    }
    if (host.startsWith("mta-sts.") &&
        (variant === "mta-missing" || variant === "mta-inapplicable")) {
      return new Response("", { status: 404 });
    }
    if (host.startsWith("mta-sts.") && variant === "mta-unavailable") {
      return new Response("unavailable", { status: 503 });
    }
    if (host.startsWith("mta-sts.") && variant === "mta-present") {
      return new Response("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n", {
        status: 200,
        headers: { "content-type": "text/plain" },
      });
    }
    if (host === "cloudflare-dns.com" || host === "dns.google") {
      const type = String(url.searchParams.get("type") || "A").toUpperCase();
      const name = String(url.searchParams.get("name") || "").toLowerCase();
      if (variant === "b2-source-unavailable") {
        throw new TypeError("simulated DNS source failure");
      }
      const answer = () => {
        if (name === "example.com" && type === "A") return json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
        if (variant === "b2-admin" && name === "grafana.example.com" && type === "A") {
          return json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.35" }] });
        }
        if (b2bAdminHosts.has(name) && type === "A") {
          return json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.36" }] });
        }
        if (name === "example.com" && type === "MX") {
          return variant === "mta-inapplicable"
            ? json({ Status: 0, Answer: [] })
            : json({ Status: 0, Answer: [{ type: 15, data: "10 mail.example.com." }] });
        }
        if (name === "example.com" && type === "NS") return json({ Status: 0, Answer: [{ type: 2, data: "ns1.example.com." }] });
        if (name === "example.com" && type === "TXT") {
          return includeSpf ? json({ Status: 0, Answer: [{ type: 16, data: `"${SPF_RECORD}"` }] }) : json({ Status: 0, Answer: [] });
        }
        if (name === "_dmarc.example.com" && type === "TXT") return json({ Status: 0, Answer: [{ type: 16, data: `"${dmarcRecord}"` }] });
        return json({ Status: 0, Answer: [] });
      };
      if (variant === "deferred-email" && (name.includes("._domainkey.") || name.startsWith("default._bimi."))) {
        return new Promise((res) => setTimeout(() => res(answer()), 1_500));
      }
      return answer();
    }
    if (host === "crt.sh") {
      if (variant === "cert-deferred") throw new TypeError("simulated CT source failure");
      if (certificateExpiryDays != null) {
        return json([{
          common_name: "example.com",
          name_value: "example.com\nwww.example.com",
          not_before: "2026-01-01T00:00:00Z",
          not_after: new Date(NOW_MS + (certificateExpiryDays * 86_400_000) + 3_600_000).toISOString(),
          issuer_name: "Let's Encrypt",
        }]);
      }
      const names = variant === "b2-admin"
        ? "example.com\ngrafana.example.com"
        : b2bAdminHosts.size > 0
          ? `example.com\n${[...b2bAdminHosts].join("\n")}`
          : null;
      return json(names ? [{
        common_name: "example.com",
        name_value: names,
        not_before: "2026-01-01T00:00:00Z",
        not_after: "2027-01-01T00:00:00Z",
        issuer_name: "Let's Encrypt",
      }] : []);
    }
    if (host === "api.certspotter.com") {
      if (variant === "cert-deferred") throw new TypeError("simulated CT source failure");
      return json([]);
    }
    if (host === "services.nvd.nist.gov") {
      if (variant === "slow-cve") {
        return {
          status: 200, ok: true, url: url.toString(),
          headers: new Headers({ "content-type": "application/json" }),
          json: () => delayedUnrefResponse(250, { vulnerabilities: [] }).then((value) => {
            onLateResolve?.();
            return value;
          }),
        };
      }
      return json({ vulnerabilities: [] });
    }
    if (host === "www.cisa.gov") {
      if (variant === "slow-kev") {
        return {
          status: 200, ok: true, url: url.toString(),
          headers: new Headers({ "content-type": "application/json" }),
          json: () => delayedUnrefResponse(250, { vulnerabilities: [] }).then((value) => {
            onLateResolve?.();
            return value;
          }),
        };
      }
      return json({ vulnerabilities: [] });
    }
    const hstsShort = variant === "b2-hsts" || variant === "b2-verification";
    const b2bPages = {
      "phpmyadmin.example.com": {
        body: "<html><title>phpMyAdmin</title></html>",
        server: "Apache",
      },
      "vcenter-gitlab.example.com": {
        body: "<html><title>VMware vCenter GitLab</title></html>",
        server: "VMware",
      },
      "vcenter.example.com": {
        body: "<html><title>VMware vCenter</title></html>",
        server: "VMware",
      },
      "gitlab.example.com": {
        body: "<html></html>",
        server: "nginx",
      },
      "openvpn.example.com": {
        body: "<html></html>",
        server: "nginx",
      },
      "admin.example.com": {
        body: "<html></html>",
        server: "nginx",
      },
    };
    const b2bPage = b2bAdminHosts.has(host) ? b2bPages[host] : null;
    if ((variant === "cert-tls-unavailable" || variant === "cert-deferred") &&
        (host === "example.com" || host === "www.example.com")) {
      throw new TypeError("simulated HTTPS source failure");
    }
    return new Response(
      b2bPage?.body || (variant === "b2-admin"
        ? "<html><title>Grafana</title></html>"
        : "<html></html>"),
      {
        status: 200,
        headers: {
          server: b2bPage?.server || (variant === "b2-admin" ? "grafana" : "nginx"),
          "content-type": "text/html",
          ...(hstsShort ? { "strict-transport-security": "max-age=86400" } : {}),
        },
      },
    );
  };
}

function seedEmailCase(db) {
  db.prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id, asset_ref, severity,
       status, evidence_json, recommended_actions_json, created_at, updated_at)
     VALUES ('mc-em','ws','email_case','email_protection','example.com','email_missing_spf','example.com','high',
       'awaiting_verification','{}','[]', datetime('now','-5 days'), datetime('now','-1 day'))`).run();
}

function seedDseVerificationCase(db) {
  db.prepare(`INSERT INTO managed_cases
      (id, workspace_id, case_type, domain_key, domain, finding_id, source_finding_type,
       source_scan_id, asset_ref, severity, status, evidence_json,
       recommended_actions_json, created_at, updated_at)
     VALUES ('mc-dse','ws','asm_exposure','attack_surface','example.com',
       'dse_hsts_short_maxage','dse_hsts_short_maxage','scan-before','example.com','low',
       'verification_requested',?, '[]', datetime('now','-5 days'), datetime('now','-1 day'))`)
    .run(JSON.stringify({
      finding: {
        id: "dse_hsts_short_maxage",
        module: "domain_security_enrichment",
        affected_hosts: ["example.com"],
      },
    }));
}

// The REAL production path: runScanEngine under the normal 19000ms budget with a
// frozen engine clock, so the ONLY thing that can end a module is its own hard
// cap on a real timer (raceModuleDeadline → onDeadline → fallback).
async function trace(variant, {
  seed = false,
  executionContext = "queue",
  capacityMode = "legacy",
  subrequestLimit = 200,
  phase5ElapsedMs = 0,
  accelerateDurableCaps = false,
  deterministicProof = false,
  engineRunner = runScanEngine,
  previousFindings = null,
} = {}) {
  const db = buildDb(); const store = new Map();
  let clockMs = NOW_MS;
  let lateResolvedWallMs = null;
  const onD1Run = (sql, args) => {
    if (phase5ElapsedMs > 0 && /current_stage/.test(sql)
        && args?.[1] === "phase5_intelligence") {
      clockMs = NOW_MS + phase5ElapsedMs;
    }
  };
  const env = {
    cybermeters_db: makeD1(db, onD1Run), cybermeters_reports: makeR2(store),
    SCAN_CAPACITY_MODE: capacityMode, SCAN_SUBREQUEST_LIMIT: String(subrequestLimit),
    SCAN_DEADLINE_MS: executionContext === "queue" || executionContext === "cron"
      ? "115000"
      : "19000",
    APP_VERSION: "email-deadline-p1",
  };
  db.prepare("INSERT INTO users (id, email) VALUES ('usr','o@example.com')").run();
  db.prepare("INSERT INTO workspaces (id, name, deleted_at) VALUES ('ws','EMAIL-P1',NULL)").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom','usr','example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws','dom')").run();
  db.prepare(`INSERT INTO scans (id, workspace_id, domain_id, domain, status, scan_quality, created_at)
              VALUES ('scan-em','ws','dom','example.com','running',NULL,?)`).run(NOW);
  if (Array.isArray(previousFindings)) {
    db.prepare(`INSERT INTO scans
      (id, workspace_id, domain_id, domain, status, score, rating, scan_quality, created_at)
      VALUES ('scan-em-previous','ws','dom','example.com','completed',100,'excellent','complete',?)`)
      .run("2026-07-28T09:00:00.000Z");
    store.set("reports/scan-em-previous.json", JSON.stringify({
      cyber_metrics_score: 100,
      risk_level: "excellent",
      scan_quality: { status: "complete" },
      findings: previousFindings,
      modules: {
        subdomains: { items: [] },
        subdomain_takeover: { risks: [] },
        asset_exposure: { assets: [] },
        cve_intelligence: {
          executed: true, technologies_checked: [], lookup_statuses: {}, results: {},
          total_cves: 0, critical_count: 0, high_count: 0, cve_coverage: "complete",
        },
        known_exploited_vulnerabilities: { executed: true, matches: [], checked: 0, matched: 0 },
        email_security_intelligence: { executed: true, findings: [] },
      },
    }));
  }
  if (seed) seedEmailCase(db);
  if (variant === "b2-verification") seedDseVerificationCase(db);

  const prevFetch = globalThis.fetch, prevLog = console.log, prevErr = console.error, prevWarn = console.warn;
  const realSetTimeout = globalThis.setTimeout;
  const realDate = globalThis.Date;
  const realRandomUuid = globalThis.crypto.randomUUID;
  let deterministicUuidSequence = 0;
  globalThis.fetch = mockFetch(variant, { onLateResolve: () => { lateResolvedWallMs = Date.now(); } });
  if (deterministicProof) {
    globalThis.Date = class FixedProofDate extends realDate {
      constructor(...args) { super(...(args.length > 0 ? args : [NOW_MS])); }
      static now() { return NOW_MS; }
      static parse(value) { return realDate.parse(value); }
      static UTC(...args) { return realDate.UTC(...args); }
    };
    globalThis.crypto.randomUUID = () => {
      deterministicUuidSequence += 1;
      return `00000000-0000-4000-8000-${String(deterministicUuidSequence).padStart(12, "0")}`;
    };
  }
  if (accelerateDurableCaps) {
    globalThis.setTimeout = (fn, ms, ...args) =>
      realSetTimeout(fn, ms === 12_000 || ms === 32_000 ? 5 : ms, ...args);
  }
  console.log = () => {}; console.error = () => {}; console.warn = () => {};
  let escaped = null;
  let engineReturnedWallMs = null;
  try {
    await engineRunner("scan-em", "dom", "ws", "example.com", env,
      { now: () => clockMs, executionContext, trigger: "manual" });
    engineReturnedWallMs = Date.now();
  } catch (e) {
    escaped = `${e?.name}: ${e?.message}`;
  } finally {
    globalThis.fetch = prevFetch;
    globalThis.setTimeout = realSetTimeout;
    globalThis.Date = realDate;
    globalThis.crypto.randomUUID = realRandomUuid;
    console.log = prevLog; console.error = prevErr; console.warn = prevWarn;
  }

  const raw = store.get("reports/scan-em.json");
  if (["slow-cve", "slow-kev", "late-email-completes"].includes(variant)) {
    await new Promise((resolve) => realSetTimeout(resolve, 350));
  }
  const rawAfterLate = store.get("reports/scan-em.json");
  const report = raw ? JSON.parse(raw) : null;
  const snapshotRaw = [...store.entries()]
    .find(([key]) => key.startsWith("reports/snapshots/ws/scan-em/"))?.[1] || null;
  const snapshot = snapshotRaw ? JSON.parse(snapshotRaw) : null;
  const scanRow = db.prepare("SELECT status, scan_quality FROM scans WHERE id='scan-em'").get() || {};
  const email = report?.modules?.email_security ?? null;
  const intel = report?.modules?.email_security_intelligence ?? null;
  return {
    db, report, snapshot, escaped,
    lateResolvedAfterEngine: lateResolvedWallMs != null && engineReturnedWallMs != null
      && lateResolvedWallMs > engineReturnedWallMs,
    reportStableAfterLate: rawAfterLate === raw,
    dbStatus: scanRow.status ?? null,
    quality: scanRow.scan_quality ?? null,
    reportQuality: report?.scan_quality?.status ?? null,
    reportError: report?.error ?? null,
    email, intel,
    historical: report?.modules?.historical_changes ?? null,
    diagnostics: report?.execution_diagnostics ?? null,
    emailActions: (email?.remediation_actions ?? []).map((a) => a.id),
    findingIds: (report?.findings || []).map((f) => f.id),
    titles: db.prepare("SELECT title FROM findings WHERE scan_id='scan-em'").all().map((r) => r.title),
    managedCases: db.prepare(
      "SELECT id, finding_id, source_finding_type, domain_key, asset_ref, status FROM managed_cases ORDER BY finding_id"
    ).all(),
    audits: db.prepare("SELECT event_type FROM audit_events").all().map((r) => r.event_type),
    motEmail: db.prepare("SELECT state, coverage, summary FROM cyber_mot_domain_states WHERE scan_id='scan-em' AND domain_key='email_protection'").get() || {},
    caseAfter: seed ? (db.prepare("SELECT status, verified_at FROM managed_cases WHERE id='mc-em'").get() || {}) : null,
  };
}

function b2bCustomerOutput(t, { includeExecutive = false, includePdf = false } = {}) {
  const scan = {
    id: t.report?.scan_id ?? "scan-em",
    domain_id: t.report?.domain_id ?? "dom",
    domain: t.report?.domain ?? "example.com",
  };
  const read = {
    snapshot: t.snapshot,
    row: { id: t.snapshot?.snapshot?.snapshot_id ?? null },
    integrity: { verified: true },
  };
  const executive = includeExecutive ? buildExecutiveReportV2({ scan, read }) : null;
  const pdfText = includePdf ? pdfPlainText(buildScanReportPdf(scan, read)) : null;
  const adminFindings = (t.report?.findings || [])
    .filter((finding) => String(finding.id || "").startsWith("admin_surface_"));
  const adminObserved = (t.snapshot?.observed_findings || [])
    .filter((finding) => String(finding.finding_id || "").startsWith("admin_surface_"));
  const adminObservations = (t.snapshot?.observations || [])
    .filter((finding) => String(finding.finding_id || "").startsWith("admin_surface_"));
  const adminActions = (t.snapshot?.remediation_actions || [])
    .filter((action) => action.remediation_id === "asm.exposure.admin");
  const adminCases = t.managedCases.filter((row) =>
    String(row.finding_id || "").startsWith("admin_surface_"));
  return {
    raw_services: t.report?.modules?.admin_surface_detection?.services || [],
    module_observations: t.report?.modules?.admin_surface_detection?.observations || [],
    report_admin_findings: adminFindings,
    attack_surface_domain: (t.snapshot?.domains || [])
      .find((domain) => domain.domain_key === "attack_surface") || null,
    snapshot_admin_findings: adminObserved,
    snapshot_admin_observations: adminObservations,
    admin_actions: adminActions,
    admin_cases: adminCases,
    ...(includeExecutive ? { executive } : {}),
    ...(includePdf ? { pdf_text: pdfText } : {}),
    score: t.report?.cyber_metrics_score ?? null,
    paired_score_control: computeScore(t.report?.modules || {}, scan.domain).score,
    score_methodology: t.snapshot?.methodology?.cyber_metrics_score_methodology_version ?? null,
    resolver_version: t.snapshot?.methodology?.cyber_mot_resolver_version ?? null,
  };
}

function mtaCustomerOutput(t, { includeExecutive = false, includePdf = false } = {}) {
  const scan = {
    id: t.report?.scan_id ?? "scan-em",
    domain_id: t.report?.domain_id ?? "dom",
    domain: t.report?.domain ?? "example.com",
  };
  const read = {
    snapshot: t.snapshot,
    row: { id: t.snapshot?.snapshot?.snapshot_id ?? null },
    integrity: { verified: true },
  };
  const executive = includeExecutive ? buildExecutiveReportV2({ scan, read }) : null;
  const pdfText = includePdf ? pdfPlainText(buildScanReportPdf(scan, read)) : null;
  const findingId = "email_intel_mta_sts_missing";
  return {
    report_findings: (t.report?.findings || []).filter((finding) => finding.id === findingId),
    email_domain: (t.snapshot?.domains || [])
      .find((domain) => domain.domain_key === "email_protection") || null,
    snapshot_findings: (t.snapshot?.observed_findings || [])
      .filter((finding) => finding.finding_id === findingId),
    actions: (t.snapshot?.remediation_actions || [])
      .filter((action) => action.remediation_id === "email.mta_sts.enable"),
    historical: t.historical,
    ...(includeExecutive ? { executive } : {}),
    ...(includePdf ? { pdf_text: pdfText } : {}),
    score: t.report?.cyber_metrics_score ?? null,
    paired_score_control: computeScore(t.report?.modules || {}, scan.domain).score,
    score_methodology: t.snapshot?.methodology?.cyber_metrics_score_methodology_version ?? null,
    resolver_version: t.snapshot?.methodology?.cyber_mot_resolver_version ?? null,
  };
}

const FALSE_EMAIL_FINDING_IDS = new Set([
  "email_missing_spf",
  "email_dkim_not_detected",
]);

function emailSkipCustomerOutput(t, { includeExecutive = false, includePdf = false } = {}) {
  const scan = {
    id: t.report?.scan_id ?? "scan-em",
    domain_id: t.report?.domain_id ?? "dom",
    domain: t.report?.domain ?? "example.com",
  };
  const read = {
    snapshot: t.snapshot,
    row: { id: t.snapshot?.snapshot?.snapshot_id ?? null },
    integrity: { verified: true },
  };
  return {
    report_findings: (t.report?.findings || [])
      .filter((finding) => FALSE_EMAIL_FINDING_IDS.has(finding.id)),
    snapshot_findings: (t.snapshot?.observed_findings || [])
      .filter((finding) => FALSE_EMAIL_FINDING_IDS.has(finding.finding_id)),
    snapshot_observations: (t.snapshot?.observations || [])
      .filter((finding) => FALSE_EMAIL_FINDING_IDS.has(finding.finding_id)),
    actions: (t.snapshot?.remediation_actions || [])
      .filter((action) => ["email.spf.publish", "email.dkim.verify"].includes(action.remediation_id)),
    email_domain: (t.snapshot?.domains || [])
      .find((domain) => domain.domain_key === "email_protection") || null,
    managed_cases: t.managedCases.filter((managedCase) =>
      FALSE_EMAIL_FINDING_IDS.has(managedCase.finding_id)),
    ...(includeExecutive ? { executive: buildExecutiveReportV2({ scan, read }) } : {}),
    ...(includePdf ? { pdf_text: pdfPlainText(buildScanReportPdf(scan, read)) } : {}),
  };
}

const PRIOR_CRITICAL_CERTIFICATE_FINDING = Object.freeze({
  id: "certificate_expiring_critical",
  module: "certificate_intelligence",
  finding_type: "finding",
  severity: "high",
  score_impact: 0,
  title: "Logged certificate validity ends within 14 days",
});

const CERTIFICATE_EXPIRY_IDS = new Set([
  "certificate_expiring_critical",
  "certificate_expiring_soon",
]);

function certCustomerOutput(t, { includeExecutive = false, includePdf = false } = {}) {
  const scan = {
    id: t.report?.scan_id ?? "scan-em",
    domain_id: t.report?.domain_id ?? "dom",
    domain: t.report?.domain ?? "example.com",
  };
  const read = {
    snapshot: t.snapshot,
    row: { id: t.snapshot?.snapshot?.snapshot_id ?? null },
    integrity: { verified: true },
  };
  const certificateIntel = t.report?.modules?.certificate_intelligence || {};
  const executive = includeExecutive ? buildExecutiveReportV2({ scan, read }) : null;
  const pdfText = includePdf ? pdfPlainText(buildScanReportPdf(scan, read)) : null;
  return {
    producer_signals: certificateIntel.suspicious_certificate_signals || [],
    module_evidence: {
      expiry_evidence: certificateIntel.expiry_evidence ?? null,
      tls_state: certificateIntel.tls_state ?? null,
      evidence_source: certificateIntel.evidence_source ?? null,
      live_certificate_verified: certificateIntel.live_certificate_verified ?? null,
      expires_at: certificateIntel.expires_at ?? null,
      days_until_expiry: certificateIntel.days_until_expiry ?? null,
      ct_sources: certificateIntel.ct_sources || [],
    },
    report_cert_findings: (t.report?.findings || [])
      .filter((finding) => CERTIFICATE_EXPIRY_IDS.has(finding.id)),
    certificates_domain: (t.snapshot?.domains || [])
      .find((domain) => domain.domain_key === "certificates_trust") || null,
    snapshot_cert_findings: (t.snapshot?.observed_findings || [])
      .filter((finding) => CERTIFICATE_EXPIRY_IDS.has(finding.finding_id)),
    snapshot_cert_observations: (t.snapshot?.observations || [])
      .filter((observation) => CERTIFICATE_EXPIRY_IDS.has(observation.finding_id)),
    cert_actions: (t.snapshot?.remediation_actions || [])
      .filter((action) => action.remediation_id === "cert.expiry.expiring"),
    cert_cases: t.managedCases.filter((managedCase) =>
      managedCase.domain_key === "certificates_trust"),
    historical: t.historical,
    ...(includeExecutive ? { executive } : {}),
    ...(includePdf ? { pdf_text: pdfText } : {}),
    score: t.report?.cyber_metrics_score ?? null,
    paired_score_control: computeScore(t.report?.modules || {}, scan.domain).score,
    score_methodology: t.snapshot?.methodology?.cyber_metrics_score_methodology_version ?? null,
    resolver_version: t.snapshot?.methodology?.cyber_mot_resolver_version ?? null,
    loaded_modules: {
      scan_engine: loadedModule(scanEngineUrl),
      report_snapshot: loadedModule(engUrl("report-snapshot.js")),
      executive_report: loadedModule(engUrl("executive-report.js")),
      pdf: loadedModule(pdfModuleUrl),
    },
  };
}

function b2bFullCustomerProjection(t) {
  const projected = b2bCustomerOutput(t, { includeExecutive: true, includePdf: true });
  return {
    report_findings: t.report?.findings || [],
    report_score: t.report?.cyber_metrics_score ?? null,
    report_risk_level: t.report?.risk_level ?? null,
    domains: t.snapshot?.domains || [],
    observed_findings: t.snapshot?.observed_findings || [],
    observations: t.snapshot?.observations || [],
    remediation_actions: t.snapshot?.remediation_actions || [],
    managed_cases: t.managedCases,
    executive: projected.executive,
    pdf_text: projected.pdf_text,
  };
}

async function traceOpenvpnCleanControl() {
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "b2b-openvpn-clean-control-"));
  const workerRoot = path.join(tempRoot, "workers/scan-api");
  const workerSource = path.join(workerRoot, "src");
  try {
    fs.mkdirSync(workerRoot, { recursive: true });
    fs.cpSync(path.join(root, "workers/scan-api/src"), workerSource, { recursive: true });
    fs.copyFileSync(
      path.join(root, "workers/scan-api/package.json"),
      path.join(workerRoot, "package.json"),
    );
    fs.symlinkSync(
      path.join(root, "workers/scan-api/node_modules"),
      path.join(workerRoot, "node_modules"),
      "dir",
    );
    const sharedRoot = path.join(root, "shared");
    if (fs.existsSync(sharedRoot)) {
      fs.cpSync(sharedRoot, path.join(tempRoot, "shared"), { recursive: true });
    }

    const assetIntelFile = path.join(workerSource, "engines/asset-intel.js");
    const source = fs.readFileSync(assetIntelFile, "utf8");
    const anchor = '    title_re: /\\bopenvpn\\b/i,          server_re: /\\bopenvpn\\b/i,  host_re: /\\bopenvpn\\b/i },';
    const replacement = '    title_re: /\\bopenvpn\\b/i,          server_re: /\\bopenvpn\\b/i,  host_re: /a^/i },';
    const count = source.split(anchor).length - 1;
    if (count !== 1) throw new Error(`OpenVPN clean-control anchor x${count}`);
    fs.writeFileSync(assetIntelFile, source.replace(anchor, replacement));

    const moduleUrl = `${pathToFileURL(path.join(workerSource, "engines/scan-engine.js")).href}?b2b-openvpn-clean-control=1`;
    const cleanEngine = await import(moduleUrl);
    return await trace("b2b-openvpn-only", {
      deterministicProof: true,
      engineRunner: cleanEngine.runScanEngine,
    });
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }
}

// Customer-output surface for the builder-level mutants: the action arrays
// buildEmailRemediationActions returns ARE modules.email_security.
// remediation_actions, served verbatim by the scan API.
function builderFlagsProbe() {
  const def = (o, k, v) => Object.defineProperty(o, k, { value: v, enumerable: false });
  const mk = ({ extras = {}, spfStatus = "observed", dkimStatus = "observed", dmarcStatus = "observed", dmarcRaw = null } = {}) => {
    const dmarcDetail = parseDmarcRecord(dmarcRaw, dmarcRaw ? 1 : 0);
    const d = {
      spf_detail: parseSpfRecord(null, 0),
      dmarc_detail: dmarcDetail,
      dkim_detail: buildDkimDetail({}),
      bimi_readiness: parseBimiRecord(null, dmarcDetail),
      policy_journey: buildDmarcPolicyJourney(dmarcDetail),
      ...extras,
    };
    def(d, "spf_evidence_status", spfStatus);
    def(d, "dkim_evidence_status", dkimStatus);
    def(d, "dmarc_evidence_status", dmarcStatus);
    return d;
  };
  const idsOf = (details) => {
    try { return { ids: buildEmailRemediationActions("example.com", details).map((a) => a.id), threw: null }; }
    catch (e) { return { ids: null, threw: `${e?.name}: ${e?.message}` }; }
  };
  // Deferred module shape as it exists AFTER the DMARCbis projection mutated it
  // (dmarc_detail is an object, spf_detail is still null) — the exact shape that
  // crashed the whole scan pre-fix.
  const projectedDeferred = applyDmarcbisEmailCompatibilityProjection(
    "example.com", deadlineDeferredEmailModuleResult(), null);
  return {
    fallback: idsOf(deadlineDeferredEmailModuleResult()),
    projectedDeferred: idsOf(projectedDeferred),
    executedFalse: idsOf(mk({ extras: { executed: false } })),
    incompleteTrue: idsOf(mk({ extras: { incomplete: true } })),
    deadlineOutcome: idsOf(mk({ extras: { outcome: "deadline_exceeded" } })),
    skipped: idsOf(mk({ extras: { skipped: true } })),
    errored: idsOf(mk({ extras: { error: "email module failed" } })),
    missingContract: idsOf({ spf_detail: parseSpfRecord(null, 0) }),
    unavailableSpf: idsOf(mk({ spfStatus: "unavailable" })),
    notYetAssessedSpf: idsOf(mk({ spfStatus: "not_yet_assessed" })),
    unavailableDmarc: idsOf(mk({ dmarcStatus: "unavailable" })),
    positiveMissing: idsOf(mk()),
    positiveMonitorOnly: idsOf(mk({ dmarcRaw: DMARC_NONE })),
    positiveMultiSpf: idsOf(mk({ extras: { spf_detail: parseSpfRecord(SPF_RECORD, 2) } })),
    positivePermissiveAll: idsOf(mk({ extras: { spf_detail: parseSpfRecord("v=spf1 +all", 1) } })),
  };
}

// ── child modes (fresh process → mutated-in-place files are actually loaded) ──
const childArg = process.argv.find((a) => a.startsWith("--child="));
if (childArg) {
  const mode = childArg.slice("--child=".length);
  let out;
  if (mode === "builder-flags") out = builderFlagsProbe();
  else if (mode === "b2b-cx") {
    const positive = await trace("b2b-vcenter");
    const owner = await trace("b2b-admin");
    const moduleOnly = await trace("b2b-hostname-only");
    const openvpnOnly = await trace("b2b-openvpn-only", { deterministicProof: true });
    const cleanControl = await traceOpenvpnCleanControl();
    out = {
      positive: b2bCustomerOutput(positive, { includeExecutive: true, includePdf: true }),
      owner: b2bCustomerOutput(owner),
      module_only: b2bCustomerOutput(moduleOnly),
      openvpn_only: b2bCustomerOutput(openvpnOnly),
      clean_control: b2bCustomerOutput(cleanControl),
    };
  }
  else if (mode === "b2b-module-only-cx") {
    out = b2bCustomerOutput(await trace("b2b-hostname-only"), { includeExecutive: true });
  }
  else if (mode === "b2b-openvpn-only-cx") {
    const t = await trace("b2b-openvpn-only", { deterministicProof: true });
    out = {
      customer: b2bCustomerOutput(t, { includeExecutive: true }),
      full_projection: b2bFullCustomerProjection(t),
    };
  }
  else if (mode === "b2b-clean-control-cx") {
    const t = await traceOpenvpnCleanControl();
    out = {
      customer: b2bCustomerOutput(t, { includeExecutive: true }),
      full_projection: b2bFullCustomerProjection(t),
    };
  }
  else if (mode === "b2b-contract") {
    const scanEngineSource = fs.readFileSync(fileURLToPath(scanEngineUrl), "utf8");
    out = {
      adminBucketGuard: scanEngineSource.includes(
        "if (adminMod && !adminMod.error && adminMod.detected && adminMod.total > 0) {",
      ),
    };
  }
  else if (mode === "b2c-contract") {
    const scanEngineSource = fs.readFileSync(fileURLToPath(scanEngineUrl), "utf8");
    const bridgeStart = scanEngineSource.indexOf(
      "    const mtaStsEvidence = modules.email_security_intelligence?.mta_sts;",
    );
    const bridgeEnd = scanEngineSource.indexOf(
      "    if (emailIntelUsable) {",
      bridgeStart,
    );
    const bridge = bridgeStart >= 0 && bridgeEnd > bridgeStart
      ? scanEngineSource.slice(bridgeStart, bridgeEnd)
      : "";
    out = {
      canonicalAdmission: bridge.includes(
        "mtaStsAdmission(mtaStsEvidence).missing_finding === true",
      ),
      publishabilityAndApplicability: bridge.includes(
        "emailIntelUsable &&\n      emailApplicability.applicable &&",
      ),
      exactSourceId: bridge.includes(
        'finding?.id === "email_intel_mta_sts_missing"',
      ),
      exactSingleSource: bridge.includes("mtaStsMissingRows.length === 1"),
      mainIdDedupe: bridge.includes(
        '!findings.some((finding) => finding?.id === "email_intel_mta_sts_missing")',
      ),
      explicitFinding: bridge.includes('finding_type: "finding"'),
      lowZero: bridge.includes('severity: "low"') && bridge.includes("score_impact: 0"),
      httpsEvidence: bridge.includes('type: "https_probe"') &&
        bridge.includes('reason: "well_known_404"') &&
        bridge.includes('source: "cloudflare_workers_fetch"'),
      tlsRptExcluded: !bridge.includes("email_intel_tls_rpt_missing"),
    };
  }
  else if (mode === "b2c-cx") {
    const t = await trace("mta-missing", { deterministicProof: true, previousFindings: [] });
    out = mtaCustomerOutput(t, { includeExecutive: true, includePdf: true });
  }
  else if (mode === "reserved-email-skip-cx") {
    const t = await trace("reserved-email-skip", {
      capacityMode: "reserved",
      subrequestLimit: 50,
      deterministicProof: true,
    });
    out = {
      email: t.email,
      dmarc_core: t.report?.modules?.dmarc_core ?? null,
      d1_titles: t.titles,
      customer: emailSkipCustomerOutput(t, { includeExecutive: true, includePdf: true }),
    };
  }
  else if (mode === "b2d-contract") {
    const scanEngineSource = fs.readFileSync(fileURLToPath(scanEngineUrl), "utf8");
    const bridgeStart = scanEngineSource.indexOf(
      "    // B2d: project only the two producer-owned, CT-bounded expiry findings",
    );
    const reconcileStart = scanEngineSource.indexOf(
      "    if (modules.historical_changes) {",
      bridgeStart,
    );
    const gateStart = scanEngineSource.indexOf(
      "      modules.historical_changes = applyScanComparability(",
      reconcileStart,
    );
    const bridge = bridgeStart >= 0 && reconcileStart > bridgeStart
      ? scanEngineSource.slice(bridgeStart, reconcileStart)
      : "";
    out = {
      loaded_module_url: scanEngineUrl,
      loaded_module_sha256: loadedScanEngineSha256(),
      tls_guard: bridge.includes(
        "modules.ssl?.tls_state === TLS_RUNTIME_STATES.OBSERVED_PRESENT",
      ),
      exact_ids: bridge.includes(`const certificateExpiryIds = [
      "certificate_expiring_critical",
      "certificate_expiring_soon",
    ];`) && !bridge.includes("certificate_expired") && !bridge.includes('"no_https"'),
      ct_live_evidence: bridge.includes(
        'certificateIntel.evidence_source === "certificate_transparency"',
      ) && bridge.includes("certificateIntel.live_certificate_verified === false") &&
        bridge.includes('type: "certificate_transparency"') &&
        bridge.includes('basis: "latest_expiring_logged_certificate"') &&
        bridge.includes("live_certificate_verified: false"),
      usable_expiry: bridge.includes('certificateIntel.expiry_evidence === "usable"'),
      numeric_band: bridge.includes("!Number.isFinite(days) || !Number.isInteger(days) || !exactBand") &&
        bridge.includes("days >= 0 && days < 14") &&
        bridge.includes("days >= 14 && days <= 29"),
      exact_source_and_dedupe: bridge.includes("sourceRows.length !== 1") &&
        bridge.includes("findings.some((finding) => finding?.id === findingId)"),
      score_neutral: bridge.includes("score_impact: 0"),
      late_order: bridgeStart >= 0 && bridgeStart < reconcileStart && reconcileStart < gateStart,
    };
  }
  else if (mode === "b2d-cert13") {
    const t = await trace("cert-expiry-13", { deterministicProof: true, previousFindings: [] });
    out = {
      loaded_module_url: scanEngineUrl,
      loaded_module_sha256: loadedScanEngineSha256(),
      findings: (t.report?.findings || []).filter((finding) =>
        String(finding.id || "").startsWith("certificate_")),
      historical: t.historical,
      actions: (t.snapshot?.remediation_actions || []).filter((action) =>
        action.remediation_id === "cert.expiry.expiring"),
      managed_cases: t.managedCases,
    };
  }
  else if (mode === "b2d-cx") {
    const variants = {
      cert13: await trace("cert-expiry-13", {
        deterministicProof: true,
        previousFindings: [],
      }),
      cert14: await trace("cert-expiry-14", {
        deterministicProof: true,
        previousFindings: [],
      }),
      cert29: await trace("cert-expiry-29", {
        deterministicProof: true,
        previousFindings: [],
      }),
      cert30: await trace("cert-expiry-30", {
        deterministicProof: true,
        previousFindings: [PRIOR_CRITICAL_CERTIFICATE_FINDING],
      }),
      tlsUnavailable: await trace("cert-tls-unavailable", {
        deterministicProof: true,
        previousFindings: [PRIOR_CRITICAL_CERTIFICATE_FINDING],
      }),
    };
    out = Object.fromEntries(Object.entries(variants).map(([name, t]) => [
      name,
      certCustomerOutput(t, { includeExecutive: true, includePdf: true }),
    ]));
  }
  else if (mode === "b2d-tls-unavailable") {
    const t = await trace("cert-tls-unavailable", { deterministicProof: true });
    out = {
      loaded_module_url: scanEngineUrl,
      loaded_module_sha256: loadedScanEngineSha256(),
      findings: (t.report?.findings || []).filter((finding) =>
        String(finding.id || "").startsWith("certificate_")),
    };
  }
  else {
    const t = await trace(mode);
    const findingProjection = (t.report?.findings || []).map((finding) => ({
      id: finding.id,
      finding_type: finding.finding_type,
      severity: finding.severity,
      score_impact: finding.score_impact,
      affected_hosts: finding.affected_hosts || [],
      evidence: finding.evidence || [],
    }));
    if ([
      "b2-admin", "b2b-admin", "b2b-vcenter", "b2b-hostname-only",
      "b2b-openvpn-only",
    ].includes(mode)) {
      out = {
        findings: findingProjection,
        findingIds: findingProjection.map((finding) => finding.id),
        adminModule: t.report?.modules?.admin_surface_detection ?? null,
        snapshotActions: t.snapshot?.remediation_actions ?? [],
        managedCases: t.managedCases,
        score: t.report?.cyber_metrics_score ?? null,
      };
    } else out = {
      escaped: t.escaped, dbStatus: t.dbStatus, quality: t.quality,
      reportQuality: t.reportQuality, reportError: t.reportError,
      lateResolvedAfterEngine: t.lateResolvedAfterEngine,
      reportStableAfterLate: t.reportStableAfterLate,
      titles: t.titles, findingIds: t.findingIds, emailActions: t.emailActions,
      score: t.report?.cyber_metrics_score ?? null,
      riskLevel: t.report?.risk_level ?? null,
      scanQuality: t.report?.scan_quality ?? null,
      diagnostics: t.diagnostics,
      risk: t.report?.modules?.risk_intelligence ?? null,
      remediation: t.report?.modules?.remediation_plan ?? null,
      cve: t.report?.modules?.cve_intelligence ?? null,
      kev: t.report?.modules?.known_exploited_vulnerabilities ?? null,
      dns: t.report?.modules?.dns ?? null,
      ssl: t.report?.modules?.ssl ?? null,
      headers: t.report?.modules?.headers ?? null,
      technology: t.report?.modules?.technology_detection ?? null,
      findings: findingProjection,
      adminModule: t.report?.modules?.admin_surface_detection ?? null,
      snapshotActions: t.snapshot?.remediation_actions ?? [],
      managedCases: t.managedCases,
      emailExecuted: t.email?.executed ?? null, emailOutcome: t.email?.outcome ?? null,
      email: t.email,
      intel: t.intel,
      historical: t.historical,
      hasMtaStsDetail: !!(t.email && Object.prototype.hasOwnProperty.call(t.email, "mta_sts_detail")),
      motEmail: t.motEmail,
    };
  }
  await new Promise((resolve, reject) => {
    process.stdout.write(JSON.stringify(out), (error) => error ? reject(error) : resolve());
  });
  process.exit(0);
}

let passed = 0, failed = 0, killed = 0;
const ok = (name, cond, detail = "") => {
  if (cond) passed += 1;
  else { failed += 1; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};

// ── A. CONTRACT + REFUSAL MATRIX ─────────────────────────────────────────────
console.log("── A. canonical fallback contract + non-publishable refusal matrix ──");
{
  // A completed run of the REAL producer (fast probes, core-owned DMARC), so
  // conformance is measured against the live contract, not a hand-written copy.
  const prevFetch = globalThis.fetch;
  globalThis.fetch = mockFetch("complete");
  const completed = await runEmailModule("example.com", { dmarcOwnedByCore: true });
  globalThis.fetch = prevFetch;
  const fb = deadlineDeferredEmailModuleResult();
  const missing = Object.keys(completed).filter((k) => !(k in fb));
  ok("A1: fallback carries EVERY enumerable key of the completed contract",
    missing.length === 0, `missing: ${missing.join(", ")}`);
  ok("A1: presence is the tri-state null — never false (not measured ≠ measured absent)",
    fb.spf.present === null && fb.dmarc.present === null && fb.dkim.present === null);
  ok("A1: the detail contract is explicitly null (non-publishable), not fabricated parses",
    fb.spf_detail === null && fb.dmarc_detail === null && fb.dkim_detail === null &&
    fb.bimi_readiness === null && fb.policy_journey === null);
  ok("A1: deferral is explicit — executed:false, incomplete:true, deadline outcome, stable reason",
    fb.executed === false && fb.incomplete === true &&
    fb.outcome === "deadline_exceeded" && fb.reason === "scan_deadline_exhausted");
  ok("A1: A1 evidence statuses are not_yet_assessed and NON-ENUMERABLE (API shape preserved)",
    fb.spf_evidence_status === "not_yet_assessed" && fb.dkim_evidence_status === "not_yet_assessed" &&
    !Object.keys(fb).includes("spf_evidence_status"));
  ok("A1: remediation_actions is an explicit empty list", Array.isArray(fb.remediation_actions) && fb.remediation_actions.length === 0);
  ok("A1: each call returns a FRESH object (no shared mutable fallback between scans)",
    deadlineDeferredEmailModuleResult() !== deadlineDeferredEmailModuleResult());
  const rt = JSON.parse(JSON.stringify(fb));
  ok("A1: JSON round-trip (R2 persistence) preserves the tri-state nulls and flags",
    rt.spf.present === null && rt.spf_detail === null && rt.executed === false && rt.incomplete === true);

  ok("A2: fallback is NOT publishable email evidence", !isPublishableEmailEvidence(fb));
  ok("A2: completed module IS publishable email evidence (positive control)",
    isPublishableEmailEvidence(completed) && hasCanonicalEmailDetailContract(completed));
  ok("A2: executed:false is non-publishable", !isPublishableModuleEvidence({ executed: false }));
  ok("A2: incomplete:true is non-publishable", !isPublishableModuleEvidence({ incomplete: true }));
  ok("A2: deadline outcome is non-publishable", !isPublishableModuleEvidence({ outcome: "deadline_exceeded" }));
  ok("A2: skippedModuleResult is non-publishable", !isPublishableModuleEvidence(skippedModuleResult("email_security")));
  ok("A2: errored module is non-publishable", !isPublishableModuleEvidence({ error: "x" }));
  ok("A2: missing detail contract is non-publishable even with no flags",
    !isPublishableEmailEvidence({ spf_detail: null, dmarc_detail: {}, dkim_detail: {}, bimi_readiness: {} }));

  // The old bare fallback (the removed shape) must ALSO be refused: legacy R2
  // reports carrying it can never rebuild into fabricated remediation.
  const legacyBare = markDeadlineDeferred({ spf: {}, dmarc: {}, dkim: {}, source: "email_security" });
  ok("A2: the REMOVED bare fallback shape is refused too", !isPublishableEmailEvidence(legacyBare));
}
{
  const flags = builderFlagsProbe();
  ok("A3: builder REFUSES the fallback without throwing → []",
    flags.fallback.threw === null && flags.fallback.ids.length === 0, JSON.stringify(flags.fallback));
  ok("A3: builder survives the post-projection deferred shape (the exact pre-fix crash input) → []",
    flags.projectedDeferred.threw === null && flags.projectedDeferred.ids.length === 0, JSON.stringify(flags.projectedDeferred));
  for (const [k, label] of [
    ["executedFalse", "executed:false"], ["incompleteTrue", "incomplete:true"],
    ["deadlineOutcome", "deadline outcome"], ["skipped", "skipped"], ["errored", "error"],
    ["missingContract", "missing detail contract"],
  ]) {
    ok(`A3: ${label} evidence creates NO actions`,
      flags[k].threw === null && flags[k].ids.length === 0, JSON.stringify(flags[k]));
  }
  ok("A4: an UNAVAILABLE SPF probe never becomes 'SPF missing' / 'publish this record'",
    !flags.unavailableSpf.ids.includes("spf_missing"), JSON.stringify(flags.unavailableSpf.ids));
  ok("A4: a not-yet-assessed SPF probe never becomes 'SPF missing'",
    !flags.notYetAssessedSpf.ids.includes("spf_missing"), JSON.stringify(flags.notYetAssessedSpf.ids));
  ok("A4: an UNAVAILABLE DMARC observation never becomes 'DMARC missing'",
    !flags.unavailableDmarc.ids.includes("dmarc_missing"), JSON.stringify(flags.unavailableDmarc.ids));
  ok("A5: POSITIVE — a completed OBSERVED assessment proving SPF absent still creates spf_missing",
    flags.positiveMissing.ids.includes("spf_missing"), JSON.stringify(flags.positiveMissing.ids));
  ok("A5: POSITIVE — a completed OBSERVED assessment proving DMARC absent still creates dmarc_missing",
    flags.positiveMissing.ids.includes("dmarc_missing"), JSON.stringify(flags.positiveMissing.ids));
  ok("A5: POSITIVE — a genuine p=none policy still creates dmarc_policy_monitoring_only",
    flags.positiveMonitorOnly.ids.includes("dmarc_policy_monitoring_only"), JSON.stringify(flags.positiveMonitorOnly.ids));
  ok("A5: POSITIVE — genuine multiple SPF records still create spf_multiple_records",
    flags.positiveMultiSpf.ids.includes("spf_multiple_records"), JSON.stringify(flags.positiveMultiSpf.ids));
  ok("A5: POSITIVE — a genuine +all policy still creates spf_permissive_all",
    flags.positivePermissiveAll.ids.includes("spf_permissive_all"), JSON.stringify(flags.positivePermissiveAll.ids));
}
{
  // Scoring + intelligence honesty gates read the conforming fallback as
  // unobserved — and their positive controls still fire on observed absence.
  const projected = applyDmarcbisEmailCompatibilityProjection("example.com", deadlineDeferredEmailModuleResult(), null);
  const { findings } = computeScore({ dns: { has_mx: true }, ssl: {}, headers: { headers: {} }, email_security: projected }, "example.com");
  ok("A6: scoring emits NO Missing SPF finding from the fallback",
    !findings.some((f) => f.id === "email_missing_spf"), findings.map((f) => f.id).join("|"));
  ok("A6: scoring emits NO fabricated DKIM observation from the fallback",
    !findings.some((f) => f.id === "email_dkim_not_detected"));
  const observedMissing = { spf: { present: false }, dmarc: { present: false }, dkim: { present: false, selectors_probed: ["default"] } };
  Object.defineProperty(observedMissing, "spf_evidence_status", { value: "observed", enumerable: false });
  Object.defineProperty(observedMissing, "dkim_evidence_status", { value: "observed", enumerable: false });
  const positive = computeScore({ dns: { has_mx: true }, ssl: {}, headers: { headers: {} }, email_security: observedMissing }, "example.com").findings;
  ok("A6: POSITIVE — observed SPF absence still scores email_missing_spf (-10)",
    positive.some((f) => f.id === "email_missing_spf" && Number(f.score_impact) === -10));
  ok("A6: POSITIVE — observed DKIM non-detection still emits the informational observation",
    positive.some((f) => f.id === "email_dkim_not_detected"));
  const partialObservedMissing = { ...observedMissing, incomplete: true };
  Object.defineProperty(partialObservedMissing, "spf_evidence_status", { value: "observed", enumerable: false });
  Object.defineProperty(partialObservedMissing, "dkim_evidence_status", { value: "observed", enumerable: false });
  const partialPositive = computeScore({
    dns: { has_mx: true }, ssl: {}, headers: { headers: {} },
    email_security: partialObservedMissing,
  }, "example.com").findings;
  ok("A6: POSITIVE — a partial module with completed SPF evidence still scores observed absence",
    partialPositive.some((f) => f.id === "email_missing_spf" && Number(f.score_impact) === -10));
  ok("A7: email-intel reads the fallback SPF as unobserved (finding + impact gated)",
    enrichSpf(deadlineDeferredEmailModuleResult()).observation_unavailable === true);
  ok("A7: email-intel reads the fallback DKIM as unobserved",
    enrichDkim(deadlineDeferredEmailModuleResult()).observation_unavailable === true);
}

// ── B. REAL runScanEngine — email exceeds its 750ms hard cap ─────────────────
console.log("\n── B. REAL runScanEngine, durable Queue budget, ONLY primary email past its hard cap ──");
const t1 = await trace("deferred-email");
ok("B: no exception escaped the engine", t1.escaped === null, String(t1.escaped));
ok("B: the scan reached a terminal COMPLETED state (not failed)",
  t1.dbStatus === "completed" && t1.report?.status === "completed",
  JSON.stringify({ db: t1.dbStatus, rep: t1.report?.status, err: t1.reportError }));
ok("B: scan_quality.status is partial (report + D1 agree)",
  t1.reportQuality === "partial" && t1.quality === "partial",
  JSON.stringify({ rep: t1.reportQuality, d1: t1.quality }));
ok("B: the email module took the DEADLINE fallback (hard-cap race)",
  t1.email?.executed === false && t1.email?.incomplete === true && t1.email?.outcome === "deadline_exceeded",
  JSON.stringify({ e: t1.email?.executed, i: t1.email?.incomplete, o: t1.email?.outcome }));
ok("B: persisted email evidence is explicitly unassessed (tri-state nulls, null details)",
  t1.email?.spf?.present === null && t1.email?.spf_detail === null && t1.email?.dkim_detail === null);
ok("B: NO fabricated missing-SPF/DMARC finding in the report",
  !t1.findingIds.some((id) => ["email_missing_spf", "email_missing_dmarc"].includes(id)),
  t1.findingIds.join("|"));
ok("B: NO fabricated DKIM observation in the report",
  !t1.findingIds.includes("email_dkim_not_detected"));
ok('B: NO "Missing SPF Record" persisted to D1', !t1.titles.includes("Missing SPF Record"), t1.titles.join(" | "));
ok("B: NO fabricated remediation actions on the deferred module",
  Array.isArray(t1.email?.remediation_actions) && t1.email.remediation_actions.length === 0,
  JSON.stringify(t1.emailActions));
ok("B: the completed intelligence module's OWN gates suppress its missing-SPF finding",
  !!t1.intel && !(t1.intel.findings || []).some((f) => f.id === "email_intel_spf_missing"),
  JSON.stringify((t1.intel?.findings || []).map((f) => f.id)));
ok("B: sibling-module findings REMAIN publishable (evidence not discarded)",
  t1.titles.length > 0, String(t1.titles.length));
ok("B: every persisted finding is non-email (nothing fabricated, nothing lost)",
  (t1.report?.findings || []).every((f) => f.module !== "email_security"),
  t1.findingIds.join("|"));
ok("B: the customer email domain is EVIDENCE-INSUFFICIENT — never healthy, never complete",
  t1.motEmail.state === "evidence_insufficient" && t1.motEmail.coverage !== "complete",
  JSON.stringify(t1.motEmail));
ok("B: no scan_failed audit — the scan did not fail", !t1.audits.includes("scan_failed"), t1.audits.join("|"));

// ── B1. Reserved-mode admission skip: no SPF/DKIM evidence was executed ─────
console.log("\n── B1. reserved-mode subrequest skip is fail-closed across customer surfaces ──");
const reservedSkip = await trace("reserved-email-skip", {
  capacityMode: "reserved",
  subrequestLimit: 50,
  deterministicProof: true,
});
const reservedCx = emailSkipCustomerOutput(reservedSkip, {
  includeExecutive: true,
  includePdf: true,
});
const reservedExecutiveText = JSON.stringify(reservedCx.executive);
ok("B1: reserved admission produces the exact bare email subrequest-skip shape",
  reservedSkip.email?.skipped === true &&
    reservedSkip.email?.skip_reason === "subrequest_budget" &&
    reservedSkip.email?.executed !== true,
  JSON.stringify(reservedSkip.email));
ok("B1: independently completed DMARC remains projected after the email module skip",
  reservedSkip.report?.modules?.dmarc_core?.skipped !== true &&
    reservedSkip.email?.dmarc?.present === true &&
    reservedSkip.email?.dmarc_detail?.raw === DMARC_REJECT,
  JSON.stringify({
    dmarc_core: reservedSkip.report?.modules?.dmarc_core,
    projected_dmarc: reservedSkip.email?.dmarc,
  }));
ok("B1: engine/report and D1 contain no false SPF finding or DKIM observation",
  reservedCx.report_findings.length === 0 &&
    !reservedSkip.titles.includes("Missing SPF Record") &&
    !reservedSkip.findingIds.includes("email_dkim_not_detected"),
  JSON.stringify({ findings: reservedCx.report_findings, titles: reservedSkip.titles }));
ok("B1: immutable snapshot contains no false SPF/DKIM item or canonical action",
  reservedCx.snapshot_findings.length === 0 &&
    reservedCx.snapshot_observations.length === 0 &&
    reservedCx.actions.length === 0 &&
    reservedCx.managed_cases.length === 0,
  JSON.stringify(reservedCx));
ok("B1: customer email domain is evidence-insufficient, never assessed healthy",
  reservedCx.email_domain?.state === "evidence_insufficient" &&
    reservedCx.email_domain?.coverage !== "complete",
  JSON.stringify(reservedCx.email_domain));
ok("B1: Executive and PDF contain no false finding/action wording",
  !reservedExecutiveText.includes("email_missing_spf") &&
    !reservedExecutiveText.includes("Missing SPF Record") &&
    !reservedExecutiveText.includes("email_dkim_not_detected") &&
    !reservedCx.pdf_text.includes("Missing SPF Record") &&
    !reservedCx.pdf_text.includes("Publish an SPF record") &&
    !reservedCx.pdf_text.includes("DKIM Could Not Be Verified Using Common Selectors"));

// ── B2. POSITIVE engine control: completed scan, genuinely missing SPF ──────
console.log("\n── B2. positive control: fast probes, NO SPF record, DMARC p=none ──");
const t2 = await trace("no-spf");
ok("B2: control scan completed", t2.dbStatus === "completed", JSON.stringify({ db: t2.dbStatus, err: t2.reportError }));
ok("B2: the email module genuinely EXECUTED", t2.email?.executed !== false && t2.email?.outcome !== "deadline_exceeded");
ok("B2: observed SPF absence still produces the email_missing_spf finding",
  t2.findingIds.includes("email_missing_spf"), t2.findingIds.join("|"));
ok('B2: …and persists "Missing SPF Record" to D1', t2.titles.includes("Missing SPF Record"));
ok("B2: …and the spf_missing remediation action IS created",
  t2.emailActions.includes("spf_missing"), JSON.stringify(t2.emailActions));
ok("B2: the genuine p=none policy still surfaces monitoring-only remediation",
  t2.emailActions.includes("dmarc_policy_monitoring_only"), JSON.stringify(t2.emailActions));

// ── B3. Durable Phase-5: slow Email Intel cannot erase CVE/KEV siblings ──────
console.log("\n── B3. durable Phase-5 preserves completed siblings ──");
const t3 = await trace("deferred-intel");
ok("B3: scan completed terminally", t3.dbStatus === "completed", JSON.stringify({ db: t3.dbStatus, err: t3.reportError }));
ok("B3: only Email Intelligence took its independent deadline fallback",
  t3.intel?.executed === false && t3.intel?.outcome === "deadline_exceeded",
  JSON.stringify(t3.intel));
ok("B3: module record attributes the timeout to its own source envelope",
  t3.intel?.reason === "module_budget_exhausted" &&
    t3.intel?.timeout_source === "module_race" &&
    t3.intel?.reason !== "scan_deadline_exhausted",
  JSON.stringify(t3.intel));
ok("B3: completed CVE sibling survives the slow Email Intelligence module",
  t3.report?.modules?.cve_intelligence?.executed !== false &&
    t3.report?.modules?.cve_intelligence?.outcome !== "deadline_exceeded",
  JSON.stringify(t3.report?.modules?.cve_intelligence));
ok("B3: completed KEV sibling survives the slow Email Intelligence module",
  t3.report?.modules?.known_exploited_vulnerabilities?.executed !== false &&
    t3.report?.modules?.known_exploited_vulnerabilities?.outcome !== "deadline_exceeded",
  JSON.stringify(t3.report?.modules?.known_exploited_vulnerabilities));
const t3Telemetry = Object.fromEntries(
  (t3.diagnostics?.modules || []).map((row) => [row.module, row]),
);
ok("B3: telemetry records independent 32s/12s/12s allocations",
  t3Telemetry.cve_intelligence?.allocated_ms === 32_000 &&
    t3Telemetry.known_exploited_vulnerabilities?.allocated_ms === 12_000 &&
    t3Telemetry.email_security_intelligence?.allocated_ms === 12_000,
  JSON.stringify(t3Telemetry));
ok("B3: only Email Intelligence telemetry is a module_race timeout",
  t3Telemetry.cve_intelligence?.timeout === false &&
    t3Telemetry.known_exploited_vulnerabilities?.timeout === false &&
    t3Telemetry.email_security_intelligence?.timeout === true &&
    t3Telemetry.email_security_intelligence?.timeout_source === "module_race",
  JSON.stringify(t3Telemetry));
ok("B3: deferred intel no longer fabricates transport detail for checks that never ran",
  !!t3.email && !Object.prototype.hasOwnProperty.call(t3.email, "mta_sts_detail"),
  JSON.stringify(Object.keys(t3.email || {})));
ok("B3: the COMPLETED primary module keeps its own genuine remediation evidence",
  t3.email?.executed !== false && Array.isArray(t3.email?.remediation_actions),
  JSON.stringify(t3.emailActions));

// ── B3c. Selective MTA-STS bridge + late historical reconciliation ──────────
console.log("\n── B3c. definitive MTA-STS absence bridge and late history ──");
const priorMtaStsFinding = {
  id: "email_intel_mta_sts_missing",
  module: "email_security_intelligence",
  severity: "low",
  title: "MTA-STS policy not published",
};
const mtaMissing = await trace("mta-missing", { previousFindings: [] });
const mtaMainRows = (mtaMissing.report?.findings || [])
  .filter((finding) => finding.id === priorMtaStsFinding.id);
const mtaModuleRows = (mtaMissing.intel?.findings || [])
  .filter((finding) => finding.id === priorMtaStsFinding.id);
const mtaEvidence = mtaMainRows[0]?.evidence || [];
ok("B3c: definitive 404 emits one module row and one explicit main finding",
  mtaModuleRows.length === 1 && mtaMainRows.length === 1 &&
    mtaMainRows[0]?.finding_type === "finding" &&
    mtaMainRows[0]?.severity === "low" && mtaMainRows[0]?.score_impact === 0);
ok("B3c: MTA-STS main finding carries exactly one HTTPS evidence row",
  mtaEvidence.length === 1 &&
    mtaEvidence[0]?.type === "https_probe" &&
    mtaEvidence[0]?.target === "https://mta-sts.example.com/.well-known/mta-sts.txt" &&
    mtaEvidence[0]?.status === 404 &&
    mtaEvidence[0]?.reason === "well_known_404" &&
    mtaEvidence[0]?.source === "cloudflare_workers_fetch" &&
    mtaEvidence[0]?.contract === "cybermeters.serviceability/v1");
ok("B3c: HTTPS evidence is never relabelled as DNS",
  !JSON.stringify(mtaMainRows[0]).includes("dns_txt_lookup") &&
    !JSON.stringify(mtaMainRows[0]).includes("cloudflare_doh"));
ok("B3c: late MTA finding is historical new exactly once",
  mtaMissing.historical?.new_findings?.filter((finding) => finding.id === priorMtaStsFinding.id).length === 1 &&
    !mtaMissing.historical?.resolved_findings?.some((finding) => finding.id === priorMtaStsFinding.id) &&
    !mtaMissing.historical?.not_reobserved_findings?.some((finding) => finding.id === priorMtaStsFinding.id));
ok("B3c: low MTA finding owns Email state and one canonical action",
  mtaMissing.motEmail?.state === "issue_detected" &&
    mtaMissing.snapshot?.observed_findings?.filter((finding) =>
      finding.finding_id === priorMtaStsFinding.id).length === 1 &&
    mtaMissing.snapshot?.remediation_actions?.filter((action) =>
      action.remediation_id === "email.mta_sts.enable").length === 1);
const mtaCx = mtaCustomerOutput(mtaMissing, { includeExecutive: true, includePdf: true });
const mtaSnapshotFinding = mtaCx.snapshot_findings[0];
const mtaExecutiveFinding = mtaCx.executive?.observed_findings?.find((finding) =>
  finding.finding_id === priorMtaStsFinding.id);
ok("B3c CX: positive MTA producer reaches one exact Executive finding and action",
  mtaCx.report_findings.length === 1 && mtaCx.snapshot_findings.length === 1 &&
    mtaCx.email_domain?.state === "issue_detected" &&
    mtaCx.email_domain?.finding_count === 1 &&
    JSON.stringify(mtaCx.email_domain?.finding_ids) === '["email_intel_mta_sts_missing"]' &&
    mtaCx.actions.length === 1 &&
    mtaCx.executive?.remediation_actions?.filter((action) =>
      action.remediation_id === "email.mta_sts.enable").length === 1);
ok("B3c CX: MTA confidence and evidence grade stay exact from report/snapshot to Executive",
  mtaSnapshotFinding?.confidence === mtaCx.report_findings[0]?.confidence &&
    Boolean(mtaSnapshotFinding?.evidence_grade?.grade) &&
    JSON.stringify(mtaExecutiveFinding) === JSON.stringify(mtaSnapshotFinding));
ok("B3c CX: MTA PDF renders exact finding metadata and canonical action before score",
  mtaCx.pdf_text?.includes("[LOW] MTA-STS policy not published") &&
    mtaCx.pdf_text?.includes(
      `Confidence: ${mtaSnapshotFinding?.confidence} - Evidence grade: ${mtaSnapshotFinding?.evidence_grade?.grade}`,
    ) &&
    mtaCx.pdf_text?.includes("Enable MTA-STS") &&
    mtaCx.pdf_text.indexOf("Enable MTA-STS") < mtaCx.pdf_text.indexOf("Assessment Score"));
ok("B3c: TLS-RPT module observations never enter main findings or actions",
  !(mtaMissing.report?.findings || []).some((finding) =>
    finding.id === "email_intel_tls_rpt_missing") &&
    !mtaMissing.snapshot?.remediation_actions?.some((action) =>
      String(action.remediation_id || "").includes("tls_rpt")));

const mtaPersistent = await trace("mta-missing", { previousFindings: [priorMtaStsFinding] });
ok("B3c: repeated definitive absence is persistent, not a transition",
  [
    ...(mtaPersistent.historical?.new_findings || []),
    ...(mtaPersistent.historical?.resolved_findings || []),
    ...(mtaPersistent.historical?.not_reobserved_findings || []),
  ].every((finding) => finding.id !== priorMtaStsFinding.id));
const mtaPresent = await trace("mta-present", { previousFindings: [priorMtaStsFinding] });
ok("B3c: admitted present policy resolves a prior missing-policy finding",
  mtaPresent.historical?.resolved_findings?.filter((finding) =>
    finding.id === priorMtaStsFinding.id).length === 1 &&
    !(mtaPresent.report?.findings || []).some((finding) => finding.id === priorMtaStsFinding.id));
const mtaUnavailable = await trace("mta-unavailable", { previousFindings: [priorMtaStsFinding] });
ok("B3c: unavailable policy observation keeps prior finding not re-observed",
  mtaUnavailable.historical?.not_reobserved_findings?.filter((finding) =>
    finding.id === priorMtaStsFinding.id).length === 1 &&
    !mtaUnavailable.historical?.resolved_findings?.some((finding) =>
      finding.id === priorMtaStsFinding.id) &&
    !(mtaUnavailable.report?.findings || []).some((finding) => finding.id === priorMtaStsFinding.id));
const mtaDeadlineDeferred = await trace("deferred-intel", {
  previousFindings: [priorMtaStsFinding],
});
ok("B3c: deadline-deferred MTA producer keeps the prior finding not re-observed",
  mtaDeadlineDeferred.historical?.not_reobserved_findings?.filter((finding) =>
    finding.id === priorMtaStsFinding.id).length === 1 &&
    !mtaDeadlineDeferred.historical?.resolved_findings?.some((finding) =>
      finding.id === priorMtaStsFinding.id));
const mtaInapplicable = await trace("mta-inapplicable", {
  previousFindings: [priorMtaStsFinding],
});
ok("B3c: mail-inapplicable domain emits no MTA finding and no false resolution",
  mtaInapplicable.email?.applicability?.applicable === false &&
    !(mtaInapplicable.report?.findings || []).some((finding) =>
      finding.id === priorMtaStsFinding.id) &&
    mtaInapplicable.historical?.not_reobserved_findings?.filter((finding) =>
      finding.id === priorMtaStsFinding.id).length === 1 &&
    !mtaInapplicable.historical?.resolved_findings?.some((finding) =>
      finding.id === priorMtaStsFinding.id));
ok("B3c: score and methodology remain byte-identical across the score-neutral bridge",
  mtaMissing.report?.cyber_metrics_score === mtaPresent.report?.cyber_metrics_score &&
    mtaMissing.report?.score_methodology === mtaPresent.report?.score_methodology);

// ── B3d. CT-bounded certificate expiry bridge + late history ─────────────
console.log("\n── B3d. CT-bounded certificate expiry bridge and late history ──");
const certFinding = (traceResult) => (traceResult.report?.findings || [])
  .filter((finding) => String(finding.id || "").startsWith("certificate_expiring_"));
const certDomain = (traceResult) => (traceResult.snapshot?.domains || [])
  .find((entry) => entry.domain_key === "certificates_trust") || null;
const certActions = (traceResult) => (traceResult.snapshot?.remediation_actions || [])
  .filter((action) => action.remediation_id === "cert.expiry.expiring");

const cert13 = await trace("cert-expiry-13", {
  deterministicProof: true,
  previousFindings: [],
});
const cert13Rows = certFinding(cert13);
const cert13Evidence = cert13Rows[0]?.evidence || [];
ok("B3d: 13 days emits one score-neutral high CT finding",
  cert13Rows.length === 1 &&
    cert13Rows[0]?.id === "certificate_expiring_critical" &&
    cert13Rows[0]?.finding_type === "finding" &&
    cert13Rows[0]?.severity === "high" && cert13Rows[0]?.score_impact === 0 &&
    cert13Rows[0]?.days_until_expiry === 13);
ok("B3d: report evidence remains explicitly CT-only and not live-leaf verified",
  cert13Rows[0]?.evidence_source === "certificate_transparency" &&
    cert13Rows[0]?.evidence_basis === "latest_expiring_logged_certificate" &&
    cert13Rows[0]?.live_certificate_verified === false &&
    cert13Evidence.length === 1 &&
    cert13Evidence[0]?.type === "certificate_transparency" &&
    cert13Evidence[0]?.basis === "latest_expiring_logged_certificate" &&
    cert13Evidence[0]?.live_certificate_verified === false &&
    cert13Evidence[0]?.providers?.includes("crt_sh"));
ok("B3d: producer title and description are copied verbatim",
  cert13Rows[0]?.title === cert13.report?.modules?.certificate_intelligence
    ?.suspicious_certificate_signals?.find((row) => row.signal === cert13Rows[0]?.id)?.title &&
    cert13Rows[0]?.description === cert13.report?.modules?.certificate_intelligence
      ?.suspicious_certificate_signals?.find((row) => row.signal === cert13Rows[0]?.id)?.description);
ok("B3d: 13-day finding owns Certificates state, one action, and one history-new row",
  certDomain(cert13)?.state === "issue_detected" &&
    certDomain(cert13)?.finding_count === 1 &&
    JSON.stringify(certDomain(cert13)?.finding_ids) === JSON.stringify(["certificate_expiring_critical"]) &&
    certActions(cert13).length === 1 &&
    typeof certActions(cert13)[0]?.case_id === "string" &&
    cert13.managedCases.filter((row) =>
      row.domain_key === "certificates_trust" &&
      row.id === certActions(cert13)[0]?.case_id).length === 1 &&
    cert13.historical?.new_findings?.filter((finding) =>
      finding.id === "certificate_expiring_critical").length === 1);

const cert14 = await trace("cert-expiry-14", { deterministicProof: true });
const cert29 = await trace("cert-expiry-29", { deterministicProof: true });
const cert30 = await trace("cert-expiry-30", {
  deterministicProof: true,
  previousFindings: [PRIOR_CRITICAL_CERTIFICATE_FINDING],
});
ok("B3d: 14 days emits one medium soon finding",
  certFinding(cert14).length === 1 &&
    certFinding(cert14)[0]?.id === "certificate_expiring_soon" &&
    certFinding(cert14)[0]?.severity === "medium" &&
    certFinding(cert14)[0]?.days_until_expiry === 14);
ok("B3d: 29 days emits one medium soon finding",
  certFinding(cert29).length === 1 &&
    certFinding(cert29)[0]?.id === "certificate_expiring_soon" &&
    certFinding(cert29)[0]?.severity === "medium" &&
    certFinding(cert29)[0]?.days_until_expiry === 29);
ok("B3d: 30 days emits no expiry finding or action and resolves the prior id",
  certFinding(cert30).length === 0 && certActions(cert30).length === 0 &&
    cert30.historical?.resolved_findings?.filter((finding) =>
      finding.id === "certificate_expiring_critical").length === 1 &&
    !cert30.historical?.not_reobserved_findings?.some((finding) =>
      finding.id === "certificate_expiring_critical"));
ok("B3d: score and methodology stay byte-identical across 13/14/29/30",
  [cert14, cert29, cert30].every((candidate) =>
    candidate.report?.cyber_metrics_score === cert13.report?.cyber_metrics_score &&
    JSON.stringify(candidate.report?.score_methodology) === JSON.stringify(cert13.report?.score_methodology)));

const certTlsUnavailable = await trace("cert-tls-unavailable", {
  deterministicProof: true,
  previousFindings: [PRIOR_CRITICAL_CERTIFICATE_FINDING],
});
ok("B3d: unavailable TLS admits no certificate finding and keeps prior evidence not re-observed",
  certFinding(certTlsUnavailable).length === 0 &&
    certTlsUnavailable.historical?.not_reobserved_findings?.filter((finding) =>
      finding.id === "certificate_expiring_critical").length === 1 &&
    !certTlsUnavailable.historical?.resolved_findings?.some((finding) =>
      finding.id === "certificate_expiring_critical"));
const certDeferred = await trace("cert-deferred", {
  deterministicProof: true,
  previousFindings: [PRIOR_CRITICAL_CERTIFICATE_FINDING],
});
ok("B3d: deferred TLS/CT producer keeps the prior expiry finding not re-observed",
  certFinding(certDeferred).length === 0 &&
    certDeferred.historical?.not_reobserved_findings?.filter((finding) =>
      finding.id === "certificate_expiring_critical").length === 1 &&
    !certDeferred.historical?.resolved_findings?.some((finding) =>
      finding.id === "certificate_expiring_critical"));
const certNonComparable = await trace("cert-expiry-13-deferred-intel", {
  deterministicProof: true,
  accelerateDurableCaps: true,
  previousFindings: [],
});
ok("B3d: non-comparable scan keeps the finding but clears transition claims",
  certNonComparable.reportQuality === "partial" &&
    certFinding(certNonComparable).length === 1 &&
    certNonComparable.historical?.comparable === false &&
    certNonComparable.historical?.new_findings?.length === 0 &&
    certNonComparable.historical?.resolved_findings?.length === 0);

// ── B3e. S4 customer-output proof from the engine-created snapshot ───────
console.log("\n── B3e. S4 certificate customer-output parity ──");
const cert13Cx = certCustomerOutput(cert13, { includeExecutive: true, includePdf: true });
const cert14Cx = certCustomerOutput(cert14, { includeExecutive: true, includePdf: true });
const cert29Cx = certCustomerOutput(cert29, { includeExecutive: true, includePdf: true });
const cert30Cx = certCustomerOutput(cert30, { includeExecutive: true, includePdf: true });
const certTlsUnavailableCx = certCustomerOutput(certTlsUnavailable, {
  includeExecutive: true,
  includePdf: true,
});

function certificateCxPositive(name, candidate, expected) {
  const signal = candidate.producer_signals.find((row) => row.signal === expected.id);
  const snapshotItem = candidate.snapshot_cert_findings[0];
  const executiveItems = (candidate.executive?.observed_findings || [])
    .filter((item) => item.finding_id === expected.id);
  const executiveDomain = (candidate.executive?.cyber_mot_domains || [])
    .find((domain) => domain.domain_key === "certificates_trust");
  const executiveActions = (candidate.executive?.remediation_actions || [])
    .filter((action) => action.remediation_id === "cert.expiry.expiring");

  ok(`B3e ${name}: snapshot copies the producer-owned certificate finding verbatim`,
    candidate.snapshot_cert_findings.length === 1 &&
      snapshotItem?.finding_id === expected.id &&
      snapshotItem?.finding_type === "finding" &&
      snapshotItem?.severity === expected.severity &&
      snapshotItem?.module === "certificate_intelligence" &&
      snapshotItem?.score_impact === 0 &&
      snapshotItem?.title === expected.title &&
      snapshotItem?.title === signal?.title &&
      snapshotItem?.explanation === signal?.description &&
      snapshotItem?.domain_keys?.includes("certificates_trust") &&
      candidate.snapshot_cert_observations.length === 0,
    JSON.stringify({ signal, snapshotItem }));
  ok(`B3e ${name}: CT-bounded explanation stays honest`,
    typeof snapshotItem?.explanation === "string" &&
      snapshotItem.explanation.includes(
        "returned by the available Certificate Transparency source",
      ) &&
      snapshotItem.explanation.includes("was not inspected") &&
      !snapshotItem.explanation.includes("service outage") &&
      !snapshotItem.explanation.includes("your certificate") &&
      !snapshotItem.explanation.includes("live certificate was verified"));
  ok(`B3e ${name}: Executive preserves the snapshot item and Certificates domain`,
    executiveItems.length === 1 &&
      JSON.stringify(executiveItems[0]) === JSON.stringify(snapshotItem) &&
      JSON.stringify(executiveDomain) === JSON.stringify(candidate.certificates_domain) &&
      executiveDomain?.state === "issue_detected" &&
      executiveDomain?.finding_count === 1 &&
      JSON.stringify(executiveDomain?.finding_ids) === JSON.stringify([expected.id]));
  ok(`B3e ${name}: one canonical action keeps one exact managed-case link`,
    candidate.cert_actions.length === 1 && executiveActions.length === 1 &&
      executiveActions[0]?.title === "Renew the certificate before expiry" &&
      JSON.stringify(executiveActions[0]?.finding_ids) === JSON.stringify([expected.id]) &&
      typeof executiveActions[0]?.case_id === "string" &&
      candidate.cert_cases.filter((managedCase) =>
        managedCase.id === executiveActions[0]?.case_id).length === 1);
  ok(`B3e ${name}: PDF preserves exact title, severity, and canonical action`,
    candidate.pdf_text.includes(`[${expected.severity.toUpperCase()}] ${expected.title}`) &&
      candidate.pdf_text.includes("Renew the certificate before expiry") &&
      !candidate.pdf_text.includes(`[${expected.severity.toUpperCase()}] Finding`) &&
      !candidate.pdf_text.includes(`[CRITICAL] ${expected.title}`));
  ok(`B3e ${name}: score and methodology remain independently frozen`,
    candidate.score === candidate.paired_score_control &&
      candidate.score_methodology === "2026-08-26.1" &&
      candidate.resolver_version === "2026-08-30.2");
}

certificateCxPositive("13-day", cert13Cx, {
  id: "certificate_expiring_critical",
  severity: "high",
  title: "Logged certificate validity ends within 14 days",
});
certificateCxPositive("14-day", cert14Cx, {
  id: "certificate_expiring_soon",
  severity: "medium",
  title: "Logged certificate validity ends within 30 days",
});
certificateCxPositive("29-day", cert29Cx, {
  id: "certificate_expiring_soon",
  severity: "medium",
  title: "Logged certificate validity ends within 30 days",
});
ok("B3e 14/29-day: producer renewal clause and score bytes stay exact",
  [cert14Cx, cert29Cx].every((candidate) => {
    const item = candidate.snapshot_cert_findings[0];
    const signal = candidate.producer_signals.find((row) =>
      row.signal === "certificate_expiring_soon");
    return item?.explanation === signal?.description &&
      item?.explanation?.endsWith(
        "Plan renewal now so the replacement is deployed before that date.",
      ) && candidate.score === cert13Cx.score &&
      candidate.score_methodology === cert13Cx.score_methodology;
  }));

function certificateCxAbsent(name, candidate) {
  const executiveCertificateFindings = (candidate.executive?.observed_findings || [])
    .filter((item) => CERTIFICATE_EXPIRY_IDS.has(item.finding_id));
  const executiveCertificateActions = (candidate.executive?.remediation_actions || [])
    .filter((action) => action.remediation_id === "cert.expiry.expiring");
  ok(`B3e ${name}: unavailable certificate authority is absent end-to-end`,
    candidate.snapshot_cert_findings.length === 0 &&
      candidate.snapshot_cert_observations.length === 0 &&
      candidate.cert_actions.length === 0 &&
      executiveCertificateFindings.length === 0 &&
      executiveCertificateActions.length === 0 &&
      candidate.certificates_domain?.state !== "issue_detected" &&
      !(candidate.certificates_domain?.finding_ids || []).some((id) =>
        CERTIFICATE_EXPIRY_IDS.has(id)) &&
      !candidate.pdf_text.includes("Logged certificate validity ends within 14 days") &&
      !candidate.pdf_text.includes("Logged certificate validity ends within 30 days") &&
      !candidate.pdf_text.includes("Renew the certificate before expiry"),
    JSON.stringify(candidate.certificates_domain));
}

certificateCxAbsent("30-day", cert30Cx);
certificateCxAbsent("TLS-unavailable", certTlsUnavailableCx);
ok("B3e absence history reuses S3b resolved versus not-reobserved proof",
  cert30Cx.historical?.resolved_findings?.filter((finding) =>
    finding.id === "certificate_expiring_critical").length === 1 &&
    !cert30Cx.historical?.not_reobserved_findings?.some((finding) =>
      finding.id === "certificate_expiring_critical") &&
    certTlsUnavailableCx.historical?.not_reobserved_findings?.filter((finding) =>
      finding.id === "certificate_expiring_critical").length === 1 &&
    !certTlsUnavailableCx.historical?.resolved_findings?.some((finding) =>
      finding.id === "certificate_expiring_critical"));

// ── B4. Legacy waitUntil byte/terminal compatibility ────────────────────────
const t4 = await trace("deferred-intel", { executionContext: "waituntil" });
ok("B4: waitUntil retains the shared all-three 1s terminal fallback",
  [t4.report?.modules?.cve_intelligence, t4.report?.modules?.known_exploited_vulnerabilities, t4.intel]
    .every((module) => module?.executed === false && module?.outcome === "deadline_exceeded"));
const t4Telemetry = (t4.diagnostics?.modules || []).filter((row) =>
  ["cve_intelligence", "known_exploited_vulnerabilities", "email_security_intelligence"].includes(row.module));
ok("B4: waitUntil telemetry remains three shared 1000ms module-race rows",
  t4Telemetry.length === 3 && t4Telemetry.every((row) =>
    row.allocated_ms === 1_000 && row.timeout === true && row.timeout_source === "module_race"),
  JSON.stringify(t4Telemetry));
ok("B4: waitUntil retains the legacy scan-deadline fallback bytes",
  [t4.report?.modules?.cve_intelligence, t4.report?.modules?.known_exploited_vulnerabilities, t4.intel]
    .every((module) => module?.reason === "scan_deadline_exhausted"
      && !Object.prototype.hasOwnProperty.call(module, "timeout_source")));

// ── B5. Other timeout directions preserve their completed siblings ─────────
console.log("\n── B5. slow CVE / slow KEV sibling-preservation directions ──");
const slowCve = await trace("slow-cve", { accelerateDurableCaps: true });
ok("B5: slow CVE alone reaches its module-local fallback",
  slowCve.report?.modules?.cve_intelligence?.reason === "module_budget_exhausted" &&
    slowCve.report?.modules?.cve_intelligence?.timeout_source === "module_race");
ok("B5: slow CVE preserves completed KEV and Email Intelligence",
  slowCve.report?.modules?.known_exploited_vulnerabilities?.outcome !== "deadline_exceeded" &&
    slowCve.intel?.outcome !== "deadline_exceeded");
const slowKev = await trace("slow-kev", { accelerateDurableCaps: true });
ok("B5: slow KEV alone reaches its module-local fallback",
  slowKev.report?.modules?.known_exploited_vulnerabilities?.reason === "module_budget_exhausted" &&
    slowKev.report?.modules?.known_exploited_vulnerabilities?.timeout_source === "module_race");
ok("B5: slow KEV preserves completed CVE and Email Intelligence",
  slowKev.report?.modules?.cve_intelligence?.outcome !== "deadline_exceeded" &&
    slowKev.intel?.outcome !== "deadline_exceeded");

// ── B6. A real abandoned Phase-5 promise resolves after terminal finalization ─
console.log("\n── B6. late Phase-5 completion cannot mutate finalized report ──");
const lateEmail = await trace("late-email-completes", { accelerateDurableCaps: true });
ok("B6: Email Intelligence first persisted the module-local fallback",
  lateEmail.intel?.reason === "module_budget_exhausted" &&
    lateEmail.intel?.timeout_source === "module_race");
ok("B6: underlying Email Intelligence body actually resolved after engine return",
  lateEmail.lateResolvedAfterEngine === true);
ok("B6: finalized R2 report bytes remain unchanged after the late completion",
  lateEmail.reportStableAfterLate === true);

// ── B7. Near-boundary admission proves concurrent MAX, never serialized SUM ─
console.log("\n── B7. Queue/Cron near-boundary max-not-sum engine admission ──");
for (const executionContext of ["queue", "cron"]) {
  const boundary = await trace("complete", { executionContext, phase5ElapsedMs: 70_000 });
  ok(`B7: ${executionContext} reaches the 70s Phase-5 boundary`,
    boundary.diagnostics?.engine_wall_ms === 70_000);
  ok(`B7: ${executionContext} admits all siblings when 32s max fits but 56s sum does not`,
    70_000 + 32_000 < 115_000 && 70_000 + 56_000 >= 115_000 &&
      [
        boundary.report?.modules?.cve_intelligence,
        boundary.report?.modules?.known_exploited_vulnerabilities,
        boundary.intel,
      ].every((module) => module?.outcome !== "deadline_exceeded"),
    JSON.stringify(boundary.diagnostics?.modules));
}

// ── B8. B2 evidence admission: DSE reachability + ASM hand-off ──────────────
console.log("\n── B8. DSE evidence reaches the report without cross-domain ASM cases ──");
const caaFindings = (t2.report?.findings || []).filter((finding) => finding.id === "dse_missing_caa");
const caaDomainKeys = caaFindings.length === 1
  ? CYBER_MOT_DOMAINS.filter((definition) => definition.match(caaFindings[0]))
    .map((definition) => definition.domain_key)
  : [];
const scoreWithoutDse = computeScore({
  ...(t2.report?.modules || {}),
  domain_security_enrichment: undefined,
}, "example.com").score;
ok("B8: complete CAA absence emits exactly one low observation",
  t2.reportQuality === "complete" && caaFindings.length === 1
    && caaFindings[0].finding_type === "observation"
    && caaFindings[0].severity === "low",
  JSON.stringify(caaFindings));
ok("B8: canonical resolver attributes the CAA observation only to Certificates & Trust",
  caaDomainKeys.length === 1 && caaDomainKeys[0] === "certificates_trust",
  JSON.stringify(caaDomainKeys));
ok("B8: score is identical with or without the score-neutral DSE projection",
  t2.report?.cyber_metrics_score === scoreWithoutDse,
  JSON.stringify({ report: t2.report?.cyber_metrics_score, withoutDse: scoreWithoutDse }));
ok("B8: the CAA observation opens no generic ASM case",
  !t2.managedCases.some((row) => row.finding_id === "dse_missing_caa"),
  JSON.stringify(t2.managedCases));

const hsts = await trace("b2-hsts");
ok("B8: short HSTS is retained as an explicit low finding",
  hsts.findingIds.includes("dse_hsts_short_maxage")
    && hsts.report?.findings?.find((finding) => finding.id === "dse_hsts_short_maxage")?.finding_type === "finding");
ok("B8: Website-attributed HSTS opens no cross-domain ASM case",
  !hsts.managedCases.some((row) => row.finding_id === "dse_hsts_short_maxage"),
  JSON.stringify(hsts.managedCases));

const admin = await trace("b2-admin");
ok("B8: explicit admin exposure remains eligible for a managed ASM case",
  admin.findingIds.includes("asset_exposure_sensitive_tool")
    && admin.managedCases.some((row) => row.finding_id === "asset_exposure_sensitive_tool"),
  JSON.stringify(admin.managedCases));
ok("B8: the score-bearing admin host has no duplicate score-zero bucket projection or case",
  !admin.report?.findings?.some((finding) => finding.id.startsWith("admin_surface_"))
    && !admin.managedCases.some((row) => row.finding_id.startsWith("admin_surface_")),
  JSON.stringify({ findings: admin.findingIds, cases: admin.managedCases }));

const unavailableDse = await trace("b2-source-unavailable");
ok("B8: partial source failure invents no DSE finding",
  unavailableDse.reportQuality === "partial"
    && !unavailableDse.findingIds.some((id) => id.startsWith("dse_")),
  JSON.stringify({ quality: unavailableDse.reportQuality, ids: unavailableDse.findingIds }));

const dseVerification = await trace("b2-verification");
ok("B8: verification still receives the full normalized finding set",
  dseVerification.findingIds.includes("dse_hsts_short_maxage")
    && dseVerification.managedCases.some((row) =>
      row.id === "mc-dse" && row.status === "verification_failed"),
  JSON.stringify(dseVerification.managedCases));

// ── B9. B2b admin-service admission + host ownership ──────────────────────
console.log("\n── B9. explicit admin-service admission and one owner per host ──");
const b2bAdmin = await trace("b2b-admin");
const b2bFindings = b2bAdmin.report?.findings || [];
const b2bBuckets = b2bFindings.filter((finding) => finding.id.startsWith("admin_surface_"));
const b2bServices = b2bAdmin.report?.modules?.admin_surface_detection?.services || [];
const b2bActions = b2bAdmin.snapshot?.remediation_actions || [];
const criticalBucket = b2bBuckets.find((finding) => finding.id === "admin_surface_critical");
ok("B9: producer service identities remain explicit findings/observations",
  b2bServices.some((service) => service.hostname === "phpmyadmin.example.com"
      && service.finding_type === "finding")
    && b2bServices.filter((service) => service.hostname === "vcenter-gitlab.example.com"
      && service.finding_type === "finding").length === 2
    && b2bServices.some((service) => service.hostname === "openvpn.example.com"
      && service.finding_type === "observation"),
  JSON.stringify(b2bServices));
ok("B9: score-bearing phpMyAdmin host keeps the single sensitive-tool owner",
  b2bFindings.some((finding) => finding.id === "asset_exposure_sensitive_tool"
      && finding.affected_hosts?.includes("phpmyadmin.example.com"))
    && !b2bBuckets.some((finding) => finding.affected_hosts?.includes("phpmyadmin.example.com")),
  JSON.stringify(b2bFindings));
ok("B9: non-scored vCenter host becomes one explicit score-neutral bucket finding",
  criticalBucket?.finding_type === "finding"
    && criticalBucket.score_impact === 0
    && criticalBucket.affected_hosts?.length === 1
    && criticalBucket.affected_hosts[0] === "vcenter-gitlab.example.com",
  JSON.stringify(b2bBuckets));
ok("B9: same-host GitLab identity remains in inventory but creates no second bucket",
  b2bServices.some((service) => service.hostname === "vcenter-gitlab.example.com"
      && service.product === "GitLab")
    && !b2bBuckets.some((finding) => finding.id === "admin_surface_medium"),
  JSON.stringify({ services: b2bServices, buckets: b2bBuckets }));
ok("B9: hostname-only OpenVPN observation produces no bucket finding or case",
  !b2bBuckets.some((finding) => finding.affected_hosts?.includes("openvpn.example.com"))
    && !b2bAdmin.managedCases.some((row) => row.asset_ref === "openvpn.example.com"),
  JSON.stringify({ buckets: b2bBuckets, cases: b2bAdmin.managedCases }));
ok("B9: canonical actions have one owner for each actionable host",
  b2bActions.filter((action) => action.remediation_id === "asm.exposure.sensitive_tool").length === 1
    && b2bActions.filter((action) => action.remediation_id === "asm.exposure.admin").length === 1,
  JSON.stringify(b2bActions));
ok("B9: managed ASM cases admit the typed bucket and preserve the scored sibling",
  b2bAdmin.managedCases.filter((row) => row.finding_id === "asset_exposure_sensitive_tool").length === 1
    && b2bAdmin.managedCases.filter((row) => row.finding_id === "admin_surface_critical").length === 1
    && !b2bAdmin.managedCases.some((row) => row.finding_id === "asset_exposure_interface_observed"),
  JSON.stringify(b2bAdmin.managedCases));
ok("B9: score remains exactly the unchanged computeScore result",
  b2bAdmin.report?.cyber_metrics_score === computeScore(
    b2bAdmin.report?.modules || {}, "example.com",
  ).score,
  JSON.stringify({ report: b2bAdmin.report?.cyber_metrics_score }));
ok("B9: partial/deferred source evidence invents no admin bucket row",
  unavailableDse.reportQuality === "partial"
    && !unavailableDse.findingIds.some((id) => id.startsWith("admin_surface_")),
  JSON.stringify({ quality: unavailableDse.reportQuality, ids: unavailableDse.findingIds }));

const b2bVcenter = await trace("b2b-vcenter");
const b2bVcenterCx = b2bCustomerOutput(b2bVcenter, {
  includeExecutive: true,
  includePdf: true,
});
const b2bVcenterFinding = b2bVcenterCx.report_admin_findings[0] || null;
const b2bVcenterSnapshotFinding = b2bVcenterCx.snapshot_admin_findings[0] || null;
const b2bVcenterAction = b2bVcenterCx.admin_actions[0] || null;
ok("B9 CX: isolated vCenter is a producer-owned explicit finding",
  b2bVcenterCx.raw_services.length === 1
    && b2bVcenterCx.raw_services[0]?.hostname === "vcenter.example.com"
    && b2bVcenterCx.raw_services[0]?.product === "VMware vCenter"
    && b2bVcenterCx.raw_services[0]?.finding_type === "finding"
    && b2bVcenterCx.raw_services[0]?.risk_level === "critical",
  JSON.stringify(b2bVcenterCx.raw_services));
ok("B9 CX: engine emits the exact score-neutral admin finding",
  b2bVcenterCx.report_admin_findings.length === 1
    && b2bVcenterFinding?.id === "admin_surface_critical"
    && b2bVcenterFinding?.finding_type === "finding"
    && b2bVcenterFinding?.severity === "critical"
    && b2bVcenterFinding?.score_impact === 0
    && b2bVcenterFinding?.title === "Critical Admin Interface Exposed",
  JSON.stringify(b2bVcenterCx.report_admin_findings));
ok("B9 CX: B3 Attack Surface owns exact issue/count/identity",
  b2bVcenterCx.attack_surface_domain?.state === "issue_detected"
    && b2bVcenterCx.attack_surface_domain?.finding_count === 1
    && JSON.stringify(b2bVcenterCx.attack_surface_domain?.finding_ids) ===
      '["admin_surface_critical"]',
  JSON.stringify(b2bVcenterCx.attack_surface_domain));
ok("B9 CX: snapshot preserves finding id/title/severity verbatim",
  b2bVcenterCx.snapshot_admin_findings.length === 1
    && b2bVcenterSnapshotFinding?.finding_id === b2bVcenterFinding?.id
    && b2bVcenterSnapshotFinding?.title === b2bVcenterFinding?.title
    && b2bVcenterSnapshotFinding?.severity === b2bVcenterFinding?.severity
    && b2bVcenterCx.snapshot_admin_observations.length === 0,
  JSON.stringify(b2bVcenterCx.snapshot_admin_findings));
ok("B9 CX: snapshot resolves exactly one canonical admin action",
  b2bVcenterCx.admin_actions.length === 1
    && b2bVcenterAction?.remediation_id === "asm.exposure.admin"
    && b2bVcenterAction?.title === "Restrict administrative interfaces"
    && JSON.stringify(b2bVcenterAction?.finding_ids) === '["admin_surface_critical"]',
  JSON.stringify(b2bVcenterCx.admin_actions));
ok("B9 CX: at most one linked case carries the exact finding identity",
  b2bVcenterCx.admin_cases.length === 1
    && b2bVcenterCx.admin_cases[0]?.finding_id === "admin_surface_critical"
    && b2bVcenterCx.admin_cases[0]?.asset_ref === "vcenter.example.com",
  JSON.stringify(b2bVcenterCx.admin_cases));
ok("B9 CX: Executive projection preserves backend domain/finding/action bytes",
  b2bVcenterCx.executive?.cyber_mot_domains?.find((domain) =>
    domain.domain_key === "attack_surface")?.finding_ids?.[0] === "admin_surface_critical"
    && b2bVcenterCx.executive?.observed_findings?.find((finding) =>
      finding.finding_id === "admin_surface_critical")?.title === b2bVcenterFinding?.title
    && b2bVcenterCx.executive?.observed_findings?.find((finding) =>
      finding.finding_id === "admin_surface_critical")?.severity === b2bVcenterFinding?.severity
    && b2bVcenterCx.executive?.remediation_actions?.filter((action) =>
      action.remediation_id === "asm.exposure.admin").length === 1,
  JSON.stringify({
    domains: b2bVcenterCx.executive?.cyber_mot_domains,
    findings: b2bVcenterCx.executive?.observed_findings,
    actions: b2bVcenterCx.executive?.remediation_actions,
  }));
ok("B9 CX: PDF renders exact backend title/severity and canonical action",
  b2bVcenterCx.pdf_text.includes("[CRITICAL] Critical Admin Interface Exposed")
    && b2bVcenterCx.pdf_text.includes("Restrict administrative interfaces"));
ok("B9 CX: score and score methodology equal the paired no-bucket control",
  b2bVcenterCx.score === b2bVcenterCx.paired_score_control
    && b2bVcenterCx.score_methodology === "2026-08-26.1"
    && b2bVcenterCx.resolver_version === "2026-08-30.2",
  JSON.stringify({
    score: b2bVcenterCx.score,
    paired: b2bVcenterCx.paired_score_control,
    scoreMethodology: b2bVcenterCx.score_methodology,
    resolver: b2bVcenterCx.resolver_version,
  }));
ok("B9 CX: phpMyAdmin remains the one score-bearing owner without admin duplication",
  b2bFindings.filter((finding) =>
    finding.id === "asset_exposure_sensitive_tool"
      && finding.affected_hosts?.includes("phpmyadmin.example.com")).length === 1
    && !b2bBuckets.some((finding) =>
      finding.affected_hosts?.includes("phpmyadmin.example.com"))
    && b2bActions.filter((action) =>
      action.remediation_id === "asm.exposure.sensitive_tool").length === 1
    && b2bAdmin.managedCases.filter((row) =>
      row.finding_id === "asset_exposure_sensitive_tool").length === 1,
  JSON.stringify({ findings: b2bFindings, actions: b2bActions, cases: b2bAdmin.managedCases }));
ok("B9 CX: combined vCenter and GitLab product names remain producer findings with one host claim",
  b2bServices.filter((service) =>
    service.hostname === "vcenter-gitlab.example.com"
      && service.finding_type === "finding").length === 2
    && b2bBuckets.filter((finding) =>
      finding.affected_hosts?.includes("vcenter-gitlab.example.com")).length === 1,
  JSON.stringify({ services: b2bServices, buckets: b2bBuckets }));

const b2bModuleOnlyTrace = await trace("b2b-hostname-only");
const b2bModuleOnly = b2bCustomerOutput(b2bModuleOnlyTrace);
const b2bModuleOnlyFull = b2bFullCustomerProjection(b2bModuleOnlyTrace);
ok("B9 CX: hostname-only GitLab/OpenVPN stay low-confidence module observations",
  ["GitLab", "OpenVPN Access Server"].every((product) =>
    b2bModuleOnly.module_observations.some((service) =>
      service.product === product
        && service.finding_type === "observation"
        && service.confidence === "low")),
  JSON.stringify(b2bModuleOnly.module_observations));
ok("B9 CX: GitLab keeps its separate canonical sensitive-subdomain producer truth",
  b2bModuleOnlyFull.report_findings.some((finding) =>
    finding.id === "subdomain_sensitive_gitlab_example_com"
      && finding.finding_type === "finding")
    && b2bModuleOnly.attack_surface_domain?.finding_ids?.includes(
      "subdomain_sensitive_gitlab_example_com")
    && b2bModuleOnlyFull.remediation_actions.some((action) =>
      action.remediation_id === "asm.subdomain.sensitive"),
  JSON.stringify({
    findings: b2bModuleOnlyFull.report_findings,
    domain: b2bModuleOnly.attack_surface_domain,
    actions: b2bModuleOnlyFull.remediation_actions,
  }));
ok("B9 CX: hostname-only product guesses have no admin customer projection",
  b2bModuleOnly.report_admin_findings.length === 0
    && b2bModuleOnly.snapshot_admin_findings.length === 0
    && b2bModuleOnly.snapshot_admin_observations.length === 0
    && b2bModuleOnly.admin_actions.length === 0
    && b2bModuleOnly.admin_cases.length === 0
    && !(b2bModuleOnly.attack_surface_domain?.finding_ids || [])
      .some((id) => String(id).startsWith("admin_surface_")),
  JSON.stringify(b2bModuleOnly));

const b2bOpenvpnTrace = await trace("b2b-openvpn-only", { deterministicProof: true });
const b2bOpenvpn = b2bCustomerOutput(b2bOpenvpnTrace);
const b2bOpenvpnFull = b2bFullCustomerProjection(b2bOpenvpnTrace);
const b2bOpenvpnCleanTrace = await traceOpenvpnCleanControl();
const b2bOpenvpnClean = b2bCustomerOutput(b2bOpenvpnCleanTrace);
const b2bOpenvpnCleanFull = b2bFullCustomerProjection(b2bOpenvpnCleanTrace);
ok("B9 CX2: isolated OpenVPN remains one low-confidence module-only observation",
  b2bOpenvpn.raw_services.length === 1
    && b2bOpenvpn.module_observations.length === 1
    && b2bOpenvpn.module_observations[0]?.hostname === "openvpn.example.com"
    && b2bOpenvpn.module_observations[0]?.product === "OpenVPN Access Server"
    && b2bOpenvpn.module_observations[0]?.finding_type === "observation"
    && b2bOpenvpn.module_observations[0]?.confidence === "low"
    && b2bOpenvpnClean.raw_services.length === 0,
  JSON.stringify({ openvpn: b2bOpenvpn.raw_services, clean: b2bOpenvpnClean.raw_services }));
ok("B9 CX2: OpenVPN changes no complete report finding/score/risk projection",
  JSON.stringify(b2bOpenvpnFull.report_findings) ===
      JSON.stringify(b2bOpenvpnCleanFull.report_findings)
    && b2bOpenvpnFull.report_score === b2bOpenvpnCleanFull.report_score
    && b2bOpenvpnFull.report_risk_level === b2bOpenvpnCleanFull.report_risk_level,
  JSON.stringify({
    openvpn: b2bOpenvpnFull.report_findings,
    clean: b2bOpenvpnCleanFull.report_findings,
  }));
ok("B9 CX2: OpenVPN changes no eight-domain customer state/count/identity bytes",
  JSON.stringify(b2bOpenvpnFull.domains) === JSON.stringify(b2bOpenvpnCleanFull.domains)
    && b2bOpenvpn.attack_surface_domain?.state === "assessed_healthy"
    && b2bOpenvpn.attack_surface_domain?.finding_count === 0
    && JSON.stringify(b2bOpenvpn.attack_surface_domain?.finding_ids) === "[]",
  JSON.stringify({
    openvpn: b2bOpenvpn.attack_surface_domain,
    clean: b2bOpenvpnClean.attack_surface_domain,
  }));
ok("B9 CX2: OpenVPN changes no snapshot finding/observation/action/case bytes",
  JSON.stringify(b2bOpenvpnFull.observed_findings) ===
      JSON.stringify(b2bOpenvpnCleanFull.observed_findings)
    && JSON.stringify(b2bOpenvpnFull.observations) ===
      JSON.stringify(b2bOpenvpnCleanFull.observations)
    && JSON.stringify(b2bOpenvpnFull.remediation_actions) ===
      JSON.stringify(b2bOpenvpnCleanFull.remediation_actions)
    && JSON.stringify(b2bOpenvpnFull.managed_cases) ===
      JSON.stringify(b2bOpenvpnCleanFull.managed_cases),
  JSON.stringify({
    observed: b2bOpenvpnFull.observed_findings,
    observations: b2bOpenvpnFull.observations,
    actions: b2bOpenvpnFull.remediation_actions,
    cases: b2bOpenvpnFull.managed_cases,
  }));
ok("B9 CX2: OpenVPN changes no Executive or PDF customer bytes",
  JSON.stringify(b2bOpenvpnFull.executive) === JSON.stringify(b2bOpenvpnCleanFull.executive)
    && b2bOpenvpnFull.pdf_text === b2bOpenvpnCleanFull.pdf_text);

// ── L. LIFECYCLE / CASE NON-PROGRESSION ─────────────────────────────────────
console.log("\n── L. email case non-progression on the incomplete observation ──");
const lf = await trace("deferred-email", { seed: true });
console.log(`   BEFORE case=awaiting_verification    AFTER case=${lf.caseAfter.status} verified_at=${lf.caseAfter.verified_at}`);
ok("L: the email case did NOT advance to verification/resolution",
  !["verification_requested", "verifying", "resolved", "verified"].includes(lf.caseAfter.status), String(lf.caseAfter.status));
ok("L: the email case was NOT verified", lf.caseAfter.verified_at == null, String(lf.caseAfter.verified_at));
ok("L: it remains awaiting_verification", lf.caseAfter.status === "awaiting_verification", String(lf.caseAfter.status));
ok("L: the CANONICAL gate refuses email verification on a partial scan",
  moduleCompletionGate({ email_security: deadlineDeferredEmailModuleResult() },
    { status: "partial", modules_skipped: ["email_security"] }).canVerify("email_security") === false);
ok("L: the same gate ALLOWS it on a complete scan (positive control)",
  moduleCompletionGate({ email_security: {} }, { status: "complete", modules_skipped: [] }).canVerify("email_security") === true);

// ── M. MUTATIONS (anchor-guarded, pinned, killed in a FRESH process) ────────
// Each mutant is applied IN PLACE, exercised through a child process that
// imports the mutated module graph and runs the real engine trace or the
// customer-output builder surface, then restored. A mutant is killed only when
// the child's CUSTOMER-VISIBLE output regresses (fabricated finding/action,
// fabricated transport detail, suppressed positive control, or a failed scan).
console.log("\n── M. mutation proof ──");
const SCAN_ENGINE = path.join(root, "workers/scan-api/src/engines/scan-engine.js");
const SCAN_BUDGET = path.join(root, "workers/scan-api/src/engines/scan-budget.js");
const EMAIL_ANALYSIS = path.join(root, "workers/scan-api/src/engines/email-analysis.js");
const SCORING = path.join(root, "workers/scan-api/src/engines/scoring.js");

function runChild(mode) {
  const out = execFileSync(process.execPath, [selfPath, `--child=${mode}`], {
    cwd: root, timeout: 180_000, maxBuffer: 32 * 1024 * 1024,
  });
  return JSON.parse(String(out));
}
async function withMutant(edits, run) {
  const originals = new Map();
  const planned = new Map();
  for (const { target, from, to } of edits) {
    const original = originals.get(target) ?? fs.readFileSync(target, "utf8");
    if (!originals.has(target)) originals.set(target, original);
    const current = planned.get(target) ?? original;
    const count = current.split(from).length - 1;
    if (count !== 1) return { applied: false, reason: `anchor x${count} in ${path.basename(target)}` };
    planned.set(target, current.replace(from, to));
  }
  for (const [target, source] of planned) fs.writeFileSync(target, source);
  try { return { applied: true, result: await run() }; }
  finally { for (const [target, src] of originals) fs.writeFileSync(target, src); }
}

const MUTATIONS = [
  {
    name: "M1 the mismatched bare fallback schema is restored",
    edits: [{
      target: SCAN_ENGINE,
      from: "runCappedModule(\"email_security\",       { fallback: deadlineDeferredEmailModuleResult,",
      to:   "runCappedModule(\"email_security\",       { fallback: () => markDeadlineDeferred({ spf: {}, dmarc: {}, dkim: {}, source: \"email_security\" }),",
    }],
    // The new scoring guard contains the old false finding too, so pin the
    // original fallback defect at the customer report contract it still breaks:
    // the canonical nullable detail field disappears entirely.
    check: () => {
      const r = runChild("deferred-email");
      return !Object.prototype.hasOwnProperty.call(r.email || {}, "spf_detail");
    },
  },
  {
    name: "M2 the wrong-module-only completion guard is restored",
    edits: [{
      target: SCAN_ENGINE,
      from: "    const emailIntelUsable =\n      isPublishableModuleEvidence(modules.email_security_intelligence) && emailApplicability.applicable;",
      to:   "    const emailIntelUsable =\n      !modules.email_security_intelligence.error && !modules.email_security_intelligence.skipped && emailApplicability.applicable;",
    }],
    // A deadline-deferred intelligence result passes the old guard → the report
    // fabricates MTA-STS transport detail for a probe that never ran.
    check: () => runChild("deferred-intel").hasMtaStsDetail === true,
  },
  {
    name: "M3 executed:false is accepted as publishable evidence",
    edits: [{
      target: SCAN_BUDGET,
      from: "    && mod.executed !== false\n",
      to:   "",
    }],
    check: () => {
      const f = runChild("builder-flags").executedFalse;
      return Array.isArray(f.ids) && f.ids.includes("spf_missing");
    },
  },
  {
    name: "M4 incomplete:true is accepted as publishable evidence",
    edits: [{
      target: SCAN_BUDGET,
      from: "    && mod.incomplete !== true\n",
      to:   "",
    }],
    check: () => {
      const f = runChild("builder-flags").incompleteTrue;
      return Array.isArray(f.ids) && f.ids.includes("spf_missing");
    },
  },
  {
    name: "M5 the unsafe detail dereference is restored (builder refusal + engine primary gate removed)",
    edits: [
      {
        target: EMAIL_ANALYSIS,
        from: "  if (!isPublishableEmailEvidence(details)) return [];\n",
        to:   "",
      },
      {
        target: SCAN_ENGINE,
        from: "    if (emailIntelUsable && isPublishableEmailEvidence(modules.email_security)) {",
        to:   "    if (emailIntelUsable) {",
      },
    ],
    // The deferred module reaches the builder again; its null spf_detail is
    // dereferenced and the WHOLE scan fails — the original P1.
    check: () => {
      const r = runChild("deferred-email");
      return r.dbStatus === "failed" && /raw/.test(String(r.reportError || ""));
    },
  },
  {
    name: "M6 the genuine completed missing-SPF positive control is suppressed",
    edits: [{
      target: EMAIL_ANALYSIS,
      from: "  if (!spf.raw) {\n    if (!spfUnobserved) {",
      to:   "  if (!spf.raw) {\n    if (false) {",
    }],
    // A real completed scan proving SPF absent must still create spf_missing;
    // the mutant silently drops the legitimate action.
    check: () => {
      const r = runChild("no-spf");
      return !r.emailActions.includes("spf_missing");
    },
  },
  {
    name: "M7 an unobserved SPF probe is converted into 'SPF missing' again",
    edits: [{
      target: EMAIL_ANALYSIS,
      from: "  const spfUnobserved = isEmailProbeUnobserved(details.spf_evidence_status);",
      to:   "  const spfUnobserved = false;",
    }],
    check: () => {
      const f = runChild("builder-flags").unavailableSpf;
      return Array.isArray(f.ids) && f.ids.includes("spf_missing");
    },
  },
  {
    name: "P1 reserved skipped email is treated as observed again",
    edits: [{
      target: SCORING,
      from: `    const emailModuleUnobserved = modules.email_security?.skipped === true ||
      modules.email_security?.executed === false;`,
      to:   "    const emailModuleUnobserved = false;",
    }],
    check: () => {
      const value = runChild("reserved-email-skip-cx");
      return value.customer.report_findings.some((finding) =>
        FALSE_EMAIL_FINDING_IDS.has(finding.id));
    },
  },
  {
    name: "M8 DSE is computed from an empty pre-Phase-1 module carrier",
    edits: [{
      target: SCAN_ENGINE,
      from: "modules.domain_security_enrichment = runDomainSecurityEnrichmentModule(domain, modules);",
      to:   "modules.domain_security_enrichment = runDomainSecurityEnrichmentModule(domain, {});",
    }],
    check: () => !runChild("b2-hsts").findingIds.includes("dse_hsts_short_maxage"),
  },
  {
    name: "M9 ASM admission accepts an explicit observation",
    edits: [{
      target: SCAN_ENGINE,
      from: "      if (!isActionableFinding(finding)) return false;",
      to:   "      if (false) return false;",
    }],
    check: () => runChild("b2b-admin").managedCases
      .some((row) => row.finding_id === "asset_exposure_interface_observed"),
  },
  {
    name: "M10 DSE domain attribution is bypassed",
    edits: [{
      target: SCAN_ENGINE,
      from: "      return domainKeys.length === 1 && domainKeys[0] === \"attack_surface\";",
      to:   "      return true;",
    }],
    check: () => runChild("b2-hsts").managedCases
      .some((row) => row.finding_id === "dse_hsts_short_maxage"),
  },
  {
    name: "M11 verification receives the filtered case-creation subset",
    edits: [{
      target: SCAN_ENGINE,
      from: "await verifyManagedAsmCasesForScan(scanId, domainId, domain, normalizedFindings, env, {",
      to:   "await verifyManagedAsmCasesForScan(scanId, domainId, domain, managedAsmFindings, env, {",
    }],
    check: () => runChild("b2-verification").managedCases
      .some((row) => row.id === "mc-dse" && row.status !== "verification_failed"),
  },
  {
    name: "B1 raw MTA observation token replaces canonical admission",
    edits: [{
      target: SCAN_ENGINE,
      from: "mtaStsAdmission(mtaStsEvidence).missing_finding === true",
      to:   'mtaStsEvidence?.observation_state === "definitive_absent"',
    }],
    check: () => runChild("b2c-contract").canonicalAdmission === false,
  },
  {
    name: "B2 bridge drops publishability and applicability admission",
    edits: [{
      target: SCAN_ENGINE,
      from: `      emailIntelUsable &&
      emailApplicability.applicable &&
      mtaStsAdmission(mtaStsEvidence).missing_finding === true &&`,
      to: `      true &&
      true &&
      mtaStsAdmission(mtaStsEvidence).missing_finding === true &&`,
    }],
    check: () => runChild("mta-inapplicable").findingIds
      .includes("email_intel_mta_sts_missing"),
  },
  {
    name: "B3 source selection widens beyond the exact MTA-STS row",
    edits: [{
      target: SCAN_ENGINE,
      from: '        finding?.id === "email_intel_mta_sts_missing" &&\n        finding?.module === "email_security_intelligence" &&',
      to:   '        finding?.module === "email_security_intelligence" &&',
    }],
    check: () => !runChild("mta-missing").findingIds.includes("email_intel_mta_sts_missing"),
  },
  {
    name: "B4 TLS-RPT is bridged instead of MTA-STS",
    edits: [{
      target: SCAN_ENGINE,
      from: '        finding?.id === "email_intel_mta_sts_missing" &&\n        finding?.module === "email_security_intelligence" &&',
      to:   '        finding?.id === "email_intel_tls_rpt_missing" &&\n        finding?.module === "email_security_intelligence" &&',
    }],
    check: () => {
      const value = runChild("mta-missing");
      return !value.findingIds.includes("email_intel_mta_sts_missing") ||
        value.findingIds.includes("email_intel_tls_rpt_missing");
    },
  },
  {
    name: "B5 explicit customer finding type is omitted",
    edits: [{
      target: SCAN_ENGINE,
      from: '        finding_type: "finding",\n        severity: "low",',
      to:   '        severity: "low",',
    }],
    check: () => runChild("mta-missing").findings
      .some((finding) => finding.id === "email_intel_mta_sts_missing" &&
        finding.finding_type !== "finding"),
  },
  {
    name: "B6 explicit HTTPS evidence is dropped",
    edits: [{
      target: SCAN_ENGINE,
      from: `        evidence: [{
          type: "https_probe",
          target: \`https://mta-sts.\${domain}/.well-known/mta-sts.txt\`,
          status: 404,
          reason: "well_known_404",
          source: "cloudflare_workers_fetch",
          contract: mtaStsEvidence.serviceability.contract_version,
        }],`,
      to:   "        evidence: [],",
    }],
    check: () => runChild("mta-missing").findings
      .some((finding) => finding.id === "email_intel_mta_sts_missing" &&
        (finding.evidence.length !== 1 ||
          finding.evidence[0]?.type !== "https_probe" ||
          finding.evidence[0]?.source !== "cloudflare_workers_fetch" ||
          finding.evidence[0]?.reason !== "well_known_404")),
  },
  {
    name: "B7 exact single-row and main-id dedupe guards are removed",
    edits: [
      {
        target: SCAN_ENGINE,
        from: "      mtaStsMissingRows.length === 1 &&",
        to:   "      mtaStsMissingRows.length >= 1 &&",
      },
      {
        target: SCAN_ENGINE,
        from: '      !findings.some((finding) => finding?.id === "email_intel_mta_sts_missing")',
        to:   "      true",
      },
    ],
    check: () => {
      const contract = runChild("b2c-contract");
      return contract.exactSingleSource === false && contract.mainIdDedupe === false;
    },
  },
  {
    name: "B8 low score-neutral MTA finding is changed to scored high",
    edits: [{
      target: SCAN_ENGINE,
      from: '        finding_type: "finding",\n        severity: "low",\n        score_impact: 0,',
      to:   '        finding_type: "finding",\n        severity: "high",\n        score_impact: -5,',
    }],
    check: () => runChild("mta-missing").findings
      .some((finding) => finding.id === "email_intel_mta_sts_missing" &&
        (finding.severity !== "low" || finding.score_impact !== 0)),
  },
];

for (const m of MUTATIONS) {
  const { applied, reason, result } = await withMutant(m.edits, async () => m.check());
  if (!applied) { failed += 1; console.error(`FAIL ${m.name} — mutation anchor missing (${reason})`); continue; }
  if (result === true) { killed += 1; console.log(`KILLED ${m.name}`); }
  else { failed += 1; console.error(`FAIL ${m.name} — mutant SURVIVED (defect not reintroduced or not detected)`); }
}
ok(`M: all ${EXPECTED_MUTANTS} pinned mutants applied and killed`, killed === EXPECTED_MUTANTS, `${killed}/${EXPECTED_MUTANTS}`);

console.log(`\n${passed} passed, ${failed} failed, ${killed}/${EXPECTED_MUTANTS} mutants killed`);
process.exit(failed ? 1 : 0);
