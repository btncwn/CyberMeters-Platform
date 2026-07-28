#!/usr/bin/env node
// Real runScanEngine complete -> partial trace through terminal persistence and
// the authenticated customer Business Risk route.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const workerRoot = path.join(root, "workers", "scan-api", "src");
const { runScanEngine } = await import(pathToFileURL(path.join(workerRoot, "engines", "scan-engine.js")).href);
const worker = await import(pathToFileURL(path.join(workerRoot, "index.js")).href);

const NOW = "2026-07-28T09:00:00.000Z";
const PARTIAL_NOW = new Date(Date.parse(NOW) + 60 * 60 * 1000).toISOString();
const EXPECTED_ASSERTIONS = 24;
let passed = 0;
let failed = 0;
const check = (name, condition, detail = "") => {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) =>
  check(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); } catch { /* convergent overlap */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const name of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((entry) => entry.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", name));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes, last_row_id: Number(result.lastInsertRowid || 0) } };
    },
  });
  return {
    prepare: (sql) => statement(sql),
    batch: async (statements) => {
      const results = [];
      db.exec("BEGIN");
      try {
        for (const entry of statements) {
          results.push(/^\s*select/i.test(entry.__sql) ? await entry.all() : await entry.run());
        }
        db.exec("COMMIT");
        return results;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
  };
}

function makeR2(store) {
  return {
    get: async (key) => {
      const body = store.get(String(key));
      return body == null ? null : {
        text: async () => body,
        json: async () => JSON.parse(body),
      };
    },
    put: async (key, body) => { store.set(String(key), String(body)); return {}; },
    delete: async (key) => { store.delete(String(key)); return {}; },
    head: async () => null,
    list: async () => ({ objects: [] }),
  };
}

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});

let providerMode = "complete";
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input) => {
  const url = new URL(String(input));
  if (url.hostname === "crt.sh") {
    if (providerMode === "partial") return jsonResponse({}, 403);
    return jsonResponse([{
      id: 1,
      name_value: "example.com\nwww.example.com",
      common_name: "example.com",
      issuer_name: "BRS Fixture CA",
      entry_timestamp: "2026-07-28T08:00:00.000Z",
      not_before: "2026-07-01T00:00:00.000Z",
      not_after: "2026-11-01T00:00:00.000Z",
    }]);
  }
  if (url.hostname === "api.certspotter.com") {
    return jsonResponse([{
      id: "brs-cert",
      not_before: "2026-07-01T00:00:00.000Z",
      not_after: "2026-11-01T00:00:00.000Z",
      issuer: { name: "BRS Fixture CA" },
      dns_names: ["example.com", "www.example.com"],
    }]);
  }
  if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
    const name = String(url.searchParams.get("name") || "").toLowerCase();
    const type = String(url.searchParams.get("type") || "A").toUpperCase();
    if (name === "example.com" && type === "A") {
      return jsonResponse({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
    }
    return jsonResponse({ Status: 0, Answer: [] });
  }
  return new Response("<html><head><title>Example</title></head><body>ok</body></html>", {
    status: 200,
    headers: { "content-type": "text/html", server: "brs-engine-trace" },
  });
};

try {
  const db = buildDb();
  const store = new Map();
  const env = {
    cybermeters_db: makeD1(db),
    cybermeters_reports: makeR2(store),
    SCAN_CAPACITY_MODE: "legacy",
    SCAN_SUBREQUEST_LIMIT: "200",
    SCAN_DEADLINE_MS: "19000",
    APP_VERSION: "brs-partial-scan-engine-trace",
    MFA_ENCRYPTION_KEY: "brs-partial-scan-engine-trace-key",
    ALLOWED_ORIGIN: "https://app.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    RESEND_API_KEY: "",
    ADMIN_EMAILS: "",
  };
  db.prepare(`
    INSERT INTO users (id,email,name,plan,status,email_verified,mfa_enabled)
    VALUES ('user','founder@example.com','Founder','starter','active',1,0)
  `).run();
  db.prepare(`
    INSERT INTO workspaces (id,name,owner_user_id,deleted_at)
    VALUES ('ws','Founder Workspace','user',NULL)
  `).run();
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES ('member','ws','user','admin')").run();
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES ('dom','user','example.com')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES ('ws','dom')").run();
  db.prepare(`
    INSERT INTO subscriptions (id,owner_user_id,plan,subscription_status,current_period_end,created_at)
    VALUES ('sub','user','starter','active','2026-08-28T00:00:00.000Z','2026-07-28T00:00:00.000Z')
  `).run();

  const run = async (scanId, createdAt, nowMs) => {
    db.prepare(`
      INSERT INTO scans (id,workspace_id,domain_id,domain,status,scan_quality,created_at)
      VALUES (?, 'ws', 'dom', 'example.com', 'running', NULL, ?)
    `).run(scanId, createdAt);
    let error = null;
    try {
      await runScanEngine(scanId, "dom", "ws", "example.com", env, {
        now: () => nowMs,
        executionContext: "queue",
        trigger: "manual",
      });
    } catch (caught) {
      error = caught;
    }
    return error;
  };

  providerMode = "complete";
  const completeError = await run("scan-complete", NOW, Date.parse(NOW));
  eq("real complete engine trace does not throw", completeError, null);
  const completeScan = db.prepare("SELECT status,scan_quality FROM scans WHERE id='scan-complete'").get();
  eq("real first scan terminal completed", completeScan.status, "completed");
  eq("real first scan canonical complete quality", completeScan.scan_quality, "complete");
  const completeBrs = db.prepare(
    "SELECT score,risk_band,calculated_at,payload_json FROM workspace_brs_scores WHERE workspace_id='ws'"
  ).get();
  check("real complete scan persists numeric canonical BRS", Number.isFinite(completeBrs?.score));
  eq("real complete scan appends one canonical BRS history point",
    db.prepare("SELECT COUNT(*) n FROM workspace_brs_score_history WHERE workspace_id='ws'").get().n, 1);
  eq("real complete scan appends one complete scan trend point",
    db.prepare("SELECT COUNT(*) n FROM historical_scores WHERE workspace_id='ws' AND brs_score IS NOT NULL").get().n, 1);
  const completePayload = JSON.parse(completeBrs.payload_json);
  eq("real complete scan exact BRS basis", completePayload.basis_scan.scan_id, "scan-complete");
  eq("real complete scan basis quality", completePayload.basis_scan.scan_quality, "complete");

  providerMode = "partial";
  const partialError = await run("scan-partial", PARTIAL_NOW, Date.parse(PARTIAL_NOW));
  eq("real partial engine trace does not throw", partialError, null);
  const partialScan = db.prepare("SELECT status,scan_quality FROM scans WHERE id='scan-partial'").get();
  eq("real second scan terminal completed", partialScan.status, "completed");
  eq("real second scan canonical partial quality", partialScan.scan_quality, "partial");
  eq("real partial scan preserves canonical BRS byte-for-byte", JSON.stringify(db.prepare(
    "SELECT score,risk_band,calculated_at,payload_json FROM workspace_brs_scores WHERE workspace_id='ws'"
  ).get()), JSON.stringify(completeBrs));
  eq("real partial scan does not append canonical history",
    db.prepare("SELECT COUNT(*) n FROM workspace_brs_score_history WHERE workspace_id='ws'").get().n, 1);
  eq("real partial scan does not append a numeric BRS trend point",
    db.prepare("SELECT COUNT(*) n FROM historical_scores WHERE workspace_id='ws' AND brs_score IS NOT NULL").get().n, 1);
  eq("real partial scan historical row records NULL BRS",
    db.prepare("SELECT brs_score FROM historical_scores WHERE scan_id='scan-partial'").get()?.brs_score, null);

  const token = "brs-engine-route-token";
  db.prepare(`
    INSERT INTO user_sessions (id,user_id,token_hash,expires_at)
    VALUES ('session','user',?, '2026-08-28T00:00:00.000Z')
  `).run(await worker.hashToken(token));
  const response = await worker.default.fetch(new Request(
    "https://api.cybermeters.com/api/workspaces/ws/business-risk",
    { headers: { Authorization: `Bearer ${token}` } },
  ), env, { waitUntil: () => {}, passThroughOnException: () => {} });
  const body = await response.json();
  eq("real authenticated Business Risk route returns 200", response.status, 200);
  eq("customer route latest partial state", body.state, "latest_incomplete");
  eq("customer route current score unavailable", body.score, null);
  eq("customer route current grade unavailable", body.grade, null);
  eq("customer route identifies latest partial scan", body.current_assessment.scan_id, "scan-partial");
  eq("customer route identifies historical complete basis", body.last_complete_assessment.basis_scan.scan_id, "scan-complete");
  check("customer route separates latest and basis scans",
    body.current_assessment.scan_id !== body.last_complete_assessment.basis_scan.scan_id);
  eq("customer route trend contains complete points only", body.trend.length, 1);
  eq("customer route trend basis is exact complete scan", body.trend[0].basis_scan_id, "scan-complete");

  if (passed + failed !== EXPECTED_ASSERTIONS) {
    failed += 1;
    console.error(`FAIL pinned assertion count — got ${passed + failed - 1} want ${EXPECTED_ASSERTIONS}`);
  }
  console.log(`BRS real engine trace: ${passed}/${passed + failed} assertions passed`);
  if (failed > 0 || passed !== EXPECTED_ASSERTIONS) process.exit(1);
  console.log("BRS real engine trace passed");
} finally {
  globalThis.fetch = originalFetch;
}
