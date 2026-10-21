#!/usr/bin/env node
// Synthetic MSP portfolio fixture for the dedicated STAGING database only.
//
// Two synthetic MSP accounts (A with three client workspaces, B with two), each
// client with one domain scanned three times over two weeks. Every scan runs the
// REAL scan engine (runScanEngine) locally against an in-memory database built
// from schema.sql + migrations; DNS answers come from the fixed table below and
// every other network call is refused, so nothing leaves this machine. The rows
// the engine writes (scans, findings, per-domain state history, report snapshot
// index, …) and the report objects it stores are exported for import into
// cybermeters-db-staging and cybermeters-reports-staging.
//
// This is SYNTHETIC data: it proves the portfolio UI, API and isolation between
// two MSPs, not a real external scan. The MSP plan rows are staging-only test
// rows with no Stripe identifiers.
//
//   node scripts/generate-msp-staging-fixture.mjs            # writes local/msp-staging/
//   node scripts/generate-msp-staging-fixture.mjs --verify   # also drives the real
//        API handler against the generated data (sign-in, portfolio, isolation)
//
// Writes only under local/ (ignored). Never contacts Cloudflare.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outDir = path.join(root, "local", "msp-staging");
const src = (...p) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...p)).href;
const DAY = 86_400_000;
const STAGING_API = "https://api-staging.cybermeters.com";
const STAGING_APP = "https://app-staging.cybermeters.com";

// ── The synthetic portfolio ────────────────────────────────────────────────
// Reserved .example names (RFC 2606). Each client's DMARC/SPF changes across
// its three scans so the per-domain trend has something honest to show.
const SPF = '"v=spf1 include:_spf.mail.example -all"';
const DMARC = (p) => `"v=DMARC1; p=${p}; rua=mailto:dmarc-reports@mail.example"`;
export const MSP_STAGING_PORTFOLIO = Object.freeze([
  { key: "a", name: "Synthetic MSP A (staging test)", clients: [
    { key: "a1", name: "Northwind Dental (synthetic)", domain: "northwind-dental.example", scans: [
      { spf: SPF, dmarc: DMARC("none") }, { spf: SPF, dmarc: DMARC("quarantine") }, { spf: SPF, dmarc: DMARC("reject") }] },
    { key: "a2", name: "Harbour Accounts (synthetic)", domain: "harbour-accounts.example", scans: [
      { spf: null, dmarc: null }, { spf: SPF, dmarc: null }, { spf: SPF, dmarc: DMARC("none") }] },
    { key: "a3", name: "Maple Legal (synthetic)", domain: "maple-legal.example", scans: [
      { spf: SPF, dmarc: DMARC("reject") }, { spf: SPF, dmarc: DMARC("reject") }, { spf: SPF, dmarc: DMARC("reject") }] },
  ] },
  { key: "b", name: "Synthetic MSP B (staging test)", clients: [
    { key: "b1", name: "Riverside Vets (synthetic)", domain: "riverside-vets.example", scans: [
      { spf: SPF, dmarc: DMARC("none") }, { spf: SPF, dmarc: DMARC("none") }, { spf: SPF, dmarc: DMARC("quarantine") }] },
    { key: "b2", name: "Quayside Cafe (synthetic)", domain: "quayside-cafe.example", scans: [
      { spf: SPF, dmarc: DMARC("reject") }, { spf: null, dmarc: DMARC("reject") }, { spf: SPF, dmarc: DMARC("reject") }] },
  ] },
]);
const SCAN_AGES_DAYS = [14, 7, 0];
// The client sites' address must pass the public-address guard (safeFetch); it is
// the address long used for IANA's example domains and is never contacted here.
const SITE_ADDRESS = "93.184.216.34";
// Website response headers the synthetic sites send (stubbed; never fetched).
const BASE_HEADERS = Object.freeze({
  "strict-transport-security": "max-age=31536000; includeSubDomains",
  "content-security-policy": "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
});

const ids = {
  user: (m) => `usr_mspstage_${m.key}`,
  subscription: (m) => `sub_staging_test_msp_${m.key}`,
  workspace: (c) => `ws_mspstage_${c.key}`,
  domain: (c) => `dom_mspstage_${c.key}`,
  scan: (c, i) => `scan_mspstage_${c.key}_${i + 1}`,
  email: (m) => `msp-${m.key}@staging-test.example`,
};

// ── Local, network-free runtime ────────────────────────────────────────────
const DNS_TYPES = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 257: "CAA" };
const DNS_NUM = Object.fromEntries(Object.entries(DNS_TYPES).map(([n, t]) => [t, Number(n)]));
let dnsZone = null; // { domain, records }
const externalAttempts = [];

function dnsAnswer(url) {
  const name = (url.searchParams.get("name") || "").replace(/\.$/, "").toLowerCase();
  let type = url.searchParams.get("type") || "A";
  if (/^\d+$/.test(type)) type = DNS_TYPES[type] || type;
  type = type.toUpperCase();
  const zone = dnsZone;
  const inZone = zone && (name === zone.domain || name.endsWith(`.${zone.domain}`));
  const data = (inZone && zone.records[name]?.[type]) || [];
  const soa = inZone ? [{ name: zone.domain, type: 6, TTL: 300, data: `ns1.mail.example. hostmaster.${zone.domain}. 1 7200 3600 1209600 300` }] : [];
  return {
    Status: inZone ? 0 : 3, TC: false, RD: true, RA: true, AD: false, CD: false,
    Question: [{ name, type: DNS_NUM[type] || 1 }],
    Answer: data.map((value) => ({ name, type: DNS_NUM[type] || 1, TTL: 300, data: value })),
    ...(data.length ? {} : { Authority: soa }),
  };
}

globalThis.fetch = async (input) => {
  const url = new URL(String(input?.url || input));
  if (url.pathname.includes("dns-query") || url.pathname === "/resolve") {
    return new Response(JSON.stringify(dnsAnswer(url)), { status: 200, headers: { "content-type": "application/dns-json" } });
  }
  const zone = dnsZone;
  if (zone && (url.host === zone.domain || url.host === `www.${zone.domain}`) && (!url.pathname || url.pathname === "/")) {
    if (url.protocol === "http:") return new Response(null, { status: 301, headers: { location: `https://${url.host}/` } });
    return new Response("<!doctype html><html><head><title>Synthetic client site</title></head><body>Synthetic staging fixture</body></html>",
      { status: 200, headers: { "content-type": "text/html; charset=utf-8", ...zone.headers } });
  }
  externalAttempts.push(url.host);
  throw new Error("network disabled in the synthetic fixture");
};
if (typeof AbortSignal.timeout !== "function") AbortSignal.timeout = () => undefined;

function zoneFor(client, scan) {
  const d = client.domain;
  const records = {
    [d]: { MX: ["10 mx1.mail.example."], A: [SITE_ADDRESS], ...(scan.spf ? { TXT: [scan.spf] } : {}) },
    [`_dmarc.${d}`]: scan.dmarc ? { TXT: [scan.dmarc] } : {},
    [`www.${d}`]: { A: [SITE_ADDRESS] },
  };
  return { domain: d, records, headers: scan.headers || BASE_HEADERS };
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup tolerated, as in the validators */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

function makeR2(store) {
  const object = (key, body) => ({ key, body, json: async () => JSON.parse(body), text: async () => body, arrayBuffer: async () => new TextEncoder().encode(body).buffer, size: body.length });
  return {
    get: async (key) => (store.has(key) ? object(key, store.get(key)) : null),
    head: async (key) => (store.has(key) ? { key, size: store.get(key).length } : null),
    put: async (key, body) => { store.set(key, typeof body === "string" ? body : new TextDecoder().decode(body)); return { key }; },
    delete: async (key) => { store.delete(key); },
    list: async ({ prefix = "" } = {}) => ({ objects: [...store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })), truncated: false }),
  };
}

// Runs fn with Date fixed to start at `atMs` (time still advances).
async function atTime(atMs, fn) {
  const RealDate = Date;
  const offset = atMs - RealDate.now();
  class FixtureDate extends RealDate {
    constructor(...args) { super(...(args.length ? args : [RealDate.now() + offset])); }
    static now() { return RealDate.now() + offset; }
  }
  globalThis.Date = FixtureDate;
  try { return await fn(); } finally { globalThis.Date = RealDate; }
}

const tables = (db) => db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'").all().map((t) => t.name);
const maxRowids = (db) => Object.fromEntries(tables(db).map((t) => {
  try { return [t, Number(db.prepare(`SELECT COALESCE(MAX(rowid), 0) m FROM "${t}"`).get().m)]; } catch { return [t, null]; }
}));

// SQLite datetime('now') cannot follow the mocked clock: shift timestamps the
// run wrote with the real clock onto the scan's synthetic time, keeping format.
const STAMP = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(\.\d+)?(Z)?$/;
function retime(db, since, realStart, realEnd, targetMs) {
  for (const t of tables(db)) {
    if (since[t] == null) continue;
    const rows = db.prepare(`SELECT rowid AS __rid, * FROM "${t}" WHERE rowid > ?`).all(since[t]);
    for (const row of rows) {
      for (const [col, value] of Object.entries(row)) {
        if (col === "__rid" || typeof value !== "string") continue;
        const m = STAMP.exec(value);
        if (!m) continue;
        const ms = Date.parse(`${m[1]}T${m[2]}${m[3] || ""}Z`);
        if (!(ms >= realStart - 2000 && ms <= realEnd + 2000)) continue;
        const shifted = new Date(targetMs + (ms - realStart)).toISOString();
        const next = m[4] ? shifted : value.includes("T") ? shifted.replace("Z", "") : shifted.slice(0, 19).replace("T", " ");
        db.prepare(`UPDATE "${t}" SET "${col}" = ? WHERE rowid = ?`).run(m[3] || m[4] ? next : next.replace(/\.\d+/, ""), row.__rid);
      }
    }
  }
}

function sqlLiteral(value) {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  if (value instanceof Uint8Array) return `X'${Buffer.from(value).toString("hex")}'`;
  return `'${String(value).replaceAll("'", "''")}'`;
}

// Parents before children, from the schema's own foreign keys.
function insertOrder(db, names) {
  const deps = new Map(names.map((t) => [t, new Set(db.prepare(`SELECT "table" AS parent FROM pragma_foreign_key_list(?)`).all(t).map((r) => r.parent).filter((p) => p !== t && names.includes(p)))]));
  const order = [];
  const seen = new Set();
  const visit = (t, stack = new Set()) => {
    if (seen.has(t) || stack.has(t)) return;
    stack.add(t);
    for (const p of deps.get(t) || []) visit(p, stack);
    seen.add(t); order.push(t);
  };
  for (const t of names) visit(t);
  return order;
}

export async function buildMspStagingFixture({ now = Date.now() } = {}) {
  const db = buildDb();
  const store = new Map();
  const env = {
    cybermeters_db: makeD1(db), cybermeters_reports: makeR2(store),
    APP_VERSION: "msp-staging-fixture", RESEND_API_KEY: "", MAINTENANCE_MODE: "off",
    ALLOWED_ORIGIN: STAGING_APP, FRONTEND_URL: STAGING_APP,
    EXPOSURE_SCAN_MODE: "disabled", TLS_ASSESSMENT_MODE: "disabled",
  };
  const worker = await import(src("index.js"));
  const { runScanEngine } = await import(src("engines", "scan-engine.js"));
  const baseline = maxRowids(db);
  const logins = {};
  const seedAt = new Date(now - (SCAN_AGES_DAYS[0] + 1) * DAY).toISOString();

  for (const msp of MSP_STAGING_PORTFOLIO) {
    const password = crypto.randomBytes(18).toString("base64url");
    logins[msp.key] = { email: ids.email(msp), password, name: msp.name };
    const hash = await worker.hashPassword(password);
    db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified, mfa_enabled, created_at) VALUES (?, ?, ?, ?, 'free', 'active', 1, 0, ?)")
      .run(ids.user(msp), ids.email(msp), hash, msp.name, seedAt);
    // Staging-only test entitlement (Executive approval, 21 Oct 2026): MSP plan,
    // active, no Stripe identifiers.
    db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, status, subscription_status, billing_interval,
                  current_period_start, current_period_end, stripe_customer_id, stripe_subscription_id, stripe_price_id, created_at, updated_at)
                VALUES (?, ?, 'enterprise', 'active', 'active', 'monthly', ?, ?, NULL, NULL, NULL, ?, ?)`)
      .run(ids.subscription(msp), ids.user(msp), seedAt, new Date(now + 365 * DAY).toISOString(), seedAt, seedAt);
    for (const client of msp.clients) {
      db.prepare("INSERT INTO workspaces (id, owner_user_id, name, created_at) VALUES (?, ?, ?, ?)").run(ids.workspace(client), ids.user(msp), client.name, seedAt);
      try { db.prepare("INSERT INTO workspace_members (workspace_id, user_id, role, created_at) VALUES (?, ?, 'owner', ?)").run(ids.workspace(client), ids.user(msp), seedAt); } catch { /* owner is implicit where the table differs */ }
      db.prepare("INSERT INTO domains (id, user_id, domain, verification_status, verified_at, created_at) VALUES (?, ?, ?, 'verified', ?, ?)").run(ids.domain(client), ids.user(msp), client.domain, seedAt, seedAt);
      db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run(ids.workspace(client), ids.domain(client));
    }
  }

  for (const [i, age] of SCAN_AGES_DAYS.entries()) {
    for (const msp of MSP_STAGING_PORTFOLIO) {
      for (const client of msp.clients) {
        const scanId = ids.scan(client, i);
        const targetMs = now - age * DAY - (msp.key === "a" ? 2 : 1) * 3_600_000;
        const before = maxRowids(db);
        db.prepare("INSERT INTO scans (id, workspace_id, domain_id, domain, status, created_at) VALUES (?, ?, ?, ?, 'running', datetime('now'))")
          .run(scanId, ids.workspace(client), ids.domain(client), client.domain);
        dnsZone = zoneFor(client, client.scans[i]);
        const realStart = Date.now();
        await atTime(targetMs, () => runScanEngine(scanId, ids.domain(client), ids.workspace(client), client.domain, env, {}));
        retime(db, before, realStart, Date.now(), targetMs);
        dnsZone = null;
      }
    }
  }
  return { db, store, env, worker: worker.default, baseline, logins };
}

export function exportFixture({ db, store, baseline }) {
  const changed = tables(db).filter((t) => baseline[t] != null && Number(db.prepare(`SELECT COALESCE(MAX(rowid), 0) m FROM "${t}"`).get().m) > baseline[t]);
  const lines = [
    "-- Synthetic MSP portfolio fixture for cybermeters-db-staging ONLY (generated by",
    "-- scripts/generate-msp-staging-fixture.mjs). Never apply to production.",
    "-- Rows written by the real scan engine with stubbed DNS and no network.",
  ];
  for (const t of insertOrder(db, changed)) {
    const rows = db.prepare(`SELECT * FROM "${t}" WHERE rowid > ? ORDER BY rowid`).all(baseline[t]);
    for (const row of rows) {
      const cols = Object.keys(row);
      lines.push(`INSERT INTO "${t}" (${cols.map((c) => `"${c}"`).join(", ")}) VALUES (${cols.map((c) => sqlLiteral(row[c])).join(", ")});`);
    }
  }
  const objects = [...store.entries()].map(([key, body]) => ({ key, sha256: crypto.createHash("sha256").update(body).digest("hex"), bytes: Buffer.byteLength(body) }));
  return { sql: `${lines.join("\n")}\n`, objects, tables: changed };
}

// ── --verify: the real API handler against the generated data ─────────────
async function verify({ worker, env, logins }) {
  const results = [];
  const ok = (name, pass, detail = "") => { results.push({ name, pass: Boolean(pass) }); console.log(`${pass ? "PASS" : "FAIL"} ${name}${pass || !detail ? "" : ` — ${detail}`}`); };
  const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
  const call = async (method, pathname, { token, body } = {}) => {
    const headers = { Origin: STAGING_APP, "content-type": "application/json" };
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await worker.fetch(new Request(`${STAGING_API}${pathname}`, { method, headers, body: body ? JSON.stringify(body) : undefined }), env, ctx);
    const type = res.headers.get("content-type") || "";
    let data = null;
    if (type.includes("json")) { try { data = await res.json(); } catch { /* malformed */ } }
    else { data = new Uint8Array(await res.arrayBuffer()); }
    return { status: res.status, type, data };
  };
  const tokens = {};
  for (const [key, login] of Object.entries(logins)) {
    const r = await call("POST", "/api/auth/login", { body: { email: login.email, password: login.password } });
    tokens[key] = r.data?.token || r.data?.session_token || null;
    ok(`MSP ${key.toUpperCase()} signs in`, r.status === 200 && tokens[key], `status ${r.status}`);
  }
  const portfolio = {};
  for (const msp of MSP_STAGING_PORTFOLIO) {
    const r = await call("GET", "/api/portfolio/domains", { token: tokens[msp.key] });
    const rows = r.data?.rows || r.data?.domains || r.data?.workspaces || [];
    portfolio[msp.key] = rows;
    ok(`MSP ${msp.key.toUpperCase()} portfolio lists exactly its ${msp.clients.length} clients`, r.status === 200 && rows.length === msp.clients.length, `status ${r.status}, ${rows.length} rows`);
    ok(`MSP ${msp.key.toUpperCase()} rows carry all eight domain states`, rows.length > 0 && rows.every((row) => (row.security_domains || row.cyber_mot_domains || []).length === 8));
    const trends = await call("GET", "/api/portfolio/trends", { token: tokens[msp.key] });
    const scanned = (trends.data?.trend || []).reduce((n, day) => n + (day.scans || 0), 0);
    ok(`MSP ${msp.key.toUpperCase()} trend counts its ${msp.clients.length * SCAN_AGES_DAYS.length} complete scans`, trends.status === 200 && scanned === msp.clients.length * SCAN_AGES_DAYS.length, `status ${trends.status}, ${scanned} scans`);
    for (const row of rows) {
      const states = row.security_domains || row.cyber_mot_domains || [];
      ok(`MSP ${msp.key.toUpperCase()} ${row.workspace_name || row.domain}: every domain has comparable history`, states.length === 8 && states.every((d) => d.trend !== "insufficient_history"),
        states.filter((d) => d.trend === "insufficient_history").map((d) => d.domain_key).join(", "));
    }
  }
  const otherWs = ids.workspace(MSP_STAGING_PORTFOLIO[1].clients[0]);
  const crossReport = await call("GET", `/api/workspaces/${otherWs}/report`, { token: tokens.a });
  ok("MSP A cannot read MSP B's client report", [403, 404].includes(crossReport.status), `status ${crossReport.status}`);
  const crossScan = await call("GET", `/api/scans/${ids.scan(MSP_STAGING_PORTFOLIO[1].clients[0], 2)}/snapshot`, { token: tokens.a });
  ok("MSP A cannot read MSP B's scan snapshot", [403, 404].includes(crossScan.status), `status ${crossScan.status}`);
  const aIds = JSON.stringify(portfolio.a);
  ok("MSP A's portfolio names no MSP B client", MSP_STAGING_PORTFOLIO[1].clients.every((c) => !aIds.includes(ids.workspace(c)) && !aIds.includes(c.domain)));
  const northwind = portfolio.a.find((row) => JSON.stringify(row).includes("northwind-dental.example"));
  const nwEmail = (northwind?.security_domains || northwind?.cyber_mot_domains || []).find((d) => d.domain_key === "email_protection");
  ok("Northwind's Email Protection trend records the DMARC change (none → quarantine → reject)", nwEmail && nwEmail.trend !== "insufficient_history" && nwEmail.previous_state != null,
    JSON.stringify({ trend: nwEmail?.trend, previous: nwEmail?.previous_state, state: nwEmail?.state }));
  const isPdf = (r) => r.status === 200 && r.type.includes("application/pdf") && Buffer.from(r.data.slice(0, 5)).toString() === "%PDF-";
  for (const msp of MSP_STAGING_PORTFOLIO) {
    const client = msp.clients[0];
    ok(`MSP ${msp.key.toUpperCase()} generates its client's executive PDF`, isPdf(await call("GET", `/api/workspaces/${ids.workspace(client)}/report`, { token: tokens[msp.key] })));
    ok(`MSP ${msp.key.toUpperCase()} generates its client's latest scan PDF`, isPdf(await call("GET", `/api/scans/${ids.scan(client, 2)}/report/pdf`, { token: tokens[msp.key] })));
  }
  const crossBA = await call("GET", `/api/workspaces/${ids.workspace(MSP_STAGING_PORTFOLIO[0].clients[0])}/report`, { token: tokens.b });
  ok("MSP B cannot read MSP A's client report", [403, 404].includes(crossBA.status), `status ${crossBA.status}`);
  const crossBAscan = await call("GET", `/api/scans/${ids.scan(MSP_STAGING_PORTFOLIO[0].clients[0], 2)}/report/pdf`, { token: tokens.b });
  ok("MSP B cannot read MSP A's scan PDF", [403, 404].includes(crossBAscan.status), `status ${crossBAscan.status}`);
  const ownSnap = await call("GET", `/api/scans/${ids.scan(MSP_STAGING_PORTFOLIO[0].clients[0], 2)}/snapshot`, { token: tokens.a });
  ok("MSP A reads its own client's latest report snapshot", ownSnap.status === 200, `status ${ownSnap.status}`);
  // Every non-DNS request the engine tried (RDAP, MTA-STS policy hosts, …) was
  // refused by the stub above; nothing was sent anywhere.
  ok("every request outside the synthetic sites was refused (no network used)", externalAttempts.length > 0 && externalAttempts.every((h) => typeof h === "string"));
  return results;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const fixture = await buildMspStagingFixture();
  const out = exportFixture(fixture);
  fs.mkdirSync(path.join(outDir, "r2"), { recursive: true, mode: 0o700 });
  fs.writeFileSync(path.join(outDir, "fixture.sql"), out.sql, { mode: 0o600 });
  for (const object of out.objects) {
    const file = path.join(outDir, "r2", object.key);
    fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, fixture.store.get(object.key), { mode: 0o600 });
  }
  fs.writeFileSync(path.join(outDir, "r2-manifest.json"), `${JSON.stringify(out.objects, null, 2)}\n`, { mode: 0o600 });
  fs.writeFileSync(path.join(outDir, "logins.json"), `${JSON.stringify(fixture.logins, null, 2)}\n`, { mode: 0o600 });
  console.log(`fixture: ${out.sql.split("\n").filter((l) => l.startsWith("INSERT")).length} rows in ${out.tables.length} tables, ${out.objects.length} report objects → ${path.relative(root, outDir)}/`);
  if (process.argv.includes("--verify")) {
    const results = await verify(fixture);
    const failed = results.filter((r) => !r.pass).length;
    console.log(`MSP staging fixture verify: ${results.length - failed} passed, ${failed} failed`);
    process.exitCode = failed ? 1 : 0;
  }
}
