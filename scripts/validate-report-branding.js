#!/usr/bin/env node
//
// White-label report branding regression (Faz 1 MSP wedge: "send the report with
// my own logo"). Proves: (1) validation of the branding payload; (2) the PDF text
// wordmark + footer switch to the account brand when white-label is on and stay
// CyberMeters otherwise; (3) resolveReportBranding only returns a brand for the
// owning account's own workspaces (isolation) and only when white-label is on;
// (4) the account endpoints gate white-label ON behind the Business entitlement,
// require a company profile, and reject api-token sessions. Node 24+. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const brandEng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "report-branding.js")).href);
const pdfEng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "pdf.js")).href);
const pdfImgEng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "pdf-image.js")).href);
const { hashToken } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "auth-crypto.js")).href);
const { validateBrandingInput, resolveReportBranding } = brandEng;
const { buildScanReportPdf } = pdfEng;
const { composeSnapshot } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "report-snapshot.js")).href);
// M5.d: the scan PDF renders a canonical snapshot read; branding stays a live
// presentation input (the policy under test here).
const mkRead = (rawReport, scanId = "sc") => ({
  status: "ok",
  snapshot: composeSnapshot({
    snapshotId: "snap_" + scanId, workspaceId: "ws_b", domainId: "dom_b", scanId,
    domain: "acme.co.uk",
    report: { status: "completed", completed_at: "2026-07-12T00:00:00Z", ...rawReport },
    cyberEssentials: null, ceReadiness: null, caseRows: [], questionSetVersions: [],
    supersedesSnapshotId: null, builtAt: "2026-07-12T00:00:05Z",
  }),
  row: { id: "snap_" + scanId }, integrity: { verified: true },
});
const { prepareLogoXObject } = pdfImgEng;

// ── Tiny PNG builder (valid IHDR/IDAT/IEND, RGBA, 8-bit) for the decode path ──
const CRC_TABLE = (() => { const t = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; } return t; })();
const crc32 = (b) => { let c = 0xFFFFFFFF; for (let i = 0; i < b.length; i++) c = CRC_TABLE[(c ^ b[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; };
const beU32 = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const zdeflate = async (u8) => new Uint8Array(await new Response(new Response(u8).body.pipeThrough(new CompressionStream("deflate"))).arrayBuffer());
const zinflate = async (u8) => new Uint8Array(await new Response(new Response(u8).body.pipeThrough(new DecompressionStream("deflate"))).arrayBuffer());
async function makePngRgba(w, h, rgba) {
  const enc = new TextEncoder();
  const chunk = (type, data) => { const tb = enc.encode(type); const body = new Uint8Array(tb.length + data.length); body.set(tb, 0); body.set(data, tb.length); return [...beU32(data.length), ...body, ...beU32(crc32(body))]; };
  const ihdr = new Uint8Array([...beU32(w), ...beU32(h), 8, 6, 0, 0, 0]);
  const stride = w * 4;
  const raw = new Uint8Array((stride + 1) * h);
  for (let y = 0; y < h; y++) { raw[y * (stride + 1)] = 0; raw.set(rgba.subarray(y * stride, (y + 1) * stride), y * (stride + 1) + 1); }
  const idat = await zdeflate(raw);
  const sig = [137, 80, 78, 71, 13, 10, 26, 10];
  return new Uint8Array([...sig, ...chunk("IHDR", ihdr), ...chunk("IDAT", idat), ...chunk("IEND", new Uint8Array(0))]);
}
const b64 = (u8) => Buffer.from(u8).toString("base64");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
db.exec("PRAGMA foreign_keys = OFF");
const makeD1 = (db) => { const wrap = (sql, a) => ({ first: async () => db.prepare(sql).get(...a) ?? null, all: async () => ({ results: db.prepare(sql).all(...a) }), run: async () => { const r = db.prepare(sql).run(...a); return { meta: { changes: r.changes } }; } }); return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } }; };

const PNG = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==";

// ── 1. Unit: validateBrandingInput ───────────────────────────────────────────
ok("rejects bad accent hex", !validateBrandingInput({ brand_accent: "red" }).ok);
ok("accepts good accent hex", validateBrandingInput({ brand_accent: "#123ABC" }).ok);
ok("rejects non-data-URI logo", !validateBrandingInput({ brand_logo: "https://evil/x.png" }).ok);
ok("accepts data-URI logo", validateBrandingInput({ brand_logo: PNG }).ok);
ok("rejects oversized logo", !validateBrandingInput({ brand_logo: "data:image/png;base64," + "A".repeat(200 * 1024) }).ok);
ok("white_label truthy coerces to 1", validateBrandingInput({ report_white_label: true }).value.report_white_label === 1);
ok("white_label falsy coerces to 0", validateBrandingInput({ report_white_label: 0 }).value.report_white_label === 0);
ok("empty logo clears to null", validateBrandingInput({ brand_logo: "" }).value.brand_logo === null);

// ── 2. Unit: PDF wordmark + footer switch ────────────────────────────────────
const scan = { id: "sc", domain: "acme.co.uk", status: "completed", score: 72, rating: "Good", created_at: "2026-07-12T00:00:00Z" };
const report = { cyber_metrics_score: 72, risk_level: "Good", findings: [] };
const plain = Buffer.from(buildScanReportPdf(scan, mkRead(report), null, null)).toString("latin1");
ok("plain PDF carries CyberMeters wordmark", plain.includes("CyberMeters"));
ok("plain PDF footer is the default generated-by line", plain.includes("Generated by CyberMeters | app.cybermeters.com"));

const branded = Buffer.from(buildScanReportPdf(scan, mkRead(report), { company_name: "Contoso MSP", accent: "#7C3AED", logo: PNG }, null)).toString("latin1");
ok("branded PDF header carries the MSP name", branded.includes("Contoso MSP"));
ok("branded PDF footer is Prepared-by + Powered-by", branded.includes("Prepared by Contoso MSP | Powered by CyberMeters"));
ok("branded PDF drops the default generated-by footer", !branded.includes("Generated by CyberMeters | app.cybermeters.com"));

// ── 2b. Logo image: PNG decode + JPEG passthrough + PDF embedding ────────────
// 2x2 RGBA: (0,0) red opaque, (1,0) fully transparent, (0,1) green, (1,1) blue.
const rgba = new Uint8Array([255, 0, 0, 255,  0, 0, 0, 0,   0, 255, 0, 255,  0, 0, 255, 255]);
const pngUri = "data:image/png;base64," + b64(await makePngRgba(2, 2, rgba));
const xo = await prepareLogoXObject(pngUri, "#00876A");
ok("PNG prepared as 8-bit FlateDecode RGB XObject", !!xo && xo.filter === "FlateDecode" && xo.colorSpace === "DeviceRGB" && xo.width === 2 && xo.height === 2 && xo.bitsPerComponent === 8);
const decoded = await zinflate(xo.bytes);
ok("opaque PNG pixel preserved (red)", decoded[0] === 255 && decoded[1] === 0 && decoded[2] === 0);
ok("transparent PNG pixel flattened over accent bg (#00876A)", decoded[3] === 0 && decoded[4] === 135 && decoded[5] === 106);

// Minimal JPEG: SOF0, 42×100, 3 components — embedded verbatim via DCTDecode.
const jpeg = new Uint8Array([0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x00, 0x2A, 0x00, 0x64, 0x03, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1, 0xFF, 0xD9]);
const jxo = await prepareLogoXObject("data:image/jpeg;base64," + b64(jpeg));
ok("JPEG embedded verbatim as DCTDecode RGB", !!jxo && jxo.filter === "DCTDecode" && jxo.colorSpace === "DeviceRGB" && jxo.width === 100 && jxo.height === 42 && jxo.bytes.length === jpeg.length);
ok("SVG logo → null (falls back to text wordmark)", (await prepareLogoXObject("data:image/svg+xml;base64," + b64(new TextEncoder().encode("<svg/>")))) === null);
ok("garbage data URI → null", (await prepareLogoXObject("not-a-data-uri")) === null);

// Embed the prepared logo into a scan report PDF.
const logoPdf = buildScanReportPdf(scan, mkRead(report), { company_name: "Contoso MSP", accent: "#7C3AED", logo: pngUri }, xo);
ok("logo PDF is a binary Uint8Array", logoPdf instanceof Uint8Array);
const lp = Buffer.from(logoPdf).toString("latin1");
ok("logo PDF is well-formed (%PDF … %%EOF)", lp.startsWith("%PDF-1.4") && lp.trimEnd().endsWith("%%EOF"));
ok("logo PDF carries an Image XObject drawn in the header", lp.includes("/Subtype /Image") && lp.includes("/Im0 Do"));
ok("logo PDF image dict Length matches the embedded bytes", lp.includes(`/Length ${xo.bytes.length} >>`));
ok("logo replaces the text wordmark (no standalone name Tj)", !lp.includes("(Contoso MSP) Tj"));
ok("logo PDF still carries the Prepared-by footer", lp.includes("Prepared by Contoso MSP | Powered by CyberMeters"));

// ── Seed accounts ────────────────────────────────────────────────────────────
// u_a: Business plan (white_label entitled) + company profile + ws_a.
// u_free: Free plan, no company profile, owns ws_free.
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_a','a@example.co.uk',1)").run();
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_free','f@example.co.uk',1)").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_a','Acme','u_a')").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_free','Freebie','u_free')").run();
db.prepare("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ('ws_a','u_a','owner')").run();
db.prepare("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ('ws_free','u_free','owner')").run();
db.prepare("INSERT INTO customer_profiles (id, owner_user_id, company_name, created_at, updated_at) VALUES ('cp_a','u_a','Contoso MSP', datetime('now'), datetime('now'))").run();
db.prepare("INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, current_period_end) VALUES ('sub_a','u_a','business','active', datetime('now','+30 day'))").run();

const TOKA = "tok_a", TOKF = "tok_f";
db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_a','u_a',?, datetime('now','+1 day'))").run(await hashToken(TOKA));
db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_f','u_free',?, datetime('now','+1 day'))").run(await hashToken(TOKF));

const env = { cybermeters_db: makeD1(db), ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test" };
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const call = async (method, p, token, body) => {
  const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${p}`, {
    method,
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body ? { "Content-Type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  }), env, ctx);
  let out = {}; try { out = await res.json(); } catch { /* */ }
  return { status: res.status, body: out };
};

// ── 3. GET report-branding: plan availability ────────────────────────────────
const gA = await call("GET", "/api/account/report-branding", TOKA);
ok("business account: GET 200", gA.status === 200);
ok("business account: white-label available", gA.body.white_label_available === true);
ok("business account: has company profile", gA.body.has_company_profile === true);
const gF = await call("GET", "/api/account/report-branding", TOKF);
ok("free account: white-label NOT available", gF.body.white_label_available === false);
ok("unauthenticated GET rejected (401)", (await call("GET", "/api/account/report-branding")).status === 401);

// ── 4. PUT gating + validation ───────────────────────────────────────────────
ok("free account cannot switch white-label ON (403 plan_feature_required)",
   (await call("PUT", "/api/account/report-branding", TOKF, { report_white_label: true })).status === 403);
const noProfile = await call("PUT", "/api/account/report-branding", TOKF, { brand_accent: "#111111" });
ok("account without company profile is told to set it first (409)", noProfile.status === 409 && noProfile.body.need_company_profile === true);
ok("bad accent rejected (400)", (await call("PUT", "/api/account/report-branding", TOKA, { brand_accent: "nope" })).status === 400);

// ── 5. PUT success + persistence ─────────────────────────────────────────────
const put = await call("PUT", "/api/account/report-branding", TOKA, { brand_logo: PNG, brand_accent: "#7C3AED", report_white_label: true });
ok("business account sets branding (200)", put.status === 200);
ok("branding persisted: white-label on", put.body.branding?.report_white_label === true);
ok("branding persisted: logo stored", put.body.branding?.brand_logo === PNG);
ok("branding persisted: accent stored", put.body.branding?.brand_accent === "#7C3AED");
const gA2 = await call("GET", "/api/account/report-branding", TOKA);
ok("re-read shows white-label on", gA2.body.branding?.report_white_label === true);

// ── 6. resolveReportBranding: isolation + on/off ─────────────────────────────
const brA = await resolveReportBranding(env, "ws_a");
ok("resolve returns the MSP brand for its own workspace", brA?.company_name === "Contoso MSP" && brA?.accent === "#7C3AED");
const brFree = await resolveReportBranding(env, "ws_free");
ok("resolve returns null for another account's workspace (isolation)", brFree === null);
ok("resolve returns null for unknown workspace", (await resolveReportBranding(env, "ws_missing")) === null);
// Turn white-label OFF → resolve must fall back to null (CyberMeters brand).
await call("PUT", "/api/account/report-branding", TOKA, { report_white_label: false });
ok("white-label OFF → resolve falls back to null", (await resolveReportBranding(env, "ws_a")) === null);

// ── 7. Migration 126 on the live pre-016 table ───────────────────────────────
// Production's customer_profiles predates 016 (user_id NOT NULL UNIQUE, a
// partial unique index on owner_user_id from 046). Captured read-only from
// production on 19 Oct 2026. On that shape the profile upsert cannot run, so
// branding can never be saved; 126 must make both work and end in the same
// table the repository builds.
const LIVE_PRE016_CUSTOMER_PROFILES = [
  `CREATE TABLE customer_profiles (
    id           TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL UNIQUE,
    company_name TEXT,
    website      TEXT,
    industry     TEXT,
    company_size TEXT,
    country      TEXT,
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at   TEXT DEFAULT CURRENT_TIMESTAMP, contact_email TEXT, contact_name  TEXT, owner_user_id TEXT, brand_logo TEXT, brand_accent TEXT, report_white_label INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
)`,
  `CREATE UNIQUE INDEX idx_customer_profiles_owner
  ON customer_profiles (owner_user_id)
  WHERE owner_user_id IS NOT NULL`,
  `CREATE INDEX idx_customer_profiles_user_id
  ON customer_profiles (user_id)`,
];
const M126 = "126-customer-profiles-rebuild.sql";
{
  const live = new DatabaseSync(":memory:");
  const tolerant = (sql) => { try { live.exec(sql); } catch { /* ordering no-ops */ } };
  tolerant(fs.readFileSync(path.join(root, "database", "schema.sql"), "utf8"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql") && f < M126).sort()) {
    tolerant(fs.readFileSync(path.join(root, "database", "migrations", f), "utf8"));
  }
  live.exec("DROP TABLE customer_profiles");
  for (const sql of LIVE_PRE016_CUSTOMER_PROFILES) live.exec(sql);
  live.exec("PRAGMA foreign_keys = ON");
  live.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_l','l@example.co.uk',1)").run();
  live.prepare("INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, subscription_status, current_period_end) VALUES ('sub_l','u_l','ws_l','business','active', datetime('now','+30 day'))").run();
  live.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_l','u_l',?, datetime('now','+1 day'))").run(await hashToken("tok_l"));
  const liveEnv = { cybermeters_db: makeD1(live), ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test" };
  const liveCall = async (method, p, body) => {
    const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${p}`, {
      method, headers: { Authorization: "Bearer tok_l", "Content-Type": "application/json" }, body: JSON.stringify(body),
    }), liveEnv, ctx);
    let out = {}; try { out = await res.json(); } catch { /* */ }
    return { status: res.status, body: out };
  };
  const company = { company_name: "Example MSP Ltd", company_size: "11-50", contact_email: "ops@example.co.uk" };

  ok("pre-126 live shape: the company profile upsert fails (the production defect is reproduced)",
     (await liveCall("PUT", "/api/account/company", company)).status === 500);

  const m126Path = path.join(root, "database", "migrations", M126);
  let applied = false;
  try { live.exec(fs.existsSync(m126Path) ? fs.readFileSync(m126Path, "utf8") : ""); applied = fs.existsSync(m126Path); } catch { applied = false; }
  ok("126 applies cleanly to the live pre-016 shape with foreign keys on", applied);

  const saved = await liveCall("PUT", "/api/account/company", company);
  ok("after 126: PUT /api/account/company succeeds (200)", saved.status === 200 && saved.body.company?.company_name === "Example MSP Ltd");
  const resaved = await liveCall("PUT", "/api/account/company", { ...company, company_name: "Example Managed IT Ltd" });
  ok("after 126: a second save updates the same profile (upsert, one row)",
     resaved.status === 200 && resaved.body.company?.company_name === "Example Managed IT Ltd" &&
     live.prepare("SELECT COUNT(*) c FROM customer_profiles WHERE owner_user_id='u_l'").get().c === 1);
  const brand = await liveCall("PUT", "/api/account/report-branding", { brand_accent: "#7C3AED", report_white_label: true });
  ok("after 126: the branding save succeeds (200, white-label on)",
     brand.status === 200 && brand.body.branding?.report_white_label === true && brand.body.branding?.brand_accent === "#7C3AED");

  const shape = (d) => JSON.stringify({
    cols: d.prepare("SELECT name, type, \"notnull\", dflt_value, pk FROM pragma_table_info('customer_profiles')").all(),
    idx: d.prepare("SELECT name, \"unique\", partial FROM pragma_index_list('customer_profiles') ORDER BY name").all()
      .map((i) => ({ ...i, cols: d.prepare(`SELECT name FROM pragma_index_info('${i.name}')`).all() })),
    fks: d.prepare("SELECT \"table\", \"from\", \"to\" FROM pragma_foreign_key_list('customer_profiles')").all(),
  });
  ok("after 126: the live and repository tables end in the same shape", shape(live) === shape(db));
  ok("after 126: the profile no longer carries user_id and keeps country",
     !/"name":"user_id"/.test(shape(live)) && /"name":"country"/.test(shape(live)));
  ok("after 126: the pre-016 table is kept, not dropped",
     live.prepare("SELECT COUNT(*) c FROM sqlite_master WHERE type='table' AND name='customer_profiles_legacy_pre016'").get().c === 1 &&
     db.prepare("SELECT COUNT(*) c FROM sqlite_master WHERE type='table' AND name='customer_profiles_legacy_pre016'").get().c === 1);
  ok("after 126: no view, trigger, index or foreign key was repointed to the legacy table",
     [live, db].every((d) =>
       d.prepare("SELECT COUNT(*) c FROM sqlite_master WHERE tbl_name <> 'customer_profiles_legacy_pre016' AND sql LIKE '%customer_profiles_legacy_pre016%'").get().c === 0));
  ok("after 126: account purge removes the legacy copy too",
     Array.isArray(worker.ACCOUNT_PURGE_TABLES) &&
     worker.ACCOUNT_PURGE_TABLES.some((t) => t.table === "customer_profiles_legacy_pre016"));

  // ── 8. Company form round trip (P1, 19 Oct 2026: saved fields came back empty) ──
  // Every field the form sends, country and the security contact included,
  // must come back from both reads the account page uses.
  const full = {
    company_name: "Example Managed IT Ltd", website: "https://example.co.uk", industry: "Legal",
    company_size: "11-50", country: "United Kingdom", contact_name: "Sam Security", contact_email: "Security@Example.co.uk",
  };
  const put = await liveCall("PUT", "/api/account/company", full);
  const getCompany = await liveCall("GET", "/api/account/company");
  const getProfile = await liveCall("GET", "/api/account/profile");
  const expected = { ...full, contact_email: "security@example.co.uk" };
  const sameFields = (row) => !!row && Object.entries(expected).every(([k, v]) => row[k] === v);
  ok("company round trip: PUT returns every saved field, country included", put.status === 200 && sameFields(put.body.company));
  ok("company round trip: GET /api/account/company returns every saved field", getCompany.status === 200 && sameFields(getCompany.body.company));
  ok("company round trip: GET /api/account/profile returns the record as `company`, country included",
     getProfile.status === 200 && sameFields(getProfile.body.company) && !("profile" in getProfile.body));
  const noCountry = { ...full }; delete noCountry.country;
  const kept = await liveCall("PUT", "/api/account/company", noCountry);
  ok("company round trip: a save that does not send country keeps the saved country", kept.status === 200 && kept.body.company?.country === "United Kingdom");
  const cleared = await liveCall("PUT", "/api/account/company", { ...full, country: "  " });
  ok("company round trip: an empty country clears it", cleared.status === 200 && cleared.body.company?.country === null);
  ok("company round trip: a country over 100 characters is rejected", (await liveCall("PUT", "/api/account/company", { ...full, country: "x".repeat(101) })).status === 400);
  ok("company round trip: markup in country is rejected", (await liveCall("PUT", "/api/account/company", { ...full, country: "<b>UK</b>" })).status === 400);
  ok("company round trip: a non-text country is rejected", (await liveCall("PUT", "/api/account/company", { ...full, country: 44 })).status === 400);
  ok("company round trip: rejected saves leave the stored country unchanged",
     live.prepare("SELECT country FROM customer_profiles WHERE owner_user_id='u_l'").get().country === null);
  live.close();
}

console.log(`\nReport branding: ${pass}/${pass + fail} passed`);
if (fail) { console.error("report-branding validation FAILED"); process.exit(1); }
console.log("report-branding validation passed");
