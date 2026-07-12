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
const plain = Buffer.from(buildScanReportPdf(scan, report)).toString("latin1");
ok("plain PDF carries CyberMeters wordmark", plain.includes("CyberMeters"));
ok("plain PDF footer is the default generated-by line", plain.includes("Generated by CyberMeters | app.cybermeters.com"));

const branded = Buffer.from(buildScanReportPdf(scan, report, { company_name: "Contoso MSP", accent: "#7C3AED", logo: PNG })).toString("latin1");
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
const logoPdf = buildScanReportPdf(scan, report, { company_name: "Contoso MSP", accent: "#7C3AED", logo: pngUri, logoImage: xo });
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

console.log(`\nReport branding: ${pass}/${pass + fail} passed`);
if (fail) { console.error("report-branding validation FAILED"); process.exit(1); }
console.log("report-branding validation passed");
