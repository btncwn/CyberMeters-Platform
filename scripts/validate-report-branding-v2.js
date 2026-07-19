#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-report-branding-v2.js  (CI-blocking)
//
// Proves the Report Branding v2 engine's contract against a REAL in-memory D1:
//   • precedence: entitled MSP white-label → per-workspace co-brand → CyberMeters
//   • NEVER unbranded (resolveReportBrandingV2 never returns null)
//   • white-label requires the plan's white_label entitlement (server-side)
//   • tenant isolation: a workspace logo / MSP profile never applies to another tenant
//   • upload validation: PNG/JPEG only by MAGIC BYTES (declared MIME never trusted),
//     SVG/WebP/oversized/too-small rejected
//   • frozen-logo integrity: a sha256 mismatch refuses the logo (→ safe fallback)
//   • attribution: co-brand + fallback keep full CyberMeters wordmark; white-label reduced
// Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import { buildDb, makeD1 } from "./security/lib/worker-harness.js";
import {
  resolveReportBrandingV2, validateLogoUpload, sniffImageType, loadBrandingLogoDataUri,
  brandingAttribution, cyberMetersDescriptor, workspaceLogoKey,
} from "../workers/scan-api/src/engines/report-branding-v2.js";

let passed = 0, failed = 0;
const ok = (n, c) => { c ? passed++ : (failed++, console.error("  ✗ " + n)); };

// ── image fixtures (valid magic bytes + parseable dimensions) ────────────────
function png(w = 64, h = 64) {
  const a = new Uint8Array(64);
  a.set([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52]);
  a[16] = (w >> 24) & 255; a[17] = (w >> 16) & 255; a[18] = (w >> 8) & 255; a[19] = w & 255;
  a[20] = (h >> 24) & 255; a[21] = (h >> 16) & 255; a[22] = (h >> 8) & 255; a[23] = h & 255;
  return a;
}
function jpeg(w = 64, h = 64) {
  const a = new Uint8Array(32);
  a.set([0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, (h >> 8) & 255, h & 255, (w >> 8) & 255, w & 255]);
  return a;
}
const svg = new TextEncoder().encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>');
const webp = (() => { const a = new Uint8Array(16); a.set([0x52, 0x49, 0x46, 0x46, 0, 0, 0, 0, 0x57, 0x45, 0x42, 0x50]); return a; })();

async function main() {
  const db = buildDb();
  const d1 = makeD1(db);
  // R2 stub keyed by object key.
  const r2store = new Map();
  const env = {
    cybermeters_db: d1,
    cybermeters_reports: { get: async (k) => (r2store.has(k) ? { arrayBuffer: async () => r2store.get(k).buffer } : null) },
  };

  // ── Seed: two accounts, three workspaces ─────────────────────────────────
  const seedUser = (id, plan) => db.prepare("INSERT INTO users (id, email, password_hash, name, plan, status, email_verified) VALUES (?,?,?,?,?,'active',1)").run(id, id + "@x.co", "x", id, plan);
  seedUser("ownerBiz", "business");   // white_label entitled
  seedUser("ownerStarter", "starter"); // NOT entitled
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsBiz','ownerBiz','Biz WS')").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsStarter','ownerStarter','Starter WS')").run();
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES ('wsBizChild','ownerBiz','Child WS')").run();

  // ── Upload validation (magic-byte, not declared MIME) ────────────────────
  const vPng = await validateLogoUpload(png());
  const vJpg = await validateLogoUpload(jpeg());
  ok("PNG upload accepted", vPng.ok && vPng.value.mime === "image/png" && vPng.value.ext === "png");
  ok("JPEG upload accepted", vJpg.ok && vJpg.value.mime === "image/jpeg");
  ok("SVG upload rejected (no sanitisation path)", !(await validateLogoUpload(svg)).ok);
  ok("WebP upload rejected", !(await validateLogoUpload(webp)).ok);
  ok("oversized upload rejected", !(await validateLogoUpload(new Uint8Array(600 * 1024))).ok);
  ok("too-small dimensions rejected", !(await validateLogoUpload(png(8, 8))).ok);
  ok("magic bytes beat a lying MIME (raw text is not an image)", sniffImageType(new TextEncoder().encode("PNGly text")) === null);

  // ── No branding yet → CyberMeters fallback, never null ───────────────────
  const bare = await resolveReportBrandingV2(env, { workspaceId: "wsStarter" });
  ok("no branding → CyberMeters fallback (never null)", bare && bare.mode === "cybermeters");
  ok("unknown workspace → CyberMeters fallback (never null)", (await resolveReportBrandingV2(env, { workspaceId: "nope" })).mode === "cybermeters");

  // ── Per-workspace co-brand logo (any plan) ───────────────────────────────
  db.prepare("INSERT INTO workspace_branding (workspace_id, logo_r2_key, logo_mime, logo_sha256, display_name) VALUES ('wsStarter', ?, 'image/png', ?, 'Starter Co')").run(workspaceLogoKey("wsStarter", vPng.value.sha256, "png"), vPng.value.sha256);
  const co = await resolveReportBrandingV2(env, { workspaceId: "wsStarter" });
  ok("workspace logo (starter) → co_brand, full attribution", co.mode === "co_brand" && co.attribution === "full" && co.source === "workspace");
  ok("co-brand keeps 'Generated by CyberMeters' footer", /Generated by CyberMeters/.test(brandingAttribution(co).footer));

  // ── Tenant isolation: wsStarter's logo must not appear for wsBiz ──────────
  ok("workspace logo does NOT leak to another workspace", (await resolveReportBrandingV2(env, { workspaceId: "wsBizChild" })).mode === "cybermeters");

  // ── MSP white-label profile, entitled account ────────────────────────────
  db.prepare("INSERT INTO msp_branding_profiles (id, owner_user_id, name, logo_r2_key, logo_mime, logo_sha256, mode, is_default) VALUES ('mbp1','ownerBiz','ACME MSP', ?, 'image/png', ?, 'white_label', 1)").run(workspaceLogoKey("wsBiz", vPng.value.sha256, "png"), vPng.value.sha256);
  const wl = await resolveReportBrandingV2(env, { workspaceId: "wsBiz" });
  ok("entitled MSP white_label profile → mode white_label", wl.mode === "white_label" && wl.attribution === "reduced");
  ok("white-label footer is reduced 'Powered by CyberMeters'", /Powered by CyberMeters/.test(brandingAttribution(wl).footer) && brandingAttribution(wl).reduced === true);

  // ── Entitlement: a NON-entitled account cannot get white_label ───────────
  db.prepare("INSERT INTO msp_branding_profiles (id, owner_user_id, name, logo_r2_key, logo_mime, logo_sha256, mode, is_default) VALUES ('mbp2','ownerStarter','Starter MSP','k','image/png','zz','white_label', 1)").run();
  const notWl = await resolveReportBrandingV2(env, { workspaceId: "wsStarter" });
  ok("non-entitled account: white_label profile ignored (stays co_brand)", notWl.mode !== "white_label");

  // ── MSP profile isolation: ownerBiz's profile must not brand ownerStarter's ws
  ok("MSP profile does not cross to another MSP's workspace", (await resolveReportBrandingV2(env, { workspaceId: "wsStarter" })).mode !== "white_label");

  // ── Frozen-logo integrity: bytes must match the frozen sha ───────────────
  const key = workspaceLogoKey("wsBizChild", vPng.value.sha256, "png");
  r2store.set(key, png());
  const good = await loadBrandingLogoDataUri(env, { logo_r2_key: key, logo_mime: "image/png", logo_sha256: vPng.value.sha256 });
  ok("matching R2 logo loads as a data URI", typeof good === "string" && good.startsWith("data:image/png;base64,"));
  const tampered = await loadBrandingLogoDataUri(env, { logo_r2_key: key, logo_mime: "image/png", logo_sha256: "deadbeef" });
  ok("sha256 mismatch refuses the logo (→ safe fallback)", tampered === null);
  ok("missing R2 object → null (→ safe fallback)", (await loadBrandingLogoDataUri(env, { logo_r2_key: "absent", logo_mime: "image/png", logo_sha256: "x" })) === null);

  // ── Fallback descriptor is always branded ────────────────────────────────
  ok("cyberMetersDescriptor is fully attributed", cyberMetersDescriptor().mode === "cybermeters" && cyberMetersDescriptor().attribution === "full");

  console.log(`\nReport branding v2: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("report-branding-v2 validation FAILED"); process.exit(1); }
  console.log("report-branding-v2 validation passed");
}
main().catch((e) => { console.error("runner crashed:", e); process.exit(1); });
