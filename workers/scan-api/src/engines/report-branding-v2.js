// ── Report Branding v2 ────────────────────────────────────────────────────────
// Per-workspace co-brand logos, MSP white-label profiles, deterministic frozen
// branding, and a fallback that guarantees no report is ever unbranded.
//
// PRECEDENCE (canonical contract PART 4), resolved server-side — NEVER from the
// request body:
//   1. an authorised MSP white-label profile, when the account is white-label
//      entitled and owns the workspace  → mode "white_label" (reduced attribution)
//   2. a per-workspace customer logo                          → mode "co_brand"   (full attribution)
//   3. the CyberMeters logo                                   → mode "cybermeters"(full attribution)
//   4. the CyberMeters text mark (render-time, if the logo bytes cannot be embedded)
//
// resolveReportBrandingV2 NEVER returns null — there is always a brand. The
// descriptor it returns is frozen into scan_report_snapshots.branding_json at
// build time, so a later logo change affects FUTURE reports only.
import { hasFeatureEntitlement } from "./entitlements.js";

export const RENDERER_IDENTITY = "cybermeters-report-renderer";
export const MAX_LOGO_BYTES = 512 * 1024; // 512 KB ceiling for an R2-stored logo
const HEX = /^#[0-9a-fA-F]{6}$/;

// R2 keys — tenant-prefixed AND content-addressed, so an object is immutable
// (a new logo is a new key) and a frozen reference never changes underneath a
// historical report.
export function workspaceLogoKey(workspaceId, sha256, ext) {
  return `branding/logos/${encodeURIComponent(workspaceId)}/${sha256}.${ext}`;
}
export function mspLogoKey(ownerUserId, sha256, ext) {
  return `branding/msp/${encodeURIComponent(ownerUserId)}/${sha256}.${ext}`;
}

const EXT_BY_MIME = { "image/png": "png", "image/jpeg": "jpg" };

// Sniff the real decoded type from magic bytes — never trust the declared MIME.
// Only PNG and JPEG are accepted: the PDF embedder can embed exactly these; WebP,
// SVG, 16-bit/interlaced/CMYK all fall back to the text mark, so accepting them
// here would only produce a silently text-branded report. SVG is rejected outright
// (no trusted sanitisation/rasterisation path exists).
export function sniffImageType(bytes) {
  if (!bytes || bytes.length < 12) return null;
  const b = bytes;
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  return null; // gif/webp/svg/bmp/… rejected
}

// PNG dimensions from the IHDR; JPEG dimensions by scanning SOF markers.
function imageDimensions(mime, b) {
  try {
    if (mime === "image/png") {
      const w = (b[16] << 24) | (b[17] << 16) | (b[18] << 8) | b[19];
      const h = (b[20] << 24) | (b[21] << 16) | (b[22] << 8) | b[23];
      return { width: w, height: h };
    }
    if (mime === "image/jpeg") {
      let i = 2;
      while (i < b.length) {
        if (b[i] !== 0xff) { i++; continue; }
        const marker = b[i + 1];
        if (marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc) {
          return { height: (b[i + 5] << 8) | b[i + 6], width: (b[i + 7] << 8) | b[i + 8] };
        }
        i += 2 + ((b[i + 2] << 8) | b[i + 3]);
      }
    }
  } catch { /* fall through */ }
  return { width: 0, height: 0 };
}

// Validate a decoded logo upload. Returns { ok, value:{ mime, ext, sha256, bytes,
// width, height, size } } or { ok:false, error }.
export async function validateLogoUpload(bytes) {
  if (!bytes || !bytes.length) return { ok: false, error: "empty logo" };
  if (bytes.length > MAX_LOGO_BYTES) return { ok: false, error: `logo too large (max ${MAX_LOGO_BYTES} bytes)` };
  const mime = sniffImageType(bytes);
  if (!mime) return { ok: false, error: "unsupported image type — only PNG and JPEG are accepted" };
  const { width, height } = imageDimensions(mime, bytes);
  if (width < 16 || height < 16) return { ok: false, error: "logo dimensions too small (min 16x16)" };
  if (width > 4096 || height > 4096) return { ok: false, error: "logo dimensions too large (max 4096x4096)" };
  if (width * height > 4_000_000) return { ok: false, error: "logo has too many pixels" };
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const sha256 = [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, "0")).join("");
  return { ok: true, value: { mime, ext: EXT_BY_MIME[mime], sha256, bytes, width, height, size: bytes.length } };
}

// The CyberMeters house brand — the terminal fallback. Always branded.
export function cyberMetersDescriptor() {
  return { mode: "cybermeters", source: "cybermeters", logo_r2_key: null, display_name: "CyberMeters", accent: null, attribution: "full", renderer_identity: RENDERER_IDENTITY };
}

// Resolve the effective branding for a workspace's report. Reads D1 authoritatively;
// the plan + ownership are derived server-side, never supplied by the caller.
// NEVER returns null.
export async function resolveReportBrandingV2(env, { workspaceId }) {
  try {
    // Owner + plan + MSP white-label entitlement for this workspace's account.
    const acct = await env.cybermeters_db
      .prepare(
        `SELECT w.owner_user_id, u.plan
         FROM workspaces w JOIN users u ON u.id = w.owner_user_id
         WHERE w.id = ? AND w.deleted_at IS NULL LIMIT 1`
      )
      .bind(workspaceId)
      .first();
    if (!acct) return cyberMetersDescriptor();

    const plan = acct.plan || "free";
    const whiteLabelEntitled = hasFeatureEntitlement(plan, "white_label");

    // Per-workspace customer logo (co-brand). Tenant boundary = workspace_id.
    const wb = await env.cybermeters_db
      .prepare(`SELECT logo_r2_key, logo_sha256, logo_mime, display_name FROM workspace_branding WHERE workspace_id = ? LIMIT 1`)
      .bind(workspaceId)
      .first();

    // 1. Entitled MSP white-label profile owned by THIS workspace's account.
    if (whiteLabelEntitled) {
      const prof = await env.cybermeters_db
        .prepare(
          `SELECT id, logo_r2_key, logo_sha256, logo_mime, accent, name, mode
           FROM msp_branding_profiles
           WHERE owner_user_id = ? AND mode = 'white_label'
           ORDER BY is_default DESC, updated_at DESC LIMIT 1`
        )
        .bind(acct.owner_user_id)
        .first();
      if (prof) {
        // A child-client (per-workspace) logo, if present, is shown within the
        // MSP white-label frame; otherwise the MSP profile logo.
        const useWorkspaceLogo = wb && wb.logo_r2_key;
        return {
          mode: "white_label",
          source: useWorkspaceLogo ? "workspace" : "msp_profile",
          profile_id: prof.id,
          logo_r2_key: useWorkspaceLogo ? wb.logo_r2_key : (prof.logo_r2_key || null),
          logo_sha256: useWorkspaceLogo ? wb.logo_sha256 : (prof.logo_sha256 || null),
          logo_mime: useWorkspaceLogo ? wb.logo_mime : (prof.logo_mime || null),
          display_name: (useWorkspaceLogo && wb.display_name) || prof.name || "Prepared report",
          accent: HEX.test(prof.accent || "") ? prof.accent : null,
          attribution: "reduced",
          renderer_identity: RENDERER_IDENTITY,
        };
      }
    }

    // 2. Per-workspace customer logo (co-brand — full CyberMeters attribution).
    if (wb && wb.logo_r2_key) {
      return {
        mode: "co_brand", source: "workspace",
        logo_r2_key: wb.logo_r2_key, logo_sha256: wb.logo_sha256, logo_mime: wb.logo_mime,
        display_name: wb.display_name || null, accent: null,
        attribution: "full", renderer_identity: RENDERER_IDENTITY,
      };
    }

    // 3. CyberMeters fallback.
    return cyberMetersDescriptor();
  } catch {
    return cyberMetersDescriptor(); // fail-safe: always branded
  }
}

// Load the logo bytes for a resolved/frozen descriptor from R2 and hand back a
// data: URI the proven PDF embedder consumes. Ownership is implicit: the key is
// tenant-prefixed and was written under an authorised path. Returns null on any
// miss/failure → the renderer uses the CyberMeters text/logo fallback.
export async function loadBrandingLogoDataUri(env, descriptor) {
  try {
    if (!descriptor || !descriptor.logo_r2_key || !descriptor.logo_mime) return null;
    const obj = await env.cybermeters_reports.get(descriptor.logo_r2_key);
    if (!obj) return null;
    const bytes = new Uint8Array(await obj.arrayBuffer());
    // Integrity: the bytes must match the frozen content hash (immutability check).
    if (descriptor.logo_sha256) {
      const digest = await crypto.subtle.digest("SHA-256", bytes);
      const sha = [...new Uint8Array(digest)].map((x) => x.toString(16).padStart(2, "0")).join("");
      if (sha !== descriptor.logo_sha256) return null;
    }
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return `data:${descriptor.logo_mime};base64,${btoa(bin)}`;
  } catch {
    return null;
  }
}

// Attribution text for a descriptor. Co-brand + fallback keep the full CyberMeters
// wordmark; entitled white-label reduces to "Powered by CyberMeters".
export function brandingAttribution(descriptor) {
  const mode = descriptor?.mode || "cybermeters";
  if (mode === "white_label") return { primary: descriptor.display_name || "Prepared report", footer: "Powered by CyberMeters · cybermeters.com", reduced: true };
  if (mode === "co_brand") return { primary: descriptor.display_name || null, footer: "Generated by CyberMeters · cybermeters.com", reduced: false };
  return { primary: "CyberMeters", footer: "Generated by CyberMeters · cybermeters.com", reduced: false };
}
