// ── White-label report branding ───────────────────────────────────────────────
// Resolves the brand to put on a workspace's report. Branding lives on the
// account (customer_profiles, keyed by owner_user_id), so an MSP's logo/name/
// colour apply to every customer workspace they own. Returns null when the
// account hasn't turned white-label on — reports then use CyberMeters' own brand.

const MAX_LOGO_BYTES = 96 * 1024;              // ~96 KB — keep the report light
const HEX = /^#[0-9a-fA-F]{6}$/;

// Read-only: the brand for a workspace's report, or null (→ CyberMeters brand).
export async function resolveReportBranding(env, workspaceId) {
  try {
    const row = await env.cybermeters_db
      .prepare(
        `SELECT cp.company_name, cp.brand_logo, cp.brand_accent, cp.report_white_label
         FROM workspaces w
         JOIN customer_profiles cp ON cp.owner_user_id = w.owner_user_id
         WHERE w.id = ? LIMIT 1`
      )
      .bind(workspaceId)
      .first();
    if (!row || !row.report_white_label || !row.company_name) return null;
    return {
      company_name: row.company_name,
      logo: row.brand_logo || null,
      accent: HEX.test(row.brand_accent || "") ? row.brand_accent : null,
    };
  } catch {
    return null; // fail-safe → CyberMeters brand
  }
}

// Validate + normalise a branding payload for PUT. Returns { ok, value|error }.
export function validateBrandingInput(body) {
  const out = {};
  if ("brand_accent" in body) {
    const a = String(body.brand_accent || "").trim();
    if (a && !HEX.test(a)) return { ok: false, error: "brand_accent must be a #RRGGBB hex colour" };
    out.brand_accent = a || null;
  }
  if ("brand_logo" in body) {
    const logo = body.brand_logo;
    if (logo === null || logo === "") { out.brand_logo = null; }
    else {
      const s = String(logo);
      if (!/^data:image\/(png|jpeg|svg\+xml|webp);base64,/.test(s)) {
        return { ok: false, error: "brand_logo must be a data: URI (png/jpeg/svg/webp)" };
      }
      if (s.length > MAX_LOGO_BYTES * 1.4) return { ok: false, error: "brand_logo is too large (max ~96 KB)" };
      out.brand_logo = s;
    }
  }
  if ("report_white_label" in body) out.report_white_label = body.report_white_label ? 1 : 0;
  return { ok: true, value: out };
}
