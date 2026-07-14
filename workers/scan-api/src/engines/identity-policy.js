// ── Identity Exposure policy — deterministic identity + risk core ───────────
// Pure, side-effect-free helpers shared by the managed identity-exposure
// lifecycle: the provider alias layer, surface-type derivation, the canonical
// managed-record identity key, and the externally-observable risk model. All
// deterministic and covered by tests.
//
// Honesty: risk here reflects ONLY externally observable signals (surface type,
// customer classification, ownership, recurrence). A publicly visible identity
// entry point is NOT automatically a vulnerability, and nothing here claims
// leaked-credential, MFA, Conditional Access or internal policy state.

// ── Provider alias layer ──────────────────────────────────────────────────
// EXPLICIT variants only — never fuzzy matching. Distinct products of one
// provider stay distinct (Microsoft Entra ID ≠ Microsoft 365 mail service).
// Keyed by the normalized (lowercased, single-spaced) provider name.
export const PROVIDER_ALIASES = Object.freeze({
  "azure ad": "microsoft_entra_id", "azure active directory": "microsoft_entra_id",
  "microsoft entra id": "microsoft_entra_id", "entra id": "microsoft_entra_id",
  "entra": "microsoft_entra_id", "microsoft entra": "microsoft_entra_id",
  "microsoft adfs": "microsoft_adfs", "adfs": "microsoft_adfs", "active directory federation services": "microsoft_adfs",
  "office 365": "microsoft_365", "office 365 login": "microsoft_365", "microsoft 365": "microsoft_365",
  "m365": "microsoft_365", "o365": "microsoft_365",
  "google workspace identity": "google_workspace", "google workspace": "google_workspace",
  "g suite": "google_workspace", "google identity": "google_workspace",
  "okta": "okta", "auth0": "auth0", "ping identity": "ping_identity", "pingfederate": "ping_identity",
  "onelogin": "onelogin", "duo": "duo_security", "duo security": "duo_security",
  "jumpcloud": "jumpcloud", "keycloak": "keycloak",
  "crowdstrike falcon identity": "crowdstrike_falcon", "crowdstrike": "crowdstrike_falcon",
});
export function providerKey(name) {
  const norm = String(name || "").trim().toLowerCase().replace(/\s+/g, " ");
  if (!norm) return null;
  if (PROVIDER_ALIASES[norm]) return PROVIDER_ALIASES[norm];
  const slug = norm.replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 60);
  return PROVIDER_ALIASES[slug] || slug || null;
}

// ── Surface types ───────────────────────────────────────────────────────────
// Closed, machine-stable set derived from the raw (asset_type, identity_type).
export const SURFACE_TYPES = Object.freeze([
  "identity_provider", "sso_portal", "saml_federation", "login_portal",
  "admin_login", "vpn_portal", "oauth_endpoint",
]);
const IDENTITY_TYPE_SURFACE = {
  idp: "identity_provider", sso: "sso_portal", saml: "saml_federation",
  vpn: "vpn_portal", login_portal: "login_portal", admin_login: "admin_login",
  oauth: "oauth_endpoint",
};
export function deriveSurfaceType(assetType, identityType) {
  const it = String(identityType || "").trim().toLowerCase();
  // A provider-typed asset with an idp/sso identity is the identity provider itself.
  if (String(assetType || "").toLowerCase() === "provider" && (it === "idp" || it === "sso" || it === "saml")) {
    return "identity_provider";
  }
  return IDENTITY_TYPE_SURFACE[it] || "login_portal";
}

// Normalize a hostname for the identity key (lowercase, strip trailing dot/port).
export function normalizeHostname(h) {
  return String(h || "").trim().toLowerCase().replace(/\.$/, "").replace(/:\d+$/, "");
}

// ── Canonical managed-record identity ─────────────────────────────────────
// Deterministic. A hostname-anchored surface keeps its identity across a
// provider change (the change is a MATERIAL event on the same record); a
// provider-level detection with no hostname is anchored on provider + surface.
export function canonicalIdentityKey({ provider_key, surface_type, hostname }) {
  const host = normalizeHostname(hostname);
  const surf = String(surface_type || "login_portal");
  if (host) return `surface:${surf}:host:${host}`;
  return `provider:${provider_key || "unknown"}:${surf}`;
}

// ── Externally-observable risk model ──────────────────────────────────────
export const RISK_STATUSES = Object.freeze(["ok", "low", "attention", "elevated", "high"]);
// A public admin/management login is the highest externally-observable concern.
const HIGH_RISK_SURFACES = new Set(["admin_login"]);

// Deterministic, EXPLAINABLE risk. Reflects surface type, customer expectation,
// ownership and recurrence — never alarmist (an expected, owned provider login
// is `ok`), never meaningless (an unexpected public admin surface is `high`).
export function assessIdentityRisk({ surface_type, customer_classification, ownership_status, recurrence_type }) {
  const cls = String(customer_classification || "unreviewed");
  const admin = HIGH_RISK_SURFACES.has(surface_type);

  // Recurrence/monitoring signals dominate when present.
  if (recurrence_type === "removal_contradicted" || recurrence_type === "exception_expired" || recurrence_type === "verification_failed") {
    return { risk_status: "high", risk_reason: recurrence_type };
  }
  if (recurrence_type === "public_admin_surface") return { risk_status: "high", risk_reason: "public_admin_surface" };
  if (recurrence_type === "provider_change" || recurrence_type === "material_change") {
    return { risk_status: "elevated", risk_reason: recurrence_type };
  }

  // Customer classification is the primary lens.
  if (cls === "expected") return { risk_status: admin ? "attention" : "ok", risk_reason: admin ? "expected_admin_surface" : "expected" };
  if (cls === "retired") return { risk_status: "attention", risk_reason: "retired_surface" };
  if (cls === "exception") return { risk_status: "attention", risk_reason: "under_exception" };
  if (cls === "unexpected") return { risk_status: admin ? "high" : "elevated", risk_reason: admin ? "unexpected_admin_surface" : "unexpected_surface" };
  if (cls === "investigate") return { risk_status: admin ? "elevated" : "attention", risk_reason: "under_investigation" };

  // Unreviewed: a public admin surface always warrants review; an unowned surface
  // needs attention; otherwise it is a low-signal observation, not an alarm.
  if (admin) return { risk_status: "elevated", risk_reason: "unreviewed_admin_surface" };
  if (ownership_status === "missing") return { risk_status: "attention", risk_reason: "unreviewed_unowned" };
  return { risk_status: "low", risk_reason: "observed_unreviewed" };
}
