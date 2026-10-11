// ── Website Security: signed-in scanning — profiles, attempts, health ───────
//
// Storage for sign-in profiles (migration 116). One profile per
// (workspace, verified domain). The secret lives only as ciphertext
// (lib/website-auth-secrets.js); this module never returns it, never logs it,
// and decrypts it only immediately before a sign-in attempt.
//
// Login health: every attempt (a customer's "Test sign-in" or a scan) is
// recorded with a code. Credential-type failures in a row pause the profile
// (SIGN_IN_PAUSE_AFTER) so CyberMeters can never lock the test account out;
// a successful test or a re-save resumes it.
import { createId } from "../lib/util.js";
import { encryptWebsiteSecret, decryptWebsiteSecret, websiteAuthKeyAvailable } from "../lib/website-auth-secrets.js";
import { normalizePlan, getEffectivePlan } from "./entitlements.js";
import { getWorkspaceBillingUserId } from "./plan-usage.js";
import { signIn, SIGN_IN_TEST_LIMITS, CREDENTIAL_FAILURE_OUTCOMES } from "./website-sign-in.js";

export const SIGN_IN_PAUSE_AFTER = 3;

export class SignInError extends Error {
  constructor(code, status = 409) { super(code); this.code = code; this.status = status; }
}

/** Signed-in scanning stores customer credentials: an active paid plan or trial only. */
export function planAllowsSignedInScanning(plan) {
  return normalizePlan(plan) !== "free";
}
export function signInVaultAvailable(env) {
  return websiteAuthKeyAvailable(env?.WEBSITE_AUTH_KEY);
}

async function sha256Hex(value) {
  return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)))]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}
/** Deterministic: concurrent first saves encrypt against the same eventual row id. */
export async function signInProfileId(workspaceId, domainId) {
  return `wsip_${(await sha256Hex(JSON.stringify(["website-sign-in", workspaceId, domainId]))).slice(0, 40)}`;
}

/** Customer-safe projection: never the ciphertext, never the secret. */
export function signInProfileView(row) {
  if (!row) return null;
  return {
    id: row.id,
    method: row.method,
    login_url: row.login_url ?? null,
    start_url: row.start_url ?? null,
    signed_in_text: row.signed_in_text ?? null,
    username_field: row.username_field ?? null,
    password_field: row.password_field ?? null,
    credential_hint: row.credential_hint,
    status: row.status,
    paused_reason: row.paused_reason ?? null,
    authorization_attested_at: row.authorization_attested_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
    last_attempt_at: row.last_attempt_at ?? null,
    last_attempt_source: row.last_attempt_source ?? null,
    last_outcome: row.last_outcome ?? null,
    last_signed_in_at: row.last_signed_in_at ?? null,
    consecutive_failures: Number(row.consecutive_failures) || 0,
  };
}

// Never store a truncated (unparseable) JSON document.
const boundedJson = (value, max) => { const text = JSON.stringify(value); return text.length <= max ? text : JSON.stringify({ truncated: true }); };
const parse = (v, fallback) => { try { return v ? JSON.parse(v) : fallback; } catch { return fallback; } };
export function signInAttemptView(row, { withSummary = false } = {}) {
  return {
    id: row.id,
    source: row.source,
    scan_id: row.scan_id ?? null,
    outcome: row.outcome,
    detail: parse(row.detail_json, {}),
    coverage: row.coverage ?? null,
    ...(withSummary ? { summary: parse(row.summary_json, null) } : {}),
    created_at: row.created_at,
  };
}

export async function loadSignInProfile(db, workspaceId, domainId) {
  return db.prepare("SELECT * FROM website_sign_in_profiles WHERE workspace_id = ? AND domain_id = ?")
    .bind(workspaceId, domainId).first();
}

const LIVE_VERIFIED = `EXISTS (SELECT 1 FROM workspaces w WHERE w.id = ? AND w.deleted_at IS NULL)
  AND EXISTS (SELECT 1 FROM workspace_domains wd WHERE wd.workspace_id = ? AND wd.domain_id = ?
              AND wd.verification_status = 'verified' AND wd.verified_at IS NOT NULL)`;

/**
 * Create or replace the profile. `input` comes from normalizeSignInInput.
 * A null `input.secret` keeps the stored secret (same method only — enforced
 * by the input validator AND by the revision/method guard below).
 */
export async function saveSignInProfile(env, { workspaceId, domainId, domain, userId, input, existing }) {
  if (!signInVaultAvailable(env)) throw new SignInError("vault_unavailable", 503);
  const db = env.cybermeters_db;
  const id = existing?.id || await signInProfileId(workspaceId, domainId);
  let ciphertext, revision, hint;
  if (input.secret) {
    ciphertext = await encryptWebsiteSecret(input.secret, { workspace_id: workspaceId, domain_id: domainId, profile_id: id, method: input.method }, env.WEBSITE_AUTH_KEY);
    input.secret = null; // drop the clear value as soon as it is sealed
    revision = crypto.randomUUID();
    hint = input.credential_hint;
  } else {
    if (!existing || existing.method !== input.method) throw new SignInError("credentials_required", 400);
    ciphertext = existing.secret_ciphertext;
    revision = existing.credential_revision;
    hint = existing.credential_hint;
  }
  const now = new Date().toISOString();
  const guardRevision = existing ? existing.credential_revision : null;
  const upsert = db.prepare(
    `INSERT INTO website_sign_in_profiles
       (id, workspace_id, domain_id, method, login_url, start_url, signed_in_text, username_field, password_field,
        credential_hint, secret_ciphertext, credential_revision, status, paused_reason,
        authorization_attested_by, authorization_attested_at, created_by, created_at, updated_at, consecutive_failures)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NULL, ?, ?, ?, ?, ?, 0
      WHERE ${LIVE_VERIFIED}
     ON CONFLICT(workspace_id, domain_id) DO UPDATE SET
       method = excluded.method, login_url = excluded.login_url, start_url = excluded.start_url,
       signed_in_text = excluded.signed_in_text, username_field = excluded.username_field,
       password_field = excluded.password_field, credential_hint = excluded.credential_hint,
       secret_ciphertext = excluded.secret_ciphertext, credential_revision = excluded.credential_revision,
       -- Only NEW credentials resume a paused profile (a successful test also does);
       -- editing other settings never buys the old password more attempts.
       status = CASE WHEN website_sign_in_profiles.credential_revision = excluded.credential_revision THEN website_sign_in_profiles.status ELSE 'active' END,
       paused_reason = CASE WHEN website_sign_in_profiles.credential_revision = excluded.credential_revision THEN website_sign_in_profiles.paused_reason ELSE NULL END,
       consecutive_failures = CASE WHEN website_sign_in_profiles.credential_revision = excluded.credential_revision THEN website_sign_in_profiles.consecutive_failures ELSE 0 END,
       authorization_attested_by = excluded.authorization_attested_by,
       authorization_attested_at = excluded.authorization_attested_at, updated_at = excluded.updated_at
     WHERE website_sign_in_profiles.credential_revision IS ?`)
    .bind(id, workspaceId, domainId, input.method, input.login_url, input.start_url, input.signed_in_text,
      input.username_field, input.password_field, hint, ciphertext, revision,
      userId, now, userId, now, now,
      workspaceId, workspaceId, domainId, guardRevision);
  const audit = db.prepare(
    `INSERT INTO audit_events (id, workspace_id, user_id, actor_type, event_type, entity_type, entity_id, description, metadata_json, created_at)
     SELECT ?, ?, ?, 'customer', ?, 'website_sign_in_profile', ?, ?, ?, ?
      WHERE EXISTS (SELECT 1 FROM website_sign_in_profiles WHERE id = ? AND workspace_id = ? AND updated_at = ? AND credential_revision = ?)`)
    .bind(createId("audit"), workspaceId, userId, existing ? "website_sign_in_profile_updated" : "website_sign_in_profile_created", id,
      existing ? "Signed-in scanning settings updated; authorization to sign in confirmed" : "Signed-in scanning set up; authorization to sign in confirmed",
      JSON.stringify({ domain, method: input.method, credentials_changed: revision !== guardRevision, authorization: "attested", independently_verified: false }),
      now, id, workspaceId, now, revision);
  await db.batch([upsert, audit]);
  const row = await loadSignInProfile(db, workspaceId, domainId);
  if (!row || row.updated_at !== now || row.credential_revision !== revision) throw new SignInError("profile_not_saved", 409);
  return row;
}

/** Deletes the profile row — the ciphertext is destroyed, not soft-deleted. */
export async function deleteSignInProfile(env, { workspaceId, domainId, domain, userId }) {
  const db = env.cybermeters_db;
  const now = new Date().toISOString();
  const audit = db.prepare(
    `INSERT INTO audit_events (id, workspace_id, user_id, actor_type, event_type, entity_type, entity_id, description, metadata_json, created_at)
     SELECT ?, ?, ?, 'customer', 'website_sign_in_profile_deleted', 'website_sign_in_profile', id, 'Signed-in scanning removed; stored credentials deleted', ?, ?
       FROM website_sign_in_profiles WHERE workspace_id = ? AND domain_id = ?`)
    .bind(createId("audit"), workspaceId, userId, JSON.stringify({ domain }), now, workspaceId, domainId);
  const del = db.prepare("DELETE FROM website_sign_in_profiles WHERE workspace_id = ? AND domain_id = ?").bind(workspaceId, domainId);
  const [, result] = await db.batch([audit, del]);
  return { deleted: Number(result?.meta?.changes ?? 0) === 1 };
}

/**
 * Records one attempt and updates the profile's login health — only when the
 * profile still carries the credentials that were tried (a re-save in between
 * starts a fresh history).
 */
export async function recordSignInAttempt(env, { workspaceId, domainId, profile, source, scanId = null, actorUserId = null, outcome, detail = {}, coverage = null, summary = null }) {
  const db = env.cybermeters_db;
  const now = new Date().toISOString();
  // Any unproven outcome after the credentials were submitted counts too: a
  // site answering a wrong password with 422, an error or a timeout must not
  // be retried forever against the real account.
  const credentialFailure = outcome !== "signed_in" && (CREDENTIAL_FAILURE_OUTCOMES.includes(outcome) || detail?.submitted === true) ? 1 : 0;
  const success = outcome === "signed_in" ? 1 : 0;
  const insert = db.prepare(
    `INSERT INTO website_sign_in_attempts
       (id, workspace_id, domain_id, profile_id, credential_revision, source, scan_id, outcome, detail_json, coverage, summary_json, actor_user_id, created_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
      WHERE EXISTS (SELECT 1 FROM workspaces w WHERE w.id = ? AND w.deleted_at IS NULL)
     ON CONFLICT DO NOTHING`)
    .bind(createId("wsia"), workspaceId, domainId, profile.id, profile.credential_revision, source, scanId, outcome,
      boundedJson(detail || {}, 16_000), coverage, summary ? boundedJson(summary, 64_000) : null, actorUserId, now, workspaceId);
  const update = db.prepare(
    `UPDATE website_sign_in_profiles SET
       last_attempt_at = ?, last_attempt_source = ?, last_outcome = ?,
       last_signed_in_at = CASE WHEN ? = 1 THEN ? ELSE last_signed_in_at END,
       consecutive_failures = CASE WHEN ? = 1 THEN 0 WHEN ? = 1 THEN consecutive_failures + 1 ELSE consecutive_failures END,
       status = CASE WHEN ? = 1 THEN 'active'
                     WHEN ? = 1 AND consecutive_failures + 1 >= ? THEN 'paused' ELSE status END,
       paused_reason = CASE WHEN ? = 1 THEN NULL
                            WHEN ? = 1 AND consecutive_failures + 1 >= ? THEN 'repeated_sign_in_failures' ELSE paused_reason END
     WHERE id = ? AND workspace_id = ? AND domain_id = ? AND credential_revision = ?`)
    .bind(now, source, outcome,
      success, now,
      success, credentialFailure,
      success, credentialFailure, SIGN_IN_PAUSE_AFTER,
      success, credentialFailure, SIGN_IN_PAUSE_AFTER,
      profile.id, workspaceId, domainId, profile.credential_revision);
  await db.batch([insert, update]);
  return now;
}

/** Decrypts immediately before use; a vault problem is an outcome, not a throw. */
export async function openSignInSecret(env, profile, { workspaceId, domainId }) {
  if (!signInVaultAvailable(env)) return null;
  try {
    return await decryptWebsiteSecret(profile.secret_ciphertext,
      { workspace_id: workspaceId, domain_id: domainId, profile_id: profile.id, method: profile.method }, env.WEBSITE_AUTH_KEY);
  } catch { return null; }
}

/** One customer-initiated test (bounded tighter than a scan). */
export async function testSignInProfile(env, { workspaceId, domainId, domain, profile, opts = {} }) {
  const secret = await openSignInSecret(env, profile, { workspaceId, domainId });
  if (!secret) return { outcome: "vault_unavailable", detail: {} };
  const result = await signIn(domain, profile, secret, { ...opts, limits: { ...SIGN_IN_TEST_LIMITS, ...(opts.limits || {}) } });
  return { outcome: result.outcome, detail: result.detail };
}

/** Verified domains of a workspace with their profile and the last 5 attempts each. */
export async function listSignInProfiles(db, workspaceId) {
  const domains = (await db.prepare(
    `SELECT d.id AS domain_id, d.domain AS domain,
            p.id, p.method, p.login_url, p.start_url, p.signed_in_text, p.username_field, p.password_field,
            p.credential_hint, p.status, p.paused_reason, p.authorization_attested_at, p.created_at, p.updated_at,
            p.last_attempt_at, p.last_attempt_source, p.last_outcome, p.last_signed_in_at, p.consecutive_failures
       FROM workspace_domains wd
       JOIN domains d ON d.id = wd.domain_id
       LEFT JOIN website_sign_in_profiles p ON p.workspace_id = wd.workspace_id AND p.domain_id = wd.domain_id
      WHERE wd.workspace_id = ? AND wd.verification_status = 'verified' AND wd.verified_at IS NOT NULL
      ORDER BY d.domain LIMIT 500`).bind(workspaceId).all()).results || [];
  const attempts = (await db.prepare(
    `SELECT id, domain_id, source, scan_id, outcome, detail_json, coverage, created_at FROM (
       SELECT a.*, ROW_NUMBER() OVER (PARTITION BY a.domain_id ORDER BY a.created_at DESC, a.id DESC) AS rn
         FROM website_sign_in_attempts a WHERE a.workspace_id = ?)
      WHERE rn <= 5 ORDER BY domain_id, created_at DESC, id DESC`).bind(workspaceId).all()).results || [];
  // The signed-in pages of the latest SCAN attempt per domain (tests check sign-in only).
  const latestScans = (await db.prepare(
    `SELECT id, domain_id, source, scan_id, outcome, detail_json, coverage, summary_json, created_at FROM (
       SELECT a.*, ROW_NUMBER() OVER (PARTITION BY a.domain_id ORDER BY a.created_at DESC, a.id DESC) AS rn
         FROM website_sign_in_attempts a WHERE a.workspace_id = ? AND a.source = 'scan')
      WHERE rn = 1`).bind(workspaceId).all()).results || [];
  const byDomain = new Map();
  for (const a of attempts) {
    if (!byDomain.has(a.domain_id)) byDomain.set(a.domain_id, []);
    byDomain.get(a.domain_id).push(signInAttemptView(a));
  }
  const scanByDomain = new Map(latestScans.map((a) => [a.domain_id, signInAttemptView(a, { withSummary: true })]));
  return domains.map((r) => ({
    domain_id: r.domain_id,
    domain: r.domain,
    profile: r.id ? signInProfileView(r) : null,
    recent_attempts: byDomain.get(r.domain_id) || [],
    latest_scan: scanByDomain.get(r.domain_id) || null,
  }));
}

/**
 * The profile a scan of (workspace, domain) may use: active, live workspace,
 * verified domain. Returns null (nothing to do), { profile, blocked } (record
 * why it was not attempted) or { profile, secret }.
 */
export async function loadSignedInScanProfile(env, { workspaceId, domainId }) {
  if (!workspaceId || !domainId) return null;
  const profile = await env.cybermeters_db.prepare(
    `SELECT p.* FROM website_sign_in_profiles p
       JOIN workspaces w ON w.id = p.workspace_id AND w.deleted_at IS NULL
       JOIN workspace_domains wd ON wd.workspace_id = p.workspace_id AND wd.domain_id = p.domain_id
        AND wd.verification_status = 'verified' AND wd.verified_at IS NOT NULL
      WHERE p.workspace_id = ? AND p.domain_id = ? AND p.status = 'active'`).bind(workspaceId, domainId).first();
  if (!profile) return null;
  const owner = await getWorkspaceBillingUserId(workspaceId, null, env);
  if (!owner || !planAllowsSignedInScanning(await getEffectivePlan(owner, env))) return { profile, blocked: "plan_required" };
  const secret = await openSignInSecret(env, profile, { workspaceId, domainId });
  if (!secret) return { profile, blocked: "vault_unavailable" };
  return { profile, secret };
}
