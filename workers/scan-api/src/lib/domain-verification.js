// ── Workspace-scoped domain-ownership verification ────────────────────────────
// The single source of truth for "has THIS workspace independently proven control
// of this domain?". Authority lives on the workspace_domains(workspace_id, domain_id)
// link (migration 079). The legacy domains.verification_* columns are read-only
// compatibility data and are NEVER consulted for scan authorization.

import { dnsQuery } from "../engines/dns.js";
import { customerSafeFailure } from "./errors.js";
import { createAuditEvent } from "./events.js";
import { redactedJson } from "./redact.js";

// Customer-safe rejection returned by every scan-start path for an unverified link.
export const DOMAIN_VERIFICATION_REQUIRED = Object.freeze({
  error:   "domain_verification_required",
  message: "Verify domain ownership before starting a Cyber MOT.",
});

// True ONLY when the exact (workspace_id, domain_id) link is 'verified'. Fails
// closed (returns false) on any error — an unreadable link is never scannable.
export async function isWorkspaceDomainVerified(env, workspaceId, domainId) {
  if (!workspaceId || !domainId) return false;
  try {
    const row = await env.cybermeters_db
      .prepare("SELECT verification_status FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?")
      .bind(workspaceId, domainId)
      .first();
    return row?.verification_status === "verified";
  } catch {
    return false;
  }
}

// ── The 48-hour auto-recheck promise ─────────────────────────────────────────
// The failure response tells the customer: "We re-check automatically every hour
// for 48 hours from when you generated this verification code." These constants
// are what makes that sentence true — the cron's eligibility window and cadence
// are derived from them, so the copy and the behaviour cannot drift apart.
//
// If you change these, change the customer copy in the same commit.
export const VERIFICATION_WINDOW_HOURS = 48;
export const VERIFICATION_RECHECK_INTERVAL = "hourly";
// Bounded per cron run: each candidate costs one DoH subrequest, and the Worker
// has a hard subrequest ceiling shared with every other task on the same tick.
export const VERIFICATION_RECHECK_BATCH = 10;

// ── The canonical DNS TXT ownership proof ────────────────────────────────────
// ONE implementation of "does this domain publish our token?", shared by the
// manual route and the hourly cron. Previously the cron carried its own copy of
// the lookup, the quote-stripping and the comparison; two copies of a proof is
// two places for them to disagree about what counts as proven.
//
// Returns a category, not a boolean, because the three failures are different
// customer actions: publish the record / fix a wrong value / wait for a resolver.
// A lookup error is NEVER reported as "not found" — it proves nothing either way.
//
//   { verified: boolean, category: "found"|"dns_not_found"|"dns_mismatch"|"dns_lookup_error", error }
export async function checkDnsTxtProof(domain, token) {
  const expected = `cybermeters-verification=${token}`;
  try {
    const result  = await dnsQuery(`_cybermeters.${domain}`, "TXT");
    const answers = result?.Answer || [];
    const verified = answers.some((a) => {
      // RFC 1035: TXT data arrives with surrounding quotes stripped by DoH JSON
      const val = String(a.data || "").replace(/^"|"$/g, "").trim();
      return val === expected;
    });
    return {
      verified,
      category: verified ? "found" : (answers.length === 0 ? "dns_not_found" : "dns_mismatch"),
      error: null,
    };
  } catch (e) {
    return {
      verified: false,
      category: "dns_lookup_error",
      error: customerSafeFailure("domain-verification/dns", e, "DNS lookup could not be completed"),
    };
  }
}

// Maps a proof category onto the canonical terminal outcome. Shared so the manual
// route and the cron cannot label the same observation differently.
export function outcomeForDnsCategory(category) {
  switch (category) {
    case "dns_mismatch":     return VERIFICATION_OUTCOMES.DNS_MISMATCH;
    case "dns_lookup_error": return VERIFICATION_OUTCOMES.DNS_LOOKUP_ERROR;
    default:                 return VERIFICATION_OUTCOMES.DNS_NOT_FOUND;
  }
}

// ── Canonical verification outcomes ──────────────────────────────────────────
// The closed vocabulary for "how did this verification attempt end?". Every
// terminal branch of POST /api/domains/:id/verify maps to exactly one of these,
// and the value is both stored (audit metadata) and returned (`outcome`) so a
// customer report, a log line and an audit row can be joined on one string.
//
// Frozen and exported so the route cannot invent an outcome the tests do not
// know about — validate-domain-verification-integrity.js asserts that every
// outcome the route can emit is a member of this set, and vice versa.
export const VERIFICATION_OUTCOMES = Object.freeze({
  // Terminal success
  ALREADY_VERIFIED:   "already_verified",
  VERIFIED_DNS_TXT:   "verified_dns_txt",
  VERIFIED_HTML_FILE: "verified_html_file",
  // Terminal "not proven" — the customer's DNS/file is not (yet) as required
  DNS_NOT_FOUND:      "dns_not_found",   // no TXT answer at _cybermeters.<domain>
  DNS_MISMATCH:       "dns_mismatch",    // TXT present, value is not the expected one
  DNS_LOOKUP_ERROR:   "dns_lookup_error",// resolver failed; neither proven nor disproven
  // Terminal rejection — the request could not be acted on
  UNAUTHORIZED:           "unauthorized",
  DOMAIN_LINK_NOT_FOUND:  "domain_link_not_found",
  WORKSPACE_AMBIGUOUS:    "workspace_ambiguous",
  NO_TOKEN:               "no_token",
  // Terminal integrity failure — the check passed but the claim did not persist
  PERSISTENCE_ZERO_ROWS:           "persistence_zero_rows",
  PERSISTENCE_UNEXPECTED_ROWS:     "persistence_unexpected_rows",
  PERSISTENCE_CONFIRMATION_FAILED: "persistence_confirmation_failed",
  // Terminal fault
  INTERNAL_ERROR: "internal_error",
  // The hourly auto-recheck stopped trying. Emitted ONCE, in the hour the row
  // crosses the 48h boundary — not on every subsequent run, which would log the
  // same dead row forever. This is the honest end of the 48-hour promise.
  RECHECK_WINDOW_EXPIRED: "recheck_window_expired",
});

const OUTCOME_VALUES = Object.freeze(Object.values(VERIFICATION_OUTCOMES));
export const isVerificationOutcome = (v) => OUTCOME_VALUES.includes(v);

// Outcomes that mean "this workspace has proven control of this domain".
const VERIFIED_OUTCOMES = new Set([
  VERIFICATION_OUTCOMES.ALREADY_VERIFIED,
  VERIFICATION_OUTCOMES.VERIFIED_DNS_TXT,
  VERIFICATION_OUTCOMES.VERIFIED_HTML_FILE,
]);
export const isVerifiedOutcome = (v) => VERIFIED_OUTCOMES.has(v);

// ── Verification-attempt telemetry ───────────────────────────────────────────
// Every outcome of POST /api/domains/:id/verify emits exactly one terminal record
// — including the early rejections that previously returned in silence (no token,
// unresolvable workspace, already verified, exception) and the 401.
//
// Why this exists: a production incident could not be diagnosed at all. The row
// sat at 'pending' with a token-generation audit above it and NOTHING after —
// while both terminal branches (verified / failed) mutate status AND audit. That
// combination proved the request never reached the DNS check, but could not say
// whether it was rejected early or never arrived, because the early-return paths
// emitted no evidence. Absence of a record must never again be ambiguous.
//
// Two sinks, deliberately:
//   • audit_events — durable, queryable, joined to the workspace. BEST-EFFORT:
//     createAuditEvent already swallows its own errors, and we swallow again here.
//   • console (redacted JSON) — always emitted, including when the audit write is
//     the thing that failed. This is what makes a telemetry failure itself visible
//     instead of silent.
// Neither may ever change the request's outcome: a verification that persisted is
// verified even if every telemetry write fails. See persistVerification — proof of
// persistence is mandatory; proof of telemetry is not.
//
// NEVER record: the verification token, the Authorization header, cookies, raw
// provider bodies, or the raw expected TXT value (it embeds the token verbatim).
// Two independent controls enforce this: the metadata below is a strict allowlist
// (an unknown key on `detail` cannot reach a sink), and the console payload goes
// through redactedJson, whose long-hex rule catches the 48-char token even if a
// future edit smuggles one into an allowlisted field.
//
// The 401 DOES write an audit row (founder decision, 14 July 2026). The route is
// public-reachable, so this is an unauthenticated write path; it is bounded by the
// global per-IP write throttle (60 / 5 min) that already guards every other write,
// and the rows carry actor_type 'anonymous' with a null workspace so they cannot
// pollute a tenant's audit view.
export async function recordVerificationAttempt(env, detail) {
  const {
    request_id = null, workspace_id = null, domain_id = null, domain = null,
    user_id = null, outcome = null, method = null,
  } = detail || {};

  // Strict allowlist. Anything not named here never reaches a sink.
  const record = {
    request_id, outcome, method,
    workspace_id, domain_id, domain,
    dns_result:            detail?.dns_result ?? null,
    html_result:           detail?.html_result ?? null,
    dns_error:             detail?.dns_error ?? null,
    html_error:            detail?.html_error ?? null,
    affected_row_count:    detail?.affected_row_count ?? null,
    persisted_status:      detail?.persisted_status ?? null,
    persisted_verified_at: detail?.persisted_verified_at ?? null,
    resolution_code:       detail?.resolution_code ?? null,
    dns_record_hash:       detail?.dns_record_hash ?? null,
    resolver_used:         detail?.resolver_used ?? null,
    created_at:            new Date().toISOString(),
  };

  // The 401 has no authenticated identity to attribute the row to, but is still
  // recorded — an attacker probing this route is exactly what we want to see.
  //
  // Note we do NOT report whether this row landed: createAuditEvent swallows its
  // own D1 errors and returns undefined, so a persisted/not-persisted flag here
  // would be an unverified claim — the precise defect this episode is fixing. The
  // console sink below is the independent record; if D1 is the thing that is down,
  // that line is what survives.
  try {
    await createAuditEvent(env, {
      workspace_id,
      user_id,
      actor_type:  user_id ? "customer" : "anonymous",
      event_type:  "domain_verification_attempted",
      entity_type: "domain",
      entity_id:   domain_id,
      description: `Verification attempt for ${domain || domain_id || "unknown domain"} → ${outcome}`,
      metadata:    record,
    });
  } catch {
    // Swallowed: telemetry must never fail the request it is describing.
    // The console line below still fires, so the failure is not invisible.
  }

  try {
    console.log("[domain-verification/attempt]", redactedJson(record));
  } catch {
    // Even the log is best-effort. Nothing here may reach the caller.
  }
}

// ── Persistence assertion ────────────────────────────────────────────────────
// A verification claim is only true if it survived the write. The UPDATE alone is
// not proof: a zero-row UPDATE is a perfectly successful D1 statement, and the
// route used to return {success:true, verification_status:"verified"} on the
// strength of a statement that changed nothing.
//
// Two independent gates, both mandatory:
//   1. meta.changes === 1 — exactly one row. Zero means the link vanished or the
//      scope was wrong. More than one means (workspace_id, domain_id) is not
//      unique, i.e. we just wrote 'verified' onto rows we did not intend to touch;
//      that is a tenant-integrity event, never a success.
//   2. A follow-up SELECT on the EXACT (workspace_id, domain_id), which must come
//      back 'verified' with a non-null verified_at AND echo back the same two ids
//      we asked for. Reading the ids back is not redundant: it is what makes the
//      returned payload's domain_id/workspace_id sourced from the persisted row
//      rather than from the caller's request.
//
// Only a persisted 'verified' with a non-null verified_at may be reported —
// the same two fields the frontend trust contract and the scan gate require.
// Fails closed on any error: an unconfirmable write is never a verification.
export async function persistVerification(env, workspaceId, domainId, method) {
  const result = {
    ok: false,
    outcome: VERIFICATION_OUTCOMES.PERSISTENCE_CONFIRMATION_FAILED,
    affected_row_count: 0,
    persisted_status: null,
    persisted_verified_at: null,
    persisted_workspace_id: null,
    persisted_domain_id: null,
  };
  if (!workspaceId || !domainId) return result;

  try {
    const upd = await env.cybermeters_db
      .prepare(`UPDATE workspace_domains
                   SET verification_status = 'verified',
                       verification_method = ?,
                       verified_at = datetime('now')
                 WHERE workspace_id = ? AND domain_id = ?`)
      .bind(method, workspaceId, domainId)
      .run();
    result.affected_row_count = upd?.meta?.changes ?? 0;

    if (result.affected_row_count === 0) {
      result.outcome = VERIFICATION_OUTCOMES.PERSISTENCE_ZERO_ROWS;
      return result;
    }
    if (result.affected_row_count > 1) {
      // Do NOT attempt a repair here: the rows are already written and guessing
      // which to revert could destroy a legitimate verification. Surface it.
      result.outcome = VERIFICATION_OUTCOMES.PERSISTENCE_UNEXPECTED_ROWS;
      return result;
    }

    // Independent re-read — never trust the statement's own account of itself.
    const row = await env.cybermeters_db
      .prepare(`SELECT workspace_id, domain_id, verification_status, verified_at
                  FROM workspace_domains
                 WHERE workspace_id = ? AND domain_id = ?`)
      .bind(workspaceId, domainId)
      .first();
    result.persisted_status       = row?.verification_status ?? null;
    result.persisted_verified_at  = row?.verified_at ?? null;
    result.persisted_workspace_id = row?.workspace_id ?? null;
    result.persisted_domain_id    = row?.domain_id ?? null;

    const confirmed = row?.verification_status === "verified"
      && Boolean(row?.verified_at)
      && row?.workspace_id === workspaceId
      && row?.domain_id === domainId;

    if (!confirmed) {
      result.outcome = VERIFICATION_OUTCOMES.PERSISTENCE_CONFIRMATION_FAILED;
      return result;
    }

    result.ok = true;
    result.outcome = null; // caller supplies the method-specific verified outcome
    return result;
  } catch {
    // Unreadable / unwritable link. We cannot confirm, so we do not claim.
    result.ok = false;
    result.outcome = VERIFICATION_OUTCOMES.PERSISTENCE_CONFIRMATION_FAILED;
    return result;
  }
}

// Deterministic, workspace-explicit resolution for POST /api/domains/:id/verification
// and /verify. Prefers an explicit workspace_id; otherwise auto-resolves ONLY when the
// caller holds domain:verify on exactly one workspace linked to the domain (the
// single-workspace onboarding case). Ambiguous (multiple) → the caller must specify,
// so the verified relationship is never guessed. A denied/absent workspace returns the
// SAME 404 as a nonexistent domain (closes the cross-tenant existence oracle).
// Returns { workspace_id } on success, or { error, status[, code] } to return as-is.
export async function resolveVerificationWorkspace(user, domainId, explicitWorkspaceId, requireWorkspaceRole, env) {
  if (explicitWorkspaceId) {
    const link = await env.cybermeters_db
      .prepare("SELECT 1 AS ok FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?")
      .bind(explicitWorkspaceId, domainId).first().catch(() => null);
    if (!link) return { error: "Domain not found", status: 404 };
    const access = await requireWorkspaceRole(user, explicitWorkspaceId, "domain:verify", env);
    if (!access) return { error: "Domain not found", status: 404 };
    return { workspace_id: explicitWorkspaceId };
  }

  let rows;
  try {
    rows = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId).all();
  } catch {
    return { error: "Domain not found", status: 404 };
  }
  const candidates = [];
  for (const { workspace_id } of (rows.results || [])) {
    const access = await requireWorkspaceRole(user, workspace_id, "domain:verify", env);
    if (access) candidates.push(workspace_id);
  }
  if (candidates.length === 0) return { error: "Domain not found", status: 404 };
  if (candidates.length > 1) {
    return { error: "workspace_id is required — this domain is linked to multiple workspaces.", code: "workspace_id_required", status: 400 };
  }
  return { workspace_id: candidates[0] };
}
