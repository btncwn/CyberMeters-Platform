// ── Certificates Managed Lifecycle ──────────────────────────────────────────
// Turns externally-observed certificates into a canonical, workspace-scoped
// MANAGED LIFECYCLE: observe → correlate identity → assess expiry/coverage →
// determine renewal readiness → assign ownership → plan renewal → record
// replacement → verify replacement externally → monitor → reopen on
// recurrence/failure/material change.
//
// EXTENDS the existing certificate-observation architecture — it does NOT add a
// second certificate scanner or a duplicate source of truth. The split is:
//   certificate_observations (mig 031) → raw externally-observed evidence + history
//   certificate_lifecycle    (mig 085) → ownership, planning, renewal, verification
// The raw store is referenced (current/previous observation ids), never copied,
// and a replacement never overwrites the old certificate's evidence.
//
// Honesty (permanent). External observation only: no live TLS handshake, no
// chain/root/OCSP/revocation, no private-key possession, no real X.509
// fingerprint or serial (they stay unknown). An unexpired certificate is NOT
// "fully trusted". A customer-asserted "renewed" is NOT externally verified —
// verification requires a NEW distinct certificate observed on the expected
// hostname(s), with acceptable coverage and a later expiry. Incomplete coverage
// cannot verify. Follow-up uses the Universal Managed-Case Model
// (certificate_case → cert.* canonical remediation).

import { emitLifecycleAlert } from "./alert-consumers.js";
import { createManagedCase, canTransitionCase, canonicalPhaseFor } from "./managed-case-model.js";
import { newCaseEventId } from "./case-workflow.js";
import { assessRenewal, renewalRequiresCase } from "./certificate-policy.js";
import { buildMonitoringTransitionDetail, isMonitoringTransition } from "./alert-occurrence.js";

function newId(prefix) {
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return `${prefix}-${(uuid || "").slice(0, 12).padEnd(12, "0")}`;
}
function parseJson(v, fallback = null) { try { return v ? JSON.parse(v) : fallback; } catch { return fallback; } }
function safeJson(v, fallback = null) { try { return v == null ? fallback : JSON.stringify(v); } catch { return fallback; } }
function lc(s) { return String(s || "").trim().toLowerCase(); }

// ── Coverage model ──────────────────────────────────────────────────────────
// Expected (customer-declared) hostnames vs observed SANs, kept SEPARATE. A
// wildcard SAN (*.example.com) matches a single-label subdomain of its parent
// only — it is NOT auto-treated as covering the apex or arbitrary depth, and it
// never makes coverage "complete" for hostnames the customer did not declare.
export const COVERAGE_STATUSES = Object.freeze(["complete", "partial", "missing", "unexpected", "unknown"]);

function wildcardCovers(wildcard, host) {
  const w = lc(wildcard);
  if (!w.startsWith("*.")) return false;
  const parent = w.slice(2);
  const h = lc(host);
  if (h === parent || !h.endsWith(`.${parent}`)) return false;
  // Exactly one extra label (wildcards match a single level, not nested depth).
  const label = h.slice(0, h.length - parent.length - 1);
  return label.length > 0 && !label.includes(".");
}
function sanCoversHost(observedSans, host) {
  const h = lc(host);
  for (const s of observedSans) {
    if (lc(s) === h) return true;
    if (wildcardCovers(s, h)) return true;
  }
  return false;
}

// Deterministic coverage assessment. No expected hostnames declared → "unknown"
// (the product does not assert coverage it cannot judge).
export function computeCoverage(expectedHostnames = [], observedSans = []) {
  const expected = [...new Set((expectedHostnames || []).map(lc).filter(Boolean))];
  const observed = [...new Set((observedSans || []).map(lc).filter(Boolean))];
  if (expected.length === 0) {
    return { status: "unknown", covered: [], missing: [], unexpected: observed, wildcard_present: observed.some((s) => s.startsWith("*.")) };
  }
  const covered = [], missing = [];
  for (const h of expected) (sanCoversHost(observed, h) ? covered : missing).push(h);
  // Unexpected = an observed non-wildcard SAN that is not an expected hostname
  // and is not itself covering an expected one via wildcard.
  const unexpected = observed.filter((s) => {
    if (s.startsWith("*.")) return !expected.some((h) => wildcardCovers(s, h));
    return !expected.includes(s);
  });
  let status;
  if (missing.length) status = covered.length ? "partial" : "missing";
  else if (unexpected.length) status = "unexpected";
  else status = "complete";
  return { status, covered, missing, unexpected, wildcard_present: observed.some((s) => s.startsWith("*.")) };
}
// Coverage strong enough to VERIFY a replacement: every declared hostname is
// covered (unexpected SANs are a flag, not a coverage failure). "unknown"
// (nothing declared) cannot verify.
function coverageAcceptable(status) { return status === "complete" || status === "unexpected"; }

// ── Ownership ───────────────────────────────────────────────────────────────
export const CERT_OWNERSHIP_STATUSES = Object.freeze(["known", "partial", "missing"]);
export function deriveCertOwnershipStatus(business, technical, renewal) {
  const owners = [business, technical, renewal].map((o) => String(o || "").trim()).filter(Boolean);
  if (business && technical) return "known";
  if (owners.length) return "partial";
  return "missing";
}

// ── Event / state vocab ─────────────────────────────────────────────────────
export const CERT_LIFECYCLE_STATES = Object.freeze([
  "observed", "review_required", "owner_missing", "renewal_planned", "renewal_in_progress",
  "awaiting_replacement", "awaiting_verification", "verified_replaced", "monitoring",
  "expired", "renewal_overdue", "exception", "retired", "reopened",
]);
export const CERT_EVENT_TYPES = Object.freeze([
  "observed", "replacement_detected", "coverage_changed", "owner_assigned", "owner_missing",
  "renewal_planned", "renewal_started", "replacement_expected", "replacement_recorded",
  "verification_requested", "verified_replaced", "verification_failed", "exception_set",
  "exception_cleared", "retired", "reopened", "monitoring_changed", "case_linked",
]);

async function appendEvent(env, rec, { actor_type = "system", actor_id = null, event_type, detail = null }) {
  await env.cybermeters_db
    .prepare(`INSERT INTO certificate_lifecycle_events
      (id, lifecycle_id, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .bind(newId("cle"), rec.id, rec.workspace_id, actor_type, actor_id, event_type, safeJson(detail))
    .run();
}

// Derive the machine-stable overall lifecycle_state from the sub-states. Renewal
// planning, verification and monitoring are DISTINCT fields; this is the single
// customer-facing rollup.
function deriveLifecycleState(rec) {
  if (rec.renewal_status === "retired") return "retired";
  if (rec.exception_until && rec.exception_until > (rec._now || "")) return "exception";
  if (rec.verification_status === "verified_replaced") return "verified_replaced";
  if (rec.renewal_readiness === "expired") return "expired";
  if (rec.recurrence_type && rec.recurrence_type !== "none" && rec.monitoring_status !== "no_longer_observed") {
    if (rec.recurrence_type === "renewal_overdue") return "renewal_overdue";
    if (rec.recurrence_type === "owner_missing") return "owner_missing";
    return "review_required";
  }
  if (rec.renewal_status === "awaiting_verification") return "awaiting_verification";
  if (rec.renewal_status === "awaiting_replacement") return "awaiting_replacement";
  if (rec.renewal_status === "in_progress") return "renewal_in_progress";
  if (rec.renewal_status === "planned") return "renewal_planned";
  if (rec.monitoring_status === "reappeared") return "reopened";
  return "observed";
}

// ── Correlation / upsert ────────────────────────────────────────────────────
// Read the workspace's raw certificate_observations, pick the CURRENT certificate
// per monitored domain, and upsert one lifecycle record per host. Observation
// fields (identity/issuer/expiry/SANs) refresh; ownership/planning/verification
// persist. Replacement = a new certificate_identity → previous observation
// preserved, new one becomes current. Soft-deleted workspaces are skipped.
export async function correlateCertificateLifecycle(env, workspaceId, { now = new Date().toISOString() } = {}) {
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(workspaceId).first().catch(() => null);
  if (!ws) return { correlated: 0, created: 0, replaced: 0, skipped: "workspace_inactive" };

  // Group raw observations by domain; join the domain hostname for primary_hostname.
  const rows = (await env.cybermeters_db
    .prepare(`SELECT o.id, o.domain_id, o.certificate_key, o.subject, o.issuer, o.san_count,
                     o.expires_at, o.first_seen, o.last_seen, o.evidence_json, d.domain AS hostname
              FROM certificate_observations o
              JOIN domains d ON d.id = o.domain_id
              WHERE o.workspace_id = ?`)
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];

  const byDomain = new Map();
  for (const r of rows) {
    if (!byDomain.has(r.domain_id)) byDomain.set(r.domain_id, []);
    byDomain.get(r.domain_id).push(r);
  }

  let created = 0, replaced = 0;
  const seenIds = new Set();
  for (const [domainId, obs] of byDomain) {
    // Current certificate = furthest-future expiry (matches the observation
    // engine's own "best cert" selection); ties break on most-recent last_seen.
    obs.sort((a, b) => (String(b.expires_at || "") .localeCompare(String(a.expires_at || ""))) || (String(b.last_seen || "").localeCompare(String(a.last_seen || ""))));
    const current = obs[0];
    const primaryHostname = current.hostname || current.subject || domainId;
    const observedSans = parseJson(current.evidence_json, {})?.san_hostnames || [];
    const renewal = assessRenewal(current.expires_at, now);
    const firstSeen = obs.reduce((min, o) => (o.first_seen && (!min || o.first_seen < min) ? o.first_seen : min), null) || now;

    const existing = await env.cybermeters_db
      .prepare(`SELECT * FROM certificate_lifecycle WHERE workspace_id = ? AND domain_id = ? AND primary_hostname = ?`)
      .bind(workspaceId, domainId, primaryHostname).first().catch(() => null);

    if (!existing) {
      const id = newId("cl");
      const coverage = computeCoverage([], observedSans); // no expected declared yet → "unknown"
      const rec = { id, workspace_id: workspaceId };
      await env.cybermeters_db
        .prepare(`INSERT INTO certificate_lifecycle
          (id, workspace_id, domain_id, primary_hostname, certificate_identity, fingerprint_sha256, serial_number,
           current_certificate_observation_id, previous_certificate_observation_id, issuer, not_before, not_after,
           days_remaining, expected_hostnames_json, observed_sans_json, coverage_status, coverage_detail_json,
           ownership_status, renewal_status, renewal_readiness, renewal_due_at, renewal_start_by,
           monitoring_status, lifecycle_state, first_seen_at, last_seen_at, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, NULL, NULL, ?, NULL, ?, NULL, ?, ?, '[]', ?, ?, ?, 'missing', 'not_started', ?, ?, ?, 'observed', 'observed', ?, ?, ?, ?)`)
        .bind(id, workspaceId, domainId, primaryHostname, current.certificate_key, current.id, current.issuer,
          current.expires_at, renewal.days_remaining, safeJson(observedSans, "[]"), coverage.status, safeJson(coverage),
          renewal.readiness, current.expires_at, renewal.renewal_start_by, firstSeen, current.last_seen || now, now, now)
        .run();
      await appendEvent(env, rec, { event_type: "observed", detail: { created: true, issuer: current.issuer, days_remaining: renewal.days_remaining, readiness: renewal.readiness } });
      created++;
      continue;
    }

    // Replacement detection — a NEW certificate identity for this host. The old
    // observation is PRESERVED (previous_certificate_observation_id); its evidence
    // is never overwritten.
    const identityChanged = existing.certificate_identity && existing.certificate_identity !== current.certificate_key;
    const expectedHosts = parseJson(existing.expected_hostnames_json, []) || [];
    const coverage = computeCoverage(expectedHosts, observedSans);
    const coverageChanged = existing.coverage_status !== coverage.status;
    const set = {
      certificate_identity: current.certificate_key,
      current_certificate_observation_id: current.id,
      issuer: current.issuer,
      not_after: current.expires_at,
      days_remaining: renewal.days_remaining,
      renewal_readiness: renewal.readiness,
      renewal_due_at: current.expires_at,
      renewal_start_by: renewal.renewal_start_by,
      observed_sans_json: safeJson(observedSans, "[]"),
      coverage_status: coverage.status,
      coverage_detail_json: safeJson(coverage),
      last_seen_at: current.last_seen || now,
      monitoring_status: existing.monitoring_status === "no_longer_observed" ? "reappeared" : "observed",
      updated_at: now,
    };
    if (identityChanged) {
      set.previous_certificate_observation_id = existing.current_certificate_observation_id || null;
      set.replacement_detected_at = now;
      replaced++;
    }
    const cols = Object.keys(set);
    await env.cybermeters_db
      .prepare(`UPDATE certificate_lifecycle SET ${cols.map((c) => `${c} = ?`).join(", ")} WHERE id = ? AND workspace_id = ?`)
      .bind(...cols.map((c) => set[c]), existing.id, workspaceId).run();
    if (identityChanged) await appendEvent(env, existing, { event_type: "replacement_detected", detail: { previous_identity: existing.certificate_identity, new_identity: current.certificate_key, previous_not_after: existing.not_after, new_not_after: current.expires_at } });
    if (coverageChanged) await appendEvent(env, existing, { event_type: "coverage_changed", detail: { from: existing.coverage_status, to: coverage.status, missing: coverage.missing, unexpected: coverage.unexpected } });
    seenIds.add(existing.id);
  }

  const monitoring = await evaluateCertificateLifecycleMonitoring(env, workspaceId, { now });
  return { correlated: byDomain.size, created, replaced, monitoring };
}

// ── Verification contract (external-observation only) ───────────────────────
// A customer "renewed" is never enough. A positive verification requires the
// CURRENT observed certificate to be a genuine, distinct replacement:
//   * a NEW certificate identity (differs from the previous cert), AND
//   * served on the expected hostname(s) — coverage acceptable, AND
//   * expiry moved forward (new not_after later than the previous), AND
//   * not otherwise failed/inconclusive.
// Incomplete coverage or no distinct new cert → inconclusive (blocks). Expiry
// not advanced → failed. Returns a STRUCTURED evidence record either way.
export function buildVerificationEvidence(rec, { current, previous, coverage, now = new Date().toISOString() }) {
  const previous_identity = previous?.certificate_key || rec.previous_identity || null;
  const new_identity = current?.certificate_key || rec.certificate_identity || null;
  const previous_not_after = previous?.expires_at || rec.previous_not_after || null;
  const new_not_after = current?.expires_at || rec.not_after || null;
  const distinct = Boolean(new_identity && previous_identity && new_identity !== previous_identity);
  const forward = Boolean(new_not_after && previous_not_after && Date.parse(new_not_after) > Date.parse(previous_not_after));
  const cov = coverage?.status || rec.coverage_status || "unknown";
  const coverageOk = coverageAcceptable(cov);

  let verification_result;
  if (!distinct) verification_result = "inconclusive";        // no genuinely new certificate observed
  else if (!coverageOk) verification_result = "inconclusive";  // incomplete coverage cannot verify
  else if (!forward) verification_result = "failed";           // new cert but expiry not advanced
  else verification_result = "verified";

  return {
    verification_method: "external_observation",
    verification_result,
    evidence_type: "certificate_observation",
    observed_at: now,
    previous_identity, new_identity, previous_not_after, new_not_after,
    distinct_certificate: distinct, expiry_advanced: forward,
    coverage_status: cov, coverage_result: coverageOk ? "acceptable" : "insufficient",
    expected_hostnames: parseJson(rec.expected_hostnames_json, []) || [],
    observed_sans: parseJson(rec.observed_sans_json, []) || [],
    issuer: rec.issuer || null,
    // Permanent honesty: chain/root/OCSP/revocation/private-key are NOT part of
    // this evidence and remain unknown (no live TLS).
    unknown_signals: ["chain_valid", "root_trusted", "ocsp", "revocation", "private_key_possession", "x509_fingerprint", "serial_number"],
  };
}

// ── Monitoring evaluator ────────────────────────────────────────────────────
// ONE deterministic pass. Explicit precedence; disappearance is never verified
// removal; an unexpired-but-unowned certificate is a monitoring observation, not
// an alarm. Persists the evaluator snapshot and, where follow-up is due, opens
// or REOPENS the certificate_case through the universal validator.
export const CERT_STALE_EVIDENCE_DAYS = 45;
export const AWAITING_VERIFICATION_STALE_DAYS = 21;

function daysBetween(from, to) {
  const d = (Date.parse(to) - Date.parse(from)) / 86400000;
  return Number.isFinite(d) ? Math.max(0, Math.floor(d)) : null;
}

// recurrence → { finding_type (for canonical remediation), case_action }
const RECURRENCE_CASE = {
  expired:              { finding_type: "certificate_expired",       action: "open_or_reopen" },
  renewal_overdue:      { finding_type: "certificate_expiring_soon", action: "open_or_reopen" },
  coverage_regression:  { finding_type: "coverage_gap",              action: "open_or_reopen" },
  unexpected_san:       { finding_type: "unexpected_san",            action: "open_or_reopen" },
  new_issuer:           { finding_type: "unexpected_issuer",         action: "open_or_reopen" },
  replacement_unverified:{ finding_type: "certificate_expiring_soon",action: "verify_replacement" },
  verification_failed:  { finding_type: "certificate_expiring_soon", action: "open_or_reopen" },
  replacement_contradicted:{ finding_type: "certificate_expiring_soon", action: "open_or_reopen" },
  exception_expired:    { finding_type: "certificate_expiring_soon", action: "open_or_reopen" },
  owner_missing:        { finding_type: "certificate_expiring_soon", action: "assign_owner" },
};

export async function evaluateCertificateLifecycleMonitoring(env, workspaceId, { now = new Date().toISOString() } = {}) {
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`).bind(workspaceId).first().catch(() => null);
  if (!ws) return { evaluated: 0, skipped: "workspace_inactive" };

  const recs = (await env.cybermeters_db
    .prepare(`SELECT * FROM certificate_lifecycle WHERE workspace_id = ?`).bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];
  let cases = 0, expiredCount = 0;

  for (const rec of recs) {
    const renewal = assessRenewal(rec.not_after, now);
    const ownership_status = deriveCertOwnershipStatus(rec.business_owner, rec.technical_owner, rec.renewal_owner);
    const evidence_age_days = daysBetween(rec.last_seen_at, now);
    const coverage = parseJson(rec.coverage_detail_json, {}) || {};
    const material_change = rec.replacement_detected_at ? (daysBetween(rec.replacement_detected_at, now) <= 30 ? 1 : 0) : 0;
    const inExceptionWindow = rec.exception_until && rec.exception_until > now;
    const verified = rec.verification_status === "verified_replaced";

    // Deterministic precedence.
    let recurrence_type = "none", monitoring_reason = null, risk_status = renewal.risk_status, required_case_action = "none";
    if (inExceptionWindow) {
      recurrence_type = "none"; monitoring_reason = "under_exception"; risk_status = "ok";
    } else if (rec.exception_until && rec.exception_until <= now && rec.renewal_status === "exception") {
      recurrence_type = "exception_expired"; monitoring_reason = "exception_window_expired"; required_case_action = "open_or_reopen";
    } else if (renewal.expired && !verified) {
      recurrence_type = "expired"; monitoring_reason = "certificate_expired"; risk_status = "expired"; required_case_action = "open_or_reopen"; expiredCount++;
    } else if (rec.renewal_status === "awaiting_verification" && rec.replacement_recorded_at && !rec.replacement_detected_at) {
      // Customer asserted completion but NO distinct new certificate observed.
      recurrence_type = "replacement_contradicted"; monitoring_reason = "recorded_replacement_not_observed"; required_case_action = "open_or_reopen";
    } else if (rec.verification_status === "failed") {
      recurrence_type = "verification_failed"; monitoring_reason = "replacement_verification_failed"; required_case_action = "open_or_reopen";
    } else if (rec.renewal_status === "awaiting_verification" && rec.replacement_detected_at && !verified) {
      recurrence_type = "replacement_unverified"; monitoring_reason = "new_certificate_awaiting_verification"; required_case_action = "verify_replacement";
    } else if (renewalRequiresCase(renewal.readiness) && !verified) {
      recurrence_type = "renewal_overdue"; monitoring_reason = "renewal_window_critical"; required_case_action = "open_or_reopen";
    } else if (coverage.status === "missing" || coverage.status === "partial") {
      recurrence_type = "coverage_regression"; monitoring_reason = "expected_hostnames_not_covered"; required_case_action = "open_or_reopen";
    } else if (coverage.status === "unexpected" && (coverage.unexpected || []).length) {
      recurrence_type = "unexpected_san"; monitoring_reason = "unexpected_san_observed"; required_case_action = "open_or_reopen";
    } else if (ownership_status === "missing" && (renewal.readiness === "preparation" || renewal.readiness === "high" || renewal.readiness === "critical")) {
      recurrence_type = "owner_missing"; monitoring_reason = "no_owner_on_at_risk_certificate"; required_case_action = "assign_owner";
    } else if (evidence_age_days != null && evidence_age_days > CERT_STALE_EVIDENCE_DAYS) {
      recurrence_type = "evidence_stale"; monitoring_reason = "certificate_evidence_stale"; required_case_action = "none";
    }

    const merged = {
      ...rec, _now: now, renewal_readiness: renewal.readiness, days_remaining: renewal.days_remaining,
      ownership_status, recurrence_type, monitoring_status: rec.monitoring_status,
    };
    const lifecycle_state = deriveLifecycleState(merged);

    // Owner-missing transition event.
    if (ownership_status === "missing" && rec.ownership_status && rec.ownership_status !== "missing") {
      await appendEvent(env, rec, { event_type: "owner_missing", detail: { readiness: renewal.readiness } });
    }

    // ── Monitoring transition (append-only) ──────────────────────────────────
    // Certificates was the one managed domain that persisted its monitoring
    // decision without ever RECORDING the transition, so there was no stable
    // answer to "when did this condition begin?" — only evaluated_at, which moves
    // every hour. This appends that missing history.
    //
    // Only a real CHANGE is recorded: re-observing the same condition on the next
    // hourly pass is not a new occurrence, and appending one would mint a fresh
    // occurrence id and re-alert the same unchanged certificate every hour.
    //
    // The detail carries enough structured state for a consumer to match the
    // current condition deterministically (see findConditionOccurrence).
    const nextMonitoring = { monitoring_status: rec.monitoring_status, recurrence_type: recurrence_type === "none" ? null : recurrence_type };
    if (isMonitoringTransition({ monitoring_status: rec.monitoring_status, recurrence_type: rec.recurrence_type }, nextMonitoring)) {
      await appendEvent(env, rec, {
        event_type: "monitoring_changed",
        detail: buildMonitoringTransitionDetail({
          from_monitoring_status: rec.monitoring_status ?? null,
          to_monitoring_status: nextMonitoring.monitoring_status ?? null,
          from_recurrence_type: rec.recurrence_type ?? null,
          to_recurrence_type: nextMonitoring.recurrence_type,
          required_case_action,
          reason: monitoring_reason,
          entity: rec.primary_hostname,
        }),
      }).catch(() => { /* history is best-effort; it must not break the evaluator */ });
    }

    await env.cybermeters_db
      .prepare(`UPDATE certificate_lifecycle SET days_remaining = ?, renewal_readiness = ?, renewal_start_by = ?,
                  ownership_status = ?, risk_status = ?, recurrence_type = ?, monitoring_reason = ?,
                  required_case_action = ?, material_change = ?, evidence_age_days = ?, lifecycle_state = ?,
                  evaluated_at = ?, updated_at = ? WHERE id = ? AND workspace_id = ?`)
      .bind(renewal.days_remaining, renewal.readiness, renewal.renewal_start_by, ownership_status, risk_status,
        recurrence_type === "none" ? null : recurrence_type, monitoring_reason,
        required_case_action, material_change, evidence_age_days, lifecycle_state, now, now, rec.id, workspaceId)
      .run();

    if (required_case_action !== "none") {
      const acted = await openOrReopenCertificateCase(env, { ...rec, ownership_status, days_remaining: renewal.days_remaining }, { recurrence: recurrence_type, action: required_case_action, now });
      // Tell the customer — through the ONE canonical pipeline, from the same
      // deterministic decision that just opened/reopened the case. Detection is not
      // repeated here. The condition-start and occurrence identity come from the
      // append-only monitoring_changed event, so hourly re-evaluation of the same
      // occurrence dedupes and pre-existing state stays silent. Never sends directly.
      await emitLifecycleAlert(env, {
        workspace_id: workspaceId, domain_key: "certificates_trust",
        record_id: rec.id, entity: rec.primary_hostname, hostname: rec.primary_hostname,
        recurrence: recurrence_type,
        finding_type: (RECURRENCE_CASE[recurrence_type] || {}).finding_type || null,
        case_id: rec.linked_case_id || null,
      }).catch(() => { /* alerting must never break the evaluator */ });
      if (acted?.ok) cases++;
    }
  }
  return { evaluated: recs.length, cases, expired: expiredCount };
}

// Open a new certificate_case OR reopen/update the EXISTING linked case through
// the universal transition validator (never a separate table, never a bare dedup
// return). A resolved/monitoring case is reopened via canTransitionCase.
export async function openOrReopenCertificateCase(env, rec, { recurrence, action, now = new Date().toISOString() } = {}) {
  const cfg = RECURRENCE_CASE[recurrence] || { finding_type: "certificate_expiring_soon" };
  if (!rec.linked_case_id) {
    return linkCertificateCase(env, rec, {
      actor: { actor_type: "system", actor_id: null }, finding_type: cfg.finding_type,
      title: `Certificate follow-up: ${rec.primary_hostname} (${String(recurrence || "review").replace(/_/g, " ")})`,
      summary: `Managed certificate for ${rec.primary_hostname} needs attention: ${String(recurrence || "review").replace(/_/g, " ")}.`,
    });
  }
  const kase = await env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases WHERE id = ? AND workspace_id = ?`).bind(rec.linked_case_id, rec.workspace_id).first().catch(() => null);
  if (!kase) {
    await env.cybermeters_db.prepare(`UPDATE certificate_lifecycle SET linked_case_id = NULL WHERE id = ? AND workspace_id = ?`).bind(rec.id, rec.workspace_id).run();
    return linkCertificateCase(env, rec, { actor: { actor_type: "system", actor_id: null }, finding_type: cfg.finding_type, title: `Certificate follow-up: ${rec.primary_hostname}`, summary: `Recurrence: ${recurrence}.` });
  }
  const phase = canonicalPhaseFor(kase.case_type, kase.status);
  if (phase === "verified" || phase === "monitoring") {
    const decision = canTransitionCase({ case: kase, target_status: "reopened", actor: { actor_type: "system", actor_id: null }, reason: recurrence, now });
    if (decision.ok) {
      const n = decision.case;
      await env.cybermeters_db
        .prepare(`UPDATE managed_cases SET status = ?, reopened_at = ?, reopened_count = ?, updated_at = ? WHERE id = ? AND workspace_id = ?`)
        .bind(n.status, n.reopened_at || now, Number(n.reopened_count || 0), n.updated_at, kase.id, kase.workspace_id).run();
      await env.cybermeters_db
        .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
                  VALUES (?, ?, ?, 'system', NULL, ?, ?, ?, ?, datetime('now'))`)
        .bind(newCaseEventId(), kase.id, kase.workspace_id, kase.status, n.status, decision.event.action, safeJson({ recurrence, lifecycle: rec.id })).run();
      await appendEvent(env, rec, { event_type: "reopened", detail: { case_id: kase.id, recurrence } });
      return { ok: true, reopened: true };
    }
  }
  // Active case → append a recurrence event (update, not a bare dedup return).
  await env.cybermeters_db
    .prepare(`INSERT INTO managed_case_events (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
              VALUES (?, ?, ?, 'system', NULL, ?, ?, 'certificate_recurrence', ?, datetime('now'))`)
    .bind(newCaseEventId(), kase.id, kase.workspace_id, kase.status, kase.status, safeJson({ recurrence, lifecycle: rec.id })).run();
  await appendEvent(env, rec, { event_type: "monitoring_changed", detail: { case_id: kase.id, recurrence, updated_case: true } });
  return { ok: true, updated: true };
}

async function linkCertificateCase(env, rec, { actor, finding_type, title, summary } = {}) {
  const result = await createManagedCase(env, {
    workspace_id: rec.workspace_id,
    domain_key: "certificates_trust",
    case_type: "certificate_case",
    source_finding_type: finding_type || "certificate_expiring_soon",
    source_finding_id: `certificate:${rec.primary_hostname}`,
    title: title || `Certificate follow-up: ${rec.primary_hostname}`,
    summary: summary || null,
    severity: "medium",
    actor: actor || { actor_type: "system", actor_id: null },
  });
  if (!result.ok) return result;
  await env.cybermeters_db
    .prepare(`UPDATE certificate_lifecycle SET linked_case_id = ?, updated_at = datetime('now') WHERE id = ? AND workspace_id = ?`)
    .bind(result.case.id, rec.id, rec.workspace_id).run();
  await appendEvent(env, rec, { actor_type: actor?.actor_type || "system", actor_id: actor?.actor_id || null, event_type: "case_linked", detail: { case_id: result.case.id, remediation_id: result.case.remediation_id } });
  return { ok: true, case: result.case };
}

// ── Workflow service ────────────────────────────────────────────────────────
// The customer actions. Every action is workspace-scoped and audit-logged
// (append-only event). Ownership assignment and renewal PLANNING are customer
// decisions; recording a completed replacement is a customer ASSERTION, never
// product-verified — verification only comes from a distinct new observed cert.
export const CERT_WORKFLOW_ACTIONS = Object.freeze([
  "assign_business_owner", "assign_technical_owner", "assign_renewal_owner",
  "set_expected_hostnames", "plan_renewal", "begin_renewal", "record_provider",
  "record_replacement_expected", "record_replacement_completed", "request_verification",
  "record_exception", "clear_exception", "retire", "reopen",
]);

async function loadRecord(env, workspaceId, id) {
  return env.cybermeters_db
    .prepare(`SELECT * FROM certificate_lifecycle WHERE id = ? AND workspace_id = ?`)
    .bind(id, workspaceId).first().catch(() => null);
}

export async function certificateLifecycleAction(env, workspaceId, id, action, opts = {}) {
  if (!CERT_WORKFLOW_ACTIONS.includes(action)) return { ok: false, code: "invalid_action" };
  const rec = await loadRecord(env, workspaceId, id);
  if (!rec) return { ok: false, code: "not_found" }; // same for foreign + nonexistent
  const actor = { actor_type: "customer", actor_id: opts.actor_id || null };
  const now = new Date().toISOString();
  const set = { updated_at: now };
  let eventType = "monitoring_changed", detail = { action };

  switch (action) {
    case "assign_business_owner":
      if (!String(opts.owner || "").trim()) return { ok: false, code: "owner_required" };
      set.business_owner = String(opts.owner).slice(0, 255);
      set.ownership_status = deriveCertOwnershipStatus(set.business_owner, rec.technical_owner, rec.renewal_owner);
      eventType = "owner_assigned"; detail = { role: "business", owner: set.business_owner, ownership_status: set.ownership_status };
      break;
    case "assign_technical_owner":
      if (!String(opts.owner || "").trim()) return { ok: false, code: "owner_required" };
      set.technical_owner = String(opts.owner).slice(0, 255);
      set.ownership_status = deriveCertOwnershipStatus(rec.business_owner, set.technical_owner, rec.renewal_owner);
      eventType = "owner_assigned"; detail = { role: "technical", owner: set.technical_owner, ownership_status: set.ownership_status };
      break;
    case "assign_renewal_owner":
      if (!String(opts.owner || "").trim()) return { ok: false, code: "owner_required" };
      set.renewal_owner = String(opts.owner).slice(0, 255);
      set.ownership_status = deriveCertOwnershipStatus(rec.business_owner, rec.technical_owner, set.renewal_owner);
      eventType = "owner_assigned"; detail = { role: "renewal", owner: set.renewal_owner, ownership_status: set.ownership_status };
      break;
    case "set_expected_hostnames": {
      const list = Array.isArray(opts.expected_hostnames) ? opts.expected_hostnames.map((h) => String(h || "").trim().toLowerCase()).filter(Boolean).slice(0, 200) : null;
      if (!list) return { ok: false, code: "hostnames_required" };
      const coverage = computeCoverage(list, parseJson(rec.observed_sans_json, []) || []);
      set.expected_hostnames_json = safeJson([...new Set(list)], "[]");
      set.coverage_status = coverage.status; set.coverage_detail_json = safeJson(coverage);
      eventType = "coverage_changed"; detail = { expected_count: list.length, coverage_status: coverage.status, missing: coverage.missing, unexpected: coverage.unexpected };
      break;
    }
    case "plan_renewal":
      set.renewal_status = "planned"; eventType = "renewal_planned"; detail = { renewal_status: "planned" };
      break;
    case "begin_renewal":
      set.renewal_status = "in_progress"; set.renewal_started_at = now; eventType = "renewal_started"; detail = { renewal_status: "in_progress" };
      break;
    case "record_provider":
      set.provider = String(opts.provider || "").slice(0, 255); eventType = "renewal_planned"; detail = { provider: set.provider };
      break;
    case "record_replacement_expected":
      if (!opts.replacement_expected_at || !Number.isFinite(Date.parse(opts.replacement_expected_at))) return { ok: false, code: "date_required" };
      set.replacement_expected_at = opts.replacement_expected_at; set.renewal_status = "awaiting_replacement";
      eventType = "replacement_expected"; detail = { replacement_expected_at: opts.replacement_expected_at };
      break;
    case "record_replacement_completed":
      // Customer ASSERTION — never product-verified. Moves to awaiting_verification;
      // verification only comes from a distinct new observed certificate.
      set.replacement_recorded_at = now; set.replacement_recorded_by = actor.actor_id;
      set.renewal_status = "awaiting_verification"; set.verification_status = "not_verified";
      eventType = "replacement_recorded"; detail = { note: "customer_asserted_not_verified" };
      break;
    case "request_verification": {
      // Attempt external verification from the current observed evidence.
      const current = rec.current_certificate_observation_id
        ? await env.cybermeters_db.prepare(`SELECT certificate_key, expires_at FROM certificate_observations WHERE id = ? AND workspace_id = ?`).bind(rec.current_certificate_observation_id, workspaceId).first().catch(() => null)
        : null;
      const previous = rec.previous_certificate_observation_id
        ? await env.cybermeters_db.prepare(`SELECT certificate_key, expires_at FROM certificate_observations WHERE id = ? AND workspace_id = ?`).bind(rec.previous_certificate_observation_id, workspaceId).first().catch(() => null)
        : null;
      const coverage = computeCoverage(parseJson(rec.expected_hostnames_json, []) || [], parseJson(rec.observed_sans_json, []) || []);
      const evidence = buildVerificationEvidence(rec, { current, previous, coverage, now });
      set.verification_detail_json = safeJson(evidence);
      set.verification_method = "external_observation";
      if (evidence.verification_result === "verified") {
        set.verification_status = "verified_replaced"; set.verified_at = now; set.renewal_status = "verified";
        eventType = "verified_replaced"; detail = evidence;
      } else if (evidence.verification_result === "failed") {
        set.verification_status = "failed"; eventType = "verification_failed"; detail = evidence;
      } else {
        set.verification_status = "inconclusive"; eventType = "verification_requested"; detail = evidence;
      }
      break;
    }
    case "record_exception":
      if (!String(opts.reason || "").trim()) return { ok: false, code: "reason_required" };
      if (!opts.exception_until || !Number.isFinite(Date.parse(opts.exception_until))) return { ok: false, code: "expiry_required" };
      set.exception_until = opts.exception_until; set.exception_reason = String(opts.reason).slice(0, 1000);
      set.renewal_status = "exception"; eventType = "exception_set"; detail = { exception_until: opts.exception_until };
      break;
    case "clear_exception":
      set.exception_until = null; set.exception_reason = null;
      if (rec.renewal_status === "exception") set.renewal_status = "not_started";
      eventType = "exception_cleared"; detail = {};
      break;
    case "retire":
      if (!String(opts.reason || "").trim()) return { ok: false, code: "reason_required" };
      set.renewal_status = "retired"; eventType = "retired"; detail = { reason: String(opts.reason).slice(0, 1000) };
      break;
    case "reopen":
      set.renewal_status = "not_started"; eventType = "reopened"; detail = {};
      break;
    default:
      return { ok: false, code: "invalid_action" };
  }

  const cols = Object.keys(set);
  await env.cybermeters_db
    .prepare(`UPDATE certificate_lifecycle SET ${cols.map((c) => `${c} = ?`).join(", ")} WHERE id = ? AND workspace_id = ?`)
    .bind(...cols.map((c) => set[c]), id, workspaceId).run();
  const updated = { ...rec, ...set };
  await appendEvent(env, updated, { actor_type: "customer", actor_id: actor.actor_id, event_type: eventType, detail });
  const fresh = await loadRecord(env, workspaceId, id);
  return { ok: true, item: certificateLifecycleToApi(fresh) };
}

// ── API serializer ──────────────────────────────────────────────────────────
export function certificateLifecycleToApi(row) {
  if (!row) return null;
  return {
    certificate_lifecycle_id: row.id,
    workspace_id: row.workspace_id,
    domain_id: row.domain_id,
    primary_hostname: row.primary_hostname,
    certificate_identity: row.certificate_identity || null,
    // Honest: real cryptographic identity is not captured without live TLS.
    fingerprint_sha256: row.fingerprint_sha256 || null,
    serial_number: row.serial_number || null,
    fingerprint_note: "Real X.509 fingerprint and serial are not captured (no live TLS handshake); a stable surrogate identity is used for replacement detection.",
    current_certificate_observation_id: row.current_certificate_observation_id || null,
    previous_certificate_observation_id: row.previous_certificate_observation_id || null,
    issuer: row.issuer || null,
    not_before: row.not_before || null,
    not_after: row.not_after || null,
    days_remaining: row.days_remaining ?? null,
    renewal_readiness: row.renewal_readiness,
    renewal_status: row.renewal_status,
    renewal_due_at: row.renewal_due_at || null,
    renewal_start_by: row.renewal_start_by || null,
    renewal_started_at: row.renewal_started_at || null,
    replacement_expected_at: row.replacement_expected_at || null,
    replacement_detected_at: row.replacement_detected_at || null,
    replacement_recorded_at: row.replacement_recorded_at || null,
    provider: row.provider || null,
    expected_hostnames: parseJson(row.expected_hostnames_json, []) || [],
    observed_sans: parseJson(row.observed_sans_json, []) || [],
    coverage_status: row.coverage_status,
    coverage_detail: parseJson(row.coverage_detail_json, {}) || {},
    business_owner: row.business_owner || null,
    technical_owner: row.technical_owner || null,
    renewal_owner: row.renewal_owner || null,
    ownership_status: row.ownership_status || deriveCertOwnershipStatus(row.business_owner, row.technical_owner, row.renewal_owner),
    verification_status: row.verification_status,
    verification_method: row.verification_method || null,
    verified_at: row.verified_at || null,
    verification_detail: parseJson(row.verification_detail_json, null),
    monitoring_status: row.monitoring_status,
    monitoring_reason: row.monitoring_reason || null,
    risk_status: row.risk_status || null,
    recurrence_type: row.recurrence_type || null,
    required_case_action: row.required_case_action || null,
    material_change: Boolean(row.material_change),
    evidence_age_days: row.evidence_age_days ?? null,
    lifecycle_state: row.lifecycle_state,
    exception_until: row.exception_until || null,
    exception_reason: row.exception_reason || null,
    evaluated_at: row.evaluated_at || null,
    linked_case_id: row.linked_case_id || null,
    first_seen_at: row.first_seen_at,
    last_seen_at: row.last_seen_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
    // Permanent honest-scope reminder carried to the client.
    scope_note: "Externally observed certificate only — no live TLS, chain, root, OCSP, revocation or private-key check. Unexpired is not the same as fully trusted; a recorded renewal is not verified until a distinct new certificate is observed with acceptable coverage and a later expiry.",
  };
}

export async function listCertificateLifecycle(env, workspaceId, { renewal_readiness = null, lifecycle_state = null, coverage_status = null, limit = 100 } = {}) {
  const where = ["workspace_id = ?"]; const binds = [workspaceId];
  if (renewal_readiness) { where.push("renewal_readiness = ?"); binds.push(renewal_readiness); }
  if (lifecycle_state) { where.push("lifecycle_state = ?"); binds.push(lifecycle_state); }
  if (coverage_status) { where.push("coverage_status = ?"); binds.push(coverage_status); }
  const rows = (await env.cybermeters_db
    .prepare(`SELECT * FROM certificate_lifecycle WHERE ${where.join(" AND ")} ORDER BY (days_remaining IS NULL), days_remaining ASC, last_seen_at DESC LIMIT ?`)
    .bind(...binds, Math.max(1, Math.min(500, Number(limit) || 100))).all().catch(() => ({ results: [] }))).results || [];
  return rows.map(certificateLifecycleToApi);
}
export async function getCertificateLifecycle(env, workspaceId, id) {
  const row = await loadRecord(env, workspaceId, id);
  return row ? certificateLifecycleToApi(row) : null;
}
export async function listCertificateLifecycleEvents(env, workspaceId, id) {
  return (await env.cybermeters_db
    .prepare(`SELECT id, actor_type, actor_id, event_type, detail_json, created_at
              FROM certificate_lifecycle_events WHERE workspace_id = ? AND lifecycle_id = ? ORDER BY created_at ASC`)
    .bind(workspaceId, id).all().catch(() => ({ results: [] }))).results || [];
}
export async function countCertificateLifecycleByReadiness(env, workspaceId) {
  const rows = (await env.cybermeters_db
    .prepare(`SELECT renewal_readiness, COUNT(*) AS n FROM certificate_lifecycle WHERE workspace_id = ? GROUP BY renewal_readiness`)
    .bind(workspaceId).all().catch(() => ({ results: [] }))).results || [];
  const counts = {};
  for (const r of rows) counts[r.renewal_readiness] = r.n;
  return counts;
}
