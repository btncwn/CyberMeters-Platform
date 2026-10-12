// ── Certificate event insertion ──
// Persists certificate-observation + CA-vendor events to D1 for the certificate timeline.
// Extracted verbatim from index.js (monolith decomposition, Phase 1c).
// upsertCertificateAuthorityVendor is module-internal.
import { hashToken } from "../lib/auth-crypto.js";
import { createId } from "../lib/util.js";
import { buildCaConcentrationAnalytics, buildCertificateLifecycleIntelligence, detectSelfSignedCertificate, mapCertificateAuthorityOwner, normalizeCertificateAuthorityVendor, normalizeCertificateIssuer } from "./cert-analysis.js";
import { isCertSensitiveHost, runCertificateIntelligenceModule } from "./cert-intel.js";
import { loadTimelineComparisonContext } from "./timeline-trust.js";

// ── Certificate Event Insertion ──────────────────────────────────────────────
//
// Fires asset_events for certificate-level signals detected by
// runCertificateIntelligenceModule.  One event per signal type per scan.
// All errors are non-fatal.

// ── Standing-condition dedupe ────────────────────────────────────────────────
//
// Certificate expiry is a STANDING condition: while the certificate stays inside
// its expiry window, a naive producer re-fires an identical asset_event on every
// comparable scan. That is timeline noise, not a security event.
//
// The condition is reduced to a deterministic *signature* of its current state
// (null when the condition is absent). An event is emitted only when either:
//   • this workspace has never recorded that condition before (its own first
//     occurrence — preserves per-workspace fan-out for a late-joining
//     workspace), or
//   • the signature has genuinely transitioned since the previous COMPARABLE
//     scan (the previous scan's report, read structurally — never parsed from
//     prose).
//
// The signature is the severity band (<14d critical vs <30d medium) plus the
// certificate's expires_at, so entry into the window, a severity escalation, and
// a renewed-then-re-expiring certificate each emit, but the daily countdown does
// not.

export function certExpiringSoonSignature(certMod) {
  const days = certMod?.days_until_expiry;
  if (days == null || !(days < 30)) return null;
  const band = days < 14 ? "critical" : "medium";
  return `${band}|${certMod?.expires_at ?? ""}`;
}

/**
 * shouldEmitCertConditionEvent(currentSignature, previousSignature, hasPriorEvent)
 *
 * Deterministic emit decision for a standing certificate condition.
 *   currentSignature  — signature of the condition on THIS scan (null = absent).
 *   previousSignature — signature on the previous comparable scan (null = absent).
 *   hasPriorEvent     — whether THIS workspace already recorded this condition.
 *
 * Emits when the condition is present now AND (the workspace has no prior record
 * of it OR its signature has changed since the previous comparable scan).
 */
export function shouldEmitCertConditionEvent(currentSignature, previousSignature, hasPriorEvent) {
  if (currentSignature == null) return false;    // condition absent now → nothing to emit
  if (!hasPriorEvent) return true;               // per-workspace first occurrence
  return currentSignature !== previousSignature; // otherwise only on genuine transition
}

export async function certConditionEventId({ workspaceId, domainId, scanId, eventType, signature } = {}) {
  const digest = await hashToken(JSON.stringify([
    "cert-condition-event-v1",
    workspaceId ?? null,
    domainId ?? null,
    scanId ?? null,
    eventType ?? null,
    signature ?? null,
  ]));
  return `asev_${digest.slice(0, 32)}`;
}

async function loadActiveCertificateWorkspaces(env, domainId) {
  const result = await env.cybermeters_db
    .prepare(
      `SELECT wd.workspace_id
       FROM workspace_domains wd
       JOIN workspaces w ON w.id = wd.workspace_id
       WHERE wd.domain_id = ? AND w.deleted_at IS NULL`
    )
    .bind(domainId)
    .all();
  return result.results || [];
}

/**
 * insertCertificateEvents(scanId, domainId, certMod, env)
 *
 * Event type written:
 *   certificate_expiring_soon — the live certificate expires in < 30 days
 */
export async function insertCertificateEvents(scanId, domainId, certMod, env, opts = {}) {
  if (!certMod || certMod.error) return;
  const comparison = await loadTimelineComparisonContext(env, {
    scanId,
    domainId,
    currentReport: opts.currentReport,
  }).catch(() => ({ comparable: false }));
  if (!comparison.comparable) return;

  let wsRows;
  try {
    wsRows = await loadActiveCertificateWorkspaces(env, domainId);
  } catch {
    return;
  }
  if (wsRows.length === 0) return;

  const now = typeof opts.now === "function"
    ? new Date(opts.now()).toISOString()
    : new Date().toISOString();

  // Content baseline for standing-condition dedupe: the previous comparable
  // scan's certificate module, read structurally (never parsed from prose).
  const prevCertMod = comparison.previousReport?.modules?.certificate_intelligence ?? null;
  const expirySigCur     = certExpiringSoonSignature(certMod);
  const expirySigPrev    = certExpiringSoonSignature(prevCertMod);

  for (const { workspace_id } of wsRows) {
    // Whether this workspace has ALREADY recorded the condition for this domain
    // (per-workspace last-occurrence tracking; one bounded query).
    let priorTypes = new Set();
    try {
      const priorRows = await env.cybermeters_db
        .prepare(
          `SELECT DISTINCT event_type FROM asset_events
           WHERE workspace_id = ? AND domain_id = ?
             AND event_type = 'certificate_expiring_soon'`
        )
        .bind(workspace_id, domainId)
        .all();
      priorTypes = new Set((priorRows.results || []).map((row) => row.event_type));
    } catch { /* treat as no prior events → the condition surfaces once */ }

    // Certificate expiring soon
    const days = certMod.days_until_expiry;
    if (
      days !== null && days < 30 &&
      shouldEmitCertConditionEvent(expirySigCur, expirySigPrev, priorTypes.has("certificate_expiring_soon"))
    ) {
      try {
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO asset_events
               (id, workspace_id, domain_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, 'certificate_expiring_soon',
                     ?, ?, ?, ?)`
          )
          .bind(
            await certConditionEventId({
              workspaceId: workspace_id,
              domainId,
              scanId,
              eventType: "certificate_expiring_soon",
              signature: expirySigCur,
            }),
            workspace_id,
            domainId,
            scanId,
            null,
            days < 14 ? "critical" : "medium",
            `Certificate expires in ${days} day${days === 1 ? "" : "s"} (${certMod.expires_at}).`,
            now
          )
          .run();
      } catch { /* non-fatal */ }
    }
  }
}

/**
 * upsertCertificateObservation(scanId, domainId, certMod, env)
 *
 * Certificate Intelligence v2 persistence. Stores one cross-scan observation
 * per workspace/domain/certificate fingerprint surrogate and emits alerts for:
 *   certificate_new_detected
 *   certificate_new_san_detected
 *   certificate_new_issuer_detected
 *
 * All writes are non-fatal so an unapplied v2 migration cannot break scans.
 */
// A certificate identity exists only for a leaf the live TLS collector captured
// completely; anything else has no key and is never persisted.
export async function certificateObservationKey(certMod) {
  const leaf = certMod?.live_tls?.leaf_certificate;
  if (certMod?.evidence_source === 'live_tls' && certMod.live_certificate_verified === true && leaf?.collection_complete === true && /^sha256:[a-f0-9]{64}$/.test(leaf.certificate_identity || '')) {
    return hashToken(`live_tls|${leaf.certificate_identity}`);
  }
  return null;
}

export async function upsertCertificateObservation(scanId, domainId, certMod, env, opts = {}) {
  if (!certMod || certMod.error) return;
  // The table is certificate-identity history. Only a certificate the live TLS
  // collector captured is an identity; a scan that observed none must not create
  // an "unknown" pseudo-certificate, churn event or false healthy record.
  const certificateKey = await certificateObservationKey(certMod);
  if (!certificateKey) return;
  const signalCompleteness = certMod.signal_completeness;
  if (signalCompleteness?.signals) {
    const identitySignals = ["san", "issuer", "expiry"];
    const hasObservedCertificateIdentity = identitySignals.some(
      (signal) =>
        signalCompleteness.signals?.[signal]?.observation === "present"
    );
    if (!hasObservedCertificateIdentity) return;
  }
  const comparison = await loadTimelineComparisonContext(env, {
    scanId,
    domainId,
    currentReport: opts.currentReport,
  }).catch(() => ({ comparable: false }));
  const canEmitTimelineEvents = comparison.comparable === true;

  let wsRows;
  try {
    wsRows = await loadActiveCertificateWorkspaces(env, domainId);
  } catch {
    return;
  }
  if (wsRows.length === 0) return;

  const now = typeof opts.now === "function"
    ? new Date(opts.now()).toISOString()
    : new Date().toISOString();
  const issuer       = certMod.issuer || "unknown";
  const subject      = certMod.subject || null;
  const sanHostnames = Array.isArray(certMod.san_hostnames) ? certMod.san_hostnames : [];
  const sanCount     = Number.isFinite(certMod.san_count) ? certMod.san_count : sanHostnames.length;
	  const evidenceJson = JSON.stringify({
	    issuer,
	    issuer_normalized: certMod.issuer_normalized ?? normalizeCertificateIssuer(issuer),
	    ca_owner: certMod.ca_owner ?? mapCertificateAuthorityOwner(normalizeCertificateIssuer(issuer)),
	    subject,
	    san_hostnames: sanHostnames,
	    expires_at: certMod.expires_at ?? null,
	    lifecycle: certMod.lifecycle ?? buildCertificateLifecycleIntelligence(certMod),
	    crypto_metadata: certMod.crypto_metadata ?? {
	      key_algorithm: certMod.key_algorithm ?? "unknown",
	      key_size_bits: certMod.key_size_bits ?? "unknown",
	      signature_algorithm: certMod.signature_algorithm ?? "unknown",
	    },
	    self_signed: certMod.self_signed ?? detectSelfSignedCertificate(issuer, subject),
	    ca_concentration_signal: certMod.ca_concentration ?? buildCaConcentrationAnalytics(issuer !== "unknown" ? [issuer] : []),
	    certificate_status: certMod.certificate_status ?? null,
	    source: certMod.source ?? "live_tls",
	    signal_completeness: certMod.signal_completeness ?? null,
        live_tls: certMod.live_tls ?? null,
        evidence_source: certMod.evidence_source ?? 'live_tls',
        live_certificate_verified: certMod.live_certificate_verified === true,
	  });

  const caVendor = normalizeCertificateAuthorityVendor(issuer);

  for (const { workspace_id } of wsRows) {
    try {
      if (caVendor) {
        await upsertCertificateAuthorityVendor(
          workspace_id,
          caVendor,
          {
            issuer,
            subject,
            san_count: sanCount,
            expires_at: certMod.expires_at ?? null,
            certificate_key: certificateKey,
          },
          env,
          now
        );
      }

      const existing = await env.cybermeters_db
        .prepare(
          `SELECT id FROM certificate_observations
           WHERE workspace_id = ? AND domain_id = ? AND certificate_key = ?
           LIMIT 1`
        )
        .bind(workspace_id, domainId, certificateKey)
        .first();

      const priorRows = await env.cybermeters_db
        .prepare(
          `SELECT issuer, evidence_json FROM certificate_observations
           WHERE workspace_id = ? AND domain_id = ?`
        )
        .bind(workspace_id, domainId)
        .all();

      const priorIssuers = new Set();
      const priorSans    = new Set();
      for (const row of (priorRows.results || [])) {
        if (row.issuer) priorIssuers.add(String(row.issuer));
        try {
          const ev = JSON.parse(row.evidence_json || "{}");
          for (const san of (ev.san_hostnames || [])) priorSans.add(String(san));
        } catch { /* ignore malformed historical evidence */ }
      }

      await env.cybermeters_db
        .prepare(
          `INSERT OR IGNORE INTO certificate_observations
             (id, workspace_id, domain_id, scan_id, certificate_key, subject,
              issuer, san_count, expires_at, first_seen, last_seen,
              evidence_json, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          createId("certobs"), workspace_id, domainId, scanId, certificateKey,
          subject, issuer, sanCount, certMod.expires_at ?? null,
          now, now, evidenceJson, now, now
        )
        .run();

      await env.cybermeters_db
        .prepare(
          `UPDATE certificate_observations
           SET scan_id = ?, issuer = ?, san_count = ?, expires_at = ?,
               last_seen = ?, evidence_json = ?, updated_at = ?
           WHERE workspace_id = ? AND domain_id = ? AND certificate_key = ?`
        )
        .bind(
          scanId, issuer, sanCount, certMod.expires_at ?? null, now,
          evidenceJson, now, workspace_id, domainId, certificateKey
        )
        .run();

      if (canEmitTimelineEvents && !existing) {
        await env.cybermeters_db
          .prepare(
            `INSERT INTO asset_events
               (id, workspace_id, domain_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, 'certificate_new_detected',
                     ?, 'medium', ?, ?)`
          )
          .bind(
            createId("asev"), workspace_id, domainId, scanId,
            sanHostnames[0] || subject,
            `New certificate detected for ${subject || "domain"} issued by ${issuer}.`,
            now
          )
          .run();
      }

      if (canEmitTimelineEvents && issuer !== "unknown" && !priorIssuers.has(issuer)) {
        await env.cybermeters_db
          .prepare(
            `INSERT INTO asset_events
               (id, workspace_id, domain_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, 'certificate_new_issuer_detected',
                     ?, 'medium', ?, ?)`
          )
          .bind(
            createId("asev"), workspace_id, domainId, scanId,
            subject,
            `New certificate issuer observed: ${issuer}.`,
            now
          )
          .run();
      }

      const newSans = sanHostnames.filter((san) => !priorSans.has(String(san)));
      if (canEmitTimelineEvents && newSans.length > 0) {
        await env.cybermeters_db
          .prepare(
            `INSERT INTO asset_events
               (id, workspace_id, domain_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, 'certificate_new_san_detected',
                     ?, ?, ?, ?)`
          )
          .bind(
            createId("asev"), workspace_id, domainId, scanId,
            newSans[0],
            newSans.some((h) => isCertSensitiveHost(h, subject || "")) ? "high" : "medium",
            `New certificate SAN hostname${newSans.length > 1 ? "s" : ""} observed: ${newSans.slice(0, 10).join(", ")}${newSans.length > 10 ? ` (+${newSans.length - 10} more)` : ""}.`,
            now
          )
          .run();
      }
    } catch { /* non-fatal per-workspace failure */ }
  }
}

async function upsertCertificateAuthorityVendor(workspaceId, caVendor, evidence, env, observedAt) {
  if (!workspaceId || !caVendor?.vendor_name) return;

  const now = observedAt || new Date().toISOString();
  const category = "certificate_authority";
  const riskLevel = "medium";
  const evidenceJson = JSON.stringify([{
    source: caVendor.source,
    detail: evidence.issuer,
    subject: evidence.subject ?? null,
    san_count: evidence.san_count ?? null,
    expires_at: evidence.expires_at ?? null,
    certificate_key: evidence.certificate_key ?? null,
  }]);
  const metadataJson = JSON.stringify({
    dependency_type: "certificate_authority",
    criticality: "high",
    business_reason: "This organisation issues or validates TLS certificates used by observed public-facing assets.",
  });

  await env.cybermeters_db
    .prepare(
      `INSERT OR IGNORE INTO workspace_vendors
         (id, workspace_id, vendor_name, category, source, evidence,
          confidence, risk_level, first_seen, last_seen, status,
          source_module, metadata_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', 'certificate_authority', ?, ?, ?)`
    )
    .bind(
      createId("vendor"),
      workspaceId,
      caVendor.vendor_name,
      category,
      caVendor.source,
      evidenceJson,
      caVendor.confidence,
      riskLevel,
      now,
      now,
      metadataJson,
      now,
      now
    )
    .run();

  await env.cybermeters_db
    .prepare(
      `UPDATE workspace_vendors
       SET last_seen = ?, source = ?, evidence = ?, confidence = ?,
           risk_level = ?, status = 'active', source_module = 'certificate_authority',
           metadata_json = ?, updated_at = ?
       WHERE workspace_id = ? AND vendor_name = ? AND category = ?`
    )
    .bind(
      now,
      caVendor.source,
      evidenceJson,
      caVendor.confidence,
      riskLevel,
      metadataJson,
      now,
      workspaceId,
      caVendor.vendor_name,
      category
    )
    .run();
}
