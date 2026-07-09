// ── Certificate event insertion ──
// Persists certificate-observation + CA-vendor events to D1 for the certificate timeline.
// Extracted verbatim from index.js (monolith decomposition, Phase 1c).
// upsertCertificateAuthorityVendor is module-internal.
import { hashToken } from "../lib/auth-crypto.js";
import { createId } from "../lib/util.js";
import { buildCaConcentrationAnalytics, buildCertificateLifecycleIntelligence, detectSelfSignedCertificate, mapCertificateAuthorityOwner, normalizeCertificateAuthorityVendor, normalizeCertificateIssuer } from "./cert-analysis.js";
import { isCertSensitiveHost, runCertificateIntelligenceModule } from "./cert-intel.js";

// ── Certificate Event Insertion ──────────────────────────────────────────────
//
// Fires asset_events for certificate-level signals detected by
// runCertificateIntelligenceModule.  One event per signal type per scan.
// All errors are non-fatal.

/**
 * insertCertificateEvents(scanId, domainId, certMod, env)
 *
 * Event types written:
 *   certificate_sensitive_host_detected — sensitive hostnames in CT logs
 *   certificate_expiring_soon           — expiry < 30 days
 *   certificate_growth_detected         — CT count > 50 hostnames
 */
export async function insertCertificateEvents(scanId, domainId, certMod, env) {
  if (!certMod || certMod.error) return;

  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch {
    return;
  }
  if (wsRows.length === 0) return;

  const now = new Date().toISOString();

  for (const { workspace_id } of wsRows) {
    // 1. Sensitive hosts detected in CT
    if (certMod.issued_for_sensitive_hosts?.length > 0) {
      try {
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO asset_events
               (id, workspace_id, domain_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, 'certificate_sensitive_host_detected',
                     ?, ?, ?, ?)`
          )
          .bind(
            createId("asev"),
            workspace_id,
            domainId,
            scanId,
            certMod.issued_for_sensitive_hosts[0],   // first / most notable
            certMod.issued_for_sensitive_hosts.length >= 5 ? "high" : "medium",
            `${certMod.issued_for_sensitive_hosts.length} sensitive hostname(s) found in CT logs: ` +
              certMod.issued_for_sensitive_hosts.slice(0, 5).join(", "),
            now
          )
          .run();
      } catch { /* non-fatal */ }
    }

    // 2. Certificate expiring soon
    const days = certMod.days_until_expiry;
    if (days !== null && days < 30) {
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
            createId("asev"),
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

    // 3. Unusual certificate growth
    if (certMod.total_certificates_seen > 50) {
      try {
        await env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO asset_events
               (id, workspace_id, domain_id, scan_id, event_type,
                hostname, severity, description, created_at)
             VALUES (?, ?, ?, ?, 'certificate_growth_detected',
                     ?, 'medium', ?, ?)`
          )
          .bind(
            createId("asev"),
            workspace_id,
            domainId,
            scanId,
            null,
            `${certMod.total_certificates_seen} unique hostnames found in CT logs.`,
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
export async function upsertCertificateObservation(scanId, domainId, certMod, env) {
  if (!certMod || certMod.error) return;

  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch {
    return;
  }
  if (wsRows.length === 0) return;

  const now          = new Date().toISOString();
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
	    source: certMod.source ?? "ssl_ct_correlation",
	  });

  const certificateKey = await hashToken([
    issuer,
    subject ?? "",
    certMod.expires_at ?? "",
    sanHostnames.slice().sort().join(","),
  ].join("|"));
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

      if (!existing) {
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

      if (issuer !== "unknown" && !priorIssuers.has(issuer)) {
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
      if (newSans.length > 0) {
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
