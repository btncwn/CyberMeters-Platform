// ── DMARC operational alerts ──────────────────────────────────────────────────
// Turns the ingested + classified sender data into real operational signals a
// customer should act on, emitted through the existing notification pipeline
// (in-app bell + workspace alert channels), deduped and tenant-scoped. Honest:
// only fires on genuine signal above a threshold. Manual sender classification
// wins (classified_at). Read-only; never mutates DMARC state.
//
// v1 detectors (from sender data, no new storage):
//   • dmarc_new_sender    — a NEW, high-volume, not-yet-recognised source.
//   • dmarc_spoofing_spike — an `unauthorised` source failing auth at volume
//                            while claiming the protected domain.
// The post-reject legitimate-failure alert (`hosted_dmarc_impact_regression`)
// ships in the impact monitor; hosted-record health alerts (disconnected /
// policy changed / rolled back) ship in the hosted-DMARC engine.
import { createNotificationEvent } from "../lib/events.js";
import { deliverWorkspaceAlert } from "./alerts.js";

export const DMARC_ALERT_THRESHOLDS = {
  NEW_SENDER_MIN_VOLUME: 50,
  NEW_SENDER_RECENT_DAYS: 2,
  SPOOFING_MIN_FAILED: 50,
  DEDUP_HOURS: 24,
  SWEEP_MAX_ROWS: 500,
};

const RISKY_CLASSES = new Set(["unknown", "suspicious", "unauthorised"]);

function effectiveClassification(row) {
  if (row.classified_at) return row.classification || "unknown";
  return row.auto_classification || row.classification || "unknown";
}

function parseEpoch(v) {
  if (!v) return 0;
  const s = String(v);
  const ms = Date.parse(s.includes("T") ? s : s.replace(" ", "T") + "Z");
  return Number.isFinite(ms) ? ms : 0;
}

async function alreadyAlerted(env, workspaceId, type, sourceIp, hours) {
  try {
    const row = await env.cybermeters_db
      .prepare(`SELECT id FROM notification_events
                WHERE workspace_id = ? AND type = ?
                  AND created_at >= datetime('now', ?)
                  AND metadata_json LIKE ? LIMIT 1`)
      .bind(workspaceId, type, `-${hours} hours`, `%"source_ip":"${sourceIp}"%`)
      .first();
    return Boolean(row);
  } catch { return false; }
}

async function emitAlert(env, workspaceId, ev) {
  // notification_events (in-app bell) is the source of truth; channel fan-out is
  // best-effort and must never block the sweep.
  await createNotificationEvent(env, workspaceId, ev);
  try { await deliverWorkspaceAlert(env, workspaceId, { kind: ev.type, summary: ev.message, ...ev }); } catch { /* channel best-effort */ }
}

export async function runDmarcAlertsSweep(env, { now = new Date() } = {}) {
  const t = DMARC_ALERT_THRESHOLDS;
  let rows;
  try {
    rows = (await env.cybermeters_db
      .prepare(`SELECT workspace_id, domain, source_ip, provider_guess, total_messages,
                       aligned_messages, failed_messages, first_seen, last_seen,
                       classification, auto_classification, classified_at
                FROM email_sender_sources
                WHERE last_seen >= datetime('now', ?)
                ORDER BY total_messages DESC LIMIT ?`)
      .bind(`-${t.NEW_SENDER_RECENT_DAYS} days`, t.SWEEP_MAX_ROWS)
      .all()).results || [];
  } catch { return { checked: 0, alerts: 0 }; }

  let alerts = 0;
  for (const row of rows) {
    const cls = effectiveClassification(row);
    const total = Number(row.total_messages || 0);
    const failed = Number(row.failed_messages || 0);
    const provider = row.provider_guess && row.provider_guess !== "unknown" ? `, ${row.provider_guess}` : "";

    // Spoofing spike: an unauthorised source failing auth at volume.
    if (cls === "unauthorised" && failed >= t.SPOOFING_MIN_FAILED) {
      if (!(await alreadyAlerted(env, row.workspace_id, "dmarc_spoofing_spike", row.source_ip, t.DEDUP_HOURS))) {
        await emitAlert(env, row.workspace_id, {
          type: "dmarc_spoofing_spike", severity: "high",
          title: `Possible spoofing of ${row.domain}`,
          message: `${failed} messages from ${row.source_ip} claimed to be ${row.domain} but failed authentication — a likely spoofing attempt. If DMARC is enforced, these are being blocked.`,
          metadata: { domain: row.domain, source_ip: row.source_ip, failed_messages: failed, classification: cls },
        });
        alerts += 1;
      }
      continue;
    }

    // New high-volume, not-yet-recognised source.
    const isNew = (now.getTime() - parseEpoch(row.first_seen)) <= t.NEW_SENDER_RECENT_DAYS * 86400000;
    if (isNew && total >= t.NEW_SENDER_MIN_VOLUME && RISKY_CLASSES.has(cls)) {
      if (!(await alreadyAlerted(env, row.workspace_id, "dmarc_new_sender", row.source_ip, t.DEDUP_HOURS))) {
        await emitAlert(env, row.workspace_id, {
          type: "dmarc_new_sender", severity: cls === "unauthorised" ? "high" : "medium",
          title: `New sender using ${row.domain}`,
          message: `A new source (${row.source_ip}${provider}) sent ${total} messages as ${row.domain} and is not yet recognised (${cls}). Review whether it is a legitimate sender for this domain.`,
          metadata: { domain: row.domain, source_ip: row.source_ip, total_messages: total, classification: cls },
        });
        alerts += 1;
      }
    }
  }
  return { checked: rows.length, alerts };
}
