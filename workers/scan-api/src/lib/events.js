// ── Audit + notification event writers ──────────────────────────────────────
// One module by measurement, not taste: the two writers reference each other
// (createNotificationsForDomain), so splitting them would create a lib cycle.
import { buildScanCompletionPresentation } from "../engines/assessment-presentation.js";
import { createId } from "./util.js";

/**
 * createNotificationEvent — inserts one row into notification_events.
 *
 * @param {object} env          - Worker env bindings
 * @param {string} workspace_id - Target workspace
 * @param {object} opts         - { type, severity, title, message, metadata, user_id }
 *
 * Always non-fatal — swallows all errors so callers never need try/catch.
 */
async function createNotificationEvent(env, workspace_id, { type, severity = "info", title, message = null, metadata = null, user_id = null } = {}) {
  if (!workspace_id || !type || !title) return;
  try {
    const id           = createId("notif");
    const metaJson     = metadata ? JSON.stringify(metadata) : null;
    await env.cybermeters_db
      .prepare(
        `INSERT INTO notification_events
           (id, workspace_id, user_id, type, severity, title, message, metadata_json, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'unread', datetime('now'))`
      )
      .bind(id, workspace_id, user_id, type, severity, title, message, metaJson)
      .run();
  } catch { /* non-fatal */ }
}

/**
 * createAuditEvent — inserts one row into audit_events.
 *
 * Always non-fatal. Audit failures must never break business logic.
 *
 * @param {object} env              - Worker env bindings
 * @param {object} opts
 *   workspace_id  {string|null}   - Workspace context (null for auth events)
 *   user_id       {string|null}   - Acting user (null for system events)
 *   event_type    {string}        - e.g. 'domain_verified', 'scan_completed'
 *   entity_type   {string|null}   - e.g. 'domain', 'scan', 'member', 'report'
 *   entity_id     {string|null}   - ID of the affected entity
 *   description   {string|null}   - Human-readable summary
 *   metadata      {object|null}   - Arbitrary JSON context
 */
async function createAuditEvent(env, {
  workspace_id  = null,
  user_id       = null,
  actor_type    = null,
  event_type,
  entity_type   = null,
  entity_id     = null,
  description   = null,
  metadata      = null,
} = {}) {
  if (!event_type) return;
  try {
    const id       = createId("audit");
    const metaJson = metadata ? JSON.stringify(metadata) : null;
    await env.cybermeters_db
      .prepare(
        `INSERT INTO audit_events
           (id, workspace_id, user_id, actor_type, event_type, entity_type, entity_id, description, metadata_json, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      )
      .bind(id, workspace_id, user_id, actor_type || (user_id ? "customer" : "system"), event_type, entity_type, entity_id, description, metaJson)
      .run();
  } catch { /* non-fatal */ }
}

/**
 * sanitizeAuditMetadata — removes sensitive keys from audit event metadata
 * before returning to clients or writing to exports.
 * Keys matching any blocked substring are replaced with "[redacted]".
 */
function sanitizeAuditMetadata(metadata) {
  if (!metadata || typeof metadata !== "object" || Array.isArray(metadata)) return metadata;
  const BLOCKED = [
    "password", "token", "secret", "authorization", "stripe",
    "recovery", "totp", "mfa_secret", "api_key", "key_material",
  ];
  const sanitized = {};
  for (const [k, v] of Object.entries(metadata)) {
    const lower = k.toLowerCase();
    const blocked = BLOCKED.some(b => lower.includes(b));
    sanitized[k] = blocked ? "[redacted]" : v;
  }
  return sanitized;
}

async function createNotificationsForDomain(
  domainId,
  domain,
  scanId,
  score,
  risk_level,
  findings,
  env,
  scanQuality = null,
  monitoringStates = null,
) {
  try {
    const wsResult = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId)
      .all();
    const workspaceIds = (wsResult.results || []).map(r => r.workspace_id);
    if (workspaceIds.length === 0) return;

    const criticalCount = findings.filter(f => f.severity === "critical").length;
    const highCount     = findings.filter(f => f.severity === "high").length;
    const meta          = { scan_id: scanId, domain, score, risk_level };
    const completion    = buildScanCompletionPresentation({
      domain,
      score,
      riskLevel: risk_level,
      scanQuality,
      monitoringStates,
    });

    for (const wsId of workspaceIds) {
      // Scan completed notification
      await createNotificationEvent(env, wsId, {
        type:     "scan_completed",
        severity: criticalCount > 0 ? "critical" : highCount > 0 ? "high" : "info",
        title:    `Scan completed for ${domain}`,
        message:  `${completion.message}${criticalCount > 0 ? ` · ${criticalCount} critical finding${criticalCount !== 1 ? "s" : ""}` : ""}${highCount > 0 ? ` · ${highCount} high finding${highCount !== 1 ? "s" : ""}` : ""}`,
        metadata: meta,
      });

      // Critical findings notification (separate, higher urgency)
      if (criticalCount > 0) {
        await createNotificationEvent(env, wsId, {
          type:     "critical_finding",
          severity: "critical",
          title:    `${criticalCount} critical finding${criticalCount !== 1 ? "s" : ""} on ${domain}`,
          message:  `A scan of ${domain} detected ${criticalCount} critical severity issue${criticalCount !== 1 ? "s" : ""} requiring immediate attention.`,
          metadata: meta,
        });
      }

      // High findings notification. Aggregated separately from critical findings
      // so mixed critical/high scans still surface both counts without per-finding spam.
      if (highCount > 0) {
        await createNotificationEvent(env, wsId, {
          type:     "high_finding",
          severity: "high",
          title:    `${highCount} high-severity finding${highCount !== 1 ? "s" : ""} on ${domain}`,
          message:  `A scan of ${domain} detected ${highCount} high-severity issue${highCount !== 1 ? "s" : ""}.`,
          metadata: meta,
        });
      }
    }
  } catch { /* non-fatal */ }
}

export {
  createAuditEvent,
  createNotificationEvent,
  createNotificationsForDomain,
  sanitizeAuditMetadata,
};
