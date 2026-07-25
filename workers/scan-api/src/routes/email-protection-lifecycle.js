// ── Email Protection lifecycle history routes ────────────────────────────────
// The read surface migration 088 never had. `email_protection_events` was read only by
// the alert pipeline and a private grading helper, and the four lifecycle-state columns
// 088 added to `email_sender_sources` are stripped by emailSenderToApi before they leave
// the API. So a customer could be told their hosted DMARC record had disconnected — at
// `high` — and had no way to see when it started, how often it had happened, or whether
// it had ever reconnected.
//
// This domain is shaped differently from its siblings and the route reflects that rather
// than inventing a record to match them: mig 088 created NO state table. The events ARE
// the history, and the current state lives on the parent rows (`hosted_dns_entries`,
// `email_sender_sources`) which their own endpoints already serve. So the resource here
// is the history itself, filterable by migration 088's two original record types
// plus P4's additive dmarc_policy_condition application vocabulary.
//
// Shaped like routes/certificates-lifecycle.js otherwise — auth, then role, then the
// soft-delete gate. Non-enumerating: an unknown record id yields an empty history, never
// a hint that it exists in another tenant.
import {
  listEmailProtectionEvents, countEmailProtectionEvents,
  HOSTED_RECORD_TYPE, SENDER_RECORD_TYPE, DMARC_POLICY_CONDITION_RECORD_TYPE,
} from "../engines/email-protection-lifecycle.js";
import { pageMeta, paginationParams } from "../lib/util.js";

const EMAIL_LIFECYCLE_SCOPE_NOTE =
  "Receiver-reported and externally observed email evidence only. This is the history of what CyberMeters recorded and when — "
  + "a hosted record disconnecting or reconnecting, a sender's condition beginning, recovering or returning, and DMARC policy changes derived from complete immutable observations. "
  + "A published DMARC preference does not prove receiver enforcement. Related timing does not establish causality or compromise. "
  + "A customer classification is recorded as the customer's own assertion and is never presented as a CyberMeters observation.";

const RECORD_TYPES = Object.freeze([
  HOSTED_RECORD_TYPE,
  SENDER_RECORD_TYPE,
  DMARC_POLICY_CONDITION_RECORD_TYPE,
]);

export async function emailProtectionLifecycleRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole } = rctx;

  const m = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/email-protection\/lifecycle$/);
  if (!m) return null;
  const wsId = m[1];

  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401);
  const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
  if (!access) return json({ error: "Forbidden" }, 403);

  // Existence + soft-delete gate. NOT the primary defence: requireWorkspaceRole above
  // already excludes deleted workspaces via its own join (index.js:1417), so this only
  // closes the delete-between-checks window. See routes/website-security.js.
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(wsId).first().catch(() => null);
  if (!ws) return json({ error: "Workspace not found" }, 404);

  if (request.method !== "GET") return json({ error: "Not found" }, 404);

  try {
    // An unrecognised record_type is rejected rather than ignored: silently returning the
    // unfiltered history for a typo'd filter is how a "scoped" list stops being scoped.
    const recordType = url.searchParams.get("record_type");
    if (recordType && !RECORD_TYPES.includes(recordType)) {
      return json({ error: `record_type must be one of: ${RECORD_TYPES.join(", ")}` }, 400);
    }

    // record_id is NOT resolved against a parent table first, and that is deliberate: the
    // events table carries workspace_id itself (mig 088 gives it no FK so history can
    // outlive a hard-deleted parent), so the tenant predicate is already complete. A
    // foreign or unknown id simply matches nothing.
    const { limit, offset } = paginationParams(url, { defaultLimit: 50, maxLimit: 200 });
    const filters = { record_id: url.searchParams.get("record_id"), record_type: recordType };
    const items = await listEmailProtectionEvents(env, wsId, { ...filters, limit, offset });
    const total = await countEmailProtectionEvents(env, wsId, filters);
    return json({
      workspace_id: wsId,
      record_types: RECORD_TYPES,
      items,
      pagination: pageMeta({ items, limit, offset, total }),
      scope_note: EMAIL_LIFECYCLE_SCOPE_NOTE,
    });
  } catch { return json({ error: "Database error" }, 500); }
}
