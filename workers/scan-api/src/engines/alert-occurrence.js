// ── Alert occurrence identity (canonical, derived — never denormalised) ──────
// Answers one question for every managed domain: "when did the condition we are
// about to alert on actually begin, and which occurrence of it is this?"
//
// The answer already exists. Each managed domain keeps an APPEND-ONLY lifecycle
// events table (certificate_lifecycle_events / identity_exposure_events /
// shadow_it_inventory_events) and appends a `monitoring_changed` row whenever the
// evaluator observes a real transition. That row IS the occurrence:
//   • its created_at is when the condition began — stable forever, because the
//     table is append-only and rows are never rewritten;
//   • its id is the occurrence identity — a later recurrence appends a NEW row and
//     therefore mints a NEW identity, with no counter to maintain.
//
// So nothing here is stored twice. There is deliberately no recurrence_detected_at
// column and no occurrence counter: that would denormalise a fact the events table
// already owns, and two copies of a timestamp eventually disagree.
//
// ── Why not the obvious columns ──────────────────────────────────────────────
// evaluated_at / updated_at are refreshed by every evaluation pass, and
// last_seen_at by every scan. Any of them as the condition-start would drift
// forward hourly, clear the activation watermark on the very next run, and re-alert
// the same unchanged condition every hour — the precise failure this module exists
// to prevent. They are never read here.
//
// ── Pre-existing rows ────────────────────────────────────────────────────────
// A row whose current condition has NO matching transition event predates alerting.
// We return null and the caller treats it as baseline-only. We must NOT invent a
// timestamp for it: stamping now() would make yesterday's backlog look like today's
// news the moment activation completes.

// Per-domain wiring for the three managed lifecycle event tables. The foreign-key
// column differs per table (a historical quirk), so it is named explicitly rather
// than guessed.
export const LIFECYCLE_EVENT_SOURCES = Object.freeze({
  certificates_trust: { table: "certificate_lifecycle_events", fk: "lifecycle_id" },
  identity_exposure: { table: "identity_exposure_events", fk: "record_id" },
  shadow_it_unmanaged_technology: { table: "shadow_it_inventory_events", fk: "item_id" },
});

function parseJson(raw, fallback = null) {
  if (!raw) return fallback;
  try { return typeof raw === "string" ? JSON.parse(raw) : raw; } catch { return fallback; }
}

// The transition event that started the CURRENT condition, or null.
//
// Matching is deterministic and strict: the newest `monitoring_changed` event whose
// recorded recurrence_type equals the condition we are alerting on. Strictness is
// the point — a loose match would attach today's alert to an unrelated older event,
// silently borrowing its (pre-watermark) timestamp and suppressing a real alert.
//
// Tenant-scoped by construction: workspace_id is always in the predicate, so an
// occurrence can never be resolved from another tenant's history.
export async function findConditionOccurrence(env, {
  workspace_id, domain_key, record_id, recurrence_type,
} = {}) {
  const source = LIFECYCLE_EVENT_SOURCES[domain_key];
  if (!source || !workspace_id || !record_id || !recurrence_type) return null;
  try {
    const rows = await env.cybermeters_db
      .prepare(`SELECT id, created_at, detail_json
                FROM ${source.table}
                WHERE workspace_id = ? AND ${source.fk} = ? AND event_type = 'monitoring_changed'
                ORDER BY created_at DESC, id DESC
                LIMIT 25`)
      .bind(workspace_id, record_id)
      .all();

    for (const row of (rows.results || [])) {
      const detail = parseJson(row.detail_json, {}) || {};
      if (String(detail.to_recurrence_type || "") === String(recurrence_type)) {
        return { occurrence_id: row.id, observed_at: row.created_at, detail };
      }
    }
    return null;   // pre-existing condition: no transition was ever recorded
  } catch (err) {
    // Fail CLOSED. Unable to establish when the condition began => we cannot show it
    // is new => it does not alert. A missed alert is recoverable on the next pass;
    // a fabricated one is not.
    console.error("[alert-occurrence] lookup failed", JSON.stringify({ workspace_id, domain_key, record_id, reason: err?.message }));
    return null;
  }
}

// The structured state a monitoring_changed event must carry for the match above to
// be deterministic. Shared so all three evaluators record the same shape.
export function buildMonitoringTransitionDetail({
  from_monitoring_status = null, to_monitoring_status = null,
  from_recurrence_type = null, to_recurrence_type = null,
  required_case_action = null, reason = null, entity = null,
} = {}) {
  return {
    from_monitoring_status, to_monitoring_status,
    from_recurrence_type, to_recurrence_type,
    required_case_action, reason,
    entity,   // the domain's own stable entity identifier (hostname / identity key / tech key)
  };
}

// Did the evaluator observe a real transition worth recording?
// Only a CHANGE is an occurrence: re-observing the same condition on the next hourly
// pass is not a new event, and must not append one — otherwise every pass would mint
// a fresh occurrence id and re-alert forever.
export function isMonitoringTransition(prev, next) {
  return String(prev?.monitoring_status ?? "") !== String(next?.monitoring_status ?? "")
    || String(prev?.recurrence_type ?? "") !== String(next?.recurrence_type ?? "");
}
