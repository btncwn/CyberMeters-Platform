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
// Each domain's append-only source of "when did this condition begin?".
//
// `type_column` exists because the managed-case history table names its vocabulary
// column `action`, while the three lifecycle tables call it `event_type`. Before
// this, the column name was hardcoded to `event_type` — so a managed-case lookup
// raised "no such column: event_type", was swallowed by the catch below, and
// returned null forever. Brand Protection and Attack Surface could therefore never
// resolve an occurrence, which is precisely why they were still on hand-rolled
// notification paths. Naming the column per source is the whole adapter.
//
// The values here are interpolated into SQL, so they are a FROZEN internal
// allowlist and are asserted against the real schema in CI — never derived from a
// request, a row, or anything a customer can influence.
export const LIFECYCLE_EVENT_SOURCES = Object.freeze({
  certificates_trust:             { table: "certificate_lifecycle_events", fk: "lifecycle_id", type_column: "event_type" },
  identity_exposure:              { table: "identity_exposure_events",     fk: "record_id",    type_column: "event_type" },
  shadow_it_unmanaged_technology: { table: "shadow_it_inventory_events",   fk: "item_id",      type_column: "event_type" },
  // Managed cases: one append-only history table, two domains, disambiguated by the
  // case's own domain_key upstream — a case_id belongs to exactly one domain, so the
  // fk cannot collide across them.
  brand_protection:               { table: "managed_case_events",          fk: "case_id",      type_column: "action" },
  attack_surface:                 { table: "managed_case_events",          fk: "case_id",      type_column: "action" },
});

// The one vocabulary value that marks a condition transition, in every source.
export const MONITORING_CHANGED = "monitoring_changed";

// ── Canonical UTC timestamp parsing (alert watermark read boundary) ──────────
// The platform persists timestamps in TWO shapes, and they are not comparable by
// Date.parse:
//
//   • ISO 8601, UTC-explicit — `2026-07-15T15:30:00.123Z`
//     (new Date().toISOString(), e.g. alert_activation.activated_at)
//   • SQLite UTC text, timezone-IMPLICIT — `2026-07-15 15:30:00`
//     (datetime('now'), e.g. managed_case_events.created_at)
//
// Date.parse treats the first as UTC and the space-separated second as LOCAL time
// (ECMA-262 leaves non-ISO formats implementation-defined; V8 reads it as local).
// So on a machine at UTC+1 the SQLite value parses one hour EARLY, and a watermark
// comparison between the two silently shifts by the machine's offset. Workers run
// in UTC, which masks it in production and surfaces it anywhere else — a defect
// that only appears off-production is worse than one that always fails.
//
// This is a READ-boundary normaliser by design: it does not rewrite stored data,
// so no migration and no backfill. Both shapes stay valid on disk; only the
// comparison is made explicit.
//
// Contract: return epoch milliseconds, or null for anything missing, malformed,
// ambiguous or unrecognised. Never guess. Callers MUST treat null as fail-closed.
const UTC_TIMESTAMP = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:?\d{2})?$/i;

export function parseUtcMs(value) {
  if (value === null || value === undefined) return null;
  const raw = String(value).trim();
  if (!raw) return null;

  const m = UTC_TIMESTAMP.exec(raw);
  if (!m) return null;                       // unrecognised shape → caller fails closed

  const [, date, time, tz] = m;
  // Append Z ONLY when the value carries no timezone of its own. A value that
  // already states its offset keeps it — we must not relabel +02:00 as UTC.
  const suffix = tz ? (tz.toUpperCase() === "Z" ? "Z" : tz) : "Z";
  const ms = Date.parse(`${date}T${time}${suffix}`);
  return Number.isFinite(ms) ? ms : null;
}

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
                WHERE workspace_id = ? AND ${source.fk} = ? AND ${source.type_column} = ?
                ORDER BY created_at DESC, id DESC
                LIMIT 25`)
      .bind(workspace_id, record_id, MONITORING_CHANGED)
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
// `recurrence_band` is an OPTIONAL third dimension (PR-B2).
//
// Some conditions worsen without changing their recurrence type. A certificate at
// 30 days and the same certificate at 7 days are both `renewal_overdue`, so on
// status+type alone no transition is seen: no event is appended, the occurrence id
// stays the same, the dedupe key stays the same, and the customer is never told it
// became urgent. The band makes "it got worse" a transition in its own right.
//
// Absent on BOTH sides (Identity Exposure, Shadow IT, managed cases) the comparison
// is "" !== "", which is false — so those domains behave exactly as before. This is
// additive by construction, and validate-alert-b2-cert-expiry-bands.js asserts it.
export function isMonitoringTransition(prev, next) {
  return String(prev?.monitoring_status ?? "") !== String(next?.monitoring_status ?? "")
    || String(prev?.recurrence_type ?? "") !== String(next?.recurrence_type ?? "")
    || String(prev?.recurrence_band ?? "") !== String(next?.recurrence_band ?? "");
}
