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
  // Email Protection (PR-B3): the mirror image of the case pair above — ONE domain
  // spanning TWO record families (hosted_dns_entries + email_sender_sources) in one
  // table. Sharing is forced, not chosen: this map allows exactly one source per
  // domain_key, so a second table would leave one family permanently unresolvable —
  // the very defect the type_column adapter above exists to fix.
  //
  // The fk is therefore generic. Safety rests on the two id namespaces ('hd-' and
  // 'esender_') being disjoint, so a record_id cannot resolve the other family's
  // occurrence. The database cannot express that invariant across two unrelated
  // parents, so CI asserts it instead.
  email_protection:               { table: "email_protection_events",      fk: "record_id",    type_column: "event_type" },
  // Website Security (corrective phase): one record family — a condition is
  // (workspace, domain, canonical finding id). The fk carries condition-row ids
  // ('wsc-…') and, for the domain-level baseline marker only, a domain_id. Those
  // cannot collide (the engine mints the 'wsc-' prefix) and the marker is not a
  // `monitoring_changed` row, so the resolver cannot match it regardless.
  website_security:               { table: "website_security_events",       fk: "record_id",    type_column: "event_type" },
  // Cyber Essentials (corrective phase): one record per (workspace, control theme).
  // The fk carries control-record ids ('cec-…') and, for the workspace-level baseline
  // marker only, a workspace_id — disjoint by the 'cec-' prefix, and the marker is not
  // a `monitoring_changed` row in any case.
  cyber_essentials_readiness:     { table: "cyber_essentials_events",        fk: "record_id",    type_column: "event_type" },
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
//
// ── Why the tie-break is `rowid DESC` and not `id DESC` ──────────────────────
// created_at is stamped by SQLite `datetime('now')` — SECOND precision. Two
// occurrences of the same recurrence on the same record inside one second tie on
// created_at and fall through to the tie-break. `id DESC` tie-breaks on random hex
// (`cle-`/`iee-`/`sie-`/`epe-`/`case_`…), so it can return the OLDER event as the
// newest occurrence. That is fail-SILENT, not fail-loud: the older event's
// dedupe_key already exists, so `INSERT OR IGNORE` swallows the newer, real alert
// as a duplicate and the customer is never told.
//
// rowid is the insertion order the table already maintains, so it answers the
// question actually being asked — which of these two appends happened last. It is
// legal here because every source is a physical rowid table (no WITHOUT ROWID, no
// view); validate-alert-occurrence-ordering.js asserts that against the real
// schema rather than trusting this comment. Rowid reuse after a purge cannot
// invert the order: SQLite assigns max(rowid)+1 over the rows that REMAIN, so a
// new append always sorts above every surviving row.
//
// This is deliberately NOT fixed by giving created_at sub-second precision.
// observationIsAfterWatermark compares this event's created_at against a
// second-truncated alert_activation.activated_at with a strict `>`, so added
// precision would flip same-second events from "at the watermark" to "after it"
// and could release a backlog of pre-existing conditions as if they were new.
// The rowid tie-break cannot: it only ever re-selects among rows whose created_at
// are IDENTICAL, so observed_at — and therefore every watermark decision — is
// bit-for-bit unchanged. PR-B3 already reached the same conclusion for its own
// lastGradedCondition read (engines/email-protection-lifecycle.js); this is the
// same fix applied to the resolver all six domains share.
export async function findConditionOccurrence(env, {
  workspace_id, domain_key, record_id, recurrence_type,
} = {}) {
  const source = LIFECYCLE_EVENT_SOURCES[domain_key];
  if (!source || !workspace_id || !record_id || !recurrence_type) return null;
  try {
    // Ask the database for the EXACT row we need, not for a page of recent rows we then
    // sift in JavaScript.
    //
    // THE DEFECT THIS REPLACED (reproduced 2026-07-16): this read `LIMIT 25` of
    // monitoring_changed rows and filtered `to_recurrence_type` in JS. But
    // `monitoring_changed` is overloaded — the same event_type also records
    // "reappeared", "no_longer_observed" and case-linkage ({case_id, recurrence,
    // updated_case}) — and Shadow IT appends one case-linkage row per evaluation pass
    // for as long as a condition persists. So the window filled with rows that can never
    // match, and from pass 26 the real occurrence was pushed out of it: measured, the
    // resolver returned the occurrence on passes 1-25 and NULL from 26 onward, forever.
    //
    // Measured impact was narrower than the window suggests — the alert on those passes
    // deduped anyway (the dedupe key IS the occurrence id), and a genuine recurrence
    // still alerted because its transition is appended immediately before this read. But
    // that is luck of ordering, not a guarantee: correctness rested on the real event
    // happening to be within the last 25 rows. An arbitrary event window is not lifecycle
    // state, and 25 is not a semantic bound — it is a number.
    //
    // LIMIT 1 here IS semantic: exactly one row can be the latest transition into this
    // condition. The index on (fk, created_at) makes this an ordered index walk that
    // stops at the first match rather than a table scan, and it is correct at any
    // lifecycle age — 25, 500 or a million events.
    //
    // json_valid() is load-bearing, not defensive noise: a bare json_extract() THROWS on
    // one malformed row and would take the whole query — and therefore every alert for
    // that record — down with it. The JS reader it replaced tolerated a bad row by
    // returning {}, so without this guard the fix would trade a bounded-window bug for a
    // poison-pill bug. CASE is used rather than `json_valid(x) AND json_extract(x)`
    // because CASE's short-circuit is guaranteed by SQL semantics; AND's is an artefact
    // of the current evaluation order.
    //
    // ── Where this differs from the JS filter it replaced ─────────────────────
    // The old predicate was `String(detail.to_recurrence_type || "") === String(rec)`,
    // which COERCED both sides. SQL compares typed values, so a to_recurrence_type
    // stored as 5 no longer matches the string "5" (SQLite does not coerce across
    // storage classes here). Measured divergences: number, boolean and object payloads,
    // plus `null` payload vs an empty-string query.
    //
    // All four are unreachable, and the check is the reachability, not the hope: every
    // writer passes a value from a frozen STRING enum (EMAIL_RECURRENCES and its peers),
    // and an empty `recurrence_type` never reaches here — the falsy guard above returns
    // null first. Every divergence also fails CLOSED (a stricter match => no occurrence
    // => no alert), which is the direction this codebase already chooses everywhere else.
    // validate-alert-occurrence.js pins the reachable shapes AND the fail-closed
    // behaviour, so a future writer that starts emitting a non-string recurrence type
    // fails a test rather than silently losing alerts.
    const row = await env.cybermeters_db
      .prepare(`SELECT id, created_at, detail_json
                FROM ${source.table}
                WHERE workspace_id = ? AND ${source.fk} = ? AND ${source.type_column} = ?
                  AND (CASE WHEN json_valid(detail_json)
                            THEN json_extract(detail_json, '$.to_recurrence_type') END) = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT 1`)
      .bind(workspace_id, record_id, MONITORING_CHANGED, String(recurrence_type))
      .first();

    if (row) {
      return { occurrence_id: row.id, observed_at: row.created_at, detail: parseJson(row.detail_json, {}) || {} };
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
