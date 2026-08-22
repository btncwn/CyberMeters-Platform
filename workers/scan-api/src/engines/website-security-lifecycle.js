// ── Website Security managed lifecycle ───────────────────────────────────────
// The missing middle. Website Security has always had the evidence (headers/ssl/tech
// modules), stable canonical finding ids, immutable R2 reports and nine canonical
// remediations. What it never had was a row saying WHEN a condition began — so no
// alert could show that anything was new. This engine is that row, and nothing more:
// it does not re-detect, re-score or re-grade anything. Detection stays in
// scoring.js; this correlates its output into durable identity + append-only history.
//
// The lifecycle answers, from persisted evidence only:
//   • which entity is monitored          → (workspace_id, domain_id, condition_key)
//   • when did the condition begin       → the monitoring_changed event's created_at
//   • which occurrence is this           → that event's id
//   • is it still present                → this scan's findings
//   • did it get worse                   → recurrence_band (the severity)
//   • did it resolve                     → absent AND the detecting module RAN
//   • did it come back                   → a new transition after a resolution
//   • or did we simply not look          → monitoring_status 'unknown'. Never a fix.
import { CYBER_MOT_DOMAINS } from "./cyber-mot-domains.js";
import {
  MONITORING_CHANGED, buildMonitoringTransitionDetail, isMonitoringTransition, parseUtcMs,
} from "./alert-occurrence.js";
import { emitLifecycleAlert } from "./alert-consumers.js";
import { moduleCompletionGate } from "./asm-cases.js";
import {
  COOKIE_FINDING_TYPES,
  evaluateCookieObservation,
  isCookieFindingType,
} from "./cookie-observation.js";
// One direction only: this module calls into the case layer, which imports nothing back.
import { openOrReopenWebsiteCase, verifyWebsiteCaseFromResolution } from "./website-security-cases.js";
import {
  projectTlsFindingsForCustomer,
  resolveTlsRuntimeState,
  TLS_RUNTIME_STATES,
} from "./tls-evidence.js";
import { maySupportDefectConclusion, mayGroundRedirectAbsence } from "../lib/serviceability.js";

export const WEBSITE_SECURITY_DOMAIN_KEY = "website_security";

// Non-alertable event vocabulary. These are STRUCTURALLY unable to alert: the
// resolver only matches `monitoring_changed`, so it cannot see them however they are
// worded. That is the point — recovery, baseline and unknown stay silent by
// construction rather than by remembering to skip a call. Absence from
// RECURRENCE_SEVERITY is the second, independent stop.
export const WS_EVENT_DOMAIN_BASELINE = "domain_baseline_established";
export const WS_EVENT_BASELINE        = "baseline_established";
export const WS_EVENT_RESOLVED        = "condition_resolved";
export const WS_EVENT_UNKNOWN         = "evidence_unknown";
export const WS_EVENT_CASE_LINKED     = "case_linked";

export const WS_NON_ALERTABLE_EVENT_TYPES = Object.freeze([
  WS_EVENT_DOMAIN_BASELINE, WS_EVENT_BASELINE, WS_EVENT_RESOLVED,
  WS_EVENT_UNKNOWN, WS_EVENT_CASE_LINKED,
]);

// ── The actionable recurrence map ───────────────────────────────────────────
// Derived from the evidence, not invented: these are the ONLY Website Security
// finding ids scoring.js can emit at a material (medium+) grade. Everything else it
// emits for this domain is `info`/`low` — the consolidated
// `security_headers_not_observed` card, `header_weak_hsts`, `canonical_url_uncertain`,
// `tech_*` version disclosure — and info-grade evidence is not a customer event. It
// is still tracked (as `unknown`, below) because a finding DOWNGRADING to info means
// our evidence got weaker, not that the customer fixed anything.
//
// Each entry names the module that must have RUN for absence to mean "fixed", and
// the finding_type the canonical remediation resolves from. The finding_type is the
// condition_key itself: the registry already keys `web.*` on these exact slugs, so
// there is no second mapping to drift.
const WS_CONDITIONS = Object.freeze({
  ssl_not_available:   { recurrence: "transport_not_available",       module: "ssl" },
  ssl_no_http_redirect:{ recurrence: "insecure_redirect",             module: "ssl" },
  ...Object.fromEntries(COOKIE_FINDING_TYPES.map((conditionKey) => [conditionKey, {
    recurrence: "browser_protection_missing",
    module: "domain_security_enrichment",
  }])),
  // header_missing_* and header_malformed_* are derived per header from the frozen
  // SECURITY_HEADERS list, so they are matched by prefix rather than enumerated —
  // enumerating them would drift the moment a header is added to that list.
});
const WS_CONDITION_PREFIXES = Object.freeze([
  { prefix: "header_missing_",   recurrence: "browser_protection_missing",   module: "headers" },
  { prefix: "header_malformed_", recurrence: "browser_protection_malformed", module: "headers" },
]);

export function websiteConditionSpec(conditionKey) {
  const key = String(conditionKey || "");
  if (WS_CONDITIONS[key]) return WS_CONDITIONS[key];
  for (const p of WS_CONDITION_PREFIXES) {
    if (key.startsWith(p.prefix)) return { recurrence: p.recurrence, module: p.module };
  }
  return null;
}

// The canonical attribution, reused rather than re-implemented: the eight-domain
// resolver already owns "which findings are Website Security?". A second regex here
// would be a second source of truth and would drift.
const WS_DOMAIN = CYBER_MOT_DOMAINS.find((d) => d.domain_key === WEBSITE_SECURITY_DOMAIN_KEY);
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const isMaterial = (s) => (SEV_RANK[String(s || "").toLowerCase()] ?? 0) >= 2;

const safeJson = (v) => { try { return v == null ? null : JSON.stringify(v); } catch { return null; } };

// Prefixed, truncated UUID — the same shape identity-lifecycle.js and
// shadow-it-inventory.js mint locally. Record ids are 'wsc-…' and event ids 'wse-…';
// the 'wsc-' prefix is what keeps condition ids disjoint from the domain_ids used as
// the record_id of the domain-level baseline marker.
function newId(prefix) {
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return `${prefix}-${(uuid || "").slice(0, 12).padEnd(12, "0")}`;
}

async function appendEvent(env, { workspace_id, record_id, event_type, detail = null, actor_type = "system", actor_id = null }) {
  await env.cybermeters_db
    .prepare(`INSERT INTO website_security_events
        (id, record_id, workspace_id, actor_type, actor_id, event_type, detail_json, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
    .bind(newId("wse"), record_id, workspace_id, actor_type, actor_id, event_type, safeJson(detail))
    .run();
}

// Has this (workspace, domain) ever been baselined?
//
// THE FLOOD GUARD, and it is per-DOMAIN rather than per-record on purpose. A
// per-record birth guard (the PR-B3 shape) does not transfer here: B3's records
// already existed with their own created_at, whereas a website condition record is
// BORN at its first evaluation — after the activation watermark — so every
// long-standing finding would look newer than the watermark and alert.
//
// The marker is also why a domain whose first scan is CLEAN is handled correctly: it
// is written on that pass even though no condition row was created, so the first
// condition to appear afterwards is genuinely new and correctly alerts, instead of
// being re-seeded as "the first pass" forever.
async function domainIsBaselined(env, workspaceId, domainId) {
  const row = await env.cybermeters_db
    .prepare(`SELECT 1 AS x FROM website_security_events
              WHERE workspace_id = ? AND record_id = ? AND event_type = ?
              LIMIT 1`)
    .bind(workspaceId, domainId, WS_EVENT_DOMAIN_BASELINE)
    .first()
    .catch(() => null);
  return Boolean(row);
}

// The current graded state of every Website Security condition in this scan.
//
// Three states, and the middle one is the whole honesty argument:
//   material   — present at medium+ : an actionable condition
//   uncertain  — present, but graded info/low because the response was a bot
//                challenge, came over HTTP, was not a 200, or the header was seen on
//                another checked path. The condition did NOT go away; our evidence
//                got weaker. Treating that as recovery would tell a customer they
//                fixed something because Cloudflare showed us a challenge page.
//   absent     — not emitted at any grade
function gradeFindings(findings, modules, gate) {
  const graded = new Map();
  for (const f of (findings || [])) {
    if (!f?.id || !WS_DOMAIN?.match(f)) continue;
    const spec = websiteConditionSpec(f.id);
    if (!spec) continue;   // a Website Security finding with no actionable mapping
    if (isCookieFindingType(f.id)) {
      const cookie = evaluateCookieObservation(f.id, modules?.domain_security_enrichment, {
        moduleComplete: gate.canVerify("domain_security_enrichment"),
      });
      if (cookie.state !== "present") continue;
    }
    // The cookie set is explicitly lifecycle-managed at its canonical finding
    // severities, including the existing low-severity SameSite finding. Other low/info
    // Website signals retain the established evidence-uncertain behaviour.
    const material = isCookieFindingType(f.id) || isMaterial(f.severity);
    const prev = graded.get(f.id);
    // Highest grade wins if a key somehow appears twice in one scan.
    if (prev && SEV_RANK[prev.severity] >= (SEV_RANK[String(f.severity || "").toLowerCase()] ?? 0)) continue;
    graded.set(f.id, {
      condition_key: f.id,
      severity: String(f.severity || "").toLowerCase(),
      title: f.title || null,
      module: spec.module,
      recurrence: spec.recurrence,
      material,
    });
  }
  return graded;
}

// ISSUE conclusions must obey the same evidence boundary as FIXED conclusions.
// Most Website modules predate the shaped serviceability field; preserve their
// established behaviour until a producer supplies that field, but never admit an
// explicitly non-serviceable module result (or an ungrounded redirect envelope).
export function mayIssueFromModule(modules, moduleName) {
  const evidence = modules?.[moduleName];
  if (evidence?.serviceability && !maySupportDefectConclusion(evidence.serviceability)) return false;
  if (moduleName === "ssl" && evidence?.http_redirect_chain
      && !mayGroundRedirectAbsence(evidence.http_redirect_chain)
      && evidence.http_redirect_chain.http_redirect_validated === false) return false;
  return true;
}

/**
 * evaluateWebsiteSecurityForScan — correlate one completed scan into the managed
 * Website Security lifecycle for one workspace, and alert on genuine transitions.
 *
 * Called from scan-engine Phase 8m with the scan's in-memory findings (which still
 * carry the canonical ids D1 discards) and its modules + scan_quality.
 *
 * Never throws: a lifecycle or alerting failure must not break the scan.
 */
// Open/reopen the canonical case for a condition and record the linkage in THIS domain's
// append-only log. The case layer owns the case and the column; the lifecycle owns its own
// events, so the `case_linked` event mig 089 reserved is written here.
//
// Never throws: a case-layer failure must not take down the evaluation pass or suppress the
// alert. The alert then carries no case_id and the customer still hears about the condition
// — strictly better than silence.
async function openWebsiteCase(env, {
  workspace_id, record_id, entity, domain, recurrence, condition_key, severity, scan_id,
}) {
  try {
    const res = await openOrReopenWebsiteCase(env, {
      workspace_id, record_id, entity, domain, recurrence, condition_key,
      severity: severity || "medium",
    });
    if (!res?.ok || !res.case?.id) return null;
    // Only a genuine open/reopen is worth a linkage event; an unchanged pass that found the
    // same open case must add nothing, or the log grows a row per evaluation forever (the
    // per-pass-row defect noted in v2026.07.16-8).
    if (res.created || res.reopened) {
      await appendEvent(env, {
        workspace_id, record_id, event_type: WS_EVENT_CASE_LINKED,
        detail: {
          case_id: res.case.id, condition_key, recurrence, entity, scan_id,
          action: res.created ? "case_opened" : "case_reopened",
        },
      }).catch(() => {});
    }
    return { case_id: res.case.id, created: Boolean(res.created), reopened: Boolean(res.reopened) };
  } catch {
    return null;
  }
}

export async function evaluateWebsiteSecurityForScan(env, {
  workspace_id, domain_id, domain, scan_id,
  findings = [], modules = null, scanQuality = null, now = null,
} = {}) {
  try {
    if (!workspace_id || !domain_id || !domain) return { skipped: "incomplete_context" };

    // A soft-deleted workspace is nonexistent: no record, no event, no alert.
    const live = await env.cybermeters_db
      .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
      .bind(workspace_id).first().catch(() => null);
    if (!live) return { skipped: "workspace_inactive" };

    const gate = moduleCompletionGate(modules, scanQuality);
    const quality = scanQuality?.status ?? null;
    const tls = resolveTlsRuntimeState(modules?.ssl);
    const graded = gradeFindings(projectTlsFindingsForCustomer(findings, modules), modules, gate);

    const existing = (await env.cybermeters_db
      .prepare(`SELECT * FROM website_security_conditions WHERE workspace_id = ? AND domain_id = ?`)
      .bind(workspace_id, domain_id).all().catch(() => ({ results: [] }))).results || [];
    const byKey = new Map(existing.map((r) => [r.condition_key, r]));

    const seeding = !(await domainIsBaselined(env, workspace_id, domain_id));

    let created = 0, transitions = 0, alerts = 0, resolved = 0, unknown = 0;

    // Every key we have a record for, plus every key this scan graded.
    const keys = new Set([...byKey.keys(), ...graded.keys()]);

    for (const key of keys) {
      const spec = websiteConditionSpec(key);
      if (!spec) continue;
      const obs = graded.get(key) || null;
      const rec = byKey.get(key) || null;

      // No active-TLS observation means no lifecycle claim at all. In particular,
      // do not create an unknown transition for a historical condition: that would
      // still turn collector failure into customer history and mutate recurrence
      // fields. Preserve the existing row/event/case bytes until a future scan has
      // observed-present or approved positive-absence evidence.
      if (key === "ssl_not_available" && tls.state === TLS_RUNTIME_STATES.UNAVAILABLE) {
        continue;
      }

      // ── What is the condition's state, honestly? ────────────────────────────
      let status, reason = null, unknown_reason = null;
      let recurrence = null, band = null;
      const cookieObservation = isCookieFindingType(key)
        ? evaluateCookieObservation(key, modules?.domain_security_enrichment, {
          moduleComplete: gate.canVerify("domain_security_enrichment"),
        })
        : null;
      if (obs && obs.material && mayIssueFromModule(modules, spec.module)
          && (!cookieObservation || cookieObservation.state === "present")) {
        status = "observed";
        recurrence = obs.recurrence;
        band = obs.severity;            // the band IS the grade: worsening escalates
      } else if (obs && obs.material && !mayIssueFromModule(modules, spec.module)) {
        // A material-looking finding backed by non-serviceable evidence is neither
        // an issue nor a recovery. Preserve it as an explicit evidence gap.
        status = "unknown";
        unknown_reason = "evidence_insufficient";
        reason = "condition_observation_not_serviceable";
      } else if (cookieObservation?.state === "clear") {
        // Cookie absence is conclusive only when cookies were actually observed and
        // the canonical predicate evaluated false. A zero-cookie response never enters.
        status = "no_longer_observed";
        reason = "cookie_observed_and_canonical_predicate_clear";
      } else if (cookieObservation?.state === "deferred") {
        status = "unknown";
        unknown_reason = gate.scanPartial ? "scan_partial" : cookieObservation.reason;
        reason = "cookie_observation_inconclusive";
      } else if (obs && !obs.material) {
        // Present but our evidence is too weak to act on. Not gone.
        status = "unknown";
        unknown_reason = "evidence_uncertain";
        reason = "condition_present_but_grade_not_material";
      } else if (gate.canVerify(spec.module)) {
        // Absent AND the detecting module provably ran to completion => a real fix.
        status = "no_longer_observed";
        reason = "absent_and_module_assessed";
      } else {
        // Absent, but we cannot show the module looked. This is the branch that stops
        // a timed-out probe reading as "the customer fixed it".
        status = "unknown";
        unknown_reason = gate.scanPartial ? "scan_partial" : "module_not_assessed";
        reason = "absent_but_module_not_assessed";
      }

      // Nothing observed and nothing recorded: nothing to say.
      if (!rec && status !== "observed") continue;

      // ── Create the record on first sight ───────────────────────────────────
      if (!rec) {
        const id = newId("wsc");
        await env.cybermeters_db
          .prepare(`INSERT INTO website_security_conditions
              (id, workspace_id, domain_id, domain, condition_key, observed_severity, observed_title,
               detecting_module, last_scan_id, last_scan_quality, first_seen_at, last_seen_at,
               last_changed_at, monitoring_status, monitoring_reason, unknown_reason,
               recurrence_type, recurrence_band, lifecycle_state, created_at, updated_at, evaluated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'),
                    datetime('now'), ?, ?, ?, ?, ?, 'observed', datetime('now'), datetime('now'), datetime('now'))`)
          .bind(id, workspace_id, domain_id, domain, key, obs?.severity ?? null, obs?.title ?? null,
                spec.module, scan_id ?? null, quality,
                seeding ? "baseline" : status, reason, unknown_reason,
                recurrence, band)
          .run();
        created++;

        // On the seeding pass this condition predates our watching — we cannot show
        // it is new, so it is baselined and can never alert for the condition it is
        // already in. Post-baseline, a NEW record is a genuine first occurrence.
        if (seeding) {
          await appendEvent(env, {
            workspace_id, record_id: id, event_type: WS_EVENT_BASELINE,
            detail: { reason: "pre_existing_at_baseline", condition_key: key, recurrence, band, entity: domain, scan_id },
          }).catch(() => {});
          continue;
        }
        if (status === "observed") {
          await appendEvent(env, {
            workspace_id, record_id: id, event_type: MONITORING_CHANGED,
            detail: {
              ...buildMonitoringTransitionDetail({
                from_monitoring_status: null, to_monitoring_status: "observed",
                from_recurrence_type: null, to_recurrence_type: recurrence,
                required_case_action: "open_or_reopen", reason: "condition_first_observed",
                entity: domain,
              }),
              recurrence_band: band, condition_key: key, scan_id, hostname: domain,
            },
          }).catch(() => {});
          transitions++;
          // The case BEFORE the alert: an alert that names a case must be able to link to
          // one, so the case has to exist by the time the alert is built.
          const opened = await openWebsiteCase(env, {
            workspace_id, record_id: id, entity: `${domain}:${key}`, domain,
            recurrence, condition_key: key, severity: obs.severity, scan_id,
          });
          const r = await emitLifecycleAlert(env, {
            workspace_id, domain_key: WEBSITE_SECURITY_DOMAIN_KEY,
            record_id: id, entity: `${domain}:${key}`, hostname: domain,
            recurrence, record_severity: obs.severity, finding_type: key,
            case_id: opened?.case_id || null,
            module_evidence: modules?.[spec.module] || null,
          }).catch(() => null);
          if (r?.emitted) alerts++;
        }
        continue;
      }

      // ── Update an existing record ──────────────────────────────────────────
      // monitoring_status is DERIVED from whether the CONDITION moved — never
      // computed independently. A baselined record that flipped baseline→observed
      // while the condition was identical would read as a transition and release the
      // whole backlog one pass later (the PR-B3 pass-two trap).
      const conditionChanged =
        String(rec.recurrence_type ?? "") !== String(recurrence ?? "")
        || String(rec.recurrence_band ?? "") !== String(band ?? "");
      const wasBaseline = rec.monitoring_status === "baseline";
      const nextStatus = (wasBaseline && !conditionChanged) ? "baseline" : status;

      const prev = {
        monitoring_status: rec.monitoring_status,
        recurrence_type: rec.recurrence_type,
        recurrence_band: rec.recurrence_band,
      };
      const next = { monitoring_status: nextStatus, recurrence_type: recurrence, recurrence_band: band };

      await env.cybermeters_db
        .prepare(`UPDATE website_security_conditions
             SET observed_severity = ?, observed_title = ?, last_scan_id = ?, last_scan_quality = ?,
                 last_seen_at = CASE WHEN ? = 'observed' THEN datetime('now') ELSE last_seen_at END,
                 last_changed_at = CASE WHEN ? = 1 THEN datetime('now') ELSE last_changed_at END,
                 monitoring_status = ?, monitoring_reason = ?, unknown_reason = ?,
                 recurrence_type = ?, recurrence_band = ?, updated_at = datetime('now'),
                 evaluated_at = datetime('now')
           WHERE id = ?`)
        .bind(obs?.severity ?? rec.observed_severity, obs?.title ?? rec.observed_title,
              scan_id ?? rec.last_scan_id, quality,
              nextStatus, conditionChanged ? 1 : 0,
              nextStatus, reason, unknown_reason, recurrence, band, rec.id)
        .run().catch(() => {});

      if (!isMonitoringTransition(prev, next)) continue;

      // ── A real transition. Which KIND decides whether it can alert. ─────────
      if (nextStatus === "no_longer_observed") {
        // Recovery: history, never an alert. No customer action is required, so
        // there is nothing to tell them to do. Structurally unalertable.
        await appendEvent(env, {
          workspace_id, record_id: rec.id, event_type: WS_EVENT_RESOLVED,
          detail: { reason, condition_key: key, from_recurrence_type: rec.recurrence_type, entity: domain, scan_id, verified_by_module: spec.module },
        }).catch(() => {});
        // The ONE system verifier for this domain. `module_assessed` is passed explicitly
        // rather than inferred: this branch is reachable only through gate.canVerify(), and
        // saying so out loud is what lets the case layer refuse on its own evidence instead
        // of trusting the branch it was called from.
        await verifyWebsiteCaseFromResolution(env, {
          workspace_id, record_id: rec.id, recovery_event_type: WS_EVENT_RESOLVED,
          module_assessed: gate.canVerify(spec.module), detecting_module: spec.module, scan_id,
        }).catch(() => {});
        resolved++;
        continue;
      }
      if (nextStatus === "unknown") {
        // We stopped being able to see it. History, never an alert, and NEVER a fix.
        await appendEvent(env, {
          workspace_id, record_id: rec.id, event_type: WS_EVENT_UNKNOWN,
          detail: { reason, unknown_reason, condition_key: key, from_recurrence_type: rec.recurrence_type, entity: domain, scan_id },
        }).catch(() => {});
        unknown++;
        continue;
      }
      if (nextStatus === "baseline") continue;   // still pre-existing, still silent

      // observed: first appearance after a recovery, or a worsened grade.
      await appendEvent(env, {
        workspace_id, record_id: rec.id, event_type: MONITORING_CHANGED,
        detail: {
          ...buildMonitoringTransitionDetail({
            from_monitoring_status: rec.monitoring_status ?? null, to_monitoring_status: "observed",
            from_recurrence_type: rec.recurrence_type ?? null, to_recurrence_type: recurrence,
            required_case_action: "open_or_reopen",
            reason: prev.monitoring_status === "no_longer_observed" ? "condition_reappeared" : "condition_changed",
            entity: domain,
          }),
          recurrence_band: band, from_recurrence_band: rec.recurrence_band ?? null,
          condition_key: key, scan_id, hostname: domain,
        },
      }).catch(() => {});
      transitions++;
      // Reappearance after a recovery reopens the canonical case; a worsened grade notes the
      // recurrence on the open one. Either way the case is resolved BEFORE the alert, so the
      // link is the case that exists now — not the stale pointer on the row we read.
      const opened = await openWebsiteCase(env, {
        workspace_id, record_id: rec.id, entity: `${domain}:${key}`, domain,
        recurrence, condition_key: key, severity: obs.severity, scan_id,
      });
      const r = await emitLifecycleAlert(env, {
        workspace_id, domain_key: WEBSITE_SECURITY_DOMAIN_KEY,
        record_id: rec.id, entity: `${domain}:${key}`, hostname: domain,
        recurrence, record_severity: obs.severity, finding_type: key,
        case_id: opened?.case_id || rec.linked_case_id || null,
        module_evidence: modules?.[spec.module] || null,
      }).catch(() => null);
      if (r?.emitted) alerts++;
    }

    // Written LAST, and unconditionally — including when this pass found nothing.
    // Its absence is what defines a seeding pass, so a clean first scan must still
    // baseline the domain or the first condition to appear later would be re-seeded
    // instead of alerted.
    if (seeding) {
      await appendEvent(env, {
        workspace_id, record_id: domain_id, event_type: WS_EVENT_DOMAIN_BASELINE,
        detail: { reason: "first_evaluation", entity: domain, scan_id, baselined_conditions: created, scan_quality: quality },
      }).catch(() => {});
    }

    return { evaluated: keys.size, created, transitions, alerts, resolved, unknown, seeding };
  } catch (err) {
    console.error("[website-security-lifecycle] evaluation failed", JSON.stringify({
      workspace_id, domain_id, reason: err?.message,
    }));
    return { skipped: "evaluator_error" };
  }
}

// ── Read accessors — the customer-facing shape ──────────────────────────────
// These existed with ZERO callers: mig 089 persisted durable identity and history that
// no route, page or API method ever read, so a customer could be alerted about a
// condition they had no way to open. Wiring them up meant fixing them first — as
// written they were `SELECT *` with no bound and a non-deterministic order.
//
// What a customer is allowed to see is decided HERE, once, rather than in each route:
//   • internal-only stays internal — `evaluated_at` is diagnostic (mig 089:123-126),
//     `domain_id` is a surrogate the customer never types, `lifecycle_state` is
//     vestigial (written at INSERT, never updated), and `recurrence_type`/`_band` are
//     alert plumbing;
//   • the honesty fields DO ship — monitoring_status, unknown_reason, last_scan_quality
//     and detecting_module are the difference between "we fixed it" and "we did not
//     look", and a surface without them would be free to imply the former.
//
// `linked_case_id` is exposed but is ALWAYS null today: nothing writes it (the INSERT
// omits it and the UPDATE set-list omits it), and no case is created for this domain.
// It is serialised so the shape does not change when case creation lands, and the API
// must not imply a case exists because the field is present.
export function websiteSecurityConditionToApi(row = {}) {
  return {
    id: row.id,
    domain: row.domain,
    condition_key: row.condition_key,
    title: row.observed_title ?? null,
    severity: row.observed_severity ?? null,
    // State + why. `unknown` is NOT recovery (mig 089:98-106) and the reason says which
    // kind of not-knowing it is.
    monitoring_status: row.monitoring_status ?? null,
    monitoring_reason: row.monitoring_reason ?? null,
    unknown_reason: row.unknown_reason ?? null,
    // Evidence provenance + completeness. A condition graded off a partial scan must
    // never read as settled.
    detecting_module: row.detecting_module ?? null,
    last_scan_id: row.last_scan_id ?? null,
    last_scan_quality: row.last_scan_quality ?? null,
    first_seen_at: row.first_seen_at ?? null,
    last_seen_at: row.last_seen_at ?? null,
    last_changed_at: row.last_changed_at ?? null,
    linked_case_id: row.linked_case_id ?? null,
  };
}

export function websiteSecurityEventToApi(row = {}) {
  let detail = null;
  try { detail = row.detail_json ? JSON.parse(row.detail_json) : null; } catch { detail = null; }
  return {
    id: row.id,
    event_type: row.event_type,
    actor_type: row.actor_type ?? null,
    created_at: row.created_at,
    detail,
  };
}

// Tenant-scoped by construction. BOUNDED: an unbounded read is a promise that a
// workspace never accumulates conditions, and this table grows with every domain ×
// every header. DETERMINISTIC: `last_seen_at DESC` alone ties on every condition seen
// in the same scan — which is all of them — so the tie-break is what makes a list
// stable enough to paginate.
export async function listWebsiteSecurityConditions(env, workspaceId, {
  domainId = null, monitoring_status = null, severity = null, limit = 50, offset = 0,
} = {}) {
  const where = ["workspace_id = ?"];
  const binds = [workspaceId];
  if (domainId) { where.push("domain_id = ?"); binds.push(domainId); }
  if (monitoring_status) { where.push("monitoring_status = ?"); binds.push(String(monitoring_status)); }
  if (severity) { where.push("observed_severity = ?"); binds.push(String(severity)); }
  const rows = await env.cybermeters_db
    .prepare(`SELECT * FROM website_security_conditions
              WHERE ${where.join(" AND ")}
              ORDER BY last_seen_at DESC, id ASC
              LIMIT ? OFFSET ?`)
    .bind(...binds, Number(limit), Number(offset))
    .all().catch(() => ({ results: [] }));
  return (rows.results || []).map(websiteSecurityConditionToApi);
}

export async function countWebsiteSecurityConditions(env, workspaceId, {
  domainId = null, monitoring_status = null, severity = null,
} = {}) {
  const where = ["workspace_id = ?"];
  const binds = [workspaceId];
  if (domainId) { where.push("domain_id = ?"); binds.push(domainId); }
  if (monitoring_status) { where.push("monitoring_status = ?"); binds.push(String(monitoring_status)); }
  if (severity) { where.push("observed_severity = ?"); binds.push(String(severity)); }
  const row = await env.cybermeters_db
    .prepare(`SELECT COUNT(*) AS n FROM website_security_conditions WHERE ${where.join(" AND ")}`)
    .bind(...binds).first().catch(() => null);
  return Number(row?.n ?? 0);
}

export async function getWebsiteSecurityCondition(env, workspaceId, recordId) {
  const row = await env.cybermeters_db
    .prepare(`SELECT * FROM website_security_conditions WHERE workspace_id = ? AND id = ?`)
    .bind(workspaceId, recordId).first().catch(() => null);
  return row ? websiteSecurityConditionToApi(row) : null;
}

export async function listWebsiteSecurityEvents(env, workspaceId, recordId, { limit = 200 } = {}) {
  const rows = await env.cybermeters_db
    .prepare(`SELECT * FROM website_security_events
              WHERE workspace_id = ? AND record_id = ?
              ORDER BY created_at DESC, rowid DESC
              LIMIT ?`)
    .bind(workspaceId, recordId, Number(limit)).all().catch(() => ({ results: [] }));
  return (rows.results || []).map(websiteSecurityEventToApi);
}
