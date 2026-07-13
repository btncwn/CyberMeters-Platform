// ── Managed DMARC change-workflow state machine + analyst review queue ──
//
// Level 3 "Premium Managed" governance layer. The hosted autopilot already runs
// a technical saga (Prepare→Execute→Verify→Commit) over hosted_dns_entries;
// THIS is the human-facing change-management layer that sits in front of it: a
// proposed policy change becomes a reviewable request that an analyst must
// approve before it executes, with an explicit, guarded state machine and a
// separation-of-duties rule (the approver may not be the requester).
//
// Purely additive — it does not alter the autopilot. A change request is a
// record of intent + governance; nothing here mutates DNS. All enums live in
// code (no CHECK constraints), matching the hosted-dns-v2 convention.
//
// Every function here is pure except newChangeRequestId's id shape; persistence
// and routing live in the route/index layer so the state machine stays testable.

export const CHANGE_STATES = [
  "draft",          // created, not yet submitted for review
  "pending_review", // submitted — sitting in the analyst queue
  "approved",       // an analyst approved it; ready to execute
  "scheduled",      // approved + a scheduled execution time set
  "applying",       // execution in flight (handed to the hosted saga)
  "verifying",      // applied to DNS; impact being monitored
  "completed",      // verified healthy — terminal success
  "rejected",       // an analyst declined it — terminal
  "rolled_back",    // apply failed or a regression was detected — terminal
  "cancelled",      // the requester withdrew it — terminal
];

export const TERMINAL_CHANGE_STATES = new Set(["completed", "rejected", "rolled_back", "cancelled"]);

// Allowed edges. A missing/terminal state maps to an empty set.
export const CHANGE_TRANSITIONS = {
  draft:          ["pending_review", "cancelled"],
  pending_review: ["approved", "rejected", "cancelled"],
  approved:       ["scheduled", "applying", "cancelled"],
  scheduled:      ["applying", "cancelled"],
  applying:       ["verifying", "rolled_back"],
  verifying:      ["completed", "rolled_back"],
  completed:      [],
  rejected:       [],
  rolled_back:    [],
  cancelled:      [],
};

export function isTerminalChangeState(state) {
  return TERMINAL_CHANGE_STATES.has(state);
}

export function canTransitionChange(from, to) {
  return (CHANGE_TRANSITIONS[from] || []).includes(to);
}

export function newChangeRequestId() {
  // 'cr-' + 12 hex. crypto.randomUUID is available in the Workers runtime.
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return "cr-" + (uuid || "").slice(0, 12).padEnd(12, "0");
}

// Guarded transition. Returns { ok, request } on success, { ok:false, error } on
// a rejected transition. Never mutates the input — returns a new object.
//   request : the current change-request record (needs at least { state, requested_by })
//   to      : target state
//   ctx     : { actor, reason, scheduled_at, now } — now is an ISO string
export function applyChangeTransition(request, to, ctx = {}) {
  if (!request || typeof request !== "object") return { ok: false, error: "No change request provided." };
  const from = request.state;
  if (isTerminalChangeState(from)) {
    return { ok: false, error: `This change request is already ${from} and cannot change.` };
  }
  if (!CHANGE_STATES.includes(to)) return { ok: false, error: `Unknown target state "${to}".` };
  if (!canTransitionChange(from, to)) {
    return { ok: false, error: `Cannot move a change request from ${from} to ${to}.` };
  }

  const now = ctx.now || new Date().toISOString();
  const actor = ctx.actor || null;
  const next = { ...request, state: to, updated_at: now };

  // Guard: analyst approval requires separation of duties.
  if (to === "approved") {
    if (!actor) return { ok: false, error: "An approving analyst is required." };
    if (actor === request.requested_by) {
      return { ok: false, error: "The analyst who approves a change must be different from the one who requested it." };
    }
    next.reviewed_by = actor;
    next.reviewed_at = now;
  }

  // Guard: a rejection or rollback must carry a reason (auditability).
  if (to === "rejected" || to === "rolled_back") {
    const reason = (ctx.reason || "").trim();
    if (!reason) return { ok: false, error: `A reason is required to ${to === "rejected" ? "reject" : "roll back"} a change request.` };
    next.reason = reason;
    if (to === "rejected") { next.reviewed_by = actor; next.reviewed_at = now; }
  }

  // Guard: scheduling needs a target time.
  if (to === "scheduled") {
    if (!ctx.scheduled_at) return { ok: false, error: "A scheduled execution time is required." };
    next.scheduled_at = ctx.scheduled_at;
  }

  if (to === "applying") next.applied_at = now;

  return { ok: true, request: next };
}

// Analyst review queue — the pending_review items an analyst must action, FIFO
// (oldest first) so nothing is starved, with an age in hours for triage. Callers
// pass already-tenant-scoped rows; this does the workflow-shaped filtering.
export function buildChangeReviewQueue(rows = [], { now } = {}) {
  const nowMs = now ? Date.parse(now) : Date.now();
  return rows
    .filter((r) => r.state === "pending_review")
    .map((r) => {
      const createdMs = r.created_at ? Date.parse(r.created_at) : nowMs;
      const ageHours = Number.isFinite(createdMs) ? Math.max(0, Math.round((nowMs - createdMs) / 3600000)) : 0;
      return { ...changeRequestToApi(r), age_hours: ageHours };
    })
    .sort((a, b) => (b.age_hours - a.age_hours)); // oldest (largest age) first
}

// Safe API serialisation — parses the evidence snapshot JSON defensively and
// never leaks internal-only columns.
export function changeRequestToApi(row = {}) {
  let evidence = null;
  try {
    evidence = typeof row.evidence_snapshot === "string"
      ? (row.evidence_snapshot ? JSON.parse(row.evidence_snapshot) : null)
      : (row.evidence_snapshot || null);
  } catch { evidence = null; }
  return {
    id: row.id,
    domain: row.domain,
    record_kind: row.record_kind || "dmarc",
    state: row.state,
    from_policy: row.from_policy || null,
    to_policy: row.to_policy || null,
    from_value: row.from_value || null,
    to_value: row.to_value || null,
    reason: row.reason || null,
    requested_by: row.requested_by || null,
    reviewed_by: row.reviewed_by || null,
    reviewed_at: row.reviewed_at || null,
    scheduled_at: row.scheduled_at || null,
    applied_at: row.applied_at || null,
    evidence,
    created_at: row.created_at || null,
    updated_at: row.updated_at || null,
    is_terminal: isTerminalChangeState(row.state),
  };
}
