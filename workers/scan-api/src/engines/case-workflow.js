// ── Generic managed-case workflow engine ───────────────────────────────────
// Pure, domain-agnostic state-machine runner for managed remediation cases.
// Case-type-specific modules provide states/transitions/guards; this module
// enforces edges, terminal immutability and reusable auditability guards.

export function newManagedCaseId() {
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return "mc-" + (uuid || "").slice(0, 12).padEnd(12, "0");
}

export function newCaseEventId() {
  const uuid = (globalThis.crypto?.randomUUID?.() || "").replace(/-/g, "");
  return "mce-" + (uuid || "").slice(0, 12).padEnd(12, "0");
}

export function createCaseMachine({ states = [], transitions = {}, terminals = [], guards = {} } = {}) {
  return {
    states: new Set(states),
    transitions,
    terminals: new Set(terminals),
    guards,
  };
}

export function canTransition(machineDef, from, to) {
  return Boolean((machineDef?.transitions?.[from] || []).includes(to));
}

export function isTerminal(machineDef, state) {
  return Boolean(machineDef?.terminals?.has ? machineDef.terminals.has(state) : machineDef?.terminals?.includes?.(state));
}

export function requireActor(ctx = {}) {
  return ctx.actor_id || ctx.actor ? true : "An actor is required.";
}

export function requireDifferentActor(field) {
  return (caseRecord = {}, ctx = {}) => {
    const actor = ctx.actor_id || ctx.actor || null;
    if (!actor) return "An actor is required.";
    if (caseRecord[field] && caseRecord[field] === actor) return "A different actor is required for this transition.";
    return true;
  };
}

export function requireReason(_caseRecord = {}, ctx = {}) {
  return String(ctx.reason || "").trim() ? true : "A reason is required.";
}

export function requireField(name) {
  return (caseRecord = {}, ctx = {}) => {
    const value = ctx[name] ?? caseRecord[name];
    return value ? true : `${name} is required.`;
  };
}

export function requireExpiry(_caseRecord = {}, ctx = {}) {
  const value = ctx.risk_accepted_until || ctx.expires_at || null;
  if (!value) return "An expiry date is required.";
  return Number.isFinite(Date.parse(value)) ? true : "A valid expiry date is required.";
}

function runGuards(machineDef, caseRecord, from, to, ctx) {
  const guards = machineDef?.guards?.[`${from}->${to}`] || machineDef?.guards?.[to] || [];
  for (const guard of guards) {
    const result = guard(caseRecord, ctx);
    if (result !== true) return result || "Transition guard failed.";
  }
  return true;
}

export function applyCaseTransition(machineDef, caseRecord, to, ctx = {}) {
  if (!caseRecord || typeof caseRecord !== "object") return { ok: false, error: "No case provided." };
  const from = caseRecord.status;
  if (isTerminal(machineDef, from)) return { ok: false, error: `Case is already ${from} and cannot change.` };
  if (!machineDef?.states?.has?.(to)) return { ok: false, error: `Unknown target state "${to}".` };
  if (!canTransition(machineDef, from, to)) return { ok: false, error: `Cannot move a case from ${from} to ${to}.` };

  const guard = runGuards(machineDef, caseRecord, from, to, ctx);
  if (guard !== true) return { ok: false, error: guard };

  const now = ctx.now || new Date().toISOString();
  const next = { ...caseRecord, status: to, updated_at: now };
  if (ctx.reason != null) next.reason = String(ctx.reason).trim() || null;
  if (ctx.risk_accepted_until != null) next.risk_accepted_until = ctx.risk_accepted_until;
  if (to === "resolved") next.resolved_at = now;
  if (to === "reopened") next.reopened_count = Number(caseRecord.reopened_count || 0) + 1;
  if (to === "verifying" || to === "resolved" || to === "verification_failed") next.last_verified_at = now;
  return { ok: true, case: next };
}

export function buildCaseQueue(rows = [], { now, statusFilter } = {}) {
  const nowMs = now ? Date.parse(now) : Date.now();
  return rows
    .filter((r) => !statusFilter || r.status === statusFilter)
    .map((r) => {
      const createdMs = r.created_at ? Date.parse(r.created_at) : nowMs;
      const ageHours = Number.isFinite(createdMs) ? Math.max(0, Math.round((nowMs - createdMs) / 3600000)) : 0;
      return { ...r, age_hours: ageHours };
    })
    .sort((a, b) => b.age_hours - a.age_hours);
}
