// ── Universal managed-cases routes ─────────────────────────────────────────
// One cross-domain case surface over the shared managed_cases table. Read
// endpoints fold every case_type onto its canonical phase so a single queue can
// render all eight Cyber MOT domains. The transition endpoint routes EVERY change
// through the universal validator canTransitionCase — no bypass. The rich,
// domain-specific ASM (/managed-cases) and Brand (/brand/cases) routes remain the
// place to drive their bespoke side effects (owner assignment, evidence bundles,
// takedown submission, product verification); this generic transition covers the
// base-lifecycle domains and any generic edge.
import {
  assignCaseOwner, canTransitionCase, canonicalPhaseFor, caseTypeEntry, CASE_TYPE_REGISTRY,
  CANONICAL_DOMAIN_KEYS, isValidDomainKey, createManagedCase,
  verificationSupportForCase,
} from "../engines/managed-case-model.js";
import { newCaseEventId } from "../engines/case-workflow.js";
import { parseBoundedInteger } from "../lib/util.js";

// Customer-safe projection of a case row + its canonical phase.
function caseToUniversalApi(row) {
  return {
    case_id: row.id,
    workspace_id: row.workspace_id,
    domain_key: row.domain_key || caseTypeEntry(row.case_type)?.domain_key || null,
    case_type: row.case_type,
    status: row.status,
    canonical_phase: canonicalPhaseFor(row.case_type, row.status),
    // How this case may EVER be concluded, from its own canonical remediation (PR #129).
    // The frontend needs it because "verified" means two different things to a customer:
    // CyberMeters re-observed the fix, or the customer said so and we cannot see it. Only
    // the backend may decide which — a screen that inferred it would be deriving a
    // verification verdict, and coverage-state semantics belong to the resolver.
    verification_support: verificationSupportForCase(row),
    status_reason: row.reason ?? null,
    title: row.title ?? null,
    summary: row.summary ?? null,
    severity: row.severity ?? null,
    priority: row.priority ?? null,
    domain: row.domain ?? null,
    asset_ref: row.asset_ref ?? null,
    source_finding_type: row.source_finding_type ?? row.finding_id ?? null,
    source_finding_id: row.finding_id ?? null,
    source_scan_id: row.source_scan_id ?? null,
    remediation_id: row.remediation_id ?? null,
    assigned_user_id: row.assigned_user_id ?? null,
    owner_type: row.owner_type ?? null,
    owner_ref: row.owner_ref ?? null,
    business_owner: row.business_owner ?? null,
    technical_owner: row.technical_owner ?? null,
    due_at: row.due_at ?? null,
    reopened_count: row.reopened_count ?? 0,
    created_at: row.created_at ?? null,
    updated_at: row.updated_at ?? null,
    verified_at: row.verified_at ?? null,
    closed_at: row.closed_at ?? null,
  };
}

// Workspace-scoped case load. Returns null for BOTH a foreign-existing and a
// nonexistent case (no cross-tenant existence oracle) — the caller maps null to
// the SAME 404 that a nonexistent id returns.
async function loadCase(env, wsId, caseId) {
  return env.cybermeters_db
    .prepare(`SELECT * FROM managed_cases WHERE id = ? AND workspace_id = ?`)
    .bind(caseId, wsId).first().catch(() => null);
}

export async function managedCasesRoutes(rctx) {
  const { request, env, url, json, requireAuth, requireWorkspaceRole } = rctx;

  const m = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/cases(?:\/([^/]+)(?:\/([^/]+))?)?$/);
  if (!m) return null;
  const wsId = m[1];
  const caseId = m[2] || null;
  const action = m[3] || null;

  const user = await requireAuth(request, env);
  if (!user) return json({ error: "Unauthorized" }, 401);
  const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
  const access = await requireWorkspaceRole(user, wsId, permission, env);
  if (!access) return json({ error: "Forbidden" }, 403);

  // Existence check AFTER authz, and gated on soft-delete: a deleted workspace
  // behaves like a nonexistent one.
  const ws = await env.cybermeters_db
    .prepare(`SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
    .bind(wsId).first().catch(() => null);
  if (!ws) return json({ error: "Workspace not found" }, 404);

  // ── GET /cases — cross-domain queue ──────────────────────────────────────
  if (request.method === "GET" && !caseId) {
    try {
      const where = ["workspace_id = ?"];
      const binds = [wsId];
      const domainKey = url.searchParams.get("domain_key");
      if (domainKey) {
        if (!isValidDomainKey(domainKey)) return json({ error: "Unknown domain_key" }, 400);
        where.push("domain_key = ?"); binds.push(domainKey);
      }
      const caseType = url.searchParams.get("case_type");
      if (caseType) { where.push("case_type = ?"); binds.push(caseType); }
      const status = url.searchParams.get("status");
      if (status) { where.push("status = ?"); binds.push(status); }
      const limit = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200);
      const rows = await env.cybermeters_db
        .prepare(`SELECT * FROM managed_cases WHERE ${where.join(" AND ")} ORDER BY created_at DESC LIMIT ?`)
        .bind(...binds, limit).all();
      const cases = (rows.results || []).map(caseToUniversalApi);
      return json({ workspace_id: wsId, domain_keys: CANONICAL_DOMAIN_KEYS, count: cases.length, cases });
    } catch {
      return json({ error: "Database error" }, 500);
    }
  }

  // ── POST /cases — create a base-lifecycle case via the common factory ────
  if (request.method === "POST" && !caseId) {
    let body = {};
    try { body = await request.json(); } catch { body = {}; }
    const entry = caseTypeEntry(body.case_type);
    // The generic factory is for the six base-lifecycle domains; ASM/Brand cases
    // are opened by their own engines (bespoke dedup/evidence).
    if (!entry) return json({ error: "invalid_case_type" }, 400);
    if (!entry.base) return json({ error: "Use the domain-specific flow for this case type." }, 409);
    const result = await createManagedCase(env, {
      workspace_id: wsId,
      domain_key: body.domain_key,
      case_type: body.case_type,
      source_finding_type: body.source_finding_type ?? null,
      source_finding_id: body.source_finding_id ?? null,
      source_scan_id: body.source_scan_id ?? null,
      domain: body.domain ?? null,
      asset_ref: body.asset_ref ?? null,
      title: body.title ?? null,
      summary: body.summary ?? null,
      severity: body.severity ?? "medium",
      priority: body.priority ?? null,
      actor: { actor_type: "customer", actor_id: user.id },
    });
    if (!result.ok) {
      const status = result.code === "workspace_inactive" || result.code === "domain_ineligible" ? 404
        : result.code === "domain_case_type_mismatch" || result.code === "invalid_domain_key" || result.code === "invalid_case_type" ? 400 : 409;
      return json({ error: result.code }, status);
    }
    return json({ case: caseToUniversalApi(result.case), created: result.created }, result.created ? 201 : 200);
  }

  if (!caseId) return json({ error: "Not found" }, 404);
  const row = await loadCase(env, wsId, caseId);
  if (!row) return json({ error: "Case not found" }, 404); // same error for foreign + nonexistent

  // ── GET /cases/:caseId — single case + append-only history ───────────────
  if (request.method === "GET" && !action) {
    const events = await env.cybermeters_db
      .prepare(`SELECT id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at
                FROM managed_case_events WHERE workspace_id = ? AND case_id = ? ORDER BY created_at ASC`)
      .bind(wsId, caseId).all().catch(() => ({ results: [] }));
    return json({ case: caseToUniversalApi(row), events: events.results || [] });
  }

  // ── POST /cases/:caseId/assign — canonical ownership assignment (M5.e) ───
  // One assignment path for EVERY case type (Brand included). Tenant-authorized
  // above; persists atomically + appends assignment_changed; empty owner is
  // refused, never fabricated.
  if (request.method === "POST" && action === "assign") {
    let body = {};
    try { body = await request.json(); } catch { body = {}; }
    const res = await assignCaseOwner(env, row, {
      owner_type: body.owner_type,
      owner_ref: body.owner_ref,
      actor_type: "customer",
      actor_id: user.id,
      assigned_user_id: body.assigned_user_id ?? null,
    });
    if (!res.ok) return json({ error: res.error, code: res.code }, res.code === "owner_ref_required" ? 400 : 404);
    return json({ case: caseToUniversalApi(res.case) });
  }

  // ── POST /cases/:caseId/transition — the ONLY generic mutation path ──────
  if (request.method === "POST" && action === "transition") {
    const entry = caseTypeEntry(row.case_type);
    if (!entry) return json({ error: "Unknown case type" }, 409);
    // ASM/Brand keep their bespoke transition endpoints (with domain-specific
    // side effects); the generic path handles the base-lifecycle domains.
    if (!entry.base) {
      return json({ error: "Use the domain-specific case endpoint for this case type.", case_type: row.case_type }, 409);
    }
    let body = {};
    try { body = await request.json(); } catch { body = {}; }
    const target = String(body.target_status || body.status || "");
    if (!target) return json({ error: "target_status is required" }, 400);

    const decision = canTransitionCase({
      case: row,
      target_status: target,
      actor: { actor_type: "customer", actor_id: user.id },
      evidence: body.evidence ?? null,
      reason: body.reason ?? null,
      risk_accepted_until: body.risk_accepted_until ?? null,
      owner_ref: body.owner_ref ?? null,
      owner_type: body.owner_type ?? null,
      assigned_user_id: body.assigned_user_id ?? null,
      actor_id: user.id,
    });
    if (!decision.ok) {
      const code = decision.code === "system_only" || decision.code === "verify_requires_system" ? 403 : 409;
      return json({ error: decision.error, code: decision.code }, code);
    }
    const next = decision.case;
    try {
      await env.cybermeters_db
        .prepare(`UPDATE managed_cases SET
            status = ?, reason = ?, risk_accepted_until = ?, updated_at = ?,
            approved_at = ?, action_started_at = ?, awaiting_verification_at = ?,
            verified_at = ?, monitoring_started_at = ?, reopened_at = ?,
            accepted_at = ?, closed_at = ?, reopened_count = ?,
            owner_type = ?, owner_ref = ?, assigned_by = ?, assigned_user_id = ?
          WHERE id = ? AND workspace_id = ? AND status = ?`)
        .bind(
          next.status, next.reason ?? null, next.risk_accepted_until ?? null, next.updated_at,
          next.approved_at ?? null, next.action_started_at ?? null, next.awaiting_verification_at ?? null,
          next.verified_at ?? null, next.monitoring_started_at ?? null, next.reopened_at ?? null,
          next.accepted_at ?? null, next.closed_at ?? null, Number(next.reopened_count || 0),
          // Ownership persists atomically with the transition (M5.e) — the
          // `assigned` guard requires it, and it survives every later step.
          next.owner_type ?? null, next.owner_ref ?? null, next.assigned_by ?? null, next.assigned_user_id ?? null,
          row.id, wsId, row.status, // CAS on the observed status — concurrent change loses
        ).run();
      // Append-only history event (never updates/deletes a prior row).
      if (next.owner_ref && next.owner_ref !== row.owner_ref) {
        await env.cybermeters_db
          .prepare(`INSERT INTO managed_case_events
              (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
          .bind(newCaseEventId(), row.id, wsId, "customer", user.id,
                row.status, next.status, "assignment_changed",
                JSON.stringify({ owner_type: next.owner_type ?? null, owner_ref: next.owner_ref, assigned_user_id: next.assigned_user_id ?? null }))
          .run();
      }
      const ev = decision.event;
      await env.cybermeters_db
        .prepare(`INSERT INTO managed_case_events
            (id, case_id, workspace_id, actor_type, actor_id, from_status, to_status, action, detail_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`)
        .bind(newCaseEventId(), ev.case_id, ev.workspace_id, ev.actor_type, ev.actor_id,
          ev.from_status, ev.to_status, ev.action, ev.detail_json).run();
    } catch {
      return json({ error: "Database error" }, 500);
    }
    return json({ case: caseToUniversalApi(next), canonical_phase: decision.canonical_phase });
  }

  return json({ error: "Not found" }, 404);
}
