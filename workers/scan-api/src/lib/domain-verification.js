// ── Workspace-scoped domain-ownership verification ────────────────────────────
// The single source of truth for "has THIS workspace independently proven control
// of this domain?". Authority lives on the workspace_domains(workspace_id, domain_id)
// link (migration 079). The legacy domains.verification_* columns are read-only
// compatibility data and are NEVER consulted for scan authorization.

// Customer-safe rejection returned by every scan-start path for an unverified link.
export const DOMAIN_VERIFICATION_REQUIRED = Object.freeze({
  error:   "domain_verification_required",
  message: "Verify domain ownership before starting a Cyber MOT.",
});

// True ONLY when the exact (workspace_id, domain_id) link is 'verified'. Fails
// closed (returns false) on any error — an unreadable link is never scannable.
export async function isWorkspaceDomainVerified(env, workspaceId, domainId) {
  if (!workspaceId || !domainId) return false;
  try {
    const row = await env.cybermeters_db
      .prepare("SELECT verification_status FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?")
      .bind(workspaceId, domainId)
      .first();
    return row?.verification_status === "verified";
  } catch {
    return false;
  }
}

// Deterministic, workspace-explicit resolution for POST /api/domains/:id/verification
// and /verify. Prefers an explicit workspace_id; otherwise auto-resolves ONLY when the
// caller holds domain:verify on exactly one workspace linked to the domain (the
// single-workspace onboarding case). Ambiguous (multiple) → the caller must specify,
// so the verified relationship is never guessed. A denied/absent workspace returns the
// SAME 404 as a nonexistent domain (closes the cross-tenant existence oracle).
// Returns { workspace_id } on success, or { error, status[, code] } to return as-is.
export async function resolveVerificationWorkspace(user, domainId, explicitWorkspaceId, requireWorkspaceRole, env) {
  if (explicitWorkspaceId) {
    const link = await env.cybermeters_db
      .prepare("SELECT 1 AS ok FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?")
      .bind(explicitWorkspaceId, domainId).first().catch(() => null);
    if (!link) return { error: "Domain not found", status: 404 };
    const access = await requireWorkspaceRole(user, explicitWorkspaceId, "domain:verify", env);
    if (!access) return { error: "Domain not found", status: 404 };
    return { workspace_id: explicitWorkspaceId };
  }

  let rows;
  try {
    rows = await env.cybermeters_db
      .prepare("SELECT workspace_id FROM workspace_domains WHERE domain_id = ?")
      .bind(domainId).all();
  } catch {
    return { error: "Domain not found", status: 404 };
  }
  const candidates = [];
  for (const { workspace_id } of (rows.results || [])) {
    const access = await requireWorkspaceRole(user, workspace_id, "domain:verify", env);
    if (access) candidates.push(workspace_id);
  }
  if (candidates.length === 0) return { error: "Domain not found", status: 404 };
  if (candidates.length > 1) {
    return { error: "workspace_id is required — this domain is linked to multiple workspaces.", code: "workspace_id_required", status: 400 };
  }
  return { workspace_id: candidates[0] };
}
