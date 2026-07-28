// ── Workspace intelligence routes ──
// Read-only identity-asset / vendor-relationship / supply-chain endpoints.
// Extracted near-verbatim from index.js (router split, Phase 2 PR #2).
// Receives the per-request routeCtx from index.js; returns a Response when a
// route matches, or null so the main router continues.
import { computeSupplyChainIntelligence } from "../engines/supply-chain.js";
import { computeIdentityExposure } from "../engines/identity-exposure.js";
import { getEffectivePlan, hasFeatureEntitlement } from "../engines/entitlements.js";

export async function workspaceIntelRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId } = rctx;
    // ── Identity Asset Discovery Routes ─────────────────────────────────────
    // GET /api/workspaces/:id/identity-assets         — full inventory
    // GET /api/workspaces/:id/identity-assets/summary — aggregated counts

    const identityListMatch    = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/identity-assets$/);
    const identitySummaryMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/identity-assets\/summary$/);

    // GET /api/workspaces/:id/identity-exposure — consolidated Identity Exposure
    // (exposed login surfaces + active impersonation infra + email spoofing).
    const identityExposureMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/identity-exposure$/);
    if (identityExposureMatch && request.method === "GET") {
      const wsId = identityExposureMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const exposure = await computeIdentityExposure(env, wsId);
        return json({ workspace_id: wsId, ...exposure, generated_at: new Date().toISOString() });
      } catch (err) {
        return serverError("api", err);
      }
    }

    if ((identityListMatch || identitySummaryMatch) && request.method === "GET") {
      const wsId = (identityListMatch ?? identitySummaryMatch)[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      const ws = await env.cybermeters_db
        .prepare(`SELECT id, name FROM workspaces WHERE id = ?`).bind(wsId).first();
      if (!ws) return json({ error: "Workspace not found" }, 404);

      if (identitySummaryMatch) {
        try {
          const [totalRow, typeRows, providerRows, highRiskRow] = await env.cybermeters_db.batch([
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active'`)
              .bind(wsId),
            env.cybermeters_db
              .prepare(`SELECT identity_type, COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active' GROUP BY identity_type`)
              .bind(wsId),
            env.cybermeters_db
              .prepare(`SELECT provider, COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active' AND provider IS NOT NULL GROUP BY provider ORDER BY n DESC`)
              .bind(wsId),
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM identity_assets WHERE workspace_id = ? AND status = 'active' AND risk_score >= 15`)
              .bind(wsId),
          ]);
          return json({
            workspace_id:       wsId,
            total:              totalRow.n ?? 0,
            high_risk_count:    highRiskRow.n ?? 0,
            by_type:            Object.fromEntries((typeRows.results ?? []).map(r => [r.identity_type, r.n])),
            providers_detected: (providerRows.results ?? []).map(r => ({ provider: r.provider, count: r.n })),
            generated_at:       new Date().toISOString(),
          });
        } catch (err) {
          return serverError("identity/summary", err, "Identity summary could not be loaded.");
        }
      }

      // Full list
      try {
        const filterType     = url.searchParams.get("identity_type");
        const filterProvider = url.searchParams.get("provider");
        const filterRisk     = url.searchParams.get("min_risk_score");

        let query = `SELECT * FROM identity_assets WHERE workspace_id = ? AND status = 'active'`;
        const params = [wsId];
        if (filterType)     { query += ` AND identity_type = ?`;  params.push(filterType); }
        if (filterProvider) { query += ` AND provider = ?`;       params.push(filterProvider); }
        if (filterRisk)     { query += ` AND risk_score >= ?`;    params.push(parseInt(filterRisk, 10) || 0); }
        query += ` ORDER BY risk_score DESC, first_seen DESC LIMIT 200`;

        const rows = await env.cybermeters_db.prepare(query).bind(...params).all();
        const assets = (rows.results ?? []).map(r => ({
          id:               r.id,
          hostname:         r.hostname,
          asset_type:       r.asset_type,
          identity_type:    r.identity_type,
          provider:         r.provider,
          internet_exposed: r.internet_exposed === 1,
          source:           r.source,
          risk_score:       r.risk_score,
          evidence:         r.evidence ? (() => { try { return JSON.parse(r.evidence); } catch { return []; } })() : [],
          first_seen:       r.first_seen,
          last_seen:        r.last_seen,
        }));

        return json({
          workspace_id:    wsId,
          workspace_name:  ws.name,
          total:           assets.length,
          high_risk_count: assets.filter(a => a.risk_score >= 15).length,
          assets,
          generated_at:    new Date().toISOString(),
        });
      } catch (err) {
        return serverError("identity/assets", err, "Identity assets could not be loaded.");
      }
    }

    // ── Vendor Relationship Routes ────────────────────────────────────────────
    // GET /api/workspaces/:id/vendor-relationships
    //   Returns vendors detected via CSP/JS analysis (source_module='vendor_relationship').
    //   Supports ?category=analytics|payments|crm|support|identity|collaboration|cloud|cdn|security
    //             ?confidence=high|medium|low
    //   Returns: { workspace_id, total, high_confidence, by_category, vendors: [...] }
    const vendorRelMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/vendor-relationships$/);
    if (vendorRelMatch && request.method === "GET") {
      const wsId = vendorRelMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'vendor_risk')) {
          return json({ error: 'plan_feature_required', feature: 'vendor_risk', required_plan: 'professional', upgrade_url: '/billing' }, 403);
        }
      }

      const filterCat  = url.searchParams.get("category");
      const filterConf = url.searchParams.get("confidence");

      const whereClauses = ["workspace_id = ?", "source_module = 'vendor_relationship'", "status = 'active'"];
      const binds        = [wsId];
      if (filterCat)  { whereClauses.push("category = ?");    binds.push(filterCat); }
      if (filterConf) { whereClauses.push("confidence = ?");  binds.push(filterConf); }
      const whereSQL = whereClauses.join(" AND ");

      try {
        const r = await env.cybermeters_db
          .prepare(
            `SELECT vendor_name AS name, category, source, evidence, confidence,
                    risk_level, first_seen, last_seen
             FROM workspace_vendors
             WHERE ${whereSQL}
             ORDER BY
               CASE confidence WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
               CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
               category, vendor_name`
          )
          .bind(...binds)
          .all();

        const vendors = (r.results || []).map(row => ({
          name:       row.name,
          category:   row.category,
          source:     row.source,
          confidence: row.confidence,
          risk_level: row.risk_level,
          first_seen: row.first_seen,
          last_seen:  row.last_seen,
          source_signals: (() => { try { return JSON.parse(row.evidence); } catch { return []; } })(),
        }));

        const byCategory = {};
        for (const v of vendors) {
          byCategory[v.category] = (byCategory[v.category] || 0) + 1;
        }
        const highConfidence = vendors.filter(v => v.confidence === "high").length;

        return json({
          workspace_id:    wsId,
          total:           vendors.length,
          high_confidence: highConfidence,
          by_category:     byCategory,
          vendors,
          generated_at:    new Date().toISOString(),
        });
      } catch (err) {
        return serverError("vendor-relationships", err);
      }
    }

    // GET /api/workspaces/:id/supply-chain
    //   Returns supply chain intelligence projected against the current
    //   canonical BRS assessment. A legacy persisted composite cannot be
    //   returned directly because its complete BRS basis may be unprovable.
    //   Returns: { supply_chain_score, operational_resilience_score, concentration_level,
    //              critical_vendor_count, tier1_count, tier2_count, tier3_count, spof_count,
    //              critical_vendors, dependency_graph, cascading_risks, concentration,
    //              compliance_readiness, asm_maturity, vendor_summary, brs_score, calculated_at }
    const supplyChainMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/supply-chain$/);
    if (supplyChainMatch && request.method === 'GET') {
      const wsId = supplyChainMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: 'Unauthorized' }, 401);
      const access = await requireWorkspaceRole(user, wsId, 'workspace:read', env);
      if (!access) return json({ error: 'Forbidden' }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'vendor_risk')) {
          return json({ error: 'plan_feature_required', feature: 'vendor_risk', required_plan: 'professional', upgrade_url: '/billing' }, 403);
        }
      }

      try {
        // Recompute the read projection from D1-only sibling evidence and the
        // canonical BRS resolver. This masks pre-contract persisted numbers as
        // soon as their BRS basis becomes incomplete or unprovable.
        const payload = await computeSupplyChainIntelligence(wsId, env);
        if (!payload) return json({ error: 'No supply chain data available. Run a scan first.' }, 404);
        return json(payload);
      } catch (err) {
        console.error('[supply-chain] GET error:', err);
        return json({ error: 'Internal server error' }, 500);
      }
    }

  return null;
}
