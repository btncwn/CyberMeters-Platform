// ── Scan routes ──
// Scan start (quota-gated, runs the scan engine via waitUntil), scan
// list/detail/report/PDF/executive-report-v2, domain scan history and the
// scheduled-scan CRUD endpoints. Extracted near-verbatim from index.js
// (router split, Phase 2 PR #14). Receives the per-request routeCtx from
// index.js; returns a Response when a route matches, or null so the main
// router continues.
// M5.d: report render paths import NO calculation brains — assessment facts
// come from the canonical snapshot via readScanReportSnapshot. The remediation
// registry attach on /report is the one sanctioned presentation join (the
// registry is the canonical remediation source of truth).
import { getEffectivePlan } from "../engines/entitlements.js";
import { buildExecutiveReportV2 } from "../engines/executive-report.js";
import { applyEvidenceQuality, normalizeFindingSchema } from "../engines/findings.js";
import { buildScanReportPdf } from "../engines/pdf.js";
import { resolveReportBranding } from "../engines/report-branding.js";
import { prepareLogoXObject } from "../engines/pdf-image.js";
import { checkScanLimit, checkScheduledScanLimit, getAccountUsage, getEntitlementUsage, getPlanLimits, getWorkspaceBillingUserId, planLimitExceeded } from "../engines/plan-usage.js";
import { buildScanQuality, runScanEngine } from "../engines/scan-engine.js";
import { findingRemediation } from "../engines/remediation-registry.js";
import { readScanReportSnapshot } from "../engines/report-snapshot.js";
import { createAuditEvent } from "../lib/events.js";
import { DOMAIN_VERIFICATION_REQUIRED, isWorkspaceDomainVerified } from "../lib/domain-verification.js";
import { createId, isValidDomain, parseBoundedInteger } from "../lib/util.js";

export async function scanRoutes(rctx) {
  const { request, env, ctx, url, json, serverError, corsHeaders,
          requireAuth, requireWorkspaceRole, consumeApiRateLimit,
          requireScanReadAccess, getAccessibleWorkspaceIds, computeNextRunAt } = rctx;

    // ── POST /api/scan ──────────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/scan") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const domain = body.domain?.trim().toLowerCase();
      let workspaceId = body.workspace_id ? String(body.workspace_id).trim() : null;

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }
      if (!workspaceId) {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        for (const id of workspaceIds) {
          const access = await requireWorkspaceRole(user, id, "scan:create", env);
          if (access) {
            workspaceId = id;
            break;
          }
        }
        if (!workspaceId) {
          return json({ error: "No workspace available for scan creation" }, 403);
        }
      }

      const scanAccess = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
      if (!scanAccess) return json({ error: "Forbidden — analyst role required to create scans" }, 403);

      // ── Enforce monthly scan quota ───────────────────────────────────────
      const scanLimitError = await checkScanLimit(user, workspaceId, env);
      if (scanLimitError) return json(scanLimitError.body, scanLimitError.status);

      const ws = await env.cybermeters_db
        .prepare(`SELECT id FROM workspaces WHERE id = ?`)
        .bind(workspaceId)
        .first();
      if (!ws) {
        return json({ error: "Workspace not found" }, 404);
      }

      const burstOwnerId = await getWorkspaceBillingUserId(workspaceId, user.id, env);
      const burstPlan = await getEffectivePlan(burstOwnerId, env);
      const burstLimit = getPlanLimits(burstPlan).scan_starts_per_hour;
      const burstLimitError = await consumeApiRateLimit(
        env,
        [
          { scope: "user", scope_id: user.id },
          { scope: "workspace", scope_id: workspaceId },
          { scope: "account", scope_id: burstOwnerId },
        ],
        "scan_start",
        burstLimit,
        3600,
        // Fail-CLOSED: a scan is expensive (many subrequests). Under D1 stress
        // — exactly when the limiter's DB reads fail — allowing unmetered scan
        // starts would let one account exhaust Worker subrequests / cost. A
        // brief 503 + retry is the safer failure mode than an unthrottled burst.
        { failClosed: true }
      );
      if (burstLimitError) return json(burstLimitError.body, burstLimitError.status);

      const userId   = user.id;
      const domainId = createId("domain");
      const scanId   = createId("scan");
      const reportKey = `reports/${scanId}.json`;
      const initialScanQuality = {
        status: "complete",
        warnings: [],
        modules_skipped: [],
        subrequest_budget: {
          estimated: 0,
          limit: 1_000,       // Sprint 10B: Workers Paid plan limit
          remaining_estimate: 1_000,
        },
      };

      await createAuditEvent(env, {
        workspace_id: workspaceId ?? null,
        user_id:      userId ?? null,
        event_type:   "scan_requested",
        entity_type:  "scan",
        entity_id:    scanId,
        description:  `Scan requested for ${domain}`,
        metadata:     { scan_id: scanId, domain, workspace_id: workspaceId ?? null },
      });

      // Register domain — reuse existing row for same (user_id, domain) pair.
      // Scoped by user_id to prevent cross-user domain aliasing.
      const existingDomain = await env.cybermeters_db
        .prepare(`SELECT id FROM domains WHERE domain = ? AND user_id = ? LIMIT 1`)
        .bind(domain, userId)
        .first();

      const resolvedDomainId = existingDomain ? existingDomain.id : domainId;

      if (!existingDomain) {
        // Entitlement: per-workspace limit + account-level limit for new domains only.
        // burstOwnerId is already resolved above for the hourly rate-limit check.
        const domScanPlan   = await getEffectivePlan(burstOwnerId, env);
        const domScanUsage  = await getEntitlementUsage(user, env, workspaceId);
        const domScanLimits = getPlanLimits(domScanPlan);
        // (a) Per-workspace limit
        if (domScanUsage.domains_in_workspace >= domScanLimits.domains_per_workspace) {
          return json(planLimitExceeded("domains", domScanLimits.domains, domScanUsage.domains_in_workspace), 403);
        }
        // (b) Account-level limit across all owned workspaces
        const domScanOwnerAcct = await getAccountUsage(burstOwnerId, env);
        if (domScanOwnerAcct.domains >= domScanLimits.domains) {
          return json(planLimitExceeded("domains", domScanLimits.domains, domScanOwnerAcct.domains), 403);
        }

        await env.cybermeters_db
          .prepare(`INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)`)
          .bind(domainId, userId, domain)
          .run();
      }

      await env.cybermeters_db
        .prepare(
          `INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id)
           VALUES (?, ?)`
        )
        .bind(workspaceId, resolvedDomainId)
        .run();

      // ── Domain-ownership verification gate (workspace-scoped) ──────────────
      // The auto-register/link above is a compatibility convenience, NOT proof of
      // control — it must never become an implicit verification bypass. The scan
      // stops here unless THIS exact (workspace_id, domain_id) relationship is
      // verified. No scan row, R2 placeholder, telemetry, managed case or report is
      // created past this point on rejection.
      if (!(await isWorkspaceDomainVerified(env, workspaceId, resolvedDomainId))) {
        // Name the EXACT record we gated on. The caller cannot start verification
        // without it, and a domain can legitimately be linked to several of the
        // caller's workspaces (and exist under several domain ids) — so a client
        // left to resolve it itself would guess, and could initiate verification
        // against a different record than the one that just blocked the scan.
        // Both ids are the caller's own, already-authorised context: workspaceId
        // came from their session and the link was resolved above, so this is not
        // an enumeration oracle.
        return json({ ...DOMAIN_VERIFICATION_REQUIRED, domain_id: resolvedDomainId, workspace_id: workspaceId }, 403);
      }

      // Create scan row — status 'running' (engine starts immediately)
      await env.cybermeters_db
        .prepare(
          `INSERT INTO scans (id, domain_id, workspace_id, domain, status) VALUES (?, ?, ?, ?, ?)`
        )
        .bind(scanId, resolvedDomainId, workspaceId, domain, "running")
        .run();

      // Write placeholder report to R2 so GET /report returns 200 immediately
      await env.cybermeters_reports.put(
        reportKey,
        JSON.stringify({
          scan_id:             scanId,
          domain_id:           resolvedDomainId,
          domain,
          status:              "running",
          cyber_metrics_score: 0,
          risk_level:          "unknown",
          findings:            [],
          recommendations:     [],
          scan_quality:         initialScanQuality,
          message:             "Scan engine is running. Poll GET /api/scans/:id for completion.",
        }, null, 2),
        { httpMetadata: { contentType: "application/json" } }
      );

      // Audit — scan started. Non-fatal.
      try {
        await createAuditEvent(env, {
          workspace_id: workspaceId ?? null,
          user_id:      userId ?? null,
          event_type:   "scan_started",
          entity_type:  "scan",
          entity_id:    scanId,
          description:  `Scan started for ${domain}`,
          metadata:     { scan_id: scanId, domain, domain_id: resolvedDomainId, workspace_id: workspaceId ?? null },
        });
      } catch { /* non-fatal */ }

      // Fire the scan engine after the response is sent
      ctx.waitUntil(runScanEngine(scanId, resolvedDomainId, workspaceId, domain, env));

      return json(
        {
          status:       "running",
          scan_id:      scanId,
          domain_id:    resolvedDomainId,
          domain,
          report_key:   reportKey,
          scan_quality: initialScanQuality,
          ...(workspaceId ? { workspace_id: workspaceId } : {}),
          message:      "Scan engine started. Poll GET /api/scans/:id until status is completed, then GET /api/scans/:id/report.",
        },
        202
      );
    }

    // ── GET /api/scans ──────────────────────────────────────────────────
    // Supports optional ?workspace_id= to scope results to a single workspace.
    if (request.method === "GET" && url.pathname === "/api/scans") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const wsFilter = url.searchParams.get("workspace_id");

      // If caller scoped the request to a workspace, verify membership first.
      if (wsFilter) {
        const wsAccess = await requireWorkspaceRole(user, wsFilter, "workspace:read", env);
        if (!wsAccess) return json({ error: "Forbidden" }, 403);
      }

      let result;
      if (wsFilter) {
        // Direct attribution: scans.workspace_id = wsFilter.
        // Fallback via domain join for historical scans where workspace_id IS NULL.
        result = await env.cybermeters_db
          .prepare(
            `SELECT DISTINCT s.id, s.domain, s.status, s.score, s.rating, s.created_at
             FROM scans s
             JOIN domains d ON d.id = s.domain_id
             JOIN workspace_domains wd ON wd.domain_id = d.id
             WHERE (
               s.workspace_id = ?
               OR (s.workspace_id IS NULL AND wd.workspace_id = ?)
             )
             ORDER BY s.created_at DESC
             LIMIT 20`
          )
          .bind(wsFilter, wsFilter)
          .all();
      } else {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        if (workspaceIds.length === 0) {
          return json({ scans: [] });
        }
        const placeholders = workspaceIds.map(() => "?").join(",");
        // Direct attribution for attributed scans; join fallback for NULL workspace_id.
        result = await env.cybermeters_db
          .prepare(
            `SELECT DISTINCT s.id, s.domain, s.status, s.score, s.rating, s.scan_quality, s.created_at
             FROM scans s
             JOIN domains d ON d.id = s.domain_id
             JOIN workspace_domains wd ON wd.domain_id = d.id
             WHERE (
               s.workspace_id IN (${placeholders})
               OR (s.workspace_id IS NULL AND wd.workspace_id IN (${placeholders}))
             )
             ORDER BY s.created_at DESC
             LIMIT 20`
          )
          .bind(...workspaceIds, ...workspaceIds)
          .all();
      }

      // ── Stuck-scan reconciliation ─────────────────────────────────────
      // Edge case: if runScanEngine was killed (Worker CPU timeout, subrequest limit)
      // between the R2 write and the D1 status write, the scan stays 'running' in D1
      // permanently even though R2 has the completed report.
      // For any scan that has been 'running' for > 10 minutes, check R2 and correct D1.
      // Only genuinely old scans are checked — in-flight scans (<10 min) are never touched.
      const STUCK_THRESHOLD_MS = 2 * 60 * 1000; // 2 minutes — scans complete in ~15s; >2min means stuck
      const nowMs = Date.now();
      const stuckScans = (result.results || []).filter(s => {
        if (s.status !== 'running') return false;
        const t = new Date(
          s.created_at.includes('T') ? s.created_at : s.created_at.replace(' ', 'T') + 'Z'
        ).getTime();
        return (nowMs - t) > STUCK_THRESHOLD_MS;
      });

      if (stuckScans.length > 0) {
        const reconResults = await Promise.allSettled(
          stuckScans.map(async (s) => {
            try {
              const obj = await env.cybermeters_reports.get(`reports/${s.id}.json`);
              if (!obj) return null;
              const raw = await obj.json();
              const correctedStatus =
                raw.status === 'completed' ? 'completed' :
                raw.status === 'failed'    ? 'failed'    : null;
              if (!correctedStatus) return null;
              // Correct D1 so future queries also return the right status, score,
              // rating, AND coverage quality — converged from the SAME R2 report, so
              // D1 and R2 cannot present contradictory quality after reconciliation.
              try {
                await env.cybermeters_db
                  .prepare(`UPDATE scans SET status = ?, score = ?, rating = ?, scan_quality = ? WHERE id = ?`)
                  .bind(
                    correctedStatus,
                    raw.cyber_metrics_score ?? null,
                    raw.risk_level          ?? null,
                    raw.scan_quality?.status ?? null,
                    s.id
                  )
                  .run();
              } catch { /* non-fatal — response still returns corrected status */ }
              return {
                id:     s.id,
                status: correctedStatus,
                score:  raw.cyber_metrics_score ?? s.score,
                rating: raw.risk_level          ?? s.rating,
                scan_quality: raw.scan_quality?.status ?? s.scan_quality ?? null,
              };
            } catch { return null; }
          })
        );

        const corrections = Object.fromEntries(
          reconResults
            .filter(r => r.status === 'fulfilled' && r.value)
            .map(r => [r.value.id, r.value])
        );

        if (Object.keys(corrections).length > 0) {
          result = {
            ...result,
            results: (result.results || []).map(s =>
              corrections[s.id]
                ? { ...s, status: corrections[s.id].status, score: corrections[s.id].score, rating: corrections[s.id].rating }
                : s
            ),
          };
        }
      }
      // ── End stuck-scan reconciliation ─────────────────────────────────

      return json({ scans: result.results, ...(wsFilter ? { workspace_id: wsFilter } : {}) });
    }

    // ── GET /api/scans/:id/report/pdf ──────────────────────────────────
    // Snapshot-native (M5.d): the PDF renders the canonical immutable snapshot
    // verbatim — no score/band/BRI/domain/taxonomy derivation on this path.
    // First authorised request for a pre-093 scan triggers the one canonical
    // reconstruction build (founder policy); afterwards the immutable snapshot
    // serves every render.
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/report\/pdf$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      const scan = await env.cybermeters_db
        .prepare(`SELECT id, domain, status, workspace_id FROM scans WHERE id = ?`)
        .bind(scanId).first();
      if (!scan) return json({ error: "Forbidden" }, 403);
      if (scan.status !== "completed") {
        return json({ error: "Report not ready: scan has not completed" }, 409);
      }

      try {
        const read = await readScanReportSnapshot(env, scanId, { allowReconstruction: true });
        if (read.status === "building") return json({ error: "Report not ready" }, 409);
        if (read.status === "not_found") return json({ error: "Report not found" }, 404);
        if (read.status !== "ok") {
          return serverError("api", new Error(`snapshot ${read.status} (${read.reason}) for scan ${scanId}`));
        }

        // Live presentation metadata under the frozen-vs-live policy: branding
        // only. Frozen security facts all come from the snapshot.
        let branding = null, logoImage = null;
        try {
          branding = await resolveReportBranding(env, scan.workspace_id);
          if (branding?.logo) logoImage = await prepareLogoXObject(branding.logo, branding.accent);
        } catch { branding = null; logoImage = null; }

        const pdfBytes = buildScanReportPdf(scan, read, branding, logoImage);
        const safeName = String(scan.domain || "scan").replace(/[^a-z0-9.-]/gi, "_");
        await createAuditEvent(env, {
          workspace_id: scan.workspace_id, user_id: user.id,
          event_type: "scan_report_downloaded", entity_type: "scan", entity_id: scanId,
          description: `Scan report PDF downloaded for ${scan.domain}`,
          metadata: { scan_id: scanId, snapshot_id: read.row.id },
        }).catch(() => {});
        return new Response(pdfBytes, {
          headers: {
            ...corsHeaders,
            "Content-Type": "application/pdf",
            "Content-Disposition": `attachment; filename="cybermeters-${safeName}-scan.pdf"`,
            "Content-Length": String(pdfBytes.length),
          },
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/scans/:id/executive-report-v2 ─────────────────────────
    // Snapshot-native (M5.d): canonical facts from the immutable snapshot;
    // module evidence referenced from the immutable scan-time artefact; the
    // five-pillar intelligence registry is retired. Branding stays live
    // (presentation metadata).
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/executive-report-v2$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      const scan = await env.cybermeters_db
        .prepare(`SELECT id, domain_id, domain, status, workspace_id, created_at FROM scans WHERE id = ?`)
        .bind(scanId).first();
      if (!scan) return json({ error: "Forbidden" }, 403);
      if (scan.status !== "completed") {
        return json({ error: "Executive report is available once the scan completes" }, 409);
      }

      try {
        const read = await readScanReportSnapshot(env, scanId, { allowReconstruction: true });
        if (read.status === "building") return json({ error: "Report not ready" }, 409);
        if (read.status === "not_found") return json({ error: "Report not found" }, 404);
        if (read.status !== "ok") {
          return serverError("api", new Error(`snapshot ${read.status} (${read.reason}) for scan ${scanId}`));
        }

        let workspace = null;
        if (scan.workspace_id) {
          workspace = await env.cybermeters_db
            .prepare(`SELECT id, name FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
            .bind(scan.workspace_id).first().catch(() => null);
        }
        let branding = null;
        try { branding = await resolveReportBranding(env, scan.workspace_id); } catch { branding = null; }

        const report = buildExecutiveReportV2({ scan, workspace, read });
        return json({ ...report, branding });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/scans/:id/snapshot ─────────────────────────────────────
    // Canonical M5.c reporting snapshot, served VERBATIM. Retrieval, integrity,
    // schema gating, repair-on-read and reconstruction all live in the ONE
    // shared helper (readScanReportSnapshot) — this route only maps its
    // deterministic states onto HTTP. Must be checked BEFORE the generic
    // /api/scans/:id route below.
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/snapshot$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];

      // Auth before DB — prevents scan ID existence probing by unauthenticated callers.
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      // Foreign-existing and nonexistent scans both yield an identical 403 —
      // no cross-tenant existence oracle (the /report sibling's contract).
      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const read = await readScanReportSnapshot(env, scanId, { allowReconstruction: true });
        if (read.status === "not_found") return json({ error: "Snapshot not found" }, 404);
        if (read.status === "building") return json({ error: "Snapshot not ready" }, 409);
        if (read.status !== "ok") {
          return serverError("api", new Error(`snapshot ${read.status} (${read.reason}) for ${scanId}`));
        }
        return json({
          snapshot: read.snapshot,
          superseded_by: read.supersededBy,
          integrity: read.integrity,
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/scans/:id/report ───────────────────────────────────────
    // Hybrid (M5.d): every ASSESSMENT fact (score, band, assessment, domains,
    // business risk, taxonomy classification) comes from the canonical
    // immutable snapshot; module evidence, recommendations and per-finding
    // detail come from the immutable scan-time artefact the snapshot itself
    // references (source_artifacts). The response contract is unchanged.
    // Per-finding remediation is attached from the Canonical Remediation
    // Registry (the one remediation source of truth) — presentation join,
    // documented under the frozen-vs-live policy.
    // Must be checked BEFORE the generic /api/scans/:id route below.
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/report$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];

      // Auth before DB — prevents scan ID existence probing by unauthenticated callers.
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const scan = await env.cybermeters_db
        .prepare(`SELECT id, domain_id, domain, status, score, rating, workspace_id, created_at
                  FROM scans WHERE id = ?`)
        .bind(scanId).first();
      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);
      if (!scan) return json({ error: "Forbidden" }, 403);

      const obj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
      if (!obj) return json({ error: "Report not found" }, 404);
      const raw = await obj.json();

      // Normalise modules — ensure every module key is present even for reports
      // stored before a module was introduced (backward-compatible defaults).
      const storedModules = raw.modules ?? {};
      const normalisedModules = {
        ...storedModules,
        asset_exposure: storedModules.asset_exposure ?? {
          checked: 0, reachable: 0, assets: [], source: "http_probe", error: null,
        },
        subdomain_takeover: storedModules.subdomain_takeover ?? {
          checked: 0, potential_risks: 0, risks: [], source: "subdomain_cname_fingerprint", error: null,
        },
        historical_changes: storedModules.historical_changes ?? {
          has_previous: false, previous_scan_id: null, previous_score: null,
          current_score: null, score_change: null, new_subdomains: [],
          removed_subdomains: [], new_findings: [], resolved_findings: [],
          new_takeover_risks: [], new_exposed_assets: [],
          source: "previous_scan_comparison", error: null,
        },
      };
      const reportFindings = applyEvidenceQuality(
        (Array.isArray(raw.findings) ? raw.findings : []).map(normalizeFindingSchema)
      );

      // Non-completed scans have no assessment to report — serve the artefact's
      // own lifecycle fields verbatim (Dashboard polls this for running scans).
      if (raw.status !== "completed" || scan.status !== "completed") {
        return json({
          scan_id: scan.id,
          domain: scan.domain,
          status: raw.status ?? scan.status,
          cyber_metrics_score: raw.cyber_metrics_score ?? null,
          risk_level: raw.risk_level ?? null,
          assessment: null,
          cyber_mot_domains: [],
          findings: reportFindings.map((f) => ({ ...f, remediation: findingRemediation(f) })),
          recommendations: Array.isArray(raw.recommendations) ? raw.recommendations : [],
          scan_quality: raw.scan_quality ?? buildScanQuality(normalisedModules),
          modules: normalisedModules,
          business_risk: null,
          ...(raw.started_at ? { started_at: raw.started_at } : {}),
          ...(raw.completed_at ? { completed_at: raw.completed_at } : {}),
          ...(raw.failed_at ? { failed_at: raw.failed_at } : {}),
          ...(raw.message ? { message: raw.message } : {}),
          ...(raw.error ? { error: raw.error } : {}),
        });
      }

      try {
        const read = await readScanReportSnapshot(env, scanId, { allowReconstruction: true });
        if (read.status === "building") return json({ error: "Report not ready" }, 409);
        if (read.status === "not_found") return json({ error: "Report not found" }, 404);
        if (read.status !== "ok") {
          return serverError("api", new Error(`snapshot ${read.status} (${read.reason}) for scan ${scanId}`));
        }
        const snap = read.snapshot;
        const overall = snap.overall || {};
        const bri = overall.business_risk_indicator || {};
        const im = bri.internal_metrics || {};
        const assessment = overall.assessment || null;
        const historicalChanges = normalisedModules.historical_changes;
        const comparable = assessment?.comparable === true;
        return json({
          scan_id: scan.id,
          domain: scan.domain,
          status: scan.status,
          // Frozen snapshot facts — never recalculated on read.
          cyber_metrics_score: overall.cyber_metrics_score ?? null,
          risk_level: overall.score_band ?? null,
          assessment,
          cyber_mot_domains: snap.domains || [],
          findings: reportFindings.map((f) => ({ ...f, remediation: findingRemediation(f) })),
          recommendations: Array.isArray(raw.recommendations) ? raw.recommendations : [],
          scan_quality: raw.scan_quality ?? buildScanQuality(normalisedModules),
          modules: {
            ...normalisedModules,
            historical_changes: {
              ...historicalChanges,
              current_score: overall.cyber_metrics_score ?? null,
              comparable,
              score_change: (comparable && historicalChanges?.previous_score != null && overall.cyber_metrics_score != null)
                ? overall.cyber_metrics_score - historicalChanges.previous_score
                : null,
            },
          },
          // Legacy shape preserved; values are the snapshot's frozen indicator.
          business_risk: bri.band == null ? null : {
            score: im.score ?? null,
            band: bri.band,
            summary: bri.explanation ?? null,
            categories: im.categories ?? null,
            top_business_risks: im.top_business_risks ?? null,
          },
          snapshot_id: read.row.id,
          snapshot_provenance: snap.snapshot?.provenance ?? null,
          ...(raw.started_at ? { started_at: raw.started_at } : {}),
          ...(raw.completed_at ? { completed_at: raw.completed_at } : {}),
        });
      } catch (err) {
        return serverError("api", err);
      }
    }

    // ── GET /api/scans/:id ──────────────────────────────────────────────
    if (
      request.method === "GET" &&
      url.pathname.startsWith("/api/scans/")
    ) {
      const scanId = url.pathname.split("/").pop();

      // Auth before DB — prevents scan ID existence probing by unauthenticated callers.
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      let scan = await env.cybermeters_db
        .prepare(
          `SELECT id, domain_id, domain, status, score, rating, scan_quality, created_at
           FROM scans WHERE id = ?`
        )
        .bind(scanId)
        .first();

      // Authorize BEFORE revealing existence — foreign-existing and nonexistent
      // both resolve to no access → identical 403 (no existence oracle).
      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);
      if (!scan) return json({ error: "Forbidden" }, 403);

      // ── Stuck-scan reconciliation ────────────────────────────────────────
      // If D1 still shows 'running' but the scan is older than 2 minutes,
      // the Worker was likely CPU-killed between the R2 write and the D1 write.
      // Check R2 for the real status and correct D1 so polling can terminate.
      if (scan.status === "running") {
        const createdMs = new Date(
          scan.created_at.includes("T") ? scan.created_at : scan.created_at + "Z"
        ).getTime();
        if (Date.now() - createdMs > 2 * 60 * 1000) {
          try {
            const obj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
            if (obj) {
              const raw = await obj.json();
              if (raw.status === "completed" || raw.status === "failed") {
                const correctedScore   = raw.cyber_metrics_score ?? null;
                const correctedRating  = raw.risk_level ?? null;
                // Converge scan_quality from the SAME canonical R2 report, matching
                // the list reconciler + finalizer, so D1 and R2 cannot present
                // contradictory quality after reconciliation. Never fabricated:
                // absent report quality stays NULL (unknown, non-authoritative).
                const correctedQuality = raw.scan_quality?.status ?? scan.scan_quality ?? null;
                await env.cybermeters_db
                  .prepare(
                    `UPDATE scans SET status = ?, score = ?, rating = ?, scan_quality = ? WHERE id = ?`
                  )
                  .bind(raw.status, correctedScore, correctedRating, correctedQuality, scanId)
                  .run();
                scan = {
                  ...scan,
                  status:       raw.status,
                  score:        correctedScore,
                  rating:       correctedRating,
                  scan_quality: correctedQuality,
                };
              }
            }
          } catch (_) {
            // R2 read failure is non-fatal — return D1 state as-is
          }
        }
      }

      return json({
        scan,
        report_key: `reports/${scan.id}.json`,
      });
    }

    // ── GET /api/domain/:domain/history ────────────────────────────────
    if (
      request.method === "GET" &&
      url.pathname.startsWith("/api/domain/") &&
      url.pathname.endsWith("/history")
    ) {
      const parts  = url.pathname.split("/");
      const domain = decodeURIComponent(parts[3]);

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const workspaceIds = await getAccessibleWorkspaceIds(user, env);
      if (workspaceIds.length === 0) return json({ error: "Forbidden" }, 403);
      const placeholders = workspaceIds.map(() => "?").join(",");
      const limit = parseBoundedInteger(url.searchParams.get("limit"), 100, 1, 500);

      const history = await env.cybermeters_db
        .prepare(
          `SELECT DISTINCT s.id, s.domain_id, s.domain, s.status, s.score, s.rating, s.scan_quality, s.created_at
           FROM scans s
           JOIN workspace_domains wd ON wd.domain_id = s.domain_id
           WHERE s.domain = ? AND wd.workspace_id IN (${placeholders})
           ORDER BY s.created_at DESC
           LIMIT ?`
        )
        .bind(domain, ...workspaceIds, limit)
        .all();

      return json({ domain, scans: history.results });
    }

    // ── POST /api/schedules ─────────────────────────────────────────────
    if (request.method === "POST" && url.pathname === "/api/schedules") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      let body;
      try {
        body = await request.json();
      } catch {
        return json({ error: "Invalid JSON body" }, 400);
      }

      const domain      = (body.domain || "").trim().toLowerCase();
      const frequency   = (body.frequency || "daily").trim().toLowerCase();
      let workspaceId = (body.workspace_id || "").trim() || null;

      if (!isValidDomain(domain)) {
        return json({ error: "Invalid domain" }, 400);
      }
      if (!["daily", "weekly"].includes(frequency)) {
        return json({ error: "frequency must be 'daily' or 'weekly'" }, 400);
      }
      if (!workspaceId) {
        const workspaceIds = await getAccessibleWorkspaceIds(user, env);
        for (const id of workspaceIds) {
          const access = await requireWorkspaceRole(user, id, "scan:create", env);
          if (access) {
            workspaceId = id;
            break;
          }
        }
        if (!workspaceId) {
          return json({ error: "No workspace available for scheduled scans" }, 403);
        }
      }
      const scheduleAccess = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
      if (!scheduleAccess) return json({ error: "Forbidden — analyst role required to manage scheduled scans" }, 403);

      // ── Enforce scheduled scan count quota ───────────────────────────────
      const schedLimitError = await checkScheduledScanLimit(user, workspaceId, env);
      if (schedLimitError) return json(schedLimitError.body, schedLimitError.status);

      // Create the table if it doesn't exist yet (idempotent — includes new columns)
      await env.cybermeters_db
        .prepare(
          `CREATE TABLE IF NOT EXISTS scheduled_scans (
             id TEXT PRIMARY KEY,
             domain TEXT NOT NULL,
             frequency TEXT NOT NULL DEFAULT 'daily',
             enabled INTEGER NOT NULL DEFAULT 1,
             last_run_at TEXT,
             next_run_at TEXT,
             workspace_id TEXT,
             last_asset_count INTEGER DEFAULT 0,
             asset_change_count INTEGER DEFAULT 0,
             created_at TEXT DEFAULT (datetime('now'))
           )`
        )
        .run();

      const schedId    = createId("sched");
      const nextRunAt  = computeNextRunAt(frequency);
      const createdAt  = new Date().toISOString();

      await env.cybermeters_db
        .prepare(
          `INSERT INTO scheduled_scans (id, domain, frequency, enabled, next_run_at, workspace_id, created_at)
           VALUES (?, ?, ?, 1, ?, ?, ?)`
        )
        .bind(schedId, domain, frequency, nextRunAt, workspaceId, createdAt)
        .run();

      await createAuditEvent(env, {
        workspace_id: workspaceId,
        user_id:      user.id,
        event_type:   "scheduled_scan_created",
        entity_type:  "scheduled_scan",
        entity_id:    schedId,
        description:  `Scheduled scan created for ${domain} (${frequency})`,
        metadata:     { scheduled_scan_id: schedId, domain, frequency, next_run_at: nextRunAt },
      });

      return json({
        schedule: {
          id:                 schedId,
          domain,
          frequency,
          enabled:            1,
          workspace_id:       workspaceId,
          last_asset_count:   0,
          asset_change_count: 0,
          last_run_at:        null,
          next_run_at:        nextRunAt,
          created_at:         createdAt,
        },
      }, 201);
    }

    // ── GET /api/schedules ──────────────────────────────────────────────
    if (request.method === "GET" && url.pathname === "/api/schedules") {
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const workspaceIds = await getAccessibleWorkspaceIds(user, env);
      if (workspaceIds.length === 0) return json({ schedules: [] });
      const placeholders = workspaceIds.map(() => "?").join(",");
      const limit = parseBoundedInteger(url.searchParams.get("limit"), 100, 1, 500);

      // Return empty list if table doesn't exist yet
      try {
        const result = await env.cybermeters_db
          .prepare(
            `SELECT id, domain, frequency, enabled, workspace_id,
                    last_asset_count, asset_change_count,
                    last_run_at, next_run_at, created_at
             FROM scheduled_scans
             WHERE workspace_id IN (${placeholders})
             ORDER BY created_at DESC
             LIMIT ?`
          )
          .bind(...workspaceIds, limit)
          .all();
        return json({ schedules: result.results });
      } catch {
        return json({ schedules: [] });
      }
    }

    // ── DELETE /api/schedules/:id ───────────────────────────────────────
    if (
      request.method === "DELETE" &&
      url.pathname.startsWith("/api/schedules/")
    ) {
      const schedId = url.pathname.split("/").pop();
      if (!schedId) {
        return json({ error: "Missing schedule id" }, 400);
      }

      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const schedule = await env.cybermeters_db
          .prepare("SELECT id, workspace_id FROM scheduled_scans WHERE id = ?")
          .bind(schedId)
          .first();
        // Authorize BEFORE revealing existence: a nonexistent schedule, a foreign
        // schedule owned by another tenant, and a schedule the caller cannot manage
        // must all produce the SAME 403 — a non-member can no longer distinguish a
        // foreign schedule's existence from a nonexistent id.
        const scheduleAccess = schedule?.workspace_id
          ? await requireWorkspaceRole(user, schedule.workspace_id, "scan:create", env)
          : null;
        if (!schedule || !scheduleAccess) return json({ error: "Forbidden" }, 403);

        const result = await env.cybermeters_db
          .prepare(`DELETE FROM scheduled_scans WHERE id = ?`)
          .bind(schedId)
          .run();

        if (result.meta?.changes === 0) {
          return json({ error: "Schedule not found" }, 404);
        }
        await createAuditEvent(env, {
          workspace_id: schedule.workspace_id,
          user_id:      user.id,
          event_type:   "scheduled_scan_deleted",
          entity_type:  "scheduled_scan",
          entity_id:    schedId,
          description:  "Scheduled scan deleted",
          metadata:     { scheduled_scan_id: schedId },
        });
      } catch {
        return json({ error: "Schedule not found" }, 404);
      }

      return json({ deleted: schedId });
    }


  return null;
}
