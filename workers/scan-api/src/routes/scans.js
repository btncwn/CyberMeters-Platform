// ── Scan routes ──
// Scan start (quota-gated, runs the scan engine via waitUntil), scan
// list/detail/report/PDF/executive-report-v2, domain scan history and the
// scheduled-scan CRUD endpoints. Extracted near-verbatim from index.js
// (router split, Phase 2 PR #14). Receives the per-request routeCtx from
// index.js; returns a Response when a route matches, or null so the main
// router continues.
import { deriveScanBusinessRisk } from "../engines/business-risk.js";
import { getEffectivePlan } from "../engines/entitlements.js";
import { buildExecutiveReportV2, resolveCanonicalScanScore } from "../engines/executive-report.js";
import { applyEvidenceQuality, normalizeFindingSchema } from "../engines/findings.js";
import { buildScanReportPdf } from "../engines/pdf.js";
import { resolveReportBranding } from "../engines/report-branding.js";
import { prepareLogoXObject } from "../engines/pdf-image.js";
import { checkScanLimit, checkScheduledScanLimit, getAccountUsage, getEntitlementUsage, getPlanLimits, getWorkspaceBillingUserId, planLimitExceeded } from "../engines/plan-usage.js";
import { buildScanQuality, runScanEngine } from "../engines/scan-engine.js";
import { buildDmarcSenderIntelligenceEvidence } from "../engines/sender-provenance.js";
import { createAuditEvent } from "../lib/events.js";
import { DOMAIN_VERIFICATION_REQUIRED, isWorkspaceDomainVerified } from "../lib/domain-verification.js";
import { resolveAssessmentPresentation } from "../engines/assessment-presentation.js";
import { resolveCyberMotDomainStates } from "../engines/cyber-mot-domains.js";
import { getCyberEssentialsSnapshot } from "../engines/ce-readiness.js";
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
        return json(DOMAIN_VERIFICATION_REQUIRED, 403);
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
    // Per-scan PDF export built from the stored V1 report. Read-only, RBAC-
    // scoped via scan access, audited. Never exposes internals.
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/report\/pdf$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);
      try {
        const scan = await env.cybermeters_db
          .prepare("SELECT id, domain, status, score, rating, created_at FROM scans WHERE id = ? LIMIT 1")
          .bind(scanId).first();
        if (!scan) return json({ error: "Scan not found" }, 404);
        if (scan.status !== "completed") return json({ error: "PDF is available only for completed scans" }, 409);

        const reportObject = await env.cybermeters_reports.get(`reports/${scanId}.json`);
        if (!reportObject) return json({ error: "Report not found" }, 404);
        const report = await reportObject.json();
        // Attach Business Risk from the same shared helper the UI uses, so the
        // PDF's score matches the on-screen report exactly.
        report.business_risk = deriveScanBusinessRisk(report);

        // White-label: lead the PDF with the account's brand when enabled. When a
        // logo is set, prepare it as an embeddable Image-XObject (JPEG direct /
        // PNG decoded); on any failure it resolves to null → text wordmark.
        const branding = access.workspace_id
          ? await resolveReportBranding(env, access.workspace_id)
          : null;
        if (branding && branding.logo) {
          branding.logoImage = await prepareLogoXObject(branding.logo, branding.accent || "#00876A");
        }
        const bytes = buildScanReportPdf(scan, report, branding);

        await createAuditEvent(env, {
          workspace_id: access.workspace_id || null,
          user_id:      user.id,
          event_type:   "scan_report_downloaded",
          entity_type:  "scan",
          entity_id:    scanId,
          description:  `Scan report PDF downloaded for ${scan.domain}`,
          metadata:     { scan_id: scanId, domain: scan.domain },
        }).catch(() => {});

        const safeName = String(scan.domain || "scan").toLowerCase().replace(/[^a-z0-9.-]/g, "-");
        return new Response(bytes, {
          status: 200,
          headers: {
            ...corsHeaders,
            "Content-Type":        "application/pdf",
            "Content-Disposition": `attachment; filename="cybermeters-${safeName}-scan.pdf"`,
            "Content-Length":      String(bytes.length),
          },
        });
      } catch (error) {
        return serverError("scan-report-pdf", error, "PDF could not be generated.");
      }
    }

    // ── GET /api/scans/:id/executive-report-v2 ─────────────────────────
    // Additive Executive Intelligence contract built from the stored scan report.
    // V1 report storage and response behavior remain unchanged.
    if (
      request.method === "GET" &&
      /^\/api\/scans\/[^/]+\/executive-report-v2$/.test(url.pathname)
    ) {
      const scanId = url.pathname.split("/")[3];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);

      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const scan = await env.cybermeters_db
          .prepare(
            `SELECT id, domain_id, domain, status, score, rating, created_at
             FROM scans WHERE id = ? LIMIT 1`
          )
          .bind(scanId)
          .first();
        if (!scan) return json({ error: "Scan not found" }, 404);
        if (scan.status !== "completed") {
          return json({ error: "Executive report is available only for completed scans" }, 409);
        }

        const reportObject = await env.cybermeters_reports.get(`reports/${scanId}.json`);
        if (!reportObject) return json({ error: "Report not found" }, 404);
        const rawReport = await reportObject.json();

        const workspace = access.workspace_id
          ? await env.cybermeters_db
              .prepare("SELECT id, name FROM workspaces WHERE id = ? LIMIT 1")
              .bind(access.workspace_id)
              .first()
          : null;

        const execReport = buildExecutiveReportV2({ scan, rawReport, workspace });
        // Additive: canonical eight-domain Cyber MOT coverage states so the Executive
        // Report UI can show all eight domains with one honest state each (no domain
        // silently disappears; Identity/Shadow-IT stay in their honest scopes).
        try {
          let ceSnap = null;
          try {
            const ceWsId = access.workspace_id || scan.workspace_id || null;
            if (ceWsId) ceSnap = await getCyberEssentialsSnapshot(ceWsId, env);
          } catch { ceSnap = null; }
          execReport.cyber_mot_domains = resolveCyberMotDomainStates(rawReport, { scanId: scan.id, cyberEssentials: ceSnap });
        } catch { execReport.cyber_mot_domains = resolveCyberMotDomainStates(null); }
        // Additive: attach DMARC sender-intelligence evidence to the Business Email
        // engine when imported report data exists. Never alters existing structure.
        try {
          const senderIntel = await buildDmarcSenderIntelligenceEvidence(
            env, access.workspace_id || null, scan.domain || rawReport.domain || null);
          if (senderIntel && execReport?.intelligence_engines?.business_email?.evidence) {
            execReport.intelligence_engines.business_email.evidence.dmarc_sender_intelligence = senderIntel;
          }
        } catch { /* non-fatal — exec report remains unchanged */ }
        // White-label: attach the account brand (logo/name/accent) so the
        // shareable HTML report can lead with the MSP's identity. Null → CyberMeters.
        try {
          execReport.branding = access.workspace_id
            ? await resolveReportBranding(env, access.workspace_id)
            : null;
        } catch { execReport.branding = null; }
        return json(execReport);
      } catch (error) {
        return serverError("executive-report-v2", error, "Executive report could not be generated.");
      }
    }

    // ── GET /api/scans/:id/report ───────────────────────────────────────
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
        .prepare(
          `SELECT id, domain_id, domain, status, score, rating, created_at
           FROM scans WHERE id = ?`
        )
        .bind(scanId)
        .first();

      // Authorize BEFORE revealing existence: requireScanReadAccess returns null for
      // BOTH a foreign-existing scan and a nonexistent scan, so both yield an
      // identical 403 — no cross-tenant existence oracle. Mirrors the /report/pdf
      // sibling. The `!scan` branch is defensive and also returns 403.
      const access = await requireScanReadAccess(user, scanId, env);
      if (!access) return json({ error: "Forbidden" }, 403);
      if (!scan) return json({ error: "Forbidden" }, 403);

      const obj = await env.cybermeters_reports.get(`reports/${scanId}.json`);
      if (!obj) {
        return json({ error: "Report not found" }, 404);
      }

      const raw = await obj.json();

      // Normalise modules — ensure every module key is present even for reports
      // stored before a module was introduced (backward-compatible defaults).
      const storedModules = raw.modules ?? {};
      const normalisedModules = {
        ...storedModules,
        asset_exposure: storedModules.asset_exposure ?? {
          checked:   0,
          reachable: 0,
          assets:    [],
          source:    "http_probe",
          error:     null,
        },
        subdomain_takeover: storedModules.subdomain_takeover ?? {
          checked:         0,
          potential_risks: 0,
          risks:           [],
          source:          "subdomain_cname_fingerprint",
          error:           null,
        },
        historical_changes: storedModules.historical_changes ?? {
          has_previous:       false,
          previous_scan_id:   null,
          previous_score:     null,
          current_score:      null,
          score_change:       null,
          new_subdomains:     [],
          removed_subdomains: [],
          new_findings:       [],
          resolved_findings:  [],
          new_takeover_risks: [],
          new_exposed_assets: [],
          source:             "previous_scan_comparison",
          error:              null,
        },
      };

      // Sprint 9A: normalise to v2 schema before returning — ensures old R2 reports
      // that pre-date the schema upgrade also expose the full v2 field set.
      const reportFindings = applyEvidenceQuality(
        (Array.isArray(raw.findings) ? raw.findings : []).map(normalizeFindingSchema)
      );

      // Compute Business Risk Score from scan findings + module signals.
      // Shared helper so the scan PDF (which reads the raw report) produces the
      // exact same score as this response.
      const businessRisk = deriveScanBusinessRisk(raw);

      const canonicalScore = resolveCanonicalScanScore(scan.score, raw.cyber_metrics_score);
      // Canonical completeness-aware presentation for THIS scan — a partial/degraded/
      // unknown scan gets no final rating and no trend delta.
      const scanQualityStatus = (raw.scan_quality ?? buildScanQuality(normalisedModules))?.status;
      const assessment = resolveAssessmentPresentation({ score: canonicalScore, scanQuality: scanQualityStatus, status: scan.status });
      const canonicalRiskLevel = assessment.display_rating;
      const historicalChanges = normalisedModules.historical_changes;
      normalisedModules.historical_changes = {
        ...historicalChanges,
        current_score: canonicalScore,
        comparable: assessment.comparable,
        // Only a complete assessment produces a delta — never improved/declined/+N.
        score_change: (assessment.comparable && historicalChanges?.previous_score != null)
          ? canonicalScore - historicalChanges.previous_score
          : null,
      };

      // Canonical eight-domain Cyber MOT coverage states — computed from THIS report,
      // with the SAME canonical Cyber Essentials snapshot every other surface uses, so
      // the CE state is identical across Dashboard, Scan Detail, Executive Report UI
      // and PDF. Compute-on-read; no new storage.
      let ceSnapshot = null;
      try {
        const ceWsId = scan.workspace_id || access?.workspace_id || null;
        if (ceWsId) ceSnapshot = await getCyberEssentialsSnapshot(ceWsId, env);
      } catch { ceSnapshot = null; }
      const cyberMotDomains = resolveCyberMotDomainStates({
        scan_id:      scan.id,
        completed_at: raw.completed_at,
        created_at:   raw.created_at,
        scan_quality: raw.scan_quality ?? buildScanQuality(normalisedModules),
        modules:      normalisedModules,
        findings:     reportFindings,
      }, { scanId: scan.id, cyberEssentials: ceSnapshot });

      return json({
        scan_id:             scan.id,
        domain:              scan.domain,
        status:              scan.status,
        cyber_metrics_score: assessment.display_score,
        risk_level:          canonicalRiskLevel,
        assessment,          // canonical decision: provisional/authoritative/comparable/quality/message
        cyber_mot_domains:   cyberMotDomains,
        findings:            reportFindings,
        recommendations:     Array.isArray(raw.recommendations) ? raw.recommendations : [],
        scan_quality:         raw.scan_quality ?? buildScanQuality(normalisedModules),
        modules:             normalisedModules,
        business_risk:       businessRisk,
        ...(raw.started_at   ? { started_at:   raw.started_at   } : {}),
        ...(raw.completed_at ? { completed_at: raw.completed_at } : {}),
        ...(raw.failed_at    ? { failed_at:    raw.failed_at    } : {}),
        ...(raw.message      ? { message:      raw.message      } : {}),
        ...(raw.error        ? { error:        raw.error        } : {}),
      });
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
