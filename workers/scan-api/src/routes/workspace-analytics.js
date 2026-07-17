// ── Workspace analytics routes ──
// Read-only scorecard / Cyber Essentials readiness / business-risk endpoints.
// Extracted near-verbatim from index.js (router split, Phase 2 PR #1).
// Receives the per-request routeCtx from index.js; returns a Response when a
// route matches, or null so the main router continues.
import { buildCyberEssentialsReadiness } from "../engines/ce-readiness.js";
import { CE_QUESTIONS, CE_QUESTION_SET_VERSION, CE_QUESTION_SET_PROVENANCE, mergeReadiness } from "../lib/cyber-essentials.js";
import { buildWorkspaceExecutivePdf } from "../engines/pdf.js";
import { readLatestWorkspaceSnapshots } from "../engines/report-snapshot.js";
import { resolveReportBranding } from "../engines/report-branding.js";
import { prepareLogoXObject } from "../engines/pdf-image.js";
import { buildScorecardData } from "../engines/scorecard.js";
import { getEffectivePlan, hasFeatureEntitlement } from "../engines/entitlements.js";
import { createId } from "../lib/util.js";

export async function workspaceAnalyticsRoutes(rctx) {
  const { request, env, ctx, url, json, serverError,
          requireAuth, requireWorkspaceRole, getWorkspaceBillingUserId,
          corsHeaders, isActionableFinding } = rctx;
    // ── GET /api/workspaces/:id/scorecard/pdf ─────────────────────────────────
    // Snapshot-native (M5.d): the executive PDF renders the latest completed
    // canonical snapshot per domain — no live recalculation on this path.
    const pdfMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scorecard\/pdf$/);
    if (pdfMatch && request.method === 'GET') {
      const wsId = pdfMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'business_risk_score')) {
          return json({ error: 'plan_feature_required', feature: 'business_risk_score', required_plan: 'starter', upgrade_url: '/billing' }, 403);
        }
      }
      try {
        const ws = await env.cybermeters_db
          .prepare(`SELECT id, name FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
          .bind(wsId).first();
        if (!ws) return json({ error: 'Workspace not found' }, 404);
        const reads = await readLatestWorkspaceSnapshots(env, wsId);
        let branding = null, logoImage = null;
        try {
          branding = await resolveReportBranding(env, wsId);
          if (branding?.logo) logoImage = await prepareLogoXObject(branding.logo, branding.accent);
        } catch { branding = null; logoImage = null; }
        // Live render: the artefact timestamp is the request time by design
        // (this endpoint is the on-demand variant of the stored report).
        const generatedAt = new Date().toISOString();
        const bytes = buildWorkspaceExecutivePdf({ workspaceName: ws.name, reads, branding, generatedAt, logoImage });
        const wsSlug = String(ws.name ?? 'report')
          .toLowerCase().replace(/\s+/g, '-').replace(/[^a-z0-9-]/g, '');
        const filename = `cybermeters-executive-report-${wsSlug}-${generatedAt.slice(0, 10)}.pdf`;
        return new Response(bytes, {
          status: 200,
          headers: {
            ...corsHeaders,
            'Content-Type':        'application/pdf',
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length':      String(bytes.length),
          },
        });
      } catch (err) {
        // Customer-safe: never echo internal error detail (the previous body
        // leaked err.message + endpoint + timestamp).
        return serverError("scorecard/pdf", err, "PDF generation failed.");
      }
    }

    // ── GET /api/workspaces/:id/scorecard/pdf-data ──────────────────────────
    // Snapshot metadata + verified snapshot bodies for export tooling. The old
    // collectPdfData recalculation blob is retired with the legacy PDF brain.
    const pdfDataMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/scorecard\/pdf-data$/);
    if (pdfDataMatch && request.method === 'GET') {
      const wsId = pdfDataMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'business_risk_score')) {
          return json({ error: 'plan_feature_required', feature: 'business_risk_score', required_plan: 'starter', upgrade_url: '/billing' }, 403);
        }
      }
      try {
        const ws = await env.cybermeters_db
          .prepare(`SELECT id, name FROM workspaces WHERE id = ? AND deleted_at IS NULL`)
          .bind(wsId).first();
        if (!ws) return json({ error: 'Workspace not found' }, 404);
        const reads = await readLatestWorkspaceSnapshots(env, wsId);
        return json({
          workspace: { id: ws.id, name: ws.name },
          snapshots: reads.map((r) => r.status === "ok"
            ? { status: "ok", snapshot: r.snapshot, integrity: r.integrity }
            : { status: r.status, domain_id: r.domain_id ?? null, scan_id: r.scan_id ?? null }),
        });
      } catch (err) {
        return serverError("scorecard/pdf-data", err, "Report data could not be generated.");
      }
    }

    // ── Cyber Essentials Readiness — self-attestation answers ────────────────
    // GET returns the question set + stored answers; PUT upserts answers. The
    // questionnaire covers the INTERNAL controls we cannot observe externally;
    // the readiness endpoint merges these with measured signal (measured wins).
    const ceAnswersMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/cyber-essentials\/answers$/
    );
    if (ceAnswersMatch && (request.method === 'GET' || request.method === 'PUT')) {
      const wsId = ceAnswersMatch[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, request.method === 'PUT' ? "workspace:manage" : "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'cyber_essentials')) {
          return json({ error: 'plan_feature_required', feature: 'cyber_essentials', required_plan: 'professional', upgrade_url: '/billing' }, 403);
        }
      }

      const validKeys = new Map(CE_QUESTIONS.map((c) => [c.control_key, new Set(c.questions.map((q) => q.key))]));
      const validAnswers = new Set(['yes', 'partial', 'no', 'unknown']);

      if (request.method === 'PUT') {
        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
        const items = Array.isArray(body?.answers) ? body.answers : [];
        for (const it of items) {
          const ck = String(it?.control_key ?? '');
          const qk = String(it?.question_key ?? '');
          const ans = String(it?.answer ?? '');
          // Ignore unknown control/question/answer keys — never trust client input.
          if (!validKeys.has(ck) || !validKeys.get(ck).has(qk) || !validAnswers.has(ans)) continue;
          try {
            // ── THE RE-VERSIONING CONTRACT — enforced in SQL, not in the client ──
            //
            // The client submits the FULL questionnaire on every save, not a delta:
            // saveAnswers() → flattenAnswers(answers) (WorkspaceCyberEssentialsPage.jsx)
            // flattens all 20 answers the page holds, untouched ones included. So an
            // unconditional `question_set_version = excluded.question_set_version` re-stamps
            // EVERY row on EVERY save — a customer editing one question would silently
            // relabel the other 19 as answers to the CURRENT wording, including questions
            // reworded since that they never saw. That is precisely the defect this column
            // exists to prevent.
            //
            // It cannot be fixed by making the client send a delta: a crafted or future
            // client would bypass that. The rule therefore lives here, and it is ONE rule:
            //
            //   THE ANSWER IS THE ATTESTATION. The version moves only when the answer does.
            //
            //   • new row                        → active version (they are answering it now)
            //   • answer VALUE changed           → active version (a genuine re-attestation)
            //   • answer same, note changed      → KEEP the stored version. A note is context
            //                                      ABOUT an attestation, not the attestation:
            //                                      "yes, via Intune" is the same yes. Only
            //                                      updated_at moves.
            //   • answer same, note same         → a NO-OP. The WHERE below means SQLite
            //                                      writes nothing at all, so updated_at,
            //                                      answered_by and the version are all
            //                                      preserved byte-for-byte. Loading the page
            //                                      and pressing Save changes nothing, and a
            //                                      crafted client resubmitting identical
            //                                      values cannot force a re-version.
            //
            // `IS NOT` is SQLite's null-safe comparison, so a stored NULL note or version
            // cannot make either branch silently misfire.
            await env.cybermeters_db
              .prepare(`INSERT INTO cyber_essentials_answers (id, workspace_id, control_key, question_key, answer, note, answered_by, question_set_version, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
                        ON CONFLICT(workspace_id, control_key, question_key)
                        DO UPDATE SET
                          answer = excluded.answer,
                          note = excluded.note,
                          answered_by = excluded.answered_by,
                          question_set_version = CASE
                            WHEN cyber_essentials_answers.answer IS NOT excluded.answer
                              THEN excluded.question_set_version
                            ELSE cyber_essentials_answers.question_set_version
                          END,
                          updated_at = datetime('now')
                        WHERE cyber_essentials_answers.answer IS NOT excluded.answer
                           OR cyber_essentials_answers.note IS NOT excluded.note`)
              .bind(createId(), wsId, ck, qk, ans, it?.note ? String(it.note).slice(0, 500) : null, user.id, CE_QUESTION_SET_VERSION)
              .run();
          } catch { /* skip a bad row, keep going — never surface raw DB errors */ }
        }
      }

      let answerRows = { results: [] };
      try {
        answerRows = await env.cybermeters_db
          .prepare(`SELECT control_key, question_key, answer, note, question_set_version, updated_at FROM cyber_essentials_answers WHERE workspace_id = ?`)
          .bind(wsId).all();
      } catch { /* empty answer set */ }
      const answers = {};
      // Which question was this actually an answer TO? Additive and kept SEPARATE from
      // `answers` so the existing response shape is untouched. A NULL version means the row
      // predates mig 092's backfill; it is reported as null rather than guessed at.
      const answer_versions = {};
      for (const r of (answerRows.results || [])) {
        if (!answers[r.control_key]) answers[r.control_key] = {};
        answers[r.control_key][r.question_key] = r.answer;
        if (!answer_versions[r.control_key]) answer_versions[r.control_key] = {};
        answer_versions[r.control_key][r.question_key] = r.question_set_version ?? null;
      }
      return json({
        question_set_version: CE_QUESTION_SET_VERSION,
        question_set_provenance: CE_QUESTION_SET_PROVENANCE,
        questions: CE_QUESTIONS,
        answers,
        answer_versions,
      });
    }

    // ── GET /api/workspaces/:id/cyber-essentials-readiness ───────────────────
    // Cyber Essentials readiness guidance only. Dynamically calculated from
    // existing CyberMeters scan/report/workspace intelligence data.
    const cyberEssentialsMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/cyber-essentials-readiness$/
    );
    if (cyberEssentialsMatch && request.method === 'GET') {
      const wsId = cyberEssentialsMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'cyber_essentials')) {
          return json({ error: 'plan_feature_required', feature: 'cyber_essentials', required_plan: 'professional', upgrade_url: '/billing' }, 403);
        }
      }

      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare('SELECT id FROM workspaces WHERE id = ?')
          .bind(wsId)
          .first();
      } catch {
        return json({ error: 'Database error' }, 500);
      }
      if (!ws) return json({ error: 'Workspace not found' }, 404);

      const readiness = await buildCyberEssentialsReadiness(wsId, env);
      if (!readiness) return json({ error: 'Database error' }, 500);
      // Additive: merge self-attestation answers with the measured categories
      // (measured wins on contradiction). Never break base readiness if this fails.
      try {
        const arows = await env.cybermeters_db
          .prepare(`SELECT control_key, question_key, answer FROM cyber_essentials_answers WHERE workspace_id = ?`)
          .bind(wsId).all();
        const answers = {};
        for (const r of (arows.results || [])) {
          if (!answers[r.control_key]) answers[r.control_key] = {};
          answers[r.control_key][r.question_key] = r.answer;
        }
        const measured = (readiness.categories || []).map((c) => ({
          control_key: c.key, measured_score: c.score, measured_gaps: c.gaps || [],
        }));
        readiness.self_assessment = {
          question_set_version: CE_QUESTION_SET_VERSION,
          controls: mergeReadiness(measured, answers),
        };
      } catch { /* self-assessment is additive; base readiness stands */ }
      return json(readiness);
    }

    // ── Executive Security Scorecard Routes ──────────────────────────────────
    // GET /api/workspaces/:id/scorecard         — business scorecard
    // GET /api/workspaces/:id/scorecard/report  — PDF-ready structured JSON
    const scorecardMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/scorecard(\/report)?$/
    );
    if (scorecardMatch && request.method === 'GET') {
      const wsId     = scorecardMatch[1];
      const isReport = !!scorecardMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare('SELECT id, name FROM workspaces WHERE id = ?')
          .bind(wsId)
          .first();
      } catch {
        return json({ error: 'Database error' }, 500);
      }
      if (!ws) return json({ error: 'Workspace not found' }, 404);

      const scorecard = await buildScorecardData(wsId, env);
      if (!scorecard) return json({ error: 'Database error' }, 500);

      // ── GET /scorecard ────────────────────────────────────────────────────
      if (!isReport) return json(scorecard);

      // ── GET /scorecard/report — structured for PDF rendering ─────────────
      const generatedAt = new Date().toISOString();

      // Derive per-section status: 'ok' | 'warning' | 'critical' | 'unknown'
      const sections = [
        {
          title:   'Asset Inventory',
          status:  scorecard.active_assets === 0 ? 'unknown'
                 : scorecard.new_assets_30d > 0  ? 'warning' : 'ok',
          summary: scorecard.active_assets > 0
            ? `${scorecard.active_assets} active assets monitored.` +
              (scorecard.new_assets_30d > 0
                ? ` ${scorecard.new_assets_30d} new in the last 30 days.`
                : ' No new assets in the last 30 days.')
            : 'No assets have been inventoried yet. Run a scan to begin discovery.',
          data: {
            active_assets:    scorecard.active_assets,
            new_assets_30d:   scorecard.new_assets_30d,
            asset_events_30d: scorecard.asset_events_30d,
          },
        },
        {
          title:   'Vendor Risk',
          status:  scorecard.vendor_risk.high   > 0 ? 'critical'
                 : scorecard.vendor_risk.medium > 0 ? 'warning' : 'ok',
          summary: scorecard.vendors_detected > 0
            ? `${scorecard.vendors_detected} vendor${scorecard.vendors_detected !== 1 ? 's' : ''} detected.` +
              (scorecard.vendor_risk.high > 0
                ? ` ${scorecard.vendor_risk.high} high-risk.`
                : ' No high-risk vendors.')
            : 'No third-party vendors detected in this scan.',
          data: {
            total:  scorecard.vendors_detected,
            ...scorecard.vendor_risk,
          },
        },
        {
          title:   'Third-Party Assets',
          status:  scorecard.third_party_assets > 0 ? 'warning' : 'ok',
          summary: scorecard.third_party_assets > 0
            ? `${scorecard.third_party_assets} third-party SaaS service${scorecard.third_party_assets !== 1 ? 's' : ''} in use (email, CRM, support, marketing).`
            : 'No third-party SaaS dependencies detected.',
          data: { count: scorecard.third_party_assets },
        },
        {
          title:   'SaaS Exposure',
          status:  scorecard.saas_exposures > 0 ? 'warning' : 'ok',
          summary: scorecard.saas_exposures > 0
            ? `${scorecard.saas_exposures} exposed SaaS portal${scorecard.saas_exposures !== 1 ? 's' : ''} or login surface${scorecard.saas_exposures !== 1 ? 's' : ''} detected.`
            : 'No externally exposed SaaS portals detected.',
          data: { count: scorecard.saas_exposures },
        },
        {
          title:   'Admin Surfaces',
          status:  scorecard.admin_surfaces > 0 ? 'critical' : 'ok',
          summary: scorecard.admin_surfaces > 0
            ? `${scorecard.admin_surfaces} admin or management interface${scorecard.admin_surfaces !== 1 ? 's' : ''} publicly exposed.`
            : 'No exposed admin surfaces detected.',
          data: { count: scorecard.admin_surfaces },
        },
        {
          title:   'Brand Monitoring',
          status:  scorecard.brand_risks.high   > 0 ? 'critical'
                 : scorecard.brand_risks.active > 0 ? 'warning' : 'ok',
          summary: scorecard.brand_risks.active > 0
            ? `${scorecard.brand_risks.active} active typosquat domain${scorecard.brand_risks.active !== 1 ? 's' : ''} detected.` +
              (scorecard.brand_risks.high > 0
                ? ` ${scorecard.brand_risks.high} high-risk.`
                : '')
            : `${scorecard.brand_risks.total} candidate domain${scorecard.brand_risks.total !== 1 ? 's' : ''} generated — none currently resolving.`,
          data: scorecard.brand_risks,
        },
        {
          title:   'Certificate Intelligence',
          status:  scorecard.certificate_risks.risk_level === 'critical' ? 'critical'
                 : scorecard.certificate_risks.risk_level === 'high'     ? 'warning'
                 : scorecard.certificate_risks.signals > 0               ? 'warning'
                 : scorecard.certificate_risks.risk_level === null        ? 'unknown' : 'ok',
          summary: scorecard.certificate_risks.risk_level
            ? `Certificate risk is ${scorecard.certificate_risks.risk_level}.` +
              (scorecard.certificate_risks.signals > 0
                ? ` ${scorecard.certificate_risks.signals} suspicious signal${scorecard.certificate_risks.signals !== 1 ? 's' : ''} detected.`
                : ' No suspicious signals.')
            : 'Certificate data not yet available from the latest scan.',
          data: scorecard.certificate_risks,
        },
        {
          title:   'Security Findings',
          status:  scorecard.critical_findings > 0 ? 'critical'
                 : scorecard.high_findings     > 0 ? 'warning' : 'ok',
          summary: (scorecard.critical_findings + scorecard.high_findings) === 0
            ? `No critical or high findings.` +
              (scorecard.medium_findings + scorecard.low_findings > 0
                ? ` ${scorecard.medium_findings + scorecard.low_findings} lower-severity finding${(scorecard.medium_findings + scorecard.low_findings) !== 1 ? 's' : ''} noted.`
                : ' Clean scan.')
            : `${scorecard.critical_findings} critical, ${scorecard.high_findings} high, ${scorecard.medium_findings} medium, ${scorecard.low_findings} low findings.`,
          data: {
            critical: scorecard.critical_findings,
            high:     scorecard.high_findings,
            medium:   scorecard.medium_findings,
            low:      scorecard.low_findings,
          },
        },
      ];

      // security_posture_chart — flat array for radar/bar chart rendering
      const sp = scorecard.security_posture;
      const security_posture_chart = sp
        ? [
            { category: 'Email Security',    score: sp.email_security?.score    ?? null, status: sp.email_security?.status    ?? 'unknown' },
            { category: 'SSL & Certificates',score: sp.ssl_certificates?.score  ?? null, status: sp.ssl_certificates?.status  ?? 'unknown' },
            { category: 'Attack Surface',    score: sp.attack_surface?.score    ?? null, status: sp.attack_surface?.status    ?? 'unknown' },
            { category: 'Third-Party Risk',  score: sp.third_party_risk?.score  ?? null, status: sp.third_party_risk?.status  ?? 'unknown' },
            { category: 'Admin Exposure',    score: sp.admin_exposure?.score    ?? null, status: sp.admin_exposure?.status    ?? 'unknown' },
          ]
        : [];

      return json({
        generated_at:           generatedAt,
        workspace:              { id: wsId, name: scorecard.workspace_name },
        scorecard,
        executive_summary:      scorecard.executive_summary,
        recommendations:        scorecard.top_recommendations,
        sections,
        security_posture:       scorecard.security_posture ?? null,
        security_posture_chart,
      });
    }

    // ── GET /api/workspaces/:id/business-risk ────────────────────────────────
    // Returns current BRS + trend data from historical_scores.
    const businessRiskMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/business-risk$/
    );
    if (businessRiskMatch && request.method === 'GET') {
      const wsId = businessRiskMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);
      {
        const ownerId = await getWorkspaceBillingUserId(wsId, user.id, env);
        const plan = await getEffectivePlan(ownerId, env);
        if (!hasFeatureEntitlement(plan, 'business_risk_score')) {
          return json({ error: 'plan_feature_required', feature: 'business_risk_score', required_plan: 'starter', upgrade_url: '/billing' }, 403);
        }
      }

      // Verify workspace exists
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare('SELECT id, name FROM workspaces WHERE id = ?')
          .bind(wsId).first();
      } catch {
        return json({ error: 'Database error' }, 500);
      }
      if (!ws) return json({ error: 'Workspace not found' }, 404);

      // Pure read (M5.e founder contract): the canonical workspace BRS is
      // computed and persisted at scan finalize (computeAndPersistWorkspaceBrs,
      // engines/business-risk.js). This GET serves that persisted result and
      // its scan-cadence trend — it never writes and never recalculates, so it
      // can never diverge from the canonical persisted value.
      try {
        const [row, historicalRows] = await Promise.all([
          env.cybermeters_db
            .prepare(`SELECT score, risk_band, calculated_at, payload_json
                      FROM workspace_brs_scores WHERE workspace_id = ?`)
            .bind(wsId).first(),
          env.cybermeters_db
            .prepare(`SELECT brs_score, score, rating, created_at
                      FROM historical_scores
                      WHERE workspace_id = ? AND brs_score IS NOT NULL
                      ORDER BY created_at DESC LIMIT 30`)
            .bind(wsId).all(),
        ]);

        const trend = (historicalRows.results ?? []).reverse().map(r => ({
          date: r.created_at, brs_score: r.brs_score, asm_score: r.score,
        }));

        let payload = null;
        if (row?.payload_json) {
          try { payload = JSON.parse(row.payload_json); } catch { payload = null; }
        }
        if (!payload) {
          // No canonical assessment persisted yet (no finalized scan since the
          // contract change, or pre-094 row) — honest not-assessed, never a
          // recomputed number and never a fabricated grade.
          return json({
            workspace_name: ws.name,
            state: "not_assessed",
            business_risk_score: null, score: null, brs: null,
            risk_band: row?.risk_band ?? null, band: row?.risk_band ?? null,
            grade: null, grade_label: row?.risk_band ?? null,
            narrative: "Business risk has not been assessed yet — it is calculated when a scan completes.",
            top_concerns: [], latest_scan: null, workspace_context: null,
            calculated_at: row?.calculated_at ?? null,
            trend,
          });
        }
        return json({ ...payload, workspace_name: ws.name, state: "assessed", trend });
      } catch (err) {
        return serverError("business-risk", err);
      }
    }

  return null;
}
