// ── Brand routes ──
// Brand Protection Intelligence v1 (profile / summary / candidates / classify)
// and legacy Brand Monitoring (list / summary / refresh) endpoints.
// Extracted near-verbatim from index.js (router split, Phase 2 PR #3).
// Receives the per-request routeCtx from index.js; returns a Response when a
// route matches, or null so the main router continues.
import { BRAND_CLASSIFICATIONS, BRAND_SUSPICIOUS_TLDS, brandCandidateToApi, brandClassificationAuditMetadata, brandProfileToApi, brandSimilarityScore, buildBrandIdnEvidence, buildBrandProfileDomainScope, buildBrandProtectionSummary, legacyBrandAssetToApi, loadWorkspaceBrandProfile, normalizeBrandVariantType, parseBrandCandidateListParams, scoreBrandCandidateRisk, validateBrandProfileInput } from "../engines/brand-protection.js";
import { approveBrandTakedown, brandCaseToApi, createBrandCaseForCandidateId, createBrandCasesForWorkspace, getBrandCase, listBrandCaseEvents, listBrandCases, recaptureBrandEvidenceBundle, recordBrandTakedownSubmission, reviewBrandCase, transitionBrandCase } from "../engines/brand-cases.js";
import { extractBrandParts, generateTyposquatCandidates, HIGH_RISK_BRAND_KEYWORDS } from "../engines/brand-typosquat.js";
import { dnsQuery } from "../engines/dns.js";
import { enrichBrandCandidatesDns, BRAND_DNS_MANUAL_BATCH_SIZE } from "../engines/brand-dns-enrichment.js";
import { createAuditEvent } from "../lib/events.js";
import { createId } from "../lib/util.js";

export async function brandRoutes(rctx) {
  const { request, env, url, json,
          requireAuth, requireWorkspaceRole } = rctx;
    // ── Brand Protection Intelligence v1 ──────────────────────────────────────
    // Persistent workflow APIs. These are additive; the legacy Brand Monitoring
    // routes below retain their response contracts for the existing frontend.
    const brandProfileMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/brand\/profile$/);
    const brandSummaryV1Match = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/brand\/summary$/);
    const brandCasesMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/brand\/cases(?:\/([^/]+)(?:\/(review|approve|submission|advance))?)?$/
    );
    const brandCandidatesMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/brand\/candidates(?:\/([^/]+)(?:\/(classify))?)?$/
    );
    if (brandProfileMatch || brandSummaryV1Match || brandCasesMatch || brandCandidatesMatch) {
      const wsId = (brandProfileMatch || brandSummaryV1Match || brandCasesMatch || brandCandidatesMatch)[1];
      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const isProfileWrite = Boolean(brandProfileMatch && request.method === "POST");
      const isCaseWrite = Boolean(brandCasesMatch && request.method !== "GET");
      const isClassificationWrite = Boolean(brandCandidatesMatch?.[3] === "classify" && request.method === "POST");
      const permission = isProfileWrite ? "workspace:manage"
        : isCaseWrite ? "workspace:manage"
        : isClassificationWrite ? "workspace:manage" : "workspace:read";
      const access = await requireWorkspaceRole(user, wsId, permission, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      try {
        const workspace = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ? LIMIT 1").bind(wsId).first();
        if (!workspace) return json({ error: "Workspace not found" }, 404);

        // GET /brand/profile — persisted profile or explicitly low-confidence
        // inference from real workspace domains. Inference is never persisted.
        if (brandProfileMatch && request.method === "GET") {
          return json({ profile: await loadWorkspaceBrandProfile(env, wsId) });
        }

        // POST /brand/profile — admin-managed protected brand scope.
        if (brandProfileMatch && request.method === "POST") {
          const body = await request.json().catch(() => null);
          const domainRows = await env.cybermeters_db
            .prepare(`SELECT d.domain FROM workspace_domains wd
                      JOIN domains d ON d.id = wd.domain_id WHERE wd.workspace_id = ?`)
            .bind(wsId).all();
          const workspaceDomains = (domainRows.results || []).map((row) => row.domain);
          const validated = validateBrandProfileInput(body, workspaceDomains);
          if (!validated.ok) return json({ error: validated.error }, 400);
          const value = validated.value;
          const existing = await env.cybermeters_db
            .prepare("SELECT id FROM workspace_brand_profiles WHERE workspace_id = ? LIMIT 1")
            .bind(wsId).first();
          const profileId = existing?.id || createId("brandprof");
          await env.cybermeters_db
            .prepare(`INSERT INTO workspace_brand_profiles
                        (id, workspace_id, brand_name, primary_domain, keywords_json,
                         protected_domains_json, created_at, updated_at)
                      VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                      ON CONFLICT(workspace_id) DO UPDATE SET
                        brand_name = excluded.brand_name,
                        primary_domain = excluded.primary_domain,
                        keywords_json = excluded.keywords_json,
                        protected_domains_json = excluded.protected_domains_json,
                        updated_at = datetime('now')`)
            .bind(profileId, wsId, value.brand_name, value.primary_domain,
              JSON.stringify(value.keywords), JSON.stringify(value.protected_domains)).run();
          await env.cybermeters_db
            .prepare("UPDATE workspace_brand_assets SET brand_profile_id = ? WHERE workspace_id = ?")
            .bind(profileId, wsId).run();
          const row = await env.cybermeters_db
            .prepare(`SELECT id, workspace_id, brand_name, primary_domain, keywords_json,
                             protected_domains_json, created_at, updated_at
                      FROM workspace_brand_profiles WHERE workspace_id = ? LIMIT 1`)
            .bind(wsId).first();
          await createAuditEvent(env, {
            workspace_id: wsId, user_id: user.id, event_type: "brand_profile_updated",
            entity_type: "brand_profile", entity_id: profileId,
            description: `Updated protected brand profile for ${value.brand_name}`,
            metadata: { brand_name: value.brand_name, primary_domain: value.primary_domain,
              keyword_count: value.keywords.length, protected_domain_count: value.protected_domains.length },
          });
          return json({ profile: brandProfileToApi(row) });
        }

        // GET /brand/summary — use the same normalized risk pipeline as the
        // candidate table so stale stored risk_level values cannot skew counts.
        if (brandSummaryV1Match && request.method === "GET") {
          const profile = await loadWorkspaceBrandProfile(env, wsId);
          const domainScope = buildBrandProfileDomainScope(profile);
          const rows = await env.cybermeters_db
            .prepare(`SELECT id, domain, candidate_domain, variant_type, similarity_score,
                             risk_level, risk_reasons, dns_resolves, https_available,
                             status, classification, first_seen, last_seen, last_checked_at,
                             mx_present, registrar_or_whois_summary, evidence_json,
                             created_at, updated_at
                      FROM workspace_brand_assets
                      WHERE workspace_id = ? AND ${domainScope.clause}`)
            .bind(wsId, ...domainScope.bindings).all();
          const candidates = (rows.results || []).map((row) => brandCandidateToApi(row, profile));
          return json(buildBrandProtectionSummary(candidates));
        }

        if (brandCasesMatch) {
          const caseId = brandCasesMatch[2] || null;
          const action = brandCasesMatch[3] || null;
          if (caseId && !/^[a-zA-Z0-9_-]{1,120}$/.test(caseId)) return json({ error: "Invalid case id" }, 400);

          if (!caseId && !action && request.method === "GET") {
            const cases = await listBrandCases(env, wsId, {
              status: url.searchParams.get("status"),
              limit: url.searchParams.get("limit") || 50,
            });
            return json({ workspace_id: wsId, cases });
          }

          const caseRow = caseId ? await getBrandCase(env, wsId, caseId) : null;
          if (!caseRow) return json({ error: "Brand case not found" }, 404);

          if (!action && request.method === "GET") {
            const events = await listBrandCaseEvents(env, wsId, caseId);
            return json({ case: brandCaseToApi(caseRow), events });
          }

          if (action === "review" && request.method === "POST") {
            const body = await request.json().catch(() => null);
            const classification = String(body?.classification || "").toLowerCase();
            let current = caseRow;
            if (current.status === "detected") {
              const triage = await transitionBrandCase(env, current, "triage", {
                actor_type: "customer", actor_id: user.id, action: "triage_started",
              });
              if (!triage.ok) return json({ error: triage.error }, 400);
              current = triage.case;
            }
            const result = await reviewBrandCase(env, current, {
              classification,
              reason: String(body?.reason || "").trim(),
              actor_id: user.id,
            });
            if (!result.ok) return json({ error: result.error }, 400);
            return json({ case: brandCaseToApi(result.case), events: await listBrandCaseEvents(env, wsId, caseId) });
          }

          if (action === "approve" && request.method === "POST") {
            const body = await request.json().catch(() => ({}));
            const reason = String(body?.reason || "Customer approved takedown preparation.").trim();
            const result = caseRow.status === "evidence_ready"
              ? await recaptureBrandEvidenceBundle(env, caseRow, { actor_id: user.id, reason: "Evidence bundle re-captured before submission." })
              : await approveBrandTakedown(env, caseRow, { actor_id: user.id, reason });
            if (!result.ok) return json({ error: result.error }, 400);
            return json({ case: brandCaseToApi(result.case), events: await listBrandCaseEvents(env, wsId, caseId) });
          }

          if (action === "submission" && request.method === "POST") {
            const body = await request.json().catch(() => null);
            const submissionReference = String(body?.submission_reference || "").trim();
            if (!submissionReference) return json({ error: "Submission reference is required" }, 400);
            const result = await recordBrandTakedownSubmission(env, caseRow, {
              actor_id: user.id,
              submission_reference: submissionReference,
              recipients: Array.isArray(body?.recipients) ? body.recipients : null,
              note: body?.note ? String(body.note) : null,
            });
            if (!result.ok) return json({ error: result.error }, 400);
            return json({ case: brandCaseToApi(result.case), events: await listBrandCaseEvents(env, wsId, caseId) });
          }

          if (action === "advance" && request.method === "POST") {
            const body = await request.json().catch(() => null);
            const target = String(body?.status || "").trim();
            const result = await transitionBrandCase(env, caseRow, target, {
              actor_type: "customer",
              actor_id: user.id,
              reason: body?.reason ? String(body.reason) : null,
              action: "manual_advance",
            });
            if (!result.ok) return json({ error: result.error }, 400);
            return json({ case: brandCaseToApi(result.case), events: await listBrandCaseEvents(env, wsId, caseId) });
          }
        }

        if (brandCandidatesMatch) {
          const candidateId = brandCandidatesMatch[2] || null;
          const action = brandCandidatesMatch[3] || null;
          if (candidateId && !/^[a-zA-Z0-9_-]{1,100}$/.test(candidateId)) {
            return json({ error: "Invalid candidate id" }, 400);
          }

          // GET /brand/candidates — bounded, allow-listed filters only.
          if (!candidateId && !action && request.method === "GET") {
            const params = parseBrandCandidateListParams(url.searchParams);
            const profile = await loadWorkspaceBrandProfile(env, wsId);
            const domainScope = buildBrandProfileDomainScope(profile);
            const where = ["workspace_id = ?"];
            const binds = [wsId];
            where.push(domainScope.clause);
            binds.push(...domainScope.bindings);
            if (params.risk) { where.push("risk_level = ?"); binds.push(params.risk); }
            if (params.status) { where.push("status = ?"); binds.push(params.status); }
            if (params.classification) {
              where.push("COALESCE(classification, 'unreviewed') = ?"); binds.push(params.classification);
            }
            const [rows, totalRow] = await Promise.all([
              env.cybermeters_db
                .prepare(`SELECT id, domain, candidate_domain, variant_type, similarity_score,
                                 risk_level, risk_reasons, dns_resolves, https_available,
                                 status, classification, first_seen, last_seen, last_checked_at,
                                 mx_present, registrar_or_whois_summary, evidence_json,
                                 created_at, updated_at
                          FROM workspace_brand_assets
                          WHERE ${where.join(" AND ")}
                          ORDER BY
                            -- Registered/live candidates first: a domain that
                            -- actually resolves (and can send mail) is the real
                            -- threat, ahead of theoretical permutations.
                            (COALESCE(mx_present, 0) + COALESCE(dns_resolves, 0)) DESC,
                            CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                              WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END,
                            CASE COALESCE(classification, 'unreviewed')
                              WHEN 'confirmed_abuse' THEN 0 WHEN 'suspicious' THEN 1
                              WHEN 'unreviewed' THEN 2 ELSE 3 END,
                            candidate_domain
                          LIMIT ? OFFSET ?`)
                .bind(...binds, params.limit, params.offset).all(),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM workspace_brand_assets WHERE ${where.join(" AND ")}`)
                .bind(...binds).first(),
            ]);
            const candidates = (rows.results || []).map((row) => brandCandidateToApi(row, profile));
            return json({ workspace_id: wsId, total: Number(totalRow?.n || 0),
              limit: params.limit, offset: params.offset, candidates });
          }

          const profile = await loadWorkspaceBrandProfile(env, wsId);
          const domainScope = buildBrandProfileDomainScope(profile);
          const row = await env.cybermeters_db
            .prepare(`SELECT id, workspace_id, domain, candidate_domain, variant_type,
                             similarity_score, risk_level, risk_reasons, dns_resolves,
                             https_available, status, classification, first_seen, last_seen,
                             last_checked_at, mx_present, registrar_or_whois_summary,
                             evidence_json, created_at, updated_at
                      FROM workspace_brand_assets
                      WHERE id = ? AND workspace_id = ? AND ${domainScope.clause} LIMIT 1`)
            .bind(candidateId, wsId, ...domainScope.bindings).first();
          if (!row) return json({ error: "Brand candidate not found" }, 404);

          // GET /brand/candidates/:id
          if (!action && request.method === "GET") {
            return json({ candidate: brandCandidateToApi(row, profile) });
          }

          // POST /brand/candidates/:id/classify
          if (action === "classify" && request.method === "POST") {
            const body = await request.json().catch(() => null);
            const classification = String(body?.classification || "").toLowerCase();
            const allowed = new Set(["owned", "ignored", "suspicious", "confirmed_abuse", "false_positive", "monitoring"]);
            if (!allowed.has(classification)) return json({ error: "Invalid classification" }, 400);
            const previous = BRAND_CLASSIFICATIONS.has(row.classification) ? row.classification : "unreviewed";
            const updatedAt = new Date().toISOString();
            const candidate = brandCandidateToApi({ ...row, classification, updated_at: updatedAt }, profile);
            await env.cybermeters_db
              .prepare(`UPDATE workspace_brand_assets
                        SET classification = ?, similarity_score = ?, risk_level = ?,
                            risk_reasons = ?, evidence_json = ?, updated_at = ?
                        WHERE id = ? AND workspace_id = ?`)
              .bind(classification, candidate.similarity_score, candidate.risk_level,
                JSON.stringify(candidate.risk_reasons), JSON.stringify(candidate.evidence),
                updatedAt, candidateId, wsId).run();
            const eventType = classification === "ignored" ? "brand_candidate_ignored"
              : classification === "owned" ? "brand_candidate_marked_owned"
                : classification === "suspicious" ? "brand_candidate_marked_suspicious"
                  : "brand_candidate_classified";
            await createAuditEvent(env, {
              workspace_id: wsId, user_id: user.id, event_type: eventType,
              entity_type: "brand_candidate", entity_id: candidateId,
              description: `Classified brand candidate ${row.candidate_domain} as ${classification}`,
              metadata: brandClassificationAuditMetadata(row, previous, classification, candidate.risk_level),
            });
            let managedCase = null;
            if (classification === "confirmed_abuse") {
              const caseResult = await createBrandCaseForCandidateId(env, wsId, candidateId, { actor_id: user.id }).catch(() => null);
              let caseRow = caseResult?.case || null;
              if (caseRow?.status === "detected") {
                const triage = await transitionBrandCase(env, caseRow, "triage", {
                  actor_type: "customer", actor_id: user.id, action: "triage_started",
                });
                if (triage.ok) caseRow = triage.case;
              }
              if (caseRow?.status === "triage") {
                const review = await reviewBrandCase(env, caseRow, {
                  classification: "confirmed_abuse",
                  reason: "Confirmed from brand candidate review.",
                  actor_id: user.id,
                });
                if (review.ok) caseRow = review.case;
              }
              managedCase = caseRow ? brandCaseToApi(caseRow) : null;
            }
            return json({ candidate, managed_case: managedCase });
          }
        }

        return json({ error: "Method not allowed" }, 405);
      } catch {
        return json({ error: "Brand protection request could not be completed" }, 500);
      }
    }

    // ── Brand Monitoring Routes ───────────────────────────────────────────────
    // GET  /api/workspaces/:id/brand-monitoring              — candidate list
    // GET  /api/workspaces/:id/brand-monitoring/summary      — risk summary
    // POST /api/workspaces/:id/brand-monitoring/refresh      — DNS validation pass
    //      (runs DoH A-record checks on top candidates; separate subrequest budget)
    const brandMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/brand-monitoring(\/summary|\/refresh)?$/
    );
    if (brandMatch && (request.method === 'GET' || request.method === 'POST')) {
      const wsId      = brandMatch[1];
      const subPath   = brandMatch[2];       // undefined | '/summary' | '/refresh'
      const isSummary = subPath === '/summary';
      const isRefresh = subPath === '/refresh';

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      // refresh requires analyst+; plain read requires viewer
      const minPerm = isRefresh ? "domain:add" : "workspace:read";
      const access = await requireWorkspaceRole(user, wsId, minPerm, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
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

      // ── POST /brand-monitoring/refresh ─────────────────────────────────────
      // Persists any missing candidates UNCHECKED, then delegates DNS validation
      // to the canonical enrichBrandCandidatesDns helper (the SAME code the hourly
      // cron sweep runs). One dedicated invocation → a larger batch than the cron.
      if (isRefresh && request.method === 'POST') {
        // Get primary (oldest-added) domain for this workspace
        let primaryDomain;
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT d.domain FROM workspace_domains wd
               JOIN domains d ON d.id = wd.domain_id
               WHERE wd.workspace_id = ?
               ORDER BY d.created_at ASC LIMIT 1`
            )
            .bind(wsId)
            .first();
          primaryDomain = r?.domain;
        } catch {
          return json({ error: 'Database error' }, 500);
        }
        if (!primaryDomain) return json({ error: 'No domains in workspace' }, 404);

        const { brand, tld } = extractBrandParts(primaryDomain);
        const allCandidates = generateTyposquatCandidates(brand, tld);
        const now           = new Date().toISOString();

        // Persist EVERY generated candidate as UNCHECKED (dns_resolves NULL) so the
        // canonical enrichment helper has the complete population to work through.
        // INSERT OR IGNORE never clobbers a row already persisted by a scan, a prior
        // refresh, or a customer classification — it only fills gaps. DNS state is
        // deliberately NOT set here; that is the enrichment helper's sole job.
        for (const c of allCandidates) {
          const similarity   = brandSimilarityScore(c.candidate_domain, brand);
          const idn          = buildBrandIdnEvidence(c.candidate_domain, brand);
          const candidateSld = c.candidate_domain.split('.')[0];
          const containsBrandKeyword = !idn.analysis.is_homograph && candidateSld.includes(brand);
          const looksLikeLogin = !idn.analysis.is_homograph &&
            HIGH_RISK_BRAND_KEYWORDS.some((keyword) => candidateSld.includes(keyword));
          const risk = scoreBrandCandidateRisk({
            variant_type: c.variant_type,
            similarity_score: similarity,
            dns_active: null,
            contains_brand_keyword: containsBrandKeyword,
            suspicious_tld: BRAND_SUSPICIOUS_TLDS.has(c.candidate_domain.split('.').pop()),
            looks_like_login: looksLikeLogin,
            idn_visual_confusable: idn.analysis.is_homograph,
            mixed_script: idn.analysis.mixed_script,
            whole_script_confusable: idn.analysis.whole_script_confusable,
            classification: "unreviewed",
          });
          const evidence = [
            { signal: "similar_to_brand", value: similarity },
            { signal: "variant_type", value: normalizeBrandVariantType(c.variant_type) },
            ...idn.evidence,
          ];
          if (containsBrandKeyword) evidence.push({ signal: "contains_brand_keyword", value: true });
          if (BRAND_SUSPICIOUS_TLDS.has(c.candidate_domain.split('.').pop())) evidence.push({ signal: "suspicious_tld", value: true });
          if (looksLikeLogin) evidence.push({ signal: "looks_like_login", value: true });
          try {
            await env.cybermeters_db
              .prepare(
                `INSERT OR IGNORE INTO workspace_brand_assets
                   (id, workspace_id, domain, candidate_domain, variant_type,
                    similarity_score, risk_level, risk_reasons, evidence_json, dns_resolves, https_available,
                    ip_address, status, first_seen, last_seen, last_checked_at, created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, 'unverified', ?, ?, NULL, ?, ?)`
              )
              .bind(
                createId('bra'), wsId, primaryDomain, c.candidate_domain, c.variant_type,
                similarity, risk.risk_level, JSON.stringify(risk.reasons), JSON.stringify(evidence),
                now, now, now, now,
              )
              .run();
          } catch { /* non-fatal */ }
        }

        try {
          await env.cybermeters_db
            .prepare(`UPDATE workspace_brand_assets
                      SET brand_profile_id = (SELECT id FROM workspace_brand_profiles WHERE workspace_id = ?)
                      WHERE workspace_id = ? AND brand_profile_id IS NULL`)
            .bind(wsId, wsId).run();
        } catch { /* profile is optional */ }

        // Canonical DNS enrichment — the SAME implementation the automatic hourly
        // cron sweep uses. Unchecked-first selection, tri-state truth, transient
        // failures left NULL for retry. One dedicated invocation → a larger batch.
        const stats = await enrichBrandCandidatesDns(env, wsId, {
          batchSize: BRAND_DNS_MANUAL_BATCH_SIZE, now, dnsQuery,
        });

        const managedCases = await createBrandCasesForWorkspace(env, wsId).catch(() => ({ opened: 0 }));

        return json({
          workspace_id:         wsId,
          brand,
          primary_domain:       primaryDomain,
          candidates_total:     allCandidates.length,
          candidates_checked:   stats.checked,
          active_domains:       stats.resolves,
          not_resolving:        stats.no_answer,
          inconclusive:         stats.transient,
          managed_cases_opened: managedCases.opened || 0,
          validated_at:         now,
        });
      }

      // ── GET /brand-monitoring/summary ───────────────────────────────────────
      if (isSummary && request.method === 'GET') {
        try {
          const [totalRow, byRiskRows, byStatusRows, highActiveRows] = await Promise.all([
            env.cybermeters_db
              .prepare('SELECT COUNT(*) AS n FROM workspace_brand_assets WHERE workspace_id = ?')
              .bind(wsId).first(),

            env.cybermeters_db
              .prepare(
                `SELECT risk_level, COUNT(*) AS n
                 FROM workspace_brand_assets WHERE workspace_id = ?
                 GROUP BY risk_level`
              )
              .bind(wsId).all(),

            env.cybermeters_db
              .prepare(
                `SELECT status, COUNT(*) AS n
                 FROM workspace_brand_assets WHERE workspace_id = ?
                 GROUP BY status`
              )
              .bind(wsId).all(),

            env.cybermeters_db
              .prepare(
                `SELECT candidate_domain, variant_type, risk_level, risk_reasons,
                        ip_address, status, first_seen, last_seen
                 FROM workspace_brand_assets
                 WHERE workspace_id = ? AND risk_level IN ('critical', 'high') AND status = 'active'
                 ORDER BY last_seen DESC LIMIT 10`
              )
              .bind(wsId).all(),
          ]);

          const byRisk   = Object.fromEntries((byRiskRows.results   || []).map(r => [r.risk_level, r.n]));
          const byStatus = Object.fromEntries((byStatusRows.results || []).map(r => [r.status, r.n]));

          return json({
            workspace_id:     wsId,
            total_candidates: totalRow?.n ?? 0,
            by_risk:          { critical: byRisk.critical ?? 0, high: byRisk.high ?? 0, medium: byRisk.medium ?? 0, low: byRisk.low ?? 0 },
            by_status:        { active: byStatus.active ?? 0, inactive: byStatus.inactive ?? 0, unverified: byStatus.unverified ?? 0 },
            high_risk_active: (highActiveRows.results || []).map(r => ({
              ...r,
              risk_reasons: (() => { try { return JSON.parse(r.risk_reasons); } catch { return []; } })(),
            })),
          });
        } catch {
          return json({ error: 'Database error' }, 500);
        }
      }

      // ── GET /brand-monitoring ────────────────────────────────────────────────
      if (!isSummary && !isRefresh && request.method === 'GET') {
        const filterStatus = url.searchParams.get('status');       // active|inactive|unverified
        const filterRisk   = url.searchParams.get('risk_level');   // high|medium|low
        const filterType   = url.searchParams.get('variant_type'); // substitution|omission|…

        const whereClauses = ['workspace_id = ?'];
        const binds        = [wsId];

        if (filterStatus) { whereClauses.push('status = ?');       binds.push(filterStatus); }
        if (filterRisk)   { whereClauses.push('risk_level = ?');   binds.push(filterRisk); }
        if (filterType)   { whereClauses.push('variant_type = ?'); binds.push(filterType); }

        const whereSQL = whereClauses.join(' AND ');

        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT candidate_domain, domain, variant_type, risk_level, risk_reasons,
                      dns_resolves, https_available, ip_address, status, first_seen, last_seen
               FROM workspace_brand_assets
               WHERE ${whereSQL}
               ORDER BY
                 CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                 CASE status     WHEN 'active'   THEN 0 WHEN 'unverified' THEN 1 ELSE 2 END,
                 candidate_domain`
            )
            .bind(...binds)
            .all();

          const assets = (r.results || []).map(legacyBrandAssetToApi);

          return json({ workspace_id: wsId, count: assets.length, candidates: assets });
        } catch {
          return json({ error: 'Database error' }, 500);
        }
      }
    }

  return null;
}
