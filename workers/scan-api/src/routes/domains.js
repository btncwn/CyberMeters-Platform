// ── Domain routes ──
// Bulk domain import, domain verification lifecycle (create-challenge /
// verify / check), and domain detail endpoints. Extracted near-verbatim from
// index.js (router split, Phase 2 PR #10). Receives the per-request routeCtx
// from index.js; returns a Response when a route matches, or null so the main
// router continues. Dispatched BEFORE the workspaces-core wsMatch block so
// /domains/import keeps winning over the :domainId pattern, as before.
import { dnsQuery } from "../engines/dns.js";
import { getEffectivePlan } from "../engines/entitlements.js";
import { normalizeHostname } from "../engines/hostnames.js";
import { getAccountUsage, getEntitlementUsage, getPlanLimits, getWorkspaceBillingUserId, planLimitExceeded } from "../engines/plan-usage.js";
import { hashToken } from "../lib/auth-crypto.js";
import { resolveVerificationWorkspace } from "../lib/domain-verification.js";
import { customerSafeFailure } from "../lib/errors.js";
import { createAuditEvent, createNotificationEvent } from "../lib/events.js";
import { createId, isValidDomain } from "../lib/util.js";

export async function domainRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, requireWorkspaceRole, requireDomainRole } = rctx;

    // ── POST /api/workspaces/:id/domains/import ───────────────────────────────
    const importMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/import$/);
    if (importMatch && request.method === "POST") {
      const workspaceId = importMatch[1];
      // RBAC: admin or above required to import domains
      const importUser = await requireAuth(request, env);
      if (!importUser) return json({ error: "Unauthorized" }, 401);
      const importAccess = await requireWorkspaceRole(importUser, workspaceId, "domain:import", env);
      if (!importAccess) return json({ error: "Forbidden — admin role required to import domains" }, 403);
      try {
        const ws = await env.cybermeters_db
          .prepare("SELECT id FROM workspaces WHERE id = ?")
          .bind(workspaceId)
          .first();
        if (!ws) return json({ error: "Workspace not found" }, 404);

        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }

        const rawList = Array.isArray(body.domains) ? body.domains : [];
        if (rawList.length === 0) return json({ error: "domains array is required and must not be empty" }, 400);
        if (rawList.length > 500) return json({ error: "Maximum 500 domains per import" }, 400);

        // Normalize + validate
        const invalid  = [];
        const valid    = [];
        const seen     = new Set();
        for (const raw of rawList) {
          if (typeof raw !== "string") { invalid.push(String(raw)); continue; }
          const d = normalizeHostname(raw.trim().toLowerCase());
          if (!d || !isValidDomain(d)) { invalid.push(raw.trim()); continue; }
          if (seen.has(d)) continue; // input-level dup
          seen.add(d);
          valid.push(d);
        }

        if (valid.length === 0) {
          return json({ imported: 0, skipped: 0, invalid: invalid.length, total: rawList.length });
        }

        // Entitlement: per-workspace limit + account-level limit — check before touching DB
        const importBillingUserId = await getWorkspaceBillingUserId(workspaceId, importUser.id, env);
        const impPlan = await getEffectivePlan(importBillingUserId, env);
        const impUsage  = await getEntitlementUsage(importUser, env, workspaceId);
        const impLimits = getPlanLimits(impPlan);
        // (a) Per-workspace headroom
        const wsRemaining = impLimits.domains_per_workspace - impUsage.domains_in_workspace;
        if (wsRemaining <= 0) {
          return json(planLimitExceeded("domains", impLimits.domains, impUsage.domains_in_workspace), 403);
        }
        // (b) Account-level headroom across all owned workspaces
        const impOwnerAcct = await getAccountUsage(importBillingUserId, env);
        const acctRemaining = impLimits.domains - impOwnerAcct.domains;
        if (acctRemaining <= 0) {
          return json(planLimitExceeded("domains", impLimits.domains, impOwnerAcct.domains), 403);
        }
        // Trim to whichever headroom is smaller
        const remaining = Math.min(wsRemaining, acctRemaining);
        // Trim valid list to what fits
        const validTrimmed = valid.slice(0, remaining);
        const trimmedCount = valid.length - validTrimmed.length;
        const validToImport = validTrimmed;

        // Find existing domains in this workspace
        const existingRows = await env.cybermeters_db
          .prepare("SELECT d.domain FROM domains d JOIN workspace_domains wd ON wd.domain_id = d.id WHERE wd.workspace_id = ?")
          .bind(workspaceId)
          .all();
        const existingSet = new Set((existingRows.results || []).map((r) => r.domain));

        let imported = 0;
        let skipped  = 0;

        for (const domain of validToImport) {
          if (existingSet.has(domain)) { skipped++; continue; }

          // Find or create domain record.
          // domains.domain has no UNIQUE constraint in D1, so ON CONFLICT(domain) is invalid.
          // Use a safe SELECT-then-INSERT pattern instead.
          let domainId;
          const existingDom = await env.cybermeters_db
            .prepare("SELECT id FROM domains WHERE domain = ? AND user_id = ? LIMIT 1")
            .bind(domain, importUser.id)
            .first();
          if (existingDom) {
            domainId = existingDom.id;
          } else {
            domainId = createId("dom");
            await env.cybermeters_db
              .prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)")
              .bind(domainId, importUser.id, domain)
              .run();
          }

          // Link to workspace
          const already = await env.cybermeters_db
            .prepare("SELECT workspace_id FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?")
            .bind(workspaceId, domainId)
            .first();

          if (already) { skipped++; continue; }

          await env.cybermeters_db
            .prepare("INSERT OR IGNORE INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)")
            .bind(workspaceId, domainId)
            .run();

          imported++;
        }

        // Audit: domain import completed
        await createAuditEvent(env, {
          workspace_id: workspaceId,
          user_id:      importUser?.id ?? null,
          event_type:   "domain_imported",
          entity_type:  "domain",
          description:  `Imported ${imported} domain${imported !== 1 ? "s" : ""} (${skipped} skipped, ${invalid.length} invalid)`,
          metadata:     { imported, skipped, invalid: invalid.length, total: rawList.length },
        });

        return json({ imported, skipped, invalid: invalid.length, trimmed: trimmedCount, total: rawList.length }, 200);
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ════════════════════════════════════════════════════════════════════════
    // DMARC Report Ingestion & Sender Intelligence v1 — manual import + reads.
    // All routes are workspace-scoped and validate domain ownership. Additive.
    // ════════════════════════════════════════════════════════════════════════

    // ── POST /api/domains/:id/verification ───────────────────────────────────
    // Generate a cryptographically secure token and return DNS + HTML instructions.
    // Idempotent: calling again resets to a new pending token.
    const domVerInitMatch = url.pathname.match(/^\/api\/domains\/([^/]+)\/verification$/);
    if (domVerInitMatch && request.method === "POST") {
      const domainId = domVerInitMatch[1];
      try {
        // Auth BEFORE any lookup — an unauthenticated caller must never learn
        // whether a domain id exists (404 vs 401 is an existence oracle).
        const dviUser = await requireAuth(request, env);
        if (!dviUser) return json({ error: "Unauthorized" }, 401);

        const domRow = await env.cybermeters_db
          .prepare("SELECT id, domain FROM domains WHERE id = ?")
          .bind(domainId)
          .first();
        if (!domRow) return json({ error: "Domain not found" }, 404);

        // Verification is WORKSPACE-scoped: resolve the exact workspace to verify.
        // Prefer an explicit workspace_id; auto-resolve only when unambiguous. A
        // denied/absent workspace returns the SAME 404 as a nonexistent domain.
        let dviBody = {};
        try { dviBody = await request.json(); } catch { /* optional body */ }
        const dviWs = await resolveVerificationWorkspace(dviUser, domainId, dviBody?.workspace_id, requireWorkspaceRole, env);
        if (dviWs.error) return json({ error: dviWs.error, ...(dviWs.code ? { code: dviWs.code } : {}) }, dviWs.status);
        const dviWorkspaceId = dviWs.workspace_id;

        // Already verified for THIS workspace — don't reset it.
        const dviLink = await env.cybermeters_db
          .prepare("SELECT verification_status FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?")
          .bind(dviWorkspaceId, domainId)
          .first();
        if (dviLink?.verification_status === "verified") {
          return json({
            already_verified: true,
            domain: domRow.domain,
            workspace_id: dviWorkspaceId,
            verification_status: "verified",
          });
        }

        // Generate a cryptographically secure 48-char hex token
        const tokenBytes = new Uint8Array(24);
        crypto.getRandomValues(tokenBytes);
        const token = Array.from(tokenBytes).map(b => b.toString(16).padStart(2, "0")).join("");

        // Store the token on the EXACT workspace-domain relationship (not the legacy
        // global domains row, which is now read-only compatibility data).
        await env.cybermeters_db
          .prepare(`UPDATE workspace_domains
                    SET verification_status = 'pending',
                        verification_token  = ?,
                        verification_method = NULL,
                        verified_at         = NULL,
                        verification_initiated_at = datetime('now')
                    WHERE workspace_id = ? AND domain_id = ?`)
          .bind(token, dviWorkspaceId, domainId)
          .run();

        const domain = domRow.domain;
        await createAuditEvent(env, {
          workspace_id: dviWorkspaceId,
          user_id:      dviUser.id,
          event_type:   "domain_verification_token_generated",
          entity_type:  "domain",
          entity_id:    domainId,
          description:  `Verification token generated for ${domain}`,
          metadata:     { domain, domain_id: domainId, workspace_id: dviWorkspaceId, method_options: ["dns_txt", "html_file"] },
        });
        return json({
          domain,
          domain_id:          domainId,
          workspace_id:       dviWorkspaceId,
          verification_status: "pending",
          token,
          dns: {
            record_type: "TXT",
            host:        `_cybermeters.${domain}`,
            value:       `cybermeters-verification=${token}`,
            instructions: [
              `Add a DNS TXT record to your domain:`,
              `  Host:  _cybermeters.${domain}`,
              `  Type:  TXT`,
              `  Value: cybermeters-verification=${token}`,
              `DNS changes can take up to 48 hours to propagate globally.`,
            ],
          },
          html: {
            url:      `https://${domain}/cybermeters-verification-${token}.html`,
            content:  token,
            instructions: [
              `Create a publicly accessible HTML file at your domain:`,
              `  URL:     https://${domain}/cybermeters-verification-${token}.html`,
              `  Content: ${token}`,
              `The file must be accessible without authentication.`,
            ],
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/domains/:id/verify ─────────────────────────────────────────
    // Perform the actual check: DNS TXT or HTML file.
    // Tries DNS first, then HTML. First passing method wins.
    const domVerCheckMatch = url.pathname.match(/^\/api\/domains\/([^/]+)\/verify$/);
    if (domVerCheckMatch && request.method === "POST") {
      const domainId = domVerCheckMatch[1];
      try {
        // Auth BEFORE any lookup — see domVerInitMatch above (existence oracle).
        const dvcUser = await requireAuth(request, env);
        if (!dvcUser) return json({ error: "Unauthorized" }, 401);

        const domRow = await env.cybermeters_db
          .prepare("SELECT id, domain FROM domains WHERE id = ?")
          .bind(domainId)
          .first();
        if (!domRow) return json({ error: "Domain not found" }, 404);

        // Workspace-scoped resolution (explicit workspace_id, or unambiguous
        // auto-resolve). Denied/absent → same 404 as nonexistent (existence oracle).
        let dvcBody = {};
        try { dvcBody = await request.json(); } catch { /* optional body */ }
        const dvcWs = await resolveVerificationWorkspace(dvcUser, domainId, dvcBody?.workspace_id, requireWorkspaceRole, env);
        if (dvcWs.error) return json({ error: dvcWs.error, ...(dvcWs.code ? { code: dvcWs.code } : {}) }, dvcWs.status);
        const dvcWorkspaceId = dvcWs.workspace_id;

        // Read verification state from the EXACT workspace-domain relationship — the
        // token was issued per workspace; another workspace's token can never verify this one.
        const dvcLink = await env.cybermeters_db
          .prepare("SELECT verification_status, verification_token FROM workspace_domains WHERE workspace_id = ? AND domain_id = ?")
          .bind(dvcWorkspaceId, domainId)
          .first();

        if (dvcLink?.verification_status === "verified") {
          return json({
            success: true,
            domain: domRow.domain,
            workspace_id: dvcWorkspaceId,
            verification_status: "verified",
            verification_method: "already_verified",
            message: "Domain is already verified.",
          });
        }

        if (!dvcLink?.verification_token) {
          return json({
            error: "No verification token found. Call POST /api/domains/:id/verification first.",
          }, 400);
        }

        const domain = domRow.domain;
        const token  = dvcLink.verification_token;
        const expectedTxtValue = `cybermeters-verification=${token}`;
        const htmlUrl          = `https://${domain}/cybermeters-verification-${token}.html`;

        // ── Method 1: DNS TXT ─────────────────────────────────────────────
        let dnsVerified = false;
        let dnsError    = null;
        try {
          const txtHost = `_cybermeters.${domain}`;
          const dnsResult = await dnsQuery(txtHost, "TXT");
          const answers = dnsResult.Answer || [];
          dnsVerified = answers.some(a => {
            // RFC 1035: TXT data arrives with surrounding quotes stripped by DoH JSON
            const val = String(a.data || "").replace(/^"|"$/g, "").trim();
            return val === expectedTxtValue;
          });
        } catch (e) {
          dnsError = customerSafeFailure("domain-verification/dns", e, "DNS lookup could not be completed");
        }

        if (dnsVerified) {
          // Update ONLY the exact workspace-domain relationship being verified.
          await env.cybermeters_db
            .prepare(`UPDATE workspace_domains
                      SET verification_status = 'verified',
                          verification_method = 'dns_txt',
                          verified_at = datetime('now')
                      WHERE workspace_id = ? AND domain_id = ?`)
            .bind(dvcWorkspaceId, domainId)
            .run();
          // Forward telemetry: fingerprint the exact TXT value we trusted + note
          // the resolver, so a later drift check can prove what was verified.
          const dnsRecordHash = await hashToken(expectedTxtValue);
          // Notifications + audit — fire-and-forget for THIS workspace only.
          try {
            await createNotificationEvent(env, dvcWorkspaceId, {
              type: "domain_verified", severity: "info",
              title: `${domain} ownership verified`,
              message: `Domain verified via DNS TXT record at _cybermeters.${domain}.`,
              metadata: { domain, domain_id: domainId, workspace_id: dvcWorkspaceId, method: "dns_txt" },
            });
            await createAuditEvent(env, {
              workspace_id: dvcWorkspaceId,
              user_id:     dvcUser?.id ?? null,
              event_type:  "domain_verified",
              entity_type: "domain",
              entity_id:   domainId,
              description: `${domain} ownership verified via DNS TXT`,
              metadata:    { domain, domain_id: domainId, workspace_id: dvcWorkspaceId, method: "dns_txt",
                             resolver_used: "cloudflare_doh", dns_record_hash: dnsRecordHash },
            });
          } catch { /* non-fatal */ }
          return json({
            success: true,
            domain,
            workspace_id: dvcWorkspaceId,
            verification_status: "verified",
            verification_method: "dns_txt",
            message: `DNS TXT record verified at _cybermeters.${domain}.`,
          });
        }

        // ── Method 2: HTML file ───────────────────────────────────────────
        let htmlVerified = false;
        let htmlError    = null;
        try {
          const htmlRes = await fetch(htmlUrl, {
            headers: { "User-Agent": "CyberMeters-Verification/1.0" },
            signal: AbortSignal.timeout(8_000),
            redirect: "follow",
          });
          if (htmlRes.ok) {
            const body = (await htmlRes.text()).trim();
            htmlVerified = body === token;
          } else {
            htmlError = `HTTP ${htmlRes.status}`;
          }
        } catch (e) {
          htmlError = customerSafeFailure("domain-verification/html", e, "HTML verification request could not be completed");
        }

        if (htmlVerified) {
          // Update ONLY the exact workspace-domain relationship being verified.
          await env.cybermeters_db
            .prepare(`UPDATE workspace_domains
                      SET verification_status = 'verified',
                          verification_method = 'html_file',
                          verified_at = datetime('now')
                      WHERE workspace_id = ? AND domain_id = ?`)
            .bind(dvcWorkspaceId, domainId)
            .run();
          // Notifications + audit — fire-and-forget for THIS workspace only.
          try {
            await createNotificationEvent(env, dvcWorkspaceId, {
              type: "domain_verified", severity: "info",
              title: `${domain} ownership verified`,
              message: `Domain verified via HTML file at ${htmlUrl}.`,
              metadata: { domain, domain_id: domainId, workspace_id: dvcWorkspaceId, method: "html_file" },
            });
            await createAuditEvent(env, {
              workspace_id: dvcWorkspaceId,
              user_id:     dvcUser?.id ?? null,
              event_type:  "domain_verified",
              entity_type: "domain",
              entity_id:   domainId,
              description: `${domain} ownership verified via HTML file`,
              metadata:    { domain, domain_id: domainId, workspace_id: dvcWorkspaceId, method: "html_file" },
            });
          } catch { /* non-fatal */ }
          return json({
            success: true,
            domain,
            workspace_id: dvcWorkspaceId,
            verification_status: "verified",
            verification_method: "html_file",
            message: `HTML verification file found at ${htmlUrl}.`,
          });
        }

        // ── Both failed ───────────────────────────────────────────────────
        // Mark ONLY the exact workspace-domain relationship failed.
        await env.cybermeters_db
          .prepare(`UPDATE workspace_domains SET verification_status = 'failed' WHERE workspace_id = ? AND domain_id = ?`)
          .bind(dvcWorkspaceId, domainId)
          .run();

        try {
          await createAuditEvent(env, {
            workspace_id: dvcWorkspaceId,
            user_id:     dvcUser?.id ?? null,
            event_type:  "domain_verification_failed",
            entity_type: "domain",
            entity_id:   domainId,
            description: `${domain} ownership verification failed`,
            metadata:    {
              domain,
              domain_id: domainId,
              workspace_id: dvcWorkspaceId,
              dns_txt_result: dnsVerified ? "found" : "not_found",
              html_file_result: htmlVerified ? "found" : "not_found",
              dns_error: dnsError || null,
              html_error: htmlError || null,
            },
          });
        } catch { /* non-fatal */ }

        return json({
          success: false,
          domain,
          verification_status: "failed",
          token,
          checks: {
            dns_txt: {
              checked: true,
              host:    `_cybermeters.${domain}`,
              expected: expectedTxtValue,
              result: dnsVerified ? "found" : "not_found",
              error:  dnsError || null,
            },
            html_file: {
              checked: true,
              url:    htmlUrl,
              result: htmlVerified ? "found" : "not_found",
              error:  htmlError || null,
            },
          },
          message: "Verification not confirmed yet — DNS changes can take a while to propagate. We re-check automatically every hour for 48 hours from when you generated this verification code, and will notify you when it succeeds.",
          auto_recheck: { enabled: true, method: "dns_txt", interval: "hourly", window_hours: 48 },
        }, 200);
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── GET /api/domains/:id ─────────────────────────────────────────────────
    // Returns domain row including verification fields. RBAC via domain→workspace link.
    const domGetMatch = url.pathname.match(/^\/api\/domains\/([^/]+)$/);
    if (domGetMatch && request.method === "GET") {
      const domainId = domGetMatch[1];
      const domGetUser = await requireAuth(request, env);
      if (!domGetUser) return json({ error: "Unauthorized" }, 401);
      const domGetAccess = await requireDomainRole(domGetUser, domainId, "workspace:read", env);
      if (!domGetAccess) return json({ error: "Forbidden" }, 403);
      try {
        const domRow = await env.cybermeters_db
          .prepare(
            `SELECT id, domain, verification_status, verification_method,
                    verification_token, verified_at, verification_initiated_at, created_at
             FROM domains WHERE id = ?`
          )
          .bind(domainId)
          .first();
        if (!domRow) return json({ error: "Domain not found" }, 404);
        const token = domRow.verification_token;
        return json({
          domain: {
            ...domRow,
            dns: token ? {
              host:  `_cybermeters.${domRow.domain}`,
              value: `cybermeters-verification=${token}`,
            } : null,
            html: token ? {
              url:     `https://${domRow.domain}/cybermeters-verification-${token}.html`,
              content: token,
            } : null,
          },
        });
      } catch (e) {
        return serverError("api", e);
      }
    }

    // ── POST /api/domains/:id/check-verification ──────────────────────────────
    // DNS TXT probe only — does NOT mark domain as verified.
    // Returns { found, value, matches } so the user can check propagation
    // before committing to the full POST /api/domains/:id/verify call.
    const domCheckMatch = url.pathname.match(/^\/api\/domains\/([^/]+)\/check-verification$/);
    if (domCheckMatch && request.method === "POST") {
      const domainId = domCheckMatch[1];
      const chkUser = await requireAuth(request, env);
      if (!chkUser) return json({ error: "Unauthorized" }, 401);
      const chkAccess = await requireDomainRole(chkUser, domainId, "domain:verify", env);
      if (!chkAccess) return json({ error: "Forbidden — admin role required" }, 403);
      try {
        const domRow = await env.cybermeters_db
          .prepare("SELECT id, domain, verification_token FROM domains WHERE id = ?")
          .bind(domainId)
          .first();
        if (!domRow) return json({ error: "Domain not found" }, 404);
        if (!domRow.verification_token) {
          return json({
            error: "No verification token. Call POST /api/domains/:id/verification first.",
          }, 400);
        }
        const domain   = domRow.domain;
        const token    = domRow.verification_token;
        const expected = `cybermeters-verification=${token}`;
        let found   = false;
        let value   = null;
        let matches = false;
        let error   = null;
        try {
          const txtHost  = `_cybermeters.${domain}`;
          const dnsResult = await dnsQuery(txtHost, "TXT");
          const answers   = dnsResult.Answer || [];
          for (const a of answers) {
            const v = String(a.data || "").replace(/^"|"$/g, "").trim();
            if (!found) { found = true; value = v; }
            if (v === expected) { matches = true; value = v; break; }
          }
        } catch (e) {
          error = customerSafeFailure("domain-verification/check", e, "DNS lookup could not be completed");
        }
        return json({ found, value, matches, expected, error });
      } catch (e) {
        return serverError("api", e);
      }
    }


  return null;
}
