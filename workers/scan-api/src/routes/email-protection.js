// ── Email Protection routes ──
// DMARC report import/list/summary, sender inventory + classification,
// BEC exposure, source validation, hosted DMARC/DNS management, RUA endpoint
// routing and alert-channel configuration for the email wedge. Extracted
// near-verbatim from index.js (router split, Phase 2 PR #9). Receives the
// per-request routeCtx from index.js; returns a Response when a route
// matches, or null so the main router continues.
import { ALERT_CHANNEL_MAX_PER_WORKSPACE, alertChannelToApi, deliverWorkspaceAlert, validateAlertChannelInput } from "../engines/alerts.js";
import { computeBecExposureScore } from "../engines/bec.js";
import { dnsQuery } from "../engines/dns.js";
import { normalizeDnsTxtValue, parseDmarcRecord } from "../engines/email-analysis.js";
import { DMARC_RAMP_LADDER, HOSTED_DNS_ENTRY_SELECT, HOSTED_DNS_REMOVAL_GRACE_DAYS, REMEDIATION_REGISTRY, analyzeSpfChain, applyHostedDmarcChange, buildDmarcDnsRecommendedValue, buildTlsRptValue, cfCreateHostedTxt, dmarcRampStepIndex, evaluateRampReadiness, getHostedDmarcPassRate, getRemediation, hostedCustomerRecordName, hostedDmarcSubdomain, hostedDnsRecordToApi, newHostedDnsRecordId, nextHostedDnsStatus, parseServerMsHosted, planAllowsHostedPolicyManagement, remediationToApi, rollbackHostedDmarc, verifyDmarcDnsSetup, verifyHostedDmarcRecord } from "../engines/hosted-dmarc.js";
import { auditDmarcRouteResult, buildDmarcEnforcementReadiness, configureDmarcEndpointRoute, emailSenderToApi, generateInboundLocalpart, generateIngestToken, hashIngestToken, ingestEndpointToApi, loadEmailSenderSources, persistDmarcRouteResult, resolveWorkspaceDomain, safelyEnsureCloudflareEmailRoute, safelyRevokeCloudflareEmailRoute, summarizeEmailSenders } from "../engines/rua-routing.js";
import { buildDmarcBusinessRisk, buildDmarcReportRemediationActions, loadBecExposureEvidence } from "../engines/sender-provenance.js";
import { RUA_INBOUND_DOMAIN_DEFAULT, ingestDmarcReport, normalizeInboundRecipientDomain, parseEmailAuthHeaders } from "../lib/dmarc-ingest.js";
import { createAuditEvent } from "../lib/events.js";
import { getEmailFrontendOrigin } from "../lib/lifecycle-email.js";
import { createId } from "../lib/util.js";

export async function emailProtectionRoutes(rctx) {
  const { request, env, url, json, serverError,
          requireAuth, requireWorkspaceRole } = rctx;

    // ── POST /api/workspaces/:wsid/domains/:domain/dmarc-reports/import ───────
    const dmarcImportMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-reports\/import$/);
    if (dmarcImportMatch && request.method === "POST") {
      const workspaceId = dmarcImportMatch[1];
      const domain = decodeURIComponent(dmarcImportMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const body = await request.json().catch(() => null);
        if (!body || typeof body.xml !== "string") {
          return json({ imported: false, error: "missing_xml", message: "Request must include an 'xml' string." }, 400);
        }

        // Shared ingestion pipeline (parse → dedupe → insert → rollup → audit).
        // Manual paste keeps its existing response shape and is NOT subject to
        // strict policy-domain matching (interactive source, user owns context).
        const result = await ingestDmarcReport(env, {
          workspaceId, domain, source: "manual_paste", xmlString: body.xml,
          filename: body.filename, actorUserId: user.id, domainId,
          enforceDomainMatch: false,
        });
        if (!result.ok) {
          return json({ imported: false, error: result.error, message: result.message }, result.status || 422);
        }
        if (result.duplicate) {
          return json({ imported: false, duplicate: true, message: "Report already imported" });
        }
        return json({ imported: true, duplicate: false, report_id: result.reportId,
          records_imported: result.records, messages_imported: result.messages,
          sources_updated: result.sourcesUpdated });
      } catch (e) {
        return serverError("dmarc-import", e, "DMARC report import failed.");
      }
    }

    // ── DMARC signed-upload endpoint (token) management ───────────────────────
    // One active upload key per workspace+domain. Raw token shown once on
    // create/rotate; only the SHA-256 hash is ever stored. Min permission:
    // scan:create (same as manual import — no stronger workspace-admin
    // permission exists in this codebase for domain-scoped data writes).
    const ingestEpRotateMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-ingest-endpoint\/rotate$/);
    const ingestEpRevokeMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-ingest-endpoint\/revoke$/);
    const ingestEpMatch       = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-ingest-endpoint$/);
    const dmarcDnsCheckMatch  = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-dns-check$/);

    // GET .../dmarc-dns-check — live, read-only DMARC RUA verification.
    if (dmarcDnsCheckMatch && request.method === "GET") {
      const workspaceId = dmarcDnsCheckMatch[1];
      const domain = decodeURIComponent(dmarcDnsCheckMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({
          domain, status: "unauthorized", message: "Authentication is required.",
        }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({
          domain, status: "unauthorized", message: "Workspace access is required.",
        }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({
          domain, status: "domain_not_in_workspace",
          message: "Domain not found in this workspace.",
        }, 404);
        return json(await verifyDmarcDnsSetup(env, workspaceId, domain));
      } catch {
        return json({
          domain, status: "dns_lookup_failed",
          message: "The DMARC DNS lookup could not be completed.",
        }, 502);
      }
    }

    // GET .../spf-analysis — live, read-only SPF chain health ("SPF surgeon").
    // Walks include:/redirect= targets, counts the RFC 7208 10-lookup budget,
    // flags void includes, and suggests a flattened record.
    // ── Remediation Registry (plug-and-play auto-fixes) ──────────────────────
    //   GET  .../remediations              → every gap + live detection (read role)
    //   GET  .../remediations/:id          → detail + the exact generated fix
    //   GET  .../remediations/:id/verify    → live re-check (is the fix live now?)
    // 'hosted' actions (DMARC today) point at their dedicated managed flow; the
    // 'apply' execution tier for other hosted records lands with the record_type
    // generalisation. This surface is read-only, so it is safe and low-risk.
    const remediationsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/remediations(?:\/([a-z0-9_]+)(\/verify)?)?$/);
    if (remediationsMatch && request.method === "GET") {
      const workspaceId = remediationsMatch[1];
      const domain = decodeURIComponent(remediationsMatch[2]).toLowerCase();
      const actionId = remediationsMatch[3] || null;
      const wantVerify = Boolean(remediationsMatch[4]);
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const ctx = { workspaceId, domain, env };

        if (!actionId) {
          // Detect every registered action in parallel; one slow/failing probe
          // never sinks the list.
          const items = await Promise.all(REMEDIATION_REGISTRY.map(async (action) => {
            try { return remediationToApi(action, await action.detect(ctx)); }
            catch { return remediationToApi(action, { applicable: true, present: false, ok: false, evidence: { error: "probe_failed" } }); }
          }));
          return json({ domain, remediations: items });
        }

        const action = getRemediation(actionId);
        if (!action) return json({ error: "Unknown remediation" }, 404);

        if (wantVerify) {
          let ok = false;
          try { ok = await action.verify(ctx); } catch { ok = false; }
          return json({ id: action.id, verified: ok });
        }

        let detection = null;
        try { detection = await action.detect(ctx); } catch { detection = null; }
        return json({
          remediation: remediationToApi(action, detection),
          fix: action.generate(ctx),
        });
      } catch (e) {
        return serverError("remediations", e, "Could not evaluate remediations.");
      }
    }

    const spfAnalysisMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/spf-analysis$/);
    if (spfAnalysisMatch && request.method === "GET") {
      const workspaceId = spfAnalysisMatch[1];
      const domain = decodeURIComponent(spfAnalysisMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({
          domain, status: "unauthorized", message: "Authentication is required.",
        }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({
          domain, status: "unauthorized", message: "Workspace access is required.",
        }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({
          domain, status: "domain_not_in_workspace",
          message: "Domain not found in this workspace.",
        }, 404);
        return json(await analyzeSpfChain(domain));
      } catch {
        return json({
          domain, status: "dns_lookup_failed",
          message: "The SPF analysis could not be completed.",
        }, 502);
      }
    }

    // ── Hosted DMARC (Hosted Records Engine — Phase A + B) ────────────────────
    //   POST   .../hosted-dmarc           → create the managed record (manage role)
    //   GET    .../hosted-dmarc           → state + ramp readiness
    //   GET    .../hosted-dmarc/verify    → live two-sided verification
    //   PUT    .../hosted-dmarc           → policy change {policy, pct, confirm} (manage + paid)
    //   POST   .../hosted-dmarc/rollback  → restore previous value (manage; never paywalled)
    //   PUT    .../hosted-dmarc/autopilot → {enabled} self-driving ramp (manage + paid)
    //   DELETE .../hosted-dmarc           → request removal (grace-protected)
    const hostedDmarcMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/hosted-dmarc(?:\/(verify|rollback|autopilot))?$/);
    if (hostedDmarcMatch) {
      const workspaceId = hostedDmarcMatch[1];
      const domain = decodeURIComponent(hostedDmarcMatch[2]).toLowerCase();
      const sub = hostedDmarcMatch[3] || null;
      const isVerify = sub === "verify";
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
        const access = await requireWorkspaceRole(user, workspaceId, permission, env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const existing = await env.cybermeters_db
          .prepare(`${HOSTED_DNS_ENTRY_SELECT}
                    WHERE workspace_id = ? AND domain = ? AND record_kind = 'dmarc' LIMIT 1`)
          .bind(workspaceId, domain).first();

        // Workspace plan (owner's plan) gates policy management; create,
        // monitoring, verification and rollback stay free.
        const planRow = await env.cybermeters_db
          .prepare(`SELECT u.plan FROM workspaces w JOIN users u ON u.id = w.owner_user_id WHERE w.id = ?`)
          .bind(workspaceId).first();
        const policyAllowed = planAllowsHostedPolicyManagement(planRow?.plan);

        if (request.method === "GET" && !sub) {
          if (!existing) return json({ record: null, policy_management_available: policyAllowed });
          const rate = await getHostedDmarcPassRate(env, workspaceId, domain);
          const changeMs = parseServerMsHosted(existing.last_change_at);
          const readiness = evaluateRampReadiness({
            pass_rate: rate.pass_rate,
            total_messages: rate.total,
            days_since_change: changeMs != null ? Math.floor((Date.now() - changeMs) / 86400000) : null,
          });
          return json({
            record: hostedDnsRecordToApi(existing),
            policy_management_available: policyAllowed,
            compliance: { pass_rate: rate.pass_rate, total_messages: rate.total, window_days: 7 },
            readiness,
          });
        }

        if (request.method === "PUT" && !sub) {
          if (!existing) return json({ error: "No hosted DMARC record for this domain yet." }, 404);
          if (!policyAllowed) return json({
            error: "Managed policy changes are available on paid plans. Monitoring stays free.",
            code: "upgrade_required",
          }, 403);
          let body;
          try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
          const policy = String(body.policy || "").trim().toLowerCase();
          const pct = body.pct == null ? 100 : Number(body.pct);
          const targetIdx = DMARC_RAMP_LADDER.findIndex((s) => s.policy === policy
            && (policy === "none" || s.pct === pct));
          if (targetIdx < 0) {
            return json({ error: "Choose a ladder step: none, quarantine (pct 5/25/50/100), or reject." }, 400);
          }
          const currentIdx = dmarcRampStepIndex(existing.current_value);
          const tightening = targetIdx > currentIdx;
          if (tightening && body.confirm !== true) {
            const rate = await getHostedDmarcPassRate(env, workspaceId, domain);
            const changeMs = parseServerMsHosted(existing.last_change_at);
            const readiness = evaluateRampReadiness({
              pass_rate: rate.pass_rate,
              total_messages: rate.total,
              days_since_change: changeMs != null ? Math.floor((Date.now() - changeMs) / 86400000) : null,
            });
            if (!readiness.ready) {
              return json({
                error: "Compliance is not ready for a stricter policy yet.",
                code: "readiness_check_failed",
                readiness,
              }, 409);
            }
          }
          const rateNow = await getHostedDmarcPassRate(env, workspaceId, domain);
          const applied = await applyHostedDmarcChange(env, existing, {
            policy, pct, userId: user.id, source: "manual", passRateNow: rateNow.pass_rate,
          });
          if (!applied.ok) {
            const msg = applied.reason === "change_budget_exceeded"
              ? "Daily policy-change limit reached for this record. Try again tomorrow."
              : applied.reason === "not_published"
                ? "The managed record is not published yet — wait for setup to complete."
                : applied.reason === "no_change"
                  ? "The record already has this policy."
                  : applied.reason === "change_in_progress"
                    ? "Another change is still being confirmed for this record. It settles automatically within the hour."
                    : applied.reason === "verify_mismatch"
                      ? "The change was submitted but could not be confirmed yet. It will settle automatically — check back shortly."
                      : "The policy change could not be applied. Please try again shortly.";
            return json({ error: msg, code: applied.reason }, 409);
          }
          const row = await env.cybermeters_db
            .prepare(`${HOSTED_DNS_ENTRY_SELECT} WHERE id = ?`).bind(existing.id).first();
          return json({ record: hostedDnsRecordToApi(row) });
        }

        if (request.method === "POST" && sub === "rollback") {
          if (!existing) return json({ error: "No hosted DMARC record for this domain." }, 404);
          const rolled = await rollbackHostedDmarc(env, existing, { userId: user.id, source: "manual" });
          if (!rolled.ok) {
            const msg = rolled.reason === "nothing_to_roll_back"
              ? "There is no previous value to restore."
              : "The rollback could not be applied. Please try again shortly.";
            return json({ error: msg, code: rolled.reason }, 409);
          }
          const row = await env.cybermeters_db
            .prepare(`${HOSTED_DNS_ENTRY_SELECT} WHERE id = ?`).bind(existing.id).first();
          return json({ record: hostedDnsRecordToApi(row) });
        }

        if (request.method === "PUT" && sub === "autopilot") {
          if (!existing) return json({ error: "No hosted DMARC record for this domain yet." }, 404);
          if (!policyAllowed) return json({
            error: "Self-driving DMARC is available on paid plans.",
            code: "upgrade_required",
          }, 403);
          let body;
          try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
          const enabled = body.enabled === true ? 1 : 0;
          await env.cybermeters_db
            .prepare(`UPDATE hosted_dns_entries SET autopilot = ?, updated_at = ? WHERE id = ?`)
            .bind(enabled, new Date().toISOString(), existing.id).run();
          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: enabled ? "hosted_dmarc_autopilot_enabled" : "hosted_dmarc_autopilot_disabled",
            entity_type: "hosted_dns_record", entity_id: existing.id,
            description: `Self-driving DMARC ${enabled ? "enabled" : "disabled"} for ${domain}`,
          });
          return json({ record: hostedDnsRecordToApi({ ...existing, autopilot: enabled }) });
        }

        if (request.method === "GET" && isVerify) {
          if (!existing) return json({ error: "No hosted DMARC record for this domain yet." }, 404);
          const checks = await verifyHostedDmarcRecord(existing);
          const next = nextHostedDnsStatus(existing, checks);
          const nowIso = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`UPDATE hosted_dns_entries SET verification_state = ?, verified_at = ?, updated_at = ? WHERE id = ?`)
            .bind(next, nowIso, nowIso, existing.id).run();
          return json({
            record: hostedDnsRecordToApi({ ...existing, status: next, last_verified_at: nowIso }),
            checks,
          });
        }

        if (request.method === "POST" && !sub) {
          if (existing) return json({ record: hostedDnsRecordToApi(existing), already_exists: true });

          // The managed record must keep reporting flowing: a CyberMeters RUA
          // address is required before we take over the value.
          const endpoint = await env.cybermeters_db
            .prepare(`SELECT address_local FROM dmarc_ingest_endpoints
                      WHERE workspace_id = ? AND domain = ? AND status = 'active' AND revoked_at IS NULL
                      ORDER BY created_at DESC LIMIT 1`)
            .bind(workspaceId, domain).first();
          if (!endpoint?.address_local) {
            return json({ error: "Create a CyberMeters reporting address for this domain first." }, 400);
          }
          const inboundDomain = normalizeInboundRecipientDomain(env.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT)
            || RUA_INBOUND_DOMAIN_DEFAULT;
          const recommendedRua = `mailto:${endpoint.address_local}@${inboundDomain}`;

          // Mirror the customer's live record (merged with our RUA); default to
          // monitor-only when none exists. Phase A never changes policy.
          let liveRecord = null;
          try {
            const res = await dnsQuery(`_dmarc.${domain}`, "TXT");
            if (Number(res?.Status ?? 1) === 0) {
              liveRecord = (res?.Answer || [])
                .map((a) => normalizeDnsTxtValue(a?.data))
                .find((v) => /^v=DMARC1(?:\s*;|$)/i.test(v)) || null;
            }
          } catch { /* fall through to the default value */ }
          const value = buildDmarcDnsRecommendedValue(liveRecord, recommendedRua);
          const parsed = parseDmarcRecord(value, 1);
          if (!parsed.valid) return json({ error: "A valid managed record could not be produced for this domain." }, 422);

          const id = newHostedDnsRecordId();
          const hostedName = `${id}.${hostedDmarcSubdomain(env)}`;
          const nowIso = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`INSERT INTO hosted_dns_entries
                        (id, workspace_id, domain, record_kind, customer_name, target_name, target_value,
                         provider, verification_state, created_by, created_at, updated_at)
                      VALUES (?, ?, ?, 'dmarc', ?, ?, ?, 'cloudflare', 'pending_dns', ?, ?, ?)`)
            .bind(id, workspaceId, domain, `_dmarc.${domain}`, hostedName, value, user.id, nowIso, nowIso).run();

          // Try the Cloudflare create immediately; the sweep retries on failure.
          let row = { id, workspace_id: workspaceId, domain, record_type: "dmarc",
            hosted_name: hostedName, current_value: value, status: "pending_dns",
            last_verified_at: null, created_at: nowIso };
          const created = await cfCreateHostedTxt(env, hostedName, value);
          if (created.ok) {
            await env.cybermeters_db
              .prepare(`UPDATE hosted_dns_entries SET provider_record_id = ?, verification_state = 'awaiting_cname', updated_at = ? WHERE id = ?`)
              .bind(created.cf_record_id, nowIso, id).run();
            row = { ...row, status: "awaiting_cname" };
          }

          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "hosted_dmarc_created", entity_type: "hosted_dns_record", entity_id: id,
            description: `Hosted DMARC record created for ${domain}`,
          });

          return json({
            record: hostedDnsRecordToApi(row),
            instructions: {
              step: `Replace any existing TXT at _dmarc.${domain} with this CNAME`,
              cname_name: `_dmarc.${domain}`,
              cname_target: hostedName,
              note: "After the CNAME resolves, CyberMeters manages the record value for you. Reporting keeps flowing to your CyberMeters address.",
            },
          }, 201);
        }

        if (request.method === "DELETE" && !sub) {
          if (!existing) return json({ error: "No hosted DMARC record for this domain." }, 404);
          const nowIso = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`UPDATE hosted_dns_entries SET verification_state = 'pending_removal', updated_at = ? WHERE id = ?`)
            .bind(nowIso, existing.id).run();
          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "hosted_dmarc_removal_requested", entity_type: "hosted_dns_record", entity_id: existing.id,
            description: `Hosted DMARC removal requested for ${domain}`,
          });
          return json({
            record: hostedDnsRecordToApi({ ...existing, status: "pending_removal" }),
            message: `Remove the CNAME at _dmarc.${domain} (or replace it with your own TXT record). The hosted value stays live until your DNS no longer depends on it, for up to ${HOSTED_DNS_REMOVAL_GRACE_DAYS} days.`,
          });
        }

        return json({ error: "Method not allowed" }, 405);
      } catch (e) {
        return serverError("hosted-dmarc", e, "Could not update the hosted DMARC record.");
      }
    }

    // ── Hosted TLS-RPT (Phase C, on the v2 hosted_dns_entries foundation) ──────
    //   POST   .../hosted-tls-rpt         → create the managed record (manage role)
    //   GET    .../hosted-tls-rpt         → current state
    //   GET    .../hosted-tls-rpt/verify  → live two-sided verification
    //   DELETE .../hosted-tls-rpt         → request removal (grace-protected)
    // Slimmer than DMARC: no policy ramp, autopilot or rollback — TLS-RPT is a
    // static, report-only record. Hosting + verification only; report ingestion
    // is a later packet.
    const hostedTlsRptMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/hosted-tls-rpt(?:\/(verify))?$/);
    if (hostedTlsRptMatch) {
      const workspaceId = hostedTlsRptMatch[1];
      const domain = decodeURIComponent(hostedTlsRptMatch[2]).toLowerCase();
      const isVerify = hostedTlsRptMatch[3] === "verify";
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
        const access = await requireWorkspaceRole(user, workspaceId, permission, env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const existing = await env.cybermeters_db
          .prepare(`${HOSTED_DNS_ENTRY_SELECT}
                    WHERE workspace_id = ? AND domain = ? AND record_kind = 'tlsrpt' LIMIT 1`)
          .bind(workspaceId, domain).first();

        const customerName = hostedCustomerRecordName(domain, "tlsrpt"); // _smtp._tls.<domain>

        if (request.method === "GET" && !isVerify) {
          return json({ record: existing ? hostedDnsRecordToApi(existing) : null });
        }

        if (request.method === "GET" && isVerify) {
          if (!existing) return json({ error: "No hosted TLS-RPT record for this domain yet." }, 404);
          const checks = await verifyHostedDmarcRecord(existing); // kind-aware (reads customer_name)
          const next = nextHostedDnsStatus(existing, checks);
          const nowIso = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`UPDATE hosted_dns_entries SET verification_state = ?, verified_at = ?, updated_at = ? WHERE id = ?`)
            .bind(next, nowIso, nowIso, existing.id).run();
          return json({ record: hostedDnsRecordToApi({ ...existing, status: next, last_verified_at: nowIso }), checks });
        }

        if (request.method === "POST") {
          if (existing) return json({ record: hostedDnsRecordToApi(existing), already_exists: true });
          // TLS-RPT reporting needs a CyberMeters mailbox — reuse the domain's
          // existing reporting address (same one DMARC RUA uses).
          const endpoint = await env.cybermeters_db
            .prepare(`SELECT address_local FROM dmarc_ingest_endpoints
                      WHERE workspace_id = ? AND domain = ? AND status = 'active' AND revoked_at IS NULL
                      ORDER BY created_at DESC LIMIT 1`)
            .bind(workspaceId, domain).first();
          if (!endpoint?.address_local) {
            return json({ error: "Create a CyberMeters reporting address for this domain first." }, 400);
          }
          const inboundDomain = normalizeInboundRecipientDomain(env.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT)
            || RUA_INBOUND_DOMAIN_DEFAULT;
          const value = buildTlsRptValue(`${endpoint.address_local}@${inboundDomain}`);

          const id = newHostedDnsRecordId();
          const hostedName = `${id}.${hostedDmarcSubdomain(env)}`;
          const nowIso = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`INSERT INTO hosted_dns_entries
                        (id, workspace_id, domain, domain_id, record_kind, customer_name, target_name, target_value,
                         provider, verification_state, created_by, created_at, updated_at)
                      VALUES (?, ?, ?, ?, 'tlsrpt', ?, ?, ?, 'cloudflare', 'pending_dns', ?, ?, ?)`)
            .bind(id, workspaceId, domain, domainId, customerName, hostedName, value, user.id, nowIso, nowIso).run();

          let row = { id, workspace_id: workspaceId, domain, record_type: "tlsrpt",
            customer_name: customerName, hosted_name: hostedName, current_value: value,
            status: "pending_dns", last_verified_at: null, created_at: nowIso };
          const created = await cfCreateHostedTxt(env, hostedName, value);
          if (created.ok) {
            await env.cybermeters_db
              .prepare(`UPDATE hosted_dns_entries SET provider_record_id = ?, verification_state = 'awaiting_cname', updated_at = ? WHERE id = ?`)
              .bind(created.cf_record_id, nowIso, id).run();
            row = { ...row, status: "awaiting_cname" };
          }

          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "hosted_tls_rpt_created", entity_type: "hosted_dns_record", entity_id: id,
            description: `Hosted TLS-RPT record created for ${domain}`,
          });

          return json({
            record: hostedDnsRecordToApi(row),
            instructions: {
              step: `Add a CNAME at ${customerName} pointing to the target below`,
              cname_name: customerName,
              cname_target: hostedName,
              note: "After the CNAME resolves, CyberMeters manages the TLS-RPT record for you.",
            },
          }, 201);
        }

        if (request.method === "DELETE") {
          if (!existing) return json({ error: "No hosted TLS-RPT record for this domain." }, 404);
          const nowIso = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`UPDATE hosted_dns_entries SET verification_state = 'pending_removal', updated_at = ? WHERE id = ?`)
            .bind(nowIso, existing.id).run();
          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "hosted_tls_rpt_removal_requested", entity_type: "hosted_dns_record", entity_id: existing.id,
            description: `Hosted TLS-RPT removal requested for ${domain}`,
          });
          return json({
            record: hostedDnsRecordToApi({ ...existing, status: "pending_removal" }),
            message: `Remove the CNAME at ${customerName} (or replace it with your own TXT). The hosted value stays live until your DNS no longer depends on it, for up to ${HOSTED_DNS_REMOVAL_GRACE_DAYS} days.`,
          });
        }

        return json({ error: "Method not allowed" }, 405);
      } catch (e) {
        return serverError("hosted-tls-rpt", e, "Could not update the hosted TLS-RPT record.");
      }
    }

    // POST .../dmarc-ingest-endpoint — create (idempotent; never duplicates).
    if (ingestEpMatch && request.method === "POST") {
      const workspaceId = ingestEpMatch[1];
      const domain = decodeURIComponent(ingestEpMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const inboundDomain = env.RUA_INBOUND_DOMAIN || "reports.cybermeters.com";

        const existing = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints
                    WHERE workspace_id = ? AND domain = ? AND status = 'active'
                    ORDER BY created_at DESC LIMIT 1`)
          .bind(workspaceId, domain).first();
        if (existing) {
          // Idempotent: never re-issue a token. Backfill an inbound RUA address
          // for endpoints created before Phase 2 so they can also receive email.
          if (!existing.address_local) {
            const local = generateInboundLocalpart();
            await env.cybermeters_db
              .prepare(`UPDATE dmarc_ingest_endpoints SET address_local = ? WHERE id = ?`)
              .bind(local, existing.id).run();
            existing.address_local = local;
            await createAuditEvent(env, {
              workspace_id: workspaceId, user_id: user.id, event_type: "dmarc_ingest_endpoint_inbound_activated",
              entity_type: "domain", entity_id: domainId,
              description: `Activated inbound DMARC reporting address for ${domain}`,
              metadata: { domain, ingest_endpoint_id: existing.id },
            });
          }
          // Route automation is deliberately non-blocking for endpoint creation.
          // Missing config or Cloudflare rejection is persisted as safe status.
          await configureDmarcEndpointRoute(env, existing, user.id);
          const current = await env.cybermeters_db
            .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE id = ?`).bind(existing.id).first();
          return json({ created: false, endpoint: ingestEndpointToApi(current || existing, { inboundDomain }),
            message: "An active upload key already exists. Rotate it to issue a new token." });
        }

        const raw = generateIngestToken();
        const tokenHash = await hashIngestToken(raw);
        const addressLocal = generateInboundLocalpart();
        const id = createId("dmaringest");
        await env.cybermeters_db
          .prepare(`INSERT INTO dmarc_ingest_endpoints
                    (id, workspace_id, domain_id, domain, token_hash, address_local, status, created_by, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, 'active', ?, datetime('now'))`)
          .bind(id, workspaceId, domainId, domain, tokenHash, addressLocal, user.id).run();
        const row = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE id = ?`).bind(id).first();
        await createAuditEvent(env, {
          workspace_id: workspaceId, user_id: user.id, event_type: "dmarc_ingest_endpoint_created",
          entity_type: "domain", entity_id: domainId,
          description: `Created DMARC ingestion endpoint (signed upload + inbound RUA) for ${domain}`,
          metadata: { domain, ingest_endpoint_id: id },
        });
        await configureDmarcEndpointRoute(env, row, user.id);
        const routedRow = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE id = ?`).bind(id).first();
        return json({ created: true, endpoint: ingestEndpointToApi(routedRow || row, { rawToken: raw, inboundDomain }) });
      } catch (e) {
        return serverError("dmarc-ingest-endpoint-create", e, "Could not create upload key.");
      }
    }

    // GET .../dmarc-ingest-endpoint — metadata only (never the token or hash).
    if (ingestEpMatch && request.method === "GET") {
      const workspaceId = ingestEpMatch[1];
      const domain = decodeURIComponent(ingestEpMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const inboundDomain = env.RUA_INBOUND_DOMAIN || "reports.cybermeters.com";
        const row = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints
                    WHERE workspace_id = ? AND domain = ? ORDER BY created_at DESC LIMIT 1`)
          .bind(workspaceId, domain).first();
        return json({ endpoint: row ? ingestEndpointToApi(row, { inboundDomain }) : null });
      } catch (e) {
        return serverError("dmarc-ingest-endpoint-get", e, "Could not load upload key.");
      }
    }

    // POST .../dmarc-ingest-endpoint/rotate — new token, same endpoint id.
    if (ingestEpRotateMatch && request.method === "POST") {
      const workspaceId = ingestEpRotateMatch[1];
      const domain = decodeURIComponent(ingestEpRotateMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const existing = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints
                    WHERE workspace_id = ? AND domain = ? ORDER BY created_at DESC LIMIT 1`)
          .bind(workspaceId, domain).first();
        if (!existing) return json({ error: "No upload key exists to rotate. Create one first." }, 404);

        const raw = generateIngestToken();
        const tokenHash = await hashIngestToken(raw);
        const candidateLocal = generateInboundLocalpart();
        const inboundDomain = env.RUA_INBOUND_DOMAIN || RUA_INBOUND_DOMAIN_DEFAULT;
        // Create the replacement exact route before changing address_local. If
        // automation is unavailable, retain the current localpart so an existing
        // manual exact route continues to work while the signed token rotates.
        const routeResult = await safelyEnsureCloudflareEmailRoute(env, candidateLocal, inboundDomain);
        await persistDmarcRouteResult(env, existing.id, routeResult);
        await auditDmarcRouteResult(env, { ...existing, address_local: candidateLocal }, user.id, routeResult, "ensure");
        const nextLocal = routeResult.ok ? candidateLocal : (existing.address_local || candidateLocal);
        await env.cybermeters_db
          .prepare(`UPDATE dmarc_ingest_endpoints
                    SET token_hash = ?, address_local = ?, status = 'active',
                        rotated_at = datetime('now'), revoked_at = NULL
                    WHERE id = ?`)
          .bind(tokenHash, nextLocal, existing.id).run();
        if (routeResult.ok && existing.cloudflare_route_id &&
            existing.cloudflare_route_id !== routeResult.route_id) {
          const oldRouteResult = await safelyRevokeCloudflareEmailRoute(env, existing.cloudflare_route_id);
          await auditDmarcRouteResult(env, existing, user.id, oldRouteResult, "revoke");
        }
        const row = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE id = ?`).bind(existing.id).first();
        await createAuditEvent(env, {
          workspace_id: workspaceId, user_id: user.id, event_type: "dmarc_ingest_endpoint_rotated",
          entity_type: "domain", entity_id: domainId,
          description: `Rotated DMARC signed-upload key for ${domain}`,
          metadata: { domain, ingest_endpoint_id: existing.id },
        });
        return json({ rotated: true, endpoint: ingestEndpointToApi(row, { rawToken: raw, inboundDomain }) });
      } catch (e) {
        return serverError("dmarc-ingest-endpoint-rotate", e, "Could not rotate upload key.");
      }
    }

    // POST .../dmarc-ingest-endpoint/revoke — disables the token immediately.
    if (ingestEpRevokeMatch && request.method === "POST") {
      const workspaceId = ingestEpRevokeMatch[1];
      const domain = decodeURIComponent(ingestEpRevokeMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const existing = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints
                    WHERE workspace_id = ? AND domain = ? ORDER BY created_at DESC LIMIT 1`)
          .bind(workspaceId, domain).first();
        if (!existing) return json({ error: "No upload key exists to revoke." }, 404);
        await env.cybermeters_db
          .prepare(`UPDATE dmarc_ingest_endpoints SET status = 'revoked', revoked_at = datetime('now') WHERE id = ?`)
          .bind(existing.id).run();
        // Endpoint revocation remains authoritative even if Cloudflare route
        // deletion is unavailable or rejected.
        const routeResult = await safelyRevokeCloudflareEmailRoute(env, existing.cloudflare_route_id);
        await persistDmarcRouteResult(env, existing.id, routeResult);
        await auditDmarcRouteResult(env, existing, user.id, routeResult, "revoke");
        const row = await env.cybermeters_db
          .prepare(`SELECT * FROM dmarc_ingest_endpoints WHERE id = ?`).bind(existing.id).first();
        await createAuditEvent(env, {
          workspace_id: workspaceId, user_id: user.id, event_type: "dmarc_ingest_endpoint_revoked",
          entity_type: "domain", entity_id: domainId,
          description: `Revoked DMARC signed-upload key for ${domain}`,
          metadata: { domain, ingest_endpoint_id: existing.id },
        });
        const inboundDomain = env.RUA_INBOUND_DOMAIN || "reports.cybermeters.com";
        return json({ revoked: true, endpoint: ingestEndpointToApi(row, { inboundDomain }) });
      } catch (e) {
        return serverError("dmarc-ingest-endpoint-revoke", e, "Could not revoke upload key.");
      }
    }

    // ── GET /api/workspaces/:wsid/domains/:domain/email-senders ──────────────
    const emailSendersMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/email-senders$/);
    if (emailSendersMatch && request.method === "GET") {
      const workspaceId = emailSendersMatch[1];
      const domain = decodeURIComponent(emailSendersMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);
        const senders = await loadEmailSenderSources(env, workspaceId, domain);
        return json({ domain, senders: senders.map(emailSenderToApi), summary: summarizeEmailSenders(senders) });
      } catch (e) {
        return serverError("email-senders", e, "Could not load email senders.");
      }
    }

    // ── POST /api/workspaces/:wsid/domains/:domain/email-senders/:source_id/classify ──
    const classifyMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/email-senders\/([^/]+)\/classify$/);
    if (classifyMatch && request.method === "POST") {
      const workspaceId = classifyMatch[1];
      const domain = decodeURIComponent(classifyMatch[2]).toLowerCase();
      const sourceId = classifyMatch[3];
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "scan:create", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const body = await request.json().catch(() => null);
        const classification = body?.classification;
        const ALLOWED = ["trusted", "suspicious", "threat", "ignored", "unknown"];
        if (!ALLOWED.includes(classification)) {
          return json({ error: `classification must be one of: ${ALLOWED.join(", ")}` }, 400);
        }
        const notes = typeof body?.notes === "string" ? body.notes.slice(0, 1000) : null;

        const sender = await env.cybermeters_db
          .prepare(`SELECT * FROM email_sender_sources WHERE id = ? AND workspace_id = ? AND domain = ? LIMIT 1`)
          .bind(sourceId, workspaceId, domain).first();
        if (!sender) return json({ error: "Sender not found for this workspace/domain" }, 404);

        await env.cybermeters_db
          .prepare(`UPDATE email_sender_sources SET classification = ?, notes = ?, updated_at = datetime('now') WHERE id = ?`)
          .bind(classification, notes, sourceId).run();
        await createAuditEvent(env, {
          workspace_id: workspaceId, user_id: user.id, event_type: "email_sender_classified",
          entity_type: "email_sender", entity_id: sourceId,
          description: `Classified sender ${sender.source_ip} as ${classification} for ${domain}`,
          metadata: { domain, source_ip: sender.source_ip, classification },
        });
        return json({ sender: emailSenderToApi({ ...sender, classification, notes }) });
      } catch (e) {
        return serverError("email-sender-classify", e, "Could not classify sender.");
      }
    }

    // ── GET /api/workspaces/:wsid/domains/:domain/bec-exposure ──────────────
    const becExposureMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/bec-exposure$/);
    if (becExposureMatch && request.method === "GET") {
      const workspaceId = becExposureMatch[1];
      const domain = decodeURIComponent(becExposureMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const evidence = await loadBecExposureEvidence(env, workspaceId, domain);
        return json(computeBecExposureScore(evidence));
      } catch {
        return json({ error: "BEC exposure score could not be calculated" }, 500);
      }
    }

    // ── GET /api/workspaces/:wsid/domains/:domain/dmarc-summary?days=30 ───────
    const dmarcSummaryMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-summary$/);
    if (dmarcSummaryMatch && request.method === "GET") {
      const workspaceId = dmarcSummaryMatch[1];
      const domain = decodeURIComponent(dmarcSummaryMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const days = Math.min(365, Math.max(1, parseInt(url.searchParams.get("days") || "30", 10) || 30));
        const cutoff = Math.floor(Date.now() / 1000) - days * 86400;

        const senders = await loadEmailSenderSources(env, workspaceId, domain);
        const sSummary = summarizeEmailSenders(senders);

        const dispoRows = await env.cybermeters_db
          .prepare(`SELECT r.disposition AS disposition, SUM(r.message_count) AS msgs,
                           SUM(CASE WHEN r.spf_aligned_result='pass' OR r.dkim_aligned_result='pass'
                                    THEN r.message_count ELSE 0 END) AS aligned
                    FROM dmarc_aggregate_records r
                    JOIN dmarc_aggregate_reports rep ON rep.id = r.report_id
                    WHERE r.workspace_id = ? AND r.domain = ? AND (rep.date_range_end IS NULL OR rep.date_range_end >= ?)
                    GROUP BY r.disposition`)
          .bind(workspaceId, domain, cutoff).all();
        const disposition = { none: 0, quarantine: 0, reject: 0 };
        let totalMsgs = 0, alignedMsgs = 0;
        for (const row of (dispoRows.results || [])) {
          const d = row.disposition || "none";
          const msgs = row.msgs || 0;
          totalMsgs += msgs; alignedMsgs += row.aligned || 0;
          if (d === "quarantine") disposition.quarantine += msgs;
          else if (d === "reject") disposition.reject += msgs;
          else disposition.none += msgs;
        }
        const failedMsgs = Math.max(0, totalMsgs - alignedMsgs);
        const passRate = totalMsgs > 0 ? Math.round((alignedMsgs / totalMsgs) * 1000) / 10 : sSummary.overall_pass_rate;

        const window = await env.cybermeters_db
          .prepare(`SELECT COUNT(*) AS c, MIN(date_range_begin) AS minb, MAX(date_range_end) AS maxe
                    FROM dmarc_aggregate_reports WHERE workspace_id = ? AND domain = ?`)
          .bind(workspaceId, domain).first();
        const daysWithData = (window?.minb && window?.maxe) ? Math.max(1, Math.round((window.maxe - window.minb) / 86400)) : 0;
        const highVolFailed = senders.filter((s) => (s.total_messages || 0) >= 50 && (typeof s.pass_rate === "number" ? s.pass_rate : 100) < 90).length;
        const readiness = buildDmarcEnforcementReadiness({
          days_with_data: daysWithData, total_messages: totalMsgs || sSummary.total_messages,
          pass_rate: passRate, unknown_senders: sSummary.unknown_senders, high_volume_failed_senders: highVolFailed,
        });

        const businessRisk = buildDmarcBusinessRisk({
          threat_senders: sSummary.threat_senders,
          suspicious_senders: sSummary.suspicious_senders,
          unknown_senders: sSummary.unknown_senders,
          failed_messages: failedMsgs,
          pass_rate: passRate,
        });

        return json({
          domain, period_days: days,
          traffic: { total_messages: totalMsgs, aligned_messages: alignedMsgs, failed_messages: failedMsgs, pass_rate: passRate },
          senders: { total: sSummary.total_senders, trusted: sSummary.trusted_senders, unknown: sSummary.unknown_senders,
                     suspicious: sSummary.suspicious_senders, threat: sSummary.threat_senders, ignored: sSummary.ignored_senders },
          disposition,
          readiness,
          business_risk: businessRisk,
          cybermeters_correlation: {
            external_attack_surface_note: "Email impersonation risk should be reviewed alongside exposed assets, SaaS exposure, and third-party dependencies.",
            linked_modules: ["assets", "saas_exposure", "vendors", "business_risk"],
            correlation_status: "placeholder",
          },
          report_remediation_actions: buildDmarcReportRemediationActions(senders, readiness),
        });
      } catch (e) {
        return serverError("dmarc-summary", e, "Could not build DMARC summary.");
      }
    }

    // ── POST /api/workspaces/:wsid/domains/:domain/validate-source ───────────
    // Instant sender validation from pasted email headers — no waiting for DMARC
    // aggregate reports. Parses Authentication-Results and decides if the message
    // is authenticated and aligned to the domain. Stateless: headers are parsed
    // and discarded, never stored.
    const validateSourceMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/validate-source$/);
    if (validateSourceMatch && request.method === "POST") {
      const workspaceId = validateSourceMatch[1];
      const domain = decodeURIComponent(validateSourceMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        let body;
        try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
        const headers = String(body.headers || "").slice(0, 100_000); // bounded
        if (!headers.trim()) return json({ error: "Paste the email headers to validate." }, 400);

        const p = parseEmailAuthHeaders(headers, domain);
        const MESSAGES = {
          authenticated_aligned: "This message is authenticated and aligned to your domain — a legitimate sender for it. If you don't recognise it, confirm the service is yours.",
          passes_not_aligned:    "This message passes SPF or DKIM, but for a different domain than yours, so it would fail DMARC alignment. If it is a service you use, add its SPF include or DKIM selector; otherwise treat it as impersonation.",
          fails:                 "This message fails both SPF and DKIM. It would be blocked once you enforce DMARC. If you did not send it, this is a spoofing attempt.",
          unparseable:           "No authentication results were found in what you pasted. Paste the full raw headers (in Gmail: ⋮ menu → Show original; in Outlook: File → Properties → Internet headers).",
        };
        return json({
          domain,
          verdict: p.verdict,
          message: MESSAGES[p.verdict] || MESSAGES.unparseable,
          spf: p.spf, dkim: p.dkim, dmarc: p.dmarc, aligned: p.aligned,
          source_ip: p.source_ip, from_domain: p.from_domain,
          dkim_domain: p.dkim_domain, dkim_selector: p.dkim_selector,
        });
      } catch (e) {
        return serverError("validate-source", e, "Could not validate the pasted headers.");
      }
    }

    // ── GET /api/workspaces/:wsid/domains/:domain/dmarc-reports?limit=50 ──────
    // Read-only DMARC report history: one row per imported aggregate report
    // (reporter org, covered period, message volume, aligned share, policy
    // applied). Never exposes raw XML, source IPs, hashes, or internal errors.
    const dmarcReportsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/dmarc-reports$/);
    if (dmarcReportsMatch && request.method === "GET") {
      const workspaceId = dmarcReportsMatch[1];
      const domain = decodeURIComponent(dmarcReportsMatch[2]).toLowerCase();
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const access = await requireWorkspaceRole(user, workspaceId, "workspace:read", env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") || "50", 10) || 50));

        const totals = await env.cybermeters_db
          .prepare(`SELECT COUNT(*) AS reports, COUNT(DISTINCT org_name) AS reporters,
                           MIN(date_range_begin) AS first_seen, MAX(date_range_end) AS last_seen,
                           SUM(message_count) AS total_messages
                    FROM dmarc_aggregate_reports WHERE workspace_id = ? AND domain = ?`)
          .bind(workspaceId, domain).first();

        const rows = await env.cybermeters_db
          .prepare(`SELECT rep.id, rep.org_name, rep.date_range_begin, rep.date_range_end,
                           rep.message_count, rep.record_count, rep.policy_p, rep.created_at,
                           COALESCE(SUM(CASE WHEN r.spf_aligned_result = 'pass' OR r.dkim_aligned_result = 'pass'
                                             THEN r.message_count ELSE 0 END), 0) AS aligned_messages
                    FROM dmarc_aggregate_reports rep
                    LEFT JOIN dmarc_aggregate_records r ON r.report_id = rep.id
                    WHERE rep.workspace_id = ? AND rep.domain = ?
                    GROUP BY rep.id
                    ORDER BY COALESCE(rep.date_range_end, 0) DESC, rep.created_at DESC
                    LIMIT ?`)
          .bind(workspaceId, domain, limit).all();

        const reports = (rows.results || []).map((r) => {
          const msgs = Math.max(0, Number(r.message_count || 0));
          const aligned = Math.min(msgs, Math.max(0, Number(r.aligned_messages || 0)));
          return {
            id: r.id,
            reporter: r.org_name || "Unknown reporter",
            date_range_begin: r.date_range_begin || null,
            date_range_end: r.date_range_end || null,
            message_count: msgs,
            record_count: Math.max(0, Number(r.record_count || 0)),
            aligned_messages: aligned,
            pass_rate: msgs > 0 ? Math.round((aligned / msgs) * 1000) / 10 : null,
            policy_applied: r.policy_p || null,
            received_at: r.created_at || null,
          };
        });

        return json({
          domain,
          totals: {
            reports: Number(totals?.reports || 0),
            reporters: Number(totals?.reporters || 0),
            first_seen: totals?.first_seen || null,
            last_seen: totals?.last_seen || null,
            total_messages: Number(totals?.total_messages || 0),
          },
          reports,
        });
      } catch (e) {
        return serverError("dmarc-reports", e, "Could not load DMARC report history.");
      }
    }

    // ── Workspace alert channels (Slack / Teams / signed webhooks) ────────────
    //   GET    .../alert-channels           → list (read role)
    //   POST   .../alert-channels           → create {channel_type, webhook_url} (manage role)
    //   POST   .../alert-channels/:cid/test → send a test event (manage role)
    //   DELETE .../alert-channels/:cid      → remove (manage role)
    const alertChannelsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/alert-channels(?:\/([^/]+)(\/test)?)?$/);
    if (alertChannelsMatch) {
      const workspaceId = alertChannelsMatch[1];
      const channelId   = alertChannelsMatch[2] ? decodeURIComponent(alertChannelsMatch[2]) : null;
      const isTest      = Boolean(alertChannelsMatch[3]);
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
        const access = await requireWorkspaceRole(user, workspaceId, permission, env);
        if (!access) return json({ error: "Forbidden" }, 403);

        if (request.method === "GET" && !channelId) {
          const rows = await env.cybermeters_db
            .prepare(`SELECT * FROM workspace_alert_channels WHERE workspace_id = ? ORDER BY created_at ASC`)
            .bind(workspaceId).all();
          return json({ channels: (rows.results || []).map(alertChannelToApi) });
        }

        if (request.method === "POST" && !channelId) {
          let body;
          try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
          const channelType = String(body.channel_type || "").trim().toLowerCase();
          const checked = validateAlertChannelInput(channelType, body.webhook_url);
          if (!checked.ok) return json({ error: checked.error }, 400);

          const countRow = await env.cybermeters_db
            .prepare(`SELECT COUNT(*) AS cnt FROM workspace_alert_channels WHERE workspace_id = ?`)
            .bind(workspaceId).first();
          if (Number(countRow?.cnt || 0) >= ALERT_CHANNEL_MAX_PER_WORKSPACE) {
            return json({ error: `A workspace can have at most ${ALERT_CHANNEL_MAX_PER_WORKSPACE} alert channels.` }, 400);
          }

          const id = createId("alch");
          const secret = channelType === "webhook"
            ? `whsec_${crypto.randomUUID().replace(/-/g, "")}` : null;
          const createdAt = new Date().toISOString();
          await env.cybermeters_db
            .prepare(`INSERT INTO workspace_alert_channels
                        (id, workspace_id, channel_type, webhook_url, secret, enabled, created_by, created_at)
                      VALUES (?, ?, ?, ?, ?, 1, ?, ?)`)
            .bind(id, workspaceId, channelType, checked.url, secret, user.id, createdAt)
            .run();
          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "alert_channel_created", entity_type: "alert_channel", entity_id: id,
            description: `Alert channel added (${channelType})`,
          });
          const row = await env.cybermeters_db
            .prepare(`SELECT * FROM workspace_alert_channels WHERE id = ?`).bind(id).first();
          // The signing secret is returned exactly once, at creation.
          return json({ channel: alertChannelToApi(row), secret }, 201);
        }

        if (request.method === "POST" && channelId && isTest) {
          const frontendOrigin = getEmailFrontendOrigin(env);
          const result = await deliverWorkspaceAlert(env, workspaceId, {
            kind: "test",
            severity: "info",
            title: "CyberMeters test alert",
            summary: "Your alert channel is connected. Scan, asset and certificate alerts will arrive here.",
            workspace_name: access.workspace_name || null,
            link: frontendOrigin ? `${frontendOrigin}/ws/alerts` : null,
          }, { channelId });
          if (result.attempted === 0) return json({ error: "Channel not found or disabled." }, 404);
          return json({ delivered: result.delivered === 1 });
        }

        if (request.method === "DELETE" && channelId && !isTest) {
          const del = await env.cybermeters_db
            .prepare(`DELETE FROM workspace_alert_channels WHERE id = ? AND workspace_id = ?`)
            .bind(channelId, workspaceId).run();
          if (!del.meta || del.meta.changes === 0) return json({ error: "Channel not found." }, 404);
          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "alert_channel_deleted", entity_type: "alert_channel", entity_id: channelId,
            description: "Alert channel removed",
          });
          return json({ ok: true });
        }

        return json({ error: "Method not allowed" }, 405);
      } catch (e) {
        return serverError("alert-channels", e, "Could not update alert channels.");
      }
    }

    // ── Finding waivers (risk acceptance) ─────────────────────────────────────
    // A workspace can explicitly accept the risk of a recurring finding for a
    // domain. Waivers never hide data silently: the UI moves the finding to an
    // "Accepted risks" section, and every waive/restore is audited.
    //   GET    .../finding-waivers                → list waivers for the domain
    //   POST   .../finding-waivers {finding_id, reason?} → upsert (manage role)
    //   DELETE .../finding-waivers/:findingId     → restore (manage role)
    const findingWaiversMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/domains\/([^/]+)\/finding-waivers(?:\/([^/]+))?$/);
    if (findingWaiversMatch) {
      const workspaceId = findingWaiversMatch[1];
      const domain = decodeURIComponent(findingWaiversMatch[2]).toLowerCase();
      const pathFindingId = findingWaiversMatch[3] ? decodeURIComponent(findingWaiversMatch[3]) : null;
      const FINDING_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,99}$/;
      try {
        const user = await requireAuth(request, env);
        if (!user) return json({ error: "Unauthorized" }, 401);
        const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
        const access = await requireWorkspaceRole(user, workspaceId, permission, env);
        if (!access) return json({ error: "Forbidden" }, 403);
        const domainId = await resolveWorkspaceDomain(env, workspaceId, domain);
        if (!domainId) return json({ error: "Domain not found in this workspace" }, 404);

        if (request.method === "GET" && !pathFindingId) {
          const rows = await env.cybermeters_db
            .prepare(`SELECT fw.finding_id, fw.reason, fw.created_at, fw.updated_at, u.name AS waived_by_name
                      FROM finding_waivers fw
                      LEFT JOIN users u ON u.id = fw.waived_by
                      WHERE fw.workspace_id = ? AND fw.domain = ?
                      ORDER BY fw.created_at DESC`)
            .bind(workspaceId, domain).all();
          return json({ domain, waivers: rows.results || [] });
        }

        if (request.method === "POST" && !pathFindingId) {
          let body;
          try { body = await request.json(); } catch { return json({ error: "Invalid JSON body" }, 400); }
          const findingId = String(body.finding_id || "").trim().toLowerCase();
          if (!FINDING_ID_RE.test(findingId)) return json({ error: "finding_id is required (letters, digits, _ . -)" }, 400);
          const reason = String(body.reason || "").trim().slice(0, 500) || null;

          await env.cybermeters_db
            .prepare(`INSERT INTO finding_waivers (id, workspace_id, domain, finding_id, reason, waived_by, created_at, updated_at)
                      VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                      ON CONFLICT(workspace_id, domain, finding_id)
                      DO UPDATE SET reason = excluded.reason, waived_by = excluded.waived_by, updated_at = datetime('now')`)
            .bind(createId("waiver"), workspaceId, domain, findingId, reason, user.id)
            .run();

          await createAuditEvent(env, {
            workspace_id: workspaceId, user_id: user.id,
            event_type: "finding_risk_accepted", entity_type: "finding", entity_id: findingId,
            description: `Risk accepted for finding "${findingId}" on ${domain}`,
            metadata: { domain, finding_id: findingId, reason },
          }).catch(() => {});
          return json({ waived: true, domain, finding_id: findingId, reason }, 201);
        }

        if (request.method === "DELETE" && pathFindingId) {
          const findingId = pathFindingId.toLowerCase();
          if (!FINDING_ID_RE.test(findingId)) return json({ error: "Invalid finding id" }, 400);
          const res = await env.cybermeters_db
            .prepare("DELETE FROM finding_waivers WHERE workspace_id = ? AND domain = ? AND finding_id = ?")
            .bind(workspaceId, domain, findingId)
            .run();
          if ((res.meta?.changes ?? 0) > 0) {
            await createAuditEvent(env, {
              workspace_id: workspaceId, user_id: user.id,
              event_type: "finding_risk_restored", entity_type: "finding", entity_id: findingId,
              description: `Risk acceptance removed for finding "${findingId}" on ${domain}`,
              metadata: { domain, finding_id: findingId },
            }).catch(() => {});
          }
          return json({ restored: true, domain, finding_id: findingId });
        }

        return json({ error: "Method not allowed" }, 405);
      } catch (e) {
        return serverError("finding-waivers", e, "Could not update risk acceptance.");
      }
    }


  return null;
}
