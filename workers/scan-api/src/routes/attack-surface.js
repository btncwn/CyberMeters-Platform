// ── Attack surface routes ──
// Workspace asset inventory (list/events/summary/timeline/detail), alert
// feed/summary, security-posture (+timeline) and vendor intelligence
// endpoints. Extracted near-verbatim from index.js (router split, Phase 2
// PR #16). Receives the per-request routeCtx from index.js; returns a
// Response when a route matches, or null so the main router continues.
import { buildCaConcentrationAnalytics, buildCertificateLifecycleIntelligence, detectSelfSignedCertificate, mapCertificateAuthorityOwner, normalizeCertificateIssuer } from "../engines/cert-analysis.js";
import { buildCertificateTrustL2 } from "../engines/cert-trust-l2.js";
import { buildCertificateCustomerPresentation } from "../engines/certificate-customer-presentation.js";
import { buildAttackSurfaceCustomerPresentation } from "../engines/attack-surface-customer-presentation.js";
import { listCertificateLifecycle } from "../engines/certificate-lifecycle.js";
import { assignManagedCaseOwner, deriveAsmCaseTraceability, getManagedCase, listManagedCaseEvents, listManagedCases, managedCaseToApi, transitionManagedCase, verifyManagedCaseById } from "../engines/asm-cases.js";
import { remapToThirdPartyCategory } from "../engines/discovery-scan.js";
import { computeWorkspaceVendorRisk, confidenceToScore, normalizeVendorKey, normalizeVendorRiskCategory, signalWeightForVendor } from "../engines/vendor-risk.js";
import { collapseCustomerTimelineEvents, countCustomerTimelineEventsByDay } from "../engines/timeline-trust.js";
import { visibleFindingSql } from "../engines/finding-identity.js";
import { projectTlsModulesForCustomer } from "../engines/tls-evidence.js";
import { SEVERITY_RANK, enrichEvent, eventTypesForCategory } from "../lib/exposure-events.js";
import { pageMeta, paginationParams, parseBoundedInteger } from "../lib/util.js";
import {
  phase5EvidenceReadCoverage,
  projectPhase5ScanRowsForCustomer,
  resolvePhase5CustomerAggregate,
} from "../engines/phase5-evidence.js";
import {
  loadAssetLifecycleEventSupport,
  projectLifecycleCollectionForCustomer,
  summariseLifecycleClaimProjection,
} from "../engines/asset-lifecycle-event-support.js";

// Projection is assembled before customer-facing collapse. Legacy counters are
// copied unchanged; unsupported/uncertain projected lifecycle rows contribute
// only a carrier day so historical evidence is never hidden.
function buildProjectionAwareTimelineDays(legacyDays, projectedEvents = [], zeroDay = {}) {
  const byDay = new Map((legacyDays || []).map((day) => [String(day.day), day]));
  for (const event of projectedEvents || []) {
    const state = event?.lifecycle_claim_support?.state;
    if (!(["unsupported", "uncertain"].includes(state))) continue;
    const day = String(event?.created_at || "").slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(day) || byDay.has(day)) continue;
    byDay.set(day, { day, ...zeroDay });
  }
  return [...byDay.values()].sort((a, b) => String(a.day).localeCompare(String(b.day)));
}

function parseJson(value, fallback = null) {
  if (value && typeof value === "object") return value;
  try { return value ? JSON.parse(value) : fallback; } catch { return fallback; }
}

async function projectLifecycleEvents(env, workspaceId, events, scope) {
  const rows = Array.isArray(events) ? events : [];
  const projection = await loadAssetLifecycleEventSupport(env, {
    workspaceId,
    events: rows,
    collectionLimit: 2000,
    scope,
  });
  return {
    projection,
    events: projectLifecycleCollectionForCustomer(rows, projection),
    summary: summariseLifecycleClaimProjection(rows, projection),
  };
}

const ASSET_PRESENTATION_COLUMNS = `
  id, workspace_id, domain_id, hostname, asset_type, source,
  first_seen, last_seen, status, wildcard_dns,
  ip_addresses, cname, redirect_to, cloud_provider,
  risk_level, metadata_json, created_at, updated_at`;

const ASSET_LIFECYCLE_COLUMNS = `,
  lifecycle_state, last_observation_state, lifecycle_policy_version,
  confirmed_removed_at, last_observation_scan_id`;

const ATTACK_SURFACE_LIFECYCLE_EVIDENCE_BOUND = 500;

async function loadAssetPresentationRows(env, workspaceId, {
  assetId = null,
  status = null,
  limit = 500,
} = {}) {
  const where = [
    "workspace_id = ?",
    ...(assetId ? ["id = ?"] : []),
    ...(status ? ["status = ?"] : []),
  ];
  const binds = [
    workspaceId,
    ...(assetId ? [assetId] : []),
    ...(status ? [status] : []),
    limit,
  ];
  const suffix = assetId
    ? "ORDER BY id LIMIT ?"
    : "ORDER BY last_seen DESC, id LIMIT ?";
  try {
    const result = await env.cybermeters_db
      .prepare(
        `SELECT ${ASSET_PRESENTATION_COLUMNS}${ASSET_LIFECYCLE_COLUMNS}
         FROM workspace_assets
         WHERE ${where.join(" AND ")}
         ${suffix}`
      )
      .bind(...binds)
      .all();
    return {
      rows: result.results || [],
      lifecycle_available: true,
    };
  } catch (error) {
    if (!/no such column/i.test(String(error?.message || ""))) throw error;
    const result = await env.cybermeters_db
      .prepare(
        `SELECT ${ASSET_PRESENTATION_COLUMNS}
         FROM workspace_assets
         WHERE ${where.join(" AND ")}
         ${suffix}`
      )
      .bind(...binds)
      .all();
    return {
      rows: result.results || [],
      lifecycle_available: false,
    };
  }
}

function lifecycleEvidenceCoverage({
  returned,
  total,
  bound,
  lifecycleAvailable,
}) {
  const truncated = total > returned;
  if (!lifecycleAvailable) {
    return {
      returned,
      total,
      bound,
      truncated,
      status: "not_recorded",
      customer_message:
        "Migration 102 lifecycle fields are not recorded. Asset identities were read only to preserve domain scope; no lifecycle conclusion is inferred.",
    };
  }
  if (truncated) {
    return {
      returned,
      total,
      bound,
      truncated: true,
      status: "truncated",
      customer_message:
        `Lifecycle evidence is truncated: ${returned} of ${total} workspace assets were read within the ${bound}-asset bound. The displayed domain lifecycle is partial and is not presented as complete.`,
    };
  }
  return {
    returned,
    total,
    bound,
    truncated: false,
    status: "complete",
    customer_message:
      `Lifecycle evidence covers all ${total} workspace assets within the ${bound}-asset bound.`,
  };
}

async function loadAttackSurfaceLifecycleEvidence(
  env,
  workspaceId,
  bound = ATTACK_SURFACE_LIFECYCLE_EVIDENCE_BOUND,
) {
  const lifecycleColumns = `
    id, domain_id, hostname, lifecycle_state, last_observation_state,
    lifecycle_policy_version, confirmed_removed_at,
    last_observation_scan_id`;
  const baseColumns = "id, domain_id, hostname";
  const read = async (columns) => {
    const result = await env.cybermeters_db
      .prepare(
        `SELECT ${columns}, COUNT(*) OVER () AS lifecycle_total
         FROM workspace_assets
         WHERE workspace_id = ?
         ORDER BY last_seen DESC, id
         LIMIT ?`
      )
      .bind(workspaceId, bound)
      .all();
    const rows = result.results || [];
    return {
      rows,
      total: Number(rows[0]?.lifecycle_total || 0),
    };
  };

  try {
    const result = await read(lifecycleColumns);
    return {
      rows: result.rows,
      lifecycle_available: true,
      coverage: lifecycleEvidenceCoverage({
        returned: result.rows.length,
        total: result.total,
        bound,
        lifecycleAvailable: true,
      }),
    };
  } catch (error) {
    if (!/no such column/i.test(String(error?.message || ""))) throw error;
    const result = await read(baseColumns);
    return {
      rows: result.rows,
      lifecycle_available: false,
      coverage: lifecycleEvidenceCoverage({
        returned: result.rows.length,
        total: result.total,
        bound,
        lifecycleAvailable: false,
      }),
    };
  }
}

async function loadAttackSurfacePresentationEvidence(env, workspaceId) {
  const signalRead = env.cybermeters_db
    .prepare(
      `WITH scan_rows AS (
         SELECT domain_id, scan_id, MAX(observed_at) AS observed_at
         FROM attack_surface_signal_observations
         WHERE workspace_id = ?
         GROUP BY domain_id, scan_id
       ),
       latest AS (
         SELECT domain_id, scan_id, observed_at
         FROM (
           SELECT domain_id, scan_id, observed_at,
                  ROW_NUMBER() OVER (
                    PARTITION BY domain_id
                    ORDER BY observed_at DESC, scan_id DESC
                  ) AS recency_rank
           FROM scan_rows
         )
         WHERE recency_rank = 1
       )
       SELECT aso.domain_id, aso.scan_id, aso.signal_key, aso.state,
              aso.reason, aso.evidence_count, aso.sources_json,
              aso.limitations_json, aso.model_version, aso.observed_at
       FROM attack_surface_signal_observations aso
       JOIN latest
         ON latest.domain_id = aso.domain_id
        AND latest.scan_id = aso.scan_id
       WHERE aso.workspace_id = ?
       ORDER BY aso.domain_id, aso.signal_key`
    )
    .bind(workspaceId, workspaceId)
    .all();
  const alertRead = env.cybermeters_db
    .prepare(
      `SELECT domain_id, scan_id, event_counts, sent_at
       FROM (
         SELECT s.domain_id, aar.scan_id, aar.event_counts, aar.sent_at,
                ROW_NUMBER() OVER (
                  PARTITION BY s.domain_id
                  ORDER BY aar.sent_at DESC, aar.id DESC
                ) AS recency_rank
         FROM asset_alert_records aar
         JOIN scans s
           ON s.id = aar.scan_id
          AND s.workspace_id = aar.workspace_id
         WHERE aar.workspace_id = ?
       )
       WHERE recency_rank = 1`
    )
    .bind(workspaceId)
    .all();
  const [signals, alerts] = await Promise.allSettled([
    signalRead,
    alertRead,
  ]);
  return {
    signal_rows: signals.status === "fulfilled"
      ? signals.value.results || []
      : [],
    signal_status: signals.status === "fulfilled"
      ? "recorded"
      : (/no such (?:table|column)/i.test(String(signals.reason?.message || ""))
          ? "not_recorded"
          : "unavailable"),
    alert_rows: alerts.status === "fulfilled"
      ? alerts.value.results || []
      : [],
    alert_status: alerts.status === "fulfilled"
      ? "recorded"
      : "unavailable",
  };
}

function presentationContext(lifecycleRows, lifecycleAvailable, evidence) {
  const signalsByDomain = new Map();
  for (const row of evidence.signal_rows) {
    let model = signalsByDomain.get(row.domain_id);
    if (!model) {
      model = {
        model_version: row.model_version || null,
        observed_at: row.observed_at || null,
        signals: {},
      };
      signalsByDomain.set(row.domain_id, model);
    }
    model.signals[row.signal_key] = row;
  }
  const alertByDomain = new Map(
    evidence.alert_rows.map((row) => [
      row.domain_id,
      {
        eligibility: parseJson(row.event_counts, {})?._eligibility || null,
        observed_at: row.sent_at || null,
      },
    ]),
  );
  const lifecycleByDomain = new Map();
  for (const row of lifecycleRows) {
    if (!lifecycleByDomain.has(row.domain_id)) {
      lifecycleByDomain.set(row.domain_id, []);
    }
    lifecycleByDomain.get(row.domain_id).push({
      ...row,
      asset_id: row.id,
    });
  }
  const domainIds = new Set([
    ...lifecycleRows.map((row) => row.domain_id).filter(Boolean),
    ...signalsByDomain.keys(),
    ...alertByDomain.keys(),
  ]);

  const build = (domainId, lifecycleRecords) => {
    const signal = signalsByDomain.get(domainId) || null;
    const alert = alertByDomain.get(domainId) || null;
    return buildAttackSurfaceCustomerPresentation({
      signalCompleteness: signal,
      lifecycleRecords: lifecycleAvailable ? lifecycleRecords : null,
      alertEligibility: alert?.eligibility || null,
      absenceReason: evidence.signal_status === "unavailable"
        ? "Attack Surface signal evidence could not be read. No favourable result is inferred."
        : "Attack Surface per-signal evidence is not recorded for this scope. No favourable result is inferred.",
      lifecycleAbsenceReason: lifecycleAvailable
        ? null
        : "Migration 102 lifecycle fields are not recorded. Legacy active/inactive status is not interpreted as observed, absent or confirmed removed.",
      alertAbsenceReason: evidence.alert_status === "unavailable"
        ? "ASM alert eligibility could not be read. No alert outcome is inferred."
        : "No ASM alert-eligibility decision is recorded for this scope. No alert outcome is inferred.",
      asOf: signal?.observed_at || alert?.observed_at || null,
    });
  };

  const byDomain = new Map(
    [...domainIds].map((domainId) => [
      domainId,
      build(domainId, lifecycleByDomain.get(domainId) || []),
    ]),
  );
  return {
    domains: [...byDomain.entries()].map(([domain_id, presentation]) => ({
      domain_id,
      ...presentation,
    })),
    forAsset: (asset) => build(
      asset.domain_id,
      lifecycleAvailable ? [{ ...asset, asset_id: asset.id }] : null,
    ),
  };
}

async function loadWorkspaceAttackSurfacePresentations(env, workspaceId) {
  const [lifecycle, evidence] = await Promise.all([
    loadAttackSurfaceLifecycleEvidence(env, workspaceId),
    loadAttackSurfacePresentationEvidence(env, workspaceId),
  ]);
  const context = presentationContext(
    lifecycle.rows,
    lifecycle.lifecycle_available,
    evidence,
  );
  return {
    domains: context.domains,
    coverage: lifecycle.coverage,
  };
}

async function loadAssetAttackSurfacePresentation(
  env,
  workspaceId,
  assetResult,
  asset,
) {
  const evidence = await loadAttackSurfacePresentationEvidence(
    env,
    workspaceId,
  );
  return presentationContext(
    assetResult.rows,
    assetResult.lifecycle_available,
    evidence,
  ).forAsset(asset);
}

// F-021 — customer-facing workspace aggregates may read R2 only for scans
// directly attributed to that workspace. A workspace_domains relationship
// selects the protected domain set; it is never scan ownership. NULL means the
// scan owner is unknown and is therefore excluded. Keeping this selection in
// one helper prevents the certificate, SaaS, cloud and admin surfaces from
// drifting back to domain-only or legacy-NULL fallbacks independently.
async function loadLatestAttributedWorkspaceScans(env, workspaceId) {
  const result = await env.cybermeters_db
    .prepare(
      `SELECT id, domain_id
       FROM (
         SELECT s.id, s.domain_id,
                ROW_NUMBER() OVER (
                  PARTITION BY s.domain_id
                  ORDER BY s.created_at DESC, s.id DESC
                ) AS row_rank
         FROM scans s
         JOIN workspace_domains wd
           ON wd.domain_id = s.domain_id
          AND wd.workspace_id = ?
         WHERE s.status = 'completed'
           AND s.workspace_id = ?
       )
       WHERE row_rank = 1`
    )
    .bind(workspaceId, workspaceId)
    .all();
  return result.results || [];
}

export async function attackSurfaceRoutes(rctx) {
  const { request, env, url, json,
          requireAuth, requireWorkspaceRole } = rctx;

    // ── /api/workspaces/:id/managed-cases ──────────────────────────────────
    const casesMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/managed-cases(?:\/([^/]+)(?:\/([^/]+))?)?$/);
    if (casesMatch) {
      const wsId = casesMatch[1];
      const caseId = casesMatch[2] || null;
      const action = casesMatch[3] || null;

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const permission = request.method === "GET" ? "workspace:read" : "workspace:manage";
      const access = await requireWorkspaceRole(user, wsId, permission, env);
      if (!access) return json({ error: "Forbidden" }, 403);

      const ws = await env.cybermeters_db
        .prepare(`SELECT id FROM workspaces WHERE id = ?`)
        .bind(wsId)
        .first()
        .catch(() => null);
      if (!ws) return json({ error: "Workspace not found" }, 404);

      if (request.method === "GET" && !caseId) {
        try {
          const cases = await listManagedCases(env, wsId, {
            status: url.searchParams.get("status"),
            case_type: url.searchParams.get("case_type") || "asm_exposure",
            limit: parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200),
          });
          // Additive traceability: each ASM case's honest relationship to the
          // latest recorded scan (linked / retained-historical / recurrence /
          // legacy-unknown). Read-only; a derivation failure omits the field
          // rather than fabricating a classification.
          try {
            const traceability = await deriveAsmCaseTraceability(env, wsId, cases);
            for (const c of cases) {
              const t = traceability.get(c.id);
              if (t) c.traceability = t;
            }
          } catch { /* omit rather than guess */ }
          return json({ workspace_id: wsId, count: cases.length, cases });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      if (!caseId) return json({ error: "Not found" }, 404);
      const row = await getManagedCase(env, wsId, caseId).catch(() => null);
      if (!row) return json({ error: "Managed case not found" }, 404);

      if (request.method === "GET" && !action) {
        const events = await listManagedCaseEvents(env, wsId, caseId).catch(() => []);
        const projected = managedCaseToApi(row);
        try {
          const t = (await deriveAsmCaseTraceability(env, wsId, [row])).get(row.id);
          if (t) projected.traceability = t;
        } catch { /* omit rather than guess */ }
        return json({ case: projected, events });
      }

      if (request.method === "POST" && action === "assign") {
        const body = await request.json().catch(() => null);
        const ownerRef = String(body?.owner_ref || "").trim();
        if (!ownerRef) return json({ error: "owner_ref is required" }, 400);
        try {
          let current = row;
          if (current.status === "open") {
            const triage = await transitionManagedCase(env, current, "triage", {
              actor_type: "customer", actor_id: user.id, action: "transition",
            });
            if (!triage.ok) return json({ error: triage.error }, 400);
            current = triage.case;
          }
          const assigned = await assignManagedCaseOwner(env, current, {
            owner_type: body?.owner_type || "unknown",
            owner_ref: ownerRef,
            assigned_by: "customer",
            actor_id: user.id,
          });
          if (!assigned.ok) return json({ error: assigned.error }, 400);
          const fresh = await getManagedCase(env, wsId, caseId);
          return json({ case: managedCaseToApi(fresh || assigned.case) });
        } catch {
          return json({ error: "Could not assign owner" }, 500);
        }
      }

      if (request.method === "POST" && action === "verify") {
        // Managed-verification profile trigger. Trusted: requires workspace:manage (checked
        // above). ALL scope is derived from the stored case — no hostname/domain_id/
        // finding_type is accepted from the client. Foreign case → 404 (non-enumerating).
        // Concurrency is CAS-based (single-invocation dedup); the optional header is an
        // audit correlation id only, not durable cross-window idempotency.
        const correlationId = (request.headers.get("x-correlation-id") || request.headers.get("idempotency-key") || "").trim().slice(0, 200) || null;
        let result;
        try {
          result = await verifyManagedCaseById(env, { workspaceId: wsId, caseId, actorId: user.id, correlationId });
        } catch {
          return json({ error: "Could not run verification" }, 500);
        }
        if (!result.ok) {
          // Non-enumerating: scope failures return the same 404 as a missing case.
          if (["not_found", "host_scope_mismatch", "domain_ineligible"].includes(result.code)) {
            return json({ error: "Managed case not found" }, 404);
          }
          if (result.code === "ineligible_state") return json({ error: "Case is not in a verification-eligible state" }, 409);
          if (result.code === "unsupported_finding_type") return json({ error: "Verification is not supported for this finding type" }, 422);
          return json({ error: "Verification could not run" }, 400);
        }
        const fresh = await getManagedCase(env, wsId, caseId).catch(() => null);
        return json({
          case: fresh ? managedCaseToApi(fresh) : null,
          verification: { profile: "managed_verification", code: result.code, decision: result.decision || null, completeness: result.completeness || null, outbound_calls: result.outbound_calls ?? null, idempotent: result.idempotent || false },
        });
      }

      if (request.method === "POST" && action === "transition") {
        const body = await request.json().catch(() => null);
        const target = String(body?.status || "").trim();
        if (!target) return json({ error: "status is required" }, 400);
        try {
          const result = await transitionManagedCase(env, row, target, {
            actor_type: "customer",
            actor_id: user.id,
            action: body?.action || "transition",
            reason: body?.reason || null,
            risk_accepted_until: body?.risk_accepted_until || null,
            detail: { reason: body?.reason || null, risk_accepted_until: body?.risk_accepted_until || null },
          });
          if (!result.ok) return json({ error: result.error }, 400);
          return json({ case: managedCaseToApi(result.case) });
        } catch {
          return json({ error: "Could not update managed case" }, 500);
        }
      }

      return json({ error: "Not found" }, 404);
    }

    // ── GET /api/workspaces/:id/exposure/feed ───────────────────────────────
    const feedMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/exposure\/feed$/);
    if (feedMatch && request.method === "GET") {
      const wsId = feedMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!ws) return json({ error: "Workspace not found" }, 404);

      const { limit, offset } = paginationParams(url, { defaultLimit: 50, maxLimit: 100 });
      const where = ["workspace_id = ?"];
      const binds = [wsId];

      const severity = url.searchParams.get("severity");
      if (severity && SEVERITY_RANK[severity] != null) {
        const allowed = Object.entries(SEVERITY_RANK)
          .filter(([, rank]) => rank >= SEVERITY_RANK[severity])
          .map(([name]) => name);
        where.push(`severity IN (${allowed.map(() => "?").join(",")})`);
        binds.push(...allowed);
      }

      const category = url.searchParams.get("category");
      if (category) {
        const eventTypes = eventTypesForCategory(category);
        if (eventTypes.length > 0) {
          where.push(`event_type IN (${eventTypes.map(() => "?").join(",")})`);
          binds.push(...eventTypes);
        } else {
          where.push("1 = 0");
        }
      }

      const eventType = url.searchParams.get("event_type");
      if (eventType) {
        where.push("event_type = ?");
        binds.push(eventType);
      }

      const hostname = url.searchParams.get("hostname");
      if (hostname) {
        where.push("hostname = ?");
        binds.push(hostname);
      }

      const domainId = url.searchParams.get("domain_id");
      if (domainId) {
        where.push("domain_id = ?");
        binds.push(domainId);
      }

      const since = url.searchParams.get("since");
      if (since && Number.isFinite(Date.parse(since))) {
        where.push("created_at >= ?");
        binds.push(since);
      }

      const until = url.searchParams.get("until");
      if (until && Number.isFinite(Date.parse(until))) {
        where.push("created_at <= ?");
        binds.push(until);
      }

      const whereSql = where.join(" AND ");
      try {
        const [pageResult, totalResult] = await env.cybermeters_db.batch([
          env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, asset_id, scan_id, event_type,
                      hostname, severity, description, created_at
               FROM asset_events
               WHERE ${whereSql}
               ORDER BY created_at DESC, id DESC
               LIMIT ? OFFSET ?`
            )
            .bind(...binds, limit, offset),
          env.cybermeters_db
            .prepare(
              `SELECT COUNT(*) AS n FROM asset_events
               WHERE ${whereSql}`
            )
            .bind(...binds),
        ]);

        const projected = await projectLifecycleEvents(
          env,
          wsId,
          pageResult.results || [],
          "exposure_feed_page",
        );
        const events = collapseCustomerTimelineEvents(projected.events).map(enrichEvent);
        const total = totalResult.results?.[0]?.n ?? 0;
        const assurance = await loadWorkspaceAttackSurfacePresentations(
          env,
          wsId,
        );
        return json({
          workspace_id: wsId,
          events,
          lifecycle_claim_projection: projected.summary,
          attack_surface_assurance: assurance.domains,
          attack_surface_assurance_coverage: assurance.coverage,
          pagination: pageMeta({ items: events, limit, offset, total }),
        });
      } catch {
        return json({ error: "Database error" }, 500);
      }
    }

    // ── /api/workspaces/:id/assets/* ────────────────────────────────────────
    // Handles list, events, summary, timeline, and per-asset detail.
    const assetsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/assets(\/[^/]*)?$/);
    if (assetsMatch && request.method === "GET") {
      const wsId  = assetsMatch[1];
      const sub   = assetsMatch[2] ?? "";   // "", "/events", "/summary", "/timeline", "/:assetId"

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let ws;
      try {
        ws = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!ws) return json({ error: "Workspace not found" }, 404);

      // ── GET /api/workspaces/:id/assets ───────────────────────────────────
      if (sub === "") {
        const statusFilter = url.searchParams.get("status");
        const limit        = parseBoundedInteger(url.searchParams.get("limit"), 200, 1, 500);
        try {
          const result = await loadAssetPresentationRows(env, wsId, {
            status: statusFilter || null,
            limit,
          });
          const assurance = await loadWorkspaceAttackSurfacePresentations(
            env,
            wsId,
          );
          return json({
            workspace_id: wsId,
            count: result.rows.length,
            assets: result.rows,
            attack_surface_assurance: assurance.domains,
            attack_surface_assurance_coverage: assurance.coverage,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/events ────────────────────────────
      if (sub === "/events") {
        const limit = parseBoundedInteger(url.searchParams.get("limit"), 100, 1, 500);
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at
               FROM asset_events
               WHERE workspace_id = ?
               ORDER BY created_at DESC LIMIT ?`
            )
            .bind(wsId, limit)
            .all();
          const projected = await projectLifecycleEvents(
            env,
            wsId,
            result.results || [],
            "asset_events_page",
          );
          const events = collapseCustomerTimelineEvents(projected.events);
          return json({
            workspace_id: wsId,
            count: events.length,
            events,
            lifecycle_claim_projection: projected.summary,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/summary ───────────────────────────
      if (sub === "/summary") {
        try {
          const [all, active, inactive, rootDomains, subdomains, exposedSvcs, cloudStorage, wildcardAssets, takeoverRisks] =
            await env.cybermeters_db.batch([
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ?`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'inactive'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'root_domain'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'subdomain'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'exposed_service'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND asset_type = 'cloud_storage'`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND wildcard_dns = 1`).bind(wsId),
              env.cybermeters_db.prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND risk_level IN ('high','critical')`).bind(wsId),
            ]);
          return json({
            workspace_id:       wsId,
            total_assets:       all.results[0]?.n         ?? 0,
            active_assets:      active.results[0]?.n      ?? 0,
            inactive_assets:    inactive.results[0]?.n    ?? 0,
            root_domains:       rootDomains.results[0]?.n ?? 0,
            subdomains:         subdomains.results[0]?.n  ?? 0,
            exposed_services:   exposedSvcs.results[0]?.n ?? 0,
            cloud_storage_assets: cloudStorage.results[0]?.n ?? 0,
            wildcard_assets:    wildcardAssets.results[0]?.n ?? 0,
            takeover_risks:     takeoverRisks.results[0]?.n  ?? 0,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/timeline ──────────────────────────
      if (sub === "/timeline") {
        try {
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at
               FROM asset_events
               WHERE workspace_id = ?
               ORDER BY created_at ASC, id ASC`
            )
            .bind(wsId)
            .all();

          // Pivot rows into { day, new_asset_discovered, asset_reappeared, ... }
          const EVENT_TYPES = [
            "new_asset_discovered", "asset_reappeared", "asset_no_longer_seen",
            "takeover_risk_detected", "wildcard_dns_detected", "cloud_storage_detected",
          ];
          const projected = await projectLifecycleEvents(
            env,
            wsId,
            result.results || [],
            "asset_timeline_all",
          );
          const legacyTimeline = countCustomerTimelineEventsByDay(
            result.results || [],
            EVENT_TYPES,
          );
          const supportedNoLongerByDay = new Map();
          if (projected.summary.coverage === "complete") {
            for (const event of projected.events) {
              if (
                event.event_type === "asset_no_longer_seen" &&
                event.lifecycle_claim_support?.state === "supported"
              ) {
                const day = String(event.created_at || "").slice(0, 10);
                supportedNoLongerByDay.set(day, (supportedNoLongerByDay.get(day) || 0) + 1);
              }
            }
          }
          const timelineDays = buildProjectionAwareTimelineDays(
            legacyTimeline,
            projected.events,
            { new_asset_discovered: 0, asset_reappeared: 0, asset_no_longer_seen: 0,
              takeover_risk_detected: 0, wildcard_dns_detected: 0, cloud_storage_detected: 0 },
          );
          return json({
            workspace_id: wsId,
            timeline: timelineDays.map((day) => ({
              ...day,
              no_longer_observed_assets:
                projected.summary.coverage === "complete"
                  ? supportedNoLongerByDay.get(day.day) || 0
                  : null,
            })),
            lifecycle_claim_projection: projected.summary,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/assets/:assetId ──────────────────────────
      {
        const assetId = sub.slice(1);   // strip leading "/"
        try {
          const assetResult = await loadAssetPresentationRows(env, wsId, {
            assetId,
            limit: 1,
          });
          const asset = assetResult.rows[0] || null;
          if (!asset) return json({ error: "Asset not found" }, 404);

          const eventsResult = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at
               FROM asset_events
               WHERE asset_id = ? AND workspace_id = ?
               ORDER BY created_at DESC LIMIT 50`
            )
            .bind(assetId, wsId)
            .all();

          const attackSurfaceAssurance = await loadAssetAttackSurfacePresentation(
            env,
            wsId,
            assetResult,
            asset,
          );
          const projected = await projectLifecycleEvents(
            env,
            wsId,
            eventsResult.results || [],
            "asset_detail_history",
          );
          return json({
            asset: {
              ...asset,
              attack_surface_assurance: attackSurfaceAssurance,
            },
            events: projected.events,
            lifecycle_claim_projection: projected.summary,
            attack_surface_assurance: attackSurfaceAssurance,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }
    }

    // ── /api/workspaces/:id/alerts/* ────────────────────────────────────────
    // GET /api/workspaces/:id/alerts          — list alerts, filterable by severity
    // GET /api/workspaces/:id/alerts/summary  — severity counts + last alert timestamp
    const alertsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/alerts(\/[^/]*)?$/);
    if (alertsMatch && request.method === "GET") {
      const wsId = alertsMatch[1];
      const sub  = alertsMatch[2] ?? "";   // "" or "/summary"

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let wsExists;
      try {
        wsExists = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!wsExists) return json({ error: "Workspace not found" }, 404);

      // ── GET /api/workspaces/:id/alerts/summary ─────────────────────────────
      if (sub === "/summary") {
        try {
          const [total, critical, high, medium, low, latest] =
            await env.cybermeters_db.batch([
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ?`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'critical'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'high'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'medium'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT COUNT(*) AS n FROM asset_alert_records WHERE workspace_id = ? AND severity = 'low'`)
                .bind(wsId),
              env.cybermeters_db
                .prepare(`SELECT sent_at FROM asset_alert_records WHERE workspace_id = ? ORDER BY sent_at DESC LIMIT 1`)
                .bind(wsId),
            ]);
          return json({
            workspace_id:       wsId,
            total:              total.results[0]?.n    ?? 0,
            critical:           critical.results[0]?.n ?? 0,
            high:               high.results[0]?.n     ?? 0,
            medium:             medium.results[0]?.n   ?? 0,
            low:                low.results[0]?.n      ?? 0,
            last_alert_at:      latest.results[0]?.sent_at ?? null,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/alerts ─────────────────────────────────────
      if (sub === "") {
        const severityFilter = url.searchParams.get("severity");
        const limit          = parseBoundedInteger(url.searchParams.get("limit"), 50, 1, 200);
        const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);

        if (severityFilter && !VALID_SEVERITIES.has(severityFilter)) {
          return json({ error: "Invalid severity value" }, 400);
        }

        try {
          const where  = severityFilter ? "AND severity = ?" : "";
          const binds  = severityFilter ? [wsId, severityFilter, limit] : [wsId, limit];
          const result = await env.cybermeters_db
            .prepare(
              `SELECT id, workspace_id, scan_id, domain, severity,
                      event_counts, top_hostnames, sent_at
               FROM asset_alert_records
               WHERE workspace_id = ? ${where}
               ORDER BY sent_at DESC
               LIMIT ?`
            )
            .bind(...binds)
            .all();

          // Parse JSON columns so consumers don't have to
          const alerts = (result.results || []).map((row) => ({
            ...row,
            event_counts:  row.event_counts  ? JSON.parse(row.event_counts)  : {},
            top_hostnames: row.top_hostnames ? JSON.parse(row.top_hostnames) : [],
          }));

          return json({ workspace_id: wsId, count: alerts.length, alerts });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // Unknown sub-resource
      return json({ error: "Not found" }, 404);
    }

    // ── /api/workspaces/:id/posture[/timeline] ──────────────────────────────
    // GET /api/workspaces/:id/posture          — current attack surface posture snapshot
    // GET /api/workspaces/:id/posture/timeline — daily metric series (last 90 days)
    //
    // Both routes use existing data only (workspace_assets, asset_events, scans,
    // findings, workspace_domains).  No new scanning modules, no scoring changes.
    const postureMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/posture(\/timeline)?$/);
    if (postureMatch && request.method === "GET") {
      const wsId    = postureMatch[1];
      const isTimeline = !!postureMatch[2];   // true → /posture/timeline

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Verify workspace exists
      let wsExists;
      try {
        wsExists = await env.cybermeters_db
          .prepare(`SELECT id FROM workspaces WHERE id = ?`)
          .bind(wsId)
          .first();
      } catch {
        return json({ error: "Database error" }, 500);
      }
      if (!wsExists) return json({ error: "Workspace not found" }, 404);

      // ── Attack Surface Size classification ────────────────────────────────
      // 0-10 = Small, 11-50 = Medium, 51-200 = Large, 201+ = Very Large
      function classifyAttackSurface(assetCount) {
        if (assetCount <= 10)  return "Small";
        if (assetCount <= 50)  return "Medium";
        if (assetCount <= 200) return "Large";
        return "Very Large";
      }

      // ── Risk trend helper ─────────────────────────────────────────────────
      // Higher score = safer. Score drop = risk going up.
      function scoreTrend(avgLast, avgPrev) {
        if (avgLast === null || avgPrev === null) return "stable";
        const delta = avgLast - avgPrev;
        if (delta >= 3)  return "down";   // score improved → risk down
        if (delta <= -3) return "up";     // score fell → risk up
        return "stable";
      }

      // ── GET /api/workspaces/:id/posture ───────────────────────────────────
      if (!isTimeline) {
        try {
          const [
            totalRow,
            activeRow,
            newAssets30dRow,
            removedAssets30dRow,
            removedAssetEvents30dRow,
            criticalNow30dRow,
            criticalPrev30dRow,
            avgScoreLast30dRow,
            avgScorePrev30dRow,
          ] = await env.cybermeters_db.batch([

            // Total assets ever tracked in this workspace
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ?`)
              .bind(wsId),

            // Currently active assets
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
              .bind(wsId),

            // Assets first discovered in the last 30 days
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND first_seen >= datetime('now', '-30 days')`)
              .bind(wsId),

            // Assets removed (no-longer-seen events) in the last 30 days
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM asset_events WHERE workspace_id = ? AND event_type = 'asset_no_longer_seen' AND created_at >= datetime('now', '-30 days')`)
              .bind(wsId),

            // Exact rows for the bounded P4 read-time projection. LIMIT 2001
            // detects collection overflow without changing the legacy count.
            env.cybermeters_db
              .prepare(
                `SELECT id, workspace_id, domain_id, asset_id, scan_id,
                        event_type, hostname, severity, description, created_at
                 FROM asset_events
                 WHERE workspace_id = ?
                   AND event_type = 'asset_no_longer_seen'
                   AND created_at >= datetime('now', '-30 days')
                 ORDER BY created_at ASC, id ASC
                 LIMIT 2001`
              )
              .bind(wsId),

            // Critical findings from scans in the last 30 days (via workspace_domains join)
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(f.id) AS n
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND ${visibleFindingSql("f", "s")}
                   AND s.created_at >= datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Critical findings from scans in the preceding 30 days (days -60 to -30)
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(f.id) AS n
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND ${visibleFindingSql("f", "s")}
                   AND s.created_at >= datetime('now', '-60 days')
                   AND s.created_at <  datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Average scan score over the last 30 days (for risk trend)
            env.cybermeters_db
              .prepare(
                `SELECT s.id, s.status, s.score, s.rating, s.scan_quality, s.created_at
                 FROM scans s
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND s.status = 'completed'
                   AND s.score IS NOT NULL
                   AND s.created_at >= datetime('now', '-30 days')`
              )
              .bind(wsId),

            // Average scan score over the preceding 30 days (days -60 to -30)
            env.cybermeters_db
              .prepare(
                `SELECT s.id, s.status, s.score, s.rating, s.scan_quality, s.created_at
                 FROM scans s
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND s.status = 'completed'
                   AND s.score IS NOT NULL
                   AND s.created_at >= datetime('now', '-60 days')
                   AND s.created_at <  datetime('now', '-30 days')`
              )
              .bind(wsId),
          ]);

          const totalAssets    = totalRow.results[0]?.n          ?? 0;
          const activeAssets   = activeRow.results[0]?.n         ?? 0;
          const newAssets30d   = newAssets30dRow.results[0]?.n   ?? 0;
          const removedAssets30d = removedAssets30dRow.results[0]?.n ?? 0;
          const lifecycleProjection = await projectLifecycleEvents(
            env,
            wsId,
            removedAssetEvents30dRow.results || [],
            "posture_summary_no_longer_observed_30d",
          );
          const noLongerObservedAssets30d =
            lifecycleProjection.summary.coverage === "complete"
              ? lifecycleProjection.summary.by_event_type?.asset_no_longer_seen?.supported ?? 0
              : null;
          const criticalNow    = criticalNow30dRow.results[0]?.n    ?? 0;
          const criticalPrev   = criticalPrev30dRow.results[0]?.n   ?? 0;
          const customerScoreRows = await projectPhase5ScanRowsForCustomer(
            env,
            [
              ...(avgScoreLast30dRow.results ?? []).map((row) => ({
                ...row,
                score_period: "current",
              })),
              ...(avgScorePrev30dRow.results ?? []).map((row) => ({
                ...row,
                score_period: "previous",
              })),
            ],
          );
          const currentAggregate = resolvePhase5CustomerAggregate(
            customerScoreRows.filter((row) => row.score_period === "current"),
          );
          const previousAggregate = resolvePhase5CustomerAggregate(
            customerScoreRows.filter((row) => row.score_period === "previous"),
          );
          const avgScoreLast30d = currentAggregate.score;
          const avgScorePrev30d = previousAggregate.score;

          const trend = scoreTrend(avgScoreLast30d, avgScorePrev30d);

          return json({
            workspace_id:                wsId,
            attack_surface_size:         classifyAttackSurface(totalAssets),
            total_assets:                totalAssets,
            active_assets:               activeAssets,
            new_assets_30d:              newAssets30d,
            // `removed_assets_30d` is a legacy compatibility alias for the
            // same no-longer-observed event count. It does not prove removal.
            removed_assets_30d:          removedAssets30d,
            no_longer_observed_assets_30d: noLongerObservedAssets30d,
            asset_growth_30d:            newAssets30d - removedAssets30d,
            critical_findings:           criticalNow,
            critical_findings_change_30d: criticalNow - criticalPrev,
            risk_trend:                  trend,
            score_trend:                 trend,   // same signal; both exposed for consumer flexibility
            avg_score_last_30d:          avgScoreLast30d !== null ? Math.round(avgScoreLast30d) : null,
            avg_score_prev_30d:          avgScorePrev30d !== null ? Math.round(avgScorePrev30d) : null,
            score_evidence_coverage: {
              overall: phase5EvidenceReadCoverage(customerScoreRows),
              current: currentAggregate.evidence_coverage,
              previous: previousAggregate.evidence_coverage,
            },
            lifecycle_claim_projection: lifecycleProjection.summary,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      // ── GET /api/workspaces/:id/posture/timeline ──────────────────────────
      // Returns one entry per day for the last 90 days.
      // asset_count is derived by applying daily deltas backward from today's total.
      if (isTimeline) {
        try {
          const [totalActiveRow, eventRows, findingRows] = await env.cybermeters_db.batch([

            // Current active asset count — used as the anchor for backward derivation
            env.cybermeters_db
              .prepare(`SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = ? AND status = 'active'`)
              .bind(wsId),

            // Raw new / removed events for the last 90 days. Collapse first,
            // then aggregate, so short-lived churn does not drive trend counts.
            env.cybermeters_db
              .prepare(
                `SELECT id, workspace_id, domain_id, asset_id, scan_id,
                        event_type, hostname, severity, description, created_at
                 FROM asset_events
                 WHERE workspace_id = ?
                   AND created_at >= datetime('now', '-90 days')
                   AND event_type IN ('new_asset_discovered', 'asset_no_longer_seen', 'asset_reappeared')
                 ORDER BY created_at ASC, id ASC`
              )
              .bind(wsId),

            // Per-day critical findings count (from scans run that day)
            env.cybermeters_db
              .prepare(
                `SELECT date(s.created_at) AS day, COUNT(f.id) AS critical_findings
                 FROM findings f
                 JOIN scans s ON f.scan_id = s.id
                 JOIN workspace_domains wd ON s.domain_id = wd.domain_id
                 WHERE wd.workspace_id = ?
                   AND f.severity = 'critical'
                   AND ${visibleFindingSql("f", "s")}
                   AND s.created_at >= datetime('now', '-90 days')
                 GROUP BY day
                 ORDER BY day ASC`
              )
              .bind(wsId),
          ]);

          // Build day-keyed maps from query results
          const eventMap    = new Map();
          const findingMap  = new Map();
          const projected = await projectLifecycleEvents(
            env,
            wsId,
            eventRows.results || [],
            "posture_timeline_90d",
          );
          const supportedNoLongerByDay = new Map();
          if (projected.summary.coverage === "complete") {
            for (const event of projected.events) {
              if (
                event.event_type === "asset_no_longer_seen" &&
                event.lifecycle_claim_support?.state === "supported"
              ) {
                const day = String(event.created_at || "").slice(0, 10);
                supportedNoLongerByDay.set(day, (supportedNoLongerByDay.get(day) || 0) + 1);
              }
            }
          }

          for (const row of countCustomerTimelineEventsByDay(eventRows.results || [], ["new_asset_discovered", "asset_no_longer_seen"])) {
            eventMap.set(row.day, {
              day: row.day,
              new_assets: row.new_asset_discovered ?? 0,
              removed_assets: row.asset_no_longer_seen ?? 0,
            });
          }
          for (const row of (findingRows.results || [])) {
            findingMap.set(row.day, row.critical_findings ?? 0);
          }

          // Projection-aware carrier days are unioned before customer collapse;
          // projected-only days retain zero legacy counters.
          const timelineDays = buildProjectionAwareTimelineDays(
            [...eventMap.values()],
            projected.events,
            { new_assets: 0, removed_assets: 0 },
          );
          const days = [...new Set([
            ...timelineDays.map((row) => row.day),
            ...findingMap.keys(),
          ])].sort();

          // Derive asset_count by walking forward from the earliest day.
          // anchor = total active assets today; walk backward from end → start to seed the
          // starting count, then walk forward to fill in each day's snapshot.
          let runningCount = totalActiveRow.results[0]?.n ?? 0;

          // First pass: walk backward from today to compute the count at the start of `days`
          for (let i = days.length - 1; i >= 0; i--) {
            const d = days[i];
            const ev = eventMap.get(d) ?? { new_assets: 0, removed_assets: 0 };
            runningCount -= ev.new_assets;
            runningCount += ev.removed_assets;
          }

          // Second pass: walk forward, incrementally updating the running count per day
          const timeline = [];
          for (const day of days) {
            const ev = eventMap.get(day) ?? { new_assets: 0, removed_assets: 0 };
            runningCount += ev.new_assets;
            runningCount -= ev.removed_assets;
            timeline.push({
              day,
              asset_count:       Math.max(0, runningCount),
              new_assets:        ev.new_assets,
              // `removed_assets` is a legacy compatibility alias for the
              // same no-longer-observed event count. It does not prove removal.
              removed_assets:    ev.removed_assets,
              no_longer_observed_assets:
                projected.summary.coverage === "complete"
                  ? supportedNoLongerByDay.get(day) || 0
                  : null,
              critical_findings: findingMap.get(day) ?? 0,
            });
          }

          return json({
            workspace_id: wsId,
            days: timeline.length,
            timeline,
            lifecycle_claim_projection: projected.summary,
          });
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }
    }

    // ── Certificate Intelligence routes ────────────────────────────────────
    // GET /api/workspaces/:id/certificates
    //   Returns latest certificate_intelligence per domain in workspace.
    //   Each entry: { domain, certificate_risk_level, days_until_expiry,
    //     expires_at, total_certificates_seen, issued_for_sensitive_hosts,
    //     wildcard_dns, suspicious_certificate_signals, ct_sources }
    //
    // GET /api/workspaces/:id/certificates/timeline
    //   Returns certificate-related asset_events from the last 90 days,
    //   grouped by day: [{ day, events:[{event_type, severity, description}] }]
    const certMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/certificates(\/timeline)?$/
    );
    if (certMatch && request.method === "GET") {
      const wsId        = certMatch[1];
      const isTimeline  = !!certMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Soft-deleted workspaces are nonexistent to certificate customer
      // surfaces. This is explicit here because the route reads R2 reports as
      // well as D1 rows and must not rely on a downstream writer guard.
      const activeWorkspace = await env.cybermeters_db
        .prepare("SELECT id FROM workspaces WHERE id = ? AND deleted_at IS NULL")
        .bind(wsId)
        .first()
        .catch(() => null);
      if (!activeWorkspace) return json({ error: "Workspace not found" }, 404);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      // ── /certificates/timeline ──────────────────────────────────────────
      if (isTimeline) {
        if (domainIds.length === 0) {
          return json({ workspace_id: wsId, days: 90, timeline: [] });
        }

        // Query asset_events for cert-related event types in this workspace
        let events;
        try {
          const cutoff = new Date(Date.now() - 90 * 86_400_000).toISOString();
          const r = await env.cybermeters_db
            .prepare(
              `SELECT event_type, severity, description, hostname,
                      DATE(created_at) AS day
               FROM asset_events
               WHERE workspace_id = ?
                 AND event_type IN (
                       'certificate_sensitive_host_detected',
                       'certificate_expiring_soon',
                       'certificate_growth_detected',
                       'certificate_new_detected',
                       'certificate_new_san_detected',
                       'certificate_new_issuer_detected'
                     )
                 AND created_at >= ?
               ORDER BY created_at DESC`
            )
            .bind(wsId, cutoff)
            .all();
          events = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        // Group by day
        const dayMap = new Map();
        for (const ev of collapseCustomerTimelineEvents(events)) {
          if (!dayMap.has(ev.day)) dayMap.set(ev.day, []);
          dayMap.get(ev.day).push({
            event_type:  ev.event_type,
            severity:    ev.severity,
            description: ev.description,
            hostname:    ev.hostname || null,
          });
        }

        const timeline = [...dayMap.entries()]
          .sort(([a], [b]) => b.localeCompare(a))
          .map(([day, evts]) => ({ day, events: evts }));

	        let issuer_history = [];
	        let certificate_timeline = [];
	        let ca_concentration = buildCaConcentrationAnalytics([], {
	          source: "historical_certificate_observations",
	        });
	        let churn = {
	          certificates_last_30_days: 0,
	          certificates_last_90_days: 0,
	          classification: "low",
        };
        try {
          const thirtyDaysAgo = new Date(Date.now() - 30 * 86_400_000).toISOString();
          const ninetyDaysAgo = new Date(Date.now() - 90 * 86_400_000).toISOString();

          const [issuerRows, certRows, churn30, churn90] = await Promise.all([
            env.cybermeters_db
              .prepare(
                `SELECT issuer, MIN(first_seen) AS first_seen,
                        MAX(last_seen) AS last_seen, COUNT(*) AS certificates
                 FROM certificate_observations
                 WHERE workspace_id = ?
                 GROUP BY issuer
                 ORDER BY first_seen ASC`
              )
              .bind(wsId)
              .all(),
            env.cybermeters_db
              .prepare(
                `SELECT subject, issuer, san_count, expires_at,
                        first_seen, last_seen
                 FROM certificate_observations
                 WHERE workspace_id = ?
                 ORDER BY first_seen DESC`
              )
              .bind(wsId)
              .all(),
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(*) AS n FROM certificate_observations
                 WHERE workspace_id = ? AND first_seen >= ?`
              )
              .bind(wsId, thirtyDaysAgo)
              .first(),
            env.cybermeters_db
              .prepare(
                `SELECT COUNT(*) AS n FROM certificate_observations
                 WHERE workspace_id = ? AND first_seen >= ?`
              )
              .bind(wsId, ninetyDaysAgo)
              .first(),
          ]);

	          issuer_history = issuerRows.results || [];
	          certificate_timeline = certRows.results || [];
	          ca_concentration = buildCaConcentrationAnalytics(certificate_timeline, {
	            source: "historical_certificate_observations",
	          });
	          const count30 = churn30?.n ?? 0;
	          const count90 = churn90?.n ?? 0;
          const classification =
            count90 >= 25 ? "unusual" :
            count90 >= 10 ? "high" :
            count90 >= 3  ? "medium" : "low";
          churn = {
            certificates_last_30_days: count30,
            certificates_last_90_days: count90,
            classification,
          };
        } catch { /* v2 migration may not be applied yet */ }

	        return json({ workspace_id: wsId, days: 90, timeline, certificate_timeline, issuer_history, churn, ca_concentration });
	      }

      // ── /certificates ───────────────────────────────────────────────────
      if (domainIds.length === 0) {
        return json({ workspace_id: wsId, total: 0, certificates: [] });
      }

      // One direct-attribution query for the latest completed scan per protected
      // domain. Legacy NULL-owner and co-linked foreign scans are excluded before
      // any R2 key is derived.
      let scanRows = [];
      try {
        scanRows = await loadLatestAttributedWorkspaceScans(env, wsId);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      // Fetch R2 reports in parallel
	      const r2Results = await Promise.allSettled(
	        scanRows.map((s) => env.cybermeters_reports.get(`reports/${s.id}.json`))
	      );

	      const caConcentrationByDomain = new Map();
	      const certificateHistoryByDomain = new Map();
	      const lifecycleByDomain = new Map();
	      try {
	        const [observed, lifecycle] = await Promise.all([
	          env.cybermeters_db
	            .prepare(
	              `SELECT domain_id, subject, issuer, san_count, expires_at,
	                      first_seen, last_seen, evidence_json
	               FROM certificate_observations
	               WHERE workspace_id = ?`
	            )
	            .bind(wsId)
	            .all(),
	          listCertificateLifecycle(env, wsId, { limit: 500 }),
	        ]);
	        const byDomain = new Map();
	        for (const row of (observed.results || [])) {
	          if (!row.domain_id) continue;
	          if (!byDomain.has(row.domain_id)) byDomain.set(row.domain_id, []);
	          byDomain.get(row.domain_id).push(row);
	        }
	        for (const [domainId, rows] of byDomain.entries()) {
	          certificateHistoryByDomain.set(domainId, rows);
	          caConcentrationByDomain.set(domainId, buildCaConcentrationAnalytics(rows, {
	            source: "historical_certificate_observations",
	          }));
	        }
	        for (const row of (lifecycle || [])) {
	          if (!row.domain_id || lifecycleByDomain.has(row.domain_id)) continue;
	          lifecycleByDomain.set(row.domain_id, row);
	        }
	      } catch { /* certificate_observations may not exist in older environments */ }

	      const certificates = [];
	      for (let i = 0; i < r2Results.length; i++) {
        if (r2Results[i].status !== "fulfilled" || !r2Results[i].value) continue;
        let report;
        try { report = await r2Results[i].value.json(); } catch { continue; }

        const ci = projectTlsModulesForCustomer(report?.modules ?? {}).certificate_intelligence;
        if (!ci) continue;

        const lifecycle = lifecycleByDomain.get(scanRows[i]?.domain_id) || null;
        const assurance = buildCertificateCustomerPresentation({
          signalCompleteness: ci.signal_completeness || null,
          lifecycle,
          absenceReason:
            "Per-signal certificate evidence was not recorded for this scan. No favourable state is inferred.",
        });
        // The lifecycle JOIN has both current and previous immutable observation
        // evidence, so prefer its relationship projection when present. Signal
        // presentation still comes from this scan's canonical P1-P4 model.
        if (lifecycle?.certificate_assurance?.relationship) {
          assurance.relationship = lifecycle.certificate_assurance.relationship;
        }

        const certificate = {
          domain:                       report.domain || null,
          certificate_risk_level:       ci.certificate_risk_level,
	          certificate_status:           ci.certificate_status,
	          issuer:                       ci.issuer || null,
	          issuer_normalized:            ci.issuer_normalized || normalizeCertificateIssuer(ci.issuer || null),
	          ca_owner:                     ci.ca_owner || mapCertificateAuthorityOwner(normalizeCertificateIssuer(ci.issuer || null)),
	          subject:                      ci.subject || null,
	          san_count:                    ci.san_count || 0,
	          san_hostnames:                ci.san_hostnames || [],
	          days_until_expiry:            ci.days_until_expiry,
	          expires_at:                   ci.expires_at,
	          lifecycle:                    ci.lifecycle || buildCertificateLifecycleIntelligence(ci),
	          key_algorithm:                ci.key_algorithm || "unknown",
	          key_size_bits:                ci.key_size_bits || "unknown",
	          signature_algorithm:          ci.signature_algorithm || "unknown",
	          crypto_metadata:              ci.crypto_metadata || {
	            key_algorithm: ci.key_algorithm || "unknown",
	            key_size_bits: ci.key_size_bits || "unknown",
	            signature_algorithm: ci.signature_algorithm || "unknown",
	          },
	          self_signed:                  ci.self_signed ?? detectSelfSignedCertificate(ci.issuer || null, ci.subject || null),
	          ca_concentration:             caConcentrationByDomain.get(scanRows[i]?.domain_id) || ci.ca_concentration || buildCaConcentrationAnalytics(ci.issuer ? [ci.issuer] : []),
	          total_certificates_seen:      ci.total_certificates_seen,
	          issued_for_sensitive_hosts:   ci.issued_for_sensitive_hosts || [],
          wildcard_dns:                 ci.wildcard_dns,
          wildcard_warning:             ci.wildcard_warning || null,
          ct_sources:                   ci.ct_sources || {},
          suspicious_certificate_signals: ci.suspicious_certificate_signals || [],
          signal_completeness:           ci.signal_completeness || null,
          certificate_assurance:         assurance,
          scan_id:                      scanRows[i]?.id || null,
        };
        Object.assign(certificate, buildCertificateTrustL2(certificate, {
          history: certificateHistoryByDomain.get(scanRows[i]?.domain_id) || [],
        }));
        certificates.push(certificate);
      }

      // Sort: critical first, then high, medium, low
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
      certificates.sort(
        (a, b) => (riskOrder[a.certificate_risk_level] ?? 5) - (riskOrder[b.certificate_risk_level] ?? 5)
      );

      return json({
        workspace_id: wsId,
        total:        certificates.length,
        certificates,
      });
    }

    // ── SaaS Exposure Discovery route ─────────────────────────────────────
    // GET /api/workspaces/:id/saas-exposure
    //   Filters: ?exposure_type=login_portal|email_gateway|saas_tenant|
    //                           support_portal|crm_portal|dev_portal|ecommerce_portal
    //            ?risk_level=low|medium|high
    //            ?category=email_identity|collaboration|crm|support|ecommerce
    //   Returns: { workspace_id, total, high_risk, exposures: [...] }
    const saasExpMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/saas-exposure$/
    );
    if (saasExpMatch && request.method === "GET") {
      const wsId = saasExpMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        return json({ workspace_id: wsId, total: 0, high_risk: 0, exposures: [] });
      }

      // 2. Latest directly attributed completed scan per protected domain.
      let scanRows;
      try {
        scanRows = await loadLatestAttributedWorkspaceScans(env, wsId);
      } catch {
        return json({ error: "Database error" }, 500);
      }
      const scanIds = scanRows.map((row) => row.id);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Merge saas_exposure.exposures across all reports (dedup by name)
      const seen      = new Set();
      const exposures = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const mod = report?.modules?.saas_exposure;
        if (!mod?.exposures?.length) continue;

        for (const exp of mod.exposures) {
          if (seen.has(exp.name)) continue;
          seen.add(exp.name);
          exposures.push({
            name:           exp.name,
            category:       exp.category,
            exposure_type:  exp.exposure_type,
            risk_level:     exp.risk_level,
            portal_url:     exp.portal_url     || null,
            admin_url:      exp.admin_url      || null,
            tenant_hint:    exp.tenant_hint    || null,
            tenant_url:     exp.tenant_url     || null,
            attack_surface: exp.attack_surface || null,
            confidence:     exp.confidence,
            domain:         report.domain      || null,
          });
        }
      }

      // Sort high → medium → low
      const riskOrder = { high: 0, medium: 1, low: 2 };
      exposures.sort((a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3));

      // Apply filters
      const filterExpType  = url.searchParams.get("exposure_type");
      const filterRisk     = url.searchParams.get("risk_level");
      const filterCategory = url.searchParams.get("category");

      const filtered = exposures.filter((e) => {
        if (filterExpType  && e.exposure_type !== filterExpType)  return false;
        if (filterRisk     && e.risk_level    !== filterRisk)     return false;
        if (filterCategory && e.category      !== filterCategory) return false;
        return true;
      });

      return json({
        workspace_id: wsId,
        total:     filtered.length,
        high_risk: filtered.filter((e) => e.risk_level === "high").length,
        exposures: filtered,
      });
    }

    // ── Cloud Asset Discovery routes ───────────────────────────────────────
    // GET /api/workspaces/:id/cloud-assets
    //   Filters: ?category=storage|cdn|serverless|paas|hosting
    //            ?provider=<name>  ?risk_level=low|medium|high
    //   Returns: { workspace_id, total, assets: [...] }
    //
    // GET /api/workspaces/:id/cloud-assets/summary
    //   Returns: { workspace_id, total, by_category:{storage,cdn,serverless,paas,hosting},
    //              high_risk, medium_risk, low_risk, providers:[{name,count}] }
    const cloudAssetsMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/cloud-assets(\/summary)?$/
    );
    if (cloudAssetsMatch && request.method === "GET") {
      const wsId      = cloudAssetsMatch[1];
      const isSummary = !!cloudAssetsMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get domain IDs for workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        const empty = isSummary
          ? { workspace_id: wsId, total: 0,
              by_category: { storage: 0, cdn: 0, serverless: 0, paas: 0, hosting: 0 },
              high_risk: 0, medium_risk: 0, low_risk: 0, providers: [] }
          : { workspace_id: wsId, total: 0, assets: [] };
        return json(empty);
      }

      // 2. Latest directly attributed completed scan per protected domain.
      let scanRows;
      try {
        scanRows = await loadLatestAttributedWorkspaceScans(env, wsId);
      } catch {
        return json({ error: "Database error" }, 500);
      }
      const scanIds = scanRows.map((row) => row.id);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Merge cloud_storage_discovery.findings across all reports (dedup by asset+provider)
      const seen   = new Set();
      const assets = [];

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) continue;
        let report;
        try { report = await r2.value.json(); } catch { continue; }

        const cloudMod = report?.modules?.cloud_storage_discovery;
        if (!cloudMod?.findings?.length) continue;

        for (const f of cloudMod.findings) {
          const key = `${f.asset}::${f.provider}`;
          if (seen.has(key)) continue;
          seen.add(key);
          assets.push({
            asset:        f.asset,
            provider:     f.provider,
            category:     f.category     || "storage",  // backward-compat for old reports
            service_type: f.service_type || "unknown",
            evidence:     f.evidence,
            risk_level:   f.risk_level,
            domain:       report.domain  || null,
          });
        }
      }

      // Sort: high first
      const riskOrder = { high: 0, medium: 1, low: 2 };
      assets.sort((a, b) => (riskOrder[a.risk_level] ?? 3) - (riskOrder[b.risk_level] ?? 3));

      if (isSummary) {
        const by_category = { storage: 0, cdn: 0, serverless: 0, paas: 0, hosting: 0 };
        const providerCount = {};
        let high_risk = 0, medium_risk = 0, low_risk = 0;

        for (const a of assets) {
          const cat = a.category;
          if (cat in by_category) by_category[cat]++;
          if (a.risk_level === "high")        high_risk++;
          else if (a.risk_level === "medium") medium_risk++;
          else if (a.risk_level === "low")    low_risk++;
          providerCount[a.provider] = (providerCount[a.provider] || 0) + 1;
        }

        const providers = Object.entries(providerCount)
          .map(([name, count]) => ({ name, count }))
          .sort((a, b) => b.count - a.count);

        return json({
          workspace_id: wsId,
          total: assets.length,
          by_category,
          high_risk,
          medium_risk,
          low_risk,
          providers,
        });
      }

      // Apply optional filters
      const filterCategory = url.searchParams.get("category");
      const filterProvider = url.searchParams.get("provider");
      const filterRisk     = url.searchParams.get("risk_level");

      const filtered = assets.filter((a) => {
        if (filterCategory && a.category   !== filterCategory) return false;
        if (filterProvider && a.provider   !== filterProvider) return false;
        if (filterRisk     && a.risk_level !== filterRisk)     return false;
        return true;
      });

      return json({ workspace_id: wsId, total: filtered.length, assets: filtered });
    }

    // ── Admin Surfaces route ───────────────────────────────────────────────
    // GET /api/workspaces/:id/admin-surfaces
    //   Filters: ?severity=critical|high|medium|low
    //            ?category=admin_panel|monitoring|vpn|collaboration|infrastructure|source_control
    //            ?confidence=confirmed|high|medium
    //   Returns: { workspace_id, total, critical, high, medium, services: [...] }
    //
    // Reads the admin_surface_detection module from the latest completed scan
    // R2 report for each domain in the workspace, then merges and deduplicates.
    const adminSurfacesMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/admin-surfaces$/
    );
    if (adminSurfacesMatch && request.method === "GET") {
      const wsId = adminSurfacesMatch[1];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // 1. Get all domain IDs for this workspace
      let domainIds;
      try {
        const r = await env.cybermeters_db
          .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ?")
          .bind(wsId)
          .all();
        domainIds = (r.results || []).map((row) => row.domain_id);
      } catch {
        return json({ error: "Database error" }, 500);
      }

      if (domainIds.length === 0) {
        return json({
          workspace_id: wsId,
          total: 0, critical: 0, high: 0, medium: 0, services: [],
          evidence_status: "not_assessed",   // A3: no domains → nothing assessed (not a clean zero)
        });
      }

      // 2. Latest directly attributed completed scan per protected domain.
      let scanRows;
      try {
        scanRows = await loadLatestAttributedWorkspaceScans(env, wsId);
      } catch {
        return json({ error: "Database error" }, 500);
      }
      const scanIds = scanRows.map((row) => row.id);

      // 3. Fetch R2 reports in parallel
      const r2Results = await Promise.allSettled(
        scanIds.map((sid) => env.cybermeters_reports.get(`reports/${sid}.json`))
      );

      // 4. Extract and merge admin_surface_detection.services across reports.
      // A3: track per-domain admin evidence availability so an unreadable report /
      // failed R2 / unavailable module can never present as a clean zero-admin result.
      const seen     = new Set();
      const services = [];
      let unavailableDomains = 0, notAssessedDomains = 0, healthyDomains = 0;
      // Domains with no completed scan are simply not assessed yet.
      notAssessedDomains += Math.max(0, domainIds.length - scanIds.length);

      for (const r2 of r2Results) {
        if (r2.status !== "fulfilled" || !r2.value) { unavailableDomains++; continue; }  // R2 rejected / object missing
        let report;
        try { report = await r2.value.json(); } catch { unavailableDomains++; continue; } // malformed / unreadable

        const adminMod = report?.modules?.admin_surface_detection;
        if (!adminMod?.services?.length) {
          // No services collected — classify WHY (never a silent clean zero).
          const es = adminMod?.evidence_status ?? null;
          if (es === "unavailable") unavailableDomains++;
          else if (es === "assessed_healthy") healthyDomains++;
          else notAssessedDomains++;   // not_assessed, module absent, or legacy report with no evidence_status
          continue;
        }

        for (const svc of adminMod.services) {
          const key = `${svc.hostname}::${svc.product}`;
          if (seen.has(key)) continue;
          seen.add(key);
          services.push({
            hostname:   svc.hostname,
            url:        svc.url        || `https://${svc.hostname}`,
            product:    svc.product,
            category:   svc.category,
            severity:   svc.severity   || svc.risk_level,
            confidence: svc.confidence,
            risk_level: svc.risk_level,
            // F-009 — the legacy admin-service `ip_address` is NOT projected.
            // This endpoint merges admin_surface_detection.services across the
            // workspace's reports, so it is both the CURRENT and the HISTORICAL
            // read path; stripping here covers both. Stored R2 bytes are NOT
            // rewritten — historical integrity is preserved and the field simply
            // stops being served. The frontend renders it behind a truthiness
            // check (SecurityPage.jsx), so an absent field degrades quietly.
            server:     svc.server     || null,
            title:      svc.title      || null,
            domain:     report.domain  || null,
          });
        }
      }

      // 5. Apply query-string filters
      const filterSeverity   = url.searchParams.get("severity");
      const filterCategory   = url.searchParams.get("category");
      const filterConfidence = url.searchParams.get("confidence");

      const filtered = services.filter((s) => {
        if (filterSeverity   && s.severity   !== filterSeverity)   return false;
        if (filterCategory   && s.category   !== filterCategory)   return false;
        if (filterConfidence && s.confidence !== filterConfidence)  return false;
        return true;
      });

      // Sort: confirmed+critical first
      const confOrder = { confirmed: 0, high: 1, medium: 2, low: 3 };
      const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      filtered.sort((a, b) => {
        const cd = (confOrder[a.confidence] ?? 4) - (confOrder[b.confidence] ?? 4);
        if (cd !== 0) return cd;
        return (riskOrder[a.risk_level] ?? 4) - (riskOrder[b.risk_level] ?? 4);
      });

      // A3 aggregate evidence status (additive; existing fields keep their meaning).
      // Uses the pre-filter found count so a query filter can never flip a real
      // exposure into a clean/healthy coverage state.
      let evidence_status;
      if (services.length > 0) evidence_status = "issue_detected";
      else if (unavailableDomains > 0) evidence_status = "unavailable";
      else if (healthyDomains > 0 && notAssessedDomains === 0) evidence_status = "assessed_healthy";
      else evidence_status = "not_assessed";

      return json({
        workspace_id: wsId,
        total:    filtered.length,
        critical: filtered.filter((s) => s.risk_level === "critical").length,
        high:     filtered.filter((s) => s.risk_level === "high").length,
        medium:   filtered.filter((s) => s.risk_level === "medium").length,
        services: filtered,
        evidence_status,   // A3: unavailable / not_assessed never presents as a clean total:0
      });
    }

    // ── Third-Party Asset Discovery routes ────────────────────────────────
    // GET /api/workspaces/:id/third-party-assets
    //   Filters: ?category=email|crm|support|collaboration|marketing|ecommerce
    //            ?risk_level=low|medium|high
    //   Returns: { workspace_id, total, assets: [...] }
    //
    // GET /api/workspaces/:id/third-party-assets/summary
    //   Returns: { workspace_id, total, email, crm, support, collaboration,
    //              marketing, ecommerce, high_risk, medium_risk, low_risk }
    const tpaMatch = url.pathname.match(
      /^\/api\/workspaces\/([^/]+)\/third-party-assets(\/summary)?$/
    );
    if (tpaMatch && request.method === "GET") {
      const wsId      = tpaMatch[1];
      const isSummary = !!tpaMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      // Read all workspace_vendors for this workspace; remap + filter in JS.
      // workspace_vendors uses the vendor-risk category taxonomy; we remap here.
      let rows;
      try {
        const r = await env.cybermeters_db
          .prepare(
            `SELECT vendor_name, category, source, evidence, confidence,
                    risk_level, status, first_seen, last_seen
             FROM workspace_vendors
             WHERE workspace_id = ? AND status = 'active'`
          )
          .bind(wsId)
          .all();
        rows = r.results || [];
      } catch {
        return json({ error: "Database error" }, 500);
      }

      // Remap to third-party taxonomy; skip infrastructure/cloud/hosting
      const assets = [];
      for (const row of rows) {
        const tpCategory = remapToThirdPartyCategory(row.vendor_name, row.category);
        if (!tpCategory) continue;

        let parsedEvidence = [];
        try { parsedEvidence = JSON.parse(row.evidence); } catch { /* ignore */ }

        assets.push({
          name:       row.vendor_name,
          category:   tpCategory,
          source:     row.source,
          evidence:   parsedEvidence,
          confidence: row.confidence,
          risk_level: row.risk_level,
          first_seen: row.first_seen,
          last_seen:  row.last_seen,
        });
      }

      // Sort: email → crm → collaboration → support → marketing → ecommerce
      const catOrder = {
        email: 0, crm: 1, collaboration: 2, support: 3, marketing: 4, ecommerce: 5,
      };
      assets.sort((a, b) => (catOrder[a.category] ?? 9) - (catOrder[b.category] ?? 9));

      if (isSummary) {
        const summary = {
          workspace_id:  wsId,
          total:         assets.length,
          email:         0,
          crm:           0,
          support:       0,
          collaboration: 0,
          marketing:     0,
          ecommerce:     0,
          high_risk:     0,
          medium_risk:   0,
          low_risk:      0,
        };
        for (const a of assets) {
          if (a.category in summary) summary[a.category]++;
          if (a.risk_level === "high")        summary.high_risk++;
          else if (a.risk_level === "medium") summary.medium_risk++;
          else if (a.risk_level === "low")    summary.low_risk++;
        }
        return json(summary);
      }

      // Apply optional filters from query string
      const filterCategory = url.searchParams.get("category");
      const filterRisk     = url.searchParams.get("risk_level");
      const filtered = assets.filter((a) => {
        if (filterCategory && a.category !== filterCategory) return false;
        if (filterRisk     && a.risk_level !== filterRisk)   return false;
        return true;
      });

      return json({ workspace_id: wsId, total: filtered.length, assets: filtered });
    }

    // ── Vendor Inventory routes ────────────────────────────────────────────
    // GET /api/workspaces/:id/vendors
    //   Filters: ?status=active|inactive  ?risk_level=low|medium|high
    //            ?category=infrastructure|cloud|email_identity|hosting|saas|
    //                      support|collaboration|ecommerce|certificate_authority
    //   Returns: { workspace_id, count, vendors: [...] }
    //
    // GET /api/workspaces/:id/vendors/summary
    //   Returns: { total_vendors, active_vendors, inactive_vendors,
    //              infrastructure, cloud, email_identity, hosting, saas,
    //              support, ecommerce, certificate_authority,
    //              high_risk, medium_risk, low_risk }
    const vendorsMatch = url.pathname.match(/^\/api\/workspaces\/([^/]+)\/vendors(\/summary)?$/);
    if (vendorsMatch && request.method === "GET") {
      const wsId      = vendorsMatch[1];
      const isSummary = !!vendorsMatch[2];

      const user = await requireAuth(request, env);
      if (!user) return json({ error: "Unauthorized" }, 401);
      const access = await requireWorkspaceRole(user, wsId, "workspace:read", env);
      if (!access) return json({ error: "Forbidden" }, 403);

      if (isSummary) {
        // Aggregate counts directly from D1 — one query
        let rows;
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT status, category, risk_level, COUNT(*) AS cnt
               FROM workspace_vendors
               WHERE workspace_id = ?
               GROUP BY status, category, risk_level`
            )
            .bind(wsId)
            .all();
          rows = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        const summary = {
          workspace_id:    wsId,
          total_vendors:   0,
          active_vendors:  0,
          inactive_vendors:0,
          infrastructure:  0,
          cloud:           0,
          email_identity:  0,
          hosting:         0,
          saas:            0,
          support:         0,
          ecommerce:       0,
          certificate_authority: 0,
          // vendor_relationship categories (Phase 7k)
          analytics:       0,
          payments:        0,
          crm:             0,
          identity:        0,
          collaboration:   0,
          cdn:             0,
          security:        0,
          // identity cross-population (Phase 8f)
          identity_provider: 0,
          high_risk:       0,
          medium_risk:     0,
          low_risk:        0,
        };

        // We need unique vendor counts, not row counts (a vendor appears once).
        // First collect unique vendor names per bucket using a Set approach via JS.
        // Re-query for unique vendor names with their attributes.
        let vendorRows;
        try {
          const r2 = await env.cybermeters_db
            .prepare(
              `SELECT vendor_name, category, risk_level, status
               FROM workspace_vendors
               WHERE workspace_id = ?`
            )
            .bind(wsId)
            .all();
          vendorRows = r2.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }

        for (const v of vendorRows) {
          summary.total_vendors++;
          if (v.status === "active")   summary.active_vendors++;
          else                         summary.inactive_vendors++;
          const cat = v.category;
          if (cat in summary) summary[cat]++;
          const rl = v.risk_level;
          if (rl === "high")   summary.high_risk++;
          else if (rl === "medium") summary.medium_risk++;
          else if (rl === "low")    summary.low_risk++;
        }

        // Backward-compatible aliases used by the current frontend.
        summary.active = summary.active_vendors;
        summary.by_risk = {
          high: summary.high_risk,
          medium: summary.medium_risk,
          low: summary.low_risk,
        };

        return json(summary);
      }

      // ── GET /api/workspaces/:id/vendors ──
      const params    = url.searchParams;
      const filterStatus   = params.get("status");
      const filterRisk     = params.get("risk_level");
      const filterCategory = params.get("category");

      // Build WHERE clause dynamically
      const whereClauses = ["workspace_id = ?"];
      const binds        = [wsId];

      if (filterStatus)   { whereClauses.push("status = ?");     binds.push(filterStatus); }
      if (filterRisk)     { whereClauses.push("risk_level = ?"); binds.push(filterRisk); }
      if (filterCategory) { whereClauses.push("category = ?");   binds.push(filterCategory); }

      const whereSQL = whereClauses.join(" AND ");
      const scoredWhereSQL = whereSQL
        .replace(/\bworkspace_id\b/g, "wv.workspace_id")
        .replace(/\bstatus\b/g, "wv.status")
        .replace(/\brisk_level\b/g, "wv.risk_level")
        .replace(/\bcategory\b/g, "wv.category");

      let vendorRows;
      try {
        const r = await env.cybermeters_db
          .prepare(
            `SELECT wv.id, wv.vendor_name, wv.vendor_name AS name, wv.category,
                    wv.source, wv.evidence, wv.confidence,
                    wv.risk_level, wv.status, wv.first_seen, wv.last_seen,
                    wv.metadata_json,
                    vrs.score AS persisted_score,
                    vrs.category_multiplier,
                    vrs.concentration_penalty
             FROM workspace_vendors wv
             LEFT JOIN vendor_risk_scores vrs
               ON vrs.vendor_id = wv.id
              AND vrs.workspace_id = wv.workspace_id
             WHERE ${scoredWhereSQL}
             ORDER BY
               COALESCE(vrs.score, 0) DESC,
               CASE wv.risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
               wv.vendor_name`
          )
          .bind(...binds)
          .all();
        vendorRows = r.results || [];
      } catch {
        try {
          const r = await env.cybermeters_db
            .prepare(
              `SELECT id, vendor_name, vendor_name AS name, category, source,
                      evidence, confidence, risk_level, status, first_seen,
                      last_seen, metadata_json
               FROM workspace_vendors
               WHERE ${whereSQL}
               ORDER BY
                 CASE risk_level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END,
                 vendor_name`
            )
            .bind(...binds)
            .all();
          vendorRows = r.results || [];
        } catch {
          return json({ error: "Database error" }, 500);
        }
      }

      const aggregate = computeWorkspaceVendorRisk(vendorRows);
      const vendors = aggregate.scored_vendors
        .slice()
        .sort((a, b) => b.score - a.score || String(a.vendor_name || a.name).localeCompare(String(b.vendor_name || b.name)))
        .map((row) => {
        const evidence = (() => { try { return JSON.parse(row.evidence); } catch { return []; } })();
        const sources = [...new Set([...(row._sources || []), ...getVendorSources(row)].filter(Boolean))];
        return {
          id: row.id,
          name: row.name || row.vendor_name,
          vendor_name: row.name || row.vendor_name,
          vendor_key: row.vendor_key || normalizeVendorKey(row.name || row.vendor_name),
          category: row.normalized_category || normalizeVendorRiskCategory(row.category, row.name || row.vendor_name, row.source),
          normalized_category: row.normalized_category || normalizeVendorRiskCategory(row.category, row.name || row.vendor_name, row.source),
          raw_category: row.category,
          source: row.source,
          sources,
          confidence: row.confidence,
          confidence_score: row.confidence_score ?? confidenceToScore(row.confidence),
          signal_weight: row.signal_weight ?? signalWeightForVendor(row),
          score: row.score ?? row.persisted_score ?? 0,
          category_multiplier: row.category_multiplier ?? 1,
          concentration_penalty: row.concentration_penalty ?? 0,
          risk_level: row.risk_level,
          status: row.status,
          first_seen: row.first_seen,
          last_seen: row.last_seen,
          evidence,
          metadata: (() => { try { return JSON.parse(row.metadata_json || "{}"); } catch { return {}; } })(),
        };
      });

      return json({
        workspace_id: wsId,
        count: vendors.length,
        vendors,
        top_vendors: aggregate.top_vendors.map((v) => ({
          id: v.id,
          name: v.vendor_name,
          vendor_key: v.vendor_key,
          category: v.normalized_category,
          score: v.score,
          risk_level: v.risk_level,
        })),
        concentration_risk: aggregate.concentration_risk,
        workspace_vendor_risk_score: aggregate.workspace_vendor_risk_score,
      });
    }


  return null;
}
