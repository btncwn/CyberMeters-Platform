// ── Item 10 P2: production Attack Surface observation persistence ────────────
//
// The six-state signal record and the asset lifecycle projection are separate
// from workspace_assets.status. The latter remains a backward-compatible
// active|inactive projection and is changed only at a confirmed transition.
import {
  applyAssetRemovalConfirmation,
  ASSET_REMOVAL_CONFIRMATION_POLICY,
  ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
  ATTACK_SURFACE_SIGNAL_KEYS,
} from "./attack-surface-signal-completeness.js";
import { normalizeHostname } from "./hostnames.js";
import { createId } from "../lib/util.js";
import { hashToken } from "../lib/auth-crypto.js";
import {
  compareLifecycleObservationOrder,
  isDecisionRelevantLifecycleObservation,
  lifecycleTimestampValiditySql,
  normalizeLifecycleTimestamp,
} from "./asset-lifecycle-event-support.js";
import { normalizeBoundedCoverageState } from "./bounded-coverage.js";

const MAX_RECHECK_HOSTS = 50;

function safeJson(value, fallback) {
  try {
    return JSON.stringify(value ?? fallback);
  } catch {
    return JSON.stringify(fallback);
  }
}

function scopedHostname(hostname, root) {
  const host = normalizeHostname(hostname);
  return host && (host === root || host.endsWith(`.${root}`)) ? host : "";
}

// One bounded read per scan, never one read per asset. Soft-deleted workspaces
// are excluded before a hostname can become an outbound probe target.
export async function loadKnownAssetRecheckHosts(env, domainId, domain) {
  const root = normalizeHostname(domain);
  if (!root || !env?.cybermeters_db) return [];
  try {
    const result = await env.cybermeters_db
      .prepare(
        `SELECT DISTINCT wa.hostname
         FROM workspace_assets wa
         JOIN workspace_domains wd
           ON wd.workspace_id = wa.workspace_id AND wd.domain_id = ?
         JOIN workspaces w
           ON w.id = wa.workspace_id AND w.deleted_at IS NULL
         WHERE wa.hostname LIKE ? AND wa.hostname <> ?
         ORDER BY wa.hostname
         LIMIT ?`
      )
      .bind(domainId, `%.${root}`, root, MAX_RECHECK_HOSTS)
      .all();
    return (result.results || [])
      .map((row) => scopedHostname(row.hostname, root))
      .filter(Boolean);
  } catch (error) {
    console.error("[attack-surface-lifecycle] recheck target load failed:", error?.message);
    return [];
  }
}

function groupHistoricalObservations(rows) {
  const relevantByAsset = new Map();
  const byAsset = new Map();
  const seenScan = new Set();
  const invalidAssetIds = new Set();
  for (const row of rows || []) {
    if (Number(row?.invalid_relevant_timestamp) === 1) {
      invalidAssetIds.add(row.asset_id);
      continue;
    }
    if (!isDecisionRelevantLifecycleObservation(row)) continue;
    const observedAt = normalizeLifecycleTimestamp(row.observed_at);
    const createdAt = normalizeLifecycleTimestamp(row.created_at);
    if (!observedAt.valid || !createdAt.valid) {
      invalidAssetIds.add(row.asset_id);
      continue;
    }
    if (!relevantByAsset.has(row.asset_id)) relevantByAsset.set(row.asset_id, []);
    // The transition helper accepts canonical UTC instants only. Normalise the
    // producer's SQLite UTC-space created/observed timestamps before replay so
    // no unqualified timestamp can acquire a Worker-local timezone meaning.
    relevantByAsset.get(row.asset_id).push({
      ...row,
      observed_at: observedAt.canonical_utc,
      created_at: createdAt.canonical_utc,
    });
  }
  for (const [assetId, assetRows] of relevantByAsset) {
    const current = [];
    byAsset.set(assetId, current);
    for (const row of assetRows.sort(compareLifecycleObservationOrder)) {
      seenScan.add(`${row.asset_id}:${row.scan_id}`);
      if (row.observation_state === "observed") {
        current.length = 0;
      } else if (row.qualifies_removal === 1) {
        current.push({ scan_id: row.scan_id, observed_at: row.observed_at });
      }
    }
  }
  return { byAsset, seenScan, invalidAssetIds };
}

export function notAssessedSignals() {
  return {
    dns_resolution: { state: "not_assessed", reason: "asset_not_in_active_recheck_envelope" },
    http_https_service: { state: "not_assessed", reason: "asset_not_in_active_recheck_envelope" },
  };
}

function normalizeRemovalObservation(row) {
  return {
    signal_states: {
      dns_resolution: row?.signal_states?.dns_resolution || notAssessedSignals().dns_resolution,
      http_https_service: row?.signal_states?.http_https_service || notAssessedSignals().http_https_service,
    },
    active_sources: ["dns_resolution", "http_https_service"],
    passive_sources: [],
  };
}

export function ctDiscoveryScopeSignals(asset, subdomainDiscovery) {
  if (asset?.source !== "certificate_transparency") return null;

  // Follow the subdomain module's explicit scope carrier. Do not independently
  // reinterpret one provider error as blindness: the producer owns that policy.
  // When it declares CT scope incomplete, active probes cannot advance OR reset
  // the lifecycle of an identity that entered the inventory through CT.
  const state = !subdomainDiscovery || subdomainDiscovery.executed === false
    ? "not_assessed"
    : subdomainDiscovery.incomplete === true
      ? "incomplete"
      : normalizeBoundedCoverageState(
          subdomainDiscovery.discovery_coverage?.coverage_state,
        ) === "bounded"
        ? "not_assessed"
        : null;
  if (!state) return null;

  const bounded = Boolean(subdomainDiscovery) &&
    subdomainDiscovery.executed !== false &&
    subdomainDiscovery.incomplete !== true &&
    normalizeBoundedCoverageState(
      subdomainDiscovery.discovery_coverage?.coverage_state,
    ) === "bounded";
  const reason = subdomainDiscovery?.incomplete_reason ||
    (bounded ? "bounded_ct_discovery_scope" : null) ||
    (state === "not_assessed"
      ? "discovery_not_evaluated"
      : "discovery_sources_incomplete");
  return {
    dns_resolution: { state, reason },
    http_https_service: { state, reason },
  };
}

function projectionStatus(lifecycleResult, legacyStatus) {
  if (lifecycleResult.transition === "confirmed_removed") return "inactive";
  if (lifecycleResult.last_observation_state === "observed") return "active";
  return legacyStatus;
}

async function deterministicAssetEventId(workspaceId, assetId, scanId, eventType) {
  const digest = await hashToken(JSON.stringify([
    "attack-surface-asset-lifecycle-event-v1",
    workspaceId,
    assetId,
    scanId,
    eventType,
  ]));
  return `evt-${digest.slice(0, 32)}`;
}

// Writes all global signal rows and all per-asset rows for one workspace in one
// D1 batch. Reads are bounded per workspace, not per asset; each scan/asset pair
// is idempotent through a real UNIQUE constraint.
export async function persistAttackSurfaceLifecycle({
  env,
  scanId,
  domainId,
  domain,
  signalCompleteness,
  assetExposure,
  subdomainDiscovery,
  observedAt,
}) {
  if (!env?.cybermeters_db || !scanId || !domainId || !signalCompleteness) return;
  const root = normalizeHostname(domain);
  const timestampInput = observedAt == null
    ? new Date().toISOString()
    : observedAt instanceof Date && Number.isFinite(observedAt.getTime())
      ? observedAt.toISOString()
      : observedAt;
  const normalizedNow = normalizeLifecycleTimestamp(timestampInput);
  if (!normalizedNow.valid) {
    return {
      status: "uncertain",
      limitation_codes: ["invalid_relevant_timestamp"],
      uncertain_asset_ids: null,
    };
  }
  const now = normalizedNow.canonical_utc;
  const uncertainAssetIds = new Set();

  const workspaceResult = await env.cybermeters_db
    .prepare(
      `SELECT wd.workspace_id
       FROM workspace_domains wd
       JOIN workspaces w ON w.id = wd.workspace_id
       WHERE wd.domain_id = ? AND w.deleted_at IS NULL`
    )
    .bind(domainId)
    .all();

  const observationByHost = new Map(
    (assetExposure?.removal_observations || [])
      .map((row) => [scopedHostname(row.host, root), row])
      .filter(([hostname]) => Boolean(hostname)),
  );

  for (const { workspace_id: workspaceId } of workspaceResult.results || []) {
    const [assetResult, historyResult] = await env.cybermeters_db.batch([
      env.cybermeters_db
        .prepare(
          `SELECT id, hostname, source, status, lifecycle_state, last_observation_state,
                  lifecycle_policy_version, confirmed_removed_at
           FROM workspace_assets
           WHERE workspace_id = ?
             AND (domain_id = ? OR hostname = ? OR hostname LIKE ?)
           ORDER BY hostname`
        )
        .bind(workspaceId, domainId, root, `%.${root}`),
      env.cybermeters_db
        .prepare(
          `WITH scoped_history AS (
             SELECT alo.asset_id, alo.scan_id, alo.observation_state,
                    alo.qualifies_removal, alo.observed_at, alo.created_at
             FROM asset_lifecycle_observations alo
             JOIN workspace_assets wa
               ON wa.id = alo.asset_id AND wa.workspace_id = alo.workspace_id
             WHERE alo.workspace_id = ?
               AND (wa.domain_id = ? OR wa.hostname = ? OR wa.hostname LIKE ?)
               AND (
                 alo.qualifies_removal = 1 OR
                 alo.observation_state = 'observed'
               )
           ), invalid_relevant AS (
             SELECT alo.asset_id,
                    NULL AS scan_id,
                    NULL AS observation_state,
                    0 AS qualifies_removal,
                    NULL AS observed_at,
                    NULL AS created_at,
                    1 AS invalid_relevant_timestamp,
                    0 AS recency_rank
             FROM scoped_history alo
             WHERE NOT (${lifecycleTimestampValiditySql("alo.observed_at")})
                OR NOT (${lifecycleTimestampValiditySql("alo.created_at")})
             GROUP BY alo.asset_id
           ), ranked_valid AS (
             SELECT alo.asset_id, alo.scan_id, alo.observation_state,
                    alo.qualifies_removal, alo.observed_at, alo.created_at,
                    0 AS invalid_relevant_timestamp,
                    ROW_NUMBER() OVER (
                      PARTITION BY alo.asset_id
                      ORDER BY julianday(alo.observed_at) DESC,
                               julianday(alo.created_at) DESC,
                               alo.scan_id COLLATE BINARY DESC
                    ) AS recency_rank
             FROM scoped_history alo
             WHERE ${lifecycleTimestampValiditySql("alo.observed_at")}
               AND ${lifecycleTimestampValiditySql("alo.created_at")}
           )
           SELECT * FROM (
             SELECT asset_id, scan_id, observation_state, qualifies_removal,
                    observed_at, created_at, invalid_relevant_timestamp, recency_rank
             FROM invalid_relevant
             UNION ALL
             SELECT asset_id, scan_id, observation_state, qualifies_removal,
                    observed_at, created_at, invalid_relevant_timestamp, recency_rank
             FROM ranked_valid
             WHERE recency_rank <= 4
           ) ordered_history
           ORDER BY asset_id,
                    invalid_relevant_timestamp DESC,
                    julianday(observed_at),
                    julianday(created_at),
                    scan_id COLLATE BINARY`
        )
        .bind(workspaceId, domainId, root, `%.${root}`),
    ]);

    const { byAsset, seenScan, invalidAssetIds } = groupHistoricalObservations(
      historyResult.results || [],
    );
    for (const assetId of invalidAssetIds) uncertainAssetIds.add(assetId);
    const statements = [];

    for (const signalKey of ATTACK_SURFACE_SIGNAL_KEYS) {
      const value = signalCompleteness.signals?.[signalKey];
      if (!value) continue;
      statements.push(
        env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO attack_surface_signal_observations
               (id, workspace_id, domain_id, scan_id, signal_key, state,
                reason, evidence_count, sources_json, limitations_json,
                model_version, observed_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
          )
          .bind(
            createId("asso"), workspaceId, domainId, scanId, signalKey,
            value.state, value.reason || null, value.evidence_count || 0,
            safeJson(value.sources, []), safeJson(value.limitations, []),
            signalCompleteness.model_version || ATTACK_SURFACE_SIGNAL_COMPLETENESS_VERSION,
            now,
          )
      );
    }

    for (const asset of assetResult.results || []) {
      if (invalidAssetIds.has(asset.id)) continue;
      if (seenScan.has(`${asset.id}:${scanId}`)) continue;
      const scopeSignals = ctDiscoveryScopeSignals(asset, subdomainDiscovery);
      const evidence = normalizeRemovalObservation(
        scopeSignals
          ? { signal_states: scopeSignals }
          : normalizeHostname(asset.hostname) === root
            ? null
            : observationByHost.get(normalizeHostname(asset.hostname)),
      );
      const previousRows = byAsset.get(asset.id) || [];
      const result = applyAssetRemovalConfirmation(
        {
          lifecycle_state: asset.lifecycle_state,
          qualifying_observations: previousRows,
          confirmed_removed_at: asset.confirmed_removed_at,
        },
        {
          scan_id: scanId,
          observed_at: now,
          signal_states: evidence.signal_states,
        },
      );
      const acceptedQualifying =
        result.last_observation_state === "not_observed" &&
        result.qualifying_observations.length > previousRows.length;

      statements.push(
        env.cybermeters_db
          .prepare(
            `INSERT OR IGNORE INTO asset_lifecycle_observations
               (id, workspace_id, domain_id, asset_id, scan_id,
                observation_state, dns_state, http_state, qualifies_removal,
                policy_version, source_detail_json, observed_at)
             VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`
          )
          .bind(
            createId("alo"), workspaceId, domainId, asset.id, scanId,
            result.last_observation_state,
            evidence.signal_states.dns_resolution.state,
            evidence.signal_states.http_https_service.state,
            acceptedQualifying ? 1 : 0,
            ASSET_REMOVAL_CONFIRMATION_POLICY.version,
            safeJson({
              dns_resolution: evidence.signal_states.dns_resolution,
              http_https_service: evidence.signal_states.http_https_service,
              active_sources: evidence.active_sources,
              passive_sources: [],
            }, {}),
            now,
          )
      );
      statements.push(
        env.cybermeters_db
          .prepare(
            `UPDATE workspace_assets
             SET lifecycle_state = ?, last_observation_state = ?,
                 lifecycle_policy_version = ?, confirmed_removed_at = ?,
                 last_observation_scan_id = ?, status = ?, updated_at = ?
             WHERE id = ? AND workspace_id = ?`
          )
          .bind(
            result.lifecycle_state,
            result.last_observation_state,
            result.policy_version,
            result.confirmed_removed_at,
            scanId,
            projectionStatus(result, asset.status),
            now,
            asset.id,
            workspaceId,
          )
      );

      if (result.transition === "confirmed_removed") {
        const eventId = await deterministicAssetEventId(
          workspaceId, asset.id, scanId, "asset_no_longer_seen",
        );
        statements.push(
          env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO asset_events
                 (id, workspace_id, domain_id, asset_id, scan_id,
                  event_type, hostname, severity, description, created_at)
               VALUES (?,?,?,?,?,'asset_no_longer_seen',?,'low',?,?)`
            )
            .bind(
              eventId, workspaceId, domainId, asset.id, scanId,
              asset.hostname,
              `Asset no longer seen in latest scan: ${asset.hostname}`,
              now,
            )
        );
      } else if (result.transition === "reappeared") {
        const eventId = await deterministicAssetEventId(
          workspaceId, asset.id, scanId, "asset_reappeared",
        );
        statements.push(
          env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO asset_events
                 (id, workspace_id, domain_id, asset_id, scan_id,
                  event_type, hostname, severity, description, created_at)
               VALUES (?,?,?,?,?,'asset_reappeared',?,'medium',?,?)`
            )
            .bind(
              eventId, workspaceId, domainId, asset.id, scanId,
              asset.hostname,
              `Asset reappeared after being absent: ${asset.hostname}`,
              now,
            )
        );
      }
    }

    if (statements.length > 0) await env.cybermeters_db.batch(statements);
  }
  return {
    status: uncertainAssetIds.size > 0 ? "uncertain" : "complete",
    limitation_codes: uncertainAssetIds.size > 0 ? ["invalid_relevant_timestamp"] : [],
    uncertain_asset_ids: [...uncertainAssetIds].sort(),
  };
}
