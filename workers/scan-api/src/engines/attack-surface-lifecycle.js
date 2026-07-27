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
  const byAsset = new Map();
  const seenScan = new Set();
  for (const row of rows || []) {
    const key = `${row.asset_id}:${row.scan_id}`;
    seenScan.add(key);
    let current = byAsset.get(row.asset_id);
    if (!current) {
      current = [];
      byAsset.set(row.asset_id, current);
    }
    if (row.observation_state === "observed") {
      current.length = 0;
    } else if (row.qualifies_removal === 1) {
      current.push({ scan_id: row.scan_id, observed_at: row.observed_at });
    }
  }
  return { byAsset, seenScan };
}

function notAssessedSignals() {
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

function projectionStatus(lifecycleResult, legacyStatus) {
  if (lifecycleResult.transition === "confirmed_removed") return "inactive";
  if (lifecycleResult.last_observation_state === "observed") return "active";
  return legacyStatus;
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
  observedAt,
}) {
  if (!env?.cybermeters_db || !scanId || !domainId || !signalCompleteness) return;
  const root = normalizeHostname(domain);
  const now = new Date(observedAt || Date.now()).toISOString();

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
          `SELECT id, hostname, status, lifecycle_state, last_observation_state,
                  lifecycle_policy_version, confirmed_removed_at
           FROM workspace_assets
           WHERE workspace_id = ?
             AND (domain_id = ? OR hostname = ? OR hostname LIKE ?)
           ORDER BY hostname`
        )
        .bind(workspaceId, domainId, root, `%.${root}`),
      env.cybermeters_db
        .prepare(
          `SELECT asset_id, scan_id, observation_state,
                  qualifies_removal, observed_at
           FROM (
             SELECT alo.asset_id, alo.scan_id, alo.observation_state,
                    alo.qualifies_removal, alo.observed_at, alo.created_at,
                    ROW_NUMBER() OVER (
                      PARTITION BY alo.asset_id
                      ORDER BY alo.observed_at DESC, alo.created_at DESC
                    ) AS recency_rank
             FROM asset_lifecycle_observations alo
             JOIN workspace_assets wa
               ON wa.id = alo.asset_id AND wa.workspace_id = alo.workspace_id
             WHERE alo.workspace_id = ?
               AND (wa.domain_id = ? OR wa.hostname = ? OR wa.hostname LIKE ?)
               AND (
                 alo.qualifies_removal = 1 OR
                 alo.observation_state = 'observed'
               )
           )
           WHERE recency_rank <= 4
           ORDER BY asset_id, observed_at, created_at`
        )
        .bind(workspaceId, domainId, root, `%.${root}`),
    ]);

    const { byAsset, seenScan } = groupHistoricalObservations(historyResult.results || []);
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
      if (seenScan.has(`${asset.id}:${scanId}`)) continue;
      const evidence = normalizeRemovalObservation(
        normalizeHostname(asset.hostname) === root
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
        statements.push(
          env.cybermeters_db
            .prepare(
              `INSERT INTO asset_events
                 (id, workspace_id, domain_id, asset_id, scan_id,
                  event_type, hostname, severity, description, created_at)
               VALUES (?,?,?,?,?,'asset_no_longer_seen',?,'low',?,?)`
            )
            .bind(
              createId("evt"), workspaceId, domainId, asset.id, scanId,
              asset.hostname,
              `Asset no longer seen in latest scan: ${asset.hostname}`,
              now,
            )
        );
      } else if (result.transition === "reappeared") {
        statements.push(
          env.cybermeters_db
            .prepare(
              `INSERT INTO asset_events
                 (id, workspace_id, domain_id, asset_id, scan_id,
                  event_type, hostname, severity, description, created_at)
               VALUES (?,?,?,?,?,'asset_reappeared',?,'medium',?,?)`
            )
            .bind(
              createId("evt"), workspaceId, domainId, asset.id, scanId,
              asset.hostname,
              `Asset reappeared after being absent: ${asset.hostname}`,
              now,
            )
        );
      }
    }

    if (statements.length > 0) await env.cybermeters_db.batch(statements);
  }
}
