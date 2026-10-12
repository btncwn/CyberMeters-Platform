// ── Asset inventory upsert ──
// Persists the discovered asset inventory to D1 (diff vs prior state, asset events, alias
// consolidation, per-asset probe metadata). Extracted verbatim from index.js (monolith
// decomposition, Phase 1c).
import { buildAssetInventoryMetadata, consolidateInventoryAssetAliases, probeAsset } from "./asset-intel.js";
import { normalizeHostname } from "./hostnames.js";
import { createId } from "../lib/util.js";
import { loadTimelineComparisonContext } from "./timeline-trust.js";

function normalizeInventoryValue(value) {
  return String(value ?? "").trim();
}

function normalizeIpAddressList(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item ?? "").trim()).filter(Boolean).sort().join(", ");
  }
  const raw = normalizeInventoryValue(value);
  if (!raw) return "";
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed.map((item) => String(item ?? "").trim()).filter(Boolean).sort().join(", ");
    }
  } catch {
    // Fall back to the legacy comma-separated representation below.
  }
  return raw.split(",").map((item) => item.trim()).filter(Boolean).sort().join(", ");
}

function hostnameFromRedirectTarget(value) {
  const raw = normalizeInventoryValue(value);
  if (!raw) return "";
  try {
    return normalizeHostname(new URL(raw).hostname);
  } catch {
    try {
      return normalizeHostname(new URL(`https://${raw}`).hostname);
    } catch {
      return normalizeHostname(raw);
    }
  }
}

function isExternalRedirectTarget(value, domain) {
  const targetHost = hostnameFromRedirectTarget(value);
  const rootHost = normalizeHostname(domain);
  if (!targetHost || !rootHost) return false;
  return targetHost !== rootHost && !targetHost.endsWith(`.${rootHost}`);
}

// ── Asset Inventory Upsert ────────────────────────────────────────────────────
// Persists cross-scan asset state into workspace_assets + asset_events.
// Called AFTER the scan completion status is written to D1 so a upsert failure
// can never leave a scan stuck in "running".
//
// One domain can belong to multiple workspaces — we upsert into each.
// Uses D1 batch() to minimise round-trips.

export async function upsertAssetInventory(scanId, domainId, domain, modules, env, opts = {}) {
  const now = new Date(opts.observedAt || Date.now()).toISOString();
  const comparison = await loadTimelineComparisonContext(env, {
    scanId,
    domainId,
    currentReport: opts.currentReport,
  }).catch(() => ({ comparable: false, comparison_status: "unavailable" }));
  const canEmitTimelineEvents = comparison.comparable === true;

  // ── Collect all discovered hostnames from this scan ───────────────────────
  const wildcardDns = modules?.subdomains?.wildcard_dns === true;

  const allAssets = [];

  // Root domain is always an asset, even if discovery finds nothing.
  // This prevents inventory from staying empty for domains with no discovered subdomains.
  const _rootHost = normalizeHostname(domain);
  if (_rootHost) allAssets.push({
    hostname:   _rootHost,
    asset_type: "root_domain",
    source:     "scan_root",
    wildcard:   0,
    risk_level: null,
    cloud:      null,
  });

  // DNS brute-force
  for (const item of modules?.dns_bruteforce?.items || []) {
    const h = normalizeHostname(item.hostname);
    if (!h) continue;
    allAssets.push({
      hostname:     h,
      asset_type:   "subdomain",
      source:       item.mail_only ? "dns_mx" : "dns_bruteforce",
      wildcard:     item.wildcard_match ? 1 : 0,
      risk_level:   null,
      cloud:        null,
      ip_addresses: JSON.stringify(item.ip_addresses || []),
    });
  }

  // First-party references: SRV record targets and hosts the home page links
  // to. A name already found above keeps its earlier source (dedupe below).
  for (const item of modules?.dns_bruteforce?.srv_items || []) {
    const h = normalizeHostname(item?.hostname);
    if (!h) continue;
    allAssets.push({
      hostname:   h,
      asset_type: "subdomain",
      source:     "dns_srv",
      wildcard:   0,
      risk_level: null,
      cloud:      null,
    });
  }
  for (const hostname of modules?.technology_detection?.linked_hostnames || []) {
    const h = normalizeHostname(hostname);
    if (!h) continue;
    allAssets.push({
      hostname:   h,
      asset_type: "subdomain",
      source:     "html_link",
      wildcard:   0,
      risk_level: null,
      cloud:      null,
    });
  }
  // Names the customer's own configuration points at, confirmed by DNS. Each
  // keeps the most specific place it was named (certificate, MX/NS, SPF…).
  for (const item of modules?.subdomains?.referenced_hostnames?.confirmed || []) {
    const h = normalizeHostname(item?.hostname);
    if (!h || typeof item?.asset_source !== "string") continue;
    allAssets.push({
      hostname:     h,
      asset_type:   "subdomain",
      source:       item.asset_source,
      wildcard:     item.wildcard_match ? 1 : 0,
      risk_level:   null,
      cloud:        null,
      ip_addresses: JSON.stringify(Array.isArray(item.ip_addresses) ? item.ip_addresses : []),
    });
  }
  // Deeper DNS discovery: the rotating word list, name variants and names the
  // zone's NSEC records list, each confirmed by DNS.
  for (const item of modules?.subdomains?.discovery_depth?.confirmed || []) {
    const h = normalizeHostname(item?.hostname);
    if (!h || typeof item?.source !== "string") continue;
    allAssets.push({
      hostname:     h,
      asset_type:   "subdomain",
      source:       item.source,
      wildcard:     item.wildcard_match ? 1 : 0,
      risk_level:   null,
      cloud:        null,
      ip_addresses: JSON.stringify(Array.isArray(item.ip_addresses) ? item.ip_addresses : []),
    });
  }
  // The merged discovery set (modules.subdomains.items) also carries names the
  // critical-prefix DNS checks found. It comes last so a more specific source
  // above keeps precedence in the dedupe below.
  for (const hostname of modules?.subdomains?.items || []) {
    const h = normalizeHostname(hostname);
    if (!h) continue;
    allAssets.push({
      hostname:   h,
      asset_type: "subdomain",
      source:     "dns_discovery",
      wildcard:   wildcardDns ? 1 : 0,
      risk_level: null,
      cloud:      null,
    });
  }

  // Cloud storage findings
  for (const finding of modules?.cloud_storage_discovery?.findings || []) {
    const h = normalizeHostname(finding.asset);
    if (!h) continue;
    const existing = allAssets.find((a) => a.hostname === h);
    if (existing) {
      existing.asset_type = "cloud_storage";
      existing.source     = "cloud_storage_discovery";
      existing.cloud      = finding.provider;
      existing.risk_level = finding.risk_level;
    } else {
      allAssets.push({
        hostname:   h,
        asset_type: "cloud_storage",
        source:     "cloud_storage_discovery",
        wildcard:   0,
        cloud:      finding.provider,
        risk_level: finding.risk_level,
      });
    }
  }

  // Exposure-probed assets
  // probeAsset() returns { host, url, ... } — use .host (the probe target) as the
  // canonical key.  .url is the post-redirect URL and may resolve to a *different*
  // hostname (e.g. probing blackbullbarbers.co.uk → redirect → www.blackbullbarbers.co.uk).
  // Falling back to .url would create spurious separate asset rows for the same host.
  for (const asset of modules?.asset_exposure?.assets || []) {
    const h = normalizeHostname(asset.host || asset.hostname || asset.url);
    if (!h) continue;
    const existing = allAssets.find((a) => a.hostname === h);
    if (existing) {
      existing.ip_addresses = existing.ip_addresses ?? JSON.stringify(asset.ip ? [asset.ip] : []);
      existing.cname        = existing.cname ?? asset.cname ?? null;
      existing.redirect_to  = asset.redirect_to ?? asset.url ?? null;
      existing.cloud        = existing.cloud ?? asset.infrastructure_provider ?? null;
      existing.aliases      = [...new Set([...(existing.aliases || []), ...(asset.aliases || [])])];
      existing.provider_targets = [...new Set([...(existing.provider_targets || []), ...(asset.provider_targets || [])])];
    } else {
      allAssets.push({
        hostname:     h,
        asset_type:   "exposed_service",
        source:       "exposure_probe",
        wildcard:     0,
        cname:        asset.cname ?? null,
        redirect_to:  asset.redirect_to ?? asset.url ?? null,
        risk_level:   null,
        cloud:        asset.infrastructure_provider ?? null,
        aliases:      asset.aliases || [],
        provider_targets: asset.provider_targets || [],
      });
    }
  }

  // ── Deduplicate allAssets by hostname ────────────────────────────────────
  // Several discovery sources can name the same hostname.  Duplicate
  // entries would produce two INSERTs with the same (workspace_id, hostname),
  // violating the UNIQUE constraint and failing the entire D1 batch silently.
  // Keep first occurrence; merge extra fields (ip_addresses, cloud, risk_level)
  // from any subsequent occurrence of the same hostname.
  const consolidatedAssets = consolidateInventoryAssetAliases(
    allAssets,
    modules?.asset_exposure?.assets || []
  );
  const assetMap = new Map();
  for (const asset of consolidatedAssets) {
    const existing = assetMap.get(asset.hostname);
    if (!existing) {
      assetMap.set(asset.hostname, { ...asset });
    } else {
      // Merge non-null fields from duplicate entry
      if (asset.ip_addresses != null) existing.ip_addresses = asset.ip_addresses;
      if (asset.cloud       != null) existing.cloud         = asset.cloud;
      if (asset.risk_level  != null) existing.risk_level    = asset.risk_level;
      if (asset.redirect_to != null) existing.redirect_to   = asset.redirect_to;
      existing.aliases = [...new Set([...(existing.aliases || []), ...(asset.aliases || [])])];
      existing.provider_targets = [...new Set([...(existing.provider_targets || []), ...(asset.provider_targets || [])])];
    }
  }
  const deduplicatedAssets = [...assetMap.values()];

  // Takeover risk annotations (applied to deduplicated list)
  const takeoverRiskMap = new Map(
    (modules?.subdomain_takeover?.risks || []).map((r) => [normalizeHostname(r.host), r])
  );
  for (const asset of deduplicatedAssets) {
    const risk = takeoverRiskMap.get(asset.hostname);
    if (risk) asset.risk_level = risk.severity ?? "high";
  }

  // Replace allAssets with deduplicated list from here on
  const finalAssets = deduplicatedAssets;

  console.log("[inventory]", JSON.stringify({
    domain,
    assets_found:  finalAssets.length,
    wildcard_dns:  wildcardDns,
  }));

  if (finalAssets.length === 0) return;

  // ── Look up workspaces linked to this domain ──────────────────────────────
  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare(
        `SELECT wd.workspace_id
         FROM workspace_domains wd
         JOIN workspaces w ON w.id = wd.workspace_id
         WHERE wd.domain_id = ? AND w.deleted_at IS NULL`
      )
      .bind(domainId)
      .all();
    wsRows = r.results || [];
  } catch (e) {
    console.error("[inventory] workspace lookup failed:", e?.message);
    return;
  }

  console.log("[inventory]", JSON.stringify({
    domain,
    workspaces: wsRows.length,
    domain_id:  domainId,
  }));

  if (wsRows.length === 0) return;

  // ── For each workspace: diff against existing assets, batch-upsert ────────
  for (const { workspace_id } of wsRows) {
    try {
      // Fetch existing assets + recent change events in a single batch round-trip.
      // The recent set suppresses duplicate DNS/IP/CNAME/redirect change events.
      // Existing assets are matched by hostname (root or *.root), not by
      // domain_id lineage: deleting and re-adding a domain issues a NEW
      // domain_id, and rows written under the old id would otherwise be
      // invisible to this diff — re-announced as "new" while the
      // UNIQUE(workspace_id, hostname) constraint silently blocks their
      // re-insert, freezing last_seen forever. domain_id is still included
      // so pre-normalisation rows with hostname variants keep matching.
      const rootHost = _rootHost ?? domain;
      const [existingResult, recentEvtResult] = await env.cybermeters_db.batch([
        env.cybermeters_db
          .prepare(
            `SELECT id, hostname, status, last_seen, ip_addresses, cname, redirect_to FROM workspace_assets
             WHERE workspace_id = ? AND (domain_id = ? OR hostname = ? OR hostname LIKE ?)`
          )
          .bind(workspace_id, domainId, rootHost, `%.${rootHost}`),
        env.cybermeters_db
          .prepare(
            `SELECT event_type, hostname FROM asset_events
             WHERE workspace_id = ? AND domain_id = ?
               AND created_at >= datetime('now', '-24 hours')`
          )
          .bind(workspace_id, domainId),
      ]);

      const existingMap = new Map(
        (existingResult.results || []).map((r) => [r.hostname, r])
      );

      // Set of "event_type:hostname" pairs already fired in the last 24 h
      const recentEvtSet = new Set(
        (recentEvtResult.results || []).map((r) => `${r.event_type}:${r.hostname}`)
      );

      const stmts = [];

      // Upsert each discovered asset
      for (const asset of finalAssets) {
        const existing = existingMap.get(asset.hostname);
        if (!existing) {
          // New asset — INSERT OR IGNORE guards against any residual duplicates
          const assetId = createId("asset");
          stmts.push(
            env.cybermeters_db
              .prepare(
                `INSERT OR IGNORE INTO workspace_assets
                   (id, workspace_id, domain_id, hostname, asset_type, source,
                    first_seen, last_seen, status, wildcard_dns,
                    ip_addresses, cname, redirect_to, cloud_provider,
                    risk_level, metadata_json, created_at, updated_at)
                 VALUES (?,?,?,?,?,?,?,?,'active',?,?,?,?,?,?,?,?,?)`
              )
              .bind(
                assetId, workspace_id, domainId, asset.hostname,
                asset.asset_type ?? "subdomain",
                asset.source ?? "dns_discovery",
                now, now,
                asset.wildcard ?? 0,
                asset.ip_addresses ?? null,
                asset.cname ?? null,
                asset.redirect_to ?? null,
                asset.cloud ?? null,
                asset.risk_level ?? null,
                buildAssetInventoryMetadata(asset),
                now, now
              )
          );
          if (canEmitTimelineEvents) {
            stmts.push(
              env.cybermeters_db
                .prepare(
                  `INSERT INTO asset_events
                     (id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at)
                   VALUES (?,?,?,?,?,'new_asset_discovered',?,'info',?,?)`
                )
                .bind(
                  createId("evt"), workspace_id, domainId, assetId, scanId,
                  asset.hostname,
                  `New asset discovered: ${asset.hostname} (${asset.source ?? "dns_discovery"})`,
                  now
                )
            );
          }
        } else {
          // Existing asset — update last_seen + status. domain_id is re-linked
          // to the current domain row so rows orphaned by a domain
          // delete/re-add are adopted instead of drifting further.
          const previousIps = normalizeIpAddressList(existing.ip_addresses);
          const currentIps = normalizeIpAddressList(asset.ip_addresses);
          if (canEmitTimelineEvents &&
              previousIps && currentIps && previousIps !== currentIps &&
              !recentEvtSet.has(`dns_ip_changed:${asset.hostname}`)) {
            recentEvtSet.add(`dns_ip_changed:${asset.hostname}`);
            stmts.push(
              env.cybermeters_db
                .prepare(
                  `INSERT INTO asset_events
                     (id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at)
                   VALUES (?,?,?,?,?,'dns_ip_changed',?,'medium',?,?)`
                )
                .bind(
                  createId("evt"), workspace_id, domainId,
                  existing.id, scanId,
                  asset.hostname,
                  `IP address for ${asset.hostname} changed: ${previousIps} → ${currentIps}`,
                  now
                )
            );
          }

          const previousCname = normalizeInventoryValue(existing.cname);
          const currentCname = normalizeInventoryValue(asset.cname);
          if (canEmitTimelineEvents &&
              previousCname && currentCname && previousCname !== currentCname &&
              !recentEvtSet.has(`dns_cname_changed:${asset.hostname}`)) {
            recentEvtSet.add(`dns_cname_changed:${asset.hostname}`);
            stmts.push(
              env.cybermeters_db
                .prepare(
                  `INSERT INTO asset_events
                     (id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at)
                   VALUES (?,?,?,?,?,'dns_cname_changed',?,'medium',?,?)`
                )
                .bind(
                  createId("evt"), workspace_id, domainId,
                  existing.id, scanId,
                  asset.hostname,
                  `CNAME for ${asset.hostname} changed: ${previousCname} → ${currentCname}`,
                  now
                )
            );
          }

          const previousRedirect = normalizeInventoryValue(existing.redirect_to);
          const currentRedirect = normalizeInventoryValue(asset.redirect_to);
          if (canEmitTimelineEvents &&
              previousRedirect && currentRedirect && previousRedirect !== currentRedirect &&
              !recentEvtSet.has(`dns_redirect_changed:${asset.hostname}`)) {
            const redirectSeverity = isExternalRedirectTarget(currentRedirect, domain) ? "high" : "low";
            recentEvtSet.add(`dns_redirect_changed:${asset.hostname}`);
            stmts.push(
              env.cybermeters_db
                .prepare(
                  `INSERT INTO asset_events
                     (id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at)
                   VALUES (?,?,?,?,?,'dns_redirect_changed',?,?,?,?)`
                )
                .bind(
                  createId("evt"), workspace_id, domainId,
                  existing.id, scanId,
                  asset.hostname,
                  redirectSeverity,
                  `${asset.hostname} now redirects to ${currentRedirect} (was ${previousRedirect})`,
                  now
                )
            );
          }

          stmts.push(
            env.cybermeters_db
              .prepare(
                `UPDATE workspace_assets
                 SET last_seen = ?, domain_id = ?,
                     risk_level = COALESCE(?, risk_level),
                     cloud_provider = COALESCE(?, cloud_provider),
                     ip_addresses = COALESCE(?, ip_addresses),
                     cname = COALESCE(?, cname),
                     redirect_to = COALESCE(?, redirect_to),
                     metadata_json = COALESCE(?, metadata_json),
                     updated_at = ?
                 WHERE workspace_id = ? AND hostname = ?`
              )
              .bind(
                now, domainId,
                asset.risk_level ?? null,
                asset.cloud ?? null,
                asset.ip_addresses ?? null,
                asset.cname ?? null,
                asset.redirect_to ?? null,
                buildAssetInventoryMetadata(asset),
                now,
                workspace_id, asset.hostname
              )
          );
        }
      }

      // Takeover risk events
      if (canEmitTimelineEvents) {
        for (const risk of modules?.subdomain_takeover?.risks || []) {
          const existingAsset = existingMap.get(risk.host) ?? { id: null };
          stmts.push(
            env.cybermeters_db
              .prepare(
                `INSERT INTO asset_events
                   (id, workspace_id, domain_id, asset_id, scan_id,
                    event_type, hostname, severity, description, created_at)
                 VALUES (?,?,?,?,?,'takeover_risk_detected',?,'high',?,?)`
              )
              .bind(
                createId("evt"), workspace_id, domainId,
                existingAsset.id ?? null, scanId,
                risk.host,
                `Subdomain takeover risk: ${risk.host} → ${risk.cname} (${risk.provider ?? risk.service})`,
                now
              )
          );
        }
      }

      // Wildcard DNS event (once per scan per workspace, if detected)
      if (canEmitTimelineEvents && wildcardDns) {
        stmts.push(
          env.cybermeters_db
            .prepare(
              `INSERT INTO asset_events
                 (id, workspace_id, domain_id, asset_id, scan_id,
                  event_type, hostname, severity, description, created_at)
               VALUES (?,?,?,null,?,'wildcard_dns_detected',?,'info',?,?)`
            )
            .bind(
              createId("evt"), workspace_id, domainId,
              scanId, domain,
              `Wildcard DNS detected for ${domain} — names that resolve through the wildcard may not be distinct services`,
              now
            )
        );
      }

      // Execute all statements in a single D1 batch round-trip
      console.log("[inventory]", JSON.stringify({
        domain, workspace_id, stmts: stmts.length,
      }));

      if (stmts.length > 0) {
        try {
          await env.cybermeters_db.batch(stmts);
        } catch (batchErr) {
          // Surface the real error so it appears in Cloudflare Workers logs
          console.error("[inventory] D1 batch failed:", batchErr?.message, batchErr?.cause);
          throw batchErr;   // re-throw so the outer per-workspace catch sees it
        }
      }

    } catch (e) {
      // Per-workspace failure is non-fatal — continue with next workspace
      console.error("[inventory] workspace upsert error for", workspace_id, ":", e?.message);
    }
  }
}
