// ── Asset inventory upsert ──
// Persists the discovered asset inventory to D1 (diff vs prior state, asset events, alias
// consolidation, per-asset probe metadata). Extracted verbatim from index.js (monolith
// decomposition, Phase 1c).
import { buildAssetInventoryMetadata, consolidateInventoryAssetAliases, probeAsset } from "./asset-intel.js";
import { collectAssetHints, hintsForAsset, mergeAssetSightings, safeLocation } from "./asset-evidence.js";
import { deriveRemovalObservation } from "./attack-surface-signal-completeness.js";
import { normalizeHostname } from "./hostnames.js";
import { createId } from "../lib/util.js";
import { hashToken } from "../lib/auth-crypto.js";
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

// Where a name's web answer finally came from, for change detection: the host
// (with a non-default port). A different path or query is not a change of
// where the name sends people, and neither is a scheme flip on the same host —
// HTTPS not answering once, so only HTTP did, is an availability question, not
// a redirect. A row stored before queries were dropped compares the same way.
function redirectLanding(value) {
  const location = safeLocation(normalizeInventoryValue(value));
  if (!location) return null;
  try {
    const url = new URL(location);
    return { host: url.host.toLowerCase(), origin: url.origin };
  } catch {
    return null;
  }
}

function redirectChangeDescription(hostname, previous, current) {
  const own = normalizeHostname(hostname);
  if (previous.host === own) return `${hostname} now redirects to ${current.origin} (it previously answered on its own name)`;
  if (current.host === own) return `${hostname} no longer redirects to ${previous.origin}; it answers on its own name`;
  return `${hostname} now redirects to ${current.origin} (was ${previous.origin})`;
}

// One event per (workspace, scan, type, name): replaying a scan's inventory
// step can never write the same event twice.
async function inventoryEventId(workspaceId, scanId, eventType, hostname) {
  const digest = await hashToken(JSON.stringify(["asset-inventory-event-v1", workspaceId, scanId, eventType, hostname]));
  return `evt-${digest.slice(0, 32)}`;
}

function splitAddressFamilies(value) {
  const list = normalizeIpAddressList(value).split(", ").filter(Boolean);
  return { v4: list.filter((address) => !address.includes(":")), v6: list.filter((address) => address.includes(":")) };
}

// DNS outcomes that settle a family: its addresses, or that it has none.
const DEFINITIVE_FAMILY_OUTCOMES = new Set(["answer", "nodata", "nxdomain", "alias", "dangling_alias"]);

// The addresses to store for a name. A family this scan answered definitively
// replaces what was stored; a family whose question failed, timed out or was
// not asked keeps the stored addresses, so a lookup failure never reads as an
// address change. Without per-family evidence the scan's list is used as is.
function addressesToStore(previousRaw, currentRaw, dnsEvidence) {
  if (currentRaw == null) return null;
  if (!dnsEvidence?.A || !dnsEvidence?.AAAA) return currentRaw;
  const previous = splitAddressFamilies(previousRaw);
  const current = splitAddressFamilies(currentRaw);
  const v4 = DEFINITIVE_FAMILY_OUTCOMES.has(dnsEvidence.A.outcome) ? current.v4 : previous.v4;
  const v6 = DEFINITIVE_FAMILY_OUTCOMES.has(dnsEvidence.AAAA.outcome) ? current.v6 : previous.v6;
  return JSON.stringify([...v4, ...v6].sort());
}

function takeoverKey(risk) {
  const host = normalizeHostname(risk?.host);
  return host ? `${host}>${normalizeHostname(risk?.cname) || ""}` : "";
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
// Only the workspace that ran the scan is written (opts.workspaceId), and only
// while it is live and still linked to the domain. Another workspace linked to
// the same domain keeps its own inventory from its own scans: one workspace's
// customer list, re-checks and evidence never reach another. Without a
// workspace nothing is written.
// Uses D1 batch() to minimise round-trips.
//
// opts.hints: where each name was seen this scan (collectAssetHints); each
// row's per-source first/last sighting is kept in sightings_json.
// opts.assetEvidence: this scan's per-name evidence (buildScanAssetEvidence);
// its per-family DNS answers decide which stored addresses a scan may replace.
//
// Change events need a comparable previous scan of the same workspace. A
// standing condition (a takeover candidate, a wildcard) is announced when it
// appears, not again on every scan while it lasts.

export async function upsertAssetInventory(scanId, domainId, domain, modules, env, opts = {}) {
  const workspaceId = typeof opts.workspaceId === "string" && opts.workspaceId ? opts.workspaceId : null;
  if (!workspaceId) {
    console.log("[inventory]", JSON.stringify({ domain, skipped: "no_workspace" }));
    return { written: false, reason: "no_workspace" };
  }
  const now = new Date(opts.observedAt || Date.now()).toISOString();
  const hints = opts.hints instanceof Map ? opts.hints : collectAssetHints(domain, modules);
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

  // SRV record targets and hosts the home page links to are references, not
  // discoveries: they arrive below with the other configuration references,
  // and only when DNS answered for them (sources dns_srv / html_link).
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
  // Hostnames the customer listed, confirmed by DNS.
  for (const item of modules?.subdomains?.customer_hostnames?.confirmed || []) {
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
  // Hostnames the site's own robots.txt, sitemaps and scripts name,
  // confirmed by DNS after page discovery.
  for (const item of modules?.subdomains?.page_references?.confirmed || []) {
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
  // A probe is a check, not a sighting: a re-checked name that DNS no longer
  // answers for, or that served nothing, must not refresh last_seen. Only a
  // name the probe actually observed (an address, an existing DNS name or an
  // HTTP response) joins the inventory from this source.
  const removalObservations = modules?.asset_exposure?.removal_observations;
  const observedByProbe = Array.isArray(removalObservations)
    ? new Set(removalObservations
      .filter((row) => deriveRemovalObservation(row?.signal_states) === "observed")
      .map((row) => normalizeHostname(row?.host))
      .filter(Boolean))
    : null;
  // Without removal observations (older result shapes), positive probe
  // evidence is an HTTP response, a redirect, an alias or an address.
  const probeObserved = (asset, host) => observedByProbe
    ? observedByProbe.has(host)
    : asset?.reachable === true ||
      (asset?.status != null && Number.isFinite(Number(asset.status))) ||
      Boolean(asset?.redirect_to || asset?.cname || asset?.ip);
  for (const asset of modules?.asset_exposure?.assets || []) {
    const h = normalizeHostname(asset.host || asset.hostname || asset.url);
    if (!h) continue;
    const existing = allAssets.find((a) => a.hostname === h);
    if (!existing && !probeObserved(asset, h)) continue;
    // Only a probe that got an answer says where the name redirects; a failed
    // probe's placeholder URL is not a location.
    const answeredLocation = Number.isInteger(asset.status) ? safeLocation(asset.redirect_to ?? asset.url ?? null) : null;
    if (existing) {
      existing.ip_addresses = existing.ip_addresses ?? JSON.stringify(asset.ip ? [asset.ip] : []);
      existing.cname        = existing.cname ?? asset.cname ?? null;
      existing.redirect_to  = answeredLocation;
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
        redirect_to:  answeredLocation,
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

  if (finalAssets.length === 0) return { written: false, reason: "no_assets" };

  // ── The scan's workspace, if it is live and still linked to the domain ─────
  let wsRows;
  try {
    const r = await env.cybermeters_db
      .prepare(
        `SELECT wd.workspace_id
         FROM workspace_domains wd
         JOIN workspaces w ON w.id = wd.workspace_id
         WHERE wd.domain_id = ? AND wd.workspace_id = ? AND w.deleted_at IS NULL`
      )
      .bind(domainId, workspaceId)
      .all();
    wsRows = r.results || [];
  } catch (e) {
    console.error("[inventory] workspace lookup failed:", e?.message);
    return { written: false, reason: "workspace_lookup_failed" };
  }

  console.log("[inventory]", JSON.stringify({
    domain,
    workspaces: wsRows.length,
    domain_id:  domainId,
  }));

  if (wsRows.length === 0) return { written: false, reason: "workspace_not_linked" };

  let written = false;
  // ── Diff against the workspace's existing assets, batch-upsert ─────────────
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
      // sightings_json arrives with migration 118; before it is applied the
      // inventory is still written, without per-source sightings.
      let sightingsColumn = true;
      const readExisting = (withSightings) => env.cybermeters_db.batch([
        env.cybermeters_db
          .prepare(
            `SELECT id, hostname, status, last_seen, ip_addresses, cname, redirect_to${withSightings ? ", sightings_json" : ""} FROM workspace_assets
             WHERE workspace_id = ? AND (domain_id = ? OR hostname = ? OR hostname LIKE ?)`
          )
          .bind(workspace_id, domainId, rootHost, `%.${rootHost}`),
        env.cybermeters_db
          .prepare(
            `SELECT event_type, hostname FROM asset_events
             WHERE workspace_id = ? AND domain_id = ?
               AND julianday(created_at) >= julianday('now', '-24 hours')`
          )
          .bind(workspace_id, domainId),
      ]);
      const [existingResult, recentEvtResult] = await readExisting(true).catch((error) => {
        if (!/no such column/i.test(String(error?.message || ""))) throw error;
        sightingsColumn = false;
        return readExisting(false);
      });

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
        const sightings = mergeAssetSightings(
          existing?.sightings_json ?? null,
          hintsForAsset(hints, asset.hostname, asset.aliases),
          { scanId, observedAt: now },
        );
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
                    risk_level, metadata_json, created_at, updated_at${sightingsColumn ? ", sightings_json" : ""})
                 VALUES (?,?,?,?,?,?,?,?,'active',?,?,?,?,?,?,?,?,?${sightingsColumn ? ",?" : ""})`
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
                now, now,
                ...(sightingsColumn ? [sightings] : [])
              )
          );
          if (canEmitTimelineEvents) {
            stmts.push(
              env.cybermeters_db
                .prepare(
                  `INSERT OR IGNORE INTO asset_events
                     (id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at)
                   VALUES (?,?,?,?,?,'new_asset_discovered',?,'info',?,?)`
                )
                .bind(
                  await inventoryEventId(workspace_id, scanId, "new_asset_discovered", asset.hostname),
                  workspace_id, domainId, assetId, scanId,
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
          const storedAddresses = addressesToStore(
            existing.ip_addresses,
            asset.ip_addresses ?? null,
            opts.assetEvidence?.get?.(asset.hostname)?.dns ?? null,
          );
          const previousIps = normalizeIpAddressList(existing.ip_addresses);
          const currentIps = normalizeIpAddressList(storedAddresses);
          if (canEmitTimelineEvents &&
              previousIps && currentIps && previousIps !== currentIps &&
              !recentEvtSet.has(`dns_ip_changed:${asset.hostname}`)) {
            recentEvtSet.add(`dns_ip_changed:${asset.hostname}`);
            stmts.push(
              env.cybermeters_db
                .prepare(
                  `INSERT OR IGNORE INTO asset_events
                     (id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at)
                   VALUES (?,?,?,?,?,'dns_ip_changed',?,'medium',?,?)`
                )
                .bind(
                  await inventoryEventId(workspace_id, scanId, "dns_ip_changed", asset.hostname),
                  workspace_id, domainId,
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
                  `INSERT OR IGNORE INTO asset_events
                     (id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at)
                   VALUES (?,?,?,?,?,'dns_cname_changed',?,'medium',?,?)`
                )
                .bind(
                  await inventoryEventId(workspace_id, scanId, "dns_cname_changed", asset.hostname),
                  workspace_id, domainId,
                  existing.id, scanId,
                  asset.hostname,
                  `CNAME for ${asset.hostname} changed: ${previousCname} → ${currentCname}`,
                  now
                )
            );
          }

          const previousRedirect = redirectLanding(existing.redirect_to);
          const currentRedirect = redirectLanding(asset.redirect_to);
          if (canEmitTimelineEvents &&
              previousRedirect && currentRedirect && previousRedirect.host !== currentRedirect.host &&
              !recentEvtSet.has(`dns_redirect_changed:${asset.hostname}`)) {
            const redirectSeverity = isExternalRedirectTarget(currentRedirect.origin, domain) ? "high" : "low";
            recentEvtSet.add(`dns_redirect_changed:${asset.hostname}`);
            stmts.push(
              env.cybermeters_db
                .prepare(
                  `INSERT OR IGNORE INTO asset_events
                     (id, workspace_id, domain_id, asset_id, scan_id,
                      event_type, hostname, severity, description, created_at)
                   VALUES (?,?,?,?,?,'dns_redirect_changed',?,?,?,?)`
                )
                .bind(
                  await inventoryEventId(workspace_id, scanId, "dns_redirect_changed", asset.hostname),
                  workspace_id, domainId,
                  existing.id, scanId,
                  asset.hostname,
                  redirectSeverity,
                  redirectChangeDescription(asset.hostname, previousRedirect, currentRedirect),
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
                     metadata_json = COALESCE(?, metadata_json),${sightingsColumn ? `
                     sightings_json = COALESCE(?, sightings_json),` : ""}
                     updated_at = ?
                 WHERE workspace_id = ? AND hostname = ?`
              )
              .bind(
                now, domainId,
                asset.risk_level ?? null,
                asset.cloud ?? null,
                storedAddresses,
                asset.cname ?? null,
                asset.redirect_to ?? null,
                buildAssetInventoryMetadata(asset),
                ...(sightingsColumn ? [sightings] : []),
                now,
                workspace_id, asset.hostname
              )
          );
        }
      }

      // Takeover risk events: a candidate the previous comparable scan did not
      // have. One that persists was announced when it appeared.
      if (canEmitTimelineEvents) {
        const previousTakeovers = new Set((comparison.previousReport?.modules?.subdomain_takeover?.risks || [])
          .map(takeoverKey).filter(Boolean));
        for (const risk of modules?.subdomain_takeover?.risks || []) {
          const key = takeoverKey(risk);
          if (!key || previousTakeovers.has(key)) continue;
          const existingAsset = existingMap.get(risk.host) ?? { id: null };
          stmts.push(
            env.cybermeters_db
              .prepare(
                `INSERT OR IGNORE INTO asset_events
                   (id, workspace_id, domain_id, asset_id, scan_id,
                    event_type, hostname, severity, description, created_at)
                 VALUES (?,?,?,?,?,'takeover_risk_detected',?,'high',?,?)`
              )
              .bind(
                await inventoryEventId(workspace_id, scanId, "takeover_risk_detected", key),
                workspace_id, domainId,
                existingAsset.id ?? null, scanId,
                risk.host,
                `Subdomain takeover risk: ${risk.host} → ${risk.cname} (${risk.provider ?? risk.service})`,
                now
              )
          );
        }
      }

      // Wildcard DNS event: when the zone starts answering every name, not on
      // every scan while it does.
      if (canEmitTimelineEvents && wildcardDns &&
          comparison.previousReport?.modules?.subdomains?.wildcard_dns !== true) {
        stmts.push(
          env.cybermeters_db
            .prepare(
              `INSERT OR IGNORE INTO asset_events
                 (id, workspace_id, domain_id, asset_id, scan_id,
                  event_type, hostname, severity, description, created_at)
               VALUES (?,?,?,null,?,'wildcard_dns_detected',?,'info',?,?)`
            )
            .bind(
              await inventoryEventId(workspace_id, scanId, "wildcard_dns_detected", domain),
              workspace_id, domainId,
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
      written = true;

    } catch (e) {
      // Failure is non-fatal for the scan; the next scan catches up.
      console.error("[inventory] workspace upsert error for", workspace_id, ":", e?.message);
    }
  }
  return { written, reason: written ? null : "write_failed" };
}
