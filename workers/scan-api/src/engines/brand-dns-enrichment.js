// ── Canonical Brand DNS enrichment ────────────────────────────────────────────
// The ONE implementation used by BOTH the manual POST /brand-monitoring/refresh
// endpoint and the automatic hourly cron sweep. There is no second copy: the
// manual and automatic paths call `enrichBrandCandidatesDns` here.
//
// Tri-state truth is preserved end to end:
//   dns_resolves NULL = not yet checked   (candidate persisted by a scan, awaiting a probe)
//   dns_resolves 0    = checked, no A record (conclusive negative)
//   dns_resolves 1    = checked, resolves    (conclusive positive)
//
// A transient resolver failure (timeout, DoH HTTP error, SERVFAIL/REFUSED) is
// NEVER coerced to 0. The row is left untouched — still NULL, last_checked_at not
// advanced — so the next batch naturally retries it. This is the honesty rule:
// "not yet checked" must never be presented as "inactive".
//
// External tools (e.g. dnstwist) only ever produce CANDIDATES. CyberMeters' own
// deterministic DoH probe is the sole authority for CyberMeters state; no external
// resolution result is imported into production state here.

import { dnsQuery as defaultDnsQuery } from "./dns.js";
import { createId } from "../lib/util.js";

// Bounded work — NOT a plan subrequest limit (CyberMeters runs on the Workers
// Paid plan). The batch is deliberately small for CONTROLLED FAN-OUT (the hourly
// cron shares one invocation with scheduled scans and every other cron task, so a
// steady trickle keeps combined fan-out predictable), for RETRY BEHAVIOUR (a
// transient failure is retried next tick, so small batches recover cleanly), and
// for PRODUCTION OBSERVABILITY (incremental progress is easy to watch). The manual
// endpoint has its own invocation and passes a larger batch.
export const BRAND_DNS_BATCH_SIZE = 10;                 // candidates per workspace per invocation
export const BRAND_DNS_SWEEP_WORKSPACES_PER_TICK = 5;   // workspaces per hourly cron tick
export const BRAND_DNS_MANUAL_BATCH_SIZE = 20;          // manual refresh: one dedicated invocation
export const BRAND_DNS_RECHECK_AFTER_MS = 7 * 24 * 60 * 60 * 1000; // re-probe a checked candidate weekly

// Classifications the customer has closed — never spend a probe on them.
const CLOSED_CLASSIFICATIONS = "('owned','ignored','false_positive')";

/**
 * Probe one candidate's A record. Returns exactly one conclusive-or-transient outcome:
 *   { outcome: 'resolves', ip }  — an A record exists (conclusive positive)
 *   { outcome: 'no_answer' }     — resolver answered, no A record (conclusive negative)
 *   { outcome: 'transient' }     — timeout / DoH error / SERVFAIL (inconclusive; DO NOT persist)
 */
export async function probeCandidateDns(candidateDomain, dnsQuery = defaultDnsQuery) {
  let resp;
  try {
    resp = await dnsQuery(candidateDomain, "A");
  } catch {
    return { outcome: "transient" };          // timeout / HTTP error → inconclusive, never 0
  }
  if (!resp || typeof resp !== "object" || typeof resp.Status !== "number") {
    return { outcome: "transient" };
  }
  const answers = Array.isArray(resp.Answer) ? resp.Answer : [];
  const aRecords = answers.filter((a) => a && a.type === 1 && a.data); // DoH type 1 = A
  if (aRecords.length > 0) return { outcome: "resolves", ip: String(aRecords[0].data) };
  // NOERROR-with-no-A (0) and NXDOMAIN (3) are both conclusive "does not resolve to an A record".
  if (resp.Status === 0 || resp.Status === 3) return { outcome: "no_answer" };
  // SERVFAIL (2) / REFUSED (5) / anything else → inconclusive, leave for retry.
  return { outcome: "transient" };
}

/**
 * Map a probe outcome to the persisted fields, or null when nothing may be
 * persisted (transient). Kept pure so a test can pin the tri-state mapping.
 */
export function outcomeToPersistence(outcome) {
  if (outcome?.outcome === "resolves") return { dns_resolves: 1, status: "active", ip_address: outcome.ip ?? null };
  if (outcome?.outcome === "no_answer") return { dns_resolves: 0, status: "inactive", ip_address: null };
  return null; // transient — do not write a definitive state, do not advance last_checked_at
}

/**
 * The bounded selection query: unchecked candidates first (dns_resolves IS NULL),
 * then checked-but-stale (older than the recheck window), deterministic risk then
 * domain tie-break. This is what prevents the first-N starvation — a checked
 * candidate is not re-probed until its neighbours have been checked or it goes stale.
 */
export function selectBrandCandidatesSql() {
  // Positional binds in order: workspace_id, staleBefore, batchSize.
  return `SELECT id, candidate_domain, dns_resolves, last_checked_at
          FROM workspace_brand_assets
          WHERE workspace_id = ?
            AND (classification IS NULL OR classification NOT IN ${CLOSED_CLASSIFICATIONS})
            AND (dns_resolves IS NULL OR last_checked_at IS NULL OR last_checked_at < ?)
          ORDER BY (dns_resolves IS NOT NULL) ASC,     -- unchecked (NULL) strictly first
                   CASE risk_level WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                   WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END ASC,
                   candidate_domain ASC
          LIMIT ?`;
}

/**
 * Historical helper retained for compatibility. Phase A Timeline Trust keeps this
 * path silent because brand DNS enrichment is not tied to a comparable scan-pair
 * producer version; resolving candidates remain visible through brand surfaces.
 */
async function fireResolvingAssetEvent(env, workspaceId, candidateDomain, riskLevel, now) {
  try {
    const domRow = await env.cybermeters_db
      .prepare("SELECT domain_id FROM workspace_domains WHERE workspace_id = ? LIMIT 1")
      .bind(workspaceId).first();
    const evType = ["high", "critical"].includes(riskLevel)
      ? "high_risk_typosquat_detected"
      : "brand_domain_detected";
    await env.cybermeters_db.prepare(
      `INSERT OR IGNORE INTO asset_events
         (id, workspace_id, domain_id, scan_id, event_type, hostname, severity, description, created_at)
       VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?)`
    ).bind(
      createId("asev"), workspaceId, domRow?.domain_id || null, evType, candidateDomain,
      ["high", "critical"].includes(riskLevel) ? "high" : "medium",
      `Lookalike candidate ${candidateDomain} is resolving via DNS`, now,
    ).run();
  } catch { /* non-fatal */ }
}

/**
 * Enrich a bounded batch of ONE workspace's brand candidates. Idempotent,
 * tenant-scoped (every read and write is filtered by workspace_id), retry-safe
 * (transient failures leave the row eligible). Returns per-outcome counts.
 */
export async function enrichBrandCandidatesDns(env, workspaceId, opts = {}) {
  const {
    batchSize = BRAND_DNS_BATCH_SIZE,
    now = new Date().toISOString(),
    dnsQuery = defaultDnsQuery,
    recheckAfterMs = BRAND_DNS_RECHECK_AFTER_MS,
    fireEvents = false,
  } = opts;
  const staleBefore = new Date(Date.now() - recheckAfterMs).toISOString();
  const stats = { selected: 0, resolves: 0, no_answer: 0, transient: 0, checked: 0 };

  let rows;
  try {
    rows = await env.cybermeters_db
      .prepare(selectBrandCandidatesSql())
      .bind(workspaceId, staleBefore, Math.max(1, batchSize))
      .all();
  } catch {
    return stats;
  }
  const candidates = rows?.results || [];
  stats.selected = candidates.length;

  for (const row of candidates) {
    const probe = await probeCandidateDns(row.candidate_domain, dnsQuery);
    stats[probe.outcome] = (stats[probe.outcome] || 0) + 1;
    const persist = outcomeToPersistence(probe);
    if (!persist) continue; // transient — untouched, retried next batch
    const wasResolving = row.dns_resolves === 1;
    try {
      await env.cybermeters_db.prepare(
        `UPDATE workspace_brand_assets
            SET dns_resolves = ?, status = ?, ip_address = ?, last_checked_at = ?, updated_at = ?
          WHERE id = ? AND workspace_id = ?`
      ).bind(persist.dns_resolves, persist.status, persist.ip_address, now, now, row.id, workspaceId).run();
      stats.checked++;
      if (fireEvents && persist.dns_resolves === 1 && !wasResolving) {
        const rl = await env.cybermeters_db
          .prepare("SELECT risk_level FROM workspace_brand_assets WHERE id = ? AND workspace_id = ?")
          .bind(row.id, workspaceId).first().catch(() => null);
        await fireResolvingAssetEvent(env, workspaceId, row.candidate_domain, rl?.risk_level, now);
      }
    } catch { /* isolated — the batch continues */ }
  }
  return stats;
}

/**
 * Automatic hourly cron sweep. Picks a bounded number of workspaces that still
 * have unchecked candidates (most-pending first) and enriches a batch of each.
 * Bounded total fan-out = workspacesPerTick × batchSize, kept small so it shares
 * the cron's subrequest budget with scheduled scans. Idempotent and self-limiting:
 * a workspace with no pending candidates is never selected.
 */
export async function runBrandDnsEnrichmentSweep(env, opts = {}) {
  const { workspacesPerTick = BRAND_DNS_SWEEP_WORKSPACES_PER_TICK, ...rest } = opts;
  let rows;
  try {
    rows = await env.cybermeters_db.prepare(
      `SELECT workspace_id, COUNT(*) AS pending
         FROM workspace_brand_assets
        WHERE dns_resolves IS NULL
          AND (classification IS NULL OR classification NOT IN ${CLOSED_CLASSIFICATIONS})
        GROUP BY workspace_id
        ORDER BY pending DESC, workspace_id ASC
        LIMIT ?`
    ).bind(Math.max(1, workspacesPerTick)).all();
  } catch {
    return { workspaces: 0, checked: 0 };
  }
  const wss = rows?.results || [];
  let checked = 0;
  for (const w of wss) {
    const s = await enrichBrandCandidatesDns(env, w.workspace_id, rest);
    checked += s.checked;
  }
  return { workspaces: wss.length, checked };
}
