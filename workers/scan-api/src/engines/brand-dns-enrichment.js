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
import { writeBrandEvidence } from "./brand-evidence-persistence.js";

// Bounded work — NOT a plan subrequest limit (CyberMeters runs on the Workers
// Paid plan). The batch is deliberately small for CONTROLLED FAN-OUT (the hourly
// cron shares one invocation with scheduled scans and every other cron task, so a
// steady trickle keeps combined fan-out predictable), for RETRY BEHAVIOUR (a
// transient failure is retried next tick, so small batches recover cleanly), and
// for PRODUCTION OBSERVABILITY (incremental progress is easy to watch). The manual
// endpoint has its own invocation and passes a larger batch.
// One candidate and one row update per slot. Verified domains now need at most
// three DNS questions (A, AAAA fallback, MX); the existing candidate caps,
// manual cooldown and weekly recheck window remain unchanged. At most 1,200
// DNS questions across the 40 x 10 hourly sweep (no HTTP or SMTP probes here).
// 40 x 10 = 400 candidate checks per
// hourly tick (4% of the Worker's 10,000-subrequest budget; about 67,000 a
// week platform-wide), so one 50-domain MSP workspace (up to 2,200 candidates)
// completes a full pass in about 55 hours, inside the weekly recheck window.
// Before 21 Oct 2026 it was 10 x 5 = 50 an hour: about 220 hours for that MSP.
export const BRAND_DNS_BATCH_SIZE = 40;                 // candidates per workspace per invocation
export const BRAND_DNS_SWEEP_WORKSPACES_PER_TICK = 10;  // workspaces per hourly cron tick
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
  if (aRecords.some((a) => typeof a.data !== "string" || !/^(\d{1,3}\.){3}\d{1,3}$/.test(a.data)
      || a.data.split(".").some((part) => Number(part) > 255))) return { outcome: "transient" };
  if (resp.Status !== 0 && aRecords.length) return { outcome: "transient" };
  if (resp.Status === 0 && aRecords.length > 0) return { outcome: "resolves", ip: String(aRecords[0].data) };
  // NOERROR-with-no-A (0) and NXDOMAIN (3) are both conclusive "does not resolve to an A record".
  if (resp.Status === 0 || resp.Status === 3) return { outcome: "no_answer" };
  // SERVFAIL (2) / REFUSED (5) / anything else → inconclusive, leave for retry.
  return { outcome: "transient" };
}

/** A/AAAA and explicit MX facts only; no connection or mail delivery is tested. */
export async function probeWatchlistDns(candidateDomain, dnsQuery = defaultDnsQuery) {
  const address = await probeCandidateDns(candidateDomain, dnsQuery);
  if (address.outcome === "transient") return null;
  let ip = address.ip ?? null;
  let resolves = address.outcome === "resolves";
  try {
    if (!resolves) {
      const v6 = await dnsQuery(candidateDomain, "AAAA");
      if (![0, 3].includes(v6?.Status)) return null;
      const answers = Array.isArray(v6.Answer) ? v6.Answer : [];
      const validV6 = (a) => {
        if (a?.type !== 28 || typeof a.data !== "string" || !a.data.includes(":")) return false;
        try { return new URL(`http://[${a.data}]/`).hostname.startsWith("["); } catch { return false; }
      };
      if (answers.some((a) => a?.type === 28 && !validV6(a))) return null;
      const record = answers.find(validV6);
      if (record && v6.Status !== 0) return null;
      if (record) { resolves = true; ip = record.data; }
    }
    const mx = await dnsQuery(candidateDomain, "MX");
    if (![0, 3].includes(mx?.Status)) return null;
    const records = (Array.isArray(mx.Answer) ? mx.Answer : []).filter((a) => a?.type === 15);
    if (records.length > 32) return null;
    if (mx.Status !== 0 && records.length) return null;
    let present = false, nullMx = false;
    for (const record of records.slice(0, 32)) {
      if (typeof record.data !== "string" || record.data.length > 260) return null;
      const parts = /^(\d{1,5})\s+([^\s]+)$/.exec(record.data.trim());
      if (!parts || Number(parts[1]) > 65535) return null;
      if (parts[1] === "0" && parts[2] === ".") { nullMx = true; continue; }
      const exchange = parts[2].replace(/\.$/, "");
      if (exchange.length > 253 || !exchange.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label))) return null;
      present = true;
    }
    if (nullMx && (present || records.length !== 1)) return null;
    return { resolves, ip, mx_present: present, null_mx: nullMx };
  } catch { return null; }
}

export function readWatchlistDnsReceipts(rows = []) {
  return rows.slice(0, 500).flatMap((row) => {
    if (["owned", "ignored", "false_positive"].includes(row.classification)) return [];
    try {
      const evidence = JSON.parse(row.evidence_json || "[]");
      if (!Array.isArray(evidence)) return [];
      const receipt = evidence.find((item) => item?.signal === "watchlist_dns_observation")?.value;
      return receipt?.candidate_domain === row.candidate_domain && receipt?.protected_domain === row.domain ? [receipt] : [];
    } catch { return []; }
  });
}

/** Publish only fresh, measured receipts for the currently verified scan scope. */
export function brandWatchlistDnsObservations(brandModule, { domain, verified = false, checkedAt } = {}) {
  if (verified !== true || brandModule?.error || brandModule?.validation?.state === "unavailable"
      || !Array.isArray(brandModule?.watchlist_dns)) return [];
  const at = Date.parse(checkedAt);
  const scope = String(domain || "").toLowerCase().replace(/\.$/, "");
  const evidence = [];
  for (const receipt of brandModule.watchlist_dns.slice(0, 20)) {
    const observed = Date.parse(receipt.checked_at);
    if (receipt.schema_version !== "brand-watchlist-dns.v1" || receipt.verified_scope !== true
        || receipt.protected_domain !== scope || !/^[a-z0-9.-]{1,253}$/.test(receipt.candidate_domain || "")
        || receipt.candidate_domain === scope || !Number.isFinite(observed) || !Number.isFinite(at)
        || observed > at + 60_000 || at - observed > BRAND_DNS_RECHECK_AFTER_MS
        || typeof receipt.resolves !== "boolean" || typeof receipt.mx_present !== "boolean") continue;
    if (receipt.resolves) evidence.push({ type: "dns_lookup", source: "dns",
      label: receipt.candidate_domain, value: "Lookalike is live: an address record was observed.",
      checked_at: receipt.checked_at });
    if (receipt.mx_present && receipt.null_mx === false) evidence.push({ type: "dns_lookup", source: "dns",
      label: receipt.candidate_domain, value: "Lookalike can receive mail according to its published MX records; delivery was not tested.",
      checked_at: receipt.checked_at });
  }
  if (!evidence.length) return [];
  return [{ id: "brand_watchlist_dns_observation", module: "brand_monitoring",
    title: "Live lookalike DNS observations", finding_type: "observation", severity: "info", score_impact: 0,
    description: "Existing watchlist names publish address or mail-routing records. These are DNS observations, not evidence of phishing, abuse or successful mail delivery. Absence of MX does not prove a name cannot receive mail.",
    evidence, confidence: 80 }];
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
  return `SELECT id, candidate_domain, domain, dns_resolves, last_checked_at, evidence_json,
                 EXISTS (SELECT 1 FROM workspace_domains wd JOIN domains d ON d.id = wd.domain_id
                          WHERE wd.workspace_id = a.workspace_id AND lower(d.domain) = lower(a.domain)
                            AND wd.verification_status = 'verified') AS protected_domain_verified
          FROM workspace_brand_assets a
          WHERE workspace_id = ?
            AND (classification IS NULL OR classification NOT IN ${CLOSED_CLASSIFICATIONS})
            AND (dns_resolves IS NULL OR last_checked_at IS NULL OR last_checked_at < ?)
            AND EXISTS (
                  SELECT 1
                    FROM workspaces w
                    JOIN workspace_domains wd ON wd.workspace_id = w.id
                    JOIN domains d ON d.id = wd.domain_id
                   WHERE w.id = a.workspace_id
                     AND w.deleted_at IS NULL
                     AND lower(d.domain) = lower(a.domain)
                )
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
      .prepare(`SELECT wd.domain_id
                  FROM workspace_domains wd
                  JOIN workspaces w
                    ON w.id = wd.workspace_id AND w.deleted_at IS NULL
                 WHERE wd.workspace_id = ?
                 LIMIT 1`)
      .bind(workspaceId).first();
    if (!domRow?.domain_id) return;
    const evType = ["high", "critical"].includes(riskLevel)
      ? "high_risk_typosquat_detected"
      : "brand_domain_detected";
    await env.cybermeters_db.prepare(
      `INSERT OR IGNORE INTO asset_events
         (id, workspace_id, domain_id, scan_id, event_type, hostname, severity, description, created_at)
       SELECT ?, ?, ?, NULL, ?, ?, ?, ?, ?
        WHERE EXISTS (
              SELECT 1
                FROM workspaces w
                JOIN workspace_domains wd
                  ON wd.workspace_id = w.id AND wd.domain_id = ?
               WHERE w.id = ? AND w.deleted_at IS NULL
            )`
    ).bind(
      createId("asev"), workspaceId, domRow?.domain_id || null, evType, candidateDomain,
      ["high", "critical"].includes(riskLevel) ? "high" : "medium",
      `Lookalike candidate ${candidateDomain} is resolving via DNS`, now,
      domRow.domain_id, workspaceId,
    ).run();
  } catch { /* non-fatal */ }
}

function runChanges(result) {
  const value = result?.meta?.changes ?? result?.changes;
  return Number.isFinite(Number(value)) ? Number(value) : 0;
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
      .bind(workspaceId, staleBefore, Math.min(BRAND_DNS_BATCH_SIZE, Math.max(1, batchSize)))
      .all();
  } catch {
    return stats;
  }
  const candidates = rows?.results || [];
  stats.selected = candidates.length;

  for (const row of candidates) {
    const measured = row.protected_domain_verified === 1 ? await probeWatchlistDns(row.candidate_domain, dnsQuery) : undefined;
    const probe = measured === undefined ? await probeCandidateDns(row.candidate_domain, dnsQuery)
      : measured ? { outcome: measured.resolves ? "resolves" : "no_answer", ip: measured.ip } : { outcome: "transient" };
    stats[probe.outcome] = (stats[probe.outcome] || 0) + 1;
    const persist = outcomeToPersistence(probe);
    if (!persist) continue; // transient — untouched, retried next batch
    const wasResolving = row.dns_resolves === 1;
    try {
      const write = async (expected) => {
        let extraFields = "";
        const extraBinds = [];
        if (measured) {
          let prior = [];
          try { const parsed = JSON.parse(expected || "[]"); if (Array.isArray(parsed)) prior = parsed; } catch { /* no prior evidence */ }
          const receipt = { schema_version: "brand-watchlist-dns.v1", verified_scope: true,
            protected_domain: row.domain, candidate_domain: row.candidate_domain,
            checked_at: now, resolves: measured.resolves, mx_present: measured.mx_present, null_mx: measured.null_mx };
          const evidence = [...prior.filter((item) => item?.signal !== "watchlist_dns_observation"),
            { signal: "watchlist_dns_observation", value: receipt }];
          extraFields = ", mx_present = ?, evidence_json = ?";
          extraBinds.push(measured.mx_present ? 1 : 0, JSON.stringify(evidence));
        }
        return env.cybermeters_db.prepare(
        `UPDATE workspace_brand_assets
            SET dns_resolves = ?, status = ?, ip_address = ?, last_checked_at = ?, updated_at = ?${extraFields}
          WHERE id = ? AND workspace_id = ?
            AND EXISTS (
                  SELECT 1
                    FROM workspaces w
                    JOIN workspace_domains wd ON wd.workspace_id = w.id
                    JOIN domains d ON d.id = wd.domain_id
                   WHERE w.id = workspace_brand_assets.workspace_id
                     AND w.deleted_at IS NULL
                     AND lower(d.domain) = lower(workspace_brand_assets.domain)
                )${measured ? " AND evidence_json IS ?" : ""}`
        ).bind(persist.dns_resolves, persist.status, persist.ip_address, now, now, ...extraBinds,
          row.id, workspaceId, ...(measured ? [expected] : [])).run();
      };
      const result = measured ? await writeBrandEvidence(env, workspaceId, row, write) : await write(row.evidence_json ?? null);
      if (runChanges(result) !== 1) continue;
      stats.checked++;
      if (fireEvents && persist.dns_resolves === 1 && !wasResolving) {
        const rl = await env.cybermeters_db
          .prepare(`SELECT risk_level FROM workspace_brand_assets a
                     WHERE id = ? AND workspace_id = ?
                       AND EXISTS (
                             SELECT 1
                               FROM workspaces w
                               JOIN workspace_domains wd ON wd.workspace_id = w.id
                               JOIN domains d ON d.id = wd.domain_id
                              WHERE w.id = a.workspace_id
                                AND w.deleted_at IS NULL
                                AND lower(d.domain) = lower(a.domain)
                           )`)
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
  const recheckAfterMs = rest.recheckAfterMs ?? BRAND_DNS_RECHECK_AFTER_MS;
  const staleBefore = new Date(Date.now() - recheckAfterMs).toISOString();
  let rows;
  try {
    // A workspace is due when any candidate is unchecked OR stale past the
    // weekly recheck window: the same predicate selectBrandCandidatesSql()
    // applies inside the workspace. Selecting on unchecked alone meant a fully
    // checked workspace was never visited again, so a lookalike registered
    // after its first check was never re-detected (21 Oct 2026: every
    // production candidate was last checked in July). Workspaces with
    // unchecked candidates go first, then the longest-waiting, so one large
    // backlog cannot starve the rest.
    rows = await env.cybermeters_db.prepare(
      `SELECT a.workspace_id,
              SUM(a.dns_resolves IS NULL) AS unchecked,
              MIN(COALESCE(a.last_checked_at, '')) AS oldest_check
         FROM workspace_brand_assets a
         JOIN workspaces w
           ON w.id = a.workspace_id AND w.deleted_at IS NULL
         JOIN workspace_domains wd ON wd.workspace_id = w.id
         JOIN domains d
           ON d.id = wd.domain_id AND lower(d.domain) = lower(a.domain)
        WHERE (a.dns_resolves IS NULL OR a.last_checked_at IS NULL OR a.last_checked_at < ?)
          AND (classification IS NULL OR classification NOT IN ${CLOSED_CLASSIFICATIONS})
        GROUP BY a.workspace_id
        ORDER BY (unchecked > 0) DESC, oldest_check ASC, a.workspace_id ASC
        LIMIT ?`
    ).bind(staleBefore, Math.max(1, workspacesPerTick)).all();
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
