// ── Customer hostname lists (migration 117) ──────────────────────────────────
// A workspace admin may list hostnames under a verified domain — a plain list,
// a CSV with a hostname column or a DNS zone file. Only in-scope names are
// kept (at most 200); the uploaded text is never stored. Every durable scan
// asks DNS about each listed name (A and AAAA), and a name joins discovery only
// when DNS answers for it: a list is a set of candidates, never a set of
// findings.
import { dnsQuery } from "./dns.js";
import { DISCOVERY_IMPORT_LIMITS, importDiscoveryInventory } from "./discovery-inventory-import.js";
import { classifyHostname, normalizeHostname } from "./hostname-candidates.js";
import { confirmationOf, confirmedHost, lookupNames, tallyConfirmation, wildcardAddressSet } from "./discovery-confirmation.js";
import { createId } from "../lib/util.js";

export const HOSTNAME_LIST_VERSION = "customer-hostnames-v1";
export const HOSTNAME_LIST_ASSET_SOURCE = "customer_list";
export const HOSTNAME_LIST_FORMATS = Object.freeze(["list", "csv", "zone"]);
export const HOSTNAME_LIST_LIMITS = Object.freeze({
  maxHostnames: DISCOVERY_IMPORT_LIMITS.maxCandidates,
  maxInputBytes: DISCOVERY_IMPORT_LIMITS.maxInputBytes,
  batchSize: 25,
  softBudgetMs: 8_000,
  budgetMs: 15_000,
});

export class HostnameListError extends Error {
  constructor(code, status = 400, detail = null) {
    super(code);
    this.code = code;
    this.status = status;
    this.detail = detail;
  }
}

const parseList = (value) => {
  try {
    const list = JSON.parse(value || "[]");
    return Array.isArray(list) ? list.filter((item) => typeof item === "string") : [];
  } catch { return []; }
};

// Names kept from stored text are re-checked against the domain on every read,
// so a stored row can never widen the scope it was saved under.
function inScope(hostnames, domain) {
  const root = normalizeHostname(domain);
  if (!root) return [];
  const names = new Set();
  for (const value of hostnames) {
    const item = classifyHostname(value, root);
    if (item.kind === "candidate") names.add(item.hostname);
  }
  return [...names].sort().slice(0, HOSTNAME_LIST_LIMITS.maxHostnames);
}

/** Parse uploaded text. Throws `unsupported_format` or `input_too_large`. */
export function parseHostnameList(text, { format, domain }) {
  if (!HOSTNAME_LIST_FORMATS.includes(format)) throw new HostnameListError("unsupported_format");
  if (typeof text !== "string") throw new HostnameListError("unsupported_input");
  if (new TextEncoder().encode(text).byteLength > HOSTNAME_LIST_LIMITS.maxInputBytes) {
    throw new HostnameListError("input_too_large", 413);
  }
  const result = importDiscoveryInventory(text, { format, domain });
  const hostnames = inScope(result.candidates.map((candidate) => candidate.hostname), domain);
  return {
    hostnames,
    summary: {
      format,
      accepted: hostnames.length,
      entries_examined: result.entries_examined,
      out_of_scope: result.out_of_scope_count,
      rejected: result.rejected_count,
      truncated: result.truncated === true,
      rejected_reasons: result.rejected_reasons,
    },
  };
}

export function hostnameListView(row, domain) {
  if (!row) return null;
  const hostnames = inScope(parseList(row.hostnames_json), domain);
  return {
    format: row.import_format,
    hostnames,
    hostname_count: hostnames.length,
    entries_examined: row.entries_examined,
    out_of_scope: row.out_of_scope_count,
    rejected: row.rejected_count,
    truncated: row.truncated === 1,
    rejected_reasons: parseList(row.rejected_reasons_json),
    saved_at: row.created_at,
  };
}

// The predicate every write repeats: a live workspace and a verified link.
const LIVE_VERIFIED = `EXISTS (SELECT 1 FROM workspaces w WHERE w.id = ? AND w.deleted_at IS NULL)
  AND EXISTS (SELECT 1 FROM workspace_domains wd WHERE wd.workspace_id = ? AND wd.domain_id = ?
              AND wd.verification_status = 'verified' AND wd.verified_at IS NOT NULL)`;

/**
 * Save a parsed list as the domain's active list. The previous list is
 * superseded in the same batch; nothing is written unless the workspace is
 * live and the domain is still verified in it.
 */
export async function saveHostnameList(db, { workspaceId, domainId, domain, userId, parsed, now = new Date().toISOString() }) {
  const id = createId("dhl");
  const { summary, hostnames } = parsed;
  const supersede = db.prepare(
    `UPDATE discovery_hostname_lists SET status = 'superseded', ended_at = ?, ended_by = ?
      WHERE workspace_id = ? AND domain_id = ? AND status = 'active' AND ${LIVE_VERIFIED}`)
    .bind(now, userId, workspaceId, domainId, workspaceId, workspaceId, domainId);
  const insert = db.prepare(
    `INSERT INTO discovery_hostname_lists
       (id, workspace_id, domain_id, status, import_format, hostnames_json, hostname_count,
        entries_examined, out_of_scope_count, rejected_count, truncated, rejected_reasons_json,
        created_by, created_at)
     SELECT ?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE ${LIVE_VERIFIED}`)
    .bind(id, workspaceId, domainId, summary.format, JSON.stringify(hostnames), hostnames.length,
      summary.entries_examined, summary.out_of_scope, summary.rejected, summary.truncated ? 1 : 0,
      JSON.stringify(summary.rejected_reasons), userId, now, workspaceId, workspaceId, domainId);
  // The audit selects the inserted row, so a refused save leaves no event.
  const audit = db.prepare(
    `INSERT INTO audit_events (id, workspace_id, user_id, actor_type, event_type, entity_type, entity_id, description, metadata_json, created_at)
     SELECT ?, ?, ?, 'customer', 'discovery_hostname_list_saved', 'discovery_hostname_list', ?, ?, ?, ?
      WHERE EXISTS (SELECT 1 FROM discovery_hostname_lists WHERE id = ? AND workspace_id = ?)`)
    .bind(createId("audit"), workspaceId, userId, id, `Hostname list saved for ${domain}`,
      JSON.stringify({ domain, format: summary.format, hostname_count: hostnames.length,
        out_of_scope: summary.out_of_scope, rejected: summary.rejected, truncated: summary.truncated }),
      now, id, workspaceId);
  const results = await db.batch([supersede, insert, audit]);
  if (results[1]?.meta?.changes !== 1) throw new HostnameListError("domain_not_verified", 403);
  return db.prepare("SELECT * FROM discovery_hostname_lists WHERE id = ? AND workspace_id = ?").bind(id, workspaceId).first();
}

/** Mark the active list cleared. Returns whether a list was cleared. */
export async function clearHostnameList(db, { workspaceId, domainId, domain, userId, now = new Date().toISOString() }) {
  const active = await db.prepare(
    "SELECT id FROM discovery_hostname_lists WHERE workspace_id = ? AND domain_id = ? AND status = 'active'")
    .bind(workspaceId, domainId).first();
  if (!active) return false;
  const clear = db.prepare(
    `UPDATE discovery_hostname_lists SET status = 'cleared', ended_at = ?, ended_by = ?
      WHERE id = ? AND workspace_id = ? AND status = 'active'`)
    .bind(now, userId, active.id, workspaceId);
  const audit = db.prepare(
    `INSERT INTO audit_events (id, workspace_id, user_id, actor_type, event_type, entity_type, entity_id, description, metadata_json, created_at)
     SELECT ?, ?, ?, 'customer', 'discovery_hostname_list_cleared', 'discovery_hostname_list', ?, ?, ?, ?
      WHERE EXISTS (SELECT 1 FROM discovery_hostname_lists WHERE id = ? AND workspace_id = ? AND status = 'cleared')`)
    .bind(createId("audit"), workspaceId, userId, active.id, `Hostname list cleared for ${domain}`,
      JSON.stringify({ domain }), now, active.id, workspaceId);
  const results = await db.batch([clear, audit]);
  return results[0]?.meta?.changes === 1;
}

/** Every verified domain of the workspace, with its active list or null. */
export async function listHostnameLists(db, workspaceId) {
  const rows = await db.prepare(
    `SELECT d.domain, l.*
       FROM workspace_domains wd
       JOIN domains d ON d.id = wd.domain_id
       LEFT JOIN discovery_hostname_lists l
         ON l.workspace_id = wd.workspace_id AND l.domain_id = wd.domain_id AND l.status = 'active'
      WHERE wd.workspace_id = ? AND wd.verification_status = 'verified' AND wd.verified_at IS NOT NULL
      ORDER BY d.domain`).bind(workspaceId).all();
  return (rows.results || []).map((row) => ({
    domain: row.domain,
    list: row.id ? hostnameListView(row, row.domain) : null,
  }));
}

/** The active list a scan of this workspace domain checks; [] when none. */
export async function loadActiveHostnames(env, { workspaceId, domainId, domain }) {
  if (!env?.cybermeters_db || !workspaceId || !domainId) return [];
  try {
    const row = await env.cybermeters_db.prepare(
      `SELECT l.hostnames_json FROM discovery_hostname_lists l
         JOIN workspace_domains wd ON wd.workspace_id = l.workspace_id AND wd.domain_id = l.domain_id
         JOIN workspaces w ON w.id = l.workspace_id AND w.deleted_at IS NULL
        WHERE l.workspace_id = ? AND l.domain_id = ? AND l.status = 'active'
          AND wd.verification_status = 'verified' AND wd.verified_at IS NOT NULL`)
      .bind(workspaceId, domainId).first();
    return row ? inScope(parseList(row.hostnames_json), domain) : [];
  } catch (error) {
    console.error("[discovery-hostname-list] load failed:", error?.message);
    return null;
  }
}

// The step did not run. With no list there is nothing to check, which is not
// a gap; every other reason leaves listed names unchecked and says so.
export function customerHostnamesNotExecuted(reason, listed = 0) {
  const gap = reason !== "no_list";
  return {
    version: HOSTNAME_LIST_VERSION,
    executed: false,
    reason,
    listed,
    confirmed: [],
    incomplete: gap,
    incomplete_reason: gap ? reason : null,
  };
}

/**
 * Ask DNS about each listed name not already discovered. Listed names are the
 * customer's own statement, not guesses: a wildcard-shaped answer is flagged,
 * not filtered.
 */
export async function confirmListedHostnames(domain, hostnames, {
  exclude = [],
  wildcardAddresses = [],
  wildcardIpv6Addresses = [],
  budget = null,
  accounting = null,
  cache = null,
  signal = null,
  clock = Date.now,
  lookup = (name, type) => dnsQuery(name, type, { accounting, cache, signal }),
} = {}) {
  const listed = inScope(Array.isArray(hostnames) ? hostnames : [], domain);
  const known = new Set((Array.isArray(exclude) ? exclude : []).map((host) => normalizeHostname(host)).filter(Boolean));
  const pending = listed.filter((hostname) => !known.has(hostname));
  const { observations, unasked_time: unaskedTime, unasked_budget: unaskedBudget } = await lookupNames(pending, lookup, {
    clock,
    deadlineAt: clock() + HOSTNAME_LIST_LIMITS.softBudgetMs,
    batchSize: HOSTNAME_LIST_LIMITS.batchSize,
    budget,
    source: "customer_hostnames",
    mode: "parallel",
  });
  const wildcardSet = wildcardAddressSet(wildcardAddresses, wildcardIpv6Addresses);
  const confirmed = [];
  const counts = {};
  for (const observation of observations) {
    const confirmation = confirmationOf(observation, { wildcardSet, filterWildcard: false });
    tallyConfirmation(counts, confirmation);
    if (confirmation.status === "confirmed") {
      confirmed.push(confirmedHost(observation.hostname, confirmation, { source: HOSTNAME_LIST_ASSET_SOURCE }));
    }
  }
  const reasons = [];
  if (unaskedTime > 0) reasons.push("time_budget_reached");
  if (unaskedBudget > 0) reasons.push("question_budget_reached");
  if ((counts.lookup_failed || 0) > 0) reasons.push("lookup_failed");
  return {
    version: HOSTNAME_LIST_VERSION,
    executed: true,
    reason: null,
    listed: listed.length,
    already_discovered: listed.length - pending.length,
    checked: observations.length,
    not_asked: unaskedTime + unaskedBudget,
    confirmed,
    not_found: counts.not_found || 0,
    no_address: counts.no_address || 0,
    lookup_failed: counts.lookup_failed || 0,
    families: counts.families || { ipv4_only: 0, ipv6_only: 0, dual_stack: 0, alias_only: 0 },
    incomplete: reasons.length > 0,
    incomplete_reason: reasons[0] ?? null,
    ...(reasons.length > 1 ? { incomplete_reasons: reasons } : {}),
  };
}
