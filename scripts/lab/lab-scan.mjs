// Run the real scan engine against a lab world and measure what it found.
//
// The engine, the schema and the migrations all come from `root`, so the same
// worlds can be replayed against an older checkout of the repository and the
// two measurements compared line for line. Storage is an in-memory SQLite copy
// of the full schema; R2 is a map; the network is the lab world.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";
import { createLabWorld, summarizeRequests } from "./lab-world.mjs";

const DAY_MS = 86_400_000;
// Consecutive lab scans are 25 hours apart: more than a day, so day-based
// windows (removal confirmation, 24-hour caches) always see a new day.
export const LAB_SCAN_SPACING_MS = DAY_MS + 3_600_000;

// Lab time: every scan starts at its own simulated instant and time then runs
// at wall speed, so timeouts behave normally while stored timestamps, history
// windows and rotation order follow the simulated calendar. Both Date.now()
// and `new Date()` follow it.
export function labClock() {
  const RealDate = Date;
  let base = RealDate.now();
  let wallBase = RealDate.now();
  const now = () => base + (RealDate.now() - wallBase);
  class LabDate extends RealDate {
    constructor(...args) { if (args.length === 0) super(now()); else super(...args); }
    static now() { return now(); }
  }
  globalThis.Date = LabDate;
  return {
    set(at) { base = at; wallBase = RealDate.now(); },
    real: () => RealDate.now(),
    restore() { globalThis.Date = RealDate; },
  };
}

export async function buildLabDb(root) {
  const { splitStatements, isToleratedStatement } = await import(
    pathToFileURL(path.join(root, "scripts", "lib", "migration-apply-tolerated.js")).href);
  const db = new DatabaseSync(":memory:");
  db.exec(fs.readFileSync(path.join(root, "database", "schema.sql"), "utf8"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    const raw = fs.readFileSync(path.join(root, "database", "migrations", file), "utf8");
    const sha = crypto.createHash("sha256").update(raw).digest("hex");
    for (const statement of splitStatements(raw)) {
      try { db.exec(statement); } catch (error) { if (!isToleratedStatement(file, sha, statement, error.message)) throw error; }
    }
  }
  return db;
}

// D1 semantics that matter here: bound statements, and batches that commit or
// roll back as one unit.
export function labD1(db, counters = { reads: 0, writes: 0 }) {
  const statement = (sql, args = []) => ({
    __sql: sql,
    __args: args,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      counters.reads++;
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => { counters.reads++; return { results: db.prepare(sql).all(...args), success: true, meta: {} }; },
    run: async () => {
      counters.writes++;
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid || 0) } };
    },
    raw: async () => { counters.reads++; return db.prepare(sql).all(...args).map((row) => Object.values(row)); },
  });
  return {
    prepare: (sql) => statement(sql),
    async batch(statements) {
      db.exec("BEGIN");
      try {
        const results = [];
        for (const entry of statements) {
          const read = /^\s*(?:select|with)\b/i.test(entry.__sql);
          if (read) { counters.reads++; results.push({ results: db.prepare(entry.__sql).all(...entry.__args), success: true, meta: {} }); }
          else {
            counters.writes++;
            const r = db.prepare(entry.__sql).run(...entry.__args);
            results.push({ success: true, meta: { changes: Number(r.changes), last_row_id: Number(r.lastInsertRowid || 0) } });
          }
        }
        db.exec("COMMIT");
        return results;
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
    },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

export function labR2(counters = { reads: 0, writes: 0 }) {
  const store = new Map();
  const object = (key, body) => ({
    key,
    size: body.length,
    text: async () => body,
    json: async () => JSON.parse(body),
    arrayBuffer: async () => new TextEncoder().encode(body).buffer,
  });
  return {
    store,
    async get(key) { counters.reads++; const body = store.get(String(key)); return body == null ? null : object(String(key), body); },
    async head(key) { counters.reads++; const body = store.get(String(key)); return body == null ? null : { key: String(key), size: body.length }; },
    async put(key, value, options = {}) {
      counters.writes++;
      const body = typeof value === "string" ? value : value instanceof ArrayBuffer ? new TextDecoder().decode(value) : String(value);
      if (options?.onlyIf && (options.onlyIf.etagDoesNotMatch === "*" || options.onlyIf instanceof Headers) && store.has(String(key))) return null;
      store.set(String(key), body);
      return { key: String(key), size: body.length };
    },
    async delete(key) { counters.writes++; store.delete(String(key)); },
    async list({ prefix = "" } = {}) { counters.reads++; return { objects: [...store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })), truncated: false }; },
  };
}

export function seedTenant(db, { userId, workspaceId, domainId, domain, customerList = [], createdAt }) {
  db.prepare("INSERT OR IGNORE INTO users (id, email, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, 'professional', 'active', 1, 0)")
    .run(userId, `${userId}@lab.invalid`, userId);
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id, created_at) VALUES (?, ?, ?, ?)").run(workspaceId, `Lab ${workspaceId}`, userId, createdAt);
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, 'owner')").run(`wm_${workspaceId}`, workspaceId, userId);
  db.prepare("INSERT INTO domains (id, user_id, domain, verification_status, verified_at) VALUES (?, ?, ?, 'verified', ?)").run(domainId, userId, domain, createdAt);
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status, verification_method, verified_at) VALUES (?, ?, 'verified', 'dns_txt', ?)")
    .run(workspaceId, domainId, createdAt);
  if (customerList.length) {
    db.prepare(`INSERT INTO discovery_hostname_lists
        (id, workspace_id, domain_id, status, import_format, hostnames_json, hostname_count, entries_examined,
         out_of_scope_count, rejected_count, truncated, rejected_reasons_json, created_by, created_at)
      VALUES (?, ?, ?, 'active', 'list', ?, ?, ?, 0, 0, 0, '[]', ?, ?)`)
      .run(`dhl_${workspaceId}`, workspaceId, domainId, JSON.stringify(customerList), customerList.length, customerList.length, userId, createdAt);
  }
}

const parse = (value, fallback) => { try { return JSON.parse(value); } catch { return fallback; } };
const sorted = (values) => [...values].sort();

function addressFamilies(addresses) {
  const list = Array.isArray(addresses) ? addresses.map(String) : [];
  return { A: sorted(list.filter((v) => !v.includes(":"))), AAAA: sorted(list.filter((v) => v.includes(":"))) };
}

// What one workspace's inventory says after the scans, against the world's truth.
export function measureInventory(db, world, workspaceId) {
  const rows = db.prepare("SELECT * FROM workspace_assets WHERE workspace_id = ? ORDER BY hostname").all(workspaceId);
  const root = world.domain;
  const found = rows.map((row) => row.hostname).filter((host) => host !== root);
  const truth = world.truth;
  const discoverable = new Set(truth.discoverable);
  const tolerated = new Set([...(truth.unconfirmable || []), ...(truth.hidden || [])]);
  const decoys = new Set(truth.decoys || []);
  const truePositive = found.filter((host) => discoverable.has(host));
  const missed = truth.discoverable.filter((host) => !found.includes(host));
  // Anything listed that the truth does not name as real is a false positive;
  // `decoys` only documents the traps the world set.
  const falsePositive = found.filter((host) => !discoverable.has(host) && !tolerated.has(host));
  const decoysListed = found.filter((host) => decoys.has(host));
  const outOfScope = found.filter((host) => host !== root && !host.endsWith(`.${root}`));
  const families = {};
  for (const [host, expected] of Object.entries(truth.families || {})) {
    const row = rows.find((r) => r.hostname === host);
    const stored = addressFamilies(parse(row?.ip_addresses, []));
    families[host] = {
      found: Boolean(row),
      A: { expected: expected.A, stored: stored.A, ok: Boolean(row) && JSON.stringify(sorted(expected.A || [])) === JSON.stringify(stored.A) },
      AAAA: expected.AAAA === null
        ? { expected: "uncertain", stored: stored.AAAA, ok: Boolean(row) }
        : { expected: expected.AAAA, stored: stored.AAAA, ok: Boolean(row) && JSON.stringify(sorted(expected.AAAA)) === JSON.stringify(stored.AAAA) },
    };
  }
  const sources = {};
  for (const row of rows) sources[row.source] = (sources[row.source] || 0) + 1;
  return {
    stored_assets: rows.length,
    found: found.length,
    expected: truth.discoverable.length,
    true_positive: truePositive.length,
    recall: truth.discoverable.length ? Number((truePositive.length / truth.discoverable.length).toFixed(3)) : null,
    missed: sorted(missed),
    false_positive: sorted(falsePositive),
    decoys_listed: sorted(decoysListed),
    out_of_scope_admitted: sorted(outOfScope),
    families,
    sources,
    rows: rows.map((row) => ({ hostname: row.hostname, source: row.source, ip_addresses: parse(row.ip_addresses, []), lifecycle_state: row.lifecycle_state, last_observation_state: row.last_observation_state, status: row.status })),
  };
}

function scanSummary(db, r2, scanId) {
  const scan = db.prepare("SELECT * FROM scans WHERE id = ?").get(scanId) || {};
  const findings = db.prepare("SELECT finding_slug, severity FROM findings WHERE scan_id = ?").all(scanId);
  const report = parse(r2.store.get(`reports/${scanId}.json`), null);
  const modules = report?.modules || {};
  const sub = modules.subdomains || {};
  const pick = (value, keys) => value ? Object.fromEntries(keys.filter((k) => value[k] !== undefined).map((k) => [k, value[k]])) : null;
  const incompleteModules = Object.entries(modules)
    .filter(([, value]) => value && typeof value === "object" && (value.incomplete === true || value.error))
    .map(([name, value]) => `${name}:${value.incomplete_reason || value.outcome || (value.error ? "error" : "incomplete")}`)
    .sort();
  return {
    status: scan.status ?? null,
    quality: scan.scan_quality ?? null,
    score: scan.score ?? null,
    findings: findings.length,
    finding_types: sorted(new Set(findings.map((f) => f.finding_slug).filter(Boolean))),
    report_stored: Boolean(report),
    incomplete_modules: incompleteModules,
    discovery: {
      referenced: pick(sub.referenced_hostnames, ["executed", "candidates_found", "checked", "not_checked", "not_found", "no_address", "lookup_failed", "incomplete_reason"]),
      customer: pick(sub.customer_hostnames, ["executed", "listed", "checked", "not_asked", "not_found", "no_address", "lookup_failed", "incomplete_reason"]),
      depth: sub.discovery_depth ? { executed: sub.discovery_depth.executed, not_asked: sub.discovery_depth.not_asked, wordlist_checked: sub.discovery_depth.wordlist?.checked, variants_checked: sub.discovery_depth.variants?.checked, nsec: sub.discovery_depth.nsec?.outcome, incomplete_reason: sub.discovery_depth.incomplete_reason } : null,
      page_references: pick(sub.page_references, ["executed", "candidates_found", "checked", "not_checked", "incomplete_reason"]),
      wildcard_dns: sub.wildcard_dns ?? null,
    },
    outside_data_modules: {
      cve_intelligence: modules.cve_intelligence ? pick(modules.cve_intelligence, ["cve_coverage", "outcome", "incomplete_reason", "total_cves", "epss_status"]) : null,
      known_exploited_vulnerabilities: modules.known_exploited_vulnerabilities ? pick(modules.known_exploited_vulnerabilities, ["catalogue_source", "error", "matched", "incomplete_reason"]) : null,
      whois_intelligence: modules.whois_intelligence ? pick(modules.whois_intelligence, ["source", "error", "incomplete_reason"]) : null,
    },
    check_pack: report?.check_pack ?? modules.check_pack ?? null,
  };
}

/**
 * Run `scans` consecutive scans of one world for one tenant. Returns the
 * inventory measurement after the last scan, a summary of every scan and the
 * request accounting split per scan.
 */
export async function runLabWorld({ root, world, egress = "open", scans = 2, startAt = "2026-10-01T09:00:00.000Z", tenant = "a", quiet = true }) {
  const db = await buildLabDb(root);
  const counters = { reads: 0, writes: 0 };
  const r2Counters = { reads: 0, writes: 0 };
  const r2 = labR2(r2Counters);
  const lab = createLabWorld(world, { egress, root });
  const { runScanEngine } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js")).href);
  const ids = { userId: `usr_${tenant}`, workspaceId: `ws_${tenant}`, domainId: `dom_${tenant}` };
  seedTenant(db, { ...ids, domain: world.domain, customerList: world.customerList || [], createdAt: startAt });
  const env = {
    cybermeters_db: labD1(db, counters),
    cybermeters_reports: r2,
    NETWORK_PROBE: lab.probe,
    SCAN_CAPACITY_MODE: "legacy",
    SCAN_SUBREQUEST_LIMIT: "200",
    APP_VERSION: "discovery-lab",
    RESEND_API_KEY: "",
    FRONTEND_URL: "https://app.cybermeters.com",
  };
  const realFetch = globalThis.fetch;
  const clock = labClock();
  globalThis.fetch = lab.fetch;
  lab.setClock(() => Date.now());
  // The engine logs operational lines; keep them out of the measurement output.
  const realConsole = { log: console.log, info: console.info, warn: console.warn, error: console.error };
  const engineLog = [];
  if (quiet) for (const level of Object.keys(realConsole)) console[level] = (...parts) => engineLog.push([level, parts.map(String).join(" ")]);
  const runs = [];
  try {
    for (let i = 0; i < scans; i++) {
      const at = Date.parse(startAt) + i * LAB_SCAN_SPACING_MS;
      clock.set(at);
      const wallStart = clock.real();
      const scanId = `scan_${tenant}_${i + 1}`;
      db.prepare("INSERT INTO scans (id, workspace_id, domain_id, domain, status, created_at) VALUES (?, ?, ?, ?, 'queued', ?)")
        .run(scanId, ids.workspaceId, ids.domainId, world.domain, new Date(at).toISOString());
      const logStart = lab.log.length;
      const before = { ...counters }, r2Before = { ...r2Counters };
      let error = null;
      try {
        await runScanEngine(scanId, ids.domainId, ids.workspaceId, world.domain, env, {
          now: () => Date.now(),
          executionContext: "queue",
          trigger: "manual",
        });
      } catch (caught) { error = caught?.message || String(caught); }
      runs.push({
        scan_id: scanId,
        at: new Date(at).toISOString(),
        elapsed_ms: clock.real() - wallStart,
        error,
        ...scanSummary(db, r2, scanId),
        requests: summarizeRequests(lab.log.slice(logStart)),
        storage: { d1_reads: counters.reads - before.reads, d1_writes: counters.writes - before.writes, r2_reads: r2Counters.reads - r2Before.reads, r2_writes: r2Counters.writes - r2Before.writes },
      });
    }
  } finally {
    globalThis.fetch = realFetch;
    clock.restore();
    Object.assign(console, realConsole);
  }
  return {
    world: world.name,
    domain: world.domain,
    egress,
    scans: runs,
    inventory: measureInventory(db, world, ids.workspaceId),
    unexpected_hosts: sorted(new Set(lab.log.filter((e) => e.kind === "unexpected").map((e) => e.host))),
    engine_log: engineLog,
    db,
    r2,
    log: lab.log,
  };
}
