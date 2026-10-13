// Load lab: many customers' scans through the real scheduler, the real scan
// route, the real queue consumer and the real scan engine, on a simulated
// clock.
//
// What runs for real, from `root`: the hourly cron (every task in it, including
// scheduled-scan selection, eligibility, admission and the interrupted-scan
// recovery), POST /api/scan through the Worker's own fetch handler with seeded
// sessions, the queue consumer (claim, duplicate handling, retries, scheduled
// settlement), the dead-letter observer, and the scan engine itself against a
// generated lab world per domain. Storage is an in-memory SQLite copy of the
// full schema whose SQL clock ('now', CURRENT_TIMESTAMP) follows the simulated
// clock, so rate-limit windows, recovery ages and monthly quotas all move with it.
//
// What is modelled, and says so: how long a scan takes in production (sampled
// from a distribution; the lab network answers at once), and the queue service
// (FIFO delivery to `maxConcurrency` consumers, retries, a dead-letter queue,
// duplicate deliveries and killed consumer invocations at chosen rates).
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { pathToFileURL } from "node:url";
import zlib from "node:zlib";
import { createLabWorld, summarizeRequests, EMAIL_PROVIDER_HOST } from "./lab-world.mjs";

const HOUR = 3_600_000;
const DAY = 24 * HOUR;
const MINUTE = 60_000;

// ── Deterministic randomness ─────────────────────────────────────────────────
export function rng(seed = 1) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6D2B79F5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const normal = () => {
    const u = Math.max(next(), 1e-12), v = next();
    return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
  };
  return { next, normal, int: (lo, hi) => lo + Math.floor(next() * (hi - lo + 1)), pick: (list) => list[Math.floor(next() * list.length)] };
}

// ── Simulated clock ──────────────────────────────────────────────────────────
// Frozen between events. While the scan engine runs it flows at wall speed from
// the event's instant, so the engine's own deadlines behave as in the lab.
export function virtualClock(startMs) {
  const RealDate = Date;
  let base = startMs;
  let wallBase = null;
  const now = () => (wallBase === null ? base : base + (RealDate.now() - wallBase));
  class VirtualDate extends RealDate {
    constructor(...args) { if (args.length === 0) super(now()); else super(...args); }
    static now() { return now(); }
  }
  globalThis.Date = VirtualDate;
  return {
    now,
    set(ms) { base = Math.max(ms, now()); wallBase = null; },
    flow() { base = now(); wallBase = RealDate.now(); },
    freeze() { base = now(); wallBase = null; },
    real: () => RealDate.now(),
    restore() { globalThis.Date = RealDate; },
  };
}

// SQLite's clock follows the simulated one: every 'now' and CURRENT_TIMESTAMP
// the product writes or compares goes through vnow().
export function rewriteSqlTime(sql) {
  return String(sql)
    .replace(/DEFAULT\s+CURRENT_TIMESTAMP/gi, "DEFAULT (datetime(vnow()))")
    .replace(/\bCURRENT_TIMESTAMP\b/gi, "datetime(vnow())")
    .replace(/'now'/gi, "vnow()");
}

export async function buildLoadDb(root, clock) {
  const { splitStatements, isToleratedStatement } = await import(
    pathToFileURL(path.join(root, "scripts", "lib", "migration-apply-tolerated.js")).href);
  const db = new DatabaseSync(":memory:");
  db.function("vnow", { deterministic: false }, () => new Date(clock.now()).toISOString().replace("T", " ").slice(0, 23));
  db.exec(rewriteSqlTime(fs.readFileSync(path.join(root, "database", "schema.sql"), "utf8")));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    const raw = fs.readFileSync(path.join(root, "database", "migrations", file), "utf8");
    const sha = crypto.createHash("sha256").update(raw).digest("hex");
    for (const statement of splitStatements(raw)) {
      try { db.exec(rewriteSqlTime(statement)); } catch (error) { if (!isToleratedStatement(file, sha, statement, error.message)) throw error; }
    }
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

// D1 stand-in: bound statements, all-or-nothing batches, and every operation
// counted against whatever the harness is doing at that moment (meter.tag).
export function meteredD1(db, meter) {
  const cache = new Map();
  const prep = (sql) => {
    let statement = cache.get(sql);
    if (!statement) {
      statement = db.prepare(rewriteSqlTime(sql));
      if (cache.size >= 2000) cache.delete(cache.keys().next().value);
      cache.set(sql, statement);
    }
    return statement;
  };
  const statement = (sql, args = []) => ({
    __sql: sql,
    __args: args,
    bind: (...bound) => statement(sql, bound),
    first: async (column) => { meter.read(); const row = prep(sql).get(...args) ?? null; return column && row ? row[column] : row; },
    all: async () => { meter.read(); return { results: prep(sql).all(...args), success: true, meta: {} }; },
    run: async () => {
      meter.write();
      const result = prep(sql).run(...args);
      return { success: true, meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid || 0) } };
    },
    raw: async () => { meter.read(); return prep(sql).all(...args).map((row) => Object.values(row)); },
  });
  return {
    prepare: (sql) => statement(sql),
    async batch(statements) {
      db.exec("BEGIN");
      try {
        const results = [];
        for (const entry of statements) {
          if (/^\s*(?:select|with)\b/i.test(entry.__sql)) { meter.read(); results.push({ results: prep(entry.__sql).all(...entry.__args), success: true, meta: {} }); }
          else {
            meter.write();
            const r = prep(entry.__sql).run(...entry.__args);
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
    async exec(sql) { meter.write(); db.exec(rewriteSqlTime(sql)); return { count: 0, duration: 0 }; },
  };
}

// R2 stand-in with the lab's semantics (scripts/lab/lab-scan.mjs labR2), holding
// objects compressed: a run stores thousands of reports of a few hundred
// kilobytes each.
export function compressedR2(counters = { reads: 0, writes: 0 }) {
  const store = new Map();
  const sizes = new Map();
  const bodyOf = (key) => { const packed = store.get(String(key)); return packed == null ? null : zlib.inflateRawSync(packed).toString("utf8"); };
  const object = (key, body) => ({
    key,
    size: Buffer.byteLength(body),
    text: async () => body,
    json: async () => JSON.parse(body),
    arrayBuffer: async () => new TextEncoder().encode(body).buffer,
  });
  return {
    store,
    sizes,
    async get(key) { counters.reads++; const body = bodyOf(key); return body == null ? null : object(String(key), body); },
    async head(key) { counters.reads++; return store.has(String(key)) ? { key: String(key), size: sizes.get(String(key)) } : null; },
    async put(key, value, options = {}) {
      counters.writes++;
      const body = typeof value === "string" ? value
        : value instanceof ArrayBuffer || ArrayBuffer.isView(value) ? new TextDecoder().decode(value) : String(value);
      if (options?.onlyIf && (options.onlyIf.etagDoesNotMatch === "*" || options.onlyIf instanceof Headers) && store.has(String(key))) return null;
      store.set(String(key), zlib.deflateRawSync(Buffer.from(body, "utf8"), { level: 1 }));
      sizes.set(String(key), Buffer.byteLength(body));
      return { key: String(key), size: Buffer.byteLength(body) };
    },
    async delete(key) { counters.writes++; store.delete(String(key)); sizes.delete(String(key)); },
    async list({ prefix = "" } = {}) { counters.reads++; return { objects: [...store.keys()].filter((k) => k.startsWith(prefix)).map((key) => ({ key })), truncated: false }; },
  };
}

export function meter() {
  const counts = {};
  const bucket = (tag) => (counts[tag] ||= { reads: 0, writes: 0 });
  return {
    tag: "idle",
    counts,
    read() { bucket(this.tag).reads++; },
    write() { bucket(this.tag).writes++; },
    total() { return Object.values(counts).reduce((sum, c) => ({ reads: sum.reads + c.reads, writes: sum.writes + c.writes }), { reads: 0, writes: 0 }); },
  };
}

// ── Lab worlds for the population ────────────────────────────────────────────
const page = (title, extra = "") => `<!doctype html><html><head><title>${title}</title></head><body>${extra}</body></html>`;

// A small organisation's domain. Variants add what real estates have: both
// address families, an exposed management tool, a name whose DNS fails, a host
// that never answers — and two that change on the second day: a management
// tool that appears, and a website that moves to a new address.
export function loadWorld(domain, variant = "plain", n = 0, day = 0) {
  const at = (label) => (label ? `${label}.${domain}` : domain);
  const ip = (k) => `34.${100 + (Math.floor(n / 250) % 100)}.${n % 250}.${k}`;
  const v6 = (k) => `2a05:d014:${(n + 1).toString(16)}::${k}`;
  const zones = {
    [at()]: { SOA: true, A: [ip(1)], MX: ["10 " + at("mail")], NS: [at("ns1")], TXT: ["v=spf1 mx -all"] },
    [at("_dmarc")]: { TXT: ["v=DMARC1; p=quarantine"] },
    [at("www")]: { CNAME: at() },
    [at("mail")]: { A: [ip(2)] },
    [at("ns1")]: { A: [ip(3)] },
    [at("app")]: { A: [ip(4)] },
  };
  const sites = {
    [at()]: {
      routes: {
        "/": {
          status: 200,
          headers: { "strict-transport-security": "max-age=31536000", "content-security-policy": `default-src 'self'; connect-src https://${at("app")}` },
          body: page(domain, `<a href="https://${at("www")}/about">About</a>`),
        },
      },
      fallback: { status: 404, body: page("Not found") },
    },
    [at("www")]: { fallback: { status: 301, headers: { location: `https://${domain}/` } } },
    [at("app")]: { fallback: { status: 200, body: page("App") } },
    [at("mail")]: { refuse: true },
    [at("ns1")]: { refuse: true },
  };
  const faults = {};
  if (variant === "dual") {
    zones[at()].AAAA = [v6(1)];
    zones[at("status")] = { AAAA: [v6(6)] };
    sites[at("status")] = { fallback: { status: 200, body: page("Status") } };
  }
  if (variant === "admin" || (variant === "late_admin" && day >= 1)) {
    zones[at("admin")] = { A: [ip(20)] };
    sites[at("admin")] = { fallback: { status: 200, body: page("phpMyAdmin", '<form><input type="password" name="pma_password"></form>') } };
  }
  if (variant === "flaky") {
    zones[at("api")] = { A: [ip(8)] };
    faults[at("api")] = { "*": "servfail" };
  }
  if (variant === "slow") {
    zones[at("api")] = { A: [ip(9)] };
    sites[at("api")] = { timeout: true };
  }
  if (variant === "moved" && day >= 1) zones[at("app")].A = [ip(44)];
  return {
    name: `load-${n}`,
    domain,
    zones,
    faults,
    sites,
    defaultSite: { status: 404, body: "" },
    tls: { [domain]: { days: 70 + (n % 40), dnsNames: [domain, at("www")] } },
  };
}

const VARIANTS = ["plain", "plain", "late_admin", "plain", "plain", "plain", "plain", "dual", "admin", "plain", "dual", "plain", "moved", "plain", "admin", "plain", "plain", "flaky", "plain", "slow"];

// ── Population ───────────────────────────────────────────────────────────────
// One managed-service provider with many client workspaces, small businesses on
// the Professional and Starter plans, a few Business accounts — and optionally
// schedules that can never run any more (verification removed by the customer,
// trial ended), which a long-lived service accumulates.
export function buildPopulation({
  startMs,
  seed = 7,
  msp = { workspaces: 40, domainsPerWorkspace: 10 },
  professional = 100,
  starter = 40,
  business = 10,
  stuckRevoked = 0,
  stuckExpiredTrial = 0,
} = {}) {
  const random = rng(seed);
  const accounts = [];
  let n = 0;
  const domainFor = (slug) => `cmload-${slug}.co.uk`;
  const addDomain = (workspace, slug, scheduleAt, extra = {}) => {
    const index = n++;
    workspace.domains.push({ id: `dom_${slug}`, domain: domainFor(slug), variant: VARIANTS[index % VARIANTS.length], n: index,
      schedule: scheduleAt == null ? null : { id: `sched_${slug}`, nextRunAt: scheduleAt, frequency: "daily" }, ...extra });
  };
  const account = (id, plan, kind, extra = {}) => {
    // Each customer calls from its own address, as real customers do.
    const ip = `10.${Math.floor(accounts.length / 250) % 250}.${accounts.length % 250}.7`;
    const row = { id, userId: `usr_${id}`, token: `tok_${id}_${crypto.randomBytes(6).toString("hex")}`, ip, plan, kind, workspaces: [], ...extra };
    accounts.push(row);
    return row;
  };
  if (msp) {
    const a = account("msp", "enterprise", "msp");
    // Created together in one sitting, so every client's daily scan falls due
    // at the same moment.
    const due = startMs + 2 * HOUR;
    for (let w = 0; w < msp.workspaces; w++) {
      const ws = { id: `ws_msp_${w}`, domains: [] };
      for (let d = 0; d < msp.domainsPerWorkspace; d++) addDomain(ws, `msp-c${w}-${d}`, due);
      a.workspaces.push(ws);
    }
  }
  for (let i = 0; i < business; i++) {
    const a = account(`biz${i}`, "business", "business");
    const due = startMs + random.int(0, 23) * HOUR + random.int(0, 59) * MINUTE;
    const ws = { id: `ws_biz${i}`, domains: [] };
    for (let d = 0; d < 10; d++) addDomain(ws, `biz${i}-${d}`, due);
    a.workspaces.push(ws);
  }
  for (let i = 0; i < professional; i++) {
    const a = account(`pro${i}`, "professional", "small");
    const ws = { id: `ws_pro${i}`, domains: [] };
    for (let d = 0; d < 3; d++) addDomain(ws, `pro${i}-${d}`, startMs + random.next() * DAY);
    a.workspaces.push(ws);
  }
  for (let i = 0; i < starter; i++) {
    const a = account(`sta${i}`, "starter", "small");
    const ws = { id: `ws_sta${i}`, domains: [] };
    addDomain(ws, `sta${i}-0`, startMs + random.next() * DAY);
    a.workspaces.push(ws);
  }
  // Overdue since before the window opened: they are the oldest due schedules.
  for (let i = 0; i < stuckRevoked; i++) {
    const a = account(`rev${i}`, "professional", "stuck_revoked");
    const ws = { id: `ws_rev${i}`, domains: [] };
    addDomain(ws, `rev${i}-0`, startMs - 3 * DAY + random.next() * DAY, { verification: "failed" });
    a.workspaces.push(ws);
  }
  for (let i = 0; i < stuckExpiredTrial; i++) {
    const a = account(`exp${i}`, "professional", "stuck_trial_expired", { trialEndedMs: startMs - 2 * DAY });
    const ws = { id: `ws_exp${i}`, domains: [] };
    addDomain(ws, `exp${i}-0`, startMs - 2 * DAY + random.next() * DAY);
    a.workspaces.push(ws);
  }
  return accounts;
}

// Manual scan requests: small customers once a working day each, Business
// accounts a few times, and one "scan every client now" from the provider.
// The provider's burst is paced just under the per-IP write budget (60 per five
// minutes), the way a script that respects the API's limits would send it.
export function buildManualDemand(accounts, { startMs, days = 2, seed = 11, mspBurstAt = 10 * HOUR, mspBurstSpacingMs = 5_500 } = {}) {
  const random = rng(seed);
  const requests = [];
  for (const a of accounts) {
    const domains = a.workspaces.flatMap((ws) => ws.domains.map((d) => ({ ws: ws.id, domain: d.domain })));
    if (!domains.length || a.kind.startsWith("stuck")) continue;
    for (let day = 0; day < days; day++) {
      const dayStart = startMs + day * DAY;
      if (a.kind === "small") requests.push({ at: dayStart + 7 * HOUR + random.next() * 12 * HOUR, account: a.id, ...random.pick(domains) });
      if (a.kind === "business") for (let k = 0; k < 5; k++) requests.push({ at: dayStart + 8 * HOUR + random.next() * 10 * HOUR, account: a.id, ...random.pick(domains) });
      if (a.kind === "msp" && day === 0 && mspBurstAt != null) {
        domains.forEach((d, i) => requests.push({ at: dayStart + mspBurstAt + i * mspBurstSpacingMs, account: a.id, ...d, burst: true }));
      }
    }
  }
  return requests.sort((x, y) => x.at - y.at);
}

// ── Seeding ──────────────────────────────────────────────────────────────────
async function seedPopulation(db, accounts, { hashToken, startMs }) {
  const iso = (ms) => new Date(ms).toISOString();
  const created = iso(startMs - 30 * DAY);
  for (const a of accounts) {
    db.prepare("INSERT INTO users (id, email, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, 'active', 1, 0)")
      .run(a.userId, `${a.id}@lab.invalid`, a.id, a.plan);
    db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, '2099-01-01 00:00:00')")
      .run(`sess_${a.id}`, a.userId, await hashToken(a.token));
    if (a.kind === "stuck_trial_expired") {
      db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, trial_end, current_period_end, created_at, updated_at)
        VALUES (?, ?, 'professional', 'trialing', 'trialing', ?, ?, ?, ?)`).run(`sub_${a.id}`, a.userId, iso(a.trialEndedMs), iso(a.trialEndedMs), created, created);
    } else {
      db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, subscription_status, status, current_period_end, created_at, updated_at)
        VALUES (?, ?, ?, 'active', 'active', '2099-01-01T00:00:00.000Z', ?, ?)`).run(`sub_${a.id}`, a.userId, a.plan, created, created);
    }
    for (const ws of a.workspaces) {
      db.prepare("INSERT INTO workspaces (id, name, owner_user_id, created_at) VALUES (?, ?, ?, ?)").run(ws.id, ws.id, a.userId, created);
      db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, 'owner')").run(`wm_${ws.id}`, ws.id, a.userId);
      for (const d of ws.domains) {
        db.prepare("INSERT INTO domains (id, user_id, domain, verification_status, verified_at) VALUES (?, ?, ?, 'verified', ?)").run(d.id, a.userId, d.domain, created);
        db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status, verification_method, verified_at) VALUES (?, ?, ?, 'dns_txt', ?)")
          .run(ws.id, d.id, d.verification || "verified", created);
        if (d.schedule) {
          // Steady state: each schedule last started one period before it falls
          // due — except the stuck ones, which last started before their
          // customer's verification lapsed or trial ended.
          const lastRun = d.verification === "failed" || a.kind === "stuck_trial_expired" ? startMs - 4 * DAY : d.schedule.nextRunAt - DAY;
          db.prepare("INSERT INTO scheduled_scans (id, domain, frequency, enabled, next_run_at, last_run_at, workspace_id, created_at) VALUES (?, ?, ?, 1, ?, ?, ?, ?)")
            .run(d.schedule.id, d.domain, d.schedule.frequency, iso(d.schedule.nextRunAt), iso(lastRun), ws.id, created);
        }
      }
    }
  }
}

// The Worker's cron triggers, read from the measured checkout's wrangler.toml.
// Only the forms this Worker uses are understood: "M * * * *" with M a minute
// or a comma-separated list of minutes.
export function cronFirings(root, startMs, endMs) {
  const toml = fs.readFileSync(path.join(root, "workers", "scan-api", "wrangler.toml"), "utf8").replace(/#[^\n]*/g, "");
  const list = toml.match(/crons\s*=\s*\[([^\]]*)\]/)?.[1] ?? "";
  const crons = [...list.matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  const firings = [];
  for (const cron of crons) {
    const [minutes, ...rest] = cron.trim().split(/\s+/);
    if (rest.join(" ") !== "* * * *" || !/^\d+(,\d+)*$/.test(minutes)) throw new Error(`load lab: cron form not understood: ${cron}`);
    const set = minutes.split(",").map(Number);
    for (let hour = Math.floor(startMs / HOUR) * HOUR; hour <= endMs; hour += HOUR) {
      for (const minute of set) {
        const at = hour + minute * MINUTE;
        if (at >= startMs && at <= endMs) firings.push({ at, cron });
      }
    }
  }
  return firings.sort((a, b) => a.at - b.at);
}

// ── Quantiles ────────────────────────────────────────────────────────────────
export function quantiles(values) {
  const list = values.filter((v) => Number.isFinite(v)).sort((a, b) => a - b);
  if (!list.length) return { n: 0, p50: null, p95: null, max: null, mean: null };
  const q = (p) => list[Math.min(list.length - 1, Math.floor(p * (list.length - 1) + 0.5))];
  return { n: list.length, p50: q(0.5), p95: q(0.95), max: list.at(-1), mean: list.reduce((a, b) => a + b, 0) / list.length };
}

const jain = (xs) => {
  const list = xs.filter((v) => Number.isFinite(v));
  if (!list.length) return null;
  const sum = list.reduce((a, b) => a + b, 0);
  const sq = list.reduce((a, b) => a + b * b, 0);
  return sq === 0 ? 1 : (sum * sum) / (list.length * sq);
};

// ── The run ──────────────────────────────────────────────────────────────────
export async function runLoadLab({
  root,
  startAt = "2026-10-14T00:00:00.000Z",
  days = 2,
  seed = 1,
  population = {},
  demand = {},
  queue: queueOptions = {},
  duration: durationOptions = {},
  progress = null,
} = {}) {
  const startMs = Date.parse(startAt);
  const endMs = startMs + days * DAY;
  const q = { maxConcurrency: 2, maxRetries: 3, deliveryDelayMs: 500, redeliveryDelayMs: 30_000, duplicateRate: 0.02, interruptRate: 0.01, invocationOverheadMs: 300, ...queueOptions };
  const dur = { medianMs: 25_000, sigma: 0.55, minMs: 8_000, maxMs: 120_000, faultFactor: 1.6, ...durationOptions };
  const random = rng(seed);
  const clock = virtualClock(startMs);
  const meterInstance = meter();
  const realConsole = { log: console.log, info: console.info, warn: console.warn, error: console.error, debug: console.debug };
  const realFetch = globalThis.fetch;

  const skips = [];
  const deliveries = [];
  const consoleLines = { total: 0, errors: 0, error_samples: {} };
  const captured = (level) => (...parts) => {
    consoleLines.total++;
    const text = parts.map((p) => (typeof p === "string" ? p : p instanceof Error ? `${p.name}: ${p.message}` : (() => { try { return JSON.stringify(p); } catch { return String(p); } })())).join(" ");
    if (level === "error") {
      consoleLines.errors++;
      // Group by the line's stable head (ids and numbers stripped).
      const head = text.replace(/[0-9a-f]{8,}|\d+/gi, "#").slice(0, 160);
      consoleLines.error_samples[head] = (consoleLines.error_samples[head] || 0) + 1;
    }
    try {
      if (text.startsWith("[scheduled-scan] skipped")) {
        const body = JSON.parse(text.slice("[scheduled-scan] skipped".length).trim());
        skips.push({ at: clock.now(), schedule_id: body.schedule_id, workspace_id: body.workspace_id, reason: body.reason });
      } else if (text.startsWith("{") && text.includes("scheduled_scan_skipped")) {
        const body = JSON.parse(text);
        skips.push({ at: clock.now(), schedule_id: body.schedule_id, workspace_id: body.workspace_id, reason: body.reason });
      } else if (text.startsWith("[scan-dispatch]")) {
        const body = JSON.parse(text.slice("[scan-dispatch]".length).trim());
        deliveries.push({ at: clock.now(), ...body });
      }
    } catch { /* unparsed operational line */ }
  };

  const db = await buildLoadDb(root, clock);
  const r2Counters = { reads: 0, writes: 0 };
  const r2 = compressedR2(r2Counters);
  // Memory: a stored report is a few hundred kilobytes, and a run stores
  // thousands. Each domain keeps its three newest scans' objects — more than
  // the engine reads back — and older ones are dropped from the stand-in.
  const keysByScan = new Map();
  const put = r2.put.bind(r2);
  r2.put = async (key, value, options) => {
    const scanId = String(key).match(/scan_[A-Za-z0-9_-]+?(?=[./]|$)/)?.[0];
    if (scanId) (keysByScan.get(scanId) || keysByScan.set(scanId, new Set()).get(scanId)).add(String(key));
    return put(key, value, options);
  };
  const recentScans = new Map();
  const pruneOlderScans = (workspaceId, domain, scanId) => {
    const key = `${workspaceId}|${domain}`;
    const list = recentScans.get(key) || [];
    list.push(scanId);
    while (list.length > 3) {
      const old = list.shift();
      for (const objectKey of keysByScan.get(old) || []) { r2.store.delete(objectKey); r2.sizes.delete(objectKey); }
      keysByScan.delete(old);
    }
    recentScans.set(key, list);
  };

  const accounts = buildPopulation({ startMs, ...population });
  const manual = buildManualDemand(accounts, { startMs, days, ...demand });
  const accountById = new Map(accounts.map((a) => [a.id, a]));
  const accountByWorkspace = new Map();
  const domainInfo = new Map();
  const scheduleOwner = new Map();
  for (const a of accounts) for (const ws of a.workspaces) {
    accountByWorkspace.set(ws.id, a);
    for (const d of ws.domains) {
      domainInfo.set(d.domain, d);
      if (d.schedule) scheduleOwner.set(d.schedule.id, { account: a, workspace: ws.id, domain: d.domain });
    }
  }

  // One lab world per customer domain; requests are routed by name.
  const labLog = [];
  const worlds = new Map();
  const worldFor = (domain) => {
    const info = domainInfo.get(domain);
    const day = Math.max(0, Math.floor((clock.now() - startMs) / DAY));
    const key = info && (info.variant === "late_admin" || info.variant === "moved") ? `${domain}|${Math.min(day, 1)}` : domain;
    let lab = worlds.get(key);
    if (!lab) {
      lab = createLabWorld(loadWorld(domain, info?.variant, info?.n ?? 0, Math.min(day, 1)), { root, log: labLog });
      lab.setClock(() => Date.now());
      worlds.set(key, lab);
    }
    return lab;
  };
  let currentDomain = null;
  const apexOf = (name) => {
    const labels = String(name || "").toLowerCase().replace(/\.$/, "").split(".");
    for (let i = 0; i < labels.length - 1; i++) {
      const candidate = labels.slice(i).join(".");
      if (domainInfo.has(candidate)) return candidate;
    }
    return null;
  };
  const routedFetch = async (input, init) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    const name = url.searchParams.get("name") || url.hostname;
    const domain = apexOf(name) || currentDomain || (url.hostname === EMAIL_PROVIDER_HOST ? accounts[0]?.workspaces[0]?.domains[0]?.domain : null);
    if (!domain) throw new TypeError(`load lab: no route to ${url.hostname}`);
    return worldFor(domain).fetch(input, init);
  };
  const probe = {
    async fetch(url, init) {
      let host = null;
      try { host = JSON.parse(init?.body || "{}")?.targets?.[0]?.hostname; } catch { host = null; }
      const domain = apexOf(host) || currentDomain;
      return worldFor(domain).probe.fetch(url, init);
    },
  };

  // ── Queue model ───────────────────────────────────────────────────────────
  let messageSeq = 0;
  const ready = [];          // { id, body, readyAt, attempts, firstSentAt, duplicateOf }
  const dlq = [];
  const queueStats = { sent: 0, duplicates_injected: 0, retries: 0, redeliveries_after_kill: 0, dead_lettered: 0 };
  const jobs = new Map();
  const job = (scanId) => {
    let row = jobs.get(scanId);
    if (!row) { row = { scan_id: scanId, deliveries: 0 }; jobs.set(scanId, row); }
    return row;
  };
  const enqueue = (body, readyAt, attempts = 1, firstSentAt = clock.now(), extra = {}) => {
    const message = { id: `msg_${++messageSeq}`, body, readyAt, attempts, firstSentAt, ...extra };
    ready.push(message);
    schedule(readyAt, "ready");
    return message;
  };
  const SCAN_QUEUE = {
    async send(body) {
      queueStats.sent++;
      const now = clock.now();
      const row = job(body.scan_id);
      row.enqueued_at = now;
      row.trigger = body.trigger || "manual";
      row.scheduled_scan_id = body.scheduled_scan_id || null;
      if (row.scheduled_scan_id) {
        // The run's due time is when its schedule first fell due, however
        // many ticks it then waited or was put back.
        row.due_at = dueSince.get(row.scheduled_scan_id) ?? null;
        dueSince.delete(row.scheduled_scan_id);
      }
      row.workspace_id = body.workspace_id;
      row.domain = body.domain;
      row.account = accountByWorkspace.get(body.workspace_id)?.id ?? null;
      enqueue(body, now + q.deliveryDelayMs);
      if (random.next() < q.duplicateRate) {
        queueStats.duplicates_injected++;
        row.duplicate_injected = true;
        enqueue(body, now + q.deliveryDelayMs + random.int(1_000, 60_000), 1, now, { duplicate: true });
      }
    },
  };

  const env = {
    cybermeters_db: meteredD1(db, meterInstance),
    cybermeters_reports: r2,
    SCAN_QUEUE,
    NETWORK_PROBE: probe,
    SCAN_DISPATCH_MODE: "queue",
    SCHEDULED_DISPATCH_MODE: "queue",
    SCAN_CAPACITY_MODE: "legacy",
    SCAN_SUBREQUEST_LIMIT: "200",
    APP_VERSION: "load-lab",
    ALLOWED_ORIGIN: "https://app.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    RESEND_API_KEY: "lab",
    ALERT_EMAIL_FROM: "alerts@lab.invalid",
    HELLO_EMAIL_FROM: "hello@lab.invalid",
    SAFE_EMAIL_FROM: "hello@lab.invalid",
    ALERT_EMAIL_TO: "ops@lab.invalid",
  };

  // ── Product code under test ───────────────────────────────────────────────
  globalThis.fetch = routedFetch;
  const src = (...p) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...p)).href;
  const worker = await import(src("index.js"));
  const { handleScanDispatchBatch } = await import(src("engines", "scan-dispatch.js"));
  const { runScanEngine } = await import(src("engines", "scan-engine.js"));
  const { handleScanDlqBatch } = await import(src("queues", "scan-dlq-observer.js"));
  const { hashToken } = await import(src("lib", "auth-crypto.js"));
  const settle = worker.settleScheduledQueueScan;

  await seedPopulation(db, accounts, { hashToken, startMs });
  for (const level of Object.keys(realConsole)) console[level] = captured(level);

  // ── Event loop ────────────────────────────────────────────────────────────
  const events = [];
  let eventSeq = 0;
  function schedule(at, type, data = null) {
    const event = { at, seq: ++eventSeq, type, data };
    // Binary insertion keeps the list ordered by (at, seq).
    let lo = 0, hi = events.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; const e = events[mid]; if (e.at < at || (e.at === at && e.seq < event.seq)) lo = mid + 1; else hi = mid; }
    events.splice(lo, 0, event);
  }
  const waits = [];
  const step = async (tag, fn) => {
    const previous = meterInstance.tag;
    meterInstance.tag = tag;
    try {
      const ctx = { waitUntil: (p) => waits.push(Promise.resolve(p).catch(() => {})), passThroughOnException: () => {} };
      const out = await fn(ctx);
      while (waits.length) await waits.shift();
      return out;
    } finally { meterInstance.tag = previous; }
  };

  const slots = Array.from({ length: q.maxConcurrency }, (_, i) => ({ i, busy: false }));
  const sampleDuration = (domain) => {
    const info = domainInfo.get(domain);
    const factor = info && (info.variant === "flaky" || info.variant === "slow") ? dur.faultFactor : 1;
    const ms = dur.medianMs * Math.exp(dur.sigma * random.normal()) * factor;
    return Math.round(Math.min(dur.maxMs, Math.max(dur.minMs, ms)));
  };

  async function deliver(slot, message) {
    slot.busy = true;
    const now = clock.now();
    const row = job(message.body.scan_id);
    row.deliveries++;
    if (row.first_delivery_at == null) row.first_delivery_at = now;
    let signal;
    const engineCalled = new Promise((resolve) => { signal = resolve; });
    const control = {};
    const deps = {
      onScheduledScanSettled: settle,
      runScanEngine: (...args) => {
        signal(args);
        return new Promise((resolve, reject) => { control.resolve = resolve; control.reject = reject; });
      },
    };
    const outcome = {};
    const batchMessage = {
      id: message.id,
      body: message.body,
      attempts: message.attempts,
      timestamp: new Date(message.firstSentAt),
      ack() { outcome.action = "ack"; },
      retry(options) { outcome.action = "retry"; outcome.delaySeconds = options?.delaySeconds ?? 0; },
    };
    meterInstance.tag = "consumer";
    const done = handleScanDispatchBatch({ queue: "cybermeters-scan-dispatch", messages: [batchMessage] }, env, {}, deps);
    const first = await Promise.race([engineCalled.then((args) => ({ engine: args })), done.then(() => ({ done: true }))]);
    meterInstance.tag = "idle";
    if (first.done) {
      settleMessage(message, outcome);
      schedule(clock.now() + q.invocationOverheadMs, "free", { slot: slot.i });
      return;
    }
    row.claimed_at = now;
    const duration = sampleDuration(message.body.domain);
    row.modelled_duration_ms = duration;
    slot.pending = { message, done, control, args: first.engine, outcome };
    if (random.next() < q.interruptRate) {
      row.killed = true;
      schedule(now + random.int(2_000, Math.max(2_001, duration)), "kill", { slot: slot.i });
    } else {
      schedule(now + duration, "engineDone", { slot: slot.i });
    }
  }

  function settleMessage(message, outcome) {
    if (outcome.action === "retry") {
      if (message.attempts >= q.maxRetries + 1) { queueStats.dead_lettered++; dlq.push(message); return; }
      queueStats.retries++;
      enqueue(message.body, clock.now() + (outcome.delaySeconds || 0) * 1000, message.attempts + 1, message.firstSentAt);
    }
  }

  async function engineDone(slot) {
    const pending = slot.pending;
    slot.pending = null;
    const [scanId, domainId, workspaceId, domain, engineEnv, options] = pending.args;
    const row = job(scanId);
    row.engine_runs = (row.engine_runs || 0) + 1;
    const logStart = labLog.length;
    const before = { ...(meterInstance.counts.engine || { reads: 0, writes: 0 }) };
    const r2Before = { ...r2Counters };
    currentDomain = domain;
    meterInstance.tag = "engine";
    clock.flow();
    const wallStart = clock.real();
    let result, error = null;
    try { result = await runScanEngine(scanId, domainId, workspaceId, domain, engineEnv, options); } catch (caught) { error = caught; }
    row.engine_wall_ms = clock.real() - wallStart;
    clock.freeze();
    currentDomain = null;
    const after = meterInstance.counts.engine;
    row.d1 = { reads: after.reads - before.reads, writes: after.writes - before.writes };
    row.r2 = { reads: r2Counters.reads - r2Before.reads, writes: r2Counters.writes - r2Before.writes };
    const summary = summarizeRequests(labLog.slice(logStart));
    row.requests = { total: summary.total, dns: summary.dns_questions, http: summary.by_kind.target || 0, probe: summary.by_kind.probe || 0, email: summary.by_kind.email || 0, unexpected: summary.by_kind.unexpected || 0 };
    meterInstance.tag = "consumer";
    if (error) pending.control.reject(error); else pending.control.resolve(result);
    await pending.done;
    meterInstance.tag = "idle";
    settleMessage(pending.message, pending.outcome);
    row.finished_at = clock.now();
    pruneOlderScans(workspaceId, domain, scanId);
    const scan = db.prepare("SELECT status, scan_quality FROM scans WHERE id = ?").get(scanId);
    row.status = scan?.status ?? null;
    row.quality = scan?.scan_quality ?? null;
    labLog.length = 0;
    slot.busy = false;
  }

  function kill(slot) {
    const pending = slot.pending;
    slot.pending = null;
    queueStats.redeliveries_after_kill++;
    // The invocation died before acking: the platform delivers the message again.
    const message = pending.message;
    if (message.attempts >= q.maxRetries + 1) { queueStats.dead_lettered++; dlq.push(message); }
    else enqueue(message.body, clock.now() + q.redeliveryDelayMs, message.attempts + 1, message.firstSentAt);
    slot.busy = false;
  }

  async function tryDeliver() {
    for (const slot of slots) {
      if (slot.busy) continue;
      const now = clock.now();
      let index = -1;
      for (let i = 0; i < ready.length; i++) {
        if (ready[i].readyAt <= now && (index === -1 || ready[i].readyAt < ready[index].readyAt)) index = i;
      }
      if (index === -1) return;
      const [message] = ready.splice(index, 1);
      await deliver(slot, message);
    }
  }

  const apiResults = [];
  async function manualRequest(request) {
    const a = accountById.get(request.account);
    const response = await step("api", (ctx) => worker.default.fetch(new Request("https://api.cybermeters.com/api/scan", {
      method: "POST",
      headers: { Authorization: `Bearer ${a.token}`, "Content-Type": "application/json", "CF-Connecting-IP": a.ip },
      body: JSON.stringify({ domain: request.domain, workspace_id: request.ws }),
    }), env, ctx));
    let body = {};
    try { body = await response.json(); } catch { body = {}; }
    apiResults.push({ at: clock.now(), account: a.id, kind: a.kind, status: response.status, error: body.error || body.code || null, burst: Boolean(request.burst) });
    if (body.scan_id) {
      const row = job(body.scan_id);
      row.requested_at = request.at;
      row.burst = Boolean(request.burst);
    }
  }

  const ticks = [];
  const dueSince = new Map();
  async function cronTick(at, cron) {
    // Which schedules are due right now, and since when.
    const due = db.prepare("SELECT id, next_run_at FROM scheduled_scans WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= ?)").all(new Date(at).toISOString());
    for (const s of due) if (!dueSince.has(s.id)) dueSince.set(s.id, Date.parse(s.next_run_at));
    const before = { ...(meterInstance.counts.cron || { reads: 0, writes: 0 }) };
    const sentBefore = queueStats.sent;
    const skipsBefore = skips.length;
    const wallStart = clock.real();
    await step("cron", (ctx) => worker.default.scheduled({ cron, scheduledTime: at, type: "scheduled" }, env, ctx));
    const after = meterInstance.counts.cron;
    // Schedules that ran this tick: their scans carry the schedule id.
    ticks.push({
      at, cron, due: due.length,
      dispatched: queueStats.sent - sentBefore,
      skipped: skips.length - skipsBefore,
      d1_reads: after.reads - before.reads, d1_writes: after.writes - before.writes,
      wall_ms: clock.real() - wallStart,
      waiting_in_queue: ready.length,
    });
  }

  // Seed the calendar. The cron triggers are the measured version's own
  // (wrangler.toml), so each version runs on the schedule it would deploy with.
  for (const { at, cron } of cronFirings(root, startMs, endMs)) schedule(at, "cron", { cron });
  for (const request of manual) schedule(request.at, "manual", request);
  for (let t = startMs; t <= endMs; t += 10 * MINUTE) schedule(t, "sample");
  const backlog = [];

  let processed = 0;
  try {
    while (events.length) {
      const event = events.shift();
      if (event.at > endMs + 6 * HOUR) break;
      clock.set(event.at);
      if (event.type === "cron") { if (event.at <= endMs) await cronTick(event.at, event.data.cron); }
      else if (event.type === "manual") await manualRequest(event.data);
      else if (event.type === "engineDone") await engineDone(slots[event.data.slot]);
      else if (event.type === "kill") kill(slots[event.data.slot]);
      else if (event.type === "free") slots[event.data.slot].busy = false;
      else if (event.type === "sample") {
        const counts = db.prepare("SELECT status, COUNT(*) AS n FROM scans WHERE status IN ('queued','running') GROUP BY status").all();
        backlog.push({ at: event.at, ready: ready.filter((m) => m.readyAt <= event.at).length, queued: counts.find((c) => c.status === "queued")?.n ?? 0, running: counts.find((c) => c.status === "running")?.n ?? 0 });
      }
      await tryDeliver();
      // After the window: keep draining until the queue is empty and idle.
      if (event.at > endMs && !ready.length && slots.every((s) => !s.busy)) break;
      if (progress && ++processed % 200 === 0) progress({ at: new Date(clock.now()).toISOString(), jobs: jobs.size, queued: ready.length });
    }
  } finally {
    Object.assign(console, realConsole);
    globalThis.fetch = realFetch;
    clock.restore();
  }

  // DLQ messages go to the real dead-letter observer.
  if (dlq.length) {
    await step("dlq", () => handleScanDlqBatch({ queue: "cybermeters-scan-dlq", messages: dlq.map((m) => ({ id: m.id, body: m.body, attempts: m.attempts, ack() {}, retry() {} })) }, env));
  }

  // Close the books from the database itself.
  const scanRows = db.prepare("SELECT id, workspace_id, domain, status, scan_quality, created_at FROM scans").all();
  for (const scan of scanRows) {
    const row = job(scan.id);
    row.status = scan.status;
    row.quality = scan.scan_quality;
    row.workspace_id ||= scan.workspace_id;
    row.domain ||= scan.domain;
    row.account ||= accountByWorkspace.get(scan.workspace_id)?.id ?? null;
  }
  const recoveredMeta = db.prepare("SELECT entity_id, metadata_json FROM audit_events WHERE event_type = 'scan_interrupted_recovered'").all();
  for (const row of recoveredMeta) job(row.entity_id).recovered_as_interrupted = true;
  const r2Bytes = {};
  for (const [key, size] of r2.sizes) {
    const prefix = String(key).split("/")[0];
    r2Bytes[prefix] = (r2Bytes[prefix] || 0) + size;
  }

  return {
    r2_bytes_by_prefix: r2Bytes,
    window: { start: startAt, end: new Date(endMs).toISOString(), days },
    model: { queue: q, duration: dur },
    accounts: accounts.map((a) => ({ id: a.id, kind: a.kind, plan: a.plan, domains: a.workspaces.reduce((n, ws) => n + ws.domains.length, 0), schedules: a.workspaces.reduce((n, ws) => n + ws.domains.filter((d) => d.schedule).length, 0) })),
    schedules: [...scheduleOwner.entries()].map(([id, o]) => ({ id, account: o.account.id, kind: o.account.kind })),
    jobs: [...jobs.values()],
    api: apiResults,
    skips,
    deliveries,
    ticks,
    backlog,
    queue: { ...queueStats, dlq_observed: dlq.length },
    storage: { d1_by_activity: meterInstance.counts, r2: { ...r2Counters } },
    recovered: recoveredMeta.map((r) => ({ scan_id: r.entity_id, ...(() => { try { return JSON.parse(r.metadata_json || "{}"); } catch { return {}; } })() })),
    console_lines: consoleLines,
    emails_sent: db.prepare("SELECT COUNT(*) AS n FROM asset_alert_records WHERE status = 'sent'").get()?.n ?? 0,
  };
}

// ── Summary ──────────────────────────────────────────────────────────────────
export function summarizeLoad(result) {
  const s = (ms) => (ms == null ? null : Math.round(ms / 1000));
  const kindOf = new Map(result.accounts.map((a) => [a.id, a.kind]));
  const jobs = result.jobs.filter((j) => j.account);
  const byKind = {};
  const kinds = [...new Set(result.accounts.map((a) => a.kind))];
  for (const kind of kinds) {
    const mine = jobs.filter((j) => kindOf.get(j.account) === kind);
    const manual = mine.filter((j) => j.trigger === "manual" && j.claimed_at != null);
    const scheduled = mine.filter((j) => j.trigger === "scheduled");
    const schedules = result.schedules.filter((x) => x.kind === kind);
    const ran = new Set(scheduled.filter((j) => j.claimed_at != null).map((j) => j.scheduled_scan_id));
    const qs = (list) => { const v = quantiles(list); return { n: v.n, p50_s: s(v.p50), p95_s: s(v.p95), max_s: s(v.max) }; };
    byKind[kind] = {
      accounts: result.accounts.filter((a) => a.kind === kind).length,
      manual_requested: result.api.filter((r) => r.kind === kind).length,
      manual_admitted: result.api.filter((r) => r.kind === kind && r.status === 202).length,
      manual_refused: Object.entries(result.api.filter((r) => r.kind === kind && r.status !== 202).reduce((m, r) => ({ ...m, [`${r.status} ${r.error}`]: (m[`${r.status} ${r.error}`] || 0) + 1 }), {})),
      manual_wait_in_queue: qs(manual.map((j) => j.claimed_at - j.enqueued_at)),
      manual_request_to_result: qs(manual.filter((j) => j.finished_at != null).map((j) => j.finished_at - j.requested_at)),
      schedules: schedules.length,
      scheduled_runs_dispatched: scheduled.length,
      schedules_never_run: schedules.filter((x) => !ran.has(x.id)).length,
      scheduled_lateness_from_due: qs(scheduled.filter((j) => j.claimed_at != null && j.due_at != null).map((j) => j.claimed_at - j.due_at)),
      scheduled_wait_in_queue: qs(scheduled.filter((j) => j.claimed_at != null).map((j) => j.claimed_at - j.enqueued_at)),
      failed: mine.filter((j) => j.status === "failed").length,
      failed_while_waiting: mine.filter((j) => j.recovered_as_interrupted && j.claimed_at == null).length,
    };
  }
  const executed = jobs.filter((j) => j.engine_wall_ms != null);
  const perScan = (pick) => quantiles(executed.map(pick));
  const round = (v) => (v == null ? null : Math.round(v * 10) / 10);
  const shareRun = result.accounts.filter((a) => a.schedules > 0 && !a.kind.startsWith("stuck")).map((a) => {
    const due = result.schedules.filter((x) => x.account === a.id).length;
    const ran = new Set(jobs.filter((j) => j.account === a.id && j.trigger === "scheduled" && j.claimed_at != null).map((j) => j.scheduled_scan_id)).size;
    return due ? ran / due : null;
  });
  const deliveriesByOutcome = result.deliveries.reduce((m, d) => ({ ...m, [d.outcome]: (m[d.outcome] || 0) + 1 }), {});
  const skipsByReason = result.skips.reduce((m, x) => ({ ...m, [x.reason]: (m[x.reason] || 0) + 1 }), {});
  return {
    window: result.window,
    jobs: {
      admitted: jobs.length,
      executed: executed.length,
      completed: jobs.filter((j) => j.status === "completed").length,
      completed_partial: jobs.filter((j) => j.status === "completed" && j.quality === "partial").length,
      failed: jobs.filter((j) => j.status === "failed").length,
      still_waiting_or_running_at_end: jobs.filter((j) => j.status === "queued" || j.status === "running").length,
    },
    by_kind: byKind,
    fairness: {
      jain_index_share_of_schedules_run: round(jain(shareRun) * 1000) / 1000,
      small_jobs_waiting_behind_big_customer: (() => {
        const small = jobs.filter((j) => kindOf.get(j.account) === "small" && j.claimed_at != null && j.trigger === "manual");
        const big = jobs.filter((j) => kindOf.get(j.account) === "msp" && j.claimed_at != null).map((j) => j.claimed_at).sort((a, b) => a - b);
        const ahead = small.map((j) => big.filter((t) => t > j.enqueued_at && t < j.claimed_at).length);
        return quantiles(ahead);
      })(),
    },
    reprocessing: {
      deliveries: result.deliveries.length,
      by_outcome: deliveriesByOutcome,
      duplicates_injected: result.queue.duplicates_injected,
      duplicate_executions: jobs.filter((j) => (j.engine_runs || 0) > 1).length,
      killed_invocations: result.queue.redeliveries_after_kill,
      retries: result.queue.retries,
      dead_lettered: result.queue.dead_lettered,
      recovered_as_interrupted: result.recovered.length,
      recovered_while_still_queued: result.recovered.filter((r) => r.status_before === "queued").length,
    },
    scheduler: {
      ticks: result.ticks.length,
      dispatched: result.ticks.reduce((n, t) => n + t.dispatched, 0),
      skipped: result.skips.length,
      skipped_by_reason: skipsByReason,
      d1_per_tick: quantiles(result.ticks.map((t) => t.d1_reads + t.d1_writes)),
    },
    errors: {
      api_5xx: result.api.filter((r) => r.status >= 500).length,
      console_error_lines: result.console_lines.errors,
    },
    per_scan: {
      d1_reads: perScan((j) => j.d1?.reads),
      d1_writes: perScan((j) => j.d1?.writes),
      r2_reads: perScan((j) => j.r2?.reads),
      r2_writes: perScan((j) => j.r2?.writes),
      dns_questions: perScan((j) => j.requests?.dns),
      http_requests: perScan((j) => j.requests?.http),
      probe_calls: perScan((j) => j.requests?.probe),
      engine_wall_ms_in_lab: perScan((j) => j.engine_wall_ms),
      modelled_duration_s: (() => { const v = perScan((j) => j.modelled_duration_ms); return { p50: s(v.p50), p95: s(v.p95), max: s(v.max) }; })(),
    },
    totals: {
      d1_by_activity: result.storage.d1_by_activity,
      r2: result.storage.r2,
      dns_questions: executed.reduce((n, j) => n + (j.requests?.dns || 0), 0),
      http_requests: executed.reduce((n, j) => n + (j.requests?.http || 0), 0),
      probe_calls: executed.reduce((n, j) => n + (j.requests?.probe || 0), 0),
      unexpected_requests: executed.reduce((n, j) => n + (j.requests?.unexpected || 0), 0),
      change_emails_sent: result.emails_sent,
    },
    backlog_peak: result.backlog.reduce((m, b) => (b.ready > m.ready ? b : m), { ready: 0 }),
  };
}
