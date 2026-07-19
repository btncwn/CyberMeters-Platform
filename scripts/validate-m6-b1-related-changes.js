#!/usr/bin/env node
//
// M6 Phase B1 — Deterministic Related Changes. Drives the REAL adapter + rules engine
// + orchestrator against an in-memory SQLite (schema.sql + every migration, incl. 098)
// with a D1 shim. Proves the honesty-critical correlation contract and its guards, and
// mutation-checks each guard by asserting the input it MUST reject is rejected (remove
// the guard and the assertion fails). Requires Node 24+ (node:sqlite). CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href;

const adapter = await import(eng("related-changes-adapter.js"));
const rules = await import(eng("related-changes-rules.js"));
const orch = await import(eng("related-changes.js"));
const { SIGNAL_FAMILY } = adapter;
const { correlateChangeEvents, RELATED_CHANGE_RULES } = rules;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// ── DB / D1 harness (posture-events precedent) ───────────────────────────────
function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering/dup — schema converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}
function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

const T_PREV = "2026-07-01T10:00:00.000Z";   // previous complete scan
const T_CUR  = "2026-07-08T10:00:00.000Z";   // current complete scan (window end)
const T_MID  = "2026-07-08T09:30:00.000Z";   // inside window
const T_OLD  = "2026-06-01T10:00:00.000Z";   // before window

function seedBase(db, { ws = "ws_1", user = "usr_1", domId = "dom_1", domain = "acme.co.uk" } = {}) {
  db.prepare("INSERT INTO users (id, email) VALUES (?, ?)").run(user, `${user}@acme.co.uk`);
  db.prepare("INSERT INTO workspaces (id, name) VALUES (?, ?)").run(ws, "Acme");
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run(domId, user, domain);
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run(ws, domId);
  const scanPrev = ws === "ws_1" ? "scan_prev" : `scan_prev_${ws}`;
  const scanCur = ws === "ws_1" ? "scan_cur" : `scan_cur_${ws}`;
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?,?,?,?,?,?,?)")
    .run(scanPrev, domId, domain, "completed", "complete", ws, T_PREV);
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?,?,?,?,?,?,?)")
    .run(scanCur, domId, domain, "completed", "complete", ws, T_CUR);
}
let assetSeq = 0;
function addAssetEvent(db, { ws = "ws_1", domId = "dom_1", scan = "scan_cur", event_type, hostname, at = T_MID }) {
  const id = `ae_${++assetSeq}`;
  db.prepare("INSERT INTO asset_events (id, workspace_id, domain_id, scan_id, event_type, hostname, severity, description, created_at) VALUES (?,?,?,?,?,?,?,?,?)")
    .run(id, ws, domId, scan, event_type, hostname, "info", "", at);
  return id;
}
function addIdentity(db, { ws = "ws_1", domId = "dom_1", hostname, at = T_MID }) {
  const id = `ia_${hostname}`;
  db.prepare("INSERT INTO identity_assets (id, workspace_id, domain_id, scan_id, hostname, asset_type, identity_type, provider, first_seen, last_seen, status, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, ws, domId, "scan_cur", hostname, "portal", "login", "custom", at, at, "active", at);
  return id;
}
function addSender(db, { ws = "ws_1", domain, ip, at = T_MID }) {
  const id = `ess_${ip}`;
  db.prepare("INSERT INTO email_sender_sources (id, workspace_id, domain, source_ip, provider_guess, first_seen, last_seen, classification, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)")
    .run(id, ws, domain, ip, "unknown", at, at, "unknown", at, at);
  return id;
}
function addShadow(db, { ws = "ws_1", key, source_type, hostnames, at = T_MID }) {
  const id = `sii_${key}`;
  db.prepare("INSERT INTO shadow_it_inventory (id, workspace_id, canonical_technology_key, display_name, source_type, observed_hostnames_json, first_seen_at, last_seen_at, last_changed_at, classification, monitoring_status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, ws, key, key, source_type, JSON.stringify(hostnames), at, at, at, "unreviewed", "observed", at, at);
  return id;
}
function addBrand(db, { ws = "ws_1", domain, candidate, dns = 1, https = 1, at = T_MID }) {
  const id = `wba_${candidate}`;
  db.prepare("INSERT INTO workspace_brand_assets (id, workspace_id, domain, candidate_domain, dns_resolves, https_available, status, first_seen, last_seen, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    .run(id, ws, domain, candidate, dns, https, "active", at, at, at, at);
  return id;
}
function makeEnv(db) { return { cybermeters_db: makeD1(db) }; }
async function run(env) {
  return orch.correlateRelatedChanges(env, { workspaceId: "ws_1", domainId: "dom_1", scanId: "scan_cur", scanQuality: "complete", assessedAt: T_CUR });
}
async function clusters(env) { return orch.listRelatedChanges(env, "ws_1", {}); }

// ── 1. Positive: >=2 independent families → cluster (new host + cert) ─────────
{
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "new_asset_discovered", hostname: "login.acme.co.uk" });
  addAssetEvent(db, { event_type: "certificate_new_detected", hostname: "login.acme.co.uk" });
  const r = await run(env);
  const cs = await clusters(env);
  ok("1a new_host_with_cert forms one cluster", r.ran && cs.length === 1);
  ok("1b cluster rule id is new_host_with_cert", cs[0]?.rule_id === "new_host_with_cert");
  ok("1c signal_family_count == 2", cs[0]?.signal_family_count === 2);
  ok("1d registrable domain resolved to eTLD+1", cs[0]?.registrable_domain === "acme.co.uk");
  ok("1e customer_state starts 'new'", cs[0]?.customer_state === "new");
  const detail = await orch.getRelatedChange(env, "ws_1", cs[0].id);
  ok("1f evidence is by pointer (source_table + record id, no payload copy)",
    detail.evidence.length === 2 &&
    detail.evidence.every((e) => e.source_table === "asset_events" && e.source_record_id && !("description" in e)));
}

// ── 2. Negative: same domain + single family → NO cluster (candidate only) ────
{
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "new_asset_discovered", hostname: "a.acme.co.uk" });
  addAssetEvent(db, { event_type: "dns_ip_changed", hostname: "b.acme.co.uk" });
  await run(env);
  const cs = await clusters(env);
  ok("2 one family (asset only, two events) never forms a cluster", cs.length === 0);
}

// ── 3. Shadow-IT provenance guard (§5) ───────────────────────────────────────
{
  // cloud_asset shadow-it + an asset event = duplicate provenance → NOT independent.
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "new_asset_discovered", hostname: "x.acme.co.uk" });
  addShadow(db, { key: "tech_cloud", source_type: "cloud_asset", hostnames: ["x.acme.co.uk"] });
  await run(env);
  ok("3a cloud_asset shadow-it does NOT corroborate an asset event", (await clusters(env)).length === 0);
}
{
  // vendor (independent) provenance shadow-it + cert = qualifies.
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "certificate_new_detected", hostname: "y.acme.co.uk" });
  addShadow(db, { key: "tech_vendor", source_type: "vendor", hostnames: ["y.acme.co.uk"] });
  await run(env);
  const cs = await clusters(env);
  ok("3b vendor shadow-it corroborates a cert → shadow_it_with_host_or_cert", cs.some((c) => c.rule_id === "shadow_it_with_host_or_cert"));
}

// ── 4. Brand alone NEVER forms a cluster (documented v1 invariant) ───────────
{
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addBrand(db, { domain: "acme.co.uk", candidate: "acme-support.co.uk" });
  db.prepare("INSERT INTO brand_abuse_campaigns (id, workspace_id, brand_profile_id, linked_domains, linked_ips, shared_certs, shared_favicon_hashes, first_seen_at, last_seen_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    .run("bac_1", "ws_1", "bp_1", JSON.stringify(["acme.co.uk"]), "[]", "[]", "[]", T_MID, T_MID, T_MID, T_MID);
  await run(env);
  ok("4 brand family alone (candidate + campaign) never forms a cluster", (await clusters(env)).length === 0);
}

// ── 5. Consistent direction: resolved events dropped (§4.5) ───────────────────
{
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "asset_no_longer_seen", hostname: "z.acme.co.uk" }); // resolved
  addAssetEvent(db, { event_type: "certificate_new_detected", hostname: "z.acme.co.uk" }); // appeared
  await run(env);
  ok("5 a resolved event cannot be one of the two families (mixed noise dropped)", (await clusters(env)).length === 0);
}

// ── 6. Complete-evidence floor + adjacency window gates ──────────────────────
{
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "new_asset_discovered", hostname: "p.acme.co.uk" });
  addAssetEvent(db, { event_type: "certificate_new_detected", hostname: "p.acme.co.uk" });
  const r = await orch.correlateRelatedChanges(env, { workspaceId: "ws_1", domainId: "dom_1", scanId: "scan_cur", scanQuality: "partial", assessedAt: T_CUR });
  ok("6a partial scan produces no correlation", r.ran === false && r.reason === "scan_not_complete");
  ok("6b partial scan wrote nothing", (await clusters(env)).length === 0);
}
{
  const db = buildDb();
  // seed with NO previous complete scan
  db.prepare("INSERT INTO users (id, email) VALUES (?, ?)").run("usr_1", "o@acme.co.uk");
  db.prepare("INSERT INTO workspaces (id, name) VALUES (?, ?)").run("ws_1", "Acme");
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run("dom_1", "usr_1", "acme.co.uk");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run("ws_1", "dom_1");
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?,?,?,?,?,?,?)")
    .run("scan_cur", "dom_1", "acme.co.uk", "completed", "complete", "ws_1", T_CUR);
  const env = makeEnv(db);
  addAssetEvent(db, { event_type: "new_asset_discovered", hostname: "p.acme.co.uk" });
  addAssetEvent(db, { event_type: "certificate_new_detected", hostname: "p.acme.co.uk" });
  const r = await run(env);
  ok("6c no adjacent complete scan → no correlation (first-scan flood guard)", r.ran === false && r.reason === "no_adjacent_complete_scan");
}
{
  // events OUTSIDE the window are ignored.
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "new_asset_discovered", hostname: "old.acme.co.uk", at: T_OLD });
  addAssetEvent(db, { event_type: "certificate_new_detected", hostname: "old.acme.co.uk", at: T_OLD });
  await run(env);
  ok("6d events before the window are not correlated", (await clusters(env)).length === 0);
}

// ── 7. Append-only recurrence + idempotency ──────────────────────────────────
{
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "new_asset_discovered", hostname: "r.acme.co.uk" });
  addAssetEvent(db, { event_type: "certificate_new_detected", hostname: "r.acme.co.uk" });
  await run(env);
  const before = (await clusters(env))[0];
  await run(env); // re-run SAME scan
  const afterSame = (await clusters(env))[0];
  const evCount = db.prepare("SELECT COUNT(*) c FROM related_change_evidence").get().c;
  ok("7a re-running the same scan is idempotent (no new evidence)", evCount === 2);
  ok("7b re-running the same scan does not bump recurrence", afterSame.recurrence_count === 1);
  ok("7c cluster row not duplicated", (await clusters(env)).length === 1);

  // A NEW scan that adds new evidence bumps recurrence.
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?,?,?,?,?,?,?)")
    .run("scan_next", "dom_1", "acme.co.uk", "completed", "complete", "ws_1", "2026-07-15T10:00:00.000Z");
  addAssetEvent(db, { scan: "scan_next", event_type: "new_asset_discovered", hostname: "r2.acme.co.uk", at: "2026-07-15T09:00:00.000Z" });
  addAssetEvent(db, { scan: "scan_next", event_type: "certificate_new_detected", hostname: "r2.acme.co.uk", at: "2026-07-15T09:00:00.000Z" });
  await orch.correlateRelatedChanges(env, { workspaceId: "ws_1", domainId: "dom_1", scanId: "scan_next", scanQuality: "complete", assessedAt: "2026-07-15T10:00:00.000Z" });
  const afterNext = (await clusters(env))[0];
  ok("7d a new scan with new correlated evidence bumps recurrence", afterNext.recurrence_count === 2);
}

// ── 8. Tenant isolation ──────────────────────────────────────────────────────
{
  const db = buildDb(); seedBase(db);
  seedBase(db, { ws: "ws_2", user: "usr_2", domId: "dom_2", domain: "other.co.uk" });
  const env = makeEnv(db);
  // ws_2 producers only
  addAssetEvent(db, { ws: "ws_2", domId: "dom_2", scan: "scan_cur_ws_2", event_type: "new_asset_discovered", hostname: "a.other.co.uk" });
  addAssetEvent(db, { ws: "ws_2", domId: "dom_2", scan: "scan_cur_ws_2", event_type: "certificate_new_detected", hostname: "a.other.co.uk" });
  await run(env); // runs for ws_1
  ok("8a ws_1 correlation sees none of ws_2's producers", (await orch.listRelatedChanges(env, "ws_1", {})).length === 0);
  await orch.correlateRelatedChanges(env, { workspaceId: "ws_2", domainId: "dom_2", scanId: "scan_cur_ws_2", scanQuality: "complete", assessedAt: T_CUR });
  const w2 = await orch.listRelatedChanges(env, "ws_2", {});
  ok("8b ws_2 gets its own cluster", w2.length === 1);
  ok("8c ws_1 still isolated (0 clusters)", (await orch.listRelatedChanges(env, "ws_1", {})).length === 0);
}

// ── 9. Customer feedback: append-only, state preserved on recurrence ─────────
{
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "new_asset_discovered", hostname: "f.acme.co.uk" });
  addAssetEvent(db, { event_type: "certificate_new_detected", hostname: "f.acme.co.uk" });
  await run(env);
  const c = (await clusters(env))[0];
  const bad = await orch.setRelatedChangeCustomerState(env, "ws_1", c.id, "new", { userId: "usr_1" });
  ok("9a cannot set state back to system-only 'new'", bad.ok === false && bad.code === "invalid_state");
  const good = await orch.setRelatedChangeCustomerState(env, "ws_1", c.id, "expected", { userId: "usr_1", note: "planned migration" });
  ok("9b mark expected succeeds", good.ok === true);
  ok("9c feedback is recorded append-only in audit_events",
    db.prepare("SELECT COUNT(*) c FROM audit_events WHERE event_type='related_change_feedback' AND entity_id=?").get(c.id).c === 1);
  // recurrence must NOT reset the declaration
  db.prepare("INSERT INTO scans (id, domain_id, domain, status, scan_quality, workspace_id, created_at) VALUES (?,?,?,?,?,?,?)")
    .run("scan_r", "dom_1", "acme.co.uk", "completed", "complete", "ws_1", "2026-07-15T10:00:00.000Z");
  addAssetEvent(db, { scan: "scan_r", event_type: "new_asset_discovered", hostname: "f2.acme.co.uk", at: "2026-07-15T09:00:00.000Z" });
  addAssetEvent(db, { scan: "scan_r", event_type: "certificate_new_detected", hostname: "f2.acme.co.uk", at: "2026-07-15T09:00:00.000Z" });
  await orch.correlateRelatedChanges(env, { workspaceId: "ws_1", domainId: "dom_1", scanId: "scan_r", scanQuality: "complete", assessedAt: "2026-07-15T10:00:00.000Z" });
  ok("9d a recurrence never silently resets a customer declaration (§4.6)",
    (await clusters(env))[0].customer_state === "expected");
}

// ── 10. Manual case creation uses a BASE case type (no bypass) + links ───────
{
  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "new_asset_discovered", hostname: "c.acme.co.uk" });
  addAssetEvent(db, { event_type: "certificate_new_detected", hostname: "c.acme.co.uk" });
  await run(env);
  const c = (await clusters(env))[0];
  const res = await orch.createCaseFromRelatedChange(env, "ws_1", c.id, { userId: "usr_1" });
  ok("10a case created from related change", res.ok === true && !!res.case?.id);
  ok("10b case uses a base case type (cert), status starts 'detected'",
    res.case?.case_type === "certificate_case" && res.case?.status === "detected");
  ok("10c cluster is linked to the case", (await clusters(env))[0].linked_case_id === res.case.id);
}

// ── 11. Pure rules engine: each shipped rule needs >=2 INDEPENDENT families ──
{
  // Craft canonical events directly and assert the pure function's contract.
  const mk = (fam, et, dir, reg = "acme.co.uk") => ({ producer_family: fam, event_type: et, direction: dir, registrable_domain: reg, entity_key: `k:${et}`, source_table: "t", source_record_id: et, observed_at: T_MID });
  ok("11a two events, one family → no cluster", correlateChangeEvents([
    mk(SIGNAL_FAMILY.ASSET, "new_asset_discovered", "appeared"),
    mk(SIGNAL_FAMILY.ASSET, "dns_ip_changed", "changed"),
  ]).length === 0);
  ok("11b every registered rule requires >=2 families", RELATED_CHANGE_RULES.every((r) => r.requires.length >= 2));
  ok("11c no registered rule references the brand family", RELATED_CHANGE_RULES.every((r) => JSON.stringify(r.requires).indexOf("brand") === -1));
  const two = correlateChangeEvents([
    mk(SIGNAL_FAMILY.EMAIL_SENDER, "email_sender_new_source", "appeared"),
    mk(SIGNAL_FAMILY.EMAIL_CONFIG, "email_spf_changed", "changed"),
  ]);
  ok("11d new sender + email-config change fires the bounded sender rule", two.some((c) => c.rule_id === "new_sender_with_email_config"));
  ok("11e cross-domain events never merge into one cluster", correlateChangeEvents([
    mk(SIGNAL_FAMILY.ASSET, "new_asset_discovered", "appeared", "acme.co.uk"),
    mk(SIGNAL_FAMILY.CERT, "certificate_new_detected", "appeared", "other.co.uk"),
  ]).length === 0);
}

// ── 12. Vocabulary lock (§9): customer-facing strings never say attack/compromise ─
{
  // The §9 lock forbids the loaded CLAIMS ("attack chain", "compromise sequence",
  // "malicious campaign", "behavioural threat", "incident", "anomalous / statistically
  // unusual"). §9 itself uses "Change != compromise" as APPROVED framing, so the bare
  // word "compromise" inside a negating educational phrase is allowed — only the
  // dangerous phrasings are banned.
  const FORBIDDEN = ["attack chain", "compromise sequence", "malicious campaign", "behavioural threat", "anomal", "statistically unusual", "threat detected"];
  const FORBIDDEN_WORD = /\bincident\b/;
  const clean = (s) => { const l = String(s || "").toLowerCase(); return !FORBIDDEN.some((w) => l.includes(w)) && !FORBIDDEN_WORD.test(l); };
  ok("12a every rule title + summary is honest-language", RELATED_CHANGE_RULES.every((r) => clean(r.title) && clean(r.summary)));

  const db = buildDb(); seedBase(db); const env = makeEnv(db);
  addAssetEvent(db, { event_type: "new_asset_discovered", hostname: "v.acme.co.uk" });
  addAssetEvent(db, { event_type: "certificate_new_detected", hostname: "v.acme.co.uk" });
  await run(env);
  const summary = await orch.buildRelatedChangesSummary(env, "ws_1");
  ok("12b the frozen summary note is honest-language", clean(summary.note));
  ok("12c the frozen summary carries schema + item list (pointer-count only)",
    summary.schema === "related_changes.v1" && Array.isArray(summary.items) && summary.total === summary.items.length);
  const c = (await clusters(env))[0];
  const res = await orch.createCaseFromRelatedChange(env, "ws_1", c.id, { userId: "usr_1" });
  ok("12d a case opened from a related change uses honest-language title + summary",
    res.ok && clean(res.case.title) && clean(res.case.summary));
}

console.log(`\nM6 B1 Related Changes: ${pass}/${pass + fail} passed`);
if (fail > 0) { console.error("related-changes validation FAILED"); process.exit(1); }
console.log("related-changes validation passed");
