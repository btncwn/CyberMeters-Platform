#!/usr/bin/env node
//
// Identity Exposure regression (Faz 0 product + internal pentest §8): consolidates
// three REAL signals (exposed login surfaces + active impersonation infra + email
// spoofing) and derives an overall level. Proves the consolidation + level logic
// AND per-workspace tenant isolation (a non-member gets 403; one workspace's data
// never bleeds into another's). Drives the real worker fetch with a seeded
// session; the email signal reads a stubbed R2 report. Node 24+. CI-blocking.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "identity-exposure.js")).href);
const { hashToken } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "lib", "auth-crypto.js")).href);
const { deriveLevel } = eng;

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

globalThis.fetch = async () => { throw new Error("network disabled"); };
AbortSignal.timeout = () => undefined;
const worker = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "index.js")).href);

const db = new DatabaseSync(":memory:");
const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* ordering no-ops */ } };
apply(path.join(root, "database", "schema.sql"));
for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) apply(path.join(root, "database", "migrations", f));
db.exec("PRAGMA foreign_keys = OFF");
const makeD1 = (db) => { const wrap = (sql, a) => ({ first: async () => db.prepare(sql).get(...a) ?? null, all: async () => ({ results: db.prepare(sql).all(...a) }), run: async () => { const r = db.prepare(sql).run(...a); return { meta: { changes: r.changes } }; } }); return { prepare(sql) { const b = wrap(sql, []); b.bind = (...a) => wrap(sql, a); return b; } }; };

// ── Seed: user u_a (member of ws_a only), workspaces ws_a + ws_b ─────────────
db.prepare("INSERT INTO users (id, email, email_verified) VALUES ('u_a','a@example.co.uk',1)").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_a','Acme','u_a')").run();
db.prepare("INSERT INTO workspaces (id, name, owner_user_id) VALUES ('ws_b','Other','u_other')").run();
db.prepare("INSERT INTO workspace_members (workspace_id, user_id, role) VALUES ('ws_a','u_a','owner')").run();
// ws_a: 2 internet-exposed login surfaces (+ ws_b's own, to prove isolation)
const idA = (id, ws, host, type) => db.prepare(`INSERT INTO identity_assets (id, workspace_id, domain_id, scan_id, hostname, identity_type, internet_exposed, status, risk_score, first_seen, last_seen) VALUES (?, ?, 'd', 'sc', ?, ?, 1, 'active', 20, datetime('now'), datetime('now'))`).run(id, ws, host, type);
idA("i1", "ws_a", "vpn.acme.co.uk", "vpn");
idA("i2", "ws_a", "owa.acme.co.uk", "login_portal");
idA("ib", "ws_b", "vpn.other.co.uk", "vpn");
// ws_a: 1 active lookalike that can send mail
db.prepare(`INSERT INTO workspace_brand_assets (id, workspace_id, domain, candidate_domain, status, dns_resolves, mx_present, https_available, classification, first_seen, last_seen, created_at, updated_at) VALUES ('b1','ws_a','acme.co.uk','acme-login.co.uk','active',1,1,0,'suspicious', datetime('now'), datetime('now'), datetime('now'), datetime('now'))`).run();
// ws_a: a domain + latest completed scan whose report shows DMARC p=none (spoofable)
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_a','d_a')").run();
db.prepare("INSERT INTO scans (id, domain_id, domain, status, created_at) VALUES ('sc_a','d_a','acme.co.uk','completed', datetime('now','-1 day'))").run();

// R2 stub: the latest scan report with a spoofable email posture.
const reports = { "reports/sc_a.json": { modules: { email_security: { spf: { present: true }, dmarc: { present: true, policy: "none" } } } } };
const r2 = { get: async (key) => (reports[key] ? { json: async () => reports[key] } : null), put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }) };

const TOKEN = "tok_a";
db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES ('s_a','u_a',?, datetime('now','+1 day'))").run(await hashToken(TOKEN));

const env = { cybermeters_db: makeD1(db), cybermeters_reports: r2, ALLOWED_ORIGIN: "https://app.cybermeters.com", APP_VERSION: "test" };
const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };
const get = async (p, token) => { const res = await worker.default.fetch(new Request(`https://app.cybermeters.com${p}`, { headers: token ? { Authorization: `Bearer ${token}` } : {} }), env, ctx); let body = {}; try { body = await res.json(); } catch { /* */ } return { status: res.status, body }; };

// ── 1. Unit: deriveLevel ─────────────────────────────────────────────────────
ok("no reachability producer → Not Assessed", deriveLevel({ internet_facing: 0, reachability_evaluated_count: 0 }, { active: 0, can_send_mail: 0, can_host_login: 0 }, { spoofable_domains: 0, checked_domains: 1 }).identity_exposure_level === "Not Assessed");
ok("public identity surface alone is not a vulnerability", deriveLevel({ internet_facing: 1, reachable_surface_count: 1, reachability_evaluated_count: 1 }, { active: 0, can_send_mail: 0, can_host_login: 0 }, { spoofable_domains: 0, checked_domains: 1 }).identity_exposure_level === "Low");
ok("deprecated internet_facing primitive cannot manufacture reachability", deriveLevel({ internet_facing: 1, reachable_surface_count: 0, reachability_evaluated_count: 0 }, { active: 0, total: 0, can_send_mail: 0, can_host_login: 0 }, { spoofable_domains: 0, checked_domains: 0 }).identity_exposure_level === "Not Assessed");
ok("spoofable domain → High", deriveLevel({ internet_facing: 0 }, { active: 0, can_send_mail: 0, can_host_login: 0 }, { spoofable_domains: 1, checked_domains: 1 }).identity_exposure_level === "High");
ok("MX observation alone → review, not confirmed abuse", deriveLevel({ internet_facing: 0 }, { active: 1, can_send_mail: 1, can_host_login: 0 }, { spoofable_domains: 0, checked_domains: 0 }).identity_exposure_level === "Medium");
// A2: a reassuring "clean" verdict is honest ONLY when evidence was actually
// assessed (checked_domains>0). With nothing assessed it must read Not Assessed.
ok("assessed non-identity evidence cannot imply identity reachability health", (() => {
  const r = deriveLevel({ internet_facing: 0, reachability_evaluated_count: 0 }, { active: 0, can_send_mail: 0, can_host_login: 0 }, { spoofable_domains: 0, checked_domains: 1 });
  return r.identity_exposure_level === "Not Assessed" && !/clean/i.test(r.summary);
})());
ok("A2: nothing assessed → Not Assessed, never a clean Low", (() => {
  const r = deriveLevel({ internet_facing: 0, count: 0 }, { active: 0, total: 0, can_send_mail: 0, can_host_login: 0 }, { spoofable_domains: 0, checked_domains: 0 });
  return r.identity_exposure_level === "Not Assessed" && !/clean/i.test(r.summary);
})());

// ── 2. Integration: consolidated exposure for ws_a ───────────────────────────
const resp = await get("/api/workspaces/ws_a/identity-exposure", TOKEN);
ok("identity-exposure authorised (200)", resp.status === 200);
const sig = resp.body.signals || {};
ok("identity candidates remain distinct from measured reachability",
  sig.exposed_login_surfaces?.surface_candidate_count === 2 &&
  sig.exposed_login_surfaces?.reachability_evaluated_count === 0 &&
  sig.exposed_login_surfaces?.reachable_surface_count === 0 &&
  sig.exposed_login_surfaces?.internet_facing === 0);
ok("active impersonation infra counted (1, mail-capable)", sig.impersonation_infrastructure?.active === 1 && sig.impersonation_infrastructure?.can_send_mail === 1);
ok("email spoofing detected from R2 report (1 spoofable)", sig.email_spoofing?.spoofable_domains === 1);
ok("overall level is High (spoofable + mail lookalike)", resp.body.identity_exposure_level === "High");
ok("summary is populated", typeof resp.body.summary === "string" && resp.body.summary.length > 20);

// ── 3. Tenant isolation ──────────────────────────────────────────────────────
ok("non-member is denied another workspace's identity exposure (403)", (await get("/api/workspaces/ws_b/identity-exposure", TOKEN)).status === 403);
ok("unauthenticated is rejected (401)", (await get("/api/workspaces/ws_a/identity-exposure")).status === 401);
// ws_a's response must not contain ws_b's host.
ok("no cross-workspace bleed (ws_b host absent from ws_a response)", !JSON.stringify(resp.body).includes("other.co.uk"));

// Customer dispositions and DNS records must not manufacture compromise claims.
reports["reports/sc_a.json"].modules.email_security = { spf: { present: false }, dmarc: { present: true, policy: "reject" }, dkim: { present: true } };
for (const classification of ["owned", "ignored", "benign", "false_positive", "dismissed"]) {
  db.prepare("UPDATE workspace_brand_assets SET classification = ? WHERE id = 'b1'").run(classification);
  const result = (await get("/api/workspaces/ws_a/identity-exposure", TOKEN)).body;
  ok(`${classification} is not an active impersonation risk`, result.signals?.impersonation_infrastructure?.active === 0 && result.identity_exposure_level !== "High");
  ok(`SPF absence with DMARC reject is not a policy gap (${classification})`, result.signals?.email_spoofing?.policy_gap_domains === 0 && !/weak or missing DMARC|can be spoofed|able to send/i.test(result.summary));
}
db.prepare("UPDATE workspace_brand_assets SET classification = 'unreviewed' WHERE id = 'b1'").run();
let result = (await get("/api/workspaces/ws_a/identity-exposure", TOKEN)).body;
ok("MX record reports receiving capability only", result.identity_exposure_level === "Medium" && result.signals.impersonation_infrastructure.mail_receiving_domains === 1 && !/send mail as you/.test(result.summary));
db.prepare("UPDATE workspace_brand_assets SET classification = 'confirmed_abuse' WHERE id = 'b1'").run();
result = (await get("/api/workspaces/ws_a/identity-exposure", TOKEN)).body;
ok("confirmed abuse still raises High", result.identity_exposure_level === "High" && result.signals.impersonation_infrastructure.confirmed_abuse_domains === 1);
db.prepare("UPDATE workspace_brand_assets SET classification = 'owned' WHERE id = 'b1'").run();
reports["reports/sc_a.json"].modules.email_security.dmarc = { present: true, policy: null };
result = (await get("/api/workspaces/ws_a/identity-exposure", TOKEN)).body;
ok("unparsed DMARC is unavailable rather than a fabricated gap", result.identity_exposure_level === "Unavailable" && result.signals.email_spoofing.details[0].policy_gap === null);
reports["reports/sc_a.json"].modules.email_security.dmarc = { present: true, policy: "reject" };
reports["reports/sc_a.json"].modules.email_security.dmarc_detail = { valid: false };
result = (await get("/api/workspaces/ws_a/identity-exposure", TOKEN)).body;
ok("invalid DMARC reject is not promoted to an enforcing policy", result.identity_exposure_level === "Unavailable" && result.signals.email_spoofing.policy_observed_domains === 0);
delete reports["reports/sc_a.json"].modules.email_security.dmarc_detail;
db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES ('ws_a','d_unreadable')").run();
db.prepare("INSERT INTO scans (id, domain_id, domain, status, created_at) VALUES ('sc_unreadable','d_unreadable','unreadable.example','completed', datetime('now'))").run();
result = (await get("/api/workspaces/ws_a/identity-exposure", TOKEN)).body;
ok("partial report failure preserves evidence gap", result.identity_exposure_level === "Unavailable" && result.signals.email_spoofing.checked_domains === 1);

// Actual probe -> discovery -> persisted TEXT evidence -> customer claim.
const { probeAsset } = await import('../workers/scan-api/src/engines/asset-intel.js');
const { runIdentityDiscoveryModule } = await import('../workers/scan-api/src/engines/identity-scan.js');
const { buildIdentityClaim } = await import('../workers/scan-api/src/engines/identity-evidence-contract.js');
const response = new Response('<html><title>Sign in</title><input type="password"></html>', { headers: { 'content-type': 'text/html' } });
Object.defineProperty(response, 'url', { value: 'https://login.acme.co.uk/' });
const probed = await probeAsset('login.acme.co.uk', { fetcher: async () => response });
const modules = { subdomains: { items: ['login.acme.co.uk'] }, asset_exposure: { source: 'http_probe', assets: [probed] } };
const discovery = runIdentityDiscoveryModule(modules, 'acme.co.uk', { observedAt: new Date().toISOString() });
const portal = discovery.portals[0];
const measuredClaim = buildIdentityClaim({ ...portal, evidence: JSON.stringify(portal.evidence) });
ok('real HTTP response is retained through serialized evidence', measuredClaim.reachability.status === 'reachable' && measuredClaim.reachability.endpoint === 'https://login.acme.co.uk/');
ok('actual password field observed, without claiming compromise', measuredClaim.reachability.password_form_observed === true);
for (const [name, asset, incomplete] of [
  ['off-host redirect', { ...probed, url: 'https://other.example/' }, false],
  ['edge failure', { ...probed, status: 530, reachable: false }, false],
  ['no real observation', { ...probed, authentication_observation: null }, false],
  ['incomplete scan evidence', probed, true],
]) {
 const r = runIdentityDiscoveryModule({ ...modules, asset_exposure: { source: 'http_probe', assets: [asset], incomplete } }, 'acme.co.uk');
 ok(`${name} cannot manufacture a measured endpoint`, buildIdentityClaim(r.portals[0]).reachability.status === 'not_evaluated');
}
const outOfScope = runIdentityDiscoveryModule(modules, 'different.example');
ok('out-of-scope hostname cannot become measured evidence', buildIdentityClaim(outOfScope.portals[0]).reachability.status === 'not_evaluated');
ok('scan aggregate counts actual measurements', discovery.reachable_surface_count === 1 && discovery.password_form_count === 1);
for (const html of [
  '<!-- <input type="password"> -->',
  '<script>const example = \'<input type="password">\';</script>',
  '<input data-type="password">',
  '<input title="type=password">',
  '<div title=\'<input type="password">\'>example</div>',
  '<textarea><input type="password"></textarea>',
  '<input type="text" type="password">',
  ' '.repeat(8_192) + '<input type="password">',
]) {
  const asset = await probeAsset('login.acme.co.uk', { fetcher: async () => new Response(html, { headers: { 'content-type': 'text/html' } }) });
  ok('non-observed or executable-string markup is not a password-field observation', asset.authentication_observation.password_form_observed === null);
}
let cancelled = false;
let produced = 0;
const endless = new ReadableStream({
  pull(controller) { produced++; controller.enqueue(new Uint8Array(4_096).fill(32)); },
  cancel() { cancelled = true; },
});
await probeAsset('login.acme.co.uk', { fetcher: async () => new Response(endless, { headers: { 'content-type': 'text/html' } }) });
ok('large HTML is cancelled at a bounded prefix', cancelled && produced <= 4);

console.log(`\nIdentity exposure: ${pass}/${pass + fail} passed`);
if (fail) { console.error("identity-exposure validation FAILED"); process.exit(1); }
console.log("identity-exposure validation passed");
