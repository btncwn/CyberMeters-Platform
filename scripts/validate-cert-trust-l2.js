#!/usr/bin/env node
//
// Certificates & Trust L2 validation. Exercises the pure L2 engine and the real
// /api/workspaces/:id/certificates route against in-memory D1/R2 stubs.
//
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.join(__dirname, "..");
const workerPath = path.join(root, "workers", "scan-api", "src", "index.js");
const certL2Path = path.join(root, "workers", "scan-api", "src", "engines", "cert-trust-l2.js");

async function loadWorker() {
  globalThis.fetch = async () => { throw new Error("network disabled"); };
  AbortSignal.timeout = () => undefined;
  return import(pathToFileURL(workerPath).href);
}

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (p) => { try { db.exec(fs.readFileSync(p, "utf8")); } catch { /* schema converges */ } };
  apply(path.join(root, "database", "schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database", "migrations")).filter((f) => f.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", f));
  }
  return db;
}

function makeD1(db) {
  const wrap = (sql, args) => ({
    __sql: sql, __args: args,
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all:   async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run:   async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid ?? 0) } }; },
  });
  return {
    prepare(sql) { const b = wrap(sql, []); b.bind = (...args) => wrap(sql, args); return b; },
    async batch(stmts) { return Promise.all(stmts.map((s) => (/^\s*select/i.test(s.__sql) ? s.all() : s.run()))); },
    async exec(sql) { db.exec(sql); return { count: 0, duration: 0 }; },
  };
}

function makeEnv(db, reports) {
  return {
    cybermeters_db: makeD1(db),
    cybermeters_reports: {
      get: async (key) => reports.get(key) || null,
      put: async () => ({}), head: async () => null, delete: async () => ({}), list: async () => ({ objects: [] }),
    },
    MFA_ENCRYPTION_KEY: "cert-l2-test-mfa-key",
    STRIPE_WEBHOOK_SECRET: "whsec_test",
    STRIPE_SECRET_KEY: "sk_test_x",
    STRIPE_PRICE_MAP: JSON.stringify({ starter_monthly: "price_sm" }),
    ALLOWED_ORIGIN: "https://app.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    APP_VERSION: "test",
    RESEND_API_KEY: "",
    ADMIN_EMAILS: "",
  };
}

const ctx = { waitUntil: () => {}, passThroughOnException: () => {} };

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };
const hasFinding = (result, type) => result.findings.some((finding) => finding.type === type);
const forbiddenTypes = new Set(["weak_key", "weak_signature", "untrusted_chain", "revoked"]);

async function main() {
  const { buildCertificateTrustL2 } = await import(pathToFileURL(certL2Path).href);

  const history = [
    {
      issuer: "CN=Old CA,O=Old Trust",
      subject: "example.co.uk",
      expires_at: "2026-07-10T00:00:00.000Z",
      first_seen: "2026-01-01T00:00:00.000Z",
      last_seen: "2026-01-10T00:00:00.000Z",
      evidence_json: JSON.stringify({ san_hostnames: ["example.co.uk", "www.example.co.uk"] }),
    },
    {
      issuer: "CN=Parallel CA,O=Parallel Trust",
      subject: "example.co.uk",
      expires_at: "2027-03-31T00:00:00.000Z",
      first_seen: "2026-02-01T00:00:00.000Z",
      last_seen: "2026-02-10T00:00:00.000Z",
      evidence_json: JSON.stringify({ san_hostnames: ["example.co.uk"] }),
    },
  ];
  const cert = {
    issuer: "CN=New CA,O=New Trust",
    subject: "example.co.uk",
    san_hostnames: ["example.co.uk", "admin.example.co.uk", "*.example.co.uk"],
    expires_at: "2026-07-20T00:00:00.000Z",
    days_until_expiry: 7,
    certificate_status: "valid",
    ct_sources: { crt_sh: 3, certspotter: 2 },
  };
  const result = buildCertificateTrustL2(cert, { history });

  ok("typed expiring_soon finding is emitted", hasFinding(result, "expiring_soon"));
  ok("unexpected issuer anomaly is emitted", result.anomalies.some((a) => a.type === "unexpected_issuer"));
  ok("unexpected SAN anomaly is emitted", result.anomalies.some((a) => a.type === "unexpected_san"));
  ok("unexpected wildcard anomaly is emitted", result.anomalies.some((a) => a.type === "unexpected_wildcard"));
  ok("parallel certificate anomaly is emitted", result.anomalies.some((a) => a.type === "parallel_certificate"));
  ok("findings include reasons/evidence/confidence", result.findings.every((f) => f.confidence && Array.isArray(f.reasons) && Array.isArray(f.evidence)));
  ok("forbidden fabricated finding types are not emitted", result.findings.every((f) => !forbiddenTypes.has(f.type)));
  ok("trust path chain/root/ocsp remain unknown", result.trust_path.chain_valid === "unknown" && result.trust_path.root_trusted === "unknown" && result.trust_path.ocsp === "unknown");
  ok("renewal readiness reports warning/critical window", ["warning", "critical"].includes(result.renewal_readiness.status));
  ok("recent reissue is derived from history", result.renewal_readiness.recent_reissue_observed === true);

  const expired = buildCertificateTrustL2({ issuer: "CN=CA", subject: "expired.example", expires_at: "2026-01-01T00:00:00.000Z", days_until_expiry: -5 }, { history: [] });
  ok("expired finding is emitted", hasFinding(expired, "expired"));
  ok("missing certificate detail emits coverage gap", hasFinding(buildCertificateTrustL2({}, { history: [] }), "coverage_gap"));

  const workerMod = await loadWorker();
  const worker = workerMod.default;
  const db = buildDb();
  const reports = new Map();
  const env = makeEnv(db, reports);
  const tokenA = "cert-l2-token-A";
  const tokenB = "cert-l2-token-B";
  const tokenHashA = await workerMod.hashToken(tokenA);
  const tokenHashB = await workerMod.hashToken(tokenB);

  db.prepare("INSERT INTO users (id, email, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, ?, 1, 0)")
    .run("userA", "a@example.com", "Alice", "free", "active");
  db.prepare("INSERT INTO users (id, email, name, plan, status, email_verified, mfa_enabled) VALUES (?, ?, ?, ?, ?, 1, 0)")
    .run("userB", "b@example.com", "Bob", "free", "active");
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))").run("sessA", "userA", tokenHashA);
  db.prepare("INSERT INTO user_sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, datetime('now','+1 day'))").run("sessB", "userB", tokenHashB);
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws1", "userA", "Alpha");
  db.prepare("INSERT INTO workspaces (id, owner_user_id, name) VALUES (?, ?, ?)").run("ws2", "userB", "Bravo");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("memA", "ws1", "userA", "admin");
  db.prepare("INSERT INTO workspace_members (id, workspace_id, user_id, role) VALUES (?, ?, ?, ?)").run("memB", "ws2", "userB", "admin");
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES (?, ?, ?)").run("dom1", "userA", "example.co.uk");
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id) VALUES (?, ?)").run("ws1", "dom1");
  db.prepare("INSERT INTO scans (id, domain_id, domain, score, rating, status, created_at) VALUES (?, ?, ?, 80, 'good', 'completed', ?)")
    .run("scan1", "dom1", "example.co.uk", "2026-07-09T12:00:00.000Z");
  db.prepare(`INSERT INTO certificate_observations
      (id, workspace_id, domain_id, scan_id, certificate_key, subject, issuer, san_count, expires_at, first_seen, last_seen, evidence_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run("certobs1", "ws1", "dom1", "scan0", "key0", "example.co.uk", "CN=Old CA,O=Old Trust", 2, "2026-07-10T00:00:00.000Z", "2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z", JSON.stringify({ san_hostnames: ["example.co.uk"] }), "2026-01-01T00:00:00.000Z", "2026-01-02T00:00:00.000Z");

  reports.set("reports/scan1.json", {
    json: async () => ({
      domain: "example.co.uk",
      modules: {
        certificate_intelligence: {
          certificate_risk_level: "medium",
          certificate_status: "valid",
          issuer: "CN=New CA,O=New Trust",
          subject: "example.co.uk",
          san_count: 2,
          san_hostnames: ["example.co.uk", "admin.example.co.uk"],
          expires_at: "2026-07-20T00:00:00.000Z",
          days_until_expiry: 7,
          total_certificates_seen: 2,
          issued_for_sensitive_hosts: ["admin.example.co.uk"],
          ct_sources: { crt_sh: 2, certspotter: 1 },
          suspicious_certificate_signals: [],
        },
      },
    }),
  });

  const call = async (path, token = tokenA) => {
    const headers = {};
    if (token) headers.Authorization = `Bearer ${token}`;
    const res = await worker.fetch(new Request(`https://api.cybermeters.com${path}`, { headers }), env, ctx);
    let data = null; try { data = await res.json(); } catch { /* ignore */ }
    return { status: res.status, data };
  };

  ok("certificates route rejects anonymous callers", (await call("/api/workspaces/ws1/certificates", null)).status === 401);
  ok("certificates route rejects foreign workspace callers", (await call("/api/workspaces/ws1/certificates", tokenB)).status === 403);
  const route = await call("/api/workspaces/ws1/certificates");
  const routeCert = route.data?.certificates?.[0];
  ok("certificates route returns L2 fields", route.status === 200 && Array.isArray(routeCert?.findings) && routeCert?.renewal_readiness && routeCert?.trust_path && Array.isArray(routeCert?.anomalies));
  ok("route keeps chain/root/ocsp unknown", routeCert?.trust_path?.chain_valid === "unknown" && routeCert?.trust_path?.root_trusted === "unknown" && routeCert?.trust_path?.ocsp === "unknown");
  ok("route emits evidence-backed unexpected issuer finding", routeCert?.findings?.some((f) => f.type === "unexpected_issuer" && f.evidence?.length > 0));

  // ── The PDF must not out-claim the engine ─────────────────────────────────
  // The defect this exists to prevent (live until 2026-07-16): the Executive PDF pushed
  // the strength 'SSL and certificate configuration is fully validated.' whenever
  // ssl_certificates.status === 'good'. sslScore (posture-scoring.js) starts at 100 and
  // only ever deducts for HTTPS availability, HTTP→HTTPS redirect and expiry, so `good`
  // meant those three things — while chain validity, root trust, OCSP and revocation were
  // never checked and are asserted "unknown" three lines above this comment.
  //
  // The PDF is the artifact customers forward to insurers and boards, so it was the one
  // surface where the product contradicted its own declared limitation. Asserted at source
  // level because the claim is a literal string, and a string is what regressed.
  // Only the customer-facing COPY is asserted — the literals actually pushed into the
  // executive summary — not the whole file. A prose comment explaining the removed claim
  // is documentation and must stay legal; an earlier draft of this guard matched its own
  // explanatory comment, which is precisely the kind of assertion-that-tests-nothing this
  // suite exists to avoid.
  // M5.d: the invented executive "strengths" copy is deleted with the legacy
  // PDF brain. The not-checked disclosure now travels as the Certificates &
  // Trust domain's own limitation, frozen in the snapshot and rendered
  // verbatim (pdf.js sectionDomains prints d.limitations).
  const pdfSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "pdf.js"), "utf8");
  ok("the PDF renders per-domain limitations verbatim (carrier of the not-checked disclosure)",
    /d\.limitations/.test(pdfSrc) && /Limitation: /.test(pdfSrc));
  ok("no PDF copy claims certificates are 'fully validated'",
    !/fully\s+(?:validated|verified)/i.test(pdfSrc));
  const domSrc = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "cyber-mot-domains.js"), "utf8");
  ok("the Certificates & Trust domain limitation names what is NOT checked, verbatim",
    domSrc.includes("Chain validity, root trust, OCSP and revocation status are not checked and remain unknown."));

  console.log(`\nCertificate Trust L2: ${pass}/${pass + fail} passed`);
  if (fail) { console.error("cert-trust-l2 validation FAILED"); process.exit(1); }
  console.log("cert-trust-l2 validation passed");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
