#!/usr/bin/env node
//
// PR-B — customer alert evidence-fidelity, DB-backed and mutation-proved.
//
// Every uncertainty, conflict and positive-defect fixture traverses the
// production managed-alert chain:
// emitLifecycleAlert → resolveCustomerAlertPresentation → emitManagedAlert →
// buildAlertEmailFields → formatAlertEmail → sendTenantAlertEmail. The suite
// inspects both the persisted in-app notification and the exact Resend payload.
//
// Mutants run the same suite in fresh Node processes against a copied engine
// tree, so module caching cannot hide a restored overclaim or silent suppression.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engineSrc = process.env.PR_B_ENGINE_SRC
  ? path.resolve(process.env.PR_B_ENGINE_SRC)
  : path.join(root, "workers", "scan-api", "src");
const eng = (file) => pathToFileURL(path.join(engineSrc, "engines", file)).href;
const mutantChild = process.argv.includes("--mutant-child");

const { emitLifecycleAlert } = await import(eng("alert-consumers.js"));
const { evaluateWebsiteSecurityForScan } = await import(eng("website-security-lifecycle.js"));

const EXPECTED_ASSERTIONS = 156;
const EXPECTED_MUTANTS = 8;
let passed = 0;
let failed = 0;
const ok = (name, condition, detail = "") => {
  if (condition) passed += 1;
  else {
    failed += 1;
    console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};
const eq = (name, got, want) =>
  ok(name, JSON.stringify(got) === JSON.stringify(want),
    `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);

function directManagedAlertCallMap() {
  const calls = new Map();
  const visit = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const absolute = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        visit(absolute);
        continue;
      }
      if (!entry.isFile() || !entry.name.endsWith(".js")) continue;
      const source = fs.readFileSync(absolute, "utf8")
        .replace(/\/\*[\s\S]*?\*\//g, "")
        .replace(/(^|[^:])\/\/.*$/gm, "$1")
        .replace(/export\s+async\s+function\s+emitManagedAlert\s*\(/g, "");
      const count = source.match(/\bemitManagedAlert\s*\(/g)?.length || 0;
      if (count > 0) calls.set(path.relative(engineSrc, absolute), count);
    }
  };
  visit(engineSrc);
  return calls;
}

const directManagedAlertCalls = directManagedAlertCallMap();
eq("direct emitManagedAlert runtime caller set is pinned",
  [...directManagedAlertCalls.keys()].sort(),
  ["engines/alert-consumers.js", "engines/spf-corroboration.js"]);
eq("lifecycle presentation bottleneck owns exactly one direct emitter call",
  directManagedAlertCalls.get("engines/alert-consumers.js"), 1);
eq("SPF corroboration deliberate non-lifecycle exemption owns exactly one direct emitter call",
  directManagedAlertCalls.get("engines/spf-corroboration.js"), 1);

function buildDb() {
  const db = new DatabaseSync(":memory:");
  const apply = (file) => {
    try { db.exec(fs.readFileSync(file, "utf8")); }
    catch { /* schema/migration overlap is intentionally tolerated */ }
  };
  apply(path.join(root, "database", "schema.sql"));
  for (const file of fs.readdirSync(path.join(root, "database", "migrations"))
    .filter((name) => name.endsWith(".sql")).sort()) {
    apply(path.join(root, "database", "migrations", file));
  }
  db.exec("PRAGMA foreign_keys = OFF");
  return db;
}

function makeD1(db) {
  const statement = (sql, args = []) => ({
    bind: (...bound) => statement(sql, bound),
    first: async (column) => {
      const row = db.prepare(sql).get(...args) ?? null;
      return column && row ? row[column] : row;
    },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => {
      const result = db.prepare(sql).run(...args);
      return { success: true, meta: { changes: result.changes } };
    },
  });
  return { prepare: (sql) => statement(sql) };
}

const db = buildDb();
const sent = [];
const originalFetch = globalThis.fetch;
const originalError = console.error;
globalThis.fetch = async (input, init) => {
  if (String(input).includes("resend.com")) {
    const payload = JSON.parse(String(init?.body || "{}"));
    sent.push(payload);
    return new Response(JSON.stringify({ id: `prb_${sent.length}` }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
  return new Response("{}", { status: 200 });
};
// Keep mutant output bounded; failed assertions still use the original writer.
if (mutantChild) console.error = (...args) => originalError(...args);

const env = {
  cybermeters_db: makeD1(db),
  ALERT_EMAIL_FROM: "alerts@cybermeters.com",
  RESEND_API_KEY: "re_prb_test",
  FRONTEND_URL: "https://app.cybermeters.com",
};

function seedWorkspace(key, name = null) {
  const user = `u_${key}`;
  const ws = `ws_${key}`;
  const domainId = `dom_${key}`;
  const domain = `${key}.example.com`;
  db.prepare(`INSERT INTO users (id,email,name,plan,email_verified,created_at)
              VALUES (?,?,?,'professional',1,datetime('now'))`)
    .run(user, `${key}@example.com`, `Owner ${key}`);
  db.prepare(`INSERT INTO subscriptions
      (id,owner_user_id,plan,subscription_status,status,current_period_end,created_at,updated_at)
      VALUES (?,?,'professional','active','active',datetime('now','+30 days'),datetime('now'),datetime('now'))`)
    .run(`sub_${key}`, user);
  db.prepare("INSERT INTO workspaces (id,owner_user_id,name) VALUES (?,?,?)")
    .run(ws, user, name || `Workspace ${key}`);
  db.prepare("INSERT INTO workspace_members (id,workspace_id,user_id,role) VALUES (?,?,?,'owner')")
    .run(`mem_${key}`, ws, user);
  db.prepare("INSERT INTO domains (id,user_id,domain) VALUES (?,?,?)")
    .run(domainId, user, domain);
  db.prepare("INSERT INTO workspace_domains (workspace_id,domain_id) VALUES (?,?)")
    .run(ws, domainId);
  return { key, user, ws, domainId, domain };
}

function activate(fx, domainKey) {
  db.prepare(`INSERT INTO alert_activation
      (id,workspace_id,domain_key,activated_at,baseline_count,created_at)
      VALUES (?,?,?,'2020-01-01T00:00:00Z',0,datetime('now'))`)
    .run(`aa_${fx.key}_${domainKey}`, fx.ws, domainKey);
}

let occurrenceSeq = 0;
function seedOccurrence(fx, domainKey, recurrence, recordId) {
  occurrenceSeq += 1;
  const detail = JSON.stringify({
    from_monitoring_status: "baseline",
    to_monitoring_status: "observed",
    from_recurrence_type: null,
    to_recurrence_type: recurrence,
    required_case_action: "review",
    reason: "fixture",
    entity: fx.domain,
  });
  if (domainKey === "website_security") {
    db.prepare(`INSERT INTO website_security_events
        (id,record_id,workspace_id,actor_type,event_type,detail_json,created_at)
        VALUES (?,?,?,'system','monitoring_changed',?,'2026-07-29T12:00:00Z')`)
      .run(`wse_prb_${occurrenceSeq}`, recordId, fx.ws, detail);
  } else {
    db.prepare(`INSERT INTO cyber_essentials_events
        (id,record_id,workspace_id,actor_type,event_type,detail_json,created_at)
        VALUES (?,?,?,'system','monitoring_changed',?,'2026-07-29T12:00:00Z')`)
      .run(`cee_prb_${occurrenceSeq}`, recordId, fx.ws, detail);
  }
}

function latestNotification(fx) {
  const row = db.prepare(
    "SELECT * FROM notification_events WHERE workspace_id=? ORDER BY rowid DESC LIMIT 1",
  ).get(fx.ws) || null;
  if (!row) return null;
  let metadata = {};
  try { metadata = JSON.parse(row.metadata_json || "{}"); } catch { metadata = {}; }
  return { ...row, metadata };
}

async function emitWebsite(key, moduleEvidence, {
  recurrence = "transport_not_available",
  findingType = "ssl_not_available",
  evidenceSource = null,
} = {}) {
  const fx = seedWorkspace(key);
  activate(fx, "website_security");
  const recordId = `wsc_${key}`;
  seedOccurrence(fx, "website_security", recurrence, recordId);
  const before = sent.length;
  const result = await emitLifecycleAlert(env, {
    workspace_id: fx.ws,
    domain_key: "website_security",
    record_id: recordId,
    entity: `${fx.domain}:${findingType}`,
    hostname: fx.domain,
    recurrence,
    record_severity: findingType === "ssl_not_available" ? "critical" : "medium",
    finding_type: findingType,
    module_evidence: moduleEvidence,
    evidence_source: evidenceSource,
  });
  return {
    fx,
    result,
    notification: latestNotification(fx),
    mail: sent.length > before ? sent.at(-1) : null,
  };
}

async function emitCe(key, controlKey, controlLabel) {
  const fx = seedWorkspace(key);
  activate(fx, "cyber_essentials_readiness");
  const recordId = `cec_${key}`;
  const recurrence = "externally_observed_control_not_ready";
  seedOccurrence(fx, "cyber_essentials_readiness", recurrence, recordId);
  const before = sent.length;
  const result = await emitLifecycleAlert(env, {
    workspace_id: fx.ws,
    domain_key: "cyber_essentials_readiness",
    record_id: recordId,
    entity: controlKey,
    recurrence,
    finding_type: "ce_control_not_ready",
    entity_type: "control_area",
    entity_display: controlLabel,
  });
  return {
    fx,
    result,
    notification: latestNotification(fx),
    mail: sent.length > before ? sent.at(-1) : null,
  };
}

const mailText = (trace) => `${trace.mail?.text || ""}\n${trace.mail?.html || ""}`;
function assertParity(label, trace) {
  const body = mailText(trace);
  ok(`${label}: alert emitted`, trace.result?.emitted === true, JSON.stringify(trace.result));
  ok(`${label}: real email payload captured`, Boolean(trace.mail));
  eq(`${label}: email subject equals persisted title`, trace.mail?.subject, trace.notification?.title);
  ok(`${label}: email body carries persisted What Changed`,
    body.includes(trace.notification?.message || "__missing__"));
  ok(`${label}: email action equals persisted action`,
    body.includes(trace.notification?.metadata?.recommended_action || "__missing__"));
}

function assertUncertain(label, trace, headline) {
  const body = mailText(trace);
  assertParity(label, trace);
  eq(`${label}: bounded evidence headline`, trace.notification?.title, headline);
  ok(`${label}: explanation is explicitly an incomplete observation`,
    /could not complete (an HTTPS\/TLS|the HTTP-to-HTTPS redirect) observation/i
      .test(trace.notification?.message || ""));
  ok(`${label}: action asks for evidence review and another assessment`,
    /Review the available evidence and run another assessment/i
      .test(trace.notification?.metadata?.recommended_action || ""));
  ok(`${label}: subject never claims a missing certificate`,
    !/missing certificate|install.*certificate|no certificate/i.test(trace.mail?.subject || ""));
  ok(`${label}: body never claims traffic is unencrypted`,
    !/all traffic.*unencrypted|serves only unencrypted|traffic is unencrypted/i.test(body));
  ok(`${label}: action never says install/renew/replace a certificate`,
    !/\b(install|renew|replace)\b[^.]{0,50}\bcertificate\b/i
      .test(trace.notification?.metadata?.recommended_action || ""));
  ok(`${label}: no healthy/resolved/fixed language`,
    !/\b(healthy|resolved|fixed|secure)\b/i.test(
      `${trace.notification?.title} ${trace.notification?.message} ${trace.notification?.metadata?.recommended_action}`,
    ));
}

function assertConflict(label, trace, headline) {
  const body = mailText(trace);
  assertParity(label, trace);
  eq(`${label}: bounded conflict headline`, trace.notification?.title, headline);
  eq(`${label}: conflict state is explicit`,
    trace.notification?.metadata?.presentation_state, "evidence_conflict");
  ok(`${label}: body names conflicting evidence without asserting a defect`,
    /conflicting .* evidence/i.test(trace.notification?.message || "")
    && /could not confirm/i.test(trace.notification?.message || ""));
  ok(`${label}: action requests review and another assessment`,
    /Review the alert evidence and run another assessment/i
      .test(trace.notification?.metadata?.recommended_action || ""));
  ok(`${label}: subject never claims a missing certificate`,
    !/missing certificate|install.*certificate|no certificate/i.test(trace.mail?.subject || ""));
  ok(`${label}: body never claims traffic is unencrypted`,
    !/all traffic.*unencrypted|serves only unencrypted|traffic is unencrypted/i.test(body));
  ok(`${label}: action never says install/renew/replace a certificate`,
    !/\b(install|renew|replace)\b[^.]{0,50}\bcertificate\b/i
      .test(trace.notification?.metadata?.recommended_action || ""));
  eq(`${label}: certificate remediation identity is withheld`,
    trace.notification?.metadata?.remediation_id, null);
}

console.log("── PR-B real customer-renderer traces ──");

// 1. Cloudflare edge / origin unreachable.
const edge = await emitWebsite("edge", {
  https_available: null,
  https_probe_executed: true,
  https_observation_state: "cloudflare_edge_error",
  https_observation_reason: "origin_unreachable",
  https_observation_completeness: "incomplete",
  incomplete: true,
  incomplete_reason: "https_origin_not_observed",
});
assertUncertain("edge/origin-unreachable", edge, "HTTPS could not be verified");
eq("edge state is preserved in notification metadata",
  edge.notification?.metadata?.evidence_state, "cloudflare_edge_error");
ok("edge event is labelled as an affected domain", mailText(edge).includes(`Affected Domain: ${edge.fx.domain}`));

// 2. Generic transport unavailable.
const unavailable = await emitWebsite("unavailable", {
  https_available: null,
  https_probe_executed: false,
  https_observation_state: "transport_unavailable",
  https_observation_completeness: "unavailable",
  incomplete: true,
  incomplete_reason: "https_transport_unavailable",
});
assertUncertain("transport-unavailable", unavailable, "HTTPS could not be verified");
eq("transport-unavailable state is preserved",
  unavailable.notification?.metadata?.evidence_state, "transport_unavailable");

// 3. Not assessed / deadline incomplete.
const notAssessed = await emitWebsite("notassessed", {
  executed: false,
  incomplete: true,
  outcome: "deadline_exceeded",
  https_available: null,
  https_probe_executed: false,
  https_observation_state: "not_assessed",
  https_observation_reason: "deadline_deferred",
});
assertUncertain("not-assessed", notAssessed, "HTTPS could not be verified");
eq("not-assessed state is preserved",
  notAssessed.notification?.metadata?.evidence_state, "not_assessed");

// 4. Positive certificate defect.
const cert = await emitWebsite("certdefect", {
  https_available: false,
  https_probe_executed: true,
});
assertParity("positive certificate defect", cert);
ok("positive certificate subject stays specific",
  /Enable HTTPS with a valid certificate/i.test(cert.mail?.subject || ""));
ok("positive certificate body says completed evidence identified the defect",
  /completed HTTPS\/TLS assessment positively identified/i.test(cert.notification?.message || ""));
ok("positive certificate action stays specific",
  /Install a publicly trusted TLS certificate/i
    .test(cert.notification?.metadata?.recommended_action || ""));
eq("positive certificate state is explicit",
  cert.notification?.metadata?.presentation_state, "positively_observed_certificate_defect");

// 5. Positive origin-observed no-redirect defect.
const redirect = await emitWebsite("redirect", {
  https_available: true,
  http_redirects_to_https: false,
  http_redirect_chain: {
    observation_state: "origin_response",
    observation_completeness: "observed",
    http_redirect_validated: true,
  },
}, {
  recurrence: "insecure_redirect",
  findingType: "ssl_no_http_redirect",
});
assertParity("positive redirect defect", redirect);
ok("positive redirect subject stays specific",
  /Redirect HTTP to HTTPS/i.test(redirect.mail?.subject || ""));
ok("positive redirect body names completed origin observation",
  /completed origin HTTP observation/i.test(redirect.notification?.message || ""));
ok("positive redirect action stays specific",
  /permanent 301 redirect/i.test(redirect.notification?.metadata?.recommended_action || ""));
eq("positive redirect state is explicit",
  redirect.notification?.metadata?.presentation_state, "positively_observed_redirect_defect");

// An unavailable redirect gets the same bounded decision across all fields.
const redirectUnknown = await emitWebsite("redirectunknown", {
  https_available: true,
  incomplete: true,
  incomplete_reason: "http_redirect_not_observed",
  http_redirects_to_https: false,
  http_redirect_chain: {
    observation_state: "transport_unavailable",
    observation_completeness: "unavailable",
    http_redirect_validated: false,
  },
}, {
  recurrence: "insecure_redirect",
  findingType: "ssl_no_http_redirect",
});
assertUncertain(
  "redirect-unavailable",
  redirectUnknown,
  "HTTP-to-HTTPS redirect could not be verified",
);

// 6. Completed healthy evidence creates no occurrence in the real evaluator.
{
  const fx = seedWorkspace("healthy");
  activate(fx, "website_security");
  const beforeMail = sent.length;
  const result = await evaluateWebsiteSecurityForScan(env, {
    workspace_id: fx.ws,
    domain_id: fx.domainId,
    domain: fx.domain,
    scan_id: "scan_healthy",
    findings: [],
    modules: {
      ssl: {
        https_available: true,
        https_probe_executed: true,
        http_redirects_to_https: true,
        http_redirect_chain: {
          observation_state: "origin_response",
          observation_completeness: "observed",
          http_redirect_validated: true,
        },
      },
      headers: { accessible: true, headers_assessed: true },
    },
    scanQuality: { status: "complete", modules_skipped: [], warnings: [] },
  });
  eq("healthy control: evaluator emitted zero alerts", result.alerts, 0);
  eq("healthy control: no notification persisted", latestNotification(fx), null);
  eq("healthy control: no email rendered", sent.length, beforeMail);
}

// 7. If an eligible certificate occurrence contradicts completed healthy
// evidence, presentation surfaces the conflict; it never suppresses delivery.
const certificateConflict = await emitWebsite("certificateconflict", {
  https_available: true,
  https_probe_executed: true,
  https_observation_state: "origin_response",
  https_observation_completeness: "observed",
});
assertConflict("certificate evidence conflict", certificateConflict, "HTTPS evidence requires review");
eq("certificate conflict preserves completed observation state",
  certificateConflict.notification?.metadata?.evidence_state, "origin_response");

// 8. The redirect contradiction follows the same no-suppression contract.
const redirectConflict = await emitWebsite("redirectconflict", {
  https_available: true,
  http_redirects_to_https: true,
  http_redirect_chain: {
    observation_state: "origin_response",
    observation_completeness: "observed",
    http_redirect_validated: true,
  },
}, {
  recurrence: "insecure_redirect",
  findingType: "ssl_no_http_redirect",
});
assertConflict(
  "redirect evidence conflict",
  redirectConflict,
  "HTTP-to-HTTPS redirect evidence requires review",
);
eq("redirect conflict preserves completed observation state",
  redirectConflict.notification?.metadata?.evidence_state, "origin_response");

// 9 + 10. Cyber Essentials control-area labels through the same renderer.
for (const [key, controlKey, label] of [
  ["ceboundary", "boundary_protection", "Boundary Protection"],
  ["cesecure", "secure_configuration", "Secure Configuration"],
]) {
  const trace = await emitCe(key, controlKey, label);
  assertParity(`CE ${controlKey}`, trace);
  const body = mailText(trace);
  ok(`CE ${controlKey}: affected object is a control area`,
    body.includes(`Affected Control Area: ${label}`));
  ok(`CE ${controlKey}: raw key is not labelled as a domain`,
    !body.includes(`Affected Domain: ${controlKey}`));
  eq(`CE ${controlKey}: typed metadata is persisted`,
    [trace.notification?.metadata?.entity_type, trace.notification?.metadata?.entity_display],
    ["control_area", label]);
  ok(`CE ${controlKey}: subject/body/action all use readiness framing`,
    /Cyber Essentials control area/i.test(trace.mail?.subject || "")
    && /control area/i.test(trace.notification?.message || "")
    && /Cyber Essentials page/i.test(trace.notification?.metadata?.recommended_action || ""));
}

// 11. Trustworthy sibling evidence survives an uncertain HTTPS observation.
const mixed = await emitWebsite("mixed", {
  https_available: null,
  https_probe_executed: true,
  https_observation_state: "cloudflare_edge_error",
  https_observation_reason: "origin_unreachable",
  incomplete: true,
  incomplete_reason: "https_origin_not_observed",
  cert_issuer: "Fixture CA",
}, {
  evidenceSource: {
    label: "Certificate Transparency",
    detail: "Fixture CA certificate observed independently",
    last_seen_at: "2026-07-29T12:00:00Z",
  },
});
assertUncertain("mixed sibling evidence", mixed, "HTTPS could not be verified");
ok("mixed alert retains the trustworthy sibling evidence heading",
  mailText(mixed).includes("How this was observed:"));
ok("mixed alert retains the independent CT fact",
  mailText(mixed).includes("Fixture CA certificate observed independently"));
ok("mixed alert does not turn the sibling certificate observation into transport proof",
  mixed.notification?.metadata?.presentation_state === "observation_unavailable");

async function runMutants() {
  console.log("\n── PR-B fresh-process mutation proof ──");
  const mutations = [
    {
      name: "M1 restore Install a TLS certificate for unavailable transport",
      file: "engines/customer-alert-presentation.js",
      from: '"Review the available evidence and run another assessment. If the result persists, verify HTTPS availability with your hosting provider."',
      to: '"Install a TLS certificate and enable HTTPS."',
    },
    {
      name: "M2 restore all traffic is transmitted unencrypted",
      file: "engines/customer-alert-presentation.js",
      from: 'what_changed: "CyberMeters could not complete an HTTPS/TLS observation during this assessment.",',
      to: 'what_changed: "HTTPS is unavailable and all traffic is transmitted unencrypted.",',
    },
    {
      name: "M3 restore Affected Domain for CE control-area events",
      file: "engines/managed-alerts.js",
      from: 'control_area: "Affected Control Area",',
      to: 'control_area: "Affected Domain",',
    },
    {
      name: "M4 select transport subject from finding id instead of evidence state",
      file: "engines/customer-alert-presentation.js",
      from: "      ...HTTPS_UNCERTAIN,\n      evidence_state: observationState(module_evidence, type),",
      to: "      ...HTTPS_UNCERTAIN,\n      title: canonical?.title || type,\n      evidence_state: observationState(module_evidence, type),",
    },
    {
      name: "M5 generalise a positively observed certificate defect",
      file: "engines/customer-alert-presentation.js",
      from: "    if (publishable && module_evidence?.https_available === false) {",
      to: "    if (false && publishable && module_evidence?.https_available === false) {",
    },
    {
      name: "M6 generalise a positively observed redirect defect",
      file: "engines/customer-alert-presentation.js",
      from: "    publishable\n    && module_evidence?.http_redirects_to_https === false",
      to: "    false && publishable\n    && module_evidence?.http_redirects_to_https === false",
    },
    {
      name: "M7 let uncertain body and action use different evidence states",
      file: "engines/customer-alert-presentation.js",
      from: "      ...HTTPS_UNCERTAIN,\n      evidence_state: observationState(module_evidence, type),",
      to: "      ...HTTPS_UNCERTAIN,\n      recommended_action: canonical?.recommended_action || HTTPS_REVIEW_ACTION,\n      evidence_state: observationState(module_evidence, type),",
    },
    {
      name: "M8 restore presentation-driven silent suppression",
      edits: [
        {
          file: "engines/customer-alert-presentation.js",
          from: "        ...HTTPS_CONFLICT,\n        evidence_state: observationState(module_evidence, type),",
          to: "        ...HTTPS_CONFLICT,\n        publish: false,\n        evidence_state: observationState(module_evidence, type),",
        },
        {
          file: "engines/alert-consumers.js",
          from: "    });\n\n    return await emitManagedAlert(env, {",
          to: "    });\n    if (presentation.publish !== true) return { skipped: \"evidence_does_not_support_alert\" };\n\n    return await emitManagedAlert(env, {",
        },
      ],
    },
  ];

  eq("mutant definitions are pinned", mutations.length, EXPECTED_MUTANTS);
  let killed = 0;
  for (const mutation of mutations) {
    const temp = fs.mkdtempSync(path.join(root, "workers", "scan-api", ".prb-mutant-"));
    const copiedSrc = path.join(temp, "src");
    try {
      fs.cpSync(path.join(root, "workers", "scan-api", "src"), copiedSrc, { recursive: true });
      const edits = mutation.edits || [{
        file: mutation.file,
        from: mutation.from,
        to: mutation.to,
      }];
      const prepared = [];
      const anchorDetails = [];
      let anchorsValid = true;
      for (const edit of edits) {
        const target = path.join(copiedSrc, edit.file);
        const source = fs.readFileSync(target, "utf8");
        const matches = source.split(edit.from).length - 1;
        anchorDetails.push(`${edit.file}=${matches}`);
        if (matches !== 1) anchorsValid = false;
        prepared.push({ ...edit, target, source });
      }
      ok(`${mutation.name}: anchors match exactly once`, anchorsValid, anchorDetails.join(", "));
      if (!anchorsValid) continue;
      for (const edit of prepared) {
        fs.writeFileSync(edit.target, edit.source.replace(edit.from, edit.to));
      }
      const child = spawnSync(process.execPath, [fileURLToPath(import.meta.url), "--mutant-child"], {
        cwd: root,
        env: { ...process.env, PR_B_ENGINE_SRC: copiedSrc },
        encoding: "utf8",
        timeout: 120_000,
        maxBuffer: 4 * 1024 * 1024,
      });
      const caught = child.status !== 0;
      if (caught) killed += 1;
      ok(`${mutation.name}: killed by real renderer assertions`, caught,
        `exit=${child.status}\n${String(child.stdout || "").slice(-500)}\n${String(child.stderr || "").slice(-500)}`);
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  }
  eq(`mutants killed ${killed}/${EXPECTED_MUTANTS} (pinned)`, killed, EXPECTED_MUTANTS);
}

if (!mutantChild) await runMutants();

globalThis.fetch = originalFetch;
console.error = originalError;

if (!mutantChild) {
  ok(`assertion count pinned at ${EXPECTED_ASSERTIONS}`,
    passed + failed + 1 === EXPECTED_ASSERTIONS,
    `count including this assertion=${passed + failed + 1}`);
}
console.log(`\ncustomer-alert evidence fidelity: ${passed}/${passed + failed} passed`);
if (failed) {
  console.error("customer-alert evidence-fidelity validation FAILED");
  process.exit(1);
}
console.log("customer-alert evidence-fidelity validation passed");
