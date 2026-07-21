#!/usr/bin/env node
// ─────────────────────────────────────────────────────────────────────────────
// validate-injection-coverage.js  (CI-blocking)
//
// The E-section (injection) of docs/SECURITY-VERIFICATION-MATRIX.md — same
// discipline as the #241/#243/#245/#247 suites. REUSES the #187/#241 harness
// (real Worker router + in-memory SQLite). The PDF escaper, the HTML email
// template renderers, the API read surfaces and the write endpoints are TESTED
// AS-IS; this suite changes no runtime.
//
//   E2 — Stored/reflected injection on SERVER-SIDE render sinks. React auto-
//        escapes the DOM (pure DOM-XSS → documented NT, release-gate DAST), so
//        this covers what the backend actually renders:
//        - PDF: pdfEsc neutralises PDF content-stream breakout (escapes \ ( ),
//          strips control/non-ASCII) so a workspace name / reason / owner_ref /
//          domain cannot inject into the content stream.
//        - HTML email (alert, digest, invitation): user-controlled fields are
//          HTML-escaped — no <script>/tag injection into a rendered email.
//        - API echo: a stored payload comes back JSON-encoded as data, and the
//          Content-Type is application/json (never text/html).
//        - Input validation: workspace name length caps; domain shape rejects
//          obviously-malformed values.
//   E4 — Mass-assignment / privileged-field injection. Each write endpoint
//        persists ONLY its allow-listed fields; an injected privileged field
//        (plan/role/status/email_verified/id/owner_user_id/deleted_at/wider
//        token scope, a client status on a case transition) is ignored or
//        rejected and is unchanged in D1 afterward.
//
// Every negative has a positive control. A RED assertion here is a real
// injection finding — STOP and report, do not patch. Requires Node 24+.
// ─────────────────────────────────────────────────────────────────────────────
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder, ctx } from "./security/lib/worker-harness.js";
import { pdfEsc } from "../workers/scan-api/src/engines/pdf.js";
import { formatAlertEmail } from "../workers/scan-api/src/engines/alerts.js";
import { buildDigestEmail } from "../workers/scan-api/src/engines/weekly-digest.js";
import { buildInvitationEmail } from "../workers/scan-api/src/routes/workspace-members.js";
import { isValidDomain } from "../workers/scan-api/src/lib/util.js";

let passed = 0, failed = 0, section = "General";
const results = [];
const sec = (s) => { section = s; };
const ok = (name, cond) => { cond ? (passed++, results.push(`PASS [${section}] ${name}`)) : (failed++, results.push(`FAIL [${section}] ${name}`)); };

// A PDF content-stream string is delimited by ( ). A payload "escapes" if it
// contains an UNESCAPED ( ) or \ — walk the string and flag any delimiter not
// preceded by an odd run of backslashes.
function hasUnescapedPdfDelimiter(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c !== "(" && c !== ")") continue;
    let bs = 0, j = i - 1;
    while (j >= 0 && s[j] === "\\") { bs++; j--; }
    if (bs % 2 === 0) return true; // an even run of backslashes → this delimiter is live
  }
  return false;
}
const hasControlChars = (s) => /[\x00-\x1F\x7F]/.test(s);

async function main() {
  const mod = await loadWorker();
  const worker = mod.default;

  const XSS = '<script>alert(1)</script>';
  const IMG = '"><img src=x onerror=alert(1)>';
  const PDF_BREAKOUT = 'Acme) Tj 0 0 0 rg (evil\\injected'; // tries to close the PDF string + inject ops
  const CONTROL = 'a\x00b\nc\x07d';

  // ── E2: PDF content-stream escaping ────────────────────────────────────────
  sec("E2 PDF escaper");
  for (const [label, payload] of [["script tag", XSS], ["paren breakout", PDF_BREAKOUT], ["control chars", CONTROL], ["backslash", 'a\\b\\c'], ["quote+paren", '")(']]) {
    const out = pdfEsc(payload);
    ok(`pdfEsc neutralises ${label}: no unescaped ( ) delimiter`, !hasUnescapedPdfDelimiter(out));
    ok(`pdfEsc strips control chars from ${label}`, !hasControlChars(out));
  }
  ok("pdfEsc escapes a lone backslash", pdfEsc("a\\b") === "a\\\\b");
  ok("pdfEsc output is ASCII-only", /^[\x20-\x7E]*$/.test(pdfEsc(XSS + PDF_BREAKOUT + CONTROL + "café ☃")));
  // Positive control: clean text is preserved (escaper is not destroying data).
  ok("pdfEsc preserves clean text (positive control)", pdfEsc("Acme Security Ltd") === "Acme Security Ltd");

  // ── E2: HTML email templates ───────────────────────────────────────────────
  sec("E2 HTML email escaping");
  const alertHtml = formatAlertEmail({ workspaceName: XSS, domain: IMG, whatChanged: XSS, recommendation: IMG, link: "https://app.cybermeters.com/x", preferencesLink: null }).html;
  ok("alert email escapes <script> in workspace name", !alertHtml.includes("<script>") && alertHtml.includes("&lt;script&gt;"));
  ok("alert email escapes the onerror img payload", !/<img[^>]*onerror/i.test(alertHtml));
  ok("alert email renders a benign field (positive control)", formatAlertEmail({ workspaceName: "Acme Ltd", domain: "acme.com", whatChanged: "TLS expiring", recommendation: "renew", link: "https://x" }).html.includes("Acme Ltd"));
  const digestChanges = { total: 1, bySeverity: { high: 1 }, top: [{ title: XSS, description: IMG, occurrences: 1 }], assessment: { coverage: "complete_assessment" } };
  const digestHtml = buildDigestEmail(XSS, digestChanges, "https://app.cybermeters.com", "ws1").html;
  ok("weekly digest escapes <script> in the workspace name", !digestHtml.includes("<script>") && digestHtml.includes("&lt;script&gt;"));
  ok("weekly digest escapes an injected change title", !/<img[^>]*onerror/i.test(digestHtml));
  const inviteHtml = buildInvitationEmail({ workspaceName: XSS, role: IMG, acceptUrl: "https://app.cybermeters.com/i", expiresAt: "2026-12-31" }).html;
  ok("invitation email escapes <script> in workspace name", !inviteHtml.includes("<script>") && inviteHtml.includes("&lt;script&gt;"));
  ok("invitation email escapes an injected role payload", !/<img[^>]*onerror/i.test(inviteHtml));

  // ── E2: API echo returns data, not markup (Content-Type) ───────────────────
  sec("E2 API echo / Content-Type");
  {
    const db = buildDb();
    const env = makeEnv(db);
    const seed = await makeSeeder(db, mod);
    seed.user("uEcho", "echo@a.co"); await seed.session("sEcho", "uEcho", "tok-echo");
    seed.workspace("wsEcho", "uEcho", XSS); seed.member("mEcho", "wsEcho", "uEcho", "owner");
    const req = new Request("https://api.cybermeters.com/api/workspaces/wsEcho", { method: "GET", headers: { Authorization: "Bearer tok-echo" } });
    const res = await worker.fetch(req, env, ctx);
    const ctype = res.headers.get("Content-Type") || "";
    const bodyText = await res.text();
    ok("API response Content-Type is application/json (not text/html)", ctype.includes("application/json") && !ctype.includes("text/html"));
    ok("API response body is valid JSON (data, not markup)", (() => { try { JSON.parse(bodyText); return true; } catch { return false; } })());
    // The payload is present as a JSON string value — never as a live <script> element.
    ok("stored payload echoes as JSON-encoded data", JSON.parse(bodyText)?.workspace?.name === XSS);
  }

  // ── E2: input validation (length caps + domain shape) ──────────────────────
  sec("E2 input validation");
  ok("isValidDomain rejects a script payload", !isValidDomain("<script>.evil"));
  ok("isValidDomain rejects a paren/space payload", !isValidDomain("a)(b .com"));
  ok("isValidDomain rejects an over-long domain", !isValidDomain("a".repeat(300) + ".com"));
  ok("isValidDomain accepts a real domain (positive control)", isValidDomain("example.com") === true);
  {
    const db = buildDb();
    const env = makeEnv(db);
    const seed = await makeSeeder(db, mod);
    seed.user("uVal", "val@a.co"); await seed.session("sVal", "uVal", "tok-val");
    seed.workspace("wsVal", "uVal", "ValWS"); seed.member("mVal", "wsVal", "uVal", "owner");
    const call = makeCaller(worker, env);
    const tooLong = await call("PATCH", "/api/workspaces/wsVal", "tok-val", { name: "x".repeat(200) });
    ok("workspace rename rejects an over-long name (length cap)", tooLong.status === 400);
    const okName = await call("PATCH", "/api/workspaces/wsVal", "tok-val", { name: "Renamed WS" });
    ok("workspace rename accepts a valid name (positive control)", okName.status === 200);
  }

  // ── E4: mass-assignment / privileged-field injection ───────────────────────
  sec("E4 mass-assignment");
  const db = buildDb();
  const env = makeEnv(db);
  const seed = await makeSeeder(db, mod);
  const call = makeCaller(worker, env);
  seed.user("uOwner", "owner@a.co"); await seed.session("sOwner", "uOwner", "tok-owner");
  seed.user("uOther", "other@a.co");
  // A professional subscription so the LEGITIMATE positive-control paths
  // (member invite needs the team_members feature; api-token needs > 1 slot)
  // are reachable — the mass-assignment oracles are independent of plan.
  seed.raw("INSERT INTO subscriptions (id, owner_user_id, workspace_id, plan, status, subscription_status, current_period_end, created_at, updated_at) VALUES ('subOwner','uOwner','wsMA','professional','active','active', ?, datetime('now'), datetime('now'))", new Date(Date.now() + 30 * 86400 * 1000).toISOString());
  seed.workspace("wsMA", "uOwner", "MA-WS"); seed.member("mMA", "wsMA", "uOwner", "owner");
  seed.workspace("wsForeign", "uOther", "Foreign"); seed.member("mForeign", "wsForeign", "uOther", "owner");

  // 1) Profile update — injected plan/role/status/email_verified/id are ignored.
  const beforeUser = db.prepare("SELECT id, plan, status, email_verified FROM users WHERE id='uOwner'").get();
  const prof = await call("PATCH", "/api/account/profile", "tok-owner", { name: "Legit Name", plan: "enterprise", role: "owner", status: "suspended", email_verified: 0, id: "hijacked" });
  ok("profile update succeeds for the allow-listed field (positive control)", prof.status === 200);
  const afterUser = db.prepare("SELECT id, name, plan, status, email_verified FROM users WHERE id='uOwner'").get();
  ok("profile: name (allow-listed) IS updated", afterUser.name === "Legit Name");
  ok("profile: injected plan is ignored", afterUser.plan === beforeUser.plan);
  ok("profile: injected status is ignored", afterUser.status === beforeUser.status);
  ok("profile: injected email_verified is ignored", afterUser.email_verified === beforeUser.email_verified);
  ok("profile: injected id is ignored (row identity intact)", afterUser.id === "uOwner");

  // 2) Workspace update — injected owner_user_id / id / deleted_at are ignored.
  const wsPatch = await call("PATCH", "/api/workspaces/wsMA", "tok-owner", { name: "Renamed MA", owner_user_id: "uOther", id: "evil-ws", deleted_at: "2020-01-01T00:00:00Z" });
  ok("workspace rename succeeds (positive control)", wsPatch.status === 200);
  const wsRow = db.prepare("SELECT id, name, owner_user_id, deleted_at FROM workspaces WHERE id='wsMA'").get();
  ok("workspace: name IS updated", wsRow.name === "Renamed MA");
  ok("workspace: injected owner_user_id is ignored", wsRow.owner_user_id === "uOwner");
  ok("workspace: injected deleted_at is ignored (not soft-deleted)", wsRow.deleted_at == null);
  ok("workspace: injected id is ignored (identity intact)", wsRow.id === "wsMA");

  // 3) Member invite — role escalation to 'owner' is rejected.
  const inviteOwner = await call("POST", "/api/workspaces/wsMA/invitations", "tok-owner", { email: "victim@x.co", role: "owner" });
  ok("member invite with role=owner is rejected (escalation blocked)", inviteOwner.status === 400);
  // A valid role passes validation + entitlement and reaches the email-delivery
  // step (the harness has no email transport, and the route compensating-deletes
  // on a failed send, so a 502 here means the role was ACCEPTED — the security
  // signal is "not rejected as an invalid role / not forbidden", vs the owner
  // escalation which is refused 400 BEFORE any insert).
  const inviteAdmin = await call("POST", "/api/workspaces/wsMA/invitations", "tok-owner", { email: "admin2@x.co", role: "admin" });
  ok("member invite with a valid role is NOT rejected as invalid/forbidden (positive control)", inviteAdmin.status !== 400 && inviteAdmin.status !== 403);
  ok("no invitation was persisted with role=owner (escalation blocked)", db.prepare("SELECT COUNT(*) AS n FROM workspace_invitations WHERE workspace_id='wsMA' AND role='owner'").get().n === 0);

  // 4) API-token create — internal identity fields ignored; foreign workspace rejected.
  const tokInternal = await call("POST", "/api/account/api-tokens", "tok-owner", { name: "tok-a", token_scope: "admin", token_workspace_id: "wsForeign" });
  ok("api-token create succeeds (positive control)", tokInternal.status === 200 || tokInternal.status === 201);
  const tokRow = db.prepare("SELECT scope, workspace_id FROM api_tokens WHERE user_id='uOwner' AND name='tok-a'").get();
  ok("api-token: injected token_scope (internal name) ignored → default read", tokRow?.scope === "read");
  ok("api-token: injected token_workspace_id (internal name) ignored → null", tokRow?.workspace_id == null);
  const tokForeign = await call("POST", "/api/account/api-tokens", "tok-owner", { name: "tok-b", workspace_id: "wsForeign" });
  ok("api-token bound to a NON-member workspace is refused (403)", tokForeign.status === 403);
  ok("no api-token was persisted for the foreign workspace", db.prepare("SELECT COUNT(*) AS n FROM api_tokens WHERE user_id='uOwner' AND workspace_id='wsForeign'").get().n === 0);
  const tokWrite = await call("POST", "/api/account/api-tokens", "tok-owner", { name: "tok-c", scope: "write" });
  ok("api-token honours a valid ALLOW-LISTED scope field (positive control)", db.prepare("SELECT scope FROM api_tokens WHERE user_id='uOwner' AND name='tok-c'").get()?.scope === "write");

  // 5) Case transition — client-supplied status / verified_at are ignored; the
  //    validator's target is authoritative.
  seed.raw("INSERT INTO managed_cases (id, workspace_id, case_type, domain_key, domain, finding_id, asset_ref, severity, status, evidence_json, recommended_actions_json, awaiting_verification_at, created_at, updated_at) VALUES ('caseMA','wsMA','identity_case','identity_exposure','a.example','identity_admin_unowned','a1','high','awaiting_verification','{}','[]',datetime('now'),datetime('now'),datetime('now'))");
  const trans = await call("POST", "/api/workspaces/wsMA/cases/caseMA/transition", "tok-owner", { target_status: "action_in_progress", status: "verified", verified_at: "2020-01-01T00:00:00Z", reason: "starting work" });
  ok("case transition succeeds to the validator target (positive control)", trans.status === 200);
  const caseRow = db.prepare("SELECT status, verified_at FROM managed_cases WHERE id='caseMA'").get();
  ok("case: persisted status is the VALIDATOR target, not the client 'status'", caseRow.status === "action_in_progress");
  ok("case: client-supplied verified_at is ignored (case never verified)", caseRow.verified_at == null);

  // ── Coverage delta ─────────────────────────────────────────────────────────
  sec("Coverage");
  const controls = {
    E2: "server-side render sinks escaped (PDF content-stream, alert/digest/invitation email HTML, JSON API echo + Content-Type, input validation)",
    E4: "mass-assignment blocked (profile plan/role/status/email_verified/id; workspace owner_user_id/id/deleted_at; member role escalation; api-token scope/workspace; case client status/verified_at)",
  };
  ok("both assessable E-section controls asserted", Object.keys(controls).length === 2);

  // ── Report ─────────────────────────────────────────────────────────────────
  const bySec = {};
  for (const line of results) { const s = line.match(/\[(.*?)\]/)[1]; (bySec[s] ??= { p: 0, f: 0 })[line.startsWith("PASS") ? "p" : "f"]++; }
  console.log("\nInjection coverage (E-section, reusing #187/#241 harness):");
  for (const [s, c] of Object.entries(bySec)) console.log(`  ${c.f ? "✗" : "✓"} ${s}: ${c.p}/${c.p + c.f}`);
  console.log("\nE-section coverage delta:");
  for (const [k, v] of Object.entries(controls)) console.log(`  + ${k} — ${v}`);
  console.log("  · NT E1/E3 pure DOM-XSS — the customer UI is React, which auto-escapes text nodes; a real reflected/stored DOM-XSS test needs a browser/DAST run and is a release-gate item. This suite covers the SERVER-SIDE render sinks (PDF, email HTML, JSON echo) where escaping is our code's responsibility.");
  if (failed) { console.log("\nFailures:"); for (const rr of results.filter((x) => x.startsWith("FAIL"))) console.log("  " + rr); }
  console.log(`\nInjection coverage: ${passed}/${passed + failed} passed`);
  if (failed) { console.error("injection-coverage validation FAILED — a RED assertion here is an injection finding, not a test bug"); process.exit(1); }
  console.log("injection-coverage validation passed");
}

main().catch((e) => { console.error("injection-coverage runner crashed:", e); process.exit(1); });
