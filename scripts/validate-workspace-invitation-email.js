#!/usr/bin/env node
//
// Workspace-invitation email delivery guard. CI-blocking.
//
// Root cause (production, 2026-07-19): POST /api/workspaces/:id/invitations
// created the invitation row + audit event and returned 201 { invitation, token }
// but made NO email-provider call — no sendCustomerEmail, no template. The
// frontend showed "Invitation sent" on the 201 alone, so invitations were never
// delivered. This suite pins the delivery fix so it cannot silently regress:
//
//   INV-E1  The handler imports the canonical sendCustomerEmail wrapper.
//   INV-E2  The invitation email is dispatched BEFORE the handler returns 201.
//   INV-E3  A failed send fails CLOSED: compensating-delete of the just-created
//           row (exact id + workspace + pending) then a generic non-2xx (502).
//   INV-E4  The "created" audit is written only on a successful handoff and
//           records the real delivery outcome (never a creation claim on failure).
//   INV-E5  The accept link is the canonical /invitations/:token route.
//   INV-E6  The failure audit never leaks the raw token (no token in that branch).
//   INV-E7  The manual-link panel no longer claims "No email will be sent".
//
// Each guard is a predicate over source that MUST hold on the real file AND MUST
// fail on a copy with the defect reintroduced (in-memory mutation) — self-proving.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (...p) => fs.readFileSync(path.join(root, ...p), "utf8");

const membersSrc = read("workers", "scan-api", "src", "routes", "workspace-members.js");
const panelSrc   = read("frontend", "src", "components", "WorkspaceMembersPanel.jsx");

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? pass++ : fail++; if (!cond) console.log("FAIL " + name); };

// A guard: predicate over source + a mutation that reintroduces the defect. The
// predicate must be true on the real source and false on the mutated source.
function guard(name, src, predicate, mutate) {
  ok(`${name} — holds on current source`, predicate(src) === true);
  const mutated = mutate(src);
  ok(`${name} — mutation changed the source`, mutated !== src);
  ok(`${name} — CAUGHT: predicate fails when the defect is reintroduced`, predicate(mutated) === false);
}

// ── INV-E1 Handler imports the canonical customer-email wrapper ───────────────
guard(
  "INV-E1 workspace-members imports sendCustomerEmail from lifecycle-email",
  membersSrc,
  (s) => /import \{[^}]*\bsendCustomerEmail\b[^}]*\} from "\.\.\/lib\/lifecycle-email\.js"/.test(s),
  (s) => s.replace(
    'import { escapeEmailHtml, getEmailFrontendOrigin, sendCustomerEmail } from "../lib/lifecycle-email.js";',
    'import { escapeEmailHtml, getEmailFrontendOrigin } from "../lib/lifecycle-email.js";'),
);

// ── INV-E2 Email is dispatched BEFORE the invitation POST returns 201 ─────────
// The invite POST is the FIRST `}, 201);` in the file (member-add's 201 is later),
// so the send call must precede it.
guard(
  "INV-E2 invitation email is sent before the 201 response",
  membersSrc,
  (s) => {
    const sendIdx = s.indexOf('const inviteDelivery = await sendCustomerEmail(subject, text, html, env, "HELLO_EMAIL_FROM", [email]);');
    const retIdx  = s.indexOf("}, 201);");
    return sendIdx !== -1 && retIdx !== -1 && sendIdx < retIdx;
  },
  // Reversion: remove the send call → the handler returns 201 without dispatching.
  (s) => s.replace('const inviteDelivery = await sendCustomerEmail(subject, text, html, env, "HELLO_EMAIL_FROM", [email]);',
                   "const inviteDelivery = { sent: true };"),
);

// ── INV-E3 A failed send fails CLOSED (compensating delete + generic non-2xx) ──
guard(
  "INV-E3 send failure compensating-deletes the just-created row and returns non-2xx",
  membersSrc,
  (s) => /if \(!inviteDelivery\.sent\) \{[\s\S]{0,900}?DELETE FROM workspace_invitations WHERE id = \? AND workspace_id = \? AND status = 'pending'[\s\S]{0,900}?return json\([^;]*?502\);/.test(s),
  // Reversion: neuter the compensating delete → a phantom pending invite survives.
  (s) => s.replace("DELETE FROM workspace_invitations WHERE id = ? AND workspace_id = ? AND status = 'pending'", "SELECT 1"),
);

// ── INV-E4 The "created" audit is tied to a real successful handoff ───────────
// It records delivery_status "accepted" + the provider id from the delivery
// result, and it sits AFTER the failure branch (which returns first), so a
// creation event can never be recorded for an undelivered invitation.
guard(
  "INV-E4 created audit records the real delivery outcome",
  membersSrc,
  (s) => /event_type:   "workspace_invitation_created"[\s\S]{0,500}?delivery_status: "accepted", provider_id: inviteDelivery\.provider_id \|\| null,/.test(s),
  (s) => s.replace('delivery_status: "accepted", provider_id: inviteDelivery.provider_id || null,', "audited: true,"),
);
ok("INV-E4 created audit is positioned after the send-failure branch",
   membersSrc.indexOf("if (!inviteDelivery.sent)") !== -1 &&
   membersSrc.indexOf('event_type:   "workspace_invitation_created"') !== -1 &&
   membersSrc.indexOf("if (!inviteDelivery.sent)") < membersSrc.indexOf('event_type:   "workspace_invitation_created"'));

// ── INV-E5 Accept link uses the canonical /invitations/:token route ───────────
guard(
  "INV-E5 accept URL points at /invitations/<token>",
  membersSrc,
  (s) => s.includes("`${inviteOrigin}/invitations/${token}`"),
  (s) => s.replace("`${inviteOrigin}/invitations/${token}`", "`${inviteOrigin}/accept/${token}`"),
);

// ── INV-E6 The failure branch never leaks the raw token ───────────────────────
guard(
  "INV-E6 send-failure branch does not leak the raw token",
  membersSrc,
  (s) => {
    const branch = (s.match(/if \(!inviteDelivery\.sent\) \{[\s\S]*?return json\([^;]*?502\);/) || [""])[0];
    return branch.length > 0 && /delivery_reason/.test(branch) && !/\btoken\b/.test(branch);
  },
  // Reversion: put the raw token into the failure audit metadata.
  (s) => s.replace("metadata:     { invitation_id: inviteId, email, role, delivery_reason: inviteDelivery.reason || \"send_failed\" },",
                   "metadata:     { invitation_id: inviteId, email, role, token, delivery_reason: inviteDelivery.reason || \"send_failed\" },"),
);

// ── INV-E7 Manual-link panel no longer claims "No email will be sent" ─────────
guard(
  "INV-E7 members panel copy reflects that an email is now sent",
  panelSrc,
  (s) => !/No email will be sent/.test(s) && /We email the invitee an accept link/.test(s),
  (s) => s.replace("We email the invitee an accept link. You can also share the generated link manually as a backup.",
                   "No email will be sent. Share the generated invite link manually."),
);

// ── INV-E8 The role carries the right article: a viewer, an analyst, an admin ──
const membersMod = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "routes", "workspace-members.js")).href);
ok("INV-E8 roleWithArticle: a viewer / an analyst / an admin / an owner",
   membersMod.roleWithArticle("viewer") === "a viewer" && membersMod.roleWithArticle("analyst") === "an analyst" &&
   membersMod.roleWithArticle("admin") === "an admin" && membersMod.roleWithArticle("owner") === "an owner" &&
   membersMod.roleWithArticle("") === "a member");
{
  const mail = membersMod.buildInvitationEmail({ workspaceName: "Acme", role: "analyst", acceptUrl: "https://app.example/invitations/t", expiresAt: new Date(Date.now() + 7 * 864e5).toISOString() });
  ok("INV-E8 invitation text and HTML say 'as an analyst' (never 'as a analyst')",
     /as an analyst\./.test(mail.text) && /as <strong>an analyst<\/strong>\./.test(mail.html) && !/as a analyst|as a <strong>/.test(mail.text + mail.html));
  const viewer = membersMod.buildInvitationEmail({ workspaceName: "Acme", role: "viewer", acceptUrl: "https://app.example/invitations/t" });
  ok("INV-E8 invitation says 'as a viewer'", /as a viewer\./.test(viewer.text) && /as <strong>a viewer<\/strong>\./.test(viewer.html));
  // ── INV-E9 Aqua scheme: aqua button with dark ink, aqua-ink links; no old green, no white on aqua ──
  ok("INV-E9 invitation button is aqua #a9f2e5 with #081f1c ink",
     /<a href="https:\/\/app\.example\/invitations\/t" style="[^"]*background:#a9f2e5;color:#081f1c[^"]*">Accept invitation<\/a>/.test(mail.html));
  ok("INV-E9 invitation wordmark and link use the aqua ink #117362", (mail.html.match(/#117362/g) || []).length >= 2);
  ok("INV-E9 invitation HTML carries no old green and no white text on the aqua ground",
     !/#0a7c5c|#00876a/i.test(mail.html) && !/background:#a9f2e5[^"]*color:#fff/i.test(mail.html));
  ok("INV-E9 invitation secondary text is at least 14px and gray-600 or darker",
     !/font-size:1[0-3]px/.test(mail.html) && !/color:#(999|bbb|ccc|ddd)\b/i.test(mail.html));
}
guard(
  "INV-E8 invitation copy uses roleWithArticle for the role",
  membersSrc,
  (s) => /const roleText\s*=\s*roleWithArticle\(role\)/.test(s) && /on CyberMeters as \$\{roleText\}\./.test(s),
  (s) => s.replace("const roleText   = roleWithArticle(role);", "const roleText   = `a ${role}`;"),
);
// Every customer email template in scan-api follows the same scheme.
for (const file of [
  ["routes", "auth.js"], ["lib", "lifecycle-email.js"], ["engines", "alerts.js"], ["engines", "asset-alerts.js"],
]) {
  const src = read("workers", "scan-api", "src", ...file);
  ok(`INV-E9 ${file.join("/")} carries no old green (#0a7c5c / #00876A)`, !/#0a7c5c|#00876a/i.test(src));
  ok(`INV-E9 ${file.join("/")} puts no white text on the aqua ground`, !/#a9f2e5[^"'`]{0,80}color:\s*(#fff\b|#ffffff|white)/i.test(src));
}

// ── Regression: existing fail-closed rate limits must remain intact ───────────
ok("invite hourly rate limit remains fail-closed",
   /consumeApiRateLimit\(env, inviteScopes, "invite_send", 10, 3600, \{ failClosed: true \}\)/.test(membersSrc));
ok("invite daily rate limit remains fail-closed",
   /consumeApiRateLimit\(env, inviteScopes, "invite_send_daily", 25, 86400, \{ failClosed: true \}\)/.test(membersSrc));

console.log(`\nvalidate-workspace-invitation-email: ${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
