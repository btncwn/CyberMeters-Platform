// ── Weekly Exposure Timeline digest ───────────────────────────────────────────
// The cheapest, most habit-forming output: a Monday "what changed this week"
// email that pulls the customer back into the product and reinforces "we're
// watching". Sent only to ACTIVE workspaces (owner with a verified email + at
// least one monitored domain), at most once per ISO week (deduped through
// lifecycle_email_events). Quiet weeks still send a short "all quiet"
// reassurance — stability is the message — but dormant workspaces get nothing,
// protecting deliverability. Never throws.

import { enrichEvent, SEVERITY_RANK } from "../lib/exposure-events.js";
import { collapseCustomerTimelineEvents } from "./timeline-trust.js";
import { deliverEmail, escapeEmailHtml } from "../lib/lifecycle-email.js";
import { createId } from "../lib/util.js";

const DIGEST_TYPE = "lifecycle_weekly_digest";
const MAX_WORKSPACES_PER_RUN = 200;
const TOP_EVENTS = 5;

// ISO-8601 week key, e.g. "2026-W28" — the dedupe scope so each week is distinct.
export function isoWeekKey(date = new Date()) {
  const d = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth(), date.getUTCDate()));
  const dayNum = (d.getUTCDay() + 6) % 7; // Mon=0..Sun=6
  d.setUTCDate(d.getUTCDate() - dayNum + 3); // nearest Thursday
  const firstThursday = new Date(Date.UTC(d.getUTCFullYear(), 0, 4));
  const week = 1 + Math.round(((d - firstThursday) / 86400000 - 3 + ((firstThursday.getUTCDay() + 6) % 7)) / 7);
  return `${d.getUTCFullYear()}-W${String(week).padStart(2, "0")}`;
}

// Read-only: the week's change events for a workspace, summarised.
export async function computeWeeklyChanges(env, workspaceId) {
  const rows = await env.cybermeters_db
    .prepare(
      `SELECT id, event_type, hostname, severity, description, created_at
       FROM asset_events
       WHERE workspace_id = ? AND created_at > datetime('now', '-7 days')
       ORDER BY created_at DESC`
    )
    .bind(workspaceId)
    .all()
    .catch(() => ({ results: [] }));

  const events = collapseCustomerTimelineEvents(rows.results || []).map(enrichEvent);
  const bySeverity = {}, byCategory = {};
  for (const e of events) {
    bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
    byCategory[e.category] = (byCategory[e.category] || 0) + 1;
  }
  const top = [...events]
    .sort((a, b) => (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0))
    .slice(0, TOP_EVENTS);
  return { total: events.length, bySeverity, byCategory, top };
}

// Pure: build the digest email. total === 0 → the short "all quiet" reassurance.
export function buildDigestEmail(wsName, changes, origin) {
  const name = wsName || "your workspace";
  const link = `${(origin || "https://app.cybermeters.com").replace(/\/$/, "")}/exposure`;
  // Canonical HTML escaper (also escapes quotes) — future-proofs against a value
  // ever being interpolated into an HTML attribute in this builder.
  const esc = escapeEmailHtml;

  if (changes.total === 0) {
    const subject = `Your CyberMeters week — all quiet on ${name}`;
    const text = `No changes to your internet-facing exposure this week. Your security posture is stable — we'll keep watching and let you know the moment something changes.\n\nView your timeline: ${link}`;
    const html = `<h2>All quiet this week</h2><p>No changes to ${esc(name)}'s internet-facing exposure this week. Your security posture is stable — we'll keep watching.</p><p><a href="${link}">View your timeline →</a></p>`;
    return { subject, text, html };
  }

  const sev = changes.bySeverity;
  const sevLine = ["critical", "high", "medium", "low", "info"]
    .filter((s) => sev[s]).map((s) => `${sev[s]} ${s}`).join(" · ");
  const subject = `Your CyberMeters week — ${changes.total} change${changes.total === 1 ? "" : "s"} on ${name}`;
  const topText = changes.top.map((e) => `• ${e.title}: ${e.description || ""}`).join("\n");
  const text =
    `${changes.total} change${changes.total === 1 ? "" : "s"} to ${name}'s internet-facing exposure this week` +
    (sevLine ? ` (${sevLine})` : "") + `.\n\n${topText}\n\nView the full timeline: ${link}`;
  const topHtml = changes.top
    .map((e) => `<li><strong>${esc(e.title)}</strong>${e.description ? ` — ${esc(e.description)}` : ""}</li>`).join("");
  const html =
    `<h2>Your CyberMeters week</h2>` +
    `<p>${changes.total} change${changes.total === 1 ? "" : "s"} to ${esc(name)}'s internet-facing exposure this week${sevLine ? ` (${esc(sevLine)})` : ""}.</p>` +
    `<ul>${topHtml}</ul><p><a href="${link}">View the full timeline →</a></p>`;
  return { subject, text, html };
}

export async function sendWeeklyDigests(env) {
  try {
    const week = isoWeekKey();
    const origin = env.FRONTEND_URL || "https://app.cybermeters.com";
    // Active workspaces only: owner has a verified email AND ≥1 monitored domain.
    const wsRows = await env.cybermeters_db
      .prepare(
        `SELECT w.id, w.name, u.email AS email, u.email_verified AS ev
         FROM workspaces w
         JOIN users u ON u.id = w.owner_user_id
         WHERE w.deleted_at IS NULL
           AND EXISTS (SELECT 1 FROM workspace_domains wd WHERE wd.workspace_id = w.id)
         LIMIT ?`
      )
      .bind(MAX_WORKSPACES_PER_RUN)
      .all()
      .catch(() => ({ results: [] }));

    for (const ws of (wsRows.results || [])) {
      try {
        const email = String(ws.email || "").trim().toLowerCase();
        if (!ws.ev || !email) continue; // never mail an unverified/absent address

        // Dedupe: one digest per workspace per ISO week.
        const dedupeKey = `${DIGEST_TYPE}:${ws.id}:${week}`;
        const rowId = createId("lifemail");
        const ins = await env.cybermeters_db
          .prepare(
            `INSERT INTO lifecycle_email_events (id, workspace_id, type, dedupe_key, status, created_at)
             VALUES (?, ?, ?, ?, 'pending', datetime('now'))
             ON CONFLICT(dedupe_key) DO NOTHING`
          )
          .bind(rowId, ws.id, DIGEST_TYPE, dedupeKey)
          .run();
        if ((ins.meta?.changes ?? 0) === 0) continue; // already sent this week

        const changes = await computeWeeklyChanges(env, ws.id);
        const mail = buildDigestEmail(ws.name, changes, origin);
        const res = await deliverEmail(mail.subject, mail.text, mail.html, env, "HELLO_EMAIL_FROM", [email]);

        await env.cybermeters_db
          .prepare(
            `UPDATE lifecycle_email_events
             SET status = ?, provider_id = ?, error = ?, sent_at = CASE WHEN ? = 'sent' THEN datetime('now') ELSE sent_at END
             WHERE id = ?`
          )
          .bind(res.sent ? "sent" : "failed", res.provider_id || null, res.sent ? null : (res.reason || "send_failed"), res.sent ? "sent" : "failed", rowId)
          .run()
          .catch(() => {});
      } catch (e) {
        console.error("[weekly-digest-ws]", ws.id, String(e?.message ?? e));
      }
    }
  } catch (e) {
    console.error("[weekly-digest]", String(e?.message ?? e));
  }
}
