// ── MTA-STS policy file for cybermeters.com itself ──────────────────────────
//
// Hosted MTA-STS manages the _mta-sts DNS policy ID and pins the policy file
// content, but the customer hosts the file (MTA_STS_POLICY_BOUNDARY in
// routes/email-protection.js). This route is that host for CyberMeters' own
// domain only: https://mta-sts.cybermeters.com/.well-known/mta-sts.txt
// (RFC 8461 section 3.2) serves the policy content the product pinned for our
// own workspace, so the file always matches what the product verifies.
//
// The host is checked before anything else in the Worker, so this hostname
// reaches no API route. One path, GET only; everything else is 404. The
// workspace is pinned by the MTA_STS_SELF_WORKSPACE_ID secret: without it, or
// with no pinned policy, the file is 404 and MTA-STS stays incomplete. It
// never serves another workspace's record. Read-only.
export const MTA_STS_SELF_HOST = "mta-sts.cybermeters.com";
export const MTA_STS_SELF_DOMAIN = "cybermeters.com";
export const MTA_STS_POLICY_PATH = "/.well-known/mta-sts.txt";

const notFound = () => new Response("Not found\n", {
  status: 404,
  headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
});

export function isMtaStsSelfHost(url) {
  return String(url?.hostname || "").toLowerCase() === MTA_STS_SELF_HOST;
}

export async function handleMtaStsSelf(request, env) {
  const url = new URL(request.url);
  if (request.method !== "GET" || url.pathname !== MTA_STS_POLICY_PATH || url.search) return notFound();
  const workspaceId = typeof env?.MTA_STS_SELF_WORKSPACE_ID === "string" ? env.MTA_STS_SELF_WORKSPACE_ID.trim() : "";
  if (!workspaceId) return notFound();
  let row = null;
  try {
    row = await env.cybermeters_db.prepare(
      `SELECT e.policy_content
         FROM hosted_dns_entries e
         JOIN workspaces w ON w.id = e.workspace_id AND w.deleted_at IS NULL
        WHERE e.workspace_id = ? AND e.domain = ? AND e.record_kind = 'mtasts'
          AND e.verification_state <> 'pending_removal'
          AND e.policy_content IS NOT NULL AND e.policy_content <> ''
        ORDER BY e.updated_at DESC LIMIT 1`,
    ).bind(workspaceId, MTA_STS_SELF_DOMAIN).first();
  } catch {
    return notFound();
  }
  if (!row?.policy_content) return notFound();
  return new Response(row.policy_content, {
    status: 200,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      // Short: a re-pinned policy (MX change) is served within minutes.
      "Cache-Control": "public, max-age=300",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
