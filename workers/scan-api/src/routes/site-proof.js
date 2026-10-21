// ── Temporary live-proof site: site-proof.cybermeters.com ────────────────────
//
// S2-5 live alert proof for Website Security and Cyber Essentials (21 Oct 2026,
// Executive option (b)): never touch the live homepage. This host is a separate
// monitored domain in its own proof workspace, served from our own zone. One
// static page, clearly a CyberMeters test page: no form, no script, no data,
// noindex. It sends a complete set of security headers; HSTS is present by
// default and absent only while SITE_PROOF_HSTS = "off" (one scan), which is
// the change Website Security and Cyber Essentials (secure configuration)
// observe and alert on, and recover from when it returns.
//
// Ownership verification uses the product's html_file method
// (/cybermeters-verification-<token>.html). The file is answered only for the
// workspace pinned by the SITE_PROOF_WORKSPACE_ID secret and only with the
// token that workspace was issued, so no other tenant can verify this host.
//
// The host is checked before any API route; everything else on it is 404.
// Removed after the proof.
export const SITE_PROOF_HOST = "site-proof.cybermeters.com";

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex, nofollow">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberMeters test page: website security proof</title>
</head>
<body>
<h1>CyberMeters test page</h1>
<p>This temporary page lets CyberMeters prove that its scanner notices a change in a website's security headers and raises an alert. It holds no data and will be removed after the test.</p>
</body>
</html>
`;

const notFound = () => new Response("Not found\n", {
  status: 404, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
});

export function isSiteProofHost(url) {
  return String(url?.hostname || "").toLowerCase() === SITE_PROOF_HOST;
}

export function siteProofHeaders(env) {
  const headers = {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Robots-Tag": "noindex, nofollow",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
  };
  if (env?.SITE_PROOF_HSTS !== "off") headers["Strict-Transport-Security"] = "max-age=31536000";
  return headers;
}

export async function handleSiteProof(request, env) {
  const url = new URL(request.url);
  if (request.method !== "GET" && request.method !== "HEAD") return notFound();
  if (url.search) return notFound();
  if (url.pathname === "/") {
    return new Response(request.method === "HEAD" ? null : PAGE, { status: 200, headers: siteProofHeaders(env) });
  }
  const match = url.pathname.match(/^\/cybermeters-verification-([A-Za-z0-9_-]{8,128})\.html$/);
  const workspaceId = typeof env?.SITE_PROOF_WORKSPACE_ID === "string" ? env.SITE_PROOF_WORKSPACE_ID.trim() : "";
  if (!match || !workspaceId) return notFound();
  let row = null;
  try {
    row = await env.cybermeters_db.prepare(
      `SELECT wd.verification_token
         FROM workspace_domains wd
         JOIN domains d ON d.id = wd.domain_id
         JOIN workspaces w ON w.id = wd.workspace_id AND w.deleted_at IS NULL
        WHERE wd.workspace_id = ? AND d.domain = ? AND wd.verification_token = ?
        LIMIT 1`,
    ).bind(workspaceId, SITE_PROOF_HOST, match[1]).first();
  } catch {
    return notFound();
  }
  if (!row?.verification_token) return notFound();
  return new Response(request.method === "HEAD" ? null : row.verification_token, {
    status: 200,
    headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Robots-Tag": "noindex" },
  });
}
