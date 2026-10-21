// ── Temporary live-proof site: the sheshire.co.uk apex ───────────────────────
//
// S2-5 live alert proof for Website Security and Cyber Essentials (21 Oct 2026,
// Executive option (b), founder-authorised 20:50 UTC: never touch the live
// homepage). sheshire.co.uk is the company test domain (its own trial
// workspace "Sheshire Test"); only its apex is served here — www/account and
// the MX stay as they are (fixtures). One static page, clearly a CyberMeters
// test page: no form, no script, no data, noindex, a complete set of security
// headers. HSTS is present unless the deploy sets SITE_PROOF_HSTS=off for one
// scan, which is the change Website Security and Cyber Essentials (secure
// configuration) observe, alert on, and recover from when it returns.
//
// The host is checked before any API route; everything else on it is 404.
// Removed after the proof.
export const SITE_PROOF_HOST = "sheshire.co.uk";

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

export function handleSiteProof(request, env) {
  const url = new URL(request.url);
  if ((request.method !== "GET" && request.method !== "HEAD") || url.search || url.pathname !== "/") return notFound();
  return new Response(request.method === "HEAD" ? null : PAGE, { status: 200, headers: siteProofHeaders(env) });
}
