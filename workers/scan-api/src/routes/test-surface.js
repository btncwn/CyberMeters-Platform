// ── Temporary live-proof host: admin.cybermeters.com ────────────────────────
//
// S2-5 live alert proof (21 Oct 2026) for Attack Surface and Identity Exposure
// on a company-controlled asset. One static page, clearly marked as a
// CyberMeters test page: no form, no login, no data, no script, noindex. Its
// hostname and title make it an administrative surface as the scanner defines
// one (asset-intel.js GENERIC_ADMIN_HOST_RE / GENERIC_ADMIN_TITLE_RE), so a
// scan observes a publicly reachable admin interface, opens an Attack Surface
// case and alerts. It imitates no product.
//
// Removed after the proof (delete the route in wrangler.toml and redeploy).
// The host is checked before any API route; everything else on it is 404.
export const TEST_SURFACE_HOST = "admin.cybermeters.com";

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex, nofollow">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberMeters test page: admin surface proof</title>
</head>
<body>
<h1>CyberMeters test page</h1>
<p>This is a temporary page that CyberMeters publishes on its own domain to prove that its scanner notices a publicly reachable admin surface and raises an alert.</p>
<p>There is no login, no form and no data here. It will be removed after the test.</p>
</body>
</html>
`;

export function isTestSurfaceHost(url) {
  return String(url?.hostname || "").toLowerCase() === TEST_SURFACE_HOST;
}

export function handleTestSurface(request) {
  const url = new URL(request.url);
  if ((request.method === "GET" || request.method === "HEAD") && url.pathname === "/" && !url.search) {
    return new Response(request.method === "HEAD" ? null : PAGE, {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Robots-Tag": "noindex, nofollow",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
        "Referrer-Policy": "no-referrer",
      },
    });
  }
  return new Response("Not found\n", { status: 404, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
}
