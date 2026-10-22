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
// S2-B adds a test sign-in for the signed-in scanning proof: /login (one
// username/password form), then two pages only a signed-in visitor sees
// (/account, /account/details). The test account lives only in Worker secrets
// (SITE_PROOF_USERNAME, SITE_PROOF_PASSWORD, SITE_PROOF_SESSION_KEY); with any of
// them missing every sign-in is refused. The session cookie is an expiring HMAC,
// HttpOnly and Secure; the pages behind it hold no data.
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

const SIGNED_IN_TEXT = "Signed in to the CyberMeters test account";
const SESSION_COOKIE = "cm_proof_session";
const SESSION_SECONDS = 3600;
const page = (title, body) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex, nofollow">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberMeters test page: ${title}</title>
</head>
<body>
<h1>CyberMeters test page</h1>
${body}
</body>
</html>
`;
const LOGIN_PAGE = (message = "") => page("sign in", `<p>This temporary test sign-in lets CyberMeters prove that it can check pages behind a sign-in. It protects no real account and will be removed after the test.</p>
${message ? `<p role="alert">${message}</p>` : ""}<form method="post" action="/login">
<label for="username">Username</label> <input id="username" name="username" type="text" autocomplete="username">
<label for="password">Password</label> <input id="password" name="password" type="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>`);
const ACCOUNT_PAGE = page("account", `<p>${SIGNED_IN_TEXT}.</p>
<p>This page is only shown after signing in. It holds no data.</p>
<p><a href="/account/details">Account details</a></p>`);
const DETAILS_PAGE = page("account details", `<p>${SIGNED_IN_TEXT}.</p>
<p>A second signed-in page with nothing on it. <a href="/account">Back to the account page</a></p>`);

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

const bytesToHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
async function hmac(key, text) {
  const k = await crypto.subtle.importKey("raw", new TextEncoder().encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return bytesToHex(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(text)));
}
// Compares digests, so the comparison takes the same time whatever the input.
async function sameSecret(a, b) {
  const [x, y] = await Promise.all([a, b].map(async (v) => bytesToHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(v))))));
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return diff === 0;
}
const accountConfigured = (env) => Boolean(env?.SITE_PROOF_USERNAME && env?.SITE_PROOF_PASSWORD && env?.SITE_PROOF_SESSION_KEY);

export async function siteProofSessionCookie(env, now = Date.now()) {
  const exp = Math.floor(now / 1000) + SESSION_SECONDS;
  return `${SESSION_COOKIE}=${exp}.${await hmac(env.SITE_PROOF_SESSION_KEY, `session:${exp}`)}; Path=/; Max-Age=${SESSION_SECONDS}; Secure; HttpOnly; SameSite=Lax`;
}
async function signedIn(request, env, now = Date.now()) {
  if (!accountConfigured(env)) return false;
  const raw = (request.headers.get("Cookie") || "").split(/;\s*/).find((c) => c.startsWith(`${SESSION_COOKIE}=`));
  const match = raw?.slice(SESSION_COOKIE.length + 1).match(/^(\d{1,12})\.([0-9a-f]{64})$/);
  if (!match || Number(match[1]) * 1000 <= now) return false;
  return sameSecret(match[2], await hmac(env.SITE_PROOF_SESSION_KEY, `session:${match[1]}`));
}
const html = (request, env, body, status = 200, extra = {}) =>
  new Response(request.method === "HEAD" ? null : body, { status, headers: { ...siteProofHeaders(env), ...extra } });
const redirect = (location, extra = {}) =>
  new Response(null, { status: 303, headers: { Location: location, "Cache-Control": "no-store", ...extra } });
// The sign-in page posts to itself, so its CSP allows exactly that.
const LOGIN_CSP = { "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" };

export async function handleSiteProof(request, env, { now = Date.now() } = {}) {
  const url = new URL(request.url);
  const read = request.method === "GET" || request.method === "HEAD";
  if (url.search) return notFound();
  if (url.pathname === "/" && read) return html(request, env, PAGE);
  if (url.pathname === "/login" && read) {
    if (await signedIn(request, env, now)) return redirect("/account");
    return html(request, env, LOGIN_PAGE(), 200, LOGIN_CSP);
  }
  if (url.pathname === "/login" && request.method === "POST") {
    const text = await request.text().catch(() => "");
    if (text.length > 2048) return html(request, env, LOGIN_PAGE("That sign-in was not accepted."), 400, LOGIN_CSP);
    const form = new URLSearchParams(text);
    const ok = accountConfigured(env)
      && (await sameSecret(form.get("username") || "", env.SITE_PROOF_USERNAME))
      && (await sameSecret(form.get("password") || "", env.SITE_PROOF_PASSWORD));
    if (!ok) return html(request, env, LOGIN_PAGE("That username and password were not accepted."), 401, LOGIN_CSP);
    return redirect("/account", { "Set-Cookie": await siteProofSessionCookie(env, now) });
  }
  if ((url.pathname === "/account" || url.pathname === "/account/details") && read) {
    if (!await signedIn(request, env, now)) return redirect("/login");
    return html(request, env, url.pathname === "/account" ? ACCOUNT_PAGE : DETAILS_PAGE);
  }
  return notFound();
}
