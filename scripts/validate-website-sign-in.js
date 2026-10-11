#!/usr/bin/env node
//
// Website Security — signed-in scanning: credential vault, sign-in session,
// profile storage and routes (migration 116). Deterministic: a fake web
// application is served through safeFetch's fetchImpl seam; D1 is node:sqlite
// with the real migration. No network. CI-blocking.
//
// Proves the credential boundary (credentials only ever travel over HTTPS to
// the verified site's own hosts; nothing is sent across a redirect to another
// host or to plain HTTP; the sign-in form is the only thing ever submitted),
// the honesty of "signed in" (signed-in text or anonymous contrast, never a
// bare 200), the refusal cases (CAPTCHA, one-time code, SSO, GET form,
// off-site form), that no secret is ever returned or stored in clear, tenant
// and role gating on every route, and the lock-out protection.
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const src = (...p) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...p)).href;
const vault = await import(src("lib", "website-auth-secrets.js"));
const si = await import(src("engines", "website-sign-in.js"));
const store = await import(src("engines", "website-sign-in-profiles.js"));
const { websiteSignInRoutes } = await import(src("routes", "website-sign-in.js"));
const { siteHosts } = await import(src("engines", "page-discovery.js"));

let pass = 0, fail = 0;
const ok = (name, cond, detail = "") => {
  if (cond) pass++;
  else { fail++; console.error(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
};
const eq = (name, got, want) => ok(name, JSON.stringify(got) === JSON.stringify(want), `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
const throwsCode = (name, fn, code) => {
  try { fn(); ok(name, false, "did not throw"); } catch (e) { ok(name, e.code === code, `code ${e.code} want ${code}`); }
};
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const ring = (active = "k1", keys = { k1: b64(new Uint8Array(32).fill(7)) }) => JSON.stringify({ v: 1, active, keys });
const KEY = ring();

// ── 1. Vault ────────────────────────────────────────────────────────────────
{
  const scope = { workspace_id: "ws_a", domain_id: "d1", profile_id: "p1", method: "form" };
  const secret = { username: "jane@acme.test", password: "S3cret-Pass!" };
  const env1 = await vault.encryptWebsiteSecret(secret, scope, KEY);
  ok("vault: ciphertext has no clear text", !/jane|S3cret/.test(env1) && !/jane|S3cret/.test(Buffer.from(JSON.parse(env1).ct, "base64").toString("latin1")));
  eq("vault: round trip", await vault.decryptWebsiteSecret(env1, scope, KEY), secret);
  for (const [field, value] of [["workspace_id", "ws_b"], ["domain_id", "d2"], ["profile_id", "p2"], ["method", "header"]]) {
    let code = null;
    try { await vault.decryptWebsiteSecret(env1, { ...scope, [field]: value }, KEY); } catch (e) { code = e.code; }
    eq(`vault: ciphertext bound to ${field}`, code, "vault_unavailable");
  }
  for (const [name, binding] of [["missing", undefined], ["not json", "x"], ["short key", ring("k1", { k1: b64(new Uint8Array(16)) })], ["v2", JSON.stringify({ v: 2, active: "k1", keys: { k1: b64(new Uint8Array(32)) } })]]) {
    ok(`vault: ${name} ring unavailable`, !vault.websiteAuthKeyAvailable(binding));
    let code = null;
    try { await vault.encryptWebsiteSecret(secret, scope, binding); } catch (e) { code = e.code; }
    eq(`vault: ${name} ring refuses to encrypt`, code, "vault_unavailable");
  }
  // Rotation: a new active key still opens the old envelope by its kid.
  const rotated = ring("k2", { k1: b64(new Uint8Array(32).fill(7)), k2: b64(new Uint8Array(32).fill(9)) });
  eq("vault: rotation keeps old kid readable", await vault.decryptWebsiteSecret(env1, scope, rotated), secret);
  eq("vault: new envelopes use the active kid", JSON.parse(await vault.encryptWebsiteSecret(secret, scope, rotated)).kid, "k2");
  let tamper = null;
  const t = JSON.parse(env1); const ct = Buffer.from(t.ct, "base64"); ct[0] ^= 1; t.ct = ct.toString("base64");
  try { await vault.decryptWebsiteSecret(JSON.stringify(t), scope, KEY); } catch (e) { tamper = e.code; }
  eq("vault: tampered ciphertext refused", tamper, "vault_unavailable");
  ok("vault: shape per method", vault.validSecret("form", secret) && !vault.validSecret("header", secret)
    && vault.validSecret("header", { header_name: "Authorization", header_value: "Bearer x" })
    && !vault.validSecret("form", { username: "a", password: "b", extra: 1 })
    && !vault.validSecret("form", { username: "a\r\nX: y", password: "b" }));
}

// ── 2. Input validation ─────────────────────────────────────────────────────
{
  const n = (body, existing = null) => si.normalizeSignInInput({ authorization_confirmed: true, ...body }, { domain: "acme.test", existing });
  const form = { method: "form", login_url: "https://acme.test/login", username: "jane@acme.test", password: "pw" };
  const r = n({ ...form, start_url: "https://www.acme.test/account?x=1#y" });
  eq("input: urls normalised (no query/fragment)", [r.login_url, r.start_url], ["https://acme.test/login", "https://www.acme.test/account"]);
  eq("input: masked hint", r.credential_hint, "j•••@acme.test");
  throwsCode("input: authorization must be confirmed", () => si.normalizeSignInInput({ ...form }, { domain: "acme.test" }), "authorization_required");
  throwsCode("input: http login refused", () => n({ ...form, login_url: "http://acme.test/login" }), "login_url_not_https");
  throwsCode("input: other host refused", () => n({ ...form, login_url: "https://evil.example/login" }), "login_url_not_on_domain");
  throwsCode("input: other subdomain refused", () => n({ ...form, login_url: "https://sso.acme.test/login" }), "login_url_not_on_domain");
  throwsCode("input: odd port refused", () => n({ ...form, login_url: "https://acme.test:8443/login" }), "login_url_invalid");
  throwsCode("input: logout start page refused", () => n({ ...form, start_url: "https://acme.test/account/logout" }), "start_url_not_a_page");
  throwsCode("input: API start page refused", () => n({ ...form, start_url: "https://acme.test/api/me" }), "start_url_not_a_page");
  throwsCode("input: start page = login page refused", () => n({ ...form, start_url: "https://acme.test/login/" }), "start_url_is_login_page");
  throwsCode("input: unknown key refused", () => n({ ...form, password_confirm: "x" }), "unsupported_input");
  throwsCode("input: username without password", () => n({ ...form, password: "" }), "username_and_password_required");
  throwsCode("input: new form profile needs credentials", () => n({ method: "form", login_url: "https://acme.test/login" }), "username_and_password_required");
  const kept = n({ method: "form", login_url: "https://acme.test/login" }, { method: "form" });
  ok("input: same method may keep the stored secret", kept.secret === null && kept.credential_hint === null);
  throwsCode("input: method change needs a new secret", () => n({ method: "header", start_url: "https://acme.test/account" }, { method: "form" }), "header_name_and_value_required");
  for (const name of ["Cookie", "Host", "X-Forwarded-For", "Proxy-Authorization", "Sec-Fetch-Site", "CF-Connecting-IP", "Content-Length", "Bad Name", "Origin"]) {
    throwsCode(`input: header ${name} refused`, () => n({ method: "header", start_url: "https://acme.test/account", header_name: name, header_value: "x" }), "header_name_invalid");
  }
  throwsCode("input: header value CRLF refused", () => n({ method: "header", start_url: "https://acme.test/account", header_name: "Authorization", header_value: "Bearer a\r\nX-Evil: 1" }), "header_value_invalid");
  eq("input: header hint names only the header", n({ method: "header", start_url: "https://acme.test/account", header_name: "Authorization", header_value: "Bearer tok" }).credential_hint, "Authorization header");
  throwsCode("input: cookie value with ; refused", () => n({ method: "cookie", start_url: "https://acme.test/account", cookie_name: "sid", cookie_value: "a; admin=1" }), "cookie_value_invalid");
  throwsCode("input: header method needs start page", () => n({ method: "header", header_name: "Authorization", header_value: "x" }), "start_url_required");
  throwsCode("input: mixed method fields refused", () => n({ method: "cookie", start_url: "https://acme.test/account", cookie_name: "a", cookie_value: "b", password: "x" }), "unsupported_input");
  eq("mask: short username", si.maskUsername("bob"), "•••");
}

// ── 3. Cookie jar ───────────────────────────────────────────────────────────
{
  let now = 1_000_000;
  const jar = si.createCookieJar(siteHosts("acme.test"), { now: () => now });
  jar.set(["a=1; Path=/", "b=2; Domain=acme.test; Path=/", "evil=x; Domain=example.com", "sub=y; Domain=shop.acme.test",
    "p=3; Path=/account", "short=4; Max-Age=10", "gone=5; Max-Age=0"], "https://acme.test/login");
  eq("jar: apex request", jar.header("https://acme.test/"), "a=1; b=2; short=4");
  eq("jar: domain cookie reaches www, host-only does not", jar.header("https://www.acme.test/"), "b=2");
  eq("jar: path match", jar.header("https://acme.test/account/x"), "p=3; a=1; b=2; short=4");
  eq("jar: path prefix is not a match", jar.header("https://acme.test/accounting"), "a=1; b=2; short=4");
  now += 11_000;
  eq("jar: expired cookie dropped", jar.header("https://acme.test/"), "a=1; b=2");
  jar.set(["a=; Max-Age=0"], "https://acme.test/");
  eq("jar: Max-Age=0 deletes", jar.header("https://acme.test/"), "b=2");
  jar.set(["wide=1; Domain=test", "dot=1; Domain=.test"], "https://acme.test/");
  eq("jar: parent-domain cookie refused", [jar.header("https://evil.test/"), jar.header("https://acme.test/")], ["", "b=2"]);
  jar.set(["x=1"], "https://evil.example/");
  eq("jar: responses from other hosts ignored", jar.header("https://acme.test/"), "b=2");
  eq("jar: never sent to other hosts", jar.header("https://evil.example/"), "");
  const flags = si.describeSetCookies(["sid=SECRETVALUE; Secure; HttpOnly; SameSite=Lax; Max-Age=2592000", "t=1; Max-Age=0", "pref=z"]);
  eq("cookie flags: names + flags, no values, deletions skipped", flags, [
    { name: "sid", secure: true, httponly: true, samesite: "lax", persistent: true, lifetime_days: 30 },
    { name: "pref", secure: false, httponly: false, samesite: null, persistent: false, lifetime_days: null },
  ]);
}

// ── 4. Sign-in form parsing ─────────────────────────────────────────────────
{
  const html = `<form action="/search"><input name=q></form>
    <form method="POST" action="/session?next=%2F&amp;x=1">
      <input type="hidden" name="authenticity_token" value="a&amp;b">
      <input type="email" name="user[email]" autocomplete="username">
      <input type="password" name="user[password]">
      <input type="checkbox" name="remember" value="1">
      <input type="checkbox" name="terms" value="yes" checked>
      <input type="text" name="website" value="">
      <button type="submit" name="commit" value="Sign in">Sign in</button>
    </form>`;
  const forms = si.extractFormsWithFields(html);
  const picked = si.pickLoginForm(forms);
  eq("form: picks the password form and fields", [picked.usernameName, picked.passwordName, picked.form.method, picked.form.action], ["user[email]", "user[password]", "post", "/session?next=%2F&x=1"]);
  const body = new URLSearchParams(si.buildLoginBody(picked.form, picked.usernameName, picked.passwordName, { username: "jane@acme.test", password: "pw!" }));
  eq("form: body carries hidden token (decoded), our values, checked boxes only, named submit",
    [...body.entries()], [["authenticity_token", "a&b"], ["user[email]", "jane@acme.test"], ["user[password]", "pw!"], ["terms", "yes"], ["website", ""], ["commit", "Sign in"]]);
  eq("form: override must exist", si.pickLoginForm(forms, { usernameField: "login" }).error, "username_field_not_found");
  eq("form: two-password form is not a sign-in form", si.pickLoginForm(si.extractFormsWithFields(`<form method=post><input name=u><input type=password name=a><input type=password name=b></form>`)).error, "login_form_not_found");
  eq("form: JS-only page has no form", si.pickLoginForm(si.extractFormsWithFields(`<div id=app></div><script>render()</script>`)).error, "login_form_not_found");
  eq("form: username before password as fallback", si.pickLoginForm(si.extractFormsWithFields(`<form method=post><input name=handle><input type=password name=pw></form>`)).usernameName, "handle");
  ok("login page: change-password form is not a sign-in page", !si.looksLikeLoginPage(`<form method=post><input type=password name=current></form>`));
  ok("login page: sign-in form is", si.looksLikeLoginPage(`<form method=post><input name=email type=email><input type=password name=pw></form>`));
  ok("captcha: recaptcha script", si.detectCaptcha(`<script src="https://www.google.com/recaptcha/api.js"></script>`));
  ok("captcha: turnstile div", si.detectCaptcha(`<div class="cf-turnstile" data-sitekey="x"></div>`));
  ok("captcha: none", !si.detectCaptcha(`<form><input name=a></form>`));
  ok("otp: autocomplete one-time-code", si.detectOneTimeCode(`<input autocomplete="one-time-code" name="c">`));
  ok("otp: named totp field", si.detectOneTimeCode(`<input name="totp_code">`));
  ok("otp: ordinary page", !si.detectOneTimeCode(`<input name="search"><input type=hidden name=otp_nonce>`));
  ok("text: script content ignored", !si.containsSignedInText(`<script>var s="Sign out"</script><p>Hello</p>`, "sign out"));
  ok("text: tags and entities folded", si.containsSignedInText(`<a>Sign&nbsp;<b>out</b></a>`, "Sign  OUT"));
  const big = "<a<b".repeat(100_000);
  const t0 = performance.now(); si.pageText(big); si.extractFormsWithFields(big); si.detectCaptcha(big);
  ok("hostile HTML parsed in linear time", performance.now() - t0 < 1500, `${Math.round(performance.now() - t0)}ms`);
}

// ── 5. Sign-in against a fake application ───────────────────────────────────
const SITE = new Set(["acme.test", "www.acme.test"]);
function fakeApp(o = {}) {
  const log = [];
  const sessions = new Map();
  let n = 0;
  const cookiesOf = (h) => Object.fromEntries(String(h.Cookie || "").split(/;\s*/).filter(Boolean).map((p) => { const i = p.indexOf("="); return [p.slice(0, i), p.slice(i + 1)]; }));
  const respond = (url, status, body, headers = {}, cookies = []) => {
    const h = new Headers({ "content-type": "text/html; charset=utf-8", ...headers });
    for (const c of cookies) h.append("set-cookie", c);
    const r = new Response(body, { status, headers: h });
    Object.defineProperty(r, "url", { value: url });
    return r;
  };
  const redirect = (url, to, status = 302, cookies = []) => respond(url, status, null, { location: to }, cookies);
  const loginHtml = (csrf, error = "") => o.loginHtml ? o.loginHtml(csrf) : `<html><title>Sign in</title>${error}
    <form method="${o.formMethod || "post"}" action="${o.formAction || "/login"}">
      <input type="hidden" name="csrf" value="${csrf}">
      <input type="email" name="email"><input type="password" name="password">
      <button type="submit">Sign in</button></form></html>`;
  const account = (s) => `<html><h1>Your account</h1><p>Signed in as Jane Tester</p><a href="/logout">Sign out</a>
    ${o.accountExtra || ""}</html>`;
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    const headers = init.headers || {};
    log.push({ url, host: u.hostname, protocol: u.protocol, path: u.pathname, method: init.method || "GET", headers: { ...headers }, body: init.body ?? null });
    if (o.route) { const r = o.route(u, init, { respond, redirect, cookiesOf, sessions, url }); if (r) return r; }
    if (!SITE.has(u.hostname)) return respond(url, 200, "<html>another site</html>");
    if (u.protocol !== "https:") return respond(url, 200, "<html>plain http</html>");
    const c = cookiesOf(headers);
    const sess = c.sid ? sessions.get(c.sid) : null;
    const method = init.method || "GET";
    if (u.pathname === "/login" && method === "GET") {
      if (o.loginRedirect) return redirect(url, o.loginRedirect);
      if (sess) return respond(url, 200, loginHtml(sess.csrf));
      const sid = `pre${++n}`;
      sessions.set(sid, { authed: false, csrf: `csrf${n}` });
      return respond(url, 200, loginHtml(`csrf${n}`), {}, [`sid=${sid}; Path=/; Secure; HttpOnly; SameSite=Lax`]);
    }
    if (u.pathname === "/login" && method === "POST") {
      const p = new URLSearchParams(init.body || "");
      if (!sess || p.get("csrf") !== sess.csrf) return respond(url, 403, "<html>CSRF</html>");
      if (p.get("email") !== "jane@acme.test" || p.get("password") !== "Corr3ct!") {
        return o.wrongMode === "redirect" ? redirect(url, "/login?error=1") : respond(url, 200, loginHtml(sess.csrf, "<p>Wrong email or password</p>"));
      }
      if (o.afterPost) return o.afterPost(url, { respond, redirect, sess, c, sessions });
      if (o.fixation) { sess.authed = true; return redirect(url, o.afterLogin || "/account"); }
      sessions.delete(c.sid);
      const sid = `auth${++n}`;
      sessions.set(sid, { authed: true });
      return redirect(url, o.afterLogin || "/account", o.postStatus || 302, [`sid=${sid}; Path=/; ${o.sessionFlags ?? "Secure; HttpOnly; SameSite=Lax"}`]);
    }
    if (u.pathname === "/account") {
      if (sess?.authed) return respond(url, 200, account(sess));
      return o.accountPublic ? respond(url, 200, "<html><h1>Your account</h1><p>Welcome</p></html>") : redirect(url, "/login");
    }
    if (u.pathname === "/dashboard") {
      return headers.Authorization === "Bearer good-token" ? respond(url, 200, "<html><p>Dashboard for Jane Tester</p></html>")
        : respond(url, 401, "<html>Unauthorized</html>");
    }
    if (u.pathname === "/portal") {
      return c.auth === "goodvalue" ? respond(url, 200, "<html><p>Portal: Jane Tester</p></html>") : redirect(url, "/login");
    }
    if (u.pathname === "/") return respond(url, 200, "<html><a href=/login>Sign in</a></html>");
    return respond(url, 404, "<html>not found</html>");
  };
  return { fetchImpl, log, sessions };
}
const FORM = { method: "form", login_url: "https://acme.test/login", start_url: "https://acme.test/account", signed_in_text: null, username_field: null, password_field: null };
const GOOD = { username: "jane@acme.test", password: "Corr3ct!" };
const run = (app, profile = FORM, secret = GOOD, extra = {}) => si.signIn("acme.test", profile, secret, { fetchImpl: app.fetchImpl, ...extra });
const boundary = (name, app, secretValues) => {
  const offsite = app.log.filter((r) => !SITE.has(r.host) || r.protocol !== "https:");
  ok(`${name}: nothing credential-bearing left the site`, offsite.every((r) => !r.headers.Cookie && !r.headers.Authorization && !r.headers["X-Api-Key"] && r.method === "GET" && !r.body),
    JSON.stringify(offsite));
  const posts = app.log.filter((r) => r.method !== "GET");
  ok(`${name}: at most the sign-in form was submitted`, posts.length <= 2 && posts.every((r) => SITE.has(r.host) && r.protocol === "https:" && r.method === "POST"), JSON.stringify(posts.map((r) => r.url)));
  ok(`${name}: no secret in any URL`, app.log.every((r) => secretValues.every((v) => !r.url.includes(encodeURIComponent(v)) && !r.url.includes(v))));
  ok(`${name}: sign-out never requested`, app.log.every((r) => !/logout|signout/i.test(r.path)));
};
const noLeak = (name, result, values) => {
  const text = JSON.stringify({ outcome: result.outcome, detail: result.detail });
  ok(`${name}: result carries no secret or session value`, values.every((v) => !text.includes(v)) && !/auth\d|pre\d|csrf\d/.test(text), text);
};
{
  const app = fakeApp();
  const r = await run(app);
  eq("form: signed in by anonymous contrast", [r.outcome, r.detail.basis, r.detail.anonymous_access], ["signed_in", "anonymous_refused", "refused"]);
  eq("form: session id renewed at sign-in", r.detail.session_cookie_renewed, "renewed");
  eq("form: cookie flags at sign-in (no values)", r.detail.cookies_at_sign_in, [{ name: "sid", secure: true, httponly: true, samesite: "lax", persistent: false, lifetime_days: null }]);
  eq("form: field names reported", [r.detail.form.username_field, r.detail.form.password_field, r.detail.form.hidden_fields], ["email", "password", 1]);
  const post = app.log.find((x) => x.method === "POST");
  eq("form: POST carries Origin + Referer (no query)", [post.headers.Origin, post.headers.Referer, post.headers["Content-Type"]], ["https://acme.test", "https://acme.test/login", "application/x-www-form-urlencoded"]);
  ok("form: POST body has the CSRF token from the page", new URLSearchParams(post.body).get("csrf") === "csrf1");
  ok("form: session returned for signed-in checks", !!r.session && !!r.startPage?.html?.includes("Jane Tester"));
  const anon = app.log.filter((x) => x.path === "/account" && !x.headers.Cookie);
  ok("form: the anonymous contrast request carries no cookie", anon.length === 1);
  boundary("form", app, [GOOD.password, GOOD.username]);
  noLeak("form", r, [GOOD.password, GOOD.username]);
}
{
  const r1 = await run(fakeApp(), { ...FORM, signed_in_text: "Signed in as Jane" });
  eq("signed-in text: found and distinctive", [r1.outcome, r1.detail.basis], ["signed_in", "signed_in_text"]);
  eq("signed-in text: not on the page", (await run(fakeApp(), { ...FORM, signed_in_text: "Welcome back, Bob" })).outcome, "signed_in_text_not_found");
  eq("signed-in text: also shown without signing in", (await run(fakeApp({ accountPublic: true }), { ...FORM, signed_in_text: "Your account" })).outcome, "signed_in_text_not_distinctive");
  eq("start page public, no text: cannot confirm", (await run(fakeApp({ accountPublic: true }), { ...FORM, start_url: "https://acme.test/" })).outcome, "start_page_public");
}
{
  const bad = { username: "jane@acme.test", password: "wrong" };
  const a1 = fakeApp(); eq("wrong password (form re-shown)", (await run(a1, FORM, bad)).outcome, "credentials_rejected");
  boundary("wrong password", a1, [bad.password]);
  eq("wrong password (redirect to login)", (await run(fakeApp({ wrongMode: "redirect" }), FORM, bad)).outcome, "credentials_rejected");
  eq("wrong password without start page", (await run(fakeApp(), { ...FORM, start_url: null }, bad)).outcome, "credentials_rejected");
  eq("no start page: lands on account, proven there", (await run(fakeApp(), { ...FORM, start_url: null })).outcome, "signed_in");
}
{
  const r = await run(fakeApp({ fixation: true }));
  eq("session fixation: id kept through sign-in", [r.outcome, r.detail.session_cookie_renewed], ["signed_in", "not_renewed"]);
  const r2 = await run(fakeApp({ sessionFlags: "Path=/" }));
  eq("session cookie without Secure/HttpOnly reported", r2.detail.cookies_at_sign_in.map((c) => [c.secure, c.httponly]), [[false, false]]);
}
{
  const a = fakeApp({ loginRedirect: "https://idp.example/authorize?client=acme" });
  const r = await run(a);
  eq("SSO: sign-in on another site is reported, not followed", [r.outcome, r.detail.offsite_host], ["sign_in_redirects_offsite", "idp.example"]);
  ok("SSO: identity provider never contacted", a.log.every((x) => x.host !== "idp.example"));
  const a2 = fakeApp({ afterLogin: "https://partner.example/welcome" });
  eq("post-login redirect off-site stops", (await run(a2)).outcome, "sign_in_redirects_offsite");
  ok("post-login redirect off-site: partner never contacted", a2.log.every((x) => x.host !== "partner.example"));
  const a3 = fakeApp({ afterLogin: "http://acme.test/account" });
  eq("post-login downgrade to http stops", (await run(a3)).outcome, "login_not_https");
  ok("downgrade: no plain-HTTP request made", a3.log.every((x) => x.protocol === "https:"));
  boundary("downgrade", a3, [GOOD.password]);
}
{
  const a = fakeApp({ afterPost: (url, { redirect }) => redirect(url, "https://www.acme.test/login2", 307) });
  eq("307 re-POST to another origin refused", (await run(a)).outcome, "sign_in_redirects_offsite");
  eq("307: only one POST made", a.log.filter((x) => x.method === "POST").length, 1);
  const b = fakeApp({ route: (u, init, { respond, redirect, url }) => {
    if (u.pathname === "/login" && init.method === "POST") return redirect(url, "/session?step=2", 307);
    return null;
  } });
  await run(b);
  eq("307 to the same origin re-POSTs there", b.log.filter((x) => x.method === "POST").map((x) => x.url), ["https://acme.test/login", "https://acme.test/session?step=2"]);
}
{
  const a = fakeApp({ formMethod: "get" });
  eq("GET sign-in form refused (password never put in a URL)", (await run(a)).outcome, "login_form_uses_get");
  ok("GET form: nothing submitted", a.log.every((x) => !x.url.includes("Corr3ct") && x.method === "GET"));
  const b = fakeApp({ formAction: "https://collector.example/auth" });
  eq("off-site form action refused", (await run(b)).outcome, "login_form_posts_offsite");
  ok("off-site action: nothing sent there", b.log.every((x) => x.host !== "collector.example"));
  const c = fakeApp({ formAction: "http://acme.test/login" });
  eq("plain-HTTP form action refused", (await run(c)).outcome, "login_not_https");
  const d = fakeApp({ loginHtml: () => `<html><script src="https://www.google.com/recaptcha/api.js"></script><form method=post><input name=email><input type=password name=password></form></html>` });
  eq("CAPTCHA on sign-in page: not bypassed", (await run(d)).outcome, "captcha_present");
  ok("CAPTCHA: nothing submitted", d.log.every((x) => x.method === "GET"));
  eq("one-time code after sign-in", (await run(fakeApp({ afterPost: (url, { respond }) => respond(url, 200, `<form method=post><input autocomplete="one-time-code" name="code"></form>`) }))).outcome, "mfa_required");
  eq("bot challenge", (await run(fakeApp({ route: (u, i, { respond, url }) => respond(url, 403, "<html>Just a moment</html>", { "cf-mitigated": "challenge" }) }))).outcome, "bot_protection");
  eq("rate limited", (await run(fakeApp({ route: (u, i, { respond, url }) => respond(url, 429, "slow down") }))).outcome, "rate_limited");
  eq("JS-built sign-in page", (await run(fakeApp({ loginHtml: () => `<div id=root></div><script src=/app.js></script>` }))).outcome, "login_form_not_found");
  eq("sign-in page unavailable", (await run(fakeApp({ route: (u, i, { respond, url }) => (u.pathname === "/login" ? respond(url, 500, "err") : null) }))).outcome, "login_page_unavailable");
  const unsafeAfter = fakeApp({ afterLogin: "/logout?next=/" });
  eq("post-sign-in redirect into sign-out not followed (no start page)", (await run(unsafeAfter, { ...FORM, start_url: null })).outcome, "sign_in_redirect_not_followed");
  ok("post-sign-in redirect into sign-out: never requested", unsafeAfter.log.every((x) => x.path !== "/logout"));
  const unsafeAfter2 = fakeApp({ afterLogin: "/logout?next=/" });
  eq("post-sign-in redirect into sign-out: start page still proves it", (await run(unsafeAfter2)).outcome, "signed_in");
  ok("…and sign-out is still never requested", unsafeAfter2.log.every((x) => x.path !== "/logout"));
  eq("budget: request ceiling ends the attempt", (await run(fakeApp(), FORM, GOOD, { limits: { maxFetches: 2 } })).outcome, "budget_exhausted");
  eq("budget: limits can only be tightened", (await run(fakeApp(), FORM, GOOD, { limits: { maxFetches: 999 } })).detail.fetches <= si.SIGN_IN_LIMITS.maxFetches, true);
  eq("account page with a change-password form still counts as signed in",
    (await run(fakeApp({ accountExtra: `<form method=post><input type=password name=current><button>Change</button></form>` }))).outcome, "signed_in");
}
{
  const H = { method: "header", login_url: null, start_url: "https://acme.test/dashboard", signed_in_text: null };
  const a = fakeApp();
  const r = await si.signIn("acme.test", H, { header_name: "Authorization", header_value: "Bearer good-token" }, { fetchImpl: a.fetchImpl });
  eq("header: signed in by contrast", [r.outcome, r.detail.basis], ["signed_in", "anonymous_refused"]);
  ok("header: anonymous request carries no Authorization", a.log.filter((x) => !x.headers.Authorization).length === 1);
  eq("header: wrong token", (await si.signIn("acme.test", H, { header_name: "Authorization", header_value: "Bearer nope" }, { fetchImpl: fakeApp().fetchImpl })).outcome, "session_rejected");
  noLeak("header", r, ["good-token"]);
  const C = { method: "cookie", login_url: null, start_url: "https://acme.test/portal", signed_in_text: "Portal: Jane" };
  const b = fakeApp();
  const rc = await si.signIn("acme.test", C, { cookie_name: "auth", cookie_value: "goodvalue" }, { fetchImpl: b.fetchImpl });
  eq("cookie: signed in by text", [rc.outcome, rc.detail.basis], ["signed_in", "signed_in_text"]);
  noLeak("cookie", rc, ["goodvalue"]);
  // A header credential must never follow a redirect off the site.
  const c = fakeApp({ route: (u, i, { redirect, url }) => (u.pathname === "/dashboard" && SITE.has(u.hostname) ? redirect(url, "https://api.partner.example/dashboard") : null) });
  await si.signIn("acme.test", H, { header_name: "Authorization", header_value: "Bearer good-token" }, { fetchImpl: c.fetchImpl });
  ok("header: never sent across a redirect to another host", c.log.every((x) => SITE.has(x.host)));
}

// ── 6. Storage + routes (real migration on node:sqlite) ─────────────────────
const DAY = 86_400_000;
function createDb() {
  const db = new DatabaseSync(":memory:");
  db.exec(`
    CREATE TABLE workspaces (id TEXT PRIMARY KEY, owner_user_id TEXT, deleted_at TEXT);
    CREATE TABLE domains (id TEXT PRIMARY KEY, domain TEXT);
    CREATE TABLE workspace_domains (workspace_id TEXT, domain_id TEXT, verification_status TEXT, verified_at TEXT);
    CREATE TABLE audit_events (id TEXT, workspace_id TEXT, user_id TEXT, actor_type TEXT, event_type TEXT, entity_type TEXT,
      entity_id TEXT, description TEXT, metadata_json TEXT, created_at TEXT);
    CREATE TABLE subscriptions (id TEXT PRIMARY KEY, owner_user_id TEXT, workspace_id TEXT, plan TEXT,
      status TEXT, subscription_status TEXT, trial_end TEXT, expires_at TEXT, current_period_end TEXT,
      payment_failed_at TEXT, stripe_subscription_id TEXT, created_at TEXT, updated_at TEXT);
  `);
  db.exec(fs.readFileSync(path.join(root, "database", "migrations", "116-website-sign-in-profiles.sql"), "utf8"));
  db.prepare("INSERT INTO domains VALUES ('d1','acme.test'), ('d2','other.test'), ('d3','unverified.test')").run();
  db.prepare("INSERT INTO workspaces VALUES ('ws_a','u_owner',NULL), ('ws_b','u_other',NULL)").run();
  db.prepare("INSERT INTO workspace_domains VALUES ('ws_a','d1','verified','2026-01-01'), ('ws_b','d2','verified','2026-01-01'), ('ws_a','d3','pending',NULL)").run();
  setPlan(db, "business", "u_owner");
  return db;
}
function setPlan(db, plan, owner) {
  db.prepare("DELETE FROM subscriptions WHERE owner_user_id = ?").run(owner);
  if (plan === "free") return;
  db.prepare("INSERT INTO subscriptions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)").run(`sub_${owner}`, owner, null, plan, null, "active", null, null,
    new Date(Date.now() + 20 * DAY).toISOString(), null, `stripe_${owner}`, new Date(Date.now() - 40 * DAY).toISOString(), new Date().toISOString());
}
function d1(db) {
  const prepare = (sql) => {
    const st = db.prepare(sql);
    const bound = (...a) => ({
      _run: () => ({ meta: { changes: Number(st.run(...a).changes) } }),
      all: async () => ({ results: st.all(...a) }),
      first: async () => st.get(...a) ?? null,
      run: async () => ({ meta: { changes: Number(st.run(...a).changes) } }),
    });
    return { bind: (...a) => bound(...a), first: async () => bound().first(), all: async () => bound().all() };
  };
  return { prepare, async batch(list) { db.exec("BEGIN"); try { const r = list.map((x) => x._run()); db.exec("COMMIT"); return r; } catch (e) { db.exec("ROLLBACK"); throw e; } } };
}
const USERS = {
  owner: { id: "u_owner" }, admin: { id: "u_admin" }, viewer: { id: "u_viewer" },
  token: { id: "u_owner", api_token_id: "tok_1" }, outsider: { id: "u_out" },
};
const ROLES = { u_owner: "owner", u_admin: "admin", u_viewer: "viewer" };
function harness(db, { env: envExtra = {}, app = fakeApp(), roles = ROLES, limit = null } = {}) {
  const env = { cybermeters_db: d1(db), WEBSITE_AUTH_KEY: KEY, ...envExtra };
  const calls = { rate: [] };
  const call = async (method, p, { user = USERS.owner, body, contentType = "application/json", ws = "ws_a", onRole } = {}) => {
    const request = new Request(`https://api.example/api/workspaces/${ws}/website-security/sign-in${p}`, {
      method, headers: body !== undefined ? { "content-type": contentType } : {}, body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const res = await websiteSignInRoutes({
      request, env, url: new URL(request.url), json: (b, s = 200) => Response.json(b, { status: s }),
      requireAuth: async () => user,
      requireWorkspaceRole: async (u, wsId, perm) => { onRole?.(perm); const role = wsId === "ws_a" ? roles[u.id] : null; return role ? { role } : null; },
      consumeApiRateLimit: async (_env, scopes, action, max) => { calls.rate.push([action, max]); return limit?.(action) || null; },
      signInOptions: { fetchImpl: app.fetchImpl, dnsResolver: null },
    });
    return [res.status, await res.json()];
  };
  return { env, call, calls, app };
}
const SAVE = { method: "form", login_url: "https://acme.test/login", start_url: "https://acme.test/account", username: GOOD.username, password: GOOD.password, authorization_confirmed: true };
{
  const db = createDb(); const h = harness(db);
  eq("route: unauthenticated 401", (await h.call("GET", "", { user: null }))[0], 401);
  eq("route: non-member 403", (await h.call("GET", "", { user: USERS.outsider }))[0], 403);
  eq("route: other tenant's workspace 403", (await h.call("GET", "", { ws: "ws_b" }))[0], 403);
  const [s0, list0] = await h.call("GET", "", { user: USERS.viewer });
  eq("route: viewer reads, cannot manage", [s0, list0.can_manage, list0.reason, list0.domains.map((d) => d.domain)], [200, false, "session_role_required", ["acme.test"]]);
  eq("route: viewer cannot save", (await h.call("PUT", "/acme.test", { user: USERS.viewer, body: SAVE }))[0], 403);
  eq("route: API token cannot save", (await h.call("PUT", "/acme.test", { user: USERS.token, body: SAVE }))[0], 403);
  eq("route: API token is never a manager", (await h.call("GET", "", { user: USERS.token }))[1].can_manage, false);
  eq("route: unverified domain 403", (await h.call("PUT", "/unverified.test", { body: SAVE }))[1].code, "domain_not_verified");
  eq("route: other tenant's domain → same 403", (await h.call("PUT", "/other.test", { body: SAVE }))[1].code, "domain_not_verified");
  eq("route: missing authorization 400", (await h.call("PUT", "/acme.test", { body: { ...SAVE, authorization_confirmed: false } }))[1].code, "authorization_required");
  eq("route: non-JSON 400", (await h.call("PUT", "/acme.test", { body: SAVE, contentType: "text/plain" }))[0], 400);
  const [s1, saved] = await h.call("PUT", "/acme.test", { body: SAVE });
  eq("route: created 201", s1, 201);
  const text = JSON.stringify(saved);
  ok("route: response holds no secret or ciphertext", !/Corr3ct|jane@acme|secret_ciphertext|"ct"/.test(text), text);
  eq("route: masked hint + active", [saved.profile.credential_hint, saved.profile.status], ["j•••@acme.test", "active"]);
  const row = db.prepare("SELECT * FROM website_sign_in_profiles").get();
  ok("store: secret stored only as ciphertext", !/Corr3ct|jane@acme\.test/.test(JSON.stringify(row)) && JSON.parse(row.secret_ciphertext).kid === "k1");
  eq("store: deterministic id", row.id, await store.signInProfileId("ws_a", "d1"));
  eq("store: audit event, no secret", db.prepare("SELECT event_type, metadata_json FROM audit_events").all().map((r) => [r.event_type, /Corr3ct/.test(r.metadata_json)]), [["website_sign_in_profile_created", false]]);
  const [, list1] = await h.call("GET", "");
  ok("route: list never includes ciphertext or secret", !/secret_ciphertext|Corr3ct|"ct"/.test(JSON.stringify(list1)));
  eq("route: list shows the profile", [list1.can_use, list1.domains[0].profile.method], [true, "form"]);
  // Settings-only update keeps the secret; a method change without one is refused.
  const rev = row.credential_revision;
  const [s2, upd] = await h.call("PUT", "/acme.test", { body: { method: "form", login_url: "https://acme.test/login", start_url: "https://acme.test/account", signed_in_text: "Signed in as Jane", authorization_confirmed: true } });
  eq("route: settings-only update keeps the secret", [s2, upd.profile.signed_in_text, db.prepare("SELECT credential_revision FROM website_sign_in_profiles").get().credential_revision], [200, "Signed in as Jane", rev]);
  eq("route: method change needs new credentials", (await h.call("PUT", "/acme.test", { body: { method: "header", start_url: "https://acme.test/dashboard", authorization_confirmed: true } }))[1].code, "header_name_and_value_required");
  // Test sign-in: records the attempt and health.
  const roleChecks = [];
  const [s3, t1] = await h.call("POST", "/acme.test/test", { onRole: (p) => roleChecks.push(p) });
  eq("route: test signs in", [s3, t1.outcome, t1.profile.last_outcome, t1.profile.consecutive_failures], [200, "signed_in", "signed_in", 0]);
  ok("route: membership re-checked after the sign-in", roleChecks.filter((p) => p === "workspace:manage").length >= 2);
  ok("route: test result holds no secret", !/Corr3ct|jane@acme|auth\d|pre\d/.test(JSON.stringify(t1)));
  eq("route: test is rate limited per workspace", h.calls.rate.find(([a]) => a === "website_sign_in_test"), ["website_sign_in_test", 6]);
  eq("attempt recorded", db.prepare("SELECT source, outcome, actor_user_id FROM website_sign_in_attempts").all().map((r) => [r.source, r.outcome, r.actor_user_id]), [["test", "signed_in", "u_owner"]]);
  // Lock-out protection: three credential failures in a row pause the profile.
  const wrong = { ...SAVE, password: "nope" };
  await h.call("PUT", "/acme.test", { body: wrong });
  for (let i = 0; i < 3; i++) await h.call("POST", "/acme.test/test");
  const paused = db.prepare("SELECT status, paused_reason, consecutive_failures FROM website_sign_in_profiles").get();
  eq("lock-out protection: paused after 3 rejected sign-ins", [paused.status, paused.paused_reason, paused.consecutive_failures], ["paused", "repeated_sign_in_failures", 3]);
  await h.call("PUT", "/acme.test", { body: { method: "form", login_url: "https://acme.test/login", start_url: "https://acme.test/account", signed_in_text: "x y z", authorization_confirmed: true } });
  eq("settings-only re-save does NOT resume", db.prepare("SELECT status FROM website_sign_in_profiles").get().status, "paused");
  await h.call("PUT", "/acme.test", { body: SAVE });
  eq("saving new credentials resumes", db.prepare("SELECT status, consecutive_failures FROM website_sign_in_profiles").get(), { status: "active", consecutive_failures: 0 });
  // Any unproven outcome after submission counts toward the pause.
  const p0 = db.prepare("SELECT * FROM website_sign_in_profiles").get();
  for (let i = 0; i < 3; i++) await store.recordSignInAttempt(h.env, { workspaceId: "ws_a", domainId: "d1", profile: p0, source: "scan", scanId: `sx${i}`, outcome: "login_error_status", detail: { submitted: true } });
  eq("post-submission errors pause too", db.prepare("SELECT status FROM website_sign_in_profiles").get().status, "paused");
  await store.recordSignInAttempt(h.env, { workspaceId: "ws_a", domainId: "d1", profile: p0, source: "test", outcome: "signed_in" });
  eq("a successful test resumes", db.prepare("SELECT status, consecutive_failures FROM website_sign_in_profiles").get(), { status: "active", consecutive_failures: 0 });
  await store.recordSignInAttempt(h.env, { workspaceId: "ws_a", domainId: "d1", profile: p0, source: "scan", scanId: "net1", outcome: "login_page_unavailable", detail: {} });
  eq("failures before submitting anything do not count", db.prepare("SELECT consecutive_failures FROM website_sign_in_profiles").get().consecutive_failures, 0);
  // Stale credentials: an attempt for an old revision never updates health.
  const profileOld = { ...db.prepare("SELECT * FROM website_sign_in_profiles").get(), credential_revision: "old" };
  await store.recordSignInAttempt(h.env, { workspaceId: "ws_a", domainId: "d1", profile: profileOld, source: "scan", scanId: "s1", outcome: "credentials_rejected" });
  eq("stale revision: health untouched", db.prepare("SELECT consecutive_failures FROM website_sign_in_profiles").get().consecutive_failures, 0);
  await store.recordSignInAttempt(h.env, { workspaceId: "ws_a", domainId: "d1", profile: profileOld, source: "scan", scanId: "s1", outcome: "credentials_rejected" });
  eq("scan attempt idempotent per scan", db.prepare("SELECT COUNT(*) AS n FROM website_sign_in_attempts WHERE scan_id = 's1'").get().n, 1);
  // A save based on a stale read never overwrites a newer secret.
  const current = db.prepare("SELECT * FROM website_sign_in_profiles").get();
  const stale = { ...current, credential_revision: "stale-rev", secret_ciphertext: "{}" };
  const keepInput = si.normalizeSignInInput({ method: "form", login_url: "https://acme.test/login", authorization_confirmed: true }, { domain: "acme.test", existing: stale });
  let staleCode = null;
  try { await store.saveSignInProfile(h.env, { workspaceId: "ws_a", domainId: "d1", domain: "acme.test", userId: "u_owner", input: keepInput, existing: stale }); } catch (e) { staleCode = e.code; }
  const afterStale = db.prepare("SELECT credential_revision, secret_ciphertext FROM website_sign_in_profiles").get();
  eq("store: stale save refused, secret untouched", [staleCode, afterStale.credential_revision, afterStale.secret_ciphertext === current.secret_ciphertext], ["profile_not_saved", current.credential_revision, true]);
  // Delete destroys the secret; audit remains.
  const [s4, del] = await h.call("DELETE", "/acme.test");
  eq("route: delete", [s4, del.deleted, db.prepare("SELECT COUNT(*) AS n FROM website_sign_in_profiles").get().n], [200, true, 0]);
  ok("route: delete audited", db.prepare("SELECT event_type FROM audit_events").all().some((r) => r.event_type === "website_sign_in_profile_deleted"));
  eq("route: test without profile 404", (await h.call("POST", "/acme.test/test"))[0], 404);
  eq("route: wrong method 405", (await h.call("PATCH", "/acme.test", { body: SAVE }))[0], 405);
}
{
  const db = createDb(); setPlan(db, "free", "u_owner");
  const h = harness(db);
  const [, list] = await h.call("GET", "");
  eq("plan: free plan cannot use it", [list.can_use, list.reason], [false, "plan_required"]);
  eq("plan: free plan cannot save", (await h.call("PUT", "/acme.test", { body: SAVE }))[1].code, "plan_required");
  const h2 = harness(createDb(), { env: { WEBSITE_AUTH_KEY: undefined } });
  eq("vault missing: unavailable, not stored in clear", (await h2.call("PUT", "/acme.test", { body: SAVE }))[0], 503);
  eq("vault missing: list says why", (await h2.call("GET", ""))[1].reason, "vault_unavailable");
  const h3 = harness(createDb(), { limit: (a) => (a === "website_sign_in_change" ? { status: 429, body: { error: "rate" } } : null) });
  eq("rate limit on saves", (await h3.call("PUT", "/acme.test", { body: SAVE }))[0], 429);
}
{
  // Membership revoked while the sign-in was running: nothing is recorded.
  const db = createDb(); const roles = { ...ROLES };
  const app = fakeApp({ route: (u) => { if (u.pathname === "/account") delete roles.u_owner; return null; } });
  const h = harness(db, { roles, app });
  await h.call("PUT", "/acme.test", { body: SAVE });
  eq("revoked mid-test: 403", (await h.call("POST", "/acme.test/test"))[0], 403);
  eq("revoked mid-test: no attempt recorded", db.prepare("SELECT COUNT(*) AS n FROM website_sign_in_attempts").get().n, 0);
  // A soft-deleted workspace stores nothing new.
  db.prepare("UPDATE workspaces SET deleted_at = 'x' WHERE id = 'ws_a'").run();
  const prof = db.prepare("SELECT * FROM website_sign_in_profiles").get();
  await store.recordSignInAttempt(h.env, { workspaceId: "ws_a", domainId: "d1", profile: prof, source: "scan", scanId: "s9", outcome: "signed_in" });
  eq("deleted workspace: no attempt row", db.prepare("SELECT COUNT(*) AS n FROM website_sign_in_attempts").get().n, 0);
}
{
  // Unverified domain at save time is refused in SQL too (not only the route).
  const db = createDb(); const env = { cybermeters_db: d1(db), WEBSITE_AUTH_KEY: KEY };
  const input = si.normalizeSignInInput({ ...SAVE, login_url: "https://unverified.test/login", start_url: "https://unverified.test/account" }, { domain: "unverified.test" });
  let code = null;
  try { await store.saveSignInProfile(env, { workspaceId: "ws_a", domainId: "d3", domain: "unverified.test", userId: "u_owner", input, existing: null }); } catch (e) { code = e.code; }
  eq("store: unverified domain never stored", [code, db.prepare("SELECT COUNT(*) AS n FROM website_sign_in_profiles").get().n], ["profile_not_saved", 0]);
}

// ── 8. Signed-in page checks ───────────────────────────────────────────────
const crawlMod = await import(src("engines", "website-signed-in-scan.js"));
const { runSignedInScan, signedInSummary, cacheControlOf, hasFrameProtection, SIGNED_IN_SCAN_LIMITS } = crawlMod;
{
  eq("cache-control: missing", cacheControlOf(null).kind, "missing");
  eq("cache-control: no-store wins", cacheControlOf("private, no-store, max-age=0").kind, "no_store");
  eq("cache-control: private", cacheControlOf("private, max-age=60").kind, "private");
  eq("cache-control: storable, unknown tokens dropped", cacheControlOf("public, max-age=600, x-evil=<script>"), { kind: "storable", directives: ["public", "max-age=600"] });
  ok("framing: XFO or frame-ancestors", hasFrameProtection(new Headers({ "x-frame-options": "DENY" })) && hasFrameProtection(new Headers({ "content-security-policy": "default-src 'self'; frame-ancestors 'none'" })) && !hasFrameProtection(new Headers({ "content-security-policy": "default-src 'self'" })));
}
function richApp(extra = {}) {
  const flags = { touched: [] };
  const app = fakeApp({ ...extra, route: (u, init, { respond, redirect, cookiesOf, sessions, url }) => {
    if (!SITE.has(u.hostname) || u.protocol !== "https:") return null;
    if (["/login", "/"].includes(u.pathname)) return null;
    const sess = sessions.get(cookiesOf(init.headers || {}).sid);
    const authed = !!sess?.authed && !(extra.endAfter && (sess.n = (sess.n || 0) + 1) > extra.endAfter);
    if (/logout|delete|close|export/.test(u.pathname)) { flags.touched.push(u.pathname); return respond(url, 200, "<html>did something</html>"); }
    const page = (body, headers = {}) => respond(url, 200, `<html><body>${body}</body></html>`, headers);
    if (extra.spa && u.pathname.startsWith("/account")) {
      return authed ? page(`<div id=app></div><a href="/account/a">a</a><a href="/account/b">b</a><p>Signed in as Jane Tester</p>`, { "cache-control": "no-store" }) : redirect(url, "/login");
    }
    switch (u.pathname) {
      case "/account":
        return authed ? page(`<h1>Account</h1><p>Signed in as Jane Tester</p>
          <a href="/account/orders">Orders</a><a href="/account/settings">Settings</a><a href="/logout">Sign out</a>
          <a href="/account/delete">Delete account</a><a href="/admin">Admin</a><a href="/api/me">me</a><a href="/account/invoice.pdf">pdf</a>
          <a href="https://other.example/x">x</a><a href="/account/close">close</a><a href="/account/export">export</a><a href="/help">Help</a>
          <a href="http://acme.test/account/plain">plain</a><a href="/account/old">old</a>`, { "cache-control": "no-store", "x-frame-options": "DENY" })
          : redirect(url, "/login");
      case "/account/orders":
        if (extra.strictAuth && !authed) return redirect(url, "/login");
        // Broken access control on purpose: served with or without a session.
        return page(`<h1>Orders</h1><a href="/account/orders/1">Order 1</a><script src="https://cdn.tracker.example/t.js"></script>`, { "cache-control": "public, max-age=600" });
      case "/account/orders/1":
        return authed ? page(`<h1>Order 1</h1><form method=post action="http://acme.test/reorder"><button>Again</button></form>`, { "cache-control": "private" }) : redirect(url, "/login");
      case "/account/settings": {
        if (extra.strictAuth && !authed) return redirect(url, "/login");
        // A cache in front of the site serves the signed-in page to everyone.
        const h = new Headers({ "content-type": "text/html" }); h.append("set-cookie", "pref=SETTINGVALUE; Path=/");
        const r = new Response(`<html><h1>Settings</h1><p>Signed in as Jane Tester</p></html>`, { status: 200, headers: h });
        Object.defineProperty(r, "url", { value: url });
        return r;
      }
      case "/admin": return authed ? respond(url, 403, "<html>Forbidden</html>") : redirect(url, "/login");
      case "/help": return page("<h1>Help</h1>");
      case "/account/old": return redirect(url, "/logout");
      default: return respond(url, 404, "nf");
    }
  } });
  return { ...app, flags };
}
{
  const app = richApp();
  const r = await runSignedInScan("acme.test", { ...FORM, signed_in_text: "Signed in as Jane" }, GOOD, { fetchImpl: app.fetchImpl });
  eq("signed-in scan: signed in and complete", [r.sign_in.outcome, r.coverage, r.partial_reasons], ["signed_in", "complete", []]);
  const by = Object.fromEntries(r.pages.map((p) => [p.path, p]));
  eq("signed-in scan: pages checked (sensitive first, depth 2)", r.pages.map((p) => `${p.path}:${p.outcome}`).sort(),
    ["/account/old:redirect_not_followed", "/account/orders/1:observed", "/account/orders:observed", "/account/settings:observed", "/account:observed", "/admin:refused", "/help:observed"].sort());
  ok("signed-in scan: never requested sign-out, delete, close or export", app.flags.touched.length === 0, JSON.stringify(app.flags.touched));
  ok("signed-in scan: API, static, other-host and plain-HTTP links never requested", app.log.every((x) => !/\/api\/|\.pdf$/.test(x.path) && SITE.has(x.host) && x.protocol === "https:"));
  eq("signed-in scan: exactly one sign-in, one POST", [app.log.filter((x) => x.path === "/login" && x.method === "GET").length, app.log.filter((x) => x.method === "POST").length], [1, 1]);
  eq("signed-in scan: unsafe links counted, not requested", r.counts.unsafe_skipped >= 4, true);
  eq("cache: start page no-store, orders storable, settings missing, order private",
    [by["/account"].cache_control.kind, by["/account/orders"].cache_control.kind, by["/account/settings"].cache_control.kind, by["/account/orders/1"].cache_control.kind],
    ["no_store", "storable", "missing", "private"]);
  eq("framing: start page protected, orders not", [by["/account"].frame_protection, by["/account/orders"].frame_protection], [true, false]);
  eq("anonymous contrast", [by["/account"].anonymous_access, by["/account/orders"].anonymous_access, by["/account/settings"].anonymous_access, by["/account/orders/1"].anonymous_access],
    ["refused", "served_same_page", "served_with_signed_in_text", "refused"]);
  eq("signed-in page facts: third-party script, HTTP form", [by["/account/orders"].third_party_scripts, by["/account/orders/1"].forms[0].action_scheme], [["cdn.tracker.example"], "http"]);
  const anonReqs = app.log.filter((x) => !x.headers.Cookie && x.path.startsWith("/account"));
  ok("anonymous contrast requests carry no session", anonReqs.length >= 3);
  const summary = signedInSummary(r);
  const text = JSON.stringify(summary);
  ok("summary: no cookie values, credentials, HTML or session ids", !/SETTINGVALUE|Corr3ct|jane@acme|<h1|auth\d|pre\d/.test(text), text.slice(0, 300));
  ok("summary: bounded", text.length < 64_000 && summary.pages.length <= 25);
  boundary("signed-in scan", app, [GOOD.password, GOOD.username]);
}
{
  const r = await runSignedInScan("acme.test", FORM, { ...GOOD, password: "bad" }, { fetchImpl: richApp().fetchImpl });
  eq("signed-in scan: refused sign-in checks no pages", [r.sign_in.outcome, r.coverage, r.pages.length], ["credentials_rejected", "not_run", 0]);
  const spa = await runSignedInScan("acme.test", FORM, GOOD, { fetchImpl: richApp({ spa: true }).fetchImpl });
  eq("SPA shell: identical pages count once", [spa.pages.length, spa.counts.duplicates], [1, 2]);
  const ended = await runSignedInScan("acme.test", FORM, GOOD, { fetchImpl: richApp({ endAfter: 2, strictAuth: true }).fetchImpl });
  ok("session ended mid-scan is reported", ended.partial_reasons.includes("session_ended"), JSON.stringify(ended.partial_reasons));
  const tight = await runSignedInScan("acme.test", FORM, GOOD, { fetchImpl: richApp().fetchImpl, limits: { maxFetches: 8 } });
  ok("request ceiling: partial, not complete", tight.coverage === "partial" && tight.partial_reasons.includes("fetch_limit"), JSON.stringify([tight.coverage, tight.partial_reasons]));
  const few = await runSignedInScan("acme.test", FORM, GOOD, { fetchImpl: richApp().fetchImpl, scanLimits: { maxPages: 2, maxPages2: 99 } });
  ok("page limit: partial", few.partial_reasons.includes("page_limit") && few.pages.filter((p) => p.outcome === "observed").length === 2);
  const big = await runSignedInScan("acme.test", FORM, GOOD, { fetchImpl: richApp().fetchImpl, scanLimits: { maxPages: 999 } });
  ok("scan limits can only be tightened", big.limits.max_pages === SIGNED_IN_SCAN_LIMITS.maxPages);
}

{
  // The profile a scan may use: active, live workspace, verified domain, paid plan, key present.
  const db = createDb(); const env = { cybermeters_db: d1(db), WEBSITE_AUTH_KEY: KEY };
  const input = si.normalizeSignInInput(SAVE, { domain: "acme.test" });
  await store.saveSignInProfile(env, { workspaceId: "ws_a", domainId: "d1", domain: "acme.test", userId: "u_owner", input, existing: null });
  const got = await store.loadSignedInScanProfile(env, { workspaceId: "ws_a", domainId: "d1" });
  eq("scan profile: usable with secret", [!!got?.secret, got?.secret?.password === GOOD.password], [true, true]);
  eq("scan profile: other workspace has none", await store.loadSignedInScanProfile(env, { workspaceId: "ws_b", domainId: "d1" }), null);
  eq("scan profile: missing key → blocked, not attempted", (await store.loadSignedInScanProfile({ ...env, WEBSITE_AUTH_KEY: undefined }, { workspaceId: "ws_a", domainId: "d1" }))?.blocked, "vault_unavailable");
  setPlan(db, "free", "u_owner");
  eq("scan profile: free plan → blocked", (await store.loadSignedInScanProfile(env, { workspaceId: "ws_a", domainId: "d1" }))?.blocked, "plan_required");
  setPlan(db, "business", "u_owner");
  db.prepare("UPDATE website_sign_in_profiles SET status = 'paused'").run();
  eq("scan profile: paused → not used", await store.loadSignedInScanProfile(env, { workspaceId: "ws_a", domainId: "d1" }), null);
  db.prepare("UPDATE website_sign_in_profiles SET status = 'active'").run();
  db.prepare("UPDATE workspace_domains SET verification_status = 'pending' WHERE workspace_id = 'ws_a' AND domain_id = 'd1'").run();
  eq("scan profile: domain no longer verified → not used", await store.loadSignedInScanProfile(env, { workspaceId: "ws_a", domainId: "d1" }), null);
  db.prepare("UPDATE workspace_domains SET verification_status = 'verified' WHERE workspace_id = 'ws_a' AND domain_id = 'd1'").run();
  db.prepare("UPDATE workspaces SET deleted_at = 'x' WHERE id = 'ws_a'").run();
  eq("scan profile: deleted workspace → not used", await store.loadSignedInScanProfile(env, { workspaceId: "ws_a", domainId: "d1" }), null);
}

// ── 5b. Non-author review hardening ─────────────────────────────────────────
{
  // A start page that sends EVERYONE to the same public page proves nothing.
  const everyone = (path, to) => ({ route: (u, i, { redirect, url }) => (u.pathname === path && SITE.has(u.hostname) ? redirect(url, to) : null) });
  const H = { method: "header", login_url: null, start_url: "https://acme.test/dashboard", signed_in_text: null };
  const a = fakeApp({ route: (u, i, { redirect, respond, url }) => (u.pathname === "/dashboard" ? redirect(url, "/app") : u.pathname === "/app" ? respond(url, 200, "<html>public app shell</html>") : null) });
  eq("universal redirect + bogus header: not signed in", (await si.signIn("acme.test", H, { header_name: "Authorization", header_value: "Bearer bogus" }, { fetchImpl: a.fetchImpl })).outcome, "start_page_public");
  eq("universal redirect + wrong password: not signed in", (await run(fakeApp(everyone("/home", "/")), { ...FORM, start_url: "https://acme.test/home" }, { ...GOOD, password: "wrong" })).outcome, "start_page_public");
  // 422 (Devise/Turbo) is a refusal, and every unproven submission counts.
  const r422 = await run(fakeApp({ afterPost: () => null, route: (u, i, { respond, url }) => (u.pathname === "/login" && i.method === "POST" ? respond(url, 422, "") : null) }), { ...FORM, start_url: null });
  eq("422 after the form is a refusal", [r422.outcome, r422.detail.submitted], ["credentials_rejected", true]);
  // A registration form before the sign-in form is never the one submitted.
  const reg = fakeApp({ loginHtml: (csrf) => `<form method=post action="/my-account/register" id="register"><input type=email name=email><input type=password name=password autocomplete="new-password"><button name=register>Register</button></form>
    <form method=post action="/login" class="woocommerce-form-login"><input type=hidden name=csrf value="${csrf}"><input type=email name=email><input type=password name=password autocomplete="current-password"><button>Log in</button></form>` });
  eq("register form skipped, sign-in form used", (await run(reg)).outcome, "signed_in");
  ok("register form never submitted", reg.log.every((x) => !/register/.test(x.path)));
  eq("signup-only page: no sign-in form", si.pickLoginForm(si.extractFormsWithFields(`<form method=post action="/signup"><input name=email><input type=password name=pw></form>`)).error, "login_form_not_found");
  eq("Devise form ids are not mistaken for registration", si.pickLoginForm(si.extractFormsWithFields(`<form id="new_user" class="new_user" action="/users/sign_in" method="post"><input type=email name="user[email]"><input type=password name="user[password]" autocomplete="current-password"></form>`)).passwordName, "user[password]");
  // Redirects into action addresses are never followed with the session.
  for (const target of ["/account/export", "/billing/upgrade?plan=pro&confirm=1", "/keys/rotate", "/account?action=delete"]) {
    const app = fakeApp({ afterLogin: target });
    const r = await run(app, { ...FORM, start_url: null });
    ok(`post-sign-in redirect into ${target} not followed`, r.outcome === "sign_in_redirect_not_followed" && app.log.every((x) => `${x.path}${new URL(x.url).search}` !== target), r.outcome);
  }
  const crawlApp = richApp({ route2: true });
  const crawl = await runSignedInScan("acme.test", FORM, GOOD, { fetchImpl: (url, init) => {
    const u = new URL(url);
    if (u.pathname === "/account" && (init.headers || {}).Cookie) {
      const r = new Response(`<html><p>Signed in as Jane Tester</p><a href="/billing">Billing</a><a href="/admin/login">Admin sign-in</a><a href="/Login">L</a><a href="/auth/google">G</a></html>`, { status: 200, headers: { "content-type": "text/html" } });
      Object.defineProperty(r, "url", { value: url }); crawlApp.log.push({ url, path: u.pathname, host: u.hostname, protocol: u.protocol, method: "GET", headers: init.headers || {} });
      return r;
    }
    if (u.pathname === "/billing") { const r = new Response(null, { status: 302, headers: { location: "/billing/upgrade?plan=pro&confirm=1" } }); Object.defineProperty(r, "url", { value: url }); crawlApp.log.push({ url, path: u.pathname, host: u.hostname, protocol: u.protocol, method: "GET", headers: init.headers || {} }); return r; }
    return crawlApp.fetchImpl(url, init);
  } });
  ok("crawl: redirect into an upgrade/confirm address not followed", crawlApp.log.every((x) => x.path !== "/billing/upgrade") && crawl.pages.some((p) => p.path === "/billing" && p.outcome === "redirect_not_followed"), JSON.stringify(crawl.pages.map((p) => [p.path, p.outcome])));
  ok("crawl: other sign-in pages never requested with the session", crawlApp.log.filter((x) => /\/admin\/login|\/Login|\/auth\/google/.test(x.path)).length === 0);
  // Signed-in text with an unreadable anonymous answer proves nothing.
  const flaky = fakeApp({ route: (u, i, { respond, url, cookiesOf }) => (u.pathname === "/account" && !cookiesOf(i.headers || {}).sid ? respond(url, 503, "busy") : null) });
  eq("anonymous answer unavailable: not confirmed", (await run(flaky, { ...FORM, signed_in_text: "Signed in as Jane" })).outcome, "anonymous_check_unavailable");
  // Renewal is only judged when unambiguous.
  const remember = fakeApp({ afterPost: (url, { redirect, sess }) => { sess.authed = true; return redirect(url, "/account", 302, ["remember_token=RT1; Path=/; Secure; HttpOnly"]); } });
  eq("kept session cookie + new remember cookie: renewal unknown", (await run(remember)).detail.session_cookie_renewed, "unknown");
  for (const name of ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override", "X-Original-URL"]) {
    throwsCode(`input: ${name} refused`, () => si.normalizeSignInInput({ method: "header", start_url: "https://acme.test/account", header_name: name, header_value: "DELETE", authorization_confirmed: true }, { domain: "acme.test" }), "header_name_invalid");
  }
}

// ── 9. End-to-end: queue scan → sign-in → workspace-private attempt row ────
{
  const { runScanEngine } = await import(src("engines", "scan-engine.js"));
  const NOW = "2026-10-11T09:00:00.000Z";
  const NOW_MS = Date.parse(NOW);
  const db = new DatabaseSync(":memory:");
  const apply = (f) => { try { db.exec(fs.readFileSync(f, "utf8")); } catch (e) { if (!/^(?:duplicate column name|no such table|table \S+ already exists|index \S+ already exists)/.test(e.message)) throw e; } };
  apply(path.join(root, "database/schema.sql"));
  for (const f of fs.readdirSync(path.join(root, "database/migrations")).filter((n) => n.endsWith(".sql")).sort()) apply(path.join(root, "database/migrations", f));
  db.exec("PRAGMA foreign_keys = OFF");
  const stmt = (sql, args = []) => ({
    __sql: sql, bind: (...b) => stmt(sql, b),
    first: async (col) => { const r = db.prepare(sql).get(...args) ?? null; return col && r ? r[col] : r; },
    all: async () => ({ results: db.prepare(sql).all(...args), success: true, meta: {} }),
    run: async () => { const r = db.prepare(sql).run(...args); return { success: true, meta: { changes: r.changes, last_row_id: Number(r.lastInsertRowid || 0) } }; },
  });
  const D1 = { prepare: (sql) => stmt(sql), exec: async (sql) => { db.exec(sql); return {}; },
    batch: async (list) => { const out = []; db.exec("BEGIN"); try { for (const x of list) out.push(/^\s*select/i.test(x.__sql) ? await x.all() : await x.run()); db.exec("COMMIT"); return out; } catch (e) { db.exec("ROLLBACK"); throw e; } } };
  const store2 = new Map();
  const R2 = { get: async (k) => { const b = store2.get(String(k)); return b == null ? null : { text: async () => b, json: async () => JSON.parse(b) }; },
    put: async (k, b) => { store2.set(String(k), String(b)); return {}; }, delete: async () => ({}), head: async () => null, list: async () => ({ objects: [] }) };
  const env = { cybermeters_db: D1, cybermeters_reports: R2, SCAN_CAPACITY_MODE: "legacy", SCAN_SUBREQUEST_LIMIT: "200", SCAN_DEADLINE_MS: "115000", APP_VERSION: "signin-trace", WEBSITE_AUTH_KEY: KEY };
  db.prepare("INSERT INTO users (id, email) VALUES ('usr','owner@example.com')").run();
  db.prepare("INSERT INTO workspaces (id, name, owner_user_id, deleted_at) VALUES ('ws','Trace','usr',NULL), ('ws2','Other','usr2',NULL)").run();
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dom','usr','acme.test')").run();
  db.prepare("INSERT INTO workspace_domains (workspace_id, domain_id, verification_status, verified_at) VALUES ('ws','dom','verified','2026-01-01'), ('ws2','dom','verified','2026-01-01')").run();
  db.prepare(`INSERT INTO subscriptions (id, owner_user_id, plan, status, subscription_status, current_period_end, created_at, updated_at) VALUES ('sub','usr','business','active','active',?,?,?)`).run(new Date(Date.now() + 20 * DAY).toISOString(), NOW, NOW);
  db.prepare(`INSERT INTO scans (id, workspace_id, domain_id, domain, status, scan_quality, created_at) VALUES ('scan-si','ws','dom','acme.test','running',NULL,?)`).run(NOW);
  const input = si.normalizeSignInInput({ ...SAVE, signed_in_text: "Signed in as Jane" }, { domain: "acme.test" });
  await store.saveSignInProfile(env, { workspaceId: "ws", domainId: "dom", domain: "acme.test", userId: "usr", input, existing: null });
  const app = richApp();
  const prevFetch = globalThis.fetch, prevErr = console.error, prevWarn = console.warn, prevLog = console.log;
  globalThis.fetch = async (input2, init) => {
    const url = new URL(String(input2));
    const j = (b) => new Response(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });
    if (url.hostname === "crt.sh" || url.hostname === "api.certspotter.com") return j([]);
    if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") {
      const name = String(url.searchParams.get("name") || "").toLowerCase();
      const type = String(url.searchParams.get("type") || "A").toUpperCase();
      return j(SITE.has(name) && type === "A" ? { Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] } : { Status: 0, Answer: [] });
    }
    return app.fetchImpl(String(input2), init);
  };
  console.error = () => {}; console.warn = () => {}; console.log = () => {};
  try { await runScanEngine("scan-si", "dom", "ws", "acme.test", env, { now: () => NOW_MS, executionContext: "queue", trigger: "manual" }); }
  finally { globalThis.fetch = prevFetch; console.error = prevErr; console.warn = prevWarn; console.log = prevLog; }
  const attempt = db.prepare("SELECT * FROM website_sign_in_attempts WHERE scan_id = 'scan-si'").get();
  eq("trace: scan signed in and recorded the attempt for its workspace", [attempt?.workspace_id, attempt?.source, attempt?.outcome, attempt?.coverage], ["ws", "scan", "signed_in", "complete"]);
  const sum = JSON.parse(attempt?.summary_json || "{}");
  ok("trace: signed-in pages stored on the attempt", (sum.pages || []).some((p) => p.path === "/account/settings" && p.anonymous_access === "served_with_signed_in_text"));
  eq("trace: other workspace sharing the domain gets nothing", db.prepare("SELECT COUNT(*) AS n FROM website_sign_in_attempts WHERE workspace_id = 'ws2'").get().n, 0);
  const report = store2.get("reports/scan-si.json") || "";
  // Only the module's own telemetry row (name, timing) is in the scan's report; no signed-in data.
  ok("trace: shared scan report carries no signed-in data", report.length > 0 && !/\/account\/settings|\/account\/orders|served_with_signed_in_text|Jane Tester|anonymous_access/.test(report));
  ok("trace: credentials never stored or reported in clear", !/Corr3ct/.test(report) && !/Corr3ct/.test(JSON.stringify(db.prepare("SELECT * FROM website_sign_in_attempts").all())));
  eq("trace: profile health updated", db.prepare("SELECT last_outcome, last_attempt_source FROM website_sign_in_profiles").get(), { last_outcome: "signed_in", last_attempt_source: "scan" });
  eq("trace: scan completed", db.prepare("SELECT status FROM scans WHERE id = 'scan-si'").get().status, "completed");
  ok("trace: scan never signed out", app.flags.touched.length === 0, JSON.stringify(app.flags.touched) + JSON.stringify(app.log.filter((x) => app.flags.touched.includes(x.path)).map((x) => [x.path, !!x.headers.Cookie])));
  // Free plan: not attempted, recorded as such, nothing sent.
  db.prepare("DELETE FROM subscriptions").run();
  db.prepare(`INSERT INTO scans (id, workspace_id, domain_id, domain, status, scan_quality, created_at) VALUES ('scan-free','ws','dom','acme.test','running',NULL,?)`).run(NOW);
  const posts = app.log.filter((x) => x.method === "POST").length;
  globalThis.fetch = async (u, i) => { const url = new URL(String(u)); if (url.hostname === "cloudflare-dns.com" || url.hostname === "dns.google") return new Response(JSON.stringify({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] }), { status: 200 }); return app.fetchImpl(String(u), i); };
  console.error = () => {}; console.warn = () => {}; console.log = () => {};
  try { await runScanEngine("scan-free", "dom", "ws", "acme.test", env, { now: () => NOW_MS, executionContext: "queue", trigger: "manual" }); }
  finally { globalThis.fetch = prevFetch; console.error = prevErr; console.warn = prevWarn; console.log = prevLog; }
  eq("trace: free plan → not attempted, recorded", db.prepare("SELECT outcome, coverage FROM website_sign_in_attempts WHERE scan_id = 'scan-free'").get(), { outcome: "plan_required", coverage: "not_run" });
  eq("trace: free plan → no sign-in submitted", app.log.filter((x) => x.method === "POST").length, posts);
}

// ── 7. Wiring ───────────────────────────────────────────────────────────────
{
  const index = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "index.js"), "utf8");
  ok("purge: both tables registered", /"website_sign_in_attempts", "website_sign_in_profiles"/.test(index));
  ok("router: sign-in routes mounted", /websiteSignInRoutes\(routeCtx\)/.test(index) && !/signInOptions/.test(index));
  const core = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "routes", "workspaces-core.js"), "utf8");
  ok("domain unlink destroys stored credentials", /await env\.cybermeters_db\s*\.prepare\(`DELETE FROM website_sign_in_profiles WHERE workspace_id = \? AND domain_id = \?`\)/.test(core));
  const engine = fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "website-sign-in.js"), "utf8");
  ok("engine never logs", !/console\./.test(engine) && !/console\./.test(fs.readFileSync(path.join(root, "workers", "scan-api", "src", "engines", "website-sign-in-profiles.js"), "utf8")));
}

console.log(`validate-website-sign-in: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
