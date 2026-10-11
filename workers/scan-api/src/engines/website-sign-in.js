// ── Website Security: signed-in scanning — sign-in session ──────────────────
//
// Signs in to the customer's OWN verified site with a test account they gave
// us, and proves the session is really signed in before anything is claimed.
//
// Safety contract (permanent):
//   • credentials are only ever sent over HTTPS to the verified site's own
//     hosts (the domain and its www/apex sibling). Redirects are followed by
//     hand, one hop at a time: a hop to another host or to plain HTTP ends the
//     attempt and nothing — no cookie, header or form value — is sent there;
//   • the ONLY thing ever submitted is the sign-in form itself (one POST);
//     a form that would send the password in a URL (GET) is refused;
//   • CAPTCHA, one-time codes and single sign-on through another site are
//     detected and reported, never bypassed;
//   • "signed in" is never assumed from a 200: it needs the customer's
//     signed-in text on the start page, or a start page that refuses an
//     anonymous request while the session gets in;
//   • nothing secret is returned or stored: no cookie or header values, no
//     password, no raw HTML. The result carries names, flags and codes only.
import { safeFetch } from "../lib/http.js";
import { isOutboundControlError } from "../lib/ssrf.js";
import {
  PROBE_HEADERS, siteHosts, normalizePath, forEachTag, attrOf, readBoundedText,
  setCookiesOf, hasPasswordField, isRequestablePath, isApiPath, classifySensitivePath,
} from "./page-discovery.js";

export const WEBSITE_SIGN_IN_VERSION = "2026-10-11.1";

// Ceiling for one signed-in run (sign-in + signed-in page checks). Callers may
// only tighten it: the test-sign-in route uses SIGN_IN_TEST_LIMITS.
export const SIGN_IN_LIMITS = Object.freeze({
  maxFetches: 40,          // every request, every redirect hop included
  maxHops: 5,              // redirects followed per navigation
  bodyBytes: 262_144,      // per HTML page read
  perFetchTimeoutMs: 8_000,
  minRemainingMs: 8_500,
  maxForms: 10,
  maxFields: 60,
  maxCookies: 50,
});

export const SIGN_IN_TEST_LIMITS = Object.freeze({ maxFetches: 16 });

export const SIGN_IN_METHODS = Object.freeze(["form", "header", "cookie"]);

/** Outcomes of one sign-in attempt. Only `signed_in` permits signed-in checks. */
export const SIGN_IN_OUTCOMES = Object.freeze([
  "signed_in",
  // the site said no
  "credentials_rejected", "session_rejected", "mfa_required", "captcha_present", "bot_protection", "rate_limited",
  // we could not confirm
  "signed_in_text_not_found", "signed_in_text_not_distinctive", "start_page_public", "start_page_unavailable",
  // the sign-in page is not something we can use safely
  "login_page_unavailable", "login_form_not_found", "username_field_not_found", "login_form_uses_get",
  "login_form_posts_offsite", "login_not_https", "sign_in_redirects_offsite", "sign_in_redirect_not_followed", "login_error_status",
  // not attempted / internal
  "vault_unavailable", "plan_required", "budget_exhausted", "error",
]);
// Outcomes that mean "the site refused these credentials or needs a human":
// repeated, they pause the profile so a scan can never lock the account out.
export const CREDENTIAL_FAILURE_OUTCOMES = Object.freeze(["credentials_rejected", "session_rejected", "mfa_required", "captcha_present"]);

// ── Input validation (route) ────────────────────────────────────────────────

const FORBIDDEN_HEADERS = new Set([
  "host", "cookie", "set-cookie", "content-length", "content-type", "transfer-encoding", "connection",
  "keep-alive", "upgrade", "te", "trailer", "expect", "origin", "referer", "user-agent", "accept",
  "accept-encoding", "accept-language", "forwarded", "via", "x-real-ip", "true-client-ip", "range",
]);
const HEADER_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,63}$/;
const HEADER_VALUE_RE = /^[\x20-\x7E]{1,4096}$/;
const COOKIE_NAME_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}$/;
const COOKIE_VALUE_RE = /^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]{1,4096}$/;
const FIELD_NAME_RE = /^[A-Za-z0-9_\-[\].:$]{1,100}$/;

export function allowedHeaderName(name) {
  if (typeof name !== "string" || !HEADER_NAME_RE.test(name)) return false;
  const n = name.toLowerCase();
  if (FORBIDDEN_HEADERS.has(n)) return false;
  return !/^(?:proxy-|sec-|x-forwarded-|cf-|x-cybermeters)/.test(n);
}

class InputError extends Error {
  constructor(code) { super(code); this.code = code; this.status = 400; }
}
const bad = (code) => { throw new InputError(code); };

/** https URL on the verified site, no credentials/port/query/fragment, safe to GET. */
export function siteUrl(raw, hosts, field) {
  if (typeof raw !== "string" || !raw.trim() || raw.length > 2048) bad(`${field}_invalid`);
  let u;
  try { u = new URL(raw.trim()); } catch { bad(`${field}_invalid`); }
  if (u.protocol !== "https:") bad(`${field}_not_https`);
  if (!hosts.has(u.hostname.toLowerCase())) bad(`${field}_not_on_domain`);
  if (u.username || u.password || (u.port && u.port !== "443")) bad(`${field}_invalid`);
  u.hash = ""; u.search = "";
  const path = normalizePath(u.pathname);
  if (isApiPath(path) || !isRequestablePath(path, { strict: true })) bad(`${field}_not_a_page`);
  return u.toString();
}

/**
 * normalizeSignInInput(body, { domain, existing })
 * → { method, login_url, start_url, signed_in_text, username_field, password_field,
 *     secret | null (keep existing), credential_hint | null }
 */
export function normalizeSignInInput(body, { domain, existing = null } = {}) {
  const allowed = ["method", "login_url", "start_url", "signed_in_text", "username_field", "password_field",
    "username", "password", "header_name", "header_value", "cookie_name", "cookie_value", "authorization_confirmed"];
  if (!body || typeof body !== "object" || Array.isArray(body) || Object.keys(body).some((k) => !allowed.includes(k))) bad("unsupported_input");
  if (body.authorization_confirmed !== true) bad("authorization_required");
  const hosts = siteHosts(domain);
  if (!hosts.size) bad("unsupported_input");
  const method = body.method;
  if (!SIGN_IN_METHODS.includes(method)) bad("method_invalid");
  const optionalText = (v, field, min, max) => {
    if (v == null || v === "") return null;
    if (typeof v !== "string") bad(`${field}_invalid`);
    const t = v.replace(/\s+/g, " ").trim();
    if (t.length < min || t.length > max) bad(`${field}_invalid`);
    return t;
  };
  const optionalField = (v, field) => {
    if (v == null || v === "") return null;
    if (typeof v !== "string" || !FIELD_NAME_RE.test(v)) bad(`${field}_invalid`);
    return v;
  };
  const out = {
    method,
    login_url: null,
    start_url: body.start_url == null || body.start_url === "" ? null : siteUrl(body.start_url, hosts, "start_url"),
    signed_in_text: optionalText(body.signed_in_text, "signed_in_text", 3, 120),
    username_field: null,
    password_field: null,
    secret: null,
    credential_hint: null,
  };
  const keepSecret = existing && existing.method === method;
  const present = (...keys) => keys.map((k) => body[k] != null && body[k] !== "");
  if (method === "form") {
    out.login_url = siteUrl(body.login_url, hosts, "login_url");
    if (out.start_url && normalizePath(new URL(out.start_url).pathname) === normalizePath(new URL(out.login_url).pathname)) bad("start_url_is_login_page");
    out.username_field = optionalField(body.username_field, "username_field");
    out.password_field = optionalField(body.password_field, "password_field");
    if (present("header_name", "header_value", "cookie_name", "cookie_value").some(Boolean)) bad("unsupported_input");
    const [u, p] = present("username", "password");
    if (u !== p) bad("username_and_password_required");
    if (u) {
      if (typeof body.username !== "string" || typeof body.password !== "string") bad("unsupported_input");
      out.secret = { username: body.username.trim(), password: body.password };
      if (!out.secret.username || out.secret.username.length > 256 || /[\r\n\0]/.test(out.secret.username)) bad("username_invalid");
      if (out.secret.password.length > 512 || /[\r\n\0]/.test(out.secret.password)) bad("password_invalid");
      out.credential_hint = maskUsername(out.secret.username);
    } else if (!keepSecret) bad("username_and_password_required");
  } else {
    if (!out.start_url) bad("start_url_required");
    if (present("login_url", "username", "password", "username_field", "password_field").some(Boolean)) bad("unsupported_input");
    const [nameKey, valueKey] = method === "header" ? ["header_name", "header_value"] : ["cookie_name", "cookie_value"];
    if (present(...(method === "header" ? ["cookie_name", "cookie_value"] : ["header_name", "header_value"])).some(Boolean)) bad("unsupported_input");
    const [n, v] = present(nameKey, valueKey);
    if (n !== v) bad(`${method}_name_and_value_required`);
    if (n) {
      const name = body[nameKey], value = body[valueKey];
      if (method === "header" ? !allowedHeaderName(name) : (typeof name !== "string" || !COOKIE_NAME_RE.test(name))) bad(`${nameKey}_invalid`);
      if (typeof value !== "string" || !(method === "header" ? HEADER_VALUE_RE : COOKIE_VALUE_RE).test(value)) bad(`${valueKey}_invalid`);
      out.secret = { [nameKey]: name, [valueKey]: value };
      out.credential_hint = method === "header" ? `${name} header` : `${name} cookie`;
    } else if (!keepSecret) bad(`${method}_name_and_value_required`);
  }
  return out;
}

export function maskUsername(u) {
  const s = String(u || "");
  const at = s.lastIndexOf("@");
  if (at > 0) return `${s[0]}•••${s.slice(at)}`.slice(0, 120);
  return s.length > 4 ? `${s[0]}•••${s[s.length - 1]}` : "•••";
}

// ── Cookie jar (RFC 6265 subset, site hosts only) ───────────────────────────

/**
 * A minimal cookie jar scoped to the verified site. Cookies for any other
 * domain are ignored, so nothing can ever be replayed to another host.
 */
export function createCookieJar(hosts, { maxCookies = SIGN_IN_LIMITS.maxCookies, now = () => Date.now() } = {}) {
  const store = new Map(); // `${name}\n${domain}\n${path}` → { name, value, domain, hostOnly, path, expiresAt, secure }
  const defaultPath = (p) => {
    if (!p || !p.startsWith("/")) return "/";
    const i = p.lastIndexOf("/");
    return i <= 0 ? "/" : p.slice(0, i);
  };
  function set(rawList, requestUrl) {
    let req;
    try { req = new URL(requestUrl); } catch { return; }
    const reqHost = req.hostname.toLowerCase();
    if (!hosts.has(reqHost)) return;
    for (const raw of rawList || []) {
      const parts = String(raw).split(";");
      const pair = parts.shift() || "";
      const eq = pair.indexOf("=");
      if (eq <= 0) continue;
      const name = pair.slice(0, eq).trim(), value = pair.slice(eq + 1).trim();
      if (!name || name.length > 128 || value.length > 4096 || /[\x00-\x1F\x7F]/.test(name + value)) continue;
      let domain = null, path = null, expiresAt = null, secure = false, remove = false;
      for (const attr of parts) {
        const i = attr.indexOf("=");
        const k = (i === -1 ? attr : attr.slice(0, i)).trim().toLowerCase();
        const v = i === -1 ? "" : attr.slice(i + 1).trim();
        if (k === "domain" && v) domain = v.replace(/^\./, "").toLowerCase();
        else if (k === "path" && v.startsWith("/")) path = v;
        else if (k === "secure") secure = true;
        else if (k === "max-age" && /^-?\d{1,12}$/.test(v)) {
          const s = Number(v);
          if (s <= 0) remove = true; else expiresAt = now() + s * 1000;
        } else if (k === "expires" && expiresAt == null) {
          const t = Date.parse(v);
          if (Number.isFinite(t)) { if (t <= now()) remove = true; else expiresAt = t; }
        }
      }
      // A Domain attribute must cover the request host AND stay on this site.
      if (domain && (!hosts.has(domain) || !(reqHost === domain || reqHost.endsWith(`.${domain}`)))) continue;
      const hostOnly = !domain;
      const entry = { name, value, domain: domain || reqHost, hostOnly, path: path || defaultPath(req.pathname), expiresAt, secure };
      const key = `${entry.name}\n${entry.domain}\n${entry.path}`;
      if (remove) { store.delete(key); continue; }
      if (!store.has(key) && store.size >= maxCookies) continue;
      store.set(key, entry);
    }
  }
  function header(url) {
    let u;
    try { u = new URL(url); } catch { return ""; }
    const host = u.hostname.toLowerCase(), path = u.pathname || "/", t = now();
    const out = [];
    for (const [key, c] of store) {
      if (c.expiresAt != null && c.expiresAt <= t) { store.delete(key); continue; }
      if (c.secure && u.protocol !== "https:") continue;
      if (c.hostOnly ? host !== c.domain : !(host === c.domain || host.endsWith(`.${c.domain}`))) continue;
      if (!(path === c.path || (path.startsWith(c.path) && (c.path.endsWith("/") || path[c.path.length] === "/")))) continue;
      out.push(c);
    }
    out.sort((a, b) => b.path.length - a.path.length);
    return out.map((c) => `${c.name}=${c.value}`).join("; ");
  }
  /** Value snapshot for in-memory comparison only (never persisted). */
  function snapshot() { return new Map([...store].map(([k, c]) => [k, c.value])); }
  return { set, header, snapshot, get size() { return store.size; } };
}

/** Names and flags of Set-Cookie headers (values discarded). */
export function describeSetCookies(rawList, { now = Date.now(), limit = 20 } = {}) {
  const out = [];
  for (const raw of rawList || []) {
    if (out.length >= limit) break;
    const parts = String(raw).split(";").map((s) => s.trim());
    const name = (parts[0] || "").split("=")[0].trim().slice(0, 80);
    if (!name) continue;
    let secure = false, httponly = false, samesite = null, lifetimeSeconds = null, removed = false;
    for (const attr of parts.slice(1)) {
      const i = attr.indexOf("=");
      const k = (i === -1 ? attr : attr.slice(0, i)).trim().toLowerCase();
      const v = i === -1 ? "" : attr.slice(i + 1).trim();
      if (k === "secure") secure = true;
      else if (k === "httponly") httponly = true;
      else if (k === "samesite") samesite = v.toLowerCase().slice(0, 10) || null;
      else if (k === "max-age" && /^-?\d{1,12}$/.test(v)) { lifetimeSeconds = Number(v); if (lifetimeSeconds <= 0) removed = true; }
      else if (k === "expires" && lifetimeSeconds == null) {
        const t = Date.parse(v);
        if (Number.isFinite(t)) { const s = Math.round((t - now) / 1000); if (s <= 0) removed = true; else lifetimeSeconds = s; }
      }
    }
    if (removed) continue; // a deletion is not a cookie the browser keeps
    out.push({
      name, secure, httponly, samesite,
      persistent: lifetimeSeconds != null,
      lifetime_days: lifetimeSeconds != null ? Math.round((lifetimeSeconds / 86400) * 10) / 10 : null,
    });
  }
  return out;
}

// ── HTML: sign-in form, CAPTCHA, one-time codes ─────────────────────────────

const ENTITY = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", "#39": "'", nbsp: " " };
export function decodeEntities(s) {
  return String(s ?? "").replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,6}|#39);/gi, (m, e) => {
    const k = e.toLowerCase();
    if (k.startsWith("#x")) { const n = parseInt(k.slice(2), 16); return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : m; }
    if (k.startsWith("#")) { const n = parseInt(k.slice(1), 10); return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : m; }
    return ENTITY[k] ?? m;
  });
}

const hasAttr = (tag, name) => new RegExp(`\\s${name}(?:\\s|=|/?>|$)`, "i").test(tag);

/** Forms with their fields (name, type, value, checked), bounded. Linear. */
export function extractFormsWithFields(html, { maxForms = SIGN_IN_LIMITS.maxForms, maxFields = SIGN_IN_LIMITS.maxFields } = {}) {
  const forms = [];
  let current = null;
  forEachTag(html, new Set(["form", "/form", "input", "button"]), (name, tag) => {
    if (name === "form") {
      if (forms.length >= maxForms) return false;
      current = {
        method: (attrOf(tag, "method") || "get").trim().toLowerCase() === "post" ? "post" : "get",
        action: attrOf(tag, "action") != null ? decodeEntities(attrOf(tag, "action")).trim() : null,
        fields: [],
        submits: [],
      };
      forms.push(current);
    } else if (name === "/form") {
      current = null;
    } else if (current && current.fields.length + current.submits.length < maxFields) {
      const type = (attrOf(tag, "type") || (name === "button" ? "submit" : "text")).trim().toLowerCase();
      const field = {
        tag: name,
        name: attrOf(tag, "name") != null ? decodeEntities(attrOf(tag, "name")) : null,
        id: attrOf(tag, "id"),
        type,
        value: attrOf(tag, "value") != null ? decodeEntities(attrOf(tag, "value")) : null,
        checked: hasAttr(tag, "checked"),
        autocomplete: (attrOf(tag, "autocomplete") || "").toLowerCase(),
      };
      if (type === "submit" || type === "image" || name === "button") { if (type === "submit") current.submits.push(field); }
      else current.fields.push(field);
    }
    return true;
  });
  return forms;
}

const USERNAME_HINT_RE = /user|e-?mail|login|account|ident|member|customer|uname/i;
const TEXTLIKE = new Set(["text", "email", "tel", ""]);

/** Choose the sign-in form and its username/password fields. */
export function pickLoginForm(forms, { usernameField = null, passwordField = null } = {}) {
  const candidates = forms.filter((f) => f.fields.filter((x) => x.type === "password").length === 1);
  if (!candidates.length) return { error: "login_form_not_found" };
  let form = candidates[0];
  if (passwordField) {
    form = candidates.find((f) => f.fields.some((x) => x.type === "password" && x.name === passwordField));
    if (!form) return { error: "login_form_not_found" };
  }
  const pwIndex = form.fields.findIndex((x) => x.type === "password");
  const pw = form.fields[pwIndex];
  if (!pw.name) return { error: "login_form_not_found" };
  let user = null;
  if (usernameField) {
    user = form.fields.find((x) => x.name === usernameField && x.type !== "hidden" && x.type !== "password");
    if (!user) return { error: "username_field_not_found" };
  } else {
    const textlike = form.fields.filter((x) => x.name && TEXTLIKE.has(x.type));
    user = textlike.find((x) => x.type === "email")
      || textlike.find((x) => x.autocomplete === "username" || x.autocomplete === "email")
      || textlike.find((x) => USERNAME_HINT_RE.test(`${x.name} ${x.id || ""}`))
      || form.fields.slice(0, pwIndex).reverse().find((x) => x.name && TEXTLIKE.has(x.type))
      || null;
    if (!user) return { error: "username_field_not_found" };
  }
  return { form, usernameName: user.name, passwordName: pw.name };
}

/** URL-encoded body for the chosen form: its own fields, our two values, one named submit. */
export function buildLoginBody(form, usernameName, passwordName, secret) {
  const params = new URLSearchParams();
  for (const f of form.fields) {
    if (!f.name || ["file", "reset", "button"].includes(f.type)) continue;
    if (f.name === usernameName && f.type !== "hidden") { params.append(f.name, secret.username); continue; }
    if (f.name === passwordName && f.type === "password") { params.append(f.name, secret.password); continue; }
    if (f.type === "password") continue; // never send anything else in a password field
    if ((f.type === "checkbox" || f.type === "radio") && !f.checked) continue;
    params.append(f.name, f.value ?? ((f.type === "checkbox" || f.type === "radio") ? "on" : ""));
  }
  const submit = form.submits.find((s) => s.name);
  if (submit) params.append(submit.name, submit.value ?? "");
  return params.toString();
}

const CAPTCHA_SRC_RE = /(?:google\.com\/recaptcha|gstatic\.com\/recaptcha|recaptcha\.net|hcaptcha\.com|challenges\.cloudflare\.com\/turnstile|arkoselabs\.com|funcaptcha\.com|captcha-delivery\.com|friendlycaptcha)/i;
const CAPTCHA_CLASS_RE = /(?:^|\s)(?:g-recaptcha|h-captcha|cf-turnstile|frc-captcha)(?:\s|$)/i;
export function detectCaptcha(html) {
  let found = false;
  forEachTag(html, new Set(["script", "iframe", "div", "button", "form", "input"]), (_n, tag) => {
    const src = attrOf(tag, "src") || "";
    if (CAPTCHA_SRC_RE.test(src) || CAPTCHA_CLASS_RE.test(attrOf(tag, "class") || "") || /\sdata-sitekey\s*=/i.test(tag)) { found = true; return false; }
    return true;
  });
  return found;
}
const OTP_NAME_RE = /(?:^|[^a-z])(?:otp|totp|mfa|2fa|tfa|two[-_ ]?factor|verification[-_ ]?code|auth[-_ ]?code|security[-_ ]?code|one[-_ ]?time|passcode)(?:$|[^a-z])/i;
export function detectOneTimeCode(html) {
  let found = false;
  forEachTag(html, new Set(["input"]), (_n, tag) => {
    const ac = (attrOf(tag, "autocomplete") || "").toLowerCase();
    const type = (attrOf(tag, "type") || "text").toLowerCase();
    if (ac === "one-time-code" || (type !== "hidden" && OTP_NAME_RE.test(`${attrOf(tag, "name") || ""} ${attrOf(tag, "id") || ""}`))) { found = true; return false; }
    return true;
  });
  return found;
}

/** Visible-ish text, lower-cased, whitespace folded. Linear: skips tags, scripts and styles. */
export function pageText(html) {
  const s = String(html || "");
  // ASCII-only folding keeps indexes aligned with `s`.
  const lower = s.replace(/[A-Z]+/g, (m) => m.toLowerCase());
  const out = [];
  let len = 0, i = 0;
  while (i < s.length && len < 200_000) {
    const lt = s.indexOf("<", i);
    const chunk = s.slice(i, lt === -1 ? s.length : lt);
    out.push(chunk);
    len += chunk.length;
    if (lt === -1) break;
    let from = lt;
    for (const raw of ["script", "style", "template", "noscript"]) {
      if (lower.startsWith(`<${raw}`, lt)) {
        const close = lower.indexOf(`</${raw}`, lt + 1);
        from = close === -1 ? s.length : close;
        break;
      }
    }
    const gt = from >= s.length ? -1 : s.indexOf(">", from);
    if (gt === -1) break;
    i = gt + 1;
    out.push(" ");
  }
  return decodeEntities(out.join("")).toLowerCase().replace(/\s+/g, " ");
}
export function containsSignedInText(html, text) {
  if (!text) return false;
  return pageText(html).includes(String(text).toLowerCase().replace(/\s+/g, " ").trim());
}
/**
 * A sign-in page, not merely a page with a password field: one form with a
 * single password field AND a visible username field. A change-password or
 * "confirm with your password" form on an account page is not a sign-in page.
 */
export function looksLikeLoginPage(html) {
  if (!html || !hasPasswordField(html)) return false;
  return !pickLoginForm(extractFormsWithFields(html)).error;
}

// ── The session ─────────────────────────────────────────────────────────────

/**
 * createSiteSession(domain, { staticAuth, opts, limits })
 * staticAuth: null | { kind: "header", name, value } | { kind: "cookie", name, value }
 * Every request goes through safeFetch (SSRF + public-DNS checks on every hop)
 * with redirect "manual"; this function follows redirects itself so the
 * credential boundary is checked on each hop.
 */
export function createSiteSession(domain, { staticAuth = null, opts = {}, limits = {} } = {}) {
  const L = { ...SIGN_IN_LIMITS };
  for (const [k, v] of Object.entries(limits || {})) if (Number.isFinite(v) && k in L && v < L[k]) L[k] = v;
  const hosts = siteHosts(domain);
  const jar = createCookieJar(hosts, { now: opts.now });
  const state = { fetches: 0, exhausted: null };
  const timeLeft = () => (typeof opts.remainingMs === "function" ? opts.remainingMs() : Infinity);
  const canFetch = () => {
    if (opts.signal?.aborted) { state.exhausted = "aborted"; return false; }
    if (state.fetches >= L.maxFetches) { state.exhausted = "fetch_limit"; return false; }
    if (timeLeft() < L.minRemainingMs) { state.exhausted = "time_budget"; return false; }
    return true;
  };
  const credentialTarget = (u) => u.protocol === "https:" && hosts.has(u.hostname.toLowerCase()) && !u.username && !u.password && (!u.port || u.port === "443");

  async function once(url, { method, body, contentType, referer, authed }) {
    state.fetches++;
    const u = new URL(url);
    const headers = { ...PROBE_HEADERS };
    if (authed && credentialTarget(u)) {
      const cookieParts = [];
      const fromJar = jar.header(url);
      if (fromJar) cookieParts.push(fromJar);
      if (staticAuth?.kind === "cookie") cookieParts.push(`${staticAuth.name}=${staticAuth.value}`);
      if (cookieParts.length) headers.Cookie = cookieParts.join("; ");
      if (staticAuth?.kind === "header") headers[staticAuth.name] = staticAuth.value;
    }
    if (method === "POST") {
      headers["Content-Type"] = contentType;
      headers.Origin = `${u.protocol}//${u.host}`;
      if (referer) headers.Referer = referer;
    }
    const timeout = AbortSignal.timeout(L.perFetchTimeoutMs);
    const signal = opts.signal && typeof AbortSignal.any === "function" ? AbortSignal.any([opts.signal, timeout]) : timeout;
    try {
      return await safeFetch(url, {
        method, body: method === "POST" ? body : undefined, headers, redirect: "manual", signal,
        accounting: opts.accounting, dnsResolver: opts.dnsResolver, dnsCache: opts.dnsCache,
        ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
      });
    } catch (err) {
      // Scan budget/deadline: end the run (the caller reports it), never retry.
      if (opts.signal?.aborted || isOutboundControlError(err)) { state.exhausted = state.exhausted || "scan_budget"; throw err; }
      return null;
    }
  }

  /**
   * navigate(url, { method, body, authed, referer })
   * → { outcome: "ok" | "offsite" | "insecure" | "stopped" | "unavailable" | "too_many_redirects" | "exhausted",
   *     res, url (final URL string), status, offsite_host, set_cookies: [raw…] }
   * Set-Cookie on EVERY hop is applied to the jar (authed) and returned for
   * flag inspection. Never follows a hop off the site; when authed, never
   * follows a hop to plain HTTP.
   */
  async function navigate(startUrl, { method = "GET", body = null, contentType = "application/x-www-form-urlencoded", authed = true, referer = null, stopAt = null } = {}) {
    let current = startUrl, m = method, b = body;
    const setCookies = [];
    for (let hop = 0; hop <= L.maxHops; hop++) {
      if (!canFetch()) return { outcome: "exhausted", url: current, set_cookies: setCookies };
      const u = new URL(current);
      if (!hosts.has(u.hostname.toLowerCase())) return { outcome: "offsite", url: current, offsite_host: u.hostname.toLowerCase(), set_cookies: setCookies };
      if (authed && !credentialTarget(u)) return { outcome: "insecure", url: current, set_cookies: setCookies };
      const res = await once(current, { method: m, body: b, contentType, referer, authed });
      if (!res) return { outcome: "unavailable", url: current, set_cookies: setCookies };
      const sc = setCookiesOf(res.headers);
      setCookies.push(...sc);
      if (authed) jar.set(sc, current);
      if ([301, 302, 303, 307, 308].includes(res.status)) {
        const loc = res.headers.get("location");
        try { await res.body?.cancel(); } catch { /* ignore */ }
        if (!loc) return { outcome: "ok", res, url: current, status: res.status, set_cookies: setCookies };
        let next;
        try { next = new URL(loc, current); } catch { return { outcome: "unavailable", url: current, set_cookies: setCookies }; }
        next.hash = "";
        if (!hosts.has(next.hostname.toLowerCase())) return { outcome: "offsite", url: current, offsite_host: next.hostname.toLowerCase(), set_cookies: setCookies };
        if (authed && !credentialTarget(next)) return { outcome: "insecure", url: next.toString(), set_cookies: setCookies };
        // The caller decides where a redirect may NOT be followed (a sign-in
        // page, an address that could change something, another path).
        if (stopAt && stopAt(next, u)) return { outcome: "stopped", url: next.toString(), status: res.status, set_cookies: setCookies };
        if (m === "POST" && (res.status === 307 || res.status === 308)) {
          // Re-sending the form is only acceptable to the very same origin.
          if (next.origin !== u.origin) return { outcome: "offsite", url: current, offsite_host: next.hostname.toLowerCase(), set_cookies: setCookies };
        } else { m = "GET"; b = null; }
        referer = `${u.origin}${u.pathname}`;
        current = next.toString();
        continue;
      }
      return { outcome: "ok", res, url: current, status: res.status, set_cookies: setCookies };
    }
    return { outcome: "too_many_redirects", url: current, set_cookies: setCookies };
  }

  /** navigate + bounded HTML body (empty when not HTML or not 2xx). */
  async function page(url, options = {}) {
    const nav = await navigate(url, options);
    let html = "";
    if (nav.outcome === "ok" && nav.res) {
      const isHtml = /html/i.test(nav.res.headers.get("content-type") || "");
      if (isHtml && nav.status >= 200 && nav.status < 300) html = await readBoundedText(nav.res, L.bodyBytes);
      else { try { await nav.res.body?.cancel(); } catch { /* ignore */ } }
    }
    return { ...nav, html };
  }

  return { hosts, jar, navigate, page, state, canFetch, limits: L };
}

/** Never follow a signed-in redirect into a sign-in page or an address that could change something. */
export function signedInStopAt(loginPath) {
  return (next) => {
    const p = normalizePath(next.pathname);
    return p === loginPath || classifySensitivePath(p) === "login" || !isRequestablePath(p, { strict: true });
  };
}
/** Anonymous contrast: any redirect to a different path is already the answer ("refused"). */
export const anonymousStopAt = (next, current) => normalizePath(next.pathname) !== normalizePath(current.pathname);

const isChallenge = (nav) => {
  const h = nav?.res?.headers;
  if (!h) return false;
  return (h.get("cf-mitigated") || "").toLowerCase() === "challenge";
};

// ── Sign-in + proof ─────────────────────────────────────────────────────────

/**
 * Proves the session is signed in on the start page. Two independent ways:
 *   1. the customer's signed-in text appears with the session and NOT
 *      without it; or
 *   2. without signed-in text: the start page serves the session a normal
 *      page while an anonymous request is refused (401/403, redirected
 *      elsewhere, or shown a password form).
 */
export async function verifySignedIn(session, { startUrl, signedInText = null, loginUrl = null }) {
  const startPath = normalizePath(new URL(startUrl).pathname);
  const loginPath = loginUrl ? normalizePath(new URL(loginUrl).pathname) : null;
  const authed = await session.page(startUrl, { authed: true, stopAt: signedInStopAt(loginPath) });
  if (authed.outcome === "exhausted") return { outcome: "budget_exhausted" };
  if (isChallenge(authed)) return { outcome: "bot_protection" };
  const authedPath = authed.outcome === "ok" ? normalizePath(new URL(authed.url).pathname) : null;
  const detail = { start_status: authed.status ?? null };
  const refused = authed.outcome === "offsite" || authed.outcome === "stopped" || [401, 403].includes(authed.status)
    || (authedPath && authedPath !== startPath && (authedPath === loginPath || classifySensitivePath(authedPath) === "login"))
    || (authed.status >= 200 && authed.status < 300 && looksLikeLoginPage(authed.html) && !containsSignedInText(authed.html, signedInText));
  if (refused) return { outcome: "session_refused", detail };
  if (authed.status === 429) return { outcome: "rate_limited", detail };
  if (authed.outcome !== "ok" || !(authed.status >= 200 && authed.status < 300) || !authed.html) return { outcome: "start_page_unavailable", detail };

  const anon = await session.page(startUrl, { authed: false, stopAt: anonymousStopAt });
  const anonPath = anon.outcome === "ok" ? normalizePath(new URL(anon.url).pathname) : null;
  let anonymous = "unavailable";
  if (anon.outcome === "offsite" || anon.outcome === "stopped" || [401, 403, 404, 410].includes(anon.status) || (anonPath && anonPath !== startPath)
      || (anon.status >= 200 && anon.status < 300 && looksLikeLoginPage(anon.html))) anonymous = "refused";
  else if (anon.outcome === "ok" && anon.status >= 200 && anon.status < 300 && anon.html) anonymous = "served";
  detail.anonymous_access = anonymous;

  if (signedInText) {
    if (!containsSignedInText(authed.html, signedInText)) return { outcome: "signed_in_text_not_found", detail };
    if (anonymous === "served" && containsSignedInText(anon.html, signedInText)) return { outcome: "signed_in_text_not_distinctive", detail };
    return { outcome: "signed_in", detail: { ...detail, basis: "signed_in_text" }, startPage: { url: authed.url, html: authed.html, res: authed.res } };
  }
  if (anonymous === "refused") return { outcome: "signed_in", detail: { ...detail, basis: "anonymous_refused" }, startPage: { url: authed.url, html: authed.html, res: authed.res } };
  if (anonymous === "served") return { outcome: "start_page_public", detail };
  return { outcome: "start_page_unavailable", detail };
}

/**
 * signIn(domain, profile, secret, opts) — one bounded sign-in attempt.
 * profile: { method, login_url, start_url, signed_in_text, username_field, password_field }
 * → { outcome, detail, session?, startPage? } — `session` only when signed_in.
 */
export async function signIn(domain, profile, secret, opts = {}) {
  const staticAuth = profile.method === "header" ? { kind: "header", name: secret.header_name, value: secret.header_value }
    : profile.method === "cookie" ? { kind: "cookie", name: secret.cookie_name, value: secret.cookie_value } : null;
  const session = createSiteSession(domain, { staticAuth, opts, limits: opts.limits });
  const detail = { method: profile.method, version: WEBSITE_SIGN_IN_VERSION };
  const finish = (outcome, extra = {}) => ({ outcome, detail: { ...detail, ...extra, fetches: session.state.fetches } });
  try {
    if (profile.method !== "form") {
      const v = await verifySignedIn(session, { startUrl: profile.start_url, signedInText: profile.signed_in_text });
      const outcome = v.outcome === "session_refused" ? "session_rejected" : v.outcome;
      return outcome === "signed_in"
        ? { ...finish(outcome, v.detail), session, startPage: v.startPage }
        : finish(outcome, v.detail);
    }

    // 1. The sign-in page itself (no credentials yet; cookies it sets are kept).
    const login = await session.page(profile.login_url, { authed: true });
    if (login.outcome === "exhausted") return finish("budget_exhausted");
    if (login.outcome === "offsite") return finish("sign_in_redirects_offsite", { offsite_host: login.offsite_host });
    if (login.outcome === "insecure") return finish("login_not_https");
    if (isChallenge(login)) return finish("bot_protection");
    if (login.status === 429) return finish("rate_limited");
    if (login.outcome !== "ok" || !(login.status >= 200 && login.status < 300) || !login.html) return finish("login_page_unavailable", { login_status: login.status ?? null });
    if (detectCaptcha(login.html)) return finish("captcha_present", { login_status: login.status });

    // 2. The form: one password field, posted with POST over HTTPS to this site.
    const picked = pickLoginForm(extractFormsWithFields(login.html), { usernameField: profile.username_field, passwordField: profile.password_field });
    if (picked.error) return finish(picked.error, { login_status: login.status });
    const { form, usernameName, passwordName } = picked;
    const formDetail = { username_field: usernameName.slice(0, 100), password_field: passwordName.slice(0, 100), fields: form.fields.length, hidden_fields: form.fields.filter((f) => f.type === "hidden").length };
    if (form.method !== "post") return finish("login_form_uses_get", { form: formDetail });
    let action;
    try { action = new URL(form.action || login.url, login.url); } catch { return finish("login_form_not_found"); }
    action.hash = "";
    if (!session.hosts.has(action.hostname.toLowerCase())) return finish("login_form_posts_offsite", { form: formDetail, offsite_host: action.hostname.toLowerCase() });
    if (action.protocol !== "https:" || (action.port && action.port !== "443") || action.username || action.password) return finish("login_not_https", { form: formDetail });

    // 3. Submit once. Cookies before/after are compared IN MEMORY only.
    const before = session.jar.snapshot();
    const loginPageUrl = new URL(login.url);
    const posted = await session.page(action.toString(), {
      method: "POST",
      body: buildLoginBody(form, usernameName, passwordName, secret),
      referer: `${loginPageUrl.origin}${loginPageUrl.pathname}`,
      authed: true,
      // After the form, never follow a redirect into an address that could change something.
      stopAt: (next) => !isRequestablePath(normalizePath(next.pathname), { strict: true }),
    });
    const cookiesAtSignIn = describeSetCookies(posted.set_cookies, { now: typeof opts.now === "function" ? opts.now() : Date.now() });
    const landing = { status: posted.status ?? null, path: posted.outcome === "ok" || posted.outcome === "stopped" ? normalizePath(new URL(posted.url).pathname) : null };
    const extra = { form: formDetail, landing, cookies_at_sign_in: cookiesAtSignIn };
    if (posted.outcome === "exhausted") return finish("budget_exhausted", extra);
    if (posted.outcome === "offsite") return finish("sign_in_redirects_offsite", { ...extra, offsite_host: posted.offsite_host });
    if (posted.outcome === "insecure") return finish("login_not_https", extra);
    if (isChallenge(posted)) return finish("bot_protection", extra);
    if (posted.status === 429) return finish("rate_limited", extra);
    // Not following a redirect into an unsafe address is fine when a start
    // page can prove the sign-in; without one there is nothing to prove it on.
    if (posted.outcome === "stopped" && !profile.start_url) return finish("sign_in_redirect_not_followed", extra);
    if ((posted.outcome !== "ok" && posted.outcome !== "stopped") || posted.status >= 500) return finish("login_error_status", extra);
    if (posted.html && detectOneTimeCode(posted.html)) return finish("mfa_required", extra);
    if (posted.html && detectCaptcha(posted.html)) return finish("captcha_present", extra);
    if ([401, 403].includes(posted.status)) return finish("credentials_rejected", extra);

    // 4. Prove it on the start page (or where the site landed us).
    if (!profile.start_url && posted.html && looksLikeLoginPage(posted.html)) return finish("credentials_rejected", extra);
    const startUrl = profile.start_url || (posted.status >= 200 && posted.status < 300 ? posted.url : null);
    if (!startUrl) return finish("login_error_status", extra);
    const v = await verifySignedIn(session, { startUrl, signedInText: profile.signed_in_text, loginUrl: profile.login_url });
    // Sent back to a sign-in page: the site did not accept these credentials.
    if (v.outcome !== "signed_in") return finish(v.outcome === "session_refused" ? "credentials_rejected" : v.outcome, { ...extra, ...v.detail });
    const after = session.jar.snapshot();
    let renewed = "no_cookie_before_sign_in";
    if (before.size) {
      renewed = [...after].some(([k, val]) => before.get(k) !== val) ? "renewed" : "not_renewed";
    }
    return { ...finish("signed_in", { ...extra, ...v.detail, session_cookie_renewed: renewed, start_path: normalizePath(new URL(startUrl).pathname) }), session, startPage: v.startPage };
  } catch (err) {
    if (opts.signal?.aborted || session.state.exhausted) return finish("budget_exhausted");
    return finish("error");
  }
}
