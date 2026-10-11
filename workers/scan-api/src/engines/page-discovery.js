// ── Website Security: bounded important-page discovery ───────────────────────
//
// Observes a SMALL, bounded set of the site's own public pages beyond the
// homepage, so Website Security can see what a single homepage response hides:
// a login page served without HSTS, a form posting to another origin or over
// plain HTTP, session cookies without Secure, mixed content, third-party
// scripts on sensitive pages.
//
// Scope and honesty (docs/DETECTION-QUALITY-ROADMAP.md Phase 5):
//   • passive GETs only (no form submission, no authentication, no fuzzing);
//   • the scanned host and its www/apex sibling only — never other hosts;
//   • candidates come from the homepage's own links, robots.txt Sitemap lines,
//     /sitemap.xml and a short list of well-known paths;
//   • hard bounds: PAGE_DISCOVERY_LIMITS (pages, fetches, bytes, time);
//   • nothing is inferred from absence: a page is "not_found" only when it was
//     actually requested and answered 404/410; an unrequested page is simply
//     not part of this observation;
//   • cookie VALUES and raw HTML are never retained.
//
// The module never sets `incomplete` (which would downgrade the whole scan);
// it reports its own `coverage` and `partial_reasons` instead.

import { safeFetch } from "../lib/http.js";
import { SECURITY_HEADERS } from "./security-headers-config.js";

export const PAGE_DISCOVERY_VERSION = "2026-10-11.1";

export const PAGE_DISCOVERY_LIMITS = Object.freeze({
  maxPages: 15,             // observed pages, homepage included
  maxFetches: 24,           // every GET: pages, robots.txt, sitemaps, probes
  bodyBytes: 98_304,        // per HTML page
  sitemapBytes: 262_144,    // per sitemap document
  maxSitemapUrls: 500,      // parsed <loc> entries considered
  maxSitemaps: 2,           // sitemap documents fetched (incl. one index hop)
  perFetchTimeoutMs: 6_000,
  minRemainingMs: 6_500,    // stop launching fetches below this
  wellKnownProbes: 6,
  maxLinksParsed: 400,
  maxForms: 10,
  maxCookies: 20,
  maxThirdPartyScripts: 20,
});

export const WELL_KNOWN_PATHS = Object.freeze([
  "/login", "/admin", "/account", "/checkout", "/signin", "/wp-login.php", "/my-account", "/user/login",
]);

const SENSITIVE_PATH_RULES = [
  ["login",    /(?:^|\/)(?:login|log-in|signin|sign-in|logon|wp-login\.php|sso|auth)(?:\/|$|\.|\?)/i],
  ["admin",    /(?:^|\/)(?:admin|wp-admin|administrator|cpanel|backend|manage)(?:\/|$)/i],
  ["checkout", /(?:^|\/)(?:checkout|cart|basket|payment|pay|billing)(?:\/|$)/i],
  ["account",  /(?:^|\/)(?:account|my-account|profile|members?|customer|user)(?:\/|$)/i],
];

const STATIC_ASSET_RE = /\.(?:png|jpe?g|gif|webp|svg|ico|css|js|mjs|map|json|xml|txt|pdf|zip|gz|mp4|mp3|wav|woff2?|ttf|eot|avif|docx?|xlsx?|pptx?|csv|rss|atom)$/i;

const PROBE_HEADERS = {
  "User-Agent":      "Mozilla/5.0 (compatible; CyberMeters-Scanner/1.0; +https://cybermeters.com/scanner)",
  "Accept":          "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
  "Accept-Language": "en-US,en;q=0.5",
};

// ── Pure helpers (exported for fixtures) ────────────────────────────────────

/** Hosts that count as "this site": the scanned host and its www/apex sibling. */
export function siteHosts(domain) {
  let d = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
  if (!d) return new Set();
  // WHATWG URL parsing gives the ASCII (punycode) form the fetched URLs will carry.
  try { d = new URL(`http://${d}/`).hostname; } catch { return new Set(); }
  const apex = d.startsWith("www.") ? d.slice(4) : d;
  return new Set([apex, `www.${apex}`]);
}

/** Normalise a path for identity: no query/fragment, no trailing slash (except root). */
export function normalizePath(pathname) {
  // Path parameters (e.g. ";jsessionid=…", added by servers for cookieless
  // clients like the scanner) are session data, not page identity: drop them.
  let p = String(pathname || "/").split(";")[0];
  try { p = decodeURI(p); } catch { /* keep raw */ }
  p = p.replace(/\/{2,}/g, "/");
  if (!p.startsWith("/")) p = `/${p}`;
  if (p.length > 1) p = p.replace(/\/+$/, "");
  return p.slice(0, 300) || "/";
}

export function classifySensitivePath(path) {
  for (const [kind, re] of SENSITIVE_PATH_RULES) if (re.test(path)) return kind;
  return null;
}

/** Resolve an href against a base; return a same-site page URL or null. */
export function toSameSitePageUrl(href, baseUrl, hosts) {
  if (typeof href !== "string") return null;
  const raw = href.trim();
  if (!raw || raw.startsWith("#") || /^(?:mailto|tel|javascript|data|sms|ftp):/i.test(raw)) return null;
  let u;
  try { u = new URL(raw, baseUrl); } catch { return null; }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  if (u.username || u.password) return null;
  if (!hosts.has(u.hostname.toLowerCase())) return null;
  if (u.port && u.port !== "443" && u.port !== "80") return null;
  // Drop path parameters (";jsessionid=…"): session data, not page identity.
  if (u.pathname.includes(";")) u.pathname = u.pathname.split(";")[0];
  if (STATIC_ASSET_RE.test(u.pathname)) return null;
  u.hash = "";
  u.search = "";
  return u;
}

// ── Linear-time HTML scanning ───────────────────────────────────────────────
// Hostile pages must not be able to burn the Worker's CPU: regexes of the form
// /<tag\b[^>]*>/ backtrack quadratically on "<a<a<a…" bodies and a module cap
// cannot interrupt synchronous work. Every scan below is a single forward pass
// with indexOf; tags longer than MAX_TAG_CHARS are ignored; comments are
// skipped; <script>/<style>/<template> CONTENT is skipped (only the opening tag
// is inspected), so text inside inline scripts is never read as markup.
const MAX_TAG_CHARS = 4096;
const RAW_TEXT_TAGS = new Set(["script", "style", "template", "textarea", "noscript"]);

function attrOf(tag, name) {
  // `tag` is bounded by MAX_TAG_CHARS, so this regex runs on a short string.
  const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"));
  return m ? (m[1] ?? m[2] ?? m[3] ?? "") : null;
}

/**
 * forEachTag(html, wanted, visit) — single forward pass. `wanted` is a Set of
 * lower-case tag names; visit(name, tagText, endIndex) may return false to stop.
 * Closing tags are reported as "/name".
 */
export function forEachTag(html, wanted, visit) {
  const text = String(html || "");
  const n = text.length;
  let lower = null; // lower-cased copy, built once on first raw-text tag
  let i = 0;
  let gt = -1; // cached position of the next '>' at or after i
  while (i < n) {
    const lt = text.indexOf("<", i);
    if (lt === -1) break;
    if (text.startsWith("<!--", lt)) {
      const end = text.indexOf("-->", lt + 4);
      if (end === -1) break;
      i = end + 3;
      continue;
    }
    if (gt < lt) { gt = text.indexOf(">", lt); if (gt === -1) break; }
    // Read the tag name directly (letters/digits only), no regex.
    let k = lt + 1;
    const closing = text[k] === "/";
    if (closing) k++;
    let name = "";
    while (k < n && name.length < 16) {
      const c = text.charCodeAt(k);
      const isAlnum = (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 48 && c <= 57);
      if (!isAlnum) break;
      name += text[k];
      k++;
    }
    name = name.toLowerCase();
    if (!name || gt - lt > MAX_TAG_CHARS) { i = lt + 1; continue; }
    const key = closing ? `/${name}` : name;
    if (wanted.has(key) && visit(key, text.slice(lt, gt + 1), gt + 1) === false) return;
    i = gt + 1;
    if (!closing && RAW_TEXT_TAGS.has(name)) {
      if (lower === null) lower = text.toLowerCase();
      const close = lower.indexOf(`</${name}`, i);
      if (close === -1) break;
      i = close;
    }
  }
}

export function extractLinks(html, limit = PAGE_DISCOVERY_LIMITS.maxLinksParsed) {
  const out = [];
  forEachTag(html, new Set(["a"]), (_n, tag) => {
    const href = attrOf(tag, "href");
    if (href != null) out.push(href);
    return out.length < limit;
  });
  return out;
}

export function parseRobotsSitemaps(text) {
  const out = [];
  for (const line of String(text || "").split(/\r?\n/)) {
    const m = line.match(/^\s*sitemap\s*:\s*(\S+)/i);
    if (m) out.push(m[1]);
    if (out.length >= 5) break;
  }
  return out;
}

export function parseSitemap(xml, limit = PAGE_DISCOVERY_LIMITS.maxSitemapUrls) {
  const text = String(xml || "");
  const isIndex = /<sitemapindex\b/i.test(text);
  const locs = [];
  const re = /<loc>\s*([^<\s]+)\s*<\/loc>/gi;
  let m;
  while ((m = re.exec(text)) && locs.length < limit) locs.push(m[1].replace(/&amp;/g, "&"));
  return { isIndex, locs };
}

/** Parse Set-Cookie strings into names + flags. Values are discarded. */
export function parseCookieFlags(setCookies, limit = PAGE_DISCOVERY_LIMITS.maxCookies) {
  const out = [];
  for (const raw of setCookies || []) {
    if (out.length >= limit) break;
    const parts = String(raw).split(";").map((s) => s.trim());
    const name = (parts[0] || "").split("=")[0].trim().slice(0, 80);
    if (!name) continue;
    const flags = parts.slice(1).map((p) => p.toLowerCase());
    const sameSite = flags.find((f) => f.startsWith("samesite="));
    out.push({
      name,
      secure: flags.includes("secure"),
      httponly: flags.includes("httponly"),
      samesite: sameSite ? sameSite.split("=")[1] || null : null,
    });
  }
  return out;
}

/** Forms on the page: where they post and whether they carry a password field. */
export function extractForms(html, pageUrl, hosts, limit = PAGE_DISCOVERY_LIMITS.maxForms) {
  const forms = [];
  let current = null;
  forEachTag(html, new Set(["form", "/form", "input"]), (name, tag) => {
    if (name === "form") {
      if (forms.length >= limit) return false;
      const method = (attrOf(tag, "method") || "get").toLowerCase() === "post" ? "post" : "get";
      const action = attrOf(tag, "action");
      let actionKind = "same_origin", actionScheme = null, actionHost = null;
      if (action && action.trim() && !action.trim().startsWith("#")) {
        try {
          const u = new URL(action.trim(), pageUrl);
          actionScheme = u.protocol === "https:" ? "https" : (u.protocol === "http:" ? "http" : null);
          if (!hosts.has(u.hostname.toLowerCase())) { actionKind = "other_origin"; actionHost = u.hostname.toLowerCase(); }
        } catch { actionKind = "unparseable"; }
      } else {
        try { actionScheme = new URL(pageUrl).protocol === "https:" ? "https" : "http"; } catch { /* keep null */ }
      }
      current = { method, action_kind: actionKind, action_scheme: actionScheme, action_host: actionHost, has_password: false };
      forms.push(current);
    } else if (name === "/form") {
      current = null;
    } else if (current && isPasswordInput(tag)) {
      current.has_password = true;
    }
    return true;
  });
  return forms;
}

function isPasswordInput(tag) {
  const t = attrOf(tag, "type");
  return typeof t === "string" && t.trim().toLowerCase() === "password";
}

export function hasPasswordField(html) {
  let found = false;
  forEachTag(html, new Set(["input"]), (_n, tag) => { if (isPasswordInput(tag)) { found = true; return false; } return true; });
  return found;
}

/** Active mixed content on an HTTPS page: http:// scripts, iframes, stylesheets, images. */
export function findMixedContent(html, pageUrl) {
  let https = false;
  try { https = new URL(pageUrl).protocol === "https:"; } catch { /* not https */ }
  if (!https) return { count: 0, hosts: [] };
  const hosts = new Set();
  let count = 0;
  forEachTag(html, new Set(["script", "iframe", "img", "link", "source", "video", "audio", "embed"]), (name, tag) => {
    if (name === "link") {
      const rel = (attrOf(tag, "rel") || "").toLowerCase();
      if (!/stylesheet|preload|modulepreload/.test(rel)) return true;
    }
    const ref = attrOf(tag, name === "link" ? "href" : "src");
    if (ref && ref.trim().toLowerCase().startsWith("http://")) {
      count++;
      try { if (hosts.size < 10) hosts.add(new URL(ref.trim()).hostname.toLowerCase()); } catch { /* ignore */ }
    }
    return true;
  });
  return { count, hosts: [...hosts] };
}

/** Hostnames of <script src> outside this site. */
export function thirdPartyScriptHosts(html, pageUrl, hosts, limit = PAGE_DISCOVERY_LIMITS.maxThirdPartyScripts) {
  const out = new Set();
  forEachTag(html, new Set(["script"]), (_n, tag) => {
    const src = attrOf(tag, "src");
    if (src) {
      try {
        const u = new URL(src.trim(), pageUrl);
        const h = u.hostname.toLowerCase();
        if ((u.protocol === "https:" || u.protocol === "http:") && !hosts.has(h)) out.add(h);
      } catch { /* ignore */ }
    }
    return out.size < limit;
  });
  return [...out].sort();
}

function fingerprint(text) {
  // Content fingerprint for soft-404 detection over the WHOLE bounded body
  // (a shared <head> longer than any prefix must not make every page "equal").
  // Not security-relevant; FNV-1a 32-bit + length.
  const s = String(text || "");
  let h = 2166136261;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return `${s.length}:${(h >>> 0).toString(16)}`;
}

async function readBoundedText(res, maxBytes) {
  if (!res?.body) { try { return (await res.text()).slice(0, maxBytes); } catch { return ""; } }
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.byteLength;
    }
  } catch { /* partial body is fine */ }
  try { await reader.cancel(); } catch { /* ignore */ }
  const buf = new Uint8Array(Math.min(total, maxBytes));
  let off = 0;
  for (const c of chunks) {
    const take = Math.min(c.byteLength, buf.length - off);
    if (take <= 0) break;
    buf.set(c.subarray(0, take), off);
    off += take;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

function headerPresence(headers) {
  const present = [], missing = [];
  for (const h of SECURITY_HEADERS) (headers.get(h.name) ? present : missing).push(h.name);
  return { present, missing };
}

function setCookiesOf(headers) {
  try {
    if (typeof headers.getSetCookie === "function") return headers.getSetCookie();
    if (typeof headers.getAll === "function") return headers.getAll("set-cookie");
    return (headers.get("set-cookie") || "").split(/\r?\n/).filter(Boolean);
  } catch { return []; }
}

// ── The module ──────────────────────────────────────────────────────────────

/**
 * runPageDiscoveryModule(domain, opts)
 * opts: { dnsResolver, dnsCache, accounting, signal, remainingMs: () => ms, fetchImpl }
 * Returns { source, version, coverage, partial_reasons, homepage_url, limits,
 *           counts, sources, pages[] } — never `incomplete`.
 */
export async function runPageDiscoveryModule(domain, opts = {}) {
  // Limits may only be TIGHTENED by a caller (tests use this); never loosened.
  const L = { ...PAGE_DISCOVERY_LIMITS };
  for (const [k, v] of Object.entries(opts.limits || {})) {
    if (Number.isFinite(v) && k in L && v < L[k]) L[k] = v;
  }
  const hosts = siteHosts(domain);
  const partial = new Set();
  const pages = [];
  const seenPaths = new Set();
  let fetches = 0;
  const sources = { homepage_links: 0, robots_sitemaps: 0, sitemap_urls: 0, well_known_probed: 0 };

  const timeLeft = () => (typeof opts.remainingMs === "function" ? opts.remainingMs() : Infinity);
  const canFetch = () => {
    if (opts.signal?.aborted) { partial.add("aborted"); return false; }
    if (fetches >= L.maxFetches) { partial.add("fetch_limit"); return false; }
    if (timeLeft() < L.minRemainingMs) { partial.add("time_budget"); return false; }
    return true;
  };
  const get = async (url) => {
    fetches++;
    const timeout = AbortSignal.timeout(L.perFetchTimeoutMs);
    let signal = timeout;
    if (opts.signal) {
      if (typeof AbortSignal.any === "function") signal = AbortSignal.any([opts.signal, timeout]);
      else {
        const c = new AbortController();
        const stop = () => c.abort();
        opts.signal.addEventListener?.("abort", stop, { once: true });
        timeout.addEventListener?.("abort", stop, { once: true });
        signal = c.signal;
      }
    }
    try {
      return await safeFetch(url, {
        method: "GET",
        redirect: "follow",
        headers: PROBE_HEADERS,
        accounting: opts.accounting,
        dnsResolver: opts.dnsResolver,
        dnsCache: opts.dnsCache,
        signal,
        ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
      });
    } catch (err) {
      // Budget/deadline control errors end the module; anything else is "unavailable".
      if (err && (err.name === "AbortError" || /budget|deadline|abort/i.test(String(err.message || err)))) {
        partial.add(opts.signal?.aborted ? "aborted" : "fetch_timeout");
        if (opts.signal?.aborted) throw err;
      }
      return null;
    }
  };

  const result = (homepageUrl) => ({
    source: "page_discovery",
    version: PAGE_DISCOVERY_VERSION,
    coverage: pages.length === 0 ? "not_run" : (partial.size ? "partial" : "complete"),
    partial_reasons: [...partial].sort(),
    homepage_url: homepageUrl,
    limits: { max_pages: L.maxPages, max_fetches: L.maxFetches },
    counts: {
      fetched: fetches,
      observed: pages.filter((p) => p.outcome === "observed").length,
      not_found: pages.filter((p) => p.outcome === "not_found").length,
      sensitive: pages.filter((p) => p.outcome === "observed" && p.sensitive_kind).length,
    },
    sources,
    pages,
  });

  if (!hosts.size) return { ...result(null), coverage: "not_run", partial_reasons: ["invalid_domain"] };

  // 1. Homepage (HTTPS first, then HTTP) — body read for links + fingerprint.
  let home = null, homeHtml = "", homeUrl = null;
  for (const proto of ["https", "http"]) {
    if (!canFetch()) break;
    const res = await get(`${proto}://${domain}/`);
    if (!res) continue;
    let finalUrl;
    try { finalUrl = new URL(res.url || `${proto}://${domain}/`); } catch { continue; }
    if (!hosts.has(finalUrl.hostname.toLowerCase())) { partial.add("homepage_redirects_offsite"); try { await res.body?.cancel(); } catch { /* */ } break; }
    if (res.status >= 500 || res.status >= 400) { partial.add("homepage_error_status"); try { await res.body?.cancel(); } catch { /* */ } continue; }
    home = res; homeUrl = stripUrl(finalUrl.toString());
    if (/html/i.test(res.headers.get("content-type") || "")) homeHtml = await readBoundedText(res, L.bodyBytes);
    else await cancelBody(res);
    break;
  }
  if (!home) {
    if (!partial.size) partial.add("homepage_unavailable");
    return { ...result(null), coverage: "not_run" };
  }
  const homePath = normalizePath(new URL(homeUrl).pathname);
  const homeFingerprint = fingerprint(homeHtml);
  pages.push(observePage({ requestedUrl: homeUrl, res: home, html: homeHtml, source: "homepage", hosts, homePath, homeFingerprint, isHome: true }));
  seenPaths.add(homePath);

  // 2. Candidates: homepage links, then sitemaps (robots.txt + /sitemap.xml).
  const candidates = new Map(); // path -> { url, source }
  const addCandidate = (u, source) => {
    if (!u) return;
    const path = normalizePath(u.pathname);
    if (seenPaths.has(path) || candidates.has(path)) return;
    candidates.set(path, { url: u.toString(), source });
    return true;
  };
  for (const href of extractLinks(homeHtml)) {
    if (addCandidate(toSameSitePageUrl(href, homeUrl, hosts), "homepage_link")) sources.homepage_links++;
  }

  const sitemapUrls = [];
  if (canFetch()) {
    const robots = await get(new URL("/robots.txt", homeUrl).toString());
    if (robots && robots.status === 200 && fromSite(robots, hosts)) {
      for (const sm of parseRobotsSitemaps(await readBoundedText(robots, 32_768))) {
        const u = toSitemapUrl(sm, homeUrl, hosts);
        if (u) { sitemapUrls.push(u); sources.robots_sitemaps++; }
      }
    } else { try { await robots?.body?.cancel(); } catch { /* */ } }
  }
  if (!sitemapUrls.length) sitemapUrls.push(new URL("/sitemap.xml", homeUrl).toString());
  let sitemapsFetched = 0;
  const sitemapQueue = [...sitemapUrls];
  while (sitemapQueue.length && sitemapsFetched < L.maxSitemaps && canFetch()) {
    const smUrl = sitemapQueue.shift();
    sitemapsFetched++;
    const res = await get(smUrl);
    if (!res || res.status !== 200 || !fromSite(res, hosts)) { await cancelBody(res); continue; }
    const { isIndex, locs } = parseSitemap(await readBoundedText(res, L.sitemapBytes));
    if (isIndex) {
      for (const loc of locs.slice(0, 3)) { const u = toSitemapUrl(loc, homeUrl, hosts); if (u) sitemapQueue.push(u); }
      continue;
    }
    for (const loc of locs) {
      if (addCandidate(toSameSitePageUrl(loc, homeUrl, hosts), "sitemap")) sources.sitemap_urls++;
    }
  }

  // 3. Rank: sensitive-looking paths first, then link order, then sitemap order.
  const ranked = [...candidates.entries()]
    .map(([path, c], i) => ({ path, ...c, i, kind: classifySensitivePath(path) }))
    .sort((a, b) => (a.kind ? 0 : 1) - (b.kind ? 0 : 1) || (a.source === b.source ? a.i - b.i : (a.source === "homepage_link" ? -1 : 1)));

  for (const c of ranked) {
    if (pages.length >= L.maxPages) { partial.add("page_limit"); break; }
    if (!canFetch()) break;
    seenPaths.add(c.path);
    const res = await get(c.url);
    const html = res && /html/i.test(res.headers.get("content-type") || "") && res.status < 400
      ? await readBoundedText(res, L.bodyBytes)
      : (await cancelBody(res), "");
    pages.push(observePage({ requestedUrl: c.url, res, html, source: c.source, hosts, homePath, homeFingerprint }));
  }

  // 4. Well-known sensitive paths for kinds not yet covered (bounded probes).
  const coveredKinds = new Set(pages.filter((p) => p.outcome === "observed" && p.sensitive_kind).map((p) => p.sensitive_kind));
  let probes = 0;
  for (const path of WELL_KNOWN_PATHS) {
    const kind = classifySensitivePath(path);
    if (coveredKinds.has(kind) || seenPaths.has(path)) continue;
    if (probes >= L.wellKnownProbes) break;
    if (pages.length >= L.maxPages) { partial.add("page_limit"); break; }
    if (!canFetch()) break;
    probes++; sources.well_known_probed++;
    seenPaths.add(path);
    const url = new URL(path, homeUrl).toString();
    const res = await get(url);
    const html = res && /html/i.test(res.headers.get("content-type") || "") && res.status < 400
      ? await readBoundedText(res, L.bodyBytes)
      : (await cancelBody(res), "");
    const page = observePage({ requestedUrl: url, res, html, source: "well_known", hosts, homePath, homeFingerprint });
    // A probe that is not a real page tells us nothing worth keeping, except a
    // definite 404/410, which is what lets a previously seen page be reported
    // as no longer found.
    if (page.outcome === "observed") { pages.push(page); if (page.sensitive_kind) coveredKinds.add(page.sensitive_kind); }
    else if (page.outcome === "not_found") pages.push(page);
  }

  return result(homeUrl);
}

async function cancelBody(res) { try { await res?.body?.cancel(); } catch { /* ignore */ } }

function toSitemapUrl(raw, homeUrl, hosts) {
  try {
    const u = new URL(String(raw).trim(), homeUrl);
    if ((u.protocol !== "https:" && u.protocol !== "http:") || !hosts.has(u.hostname.toLowerCase())) return null;
    if (u.username || u.password) return null;
    if (u.port && u.port !== "443" && u.port !== "80") return null;
    u.hash = "";
    return u.toString();
  } catch { return null; }
}

/** True when a response (after redirects) still comes from this site. */
function fromSite(res, hosts) {
  try { return !!res && hosts.has(new URL(res.url).hostname.toLowerCase()); } catch { return false; }
}

/** Origin + path only: never keep a query string or fragment from a redirect. */
function stripUrl(u) {
  try { const x = new URL(u); return `${x.protocol}//${x.host}${x.pathname.split(";")[0]}`; } catch { return null; }
}

function observePage({ requestedUrl, res, html, source, hosts, homePath, homeFingerprint, isHome = false }) {
  let path = "/";
  try { path = normalizePath(new URL(requestedUrl).pathname); } catch { /* keep root */ }
  const base = { path, source, requested_url: requestedUrl, sensitive_kind: classifySensitivePath(path), sensitive_basis: null };
  if (base.sensitive_kind) base.sensitive_basis = "path";
  if (!res) return { ...base, outcome: "unavailable", status_code: null, final_url: null };
  let final;
  try { final = new URL(res.url || requestedUrl); } catch { final = null; }
  const finalHost = final?.hostname?.toLowerCase();
  const common = {
    ...base,
    status_code: res.status,
    final_url: final ? stripUrl(final.toString()) : null,
    redirected: (() => {
      try {
        const req = new URL(requestedUrl);
        return !!final && (final.host !== req.host || final.protocol !== req.protocol || normalizePath(final.pathname) !== path);
      } catch { return false; }
    })(),
    https: final?.protocol === "https:",
  };
  if (finalHost && !hosts.has(finalHost)) return { ...common, outcome: "redirected_offsite", offsite_host: finalHost };
  if (res.status === 404 || res.status === 410) return { ...common, outcome: "not_found" };
  if (res.status >= 500) return { ...common, outcome: "error_status" };
  if (res.status >= 400) return { ...common, outcome: "refused" };
  const contentType = (res.headers.get("content-type") || "").split(";")[0].trim().toLowerCase();
  if (!/html/.test(contentType)) return { ...common, outcome: "not_html", content_type: contentType || null };
  if (!isHome && final && normalizePath(final.pathname) === homePath) return { ...common, outcome: "soft_404", soft_404_basis: "redirected_to_homepage" };
  if (!isHome && html && fingerprint(html) === homeFingerprint) return { ...common, outcome: "soft_404", soft_404_basis: "same_content_as_homepage" };
  const pageUrl = final ? final.toString() : requestedUrl;
  const forms = extractForms(html, pageUrl, hosts);
  const hasPassword = forms.some((f) => f.has_password) || hasPasswordField(html);
  const observation = {
    ...common,
    outcome: "observed",
    security_headers: headerPresence(res.headers),
    cookies: parseCookieFlags(setCookiesOf(res.headers)),
    forms,
    password_field: hasPassword,
    mixed_content: findMixedContent(html, pageUrl),
    third_party_scripts: thirdPartyScriptHosts(html, pageUrl, hosts),
  };
  if (hasPassword && observation.sensitive_kind !== "login") {
    observation.sensitive_kind = "login";
    observation.sensitive_basis = "password_field";
  }
  return observation;
}
