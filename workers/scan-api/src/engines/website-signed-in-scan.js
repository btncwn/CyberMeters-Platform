// ── Website Security: signed-in scanning — pages behind the sign-in ─────────
//
// After a PROVEN sign-in (engines/website-sign-in.js), checks a small number of
// the site's own pages that only a signed-in user sees, with read-only GETs:
//   • every address is checked by the strict safe-GET classifier (no sign-out,
//     delete, cancel, unsubscribe, action verbs, API endpoints) — nothing is
//     ever submitted after the sign-in form;
//   • the sign-in page is never requested again (no repeated sign-ins);
//   • bounded: SIGNED_IN_SCAN_LIMITS pages and depth, inside the session's
//     request/time ceiling (SIGN_IN_LIMITS);
//   • a SPA shell that answers every address the same way counts once.
//
// What a signed-in page is checked for (facts, not verdicts):
//   Cache-Control (can a cache keep a copy of this page?), framing protection,
//   the usual security headers, cookie flags (names only), forms posting
//   elsewhere or over HTTP, mixed content, third-party scripts on pages that
//   handle customer data — and the anonymous contrast: the same address
//   requested WITHOUT the session, to see whether it is refused, or still
//   served (and whether it still shows the customer's signed-in text, which
//   would mean signed-in content reached a request that was not signed in).
//
// The result is workspace-private: it is stored only on that workspace's
// sign-in attempt row and never placed in the domain's shared scan report.
import { isOutboundControlError } from "../lib/ssrf.js";
import {
  normalizePath, extractLinks, toSameSitePageUrl, classifySensitivePath,
  extractForms, findMixedContent, thirdPartyScriptHosts, headerPresence, setCookiesOf, structureFingerprint,
} from "./page-discovery.js";
import {
  signIn, WEBSITE_SIGN_IN_VERSION, containsSignedInText, looksLikeLoginPage, describeSetCookies, signedInStopAt, anonymousStopAt,
  anonymousAnswer, signedInRequestable,
} from "./website-sign-in.js";

export const SIGNED_IN_SCAN_VERSION = "2026-10-11.1";
export const SIGNED_IN_SCAN_LIMITS = Object.freeze({ maxPages: 10, maxDepth: 2, anonymousChecks: 4, maxLinksPerPage: 200 });

const CACHE_TOKENS = /^(?:public|private|no-cache|no-store|must-revalidate|proxy-revalidate|immutable|(?:s-)?max-age=\d{1,10})$/;
/** How a cache may keep this response. Only known directive tokens are kept. */
export function cacheControlOf(value) {
  const raw = String(value || "").toLowerCase();
  const directives = raw.split(",").map((s) => s.trim()).filter((s) => CACHE_TOKENS.test(s)).slice(0, 8);
  let kind;
  if (!raw.trim()) kind = "missing";
  else if (directives.includes("no-store")) kind = "no_store";
  else if (directives.includes("private")) kind = "private";
  else kind = "storable";
  return { kind, directives };
}
export function hasFrameProtection(headers) {
  if (headers.get("x-frame-options")) return true;
  return /(?:^|;)\s*frame-ancestors\s/i.test(headers.get("content-security-policy") || "");
}

function observeSignedInPage({ url, res, html, depth, hosts }) {
  const path = normalizePath(new URL(url).pathname);
  return {
    path,
    depth,
    outcome: "observed",
    status_code: res.status,
    sensitive_kind: classifySensitivePath(path),
    cache_control: cacheControlOf(res.headers.get("cache-control")),
    frame_protection: hasFrameProtection(res.headers),
    security_headers: headerPresence(res.headers),
    cookies: describeSetCookies(setCookiesOf(res.headers)),
    forms: extractForms(html, url, hosts).map((f) => ({ method: f.method, action_kind: f.action_kind, action_scheme: f.action_scheme, action_host: f.action_host, has_password: f.has_password })),
    mixed_content: findMixedContent(html, url),
    third_party_scripts: thirdPartyScriptHosts(html, url, hosts),
    anonymous_access: "not_checked",
  };
}

/**
 * runSignedInScan(domain, profile, secret, opts) — sign in, prove it, then
 * check signed-in pages. Never throws for site behaviour; outbound control
 * errors (scan budget/deadline) end it with coverage "partial"/"not_run".
 */
export async function runSignedInScan(domain, profile, secret, opts = {}) {
  const L = { ...SIGNED_IN_SCAN_LIMITS };
  for (const [k, v] of Object.entries(opts.scanLimits || {})) if (Number.isFinite(v) && k in L && v < L[k]) L[k] = v;
  const base = { source: "signed_in_scan", version: SIGNED_IN_SCAN_VERSION, sign_in_version: WEBSITE_SIGN_IN_VERSION };
  const signed = await signIn(domain, profile, secret, opts);
  const signInPart = { outcome: signed.outcome, detail: signed.detail };
  if (signed.outcome !== "signed_in") {
    return { ...base, sign_in: signInPart, coverage: "not_run", partial_reasons: ["not_signed_in"], counts: { fetched: signed.detail?.fetches ?? 0, pages_observed: 0 }, limits: { max_pages: L.maxPages }, pages: [] };
  }
  const { session, startPage } = signed;
  const hosts = session.hosts;
  const partial = new Set();
  const loginPath = profile.login_url ? normalizePath(new URL(profile.login_url).pathname) : null;
  const startUrl = startPage.url;
  const startPath = normalizePath(new URL(startUrl).pathname);
  const counts = { fetched: 0, pages_observed: 0, refused: 0, duplicates: 0, anonymous_checked: 0, unsafe_skipped: 0, links_seen: 0 };
  const pages = [];
  const visited = new Set([startPath]);
  if (loginPath) visited.add(loginPath);
  const startShape = structureFingerprint(startPage.html, { baseUrl: startUrl });

  const start = observeSignedInPage({ url: startUrl, res: startPage.res, html: startPage.html, depth: 0, hosts });
  start.anonymous_access = signed.detail.anonymous_access === "refused" ? "refused" : signed.detail.anonymous_access === "served" ? "served_different_page" : "not_checked";
  pages.push(start);
  const htmlByPath = new Map([[startPath, startPage.html]]);
  const finalPathByPath = new Map([[startPath, normalizePath(new URL(startPage.url).pathname)]]);

  // Breadth-first by depth; within a depth, sensitive-looking pages first.
  let frontier = [{ url: startUrl, html: startPage.html, depth: 0 }];
  let refusedInRow = 0;
  const stopFor = () => { partial.add(session.state.exhausted || "time_budget"); };
  try {
    crawl: for (let depth = 1; depth <= L.maxDepth && frontier.length; depth++) {
      const next = [];
      const seen = new Set();
      for (const parent of frontier) {
        for (const href of extractLinks(parent.html, L.maxLinksPerPage)) {
          const u = toSameSitePageUrl(href, parent.url, hosts);
          if (!u || u.protocol !== "https:") continue;
          const path = normalizePath(u.pathname);
          if (visited.has(path) || seen.has(path)) continue;
          counts.links_seen++;
          if (!signedInRequestable(path)) { counts.unsafe_skipped++; seen.add(path); continue; }
          seen.add(path);
          next.push({ url: u.toString(), path, i: next.length, kind: classifySensitivePath(path) });
        }
      }
      next.sort((a, b) => (a.kind ? 0 : 1) - (b.kind ? 0 : 1) || a.i - b.i);
      const fetched = [];
      for (const c of next) {
        if (pages.filter((p) => p.outcome === "observed").length >= L.maxPages) { partial.add("page_limit"); break crawl; }
        if (!session.canFetch()) { stopFor(); break crawl; }
        visited.add(c.path);
        const nav = await session.page(c.url, { authed: true, stopAt: signedInStopAt(loginPath) });
        if (nav.outcome === "exhausted") { stopFor(); break crawl; }
        const finalPath = nav.outcome === "ok" ? normalizePath(new URL(nav.url).pathname) : null;
        if (nav.outcome === "stopped") {
          // Redirected into an address we never request: a sign-in page means
          // "refused"; anything else (e.g. sign-out) is simply not followed.
          const target = normalizePath(new URL(nav.url).pathname);
          if (target !== loginPath && classifySensitivePath(target) !== "login") {
            pages.push({ path: c.path, depth, outcome: "redirect_not_followed", status_code: nav.status ?? null, sensitive_kind: c.kind });
            continue;
          }
        }
        const refused = nav.outcome === "offsite" || nav.outcome === "stopped" || [401, 403].includes(nav.status)
          || (finalPath && finalPath !== c.path && (finalPath === loginPath || classifySensitivePath(finalPath) === "login"))
          || (nav.html && looksLikeLoginPage(nav.html));
        if (refused) {
          counts.refused++;
          pages.push({ path: c.path, depth, outcome: "refused", status_code: nav.status ?? null, sensitive_kind: c.kind });
          if (++refusedInRow >= 2) {
            // Two refusals in a row: is the session itself gone?
            const check = await session.page(startUrl, { authed: true, stopAt: signedInStopAt(loginPath) });
            const lost = check.outcome !== "ok" || [401, 403].includes(check.status) || (check.html && looksLikeLoginPage(check.html))
              || normalizePath(new URL(check.url).pathname) !== finalPathByPath.get(startPath);
            if (lost) { partial.add("session_ended"); break crawl; }
            refusedInRow = 0;
          }
          continue;
        }
        refusedInRow = 0;
        if (nav.outcome !== "ok" || !nav.res) { pages.push({ path: c.path, depth, outcome: nav.outcome === "offsite" ? "redirected_offsite" : "unavailable", status_code: nav.status ?? null, sensitive_kind: c.kind }); continue; }
        if (nav.status === 404 || nav.status === 410) { pages.push({ path: c.path, depth, outcome: "not_found", status_code: nav.status, sensitive_kind: c.kind }); continue; }
        if (nav.status >= 400) { pages.push({ path: c.path, depth, outcome: "error_status", status_code: nav.status, sensitive_kind: c.kind }); continue; }
        if (!nav.html) { pages.push({ path: c.path, depth, outcome: "not_html", status_code: nav.status, sensitive_kind: c.kind }); continue; }
        // A redirect to a page already checked, or a SPA shell identical to the start page, counts once.
        if (finalPath !== c.path && visited.has(finalPath)) { counts.duplicates++; continue; }
        visited.add(finalPath);
        const shape = structureFingerprint(nav.html, { baseUrl: nav.url });
        if (shape === startShape) { counts.duplicates++; continue; }
        const page = observeSignedInPage({ url: nav.url, res: nav.res, html: nav.html, depth, hosts });
        page.path = c.path;
        pages.push(page);
        htmlByPath.set(c.path, nav.html);
        finalPathByPath.set(c.path, finalPath);
        fetched.push({ url: nav.url, html: nav.html, depth });
      }
      frontier = depth < L.maxDepth ? fetched : [];
    }

    // Anonymous contrast: the same addresses WITHOUT the session.
    const toCheck = pages.filter((p) => p.outcome === "observed" && p.path !== startPath)
      .sort((a, b) => (a.sensitive_kind ? 0 : 1) - (b.sensitive_kind ? 0 : 1) || a.depth - b.depth)
      .slice(0, L.anonymousChecks);
    for (const p of toCheck) {
      if (!session.canFetch()) { stopFor(); break; }
      const url = new URL(p.path, startUrl).toString();
      const anon = await session.page(url, { authed: false, stopAt: anonymousStopAt(loginPath) });
      if (anon.outcome === "exhausted") { stopFor(); break; }
      counts.anonymous_checked++;
      const answer = anonymousAnswer(anon, finalPathByPath.get(p.path));
      if (answer === "served") {
        if (profile.signed_in_text && containsSignedInText(anon.html, profile.signed_in_text)) p.anonymous_access = "served_with_signed_in_text";
        else {
          const same = structureFingerprint(anon.html, { baseUrl: url }) === structureFingerprint(htmlByPath.get(p.path) || "", { baseUrl: url });
          p.anonymous_access = same ? "served_same_page" : "served_different_page";
        }
      } else p.anonymous_access = answer;
    }
  } catch (err) {
    if (session.state.exhausted || isOutboundControlError(err) || opts.signal?.aborted) partial.add(session.state.exhausted || "aborted");
    else partial.add("error");
  }
  counts.fetched = session.state.fetches;
  counts.pages_observed = pages.filter((p) => p.outcome === "observed").length;
  return {
    ...base,
    sign_in: signInPart,
    coverage: partial.size ? "partial" : "complete",
    partial_reasons: [...partial].sort(),
    counts,
    limits: { max_pages: L.maxPages, max_depth: L.maxDepth },
    pages,
  };
}

/** Compact, storage-safe summary for the attempt row (no HTML, no values). */
export function signedInSummary(result) {
  return {
    version: result.version,
    coverage: result.coverage,
    partial_reasons: result.partial_reasons,
    counts: result.counts,
    limits: result.limits,
    pages: (result.pages || []).slice(0, 25).map((p) => ({
      path: String(p.path).slice(0, 300),
      depth: p.depth,
      outcome: p.outcome,
      status_code: p.status_code ?? null,
      sensitive_kind: p.sensitive_kind ?? null,
      ...(p.outcome === "observed" ? {
        cache_control: p.cache_control,
        frame_protection: p.frame_protection,
        missing_headers: p.security_headers?.missing || [],
        cookies: (p.cookies || []).slice(0, 10),
        forms: (p.forms || []).slice(0, 5),
        mixed_content: { count: p.mixed_content?.count || 0, hosts: (p.mixed_content?.hosts || []).slice(0, 5) },
        third_party_scripts: (p.third_party_scripts || []).slice(0, 10),
        anonymous_access: p.anonymous_access,
      } : {}),
    })),
  };
}

