// ── Technology detection scan module ──
// Module 5 scan phase: fetches the site, reads response headers + a body snippet, and
// infers the technology stack (server/framework/CMS/versions). Extracted verbatim from
// index.js (monolith decomposition, Phase 1c). looksVersioned is module-internal.
import { safeFetch } from "../lib/http.js";
import { classifyFetchObservation, FETCH_OBSERVATION_STATES } from "../lib/fetch-observation.js";

// ── Module 5: Technology Detection ───────────────────────────────────────────
// Ported from tech_fingerprint.py — collects response headers and infers the
// technology stack.  Runs in Phase 1 parallel with the other core modules.
// Never throws; returns { error } on failure so the scan pipeline continues.

/** Return true if a string matches a version-like pattern (e.g. "PHP/8.1.2"). */
function looksVersioned(s) {
  if (!s) return false;
  // Matches "/1.2", "/ 2", "1.2.3", " v2.4" etc.
  return /[\/\s][0-9]+\.[0-9]/.test(s) || /[\/\s][0-9]{1,3}$/.test(s.trim());
}

export async function runTechModule(domain, opts = {}) {
  const accounting = opts.accounting || null;
  let res = null;
  let bodySnippet = "";

  try {
    res = await safeFetch(`https://${domain}`, {
      method:   "GET",
      redirect: "follow",
      accounting,
    });
    if (res) {
      // Read first 4 KB of body — enough for <script src> / vite markers in <head>
      const reader = res.body?.getReader();
      if (reader) {
        const { value } = await reader.read();
        reader.cancel();
        if (value) bodySnippet = new TextDecoder().decode(value.slice(0, 4096));
      }
    }
  } catch {
    return { error: "Tech module fetch failed" };
  }

  if (!res) return { error: "Tech module: no response" };

  // ── 52x/530: an edge error page is not the customer's technology stack ──────
  // Item 11A completeness criterion, technology arm. A Cloudflare-synthesised
  // edge failure carries `server: cloudflare` and a `cf-ray`, which this module
  // read as positive evidence and published as a DETECTED TECHNOLOGY of the
  // customer — while every real stack marker (nginx, PHP, WordPress …) came back
  // absent because no origin body was ever served. Detected-from-an-error-page
  // and genuinely-absent are different facts.
  //
  // Same shared predicate as headers-scan and ssl-scan (lib/fetch-observation.js);
  // this module asserts nothing new about any status code. `incomplete` is the
  // canonical "this module did not truly run", so every downstream gate defers.
  const observation = classifyFetchObservation({ response: res, executed: true });
  if (observation.state !== FETCH_OBSERVATION_STATES.ORIGIN_RESPONSE) {
    return {
      incomplete:        true,
      incomplete_reason: "origin_not_observed",
      tech_observation: {
        state:          observation.state,
        reason:         observation.reason,
        completeness:   observation.completeness,
        probe_executed: observation.probe_executed,
      },
      final_url:     res.url || `https://${domain}`,
      status_code:   res.status ?? null,
      // Deliberately empty rather than absent: a consumer that reads
      // `.technologies.length` must see zero WITH `incomplete` beside it, never
      // a stack inferred from an error page.
      technologies:  [],
      info_findings: [],
    };
  }

  const h = (name) => res.headers.get(name) ?? null;

  const server     = h("server");
  const poweredBy  = h("x-powered-by");
  const ct         = h("content-type");
  const hsts       = h("strict-transport-security");
  const csp        = h("content-security-policy");
  const xfo        = h("x-frame-options");
  const xcto       = h("x-content-type-options");
  const cfRay      = h("cf-ray");
  const finalUrl   = res.url || `https://${domain}`;
  const statusCode = res.status;

  // ── Inferred technologies ────────────────────────────────────────────────
  const technologies = [];

  const serverLc    = (server    || "").toLowerCase();
  const poweredByLc = (poweredBy || "").toLowerCase();
  const bodyLc      = bodySnippet.toLowerCase();
  const externalScripts = [];
  for (const match of bodySnippet.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) {
    try {
      const scriptUrl = new URL(match[1], finalUrl);
      externalScripts.push(scriptUrl.hostname.toLowerCase());
    } catch { /* skip malformed script src */ }
  }

  if (cfRay || serverLc.includes("cloudflare"))          technologies.push("Cloudflare");
  if (serverLc.includes("nginx"))                        technologies.push("nginx");
  if (serverLc.includes("apache"))                       technologies.push("Apache");
  if (serverLc.includes("iis"))                          technologies.push("Microsoft IIS");
  if (serverLc.includes("openresty"))                    technologies.push("OpenResty");
  if (serverLc.includes("litespeed"))                    technologies.push("LiteSpeed");
  if (poweredByLc.includes("express"))                   technologies.push("Express");
  if (poweredByLc.includes("php"))                       technologies.push("PHP");
  if (poweredByLc.includes("asp.net"))                   technologies.push("ASP.NET");
  if (poweredByLc.includes("next.js"))                   technologies.push("Next.js");
  if (poweredByLc.includes("django"))                    technologies.push("Django");
  if (bodyLc.includes("/assets/index-") ||
      bodyLc.includes("vite") ||
      bodyLc.includes("__vite_"))                        technologies.push("React/Vite");
  if (!technologies.some(t => t === "React/Vite") &&
      bodyLc.includes("_next/static"))                   technologies.push("Next.js");
  if (bodyLc.includes("wp-content") ||
      bodyLc.includes("wp-includes"))                    technologies.push("WordPress");
  if (bodyLc.includes("drupal"))                         technologies.push("Drupal");
  if (bodyLc.includes("joomla"))                         technologies.push("Joomla");

  // ── Informational findings (no score impact) ─────────────────────────────
  // Only raised when headers expose specific version strings — not for generic
  // server names.  "Do not penalize generic Server header yet."
  const infoFindings = [];

  if (poweredBy && looksVersioned(poweredBy)) {
    infoFindings.push({
      id:           "tech_xpoweredby_version_disclosure",
      severity:     "low",
      title:        "X-Powered-By header exposes technology version",
      description:  `The X-Powered-By header discloses a version string: "${poweredBy}". ` +
                    "Attackers can use version information to target known CVEs. Remove or mask this header.",
      score_impact: 0,
    });
  }

  if (server && looksVersioned(server)) {
    infoFindings.push({
      id:           "tech_server_version_disclosure",
      severity:     "low",
      title:        "Server header exposes software version",
      description:  `The Server header discloses a version string: "${server}". ` +
                    "Consider configuring your web server to return a generic or empty Server header.",
      score_impact: 0,
    });
  }

  return {
    final_url:                 finalUrl,
    status_code:               statusCode,
    server,
    x_powered_by:              poweredBy,
    content_type:              ct,
    strict_transport_security: hsts,
    content_security_policy:   csp,
    x_frame_options:           xfo,
    x_content_type_options:    xcto,
    external_scripts:          [...new Set(externalScripts)],
    technologies:              [...new Set(technologies)],  // deduplicate
    info_findings:             infoFindings,
  };
}
