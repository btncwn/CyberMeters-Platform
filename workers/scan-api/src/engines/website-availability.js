// ── Website Security: is a website actually served on this domain? ──────────
//
// A domain can resolve, accept HTTPS and still serve no website: the hosting
// platform answers "not found" for the home page because no site or store is
// connected to the domain any more (a closed Shopify store is the common case).
// Customers then see an error page, and the DNS keeps pointing at a platform
// with nothing behind it.
//
// This is an OBSERVATION (score_impact 0) built only from the headers module's
// own home-page GET, which identifies the scanner honestly and already records
// every checked path. It is raised only when the evidence is conclusive:
//   • the headers module assessed the origin (not a bot challenge or edge error);
//   • the home page answer is 404 or 410, a definitive "not here" from the origin;
//   • the final URL stayed on this domain (root or www), so a redirect elsewhere
//     is never blamed on this domain;
//   • no checked home-page path (/, final canonical URL, www variant) served
//     anything else — one 2xx anywhere means a website exists.
// A 5xx, 401/403/429, a timeout or an unassessed module never raises it: those
// are not conclusive answers about whether a website is served.
//
// A second observation covers the site that is DOWN rather than absent: every
// home-page request in this scan (HTTPS and HTTP) was answered by a Cloudflare
// edge error (520-530) or an origin 5xx, so no response from the site itself was
// seen. That is reported as exactly what was observed in this scan — visitors
// were most likely seeing an error page — never as a conclusion that the site is
// gone, and a probe that never ran (budget, timeout, DNS) raises nothing.

export const HOME_PAGE_NOT_FOUND_ID = "https_home_page_not_found";
export const HOME_PAGE_UNAVAILABLE_ID = "https_home_page_unavailable";

// What each Cloudflare edge code means for the visitor, in plain words.
const EDGE_ERROR_TEXT = Object.freeze({
  520: "Cloudflare received an unknown error from the website's server",
  521: "the website's server refused the connection",
  522: "the connection to the website's server timed out",
  523: "Cloudflare could not reach the website's server",
  524: "the website's server took too long to respond",
  525: "the secure (SSL) connection between Cloudflare and the website's server failed",
  526: "the website's server presented an invalid SSL certificate to Cloudflare",
  530: "Cloudflare could not reach the website's server",
});
const UNAVAILABLE_LABELS = new Set(["origin_not_observed", "origin_error_response"]);

const NOT_FOUND_STATUSES = new Set([404, 410]);
const HOME_PAGE_LABELS = new Set(["/", "final_canonical_url", "www_variant"]);

function hostOf(url) {
  try { return new URL(String(url)).hostname.toLowerCase().replace(/\.$/, ""); } catch { return null; }
}

function sameSite(url, root) {
  const host = hostOf(url);
  return Boolean(host) && (host === root || host === `www.${root}`);
}

// Provider attribution comes only from the response's own headers; an
// unrecognised platform is described generically rather than guessed.
function hostingProvider(snapshot) {
  const headers = snapshot && typeof snapshot === "object" ? snapshot : {};
  const keys = Object.keys(headers).map((key) => key.toLowerCase());
  const poweredBy = String(headers["powered-by"] ?? headers["x-powered-by"] ?? "").toLowerCase();
  if (poweredBy.includes("shopify") ||
      keys.some((key) => key.startsWith("x-shopify") || key.startsWith("x-sorting-hat"))) {
    return "Shopify";
  }
  return null;
}

export function homePageAvailabilityFindings(modules, { domain, checkedAt = null } = {}) {
  const headers = modules?.headers;
  const root = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
  if (!headers || !root) return [];
  return [
    ...homePageNotFound(headers, root, checkedAt),
    ...homePageUnavailable(headers, root, checkedAt),
  ];
}

function homePageUnavailable(headers, root, checkedAt) {
  if (headers.accessible === true || headers.headers_assessed === true) return [];
  const paths = Array.isArray(headers.checked_paths) ? headers.checked_paths : [];
  if (paths.length === 0) return [];
  // Every recorded home-page answer must be an edge error or an origin 5xx on
  // this domain; any other answer (or none) is not this observation.
  const failing = paths.every((path) =>
    UNAVAILABLE_LABELS.has(path?.label) &&
    Number(path.status_code) >= 500 && Number(path.status_code) <= 599 &&
    sameSite(path.requested_url, root));
  if (!failing) return [];
  if (!paths.some((path) => String(path.requested_url || "").startsWith("https://"))) return [];

  const answers = [...new Map(paths.map((path) => {
    const code = Number(path.status_code);
    const edge = path.label === "origin_not_observed" && EDGE_ERROR_TEXT[code];
    const text = edge
      ? `HTTP ${code}: ${EDGE_ERROR_TEXT[code]}`
      : `HTTP ${code}: the website's server returned an error`;
    return [code, text];
  })).values()];

  return [{
    // Literal on purpose (see the not-found observation below).
    id: "https_home_page_unavailable",
    finding_type: "observation",
    module: "headers",
    severity: "low",
    confidence: "high",
    title: "Website returned an error instead of the home page",
    description: `In this scan, every request to the home page of ${root} returned an error instead of the website (${answers.join("; ")}). Visitors were most likely seeing an error page when the scan ran. One scan can catch a short outage; if this appears again on the next scan, the site is down.`,
    score_impact: 0,
    evidence: {
      evidence_type: "https_probe",
      probe_target: `https://${root}`,
      observed_value: answers.join("; "),
      expected_value: "The website's home page served by its own server",
      checked_paths: paths.map((path) => ({
        label: path.label,
        method: path.method || null,
        requested_url: path.requested_url || null,
        status_code: Number(path.status_code),
      })),
      checked_at: checkedAt,
    },
  }];
}

function homePageNotFound(headers, root, checkedAt) {
  if (headers.headers_assessed !== true || headers.accessible !== true) return [];
  if (headers.validation_uncertain === true ||
      (Array.isArray(headers.bot_protection_signals) && headers.bot_protection_signals.length > 0)) {
    return [];
  }
  const status = Number(headers.status_code);
  if (!NOT_FOUND_STATUSES.has(status)) return [];
  const finalUrl = headers.response_url || headers.original_url;
  if (!sameSite(finalUrl, root)) return [];

  const homePaths = (Array.isArray(headers.checked_paths) ? headers.checked_paths : [])
    .filter((path) => HOME_PAGE_LABELS.has(path?.label) && path?.status === "ok");
  if (homePaths.length === 0) return [];
  if (!homePaths.every((path) =>
    NOT_FOUND_STATUSES.has(Number(path.status_code)) &&
    (!path.final_url || sameSite(path.final_url, root)))) {
    return [];
  }

  const provider = hostingProvider(headers.raw_capture?.headers_snapshot);
  const statusText = status === 410 ? "410 (gone)" : "404 (not found)";
  const description = provider
    ? `The home page at ${finalUrl} returned HTTP ${statusText} from ${provider}. The domain points to ${provider}, but no active site or store is serving it, so visitors see an error page.`
    : `The home page at ${finalUrl} returned HTTP ${statusText}. Visitors to ${root} see an error page instead of a website.`;

  return [{
    // Literal on purpose: the remediation-coverage sweep discovers emitters by
    // their literal ids, and the exported constant must stay equal to it.
    id: "https_home_page_not_found",
    finding_type: "observation",
    module: "headers",
    severity: "low",
    confidence: "high",
    title: provider ? `No active ${provider} site is served on this domain` : "Home page returns 'not found'",
    description,
    score_impact: 0,
    evidence: {
      evidence_type: "https_probe",
      probe_target: finalUrl,
      observed_value: `HTTP ${status}`,
      expected_value: "The website's home page (HTTP 2xx), or no website records if no site is intended",
      hosting_provider: provider,
      checked_paths: homePaths.map((path) => ({
        label: path.label,
        method: path.method || null,
        status_code: Number(path.status_code),
        final_url: path.final_url || null,
      })),
      checked_at: checkedAt,
    },
  }];
}
