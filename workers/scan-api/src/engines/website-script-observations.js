import { forEachTag } from "./page-discovery.js";
import { JAVASCRIPT_ADVISORY_DATA } from "./javascript-advisory-data.js";

export const SCRIPT_LIMITS = Object.freeze({ html_chars: 65536, scripts: 40, tag_chars: 4096 });
const space = (c) => /[ \t\r\n\f]/.test(c || "");
const ownHost = (host, root) => typeof host === "string" && typeof root === "string" && (host === root || host.endsWith(`.${root}`));

// Reuse the bounded forward tag traversal. Read actual attributes instead of
// matching src/integrity text inside another attribute's quoted value. Reject
// truncated/ambiguous tags, including a quoted '>' that the traversal split.
function attributes(tag, name) {
  const prefix = new RegExp(`^<${name}(?=[\\s/>])`, "i").exec(tag);
  if (!prefix) return null;
  const out = new Map();
  let i = prefix[0].length;
  while (i < tag.length) {
    while (space(tag[i])) i++;
    if (tag[i] === ">" || (tag[i] === "/" && tag[i + 1] === ">")) return out;
    const start = i;
    while (/[a-z0-9_:-]/i.test(tag[i] || "") && i < tag.length) i++;
    if (i === start) return null;
    const key = tag.slice(start, i).toLowerCase();
    while (space(tag[i])) i++;
    let value = "";
    if (tag[i] === "=") {
      i++;
      while (space(tag[i])) i++;
      if (tag[i] === '"' || tag[i] === "'") {
        const quote = tag[i++], end = tag.indexOf(quote, i);
        if (end < 0) return null;
        value = tag.slice(i, end); i = end + 1;
      } else {
        const begin = i;
        while (i < tag.length && !space(tag[i]) && tag[i] !== ">") i++;
        value = tag.slice(begin, i);
        if (/["'<`=]/.test(value)) return null;
      }
    }
    if (!out.has(key)) out.set(key, value); // HTML keeps the first duplicate
  }
  return null;
}

const versionParts = (value) => /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(value || "")
  ? value.split(".").map(Number) : null;
const compare = (a, b) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];

export function declaredLibrary(path) {
  // Exact distribution labels only, never an arbitrary ?version= value,
  // major/minor guess, prerelease, unrelated bundle or similarly named package.
  const match = path.match(/\/(jquery|lodash)-(\d+\.\d+\.\d+)(?:\.min)?\.js$/i)
    || path.match(/\/(jquery|lodash)(?:@|\/)(\d+\.\d+\.\d+)\/(?:dist\/)?\1(?:\.min)?\.js$/i);
  if (!match || !versionParts(match[2])) return null;
  const library = { package: match[1].toLowerCase(), version: match[2] };
  library.advisories = JAVASCRIPT_ADVISORY_DATA.advisories.filter((row) => row.package === library.package
    && compare(versionParts(library.version), versionParts(row.introduced)) >= 0
    && compare(versionParts(library.version), versionParts(row.fixed)) < 0).map((row) => ({ id: row.id, source: row.source }));
  return library;
}

export function observeWebsiteScripts(html, pageUrl, domain) {
  const root = String(domain || "").toLowerCase();
  let base;
  try { base = new URL(pageUrl); } catch { return null; }
  if (!root || !ownHost(base.hostname, root) || !["http:", "https:"].includes(base.protocol) || base.username || base.password) return null;
  const window = String(html || "").slice(0, SCRIPT_LIMITS.html_chars);
  const scripts = [];
  const result = { schema_version: "website_scripts.v1", domain: root, source_host: base.hostname,
    coverage: "bounded_html_window", chars_examined: window.length, advisory_data_version: JAVASCRIPT_ADVISORY_DATA.version,
    advisory_data_reviewed_at: JAVASCRIPT_ADVISORY_DATA.reviewed_at, supported_packages: ["jquery", "lodash"],
    relative_urls_with_base_omitted: false, scripts };
  // Use the shared traversal's quote-aware mode, including HTML raw-text/RCDATA
  // contexts. Validate ALL visited tags before accepting script facts; reject
  // long contexts that the bounded traversal could skip. Both passes are linear
  // within the existing HTML window. Legacy traversal callers keep their mode.
  let ambiguous = false, end = -1;
  for (let start = window.indexOf("<"); start !== -1; start = window.indexOf("<", start + 1)) {
    if (end < start) end = window.indexOf(">", start);
    if (end === -1) break;
    if (end - start > SCRIPT_LIMITS.tag_chars) { ambiguous = true; break; }
  }
  const traversal = ambiguous ? null : forEachTag(window, { has: () => true }, (name, tag) => {
    if (!attributes(tag, name)) { ambiguous = true; return false; }
    if (name === "base") result.relative_urls_with_base_omitted = true;
    return true;
  }, { quotedAttributes: true });
  if (traversal?.incomplete) ambiguous = true;
  if (ambiguous) return { ...result, coverage: "not_assessed", reason: "ambiguous_markup" };
  const hasBase = result.relative_urls_with_base_omitted;
  forEachTag(window, new Set(["script"]), (_name, tag) => {
    const attrs = attributes(tag, "script");
    const src = attrs?.get("src")?.trim();
    const type = attrs?.get("type")?.trim().toLowerCase();
    if (!src || src.length > 1024 || (type && !["module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"].includes(type))) return true;
    // An HTML base or character reference makes relative URL interpretation
    // ambiguous in this bounded window. Skip it, never invent a script host.
    if (hasBase && !/^(?:https?:)?\/\//i.test(src)) return true;
    if (/&(?:#|[a-z])/i.test(src.split("?")[0])) return true;
    let url;
    try { url = new URL(src, base); } catch { return true; }
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || !url.hostname) return true;
    scripts.push({ reference: scripts.length + 1, host: url.hostname.toLowerCase(),
      outside_domain: !ownHost(url.hostname, root), integrity_declared: Boolean(attrs.get("integrity")?.trim()),
      library: declaredLibrary(url.pathname) });
    return scripts.length < SCRIPT_LIMITS.scripts;
  }, { quotedAttributes: true });
  return result;
}

export function websiteScriptFindings(tech, { domain, verified = false } = {}) {
  const data = tech?.script_observations;
  if (verified !== true || tech?.error || tech?.incomplete || data?.schema_version !== "website_scripts.v1"
      || data.domain !== String(domain || "").toLowerCase() || !ownHost(data.source_host, data.domain)) return [];
  const scripts = (Array.isArray(data.scripts) ? data.scripts : []).slice(0, SCRIPT_LIMITS.scripts);
  const fact = (id, title, description, evidence) => ({ id, module: "technology_detection", severity: "info",
    finding_type: "observation", score_impact: 0, confidence: 75, title, description,
    evidence: evidence.map((value) => ({ type: "http_probe", value })) });
  const findings = [];
  const hosts = [...new Set(scripts.filter((row) => row.outside_domain === true).map((row) => row.host))];
  if (hosts.length) findings.push(fact("tech_script_host_observation", "External script hosts referenced",
    "The fetched HTML window referenced script hosts outside the verified domain. Host ownership, script execution and active service use were not established.", hosts));
  const missing = scripts.filter((row) => row.integrity_declared === false);
  if (missing.length) findings.push(fact("tech_script_integrity_observation", "Script references without integrity metadata",
    "These script elements had no nonempty integrity attribute in the fetched HTML window. Other references may exist outside this window; browser loading and integrity enforcement were not tested.",
    missing.map((row) => `Reference ${row.reference} on ${row.host}: no nonempty integrity attribute observed.`)));
  const matches = scripts.flatMap((row) => (row.library?.advisories || []).map((advisory) =>
    `${row.library.package} ${row.library.version} declared by reference ${row.reference} on ${row.host}: matches ${advisory.id} (${advisory.source}); bundled data ${data.advisory_data_version}.`));
  if (matches.length) findings.push(fact("tech_script_advisory_observation", "Declared script versions match public advisory ranges",
    "Script addresses declared versions within the bundled advisory ranges. File bytes, backported fixes, affected API use and exploitability were not checked; this is not a confirmed vulnerability or a complete advisory assessment.", matches));
  return findings;
}
