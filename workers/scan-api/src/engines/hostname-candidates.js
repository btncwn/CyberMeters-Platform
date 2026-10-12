// Pure hostname evidence extraction. No candidate asserts DNS or service state.
export const HOSTNAME_CANDIDATE_LIMITS = Object.freeze({
  maxCandidates: 200,
  maxInputBytes: 16_384,
  maxListItems: 500,
});

export const HOSTNAME_CANDIDATE_SOURCES = Object.freeze({
  liveTlsDnsNames: "live_tls_san",
  csp: "csp",
  linkedHostnames: "linked_hostnames",
  srvTargets: "srv",
  mxValues: "mx",
  nameservers: "ns",
});

const compare = (a, b) => a < b ? -1 : a > b ? 1 : 0;
const safeLimit = (value, fallback) => Number.isSafeInteger(value) && value >= 0
  ? Math.min(value, fallback) : fallback;

// Exported for the other pure discovery modules: accepts a hostname, not a URL.
export function normalizeHostname(value) {
  try {
    if (typeof value !== "string") return null;
    let name = value.trim();
    if (!name || name.length > 1_024 || /[\s\u0000-\u001f\u007f/\\:@?#%*\[\]]/u.test(name)) return null;
    // WHATWG URL applies the runtime's IDNA mapping, including Unicode dots.
    name = new URL(`http://${name}`).hostname.toLowerCase();
    if (name.endsWith(".")) name = name.slice(0, -1);
    if (!name || name.length > 253 || /^[0-9.]+$/.test(name)) return null;
    const labels = name.split(".");
    if (labels.some((label) => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) return null;
    return name;
  } catch { return null; }
}

// Out-of-scope results deliberately contain no hostname.
export function classifyHostname(value, domain) {
  try {
    const root = normalizeHostname(domain);
    if (!root || typeof value !== "string") return { kind: "rejected" };
    const raw = value.trim();
    const wildcard = raw.startsWith("*.");
    const hostname = normalizeHostname(wildcard ? raw.slice(2) : raw);
    if (!hostname) return { kind: "rejected" };
    if (!(hostname === root || hostname.endsWith("." + root))) return { kind: "out_of_scope" };
    if (wildcard) return { kind: "wildcard", scope: hostname };
    return hostname === root ? { kind: "root", hostname } : { kind: "candidate", hostname };
  } catch { return { kind: "rejected" }; }
}

export function exceedsUtf8Bytes(value, maxBytes) {
  if (typeof value !== "string") return false;
  // Avoid allocating an encoded copy of a plainly oversized string.
  return value.length > maxBytes || new TextEncoder().encode(value).length > maxBytes;
}

// A request-local accumulator, shared by all extractors. Nothing escapes except
// fresh result objects. truncated_count counts omitted input entries/whole
// oversized strings and distinct output names/scopes, never omitted bytes.
export function createCandidateCollector(options = {}) {
  const opts = options && typeof options === "object" ? options : {};
  const root = normalizeHostname(opts.domain);
  const observedAt = typeof opts.observedAt === "string" && opts.observedAt.length <= 128 ? opts.observedAt : null;
  const maxCandidates = safeLimit(opts.maxCandidates, HOSTNAME_CANDIDATE_LIMITS.maxCandidates);
  const maxInputBytes = Number.isSafeInteger(opts.maxInputBytes) && opts.maxInputBytes >= 0
    ? Math.min(opts.maxInputBytes, 262_144) : HOSTNAME_CANDIDATE_LIMITS.maxInputBytes;
  const names = new Map();
  const wildcards = new Set();
  let outOfScope = 0, rejected = 0, truncatedCount = 0;
  const count = (n) => Number.isSafeInteger(n) && n > 0 ? n : 0;
  const reject = (n = 1) => { rejected += count(n); };
  const truncate = (n = 1) => { truncatedCount += count(n); };
  return {
    reject,
    truncate,
    add(value, source) {
      if (!root) return;
      if (exceedsUtf8Bytes(value, maxInputBytes)) { truncate(); return; }
      const item = classifyHostname(value, root);
      if (item.kind === "out_of_scope") { outOfScope++; return; }
      if (item.kind === "rejected") { reject(); return; }
      if (item.kind === "root") return;
      if (item.kind === "wildcard") { wildcards.add(item.scope); return; }
      if (typeof source !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(source)) { reject(); return; }
      if (!names.has(item.hostname)) names.set(item.hostname, new Set());
      names.get(item.hostname).add(source);
    },
    result() {
      const sorted = [...names.keys()].sort(compare);
      const scopes = [...wildcards].sort(compare);
      const dropped = Math.max(0, sorted.length - maxCandidates) + Math.max(0, scopes.length - maxCandidates);
      return {
        version: "hostname-candidates-v1",
        root,
        observed_at: observedAt,
        candidates: sorted.slice(0, maxCandidates).map((hostname) => ({
          hostname, sources: [...names.get(hostname)].sort(compare),
        })),
        wildcard_scopes: scopes.slice(0, maxCandidates),
        out_of_scope_count: outOfScope,
        rejected_count: rejected,
        truncated: truncatedCount + dropped > 0,
        truncated_count: truncatedCount + dropped,
      };
    },
  };
}

const CSP_HOST_DIRECTIVES = new Set([
  "default-src", "child-src", "connect-src", "font-src", "frame-src", "img-src",
  "manifest-src", "media-src", "object-src", "script-src", "script-src-elem",
  "script-src-attr", "style-src", "style-src-elem", "style-src-attr", "worker-src",
  "base-uri", "form-action", "frame-ancestors", "navigate-to", "prefetch-src",
]);

function isCspHostSource(token) {
  // URL repairs malformed authorities; CSP host-source syntax must not.
  const form = /^(?:[a-z][a-z0-9+.-]*:\/\/)?([^/?#]+)(?:\/[^?#]*)?$/i.exec(token);
  if (!form || token.includes("\\")) return false;
  const authority = /^((?:\*\.)?[^:*]+)(?::(?:\*|[0-9]+))?$/.exec(form[1]);
  if (!authority) return false;
  const host = authority[1].startsWith("*.") ? authority[1].slice(2) : authority[1];
  return normalizeHostname(host) !== null;
}

function cspHostname(token) {
  if (!token || token.startsWith("'") || token === "*" || /^[a-z][a-z0-9+.-]*:$/i.test(token)) return null;
  if (/^(?:nonce-|sha(?:256|384|512)-|data:|blob:)/i.test(token)) return null;
  if (!isCspHostSource(token)) return null;
  try {
    const input = /^[a-z][a-z0-9+.-]*:\/\//i.test(token) ? token : `http://${token}`;
    // CSP permits a wildcard port; URL does not. It changes no hostname.
    const url = new URL(input.replace(/:\*(?=\/|$)/, ""));
    if (url.username || url.password || url.search || url.hash) return null;
    return url.hostname || null;
  } catch { return null; }
}

export function extractHostnameCandidates(input = {}) {
  try {
    if (!input || typeof input !== "object" || Array.isArray(input)) return createCandidateCollector().result();
    const { domain, observedAt, sources } = input;
    const collector = createCandidateCollector({ domain, observedAt });
    if (!normalizeHostname(domain) || !sources || typeof sources !== "object" || Array.isArray(sources)) return collector.result();
    const { maxInputBytes, maxListItems } = HOSTNAME_CANDIDATE_LIMITS;
    for (const key of ["liveTlsDnsNames", "linkedHostnames", "srvTargets", "mxValues", "nameservers"]) {
      const values = sources[key];
      if (values == null) continue;
      if (!Array.isArray(values)) { collector.reject(); continue; }
      collector.truncate(Math.max(0, values.length - maxListItems));
      for (const value of values.slice(0, maxListItems)) {
        if (exceedsUtf8Bytes(value, maxInputBytes)) { collector.truncate(); continue; }
        if (typeof value !== "string") { collector.reject(); continue; }
        const hostname = key === "mxValues" ? value.trim().replace(/^\d+\s+/, "") : value;
        if (key === "mxValues" && hostname === ".") continue;
        collector.add(hostname, HOSTNAME_CANDIDATE_SOURCES[key]);
      }
    }
    const csp = sources.csp;
    if (csp != null) {
      if (typeof csp !== "string") collector.reject();
      else if (exceedsUtf8Bytes(csp, maxInputBytes)) collector.truncate();
      else {
        let examined = 0;
        // A combined HTTP header can contain multiple policies, comma-separated.
        for (const directive of csp.split(/[;,]/)) {
          const [name, ...tokens] = directive.trim().split(/\s+/);
          if (!CSP_HOST_DIRECTIVES.has(name.toLowerCase())) continue;
          for (const token of tokens) {
            if (examined++ >= maxListItems) { collector.truncate(); continue; }
            const hostname = cspHostname(token);
            if (hostname !== null) collector.add(hostname, HOSTNAME_CANDIDATE_SOURCES.csp);
          }
        }
      }
    }
    return collector.result();
  } catch {
    // Malformed data, including exceptional property access, is never evidence.
    return createCandidateCollector().result();
  }
}
