// ── Asset evidence ───────────────────────────────────────────────────────────
// Why a name is in a workspace's inventory, kept as separate facts:
//
//   hints     — where the name was seen this scan: the certificate the site
//               serves, a DNS record, a header or page of the site, the
//               customer's own list, a word list or a name pattern. A hint is
//               never proof the name exists, belongs to the customer or serves
//               anything.
//   scope     — why the name falls inside a domain the workspace verified
//               (read from the workspace's own verification, never stored here).
//   dns       — what DNS said for each address family, and when.
//   service   — which protocol and port answered, and when.
//   findings  — which finding rests on which measurement.
//   not checked — what this scan did not check for the name, and why.
//
// Evidence is written per workspace and per scan, beside the lifecycle
// observation (asset_lifecycle_observations.source_detail_json), and per
// source on the asset row (workspace_assets.sightings_json). Nothing is
// back-filled: an asset recorded before this model says so. No URL query,
// fragment or path parameter, no token and no page body is kept; a page title
// is kept only when a finding rests on it, shortened.
import { normalizeHostname } from "./hostnames.js";
import { compactConfirmationDns, compactFamily } from "./dns-family-evidence.js";
import { REFERENCED_HOSTNAME_ASSET_SOURCES } from "./referenced-hostnames.js";
import { PAGE_REFERENCE_ASSET_SOURCES } from "./page-references.js";
import { CHECK_PACK_VERSION, describeCheckForFinding } from "./check-pack.js";

export const ASSET_EVIDENCE_VERSION = "asset-evidence-v1";
export const ASSET_SIGHTINGS_VERSION = "asset-sightings-v1";

export const ASSET_EVIDENCE_LIMITS = Object.freeze({
  findings: 10,
  titleChars: 80,
  observedChars: 160,
  sightingSources: 32,
  observationsRead: 10,
});

const GENERIC_DISCOVERY_SOURCE = "dns_discovery";
const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const text = (value, max) => (typeof value === "string" && value.trim() ? value.trim().slice(0, max) : null);

function rootOf(domain) {
  return normalizeHostname(domain);
}

function inScope(host, root) {
  return Boolean(host && root && (host === root || host.endsWith(`.${root}`)));
}

function hostsOfFinding(finding) {
  const raw = finding?.affected_hosts;
  const list = Array.isArray(raw) ? raw : typeof raw === "string" ? [raw] : [];
  return [...new Set(list.map((host) => normalizeHostname(host)).filter(Boolean))];
}

// ── A location without its secrets ──────────────────────────────────────────
// Scheme, host, port and path only: no query, fragment, user information or
// path parameters (";jsessionid=…"). Anything that does not parse is dropped.
export function safeLocation(value) {
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    const url = new URL(value.trim().includes("://") ? value.trim() : `https://${value.trim()}`);
    if (url.protocol !== "https:" && url.protocol !== "http:") return null;
    const path = url.pathname.split(";")[0] || "/";
    return `${url.protocol}//${url.host}${path}`.slice(0, 200);
  } catch {
    return null;
  }
}

function endpointOf(value) {
  try {
    const url = new URL(value);
    const protocol = url.protocol.replace(":", "");
    if (protocol !== "https" && protocol !== "http") return null;
    return {
      protocol,
      host: normalizeHostname(url.hostname),
      port: url.port ? Number(url.port) : protocol === "https" ? 443 : 80,
    };
  } catch {
    return null;
  }
}

// ── Hints: where each name was seen this scan ───────────────────────────────
/**
 * Every in-scope name this scan saw, with each place it was seen (asset
 * source codes). `listedHostnames` is the customer's list for this workspace
 * and domain; `referencedCandidates` is every configuration reference the scan
 * read ({hostname, sources}), including names another step had already found.
 * The generic discovery source is used only when nothing more specific named
 * a host.
 */
export function collectAssetHints(domain, modules, { listedHostnames = [], referencedCandidates = [] } = {}) {
  const root = rootOf(domain);
  const hints = new Map();
  const add = (host, source) => {
    const hostname = normalizeHostname(host);
    if (!inScope(hostname, root) || typeof source !== "string" || !source) return;
    if (!hints.has(hostname)) hints.set(hostname, new Set());
    hints.get(hostname).add(source);
  };
  if (root) add(root, "scan_root");
  const sub = modules?.subdomains || {};
  for (const item of modules?.dns_bruteforce?.items || []) {
    add(item?.hostname, item?.mail_only ? "dns_mx" : (typeof item?.source === "string" ? item.source : "dns_bruteforce"));
  }
  for (const item of modules?.dns_bruteforce?.srv_items || []) add(item?.hostname, "dns_srv");
  for (const candidate of Array.isArray(referencedCandidates) ? referencedCandidates : []) {
    for (const source of Array.isArray(candidate?.sources) ? candidate.sources : []) {
      add(candidate?.hostname, REFERENCED_HOSTNAME_ASSET_SOURCES[source]);
    }
  }
  for (const item of sub.referenced_hostnames?.confirmed || []) {
    add(item?.hostname, item?.asset_source);
    for (const source of Array.isArray(item?.sources) ? item.sources : []) add(item?.hostname, REFERENCED_HOSTNAME_ASSET_SOURCES[source]);
  }
  for (const host of Array.isArray(listedHostnames) ? listedHostnames : []) add(host, "customer_list");
  for (const item of sub.customer_hostnames?.confirmed || []) add(item?.hostname, item?.source);
  for (const item of sub.discovery_depth?.confirmed || []) add(item?.hostname, item?.source);
  for (const item of sub.page_references?.confirmed || []) add(item?.hostname, item?.asset_source);
  for (const candidate of modules?.page_discovery?.hostname_references?.candidates || []) {
    for (const source of Array.isArray(candidate?.sources) ? candidate.sources : []) {
      add(candidate?.hostname, PAGE_REFERENCE_ASSET_SOURCES[source]);
    }
  }
  for (const finding of modules?.cloud_storage_discovery?.findings || []) add(finding?.asset, "cloud_storage_discovery");
  for (const host of Array.isArray(sub.items) ? sub.items : []) {
    const hostname = normalizeHostname(host);
    if (hostname && !hints.has(hostname)) add(hostname, GENERIC_DISCOVERY_SOURCE);
  }
  return hints;
}

// The hints for an inventory row: its own name and every alias folded into it.
export function hintsForAsset(hints, hostname, aliases = []) {
  const sources = new Set();
  for (const name of [hostname, ...(Array.isArray(aliases) ? aliases : [])]) {
    for (const source of hints?.get?.(normalizeHostname(name)) || []) sources.add(source);
  }
  return [...sources].sort(compare);
}

// ── Sightings: first and last time each source named the asset ──────────────
function parseJson(value) {
  if (value && typeof value === "object") return value;
  try { return value ? JSON.parse(value) : null; } catch { return null; }
}

/**
 * The asset row's per-source sightings after this scan. `existing` is the
 * stored JSON (or null). Returns null when there is nothing to record and no
 * prior record, so a row recorded before this model stays untouched until a
 * source names it. Replaying a scan, or applying an older one late, never
 * moves a first sighting later or a last sighting earlier.
 */
export function mergeAssetSightings(existing, sources, { scanId = null, observedAt } = {}) {
  const prior = parseJson(existing);
  const valid = prior?.version === ASSET_SIGHTINGS_VERSION && prior.sources && typeof prior.sources === "object";
  const list = [...new Set((Array.isArray(sources) ? sources : [...(sources || [])]).filter((source) => typeof source === "string" && source))].sort(compare);
  if (list.length === 0 || typeof observedAt !== "string") return valid ? JSON.stringify(prior) : null;
  const next = {
    version: ASSET_SIGHTINGS_VERSION,
    recorded_since: valid && typeof prior.recorded_since === "string" && prior.recorded_since < observedAt ? prior.recorded_since : observedAt,
    sources: valid ? { ...prior.sources } : {},
  };
  for (const source of list) {
    const seen = next.sources[source];
    if (!seen && Object.keys(next.sources).length >= ASSET_EVIDENCE_LIMITS.sightingSources) continue;
    next.sources[source] = !seen
      ? { first_seen_at: observedAt, last_seen_at: observedAt, first_scan_id: scanId, last_scan_id: scanId }
      : {
        first_seen_at: seen.first_seen_at && seen.first_seen_at <= observedAt ? seen.first_seen_at : observedAt,
        first_scan_id: seen.first_seen_at && seen.first_seen_at <= observedAt ? seen.first_scan_id ?? null : scanId,
        last_seen_at: seen.last_seen_at && seen.last_seen_at >= observedAt ? seen.last_seen_at : observedAt,
        last_scan_id: seen.last_seen_at && seen.last_seen_at >= observedAt ? seen.last_scan_id ?? null : scanId,
      };
  }
  return JSON.stringify(next);
}

function rootDnsEvidence(dnsModule) {
  if (!dnsModule || typeof dnsModule !== "object") return null;
  const values = (records) => (Array.isArray(records) ? records : []).map((record) => record?.value).filter((value) => typeof value === "string");
  const assessed = dnsModule.resolution_assessed !== false;
  const family = (records) => {
    const addresses = values(records);
    return compactFamily({ outcome: addresses.length ? "answer" : assessed ? "no_address_recorded" : "unavailable", addresses });
  };
  return { source: "domain_lookup", A: family(dnsModule.a_records), AAAA: family(dnsModule.aaaa_records) };
}

// ── Service: which protocol and port answered ───────────────────────────────
const PROBE_FAILURES = new Set(["timeout", "connection_failed", "blocked", "not_run_budget", "dns_unavailable", "no_address", "redirect_unresolved"]);

function serviceFromProbe(asset) {
  if (!asset || typeof asset !== "object") return null;
  const attempts = (Array.isArray(asset.attempts) ? asset.attempts : [])
    .filter((attempt) => attempt && (attempt.protocol === "https" || attempt.protocol === "http"))
    .slice(0, 2)
    .map((attempt) => ({
      protocol: attempt.protocol,
      port: Number.isInteger(attempt.port) ? attempt.port : attempt.protocol === "https" ? 443 : 80,
      outcome: attempt.outcome === "responded" || PROBE_FAILURES.has(attempt.outcome) ? attempt.outcome : "connection_failed",
      ...(attempt.outcome === "responded" && Number.isInteger(attempt.status) ? { status: attempt.status } : {}),
      ...(attempt.ended_at ? { ended_at: attempt.ended_at } : {}),
    }));
  if (attempts.length === 0 && Number.isInteger(asset.status)) {
    // A result recorded without its attempts: the answer is real, the protocol
    // that carried it is not known.
    attempts.push({ protocol: null, port: null, outcome: "responded", status: asset.status });
  }
  if (attempts.length === 0) return null;
  return { source: "web_check", attempts, address_family: "not_recorded" };
}

function serviceFromHeaders(headers) {
  if (!headers || typeof headers !== "object") return null;
  const requested = endpointOf(headers.original_url);
  if (!requested) return null;
  const ended = endpointOf(headers.response_url);
  const responded = Number.isInteger(headers.status_code);
  const attempt = {
    protocol: requested.protocol,
    port: requested.port,
    outcome: responded ? "responded" : "connection_failed",
    ...(responded ? { status: headers.status_code } : {}),
    ...(responded && ended && (ended.host !== requested.host || ended.port !== requested.port || ended.protocol !== requested.protocol)
      ? { ended_at: ended } : {}),
  };
  return { source: "domain_check", attempts: [attempt], address_family: "not_recorded" };
}

// ── Findings and the measurement each rests on ─────────────────────────────
function measurementFor(finding, host, { exposure, admin, takeover }) {
  const type = String(finding?.id ?? "");
  if (type === "subdomain_takeover") {
    const risk = takeover.get(host);
    return risk
      ? { kind: "unclaimed_alias", alias_target: normalizeHostname(risk.cname) || null, provider: text(risk.provider ?? risk.service, 60) }
      : { kind: "not_recorded" };
  }
  const probe = exposure.get(host);
  const responded = (probe?.attempts || []).find((attempt) => attempt?.outcome === "responded");
  if (type.startsWith("admin_surface_")) {
    const service = admin.get(host);
    return {
      kind: "web_signature",
      product: text(service?.product, 60),
      signals: (Array.isArray(service?.evidence_signals) ? service.evidence_signals : []).filter((signal) => typeof signal === "string").slice(0, 3),
      protocol: responded?.protocol ?? null,
      port: responded?.port ?? null,
      status: Number.isInteger(probe?.status) ? probe.status : null,
    };
  }
  if (type.startsWith("asset_exposure_")) {
    return {
      kind: "web_response",
      protocol: responded?.protocol ?? null,
      port: responded?.port ?? null,
      status: Number.isInteger(probe?.status) ? probe.status : null,
      page_title: text(probe?.title, ASSET_EVIDENCE_LIMITS.titleChars),
    };
  }
  const evidence = finding?.evidence;
  if (evidence && typeof evidence === "object" && (evidence.observed_value || evidence.evidence_type)) {
    return {
      kind: text(evidence.evidence_type, 60) || "observation",
      observed: text(evidence.observed_value, ASSET_EVIDENCE_LIMITS.observedChars),
    };
  }
  return { kind: "not_recorded" };
}

function findingEvidence(finding, host, maps) {
  return {
    finding_type: String(finding?.id ?? "unknown"),
    title: text(finding?.title, 120),
    severity: typeof finding?.severity === "string" ? finding.severity : null,
    check_id: typeof finding?.check?.check_id === "string" ? finding.check.check_id : null,
    check_version: typeof finding?.check?.version === "string" ? finding.check.version : null,
    measured: measurementFor(finding, host, maps),
  };
}

// ── What this scan did not check ────────────────────────────────────────────
// Attempt outcomes that mean no request reached the name.
const NOT_REQUESTED = new Set(["not_run_budget", "dns_unavailable", "no_address", "blocked"]);
const NOT_REQUESTED_REASON = Object.freeze({
  not_run_budget: "request_budget",
  dns_unavailable: "dns_resolution_unavailable",
  no_address: "no_address",
  blocked: "blocked_address",
});

function notChecked({ dns, service, probe, root, host }) {
  const gaps = [];
  if (!dns) gaps.push({ part: "dns", reason: "not_checked_this_scan" });
  else if (dns.AAAA?.outcome === "not_asked") gaps.push({ part: "dns_ipv6", reason: dns.AAAA.reason || "not_asked" });
  const attempts = Array.isArray(service?.attempts) ? service.attempts : [];
  if (!service) {
    const reason = probe?.probe_status === "not_applicable" ? "no_address"
      : probe?.probe_status === "not_executed" ? (probe.reason === "dns_resolution_unavailable" ? "dns_resolution_unavailable" : "request_budget")
      : host === root ? "domain_check_not_recorded"
      : "not_in_this_scans_web_checks";
    gaps.push({ part: "service", reason });
  } else if (attempts.length > 0 && attempts.every((attempt) => NOT_REQUESTED.has(attempt.outcome))) {
    // The web check ran but never reached the name: nothing about the
    // service, or any finding that rests on it, was assessed.
    gaps.push({ part: "service", reason: NOT_REQUESTED_REASON[attempts[0].outcome] || "request_budget" });
  }
  if ((dns?.AAAA?.addresses || []).length > 0 && service) gaps.push({ part: "service_ipv6", reason: "address_family_not_recorded" });
  return gaps;
}

/**
 * This scan's evidence for every in-scope name it touched: hints, DNS per
 * family, service attempts, findings with their measurements and what was not
 * checked. Pure: reads the scan's modules and findings only.
 */
export function buildScanAssetEvidence({ domain, modules = {}, findings = [], hints = new Map() } = {}) {
  const root = rootOf(domain);
  const evidence = new Map();
  if (!root) return evidence;

  const dnsByHost = new Map();
  const keepDns = (host, dns) => {
    const hostname = normalizeHostname(host);
    if (inScope(hostname, root) && dns && !dnsByHost.has(hostname)) dnsByHost.set(hostname, dns);
  };
  const sub = modules?.subdomains || {};
  const confirmedLists = [
    modules?.dns_bruteforce?.items,
    sub.referenced_hostnames?.confirmed,
    sub.customer_hostnames?.confirmed,
    sub.discovery_depth?.confirmed,
    sub.page_references?.confirmed,
  ];
  for (const list of confirmedLists) {
    for (const item of Array.isArray(list) ? list : []) keepDns(item?.hostname, compactConfirmationDns(item?.dns, "discovery"));
  }
  for (const row of modules?.asset_exposure?.removal_observations || []) {
    if (row?.dns) keepDns(row.host, row.dns);
  }
  keepDns(root, rootDnsEvidence(modules?.dns));

  const exposure = new Map();
  for (const asset of modules?.asset_exposure?.assets || []) {
    const hostname = normalizeHostname(asset?.host || asset?.hostname);
    if (inScope(hostname, root) && !exposure.has(hostname)) exposure.set(hostname, asset);
  }
  const admin = new Map();
  for (const service of modules?.admin_surface_detection?.services || []) {
    const hostname = normalizeHostname(service?.hostname);
    if (hostname && service?.finding_type === "finding" && !admin.has(hostname)) admin.set(hostname, service);
  }
  const takeover = new Map((modules?.subdomain_takeover?.risks || [])
    .map((risk) => [normalizeHostname(risk?.host), risk]).filter(([hostname]) => Boolean(hostname)));

  const findingsByHost = new Map();
  for (const finding of Array.isArray(findings) ? findings : []) {
    for (const hostname of hostsOfFinding(finding)) {
      if (!inScope(hostname, root)) continue;
      if (!findingsByHost.has(hostname)) findingsByHost.set(hostname, []);
      findingsByHost.get(hostname).push(finding);
    }
  }

  const hosts = new Set([root, ...hints.keys(), ...dnsByHost.keys(), ...exposure.keys(), ...findingsByHost.keys()]);
  for (const host of hosts) {
    if (!inScope(host, root)) continue;
    const dns = dnsByHost.get(host) ?? null;
    const probe = exposure.get(host) ?? null;
    const service = host === root ? serviceFromHeaders(modules?.headers) : serviceFromProbe(probe);
    const hostFindings = (findingsByHost.get(host) || [])
      .slice(0, ASSET_EVIDENCE_LIMITS.findings)
      .map((finding) => findingEvidence(finding, host, { exposure, admin, takeover }));
    evidence.set(host, {
      version: ASSET_EVIDENCE_VERSION,
      named_by: [...(hints.get(host) || [])].sort(compare),
      dns,
      service,
      findings: hostFindings,
      ...((findingsByHost.get(host) || []).length > ASSET_EVIDENCE_LIMITS.findings
        ? { more_findings: findingsByHost.get(host).length - ASSET_EVIDENCE_LIMITS.findings } : {}),
      not_checked: notChecked({ dns, service, probe, root, host }),
    });
  }
  return evidence;
}

// An inventory name this scan did not touch at all.
export function evidenceNotCheckedThisScan() {
  return {
    version: ASSET_EVIDENCE_VERSION,
    named_by: [],
    dns: null,
    service: null,
    findings: [],
    not_checked: [
      { part: "dns", reason: "not_checked_this_scan" },
      { part: "service", reason: "not_in_this_scans_web_checks" },
    ],
  };
}

// ── Reading it back: the customer view ──────────────────────────────────────
const DNS_OUTCOME_LABELS = Object.freeze({
  answer: "Answered with an address",
  alias: "An alias (CNAME) with no address at its end",
  dangling_alias: "An alias (CNAME) to a name that does not exist",
  nxdomain: "No such name (NXDOMAIN)",
  nodata: "The name exists but has no address of this type",
  servfail: "The resolver failed (SERVFAIL); the answer is unknown",
  refused: "The resolver refused the question; the answer is unknown",
  timeout: "No answer in time; the answer is unknown",
  transport_error: "The resolver could not be reached; the answer is unknown",
  invalid: "The answer could not be read; the answer is unknown",
  not_asked: "Not asked",
  no_address_recorded: "No address recorded",
  unavailable: "The lookup did not complete; the answer is unknown",
});

const NOT_ASKED_REASONS = Object.freeze({
  budget: "the scan's DNS question budget was spent",
  time: "the scan's time limit was reached",
  name_does_not_exist: "the IPv4 answer said the name does not exist",
  wildcard_shaped: "the IPv4 answer matched the zone's catch-all answer",
});

const SERVICE_OUTCOME_LABELS = Object.freeze({
  responded: "Answered",
  timeout: "No answer in time; whether a service runs here is unknown",
  connection_failed: "The connection failed (refused, reset or a TLS error)",
  blocked: "Not requested: the name points at a private or reserved address",
  not_run_budget: "Not requested: the scan's request budget was spent",
  dns_unavailable: "Not requested: the address lookup failed",
  no_address: "Not requested: DNS says the name has no address",
  redirect_unresolved: "Redirected to a name whose address could not be found",
});

const GAP_LABELS = Object.freeze({
  "dns:not_checked_this_scan": "DNS was not asked about this name in this scan (it was neither found again nor in this scan's re-check set).",
  "dns_ipv6:budget": "The IPv6 (AAAA) question was not asked: the scan's DNS question budget was spent.",
  "dns_ipv6:time": "The IPv6 (AAAA) question was not asked: the scan's time limit was reached.",
  "dns_ipv6:name_does_not_exist": "The IPv6 (AAAA) question was not asked because the IPv4 answer said the name does not exist.",
  "dns_ipv6:wildcard_shaped": "The IPv6 (AAAA) question was not asked because the IPv4 answer matched the zone's catch-all answer.",
  "dns_ipv6:not_asked": "The IPv6 (AAAA) question was not asked.",
  "service:not_in_this_scans_web_checks": "No web request was made to this name in this scan (each scan checks a limited number of names; names checked least recently go first).",
  "service:no_address": "No web request was made: DNS says the name has no address.",
  "service:dns_resolution_unavailable": "No web request was made: the address lookup before it failed.",
  "service:request_budget": "No web request was made: the scan's request budget was spent.",
  "service:blocked_address": "No web request was made: the name points at a private or reserved address.",
  "service:domain_check_not_recorded": "The web check of the domain did not record which protocol answered.",
  "service_ipv6:address_family_not_recorded": "The name has IPv6 addresses, but the web check does not record which address family it connected over, so an answer is not proof the service works over IPv6.",
});

const STATIC_GAPS = Object.freeze([
  { part: "other_ports", label: "Only HTTPS (port 443) and HTTP (port 80) are requested. Other ports are not scanned without the owner's permission." },
]);
const NON_ROOT_GAPS = Object.freeze([
  { part: "certificate", label: "The certificate this name serves is not read: certificate checks cover the domain's own name on port 443." },
]);

const VERIFICATION_METHOD_LABELS = Object.freeze({
  dns_txt: "a DNS TXT record",
  html_file: "a file on the website",
});

function familyView(type, family) {
  if (!family) return null;
  const reason = family.outcome === "not_asked" && family.reason ? NOT_ASKED_REASONS[family.reason] : null;
  return {
    family: type === "A" ? "IPv4 (A)" : type === "AAAA" ? "IPv6 (AAAA)" : "Mail (MX)",
    outcome: family.outcome,
    label: `${DNS_OUTCOME_LABELS[family.outcome] ?? DNS_OUTCOME_LABELS.invalid}${reason ? `: ${reason}` : ""}`,
    values: type === "MX" ? (family.exchanges || []) : (family.addresses || []),
    ...(family.more_addresses ? { more_values: family.more_addresses } : {}),
  };
}

function dnsView(dns) {
  if (!dns) return null;
  const families = dns.MX && !dns.A
    ? [familyView("MX", dns.MX)]
    : [familyView("A", dns.A), familyView("AAAA", dns.AAAA)].filter(Boolean);
  return {
    families,
    alias_chain: Array.isArray(dns.alias_chain) ? dns.alias_chain : [],
    uncertain: Array.isArray(dns.uncertain) && dns.uncertain.length
      ? `One address family answered while the other ${dns.uncertain.length > 1 ? "did not" : "failed or disagreed"}; the address found is kept and the other family is unknown.`
      : null,
    asked_by: dns.source === "discovery" ? "Discovery" : dns.source === "web_check" ? "Re-check before the web request" : "Domain lookup",
  };
}

function serviceView(service) {
  if (!service) return null;
  const attempts = (service.attempts || []).map((attempt) => ({
    protocol: attempt.protocol ? attempt.protocol.toUpperCase() : null,
    port: attempt.port ?? null,
    outcome: attempt.outcome,
    status: attempt.status ?? null,
    label: attempt.outcome === "responded"
      ? `Answered${attempt.status != null ? ` with HTTP ${attempt.status}` : ""}${attempt.protocol ? "" : " (protocol not recorded)"}`
      : SERVICE_OUTCOME_LABELS[attempt.outcome] ?? SERVICE_OUTCOME_LABELS.connection_failed,
    ...(attempt.ended_at?.host ? {
      ended_at: `${String(attempt.ended_at.protocol || "").toUpperCase()} ${attempt.ended_at.host} port ${attempt.ended_at.port}`,
    } : {}),
  }));
  return {
    answered: attempts.some((attempt) => attempt.outcome === "responded"),
    attempts,
    address_family_note: "The web request does not record whether it connected over IPv4 or IPv6.",
  };
}

function measurementLabel(measured) {
  switch (measured?.kind) {
    case "web_response":
      return [
        measured.protocol ? `${measured.protocol.toUpperCase()}${measured.port ? ` port ${measured.port}` : ""}` : "A web request",
        measured.status != null ? `answered with HTTP ${measured.status}` : "answered",
        measured.page_title ? `and the page title "${measured.page_title}"` : null,
      ].filter(Boolean).join(" ");
    case "web_signature":
      return `${measured.product || "A known product"} recognised from ${(measured.signals || []).map((signal) => ({ product_title: "the page title", server_header: "the Server header", hostname: "the name" }[signal] || signal)).join(", ") || "the response"}${measured.status != null ? ` (HTTP ${measured.status})` : ""}`;
    case "unclaimed_alias":
      return `The alias points at ${measured.alias_target || "a provider name"}${measured.provider ? ` (${measured.provider})` : ""}, which answers that the resource is unclaimed`;
    case "not_recorded":
      return "Measured in this scan; the details are in the scan report.";
    default:
      return measured?.observed || "The measurement is in the scan report.";
  }
}

function findingView(finding) {
  const check = describeCheckForFinding({ id: finding.finding_type });
  return {
    finding_type: finding.finding_type,
    title: finding.title,
    severity: finding.severity,
    check_id: finding.check_id,
    check_version: finding.check_version,
    rule: check?.observation ? String(check.observation).slice(0, 400) : null,
    measured: finding.measured,
    measured_label: measurementLabel(finding.measured),
  };
}

function scopeView(asset, scopeRow) {
  const host = normalizeHostname(asset?.hostname);
  const domain = normalizeHostname(scopeRow?.domain);
  if (!scopeRow || !domain) {
    return { state: "unknown", domain: null, label: "The domain this name belongs to is not linked to this workspace any more. The name is kept for history." };
  }
  const relation = host === domain ? "domain_itself" : host && host.endsWith(`.${domain}`) ? "under_domain" : "outside_domain";
  const verified = scopeRow.verification_status === "verified";
  const method = VERIFICATION_METHOD_LABELS[scopeRow.verification_method] || null;
  const base = {
    domain,
    relation,
    verification_method: scopeRow.verification_method || null,
    verified_at: verified ? scopeRow.verified_at || null : null,
  };
  if (relation === "outside_domain") {
    return { ...base, state: "outside_domain", label: `Not under ${domain}. Seen as a related name; who owns it cannot be told from outside, so it is not treated as your asset.` };
  }
  if (!verified) {
    return { ...base, state: "domain_not_verified", label: `${relation === "domain_itself" ? "This is" : "Under"} ${domain}, whose verification in this workspace is not current. Scans resume once the domain is verified again.` };
  }
  return {
    ...base,
    state: "in_scope",
    label: `${relation === "domain_itself" ? "This is" : "Under"} ${domain}, which this workspace verified${method ? ` with ${method}` : ""}.`,
  };
}

function sightingsView(asset, sightingsJson) {
  const parsed = parseJson(sightingsJson);
  const valid = parsed?.version === ASSET_SIGHTINGS_VERSION && parsed.sources && typeof parsed.sources === "object";
  const sources = valid
    ? Object.entries(parsed.sources)
      .map(([source, seen]) => ({
        source,
        first_seen_at: seen?.first_seen_at ?? null,
        last_seen_at: seen?.last_seen_at ?? null,
      }))
      .sort((a, b) => compare(a.first_seen_at || "", b.first_seen_at || "") || compare(a.source, b.source))
    : [];
  const recordedSince = valid ? parsed.recorded_since ?? null : null;
  const fromStart = Boolean(recordedSince && asset?.first_seen && recordedSince <= asset.first_seen);
  return {
    status: !valid ? "not_recorded" : fromStart ? "recorded" : "recorded_since",
    recorded_since: recordedSince,
    first_source: typeof asset?.source === "string" ? asset.source : null,
    sources,
    note: !valid
      ? "Where this name was seen is recorded per source from its next scan. Until then only the source that first found it is known."
      : fromStart
      ? null
      : "Sources are recorded per source from the date shown. Before that, only the source that first found this name was kept.",
  };
}

function latestWith(rows, pick) {
  for (const row of rows) {
    const evidence = row.evidence;
    if (evidence && pick(evidence)) return row;
  }
  return null;
}

/**
 * The evidence for one asset of one workspace, for the asset detail view.
 * Three bounded reads: the workspace's domain link, the asset's sightings and
 * its latest lifecycle observations. Never throws.
 */
export async function loadAssetEvidence(env, workspaceId, asset) {
  const empty = (status, message) => ({ version: ASSET_EVIDENCE_VERSION, status, customer_message: message });
  if (!env?.cybermeters_db || !workspaceId || !asset?.id) {
    return empty("unavailable", "Evidence for this name could not be read.");
  }
  const db = env.cybermeters_db;
  try {
    const scopeRead = db.prepare(
      `SELECT d.domain, wd.verification_status, wd.verification_method, wd.verified_at
       FROM workspace_domains wd
       JOIN domains d ON d.id = wd.domain_id
       WHERE wd.workspace_id = ? AND wd.domain_id = ?`
    ).bind(workspaceId, asset.domain_id ?? null).first();
    const sightingsRead = db.prepare(
      "SELECT sightings_json FROM workspace_assets WHERE id = ? AND workspace_id = ?"
    ).bind(asset.id, workspaceId).first().catch((error) => {
      if (/no such column/i.test(String(error?.message || ""))) return null;
      throw error;
    });
    const observationsRead = db.prepare(
      `SELECT scan_id, observation_state, dns_state, http_state, source_detail_json, observed_at
       FROM asset_lifecycle_observations
       WHERE workspace_id = ? AND asset_id = ?
       ORDER BY observed_at DESC, created_at DESC
       LIMIT ?`
    ).bind(workspaceId, asset.id, ASSET_EVIDENCE_LIMITS.observationsRead).all().catch((error) => {
      if (/no such table/i.test(String(error?.message || ""))) return { results: [] };
      throw error;
    });
    const [scopeRow, sightingsRow, observations] = await Promise.all([scopeRead, sightingsRead, observationsRead]);

    const rows = (observations?.results || []).map((row) => {
      const detail = parseJson(row.source_detail_json);
      const evidence = detail?.evidence?.version === ASSET_EVIDENCE_VERSION ? detail.evidence : null;
      return { scan_id: row.scan_id, observed_at: row.observed_at, evidence };
    });
    const latest = rows[0] || null;
    const recorded = rows.some((row) => row.evidence);
    const dnsRow = latestWith(rows, (evidence) => Boolean(evidence.dns));
    const serviceRow = latestWith(rows, (evidence) => Boolean(evidence.service));
    const hintRow = latestWith(rows, (evidence) => (evidence.named_by || []).length > 0);
    const isRoot = normalizeHostname(asset.hostname) === normalizeHostname(scopeRow?.domain);
    const gaps = (latest?.evidence?.not_checked || [])
      .map((gap) => ({ part: gap.part, label: GAP_LABELS[`${gap.part}:${gap.reason}`] || null }))
      .filter((gap) => gap.label);

    return {
      version: ASSET_EVIDENCE_VERSION,
      check_pack_version: CHECK_PACK_VERSION,
      status: recorded ? "recorded" : "not_recorded",
      customer_message: recorded
        ? null
        : "This name was recorded before CyberMeters kept per-name evidence. DNS, web and finding evidence appear from the next scan that checks it.",
      latest_scan: latest ? { scan_id: latest.scan_id, observed_at: latest.observed_at, evidence_recorded: Boolean(latest.evidence) } : null,
      scope: scopeView(asset, scopeRow),
      seen_in: {
        ...sightingsView(asset, sightingsRow?.sightings_json ?? null),
        latest_scan_hints: hintRow ? { observed_at: hintRow.observed_at, sources: hintRow.evidence.named_by } : null,
      },
      dns: dnsRow
        ? { status: "checked", checked_at: dnsRow.observed_at, scan_id: dnsRow.scan_id, ...dnsView(dnsRow.evidence.dns) }
        : { status: recorded ? "not_checked" : "not_recorded", checked_at: null },
      service: serviceRow
        ? { status: "checked", checked_at: serviceRow.observed_at, scan_id: serviceRow.scan_id, ...serviceView(serviceRow.evidence.service) }
        : { status: recorded ? "not_checked" : "not_recorded", checked_at: null },
      findings: serviceRow || latest?.evidence
        ? {
          measured_at: (serviceRow ?? latest).observed_at,
          items: ((serviceRow ?? latest).evidence?.findings || []).map(findingView),
          more: (serviceRow ?? latest).evidence?.more_findings || 0,
        }
        : null,
      not_checked: recorded
        ? [...gaps, ...STATIC_GAPS, ...(isRoot ? [] : NON_ROOT_GAPS)]
        : [...STATIC_GAPS, ...(isRoot ? [] : NON_ROOT_GAPS)],
    };
  } catch {
    return empty("unavailable", "Evidence for this name could not be read.");
  }
}
