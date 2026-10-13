// A small, deterministic stand-in for the internet, for the discovery lab.
//
// One world holds a set of DNS zones, the web sites behind them and the
// certificate each site's root serves. It answers the scan engine's requests
// the way the real services would — DNS-over-HTTPS JSON with CNAME chains,
// wildcards, NXDOMAIN/NODATA/SERVFAIL/REFUSED and timeouts; HTTP responses and
// connection failures; the live-TLS collector's receipts — and records every
// request. Anything it was not told about fails closed and is recorded as
// unexpected, so no request can quietly reach the real network.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const DEFAULT_ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

export const DNS_RESOLVER_HOSTS = Object.freeze(["cloudflare-dns.com", "dns.google", "dns.quad9.net"]);

// Services that publish outside data about vulnerabilities or domain
// registrations. A scan's own measurement never needs them. Any other host the
// world does not know — a certificate-log search service included — is refused
// and recorded as unexpected.
export const OUTSIDE_DATA_HOST_PATTERNS = Object.freeze([
  { label: "nvd", test: (host) => host === "services.nvd.nist.gov" },
  { label: "epss", test: (host) => host === "api.first.org" },
  { label: "kev", test: (host) => host === "www.cisa.gov" || host === "cisa.gov" },
  { label: "rdap", test: (host) => host.startsWith("rdap.") || host.includes(".rdap.") },
  { label: "osv", test: (host) => host === "api.osv.dev" },
]);

export function outsideDataLabel(host) {
  return OUTSIDE_DATA_HOST_PATTERNS.find((pattern) => pattern.test(host))?.label ?? null;
}

const TYPE_CODES = Object.freeze({ A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, SRV: 33, DS: 43, RRSIG: 46, NSEC: 47, DNSKEY: 48, CAA: 257 });
const lower = (value) => String(value || "").toLowerCase().replace(/\.$/, "");
const fqdn = (value) => `${lower(value)}.`;

function timeoutError(message = "The operation timed out") {
  return new DOMException(message, "TimeoutError");
}

/**
 * world: {
 *   zones: { owner: { A, AAAA, CNAME, MX, NS, TXT, SRV, CAA } },   owner names are absolute
 *   wildcards: { parent: { A, AAAA, ... } },                       *.parent answers
 *   faults: { owner: { A: "servfail"|"refused"|"timeout"|"truncated", AAAA: ... , "*": ... } },
 *   sites: { host: { refuse?, timeout?, routes: { "/path": { status, headers, body } }, fallback } },
 *   tls: { host: { dnsNames, days, hostnameMatch, trust, identity, issuer } },
 *   outsideData: { nvd, epss, kev, rdap } canned bodies (used only when egress is open)
 * }
 * options.egress: "open" serves outside data hosts; "blocked" refuses them.
 * options.log: the request log to append to (a world that changes between
 * scans keeps one log across its versions).
 *
 * The email provider's send endpoint is stood in for as well: a message the
 * engine sends is recorded (recipients, subject, text) and accepted, so a lab
 * run can count and read every notification without a real send.
 */
export const EMAIL_PROVIDER_HOST = "api.resend.com";

export function createLabWorld(world, { egress = "open", root = DEFAULT_ROOT, log = [] } = {}) {
  const zones = new Map(Object.entries(world.zones || {}).map(([name, records]) => [lower(name), records]));
  const wildcards = new Map(Object.entries(world.wildcards || {}).map(([name, records]) => [lower(name), records]));
  const faults = new Map(Object.entries(world.faults || {}).map(([name, value]) => [lower(name), value]));
  const sites = new Map(Object.entries(world.sites || {}).map(([name, value]) => [lower(name), value]));
  let clock = () => Date.now();
  // Zone apexes the world is authoritative for.
  const apexes = [...zones.entries()].filter(([, records]) => records?.SOA).map(([name]) => name);

  // A name exists when it owns records or anything below it does (an empty
  // non-terminal), including the parent of a wildcard.
  const exists = (name) => zones.has(name) || wildcards.has(name)
    || [...zones.keys(), ...wildcards.keys()].some((owner) => owner.endsWith(`.${name}`));
  const wildcardFor = (name) => {
    // The closest enclosing wildcard, only where no real name exists (RFC 4592).
    if (exists(name)) return null;
    const labels = name.split(".");
    for (let i = 1; i < labels.length; i++) {
      const parent = labels.slice(i).join(".");
      if (wildcards.has(parent)) return wildcards.get(parent);
      if (exists(parent)) return null;
    }
    return null;
  };
  const recordsOf = (name) => zones.get(name) ?? wildcardFor(name);
  const soaFor = (name) => {
    const apex = [...zones.keys()].filter((owner) => zones.get(owner)?.SOA && (name === owner || name.endsWith(`.${owner}`)))
      .sort((a, b) => b.length - a.length)[0] ?? name.split(".").slice(-2).join(".");
    return { name: apex, type: TYPE_CODES.SOA, TTL: 300, data: `ns1.${apex}. hostmaster.${apex}. 1 7200 3600 1209600 300` };
  };
  const toData = (type, value) => {
    if (type === "CNAME" || type === "NS") return fqdn(value);
    if (type === "MX") { const [pref, host] = String(value).split(/\s+/); return `${pref} ${fqdn(host)}`; }
    if (type === "SRV") { const parts = String(value).split(/\s+/); return `${parts[0]} ${parts[1]} ${parts[2]} ${fqdn(parts[3])}`; }
    if (type === "TXT") return `"${value}"`;
    return String(value);
  };

  // Cloudflare's DoH JSON always carries the header flags; consumers check them.
  const packet = (body) => ({ Status: body.Status, TC: body.TC ?? false, RD: true, RA: true, AD: false, CD: false,
    Question: body.Question, ...(body.Answer ? { Answer: body.Answer } : {}), ...(body.Authority ? { Authority: body.Authority } : {}) });

  function answerDns(qname, qtype) {
    return packet(rawAnswer(qname, qtype));
  }

  function rawAnswer(qname, qtype) {
    const name = lower(qname);
    const fault = faults.get(name)?.[qtype] ?? faults.get(name)?.["*"];
    if (fault === "timeout") throw timeoutError();
    if (fault === "servfail") return { Status: 2, Question: [{ name, type: TYPE_CODES[qtype] ?? 0 }] };
    if (fault === "refused") return { Status: 5, Question: [{ name, type: TYPE_CODES[qtype] ?? 0 }] };
    if (fault === "truncated") return { Status: 0, TC: true, Question: [{ name, type: TYPE_CODES[qtype] ?? 0 }], Answer: [] };
    const answer = [];
    let owner = name;
    const seen = new Set();
    for (let hops = 0; hops < 20; hops++) {
      const records = recordsOf(owner);
      if (qtype !== "CNAME" && records?.CNAME) {
        answer.push({ name: owner, type: TYPE_CODES.CNAME, TTL: 300, data: toData("CNAME", records.CNAME) });
        if (seen.has(owner)) break;
        seen.add(owner);
        owner = lower(records.CNAME);
        if (seen.has(owner)) {
          // A loop: the resolver hands back what it collected and stops.
          return { Status: 2, Question: [{ name, type: TYPE_CODES[qtype] ?? 0 }], Answer: answer };
        }
        continue;
      }
      const values = records?.[qtype];
      if (Array.isArray(values) && values.length) {
        for (const value of values) answer.push({ name: owner, type: TYPE_CODES[qtype], TTL: 300, data: toData(qtype, value) });
        return { Status: 0, Question: [{ name, type: TYPE_CODES[qtype] }], Answer: answer };
      }
      if (typeof values === "string") {
        answer.push({ name: owner, type: TYPE_CODES[qtype], TTL: 300, data: toData(qtype, values) });
        return { Status: 0, Question: [{ name, type: TYPE_CODES[qtype] }], Answer: answer };
      }
      if (records || exists(owner)) {
        return { Status: 0, Question: [{ name, type: TYPE_CODES[qtype] ?? 0 }], Answer: answer, Authority: [soaFor(owner)] };
      }
      return { Status: 3, Question: [{ name, type: TYPE_CODES[qtype] ?? 0 }], Answer: answer, Authority: [soaFor(owner)] };
    }
    return { Status: 2, Question: [{ name, type: TYPE_CODES[qtype] ?? 0 }] };
  }

  // Addresses the name resolves to, following aliases; used for HTTP routing.
  function addressesOf(host) {
    const out = [];
    for (const type of ["A", "AAAA"]) {
      try {
        const response = answerDns(host, type);
        if (response.Status === 0) out.push(...(response.Answer || []).filter((r) => r.type === TYPE_CODES[type]).map((r) => r.data));
      } catch { /* timeouts resolve nothing */ }
    }
    return out;
  }

  const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
    status, headers: { "content-type": "application/json", ...headers },
  });

  function outsideData(label, url) {
    const canned = world.outsideData?.[label];
    if (label === "kev") return json(canned ?? { vulnerabilities: [] });
    if (label === "nvd") return json(canned ?? { vulnerabilities: [] });
    if (label === "epss") return json(canned ?? { data: [] });
    if (label === "rdap") return json(canned ?? {
      objectClassName: "domain",
      ldhName: url.pathname.split("/").pop(),
      events: [
        { eventAction: "registration", eventDate: "2019-03-01T00:00:00Z" },
        { eventAction: "expiration", eventDate: "2027-03-01T00:00:00Z" },
      ],
    }, 200, { "content-type": "application/rdap+json" });
    return json({});
  }

  // A real fetch() response knows the URL it came from; consumers check it.
  const at = (response, url) => { Object.defineProperty(response, "url", { value: url.toString() }); return response; };

  async function labFetch(input, init = {}) {
    const request = input instanceof Request ? input : null;
    const url = new URL(String(request ? request.url : input));
    return at(await route(url, request, init), url);
  }

  async function route(url, request, init) {
    const host = url.hostname.toLowerCase();
    const method = String(init.method || request?.method || "GET").toUpperCase();
    const entry = { at: clock(), host, method, path: url.pathname, kind: "other", outcome: null };
    log.push(entry);

    if (DNS_RESOLVER_HOSTS.includes(host)) {
      entry.kind = "dns";
      entry.resolver = host;
      entry.name = lower(url.searchParams.get("name"));
      entry.type = String(url.searchParams.get("type") || "A").toUpperCase();
      entry.dnssec = url.searchParams.get("do") === "1";
      try {
        const body = answerDns(entry.name, entry.type);
        entry.outcome = `rcode_${body.Status}`;
        return json(body, 200, { "content-type": "application/dns-json" });
      } catch (error) {
        entry.outcome = "timeout";
        throw error;
      }
    }

    if (host === EMAIL_PROVIDER_HOST && method === "POST" && url.pathname === "/emails") {
      entry.kind = "email";
      let message = null;
      try { message = JSON.parse(String(init.body ?? (request ? await request.text() : ""))); } catch { message = null; }
      entry.outcome = message ? "accepted" : "rejected";
      entry.email = message ? { to: message.to, subject: message.subject, text: message.text } : null;
      return message ? json({ id: `lab-email-${log.filter((e) => e.kind === "email").length}` }) : json({ name: "validation_error" }, 422);
    }

    const outside = outsideDataLabel(host);
    if (outside) {
      entry.kind = "outside_data";
      entry.service = outside;
      if (egress === "blocked") {
        entry.outcome = "blocked";
        throw new TypeError(`lab egress blocked: ${host}`);
      }
      entry.outcome = "served";
      return outsideData(outside, url);
    }

    const site = sites.get(host);
    const underLabZone = apexes.some((apex) => host === apex || host.endsWith(`.${apex}`));
    if (site || underLabZone || exists(host) || wildcardFor(host)) {
      entry.kind = "target";
      if (site?.timeout) { entry.outcome = "timeout"; throw timeoutError(); }
      if (addressesOf(host).length === 0) { entry.outcome = "no_address"; throw new TypeError("fetch failed: getaddrinfo ENOTFOUND"); }
      if (site?.refuse) { entry.outcome = "refused"; throw new TypeError("fetch failed: connection refused"); }
      const page = site?.routes?.[url.pathname] ?? site?.fallback ?? world.defaultSite ?? { status: 404, body: "" };
      const status = page.status ?? 200;
      entry.outcome = `http_${status}`;
      const body = method === "HEAD" || status === 204 || status === 304 ? null
        : typeof page.body === "function" ? page.body(url) : (page.body ?? "");
      if (typeof body === "string" && body.length > (world.maxBodyBytes ?? Infinity)) entry.oversized = true;
      return new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", ...(page.headers || {}) } });
    }

    entry.kind = "unexpected";
    entry.outcome = "refused";
    throw new TypeError(`lab: no route to ${host}`);
  }

  async function probeFetch(_url, init) {
    const { liveTlsReceipt } = await import(pathToFileURL(path.join(root, "scripts", "lib", "live-tls-fixture.mjs")).href);
    const request = JSON.parse(init.body);
    const hostname = request.targets?.[0]?.hostname;
    log.push({ at: clock(), host: "network-probe.internal", kind: "probe", method: "POST", path: "/collect", profile: request.profile, name: hostname, outcome: null });
    const tls = world.tls?.[lower(hostname)];
    const now = new Date(clock()).toISOString();
    const base = {
      request_id: request.request_id, workspace_id: request.workspace_id, scan_id: request.scan_id,
      profile: request.profile, started_at: now,
    };
    if (!tls) {
      log.at(-1).outcome = "not_served";
      return Response.json({
        ...liveTlsReceipt({ domain: hostname, finishedAt: now }),
        ...base,
        coverage: { planned: 1, attempted: 1, completed: 0, not_run: 0 },
        quality: "partial",
        observations: [{ address: addressesOf(hostname)[0] ?? "34.120.0.1", hostname, port: 443, transport: "tcp", state: "closed", service: null, tls: null, reason: "connection_refused" }],
        limitations: ["Lab: no TLS service on this name."],
      });
    }
    log.at(-1).outcome = "served";
    const address = addressesOf(hostname).find((value) => !value.includes(":")) ?? addressesOf(hostname)[0];
    return Response.json({ ...liveTlsReceipt({ domain: hostname, finishedAt: now, address, ...tls }), ...base });
  }

  return {
    fetch: labFetch,
    probe: { fetch: probeFetch },
    log,
    setClock(fn) { clock = fn; },
    answerDns,
  };
}

// Group a request log into counts a person can read.
export function summarizeRequests(log) {
  const byKind = {}, byHost = {}, dnsByType = {}, outside = {};
  let dnsQuestions = 0;
  for (const entry of log) {
    byKind[entry.kind] = (byKind[entry.kind] || 0) + 1;
    byHost[entry.host] = (byHost[entry.host] || 0) + 1;
    if (entry.kind === "dns") {
      dnsQuestions++;
      dnsByType[entry.type] = (dnsByType[entry.type] || 0) + 1;
    }
    if (entry.kind === "outside_data") outside[entry.service] = (outside[entry.service] || 0) + 1;
  }
  return { total: log.length, by_kind: byKind, by_host: byHost, dns_questions: dnsQuestions, dns_by_type: dnsByType, outside_data: outside };
}
