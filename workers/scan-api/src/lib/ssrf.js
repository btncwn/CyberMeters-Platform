// ── SSRF guard for outbound scan fetches ──
// The scanner only ever fetches PUBLIC customer assets. A private/reserved
// target is therefore always either a redirect-time misdirect (a public domain
// that 302s to an internal address) or a public domain whose A record points at
// an internal IP. Cloudflare's egress does not route RFC1918 in practice, but
// per project policy (scripts/validate-ssrf-domain-guard.js) the app must not
// rely on the runtime alone — this is that app-layer control, applied per hop.

// True if a hostname is a loopback / private / link-local / reserved literal, or
// an obviously non-public single-label / .local / .internal name. Accepts either
// a hostname or a bare IP literal (used to vet resolved addresses too).
export function hostIsPrivateOrReserved(hostname) {
  const host = String(hostname || "").trim().toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  if (!host) return true;
  if (host === "localhost" || host.endsWith(".localhost") ||
      host.endsWith(".local") || host.endsWith(".internal")) return true;
  // No dot and no colon → single-label internal name or a decimal-encoded IPv4
  // (e.g. 2130706433 == 127.0.0.1). Public hosts always have a dot.
  if (!host.includes(".") && !host.includes(":")) return true;
  // IPv4 loopback / private / link-local / "this network" (0.0.0.0/8) / CGNAT
  // (100.64.0.0/10) ranges.
  if (/^(0\.|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(host)) return true;
  // IPv4 multicast (224.0.0.0/4) and reserved/broadcast (240.0.0.0/4, 255.*): never
  // a public unicast asset, so never a legitimate scan target.
  if (/^(22[4-9]|23\d|24\d|25[0-5])\./.test(host)) return true;
  // IPv4-mapped IPv6 — an attacker can encode a prohibited v4 address as
  // ::ffff:169.254.169.254 (dotted) or ::ffff:a9fe:a9fe (hex). Decode and re-vet the
  // embedded IPv4 so the mapping cannot smuggle a private/reserved target past the
  // IPv4 gate above.
  const v4mappedDotted = host.match(/^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i);
  if (v4mappedDotted) return hostIsPrivateOrReserved(v4mappedDotted[1]);
  const v4mappedHex = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (v4mappedHex) {
    const hi = parseInt(v4mappedHex[1], 16), lo = parseInt(v4mappedHex[2], 16);
    return hostIsPrivateOrReserved(`${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`);
  }
  // IPv6 loopback (::1), unspecified (::), ULA (fc00::/7 → fc/fd), link-local
  // (fe80::/10 → first hextet fe80–febf).
  if (host === "::1" || host === "::" || /^f[cd][0-9a-f]*:/i.test(host) || /^fe[89ab][0-9a-f]:/i.test(host)) return true;
  return false;
}

// True if the URL is unfetchable-by-policy: non-http(s), embeds credentials,
// malformed, or targets a private/reserved host.
export function urlIsBlockedTarget(rawUrl) {
  let u;
  try { u = new URL(rawUrl); } catch { return true; }
  if (u.protocol !== "http:" && u.protocol !== "https:") return true;
  if (u.username || u.password) return true;
  return hostIsPrivateOrReserved(u.hostname);
}

// Resolves a domain (A + AAAA) and returns true if ANY answer is a private/
// reserved IP — the durable check for a public domain pointed at an internal
// address (the string gate never resolves DNS). Fails OPEN on resolver error:
// the per-hop literal guard + Cloudflare egress backstop still apply, and a
// flaky DoH lookup must never block a legitimate scan.
export async function resolvesToPrivateIp(domain, dnsQuery) {
  if (typeof dnsQuery !== "function") return false;
  try {
    const results = await Promise.allSettled([dnsQuery(domain, "A"), dnsQuery(domain, "AAAA")]);
    for (const r of results) {
      if (r.status !== "fulfilled") continue;
      for (const ans of (r.value?.Answer || [])) {
        const ip = String(ans?.data || "").trim();
        if (ip && hostIsPrivateOrReserved(ip)) return true;
      }
    }
  } catch { /* fail open */ }
  return false;
}

// Strict outbound resolution is deliberately ADDITIVE. The legacy
// resolvesToPrivateIp helper above remains fail-open for its existing caller;
// security-sensitive sinks opt into this tri-state contract instead.
export const STRICT_DNS_STATES = Object.freeze({
  PUBLIC: "public",
  BLOCKED: "blocked",
  UNAVAILABLE: "unavailable",
});

// Budget/deadline/cancellation errors are control-flow, not evidence that a
// target is safe or merely unreachable. Shared fetch callers must be able to
// observe them so the scan engine can publish an honest incomplete outcome.
export function isOutboundControlError(error) {
  const name = String(error?.name || "");
  const code = String(error?.code || "");
  return error?.subrequestLimit === true
    || code === "scan_subrequest_budget_exhausted"
    || code === "scan_deadline_exhausted"
    || code === "module_budget_exhausted"
    || name === "AbortError"
    || name === "TimeoutError";
}

function parseIpv4(value) {
  const raw = String(value || "").trim();
  const parts = raw.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) return null;
  const bytes = parts.map(Number);
  if (bytes.some((byte) => byte < 0 || byte > 255)) return null;
  return bytes;
}

function ipv4IsPublic(bytes) {
  if (!bytes) return false;
  const [a, b, c] = bytes;
  return !(
    a === 0
    || a === 10
    || a === 127
    || (a === 100 && b >= 64 && b <= 127)
    || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 0 && c === 0)
    || (a === 192 && b === 0 && c === 2)
    || (a === 192 && b === 88 && c === 99)
    || (a === 192 && b === 168)
    || (a === 198 && (b === 18 || b === 19))
    || (a === 198 && b === 51 && c === 100)
    || (a === 203 && b === 0 && c === 113)
    || a >= 224
  );
}

function parseIpv6Part(part) {
  if (!part) return [];
  const tokens = part.split(":");
  const words = [];
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index];
    if (!token) return null;
    if (token.includes(".")) {
      if (index !== tokens.length - 1) return null;
      const v4 = parseIpv4(token);
      if (!v4) return null;
      words.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      continue;
    }
    if (!/^[0-9a-f]{1,4}$/i.test(token)) return null;
    words.push(parseInt(token, 16));
  }
  return words;
}

function parseIpv6(value) {
  const raw = String(value || "").trim().toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  if (!raw || raw.includes("%") || (raw.match(/::/g) || []).length > 1) return null;
  const compressed = raw.includes("::");
  const [leftRaw, rightRaw = ""] = compressed ? raw.split("::") : [raw, ""];
  const left = parseIpv6Part(leftRaw);
  const right = parseIpv6Part(rightRaw);
  if (!left || !right) return null;
  if (!compressed && left.length !== 8) return null;
  if (compressed && left.length + right.length >= 8) return null;
  const words = compressed
    ? [...left, ...Array(8 - left.length - right.length).fill(0), ...right]
    : left;
  if (words.length !== 8) return null;
  return words.flatMap((word) => [(word >> 8) & 0xff, word & 0xff]);
}

function ipv6Range(prefix, bits, { embeddedIpv4 = false } = {}) {
  return Object.freeze({ bytes: parseIpv6(prefix), bits, embeddedIpv4 });
}

function ipv6MatchesRange(bytes, range) {
  if (!bytes || !range?.bytes || bytes.length !== range.bytes.length) return false;
  const completeBytes = Math.floor(range.bits / 8);
  for (let index = 0; index < completeBytes; index += 1) {
    if (bytes[index] !== range.bytes[index]) return false;
  }
  const remainingBits = range.bits % 8;
  if (remainingBits === 0) return true;
  const mask = (0xff << (8 - remainingBits)) & 0xff;
  return (bytes[completeBytes] & mask) === (range.bytes[completeBytes] & mask);
}

// IANA IPv6 Special-Purpose Address Registry, updated 2025-10-09. The broad
// 2001::/23 protocol-assignment parent is NOT globally reachable unless a more
// specific registered allocation explicitly says it is. N/A/blank registry
// reachability remains denied; this boundary admits only a positive True.
const IANA_GLOBALLY_REACHABLE_IPV6 = Object.freeze([
  ipv6Range("64:ff9b::", 96, { embeddedIpv4: true }),
  ipv6Range("2001:1::1", 128),
  ipv6Range("2001:1::2", 128),
  ipv6Range("2001:1::3", 128),
  ipv6Range("2001:3::", 32),
  ipv6Range("2001:4:112::", 48),
  ipv6Range("2001:20::", 28),
  ipv6Range("2001:30::", 28),
  ipv6Range("2620:4f:8000::", 48),
]);

const IANA_NON_GLOBALLY_REACHABLE_IPV6_IN_2000_3 = Object.freeze([
  ipv6Range("2001::", 23),
  ipv6Range("2001:db8::", 32),
  ipv6Range("2002::", 16),
  ipv6Range("3fff::", 20),
]);

function ipv6IsPublic(bytes) {
  if (!bytes) return false;
  for (const range of IANA_GLOBALLY_REACHABLE_IPV6) {
    if (!ipv6MatchesRange(bytes, range)) continue;
    // The RFC 6052 well-known prefix carries an IPv4 destination. A globally
    // reachable prefix must not turn an embedded private IPv4 into a public one.
    return !range.embeddedIpv4 || ipv4IsPublic(bytes.slice(12, 16));
  }
  if (IANA_NON_GLOBALLY_REACHABLE_IPV6_IN_2000_3.some((range) =>
    ipv6MatchesRange(bytes, range))) return false;
  // Ordinary IPv6 global unicast is 2000::/3. All other special-purpose space
  // defaults denied unless explicitly admitted above by the current registry.
  return (bytes[0] & 0xe0) === 0x20;
}

function parseIp(value) {
  const raw = String(value || "").trim().replace(/^\[/, "").replace(/\]$/, "");
  const v4 = parseIpv4(raw);
  if (v4) return { family: "A", bytes: v4, public: ipv4IsPublic(v4) };
  const v6 = raw.includes(":") ? parseIpv6(raw) : null;
  if (v6) return { family: "AAAA", bytes: v6, public: ipv6IsPublic(v6) };
  return null;
}

function validCname(value) {
  const raw = String(value || "").trim().replace(/\.$/, "");
  if (!raw || raw.length > 253 || !raw.includes(".")) return false;
  return raw.split(".").every((label) =>
    label.length >= 1 && label.length <= 63
      && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
}

function inspectDnsPacket(packet, family) {
  if (!packet || typeof packet !== "object" || Array.isArray(packet)) {
    return { ok: false, reason: "malformed_answer", addresses: [] };
  }
  if (!Number.isInteger(packet.Status) || packet.Status !== 0
      || packet.TC === true || !Array.isArray(packet.Answer)) {
    return { ok: false, reason: "incomplete_answer", addresses: [] };
  }
  const expectedType = family === "AAAA" ? 28 : 1;
  const addresses = [];
  // A successful empty answer is authoritative NODATA for this family. It is
  // safe only when the sibling family supplies at least one public terminal;
  // the caller keeps both-families-empty fail-closed.
  if (packet.Answer.length === 0) {
    return { ok: true, reason: null, nodata: true, addresses: [] };
  }
  for (const answer of packet.Answer) {
    if (!answer || typeof answer !== "object" || !Number.isInteger(answer.type)
        || typeof answer.data !== "string") {
      return { ok: false, reason: "malformed_answer", addresses: [] };
    }
    if (answer.type === 5) {
      if (!validCname(answer.data)) return { ok: false, reason: "malformed_answer", addresses: [] };
      continue;
    }
    if (answer.type !== expectedType) {
      return { ok: false, reason: "malformed_answer", addresses: [] };
    }
    const parsed = parseIp(answer.data);
    if (!parsed || parsed.family !== family) {
      return { ok: false, reason: "malformed_answer", addresses: [] };
    }
    addresses.push({ value: String(answer.data).trim(), public: parsed.public });
  }
  if (addresses.length === 0) {
    return { ok: false, reason: "no_terminal_address", addresses: [] };
  }
  return { ok: true, reason: null, nodata: false, addresses };
}

// Resolve both address families and classify the target without ever treating
// uncertainty as public. Each family needs a valid DNS response; one family may
// be authoritative NODATA when the sibling has a public terminal. Every terminal
// address must be globally public, and both-families-NODATA remains unavailable.
export async function resolvePublicDnsTarget(domain, dnsQuery, opts = {}) {
  const host = String(domain || "").trim().toLowerCase().replace(/^\[/, "").replace(/\]$/, "");
  const literal = parseIp(host);
  if (literal) {
    return literal.public
      ? { state: STRICT_DNS_STATES.PUBLIC, reason: null, literal: true, addresses: [host] }
      : { state: STRICT_DNS_STATES.BLOCKED, reason: "private_or_reserved_literal", literal: true, addresses: [host] };
  }
  if (typeof dnsQuery !== "function") {
    return { state: STRICT_DNS_STATES.UNAVAILABLE, reason: "resolver_missing", literal: false, addresses: [] };
  }

  const settled = await Promise.allSettled([
    dnsQuery(host, "A", { cache: opts.cache, accounting: opts.accounting, signal: opts.signal }),
    dnsQuery(host, "AAAA", { cache: opts.cache, accounting: opts.accounting, signal: opts.signal }),
  ]);
  const controlError = settled.find((result) =>
    result.status === "rejected" && isOutboundControlError(result.reason));
  if (controlError) throw controlError.reason;

  // Inspect fulfilled evidence before collapsing an ordinary sibling rejection.
  // A definitive private/reserved terminal remains a block with provenance in
  // either family order, while typed control errors above still dominate.
  const a = settled[0].status === "fulfilled"
    ? inspectDnsPacket(settled[0].value, "A")
    : { ok: false, reason: "resolver_error", addresses: [] };
  const aaaa = settled[1].status === "fulfilled"
    ? inspectDnsPacket(settled[1].value, "AAAA")
    : { ok: false, reason: "resolver_error", addresses: [] };
  const knownAddresses = [...a.addresses, ...aaaa.addresses];
  // A known private/reserved terminal is a definitive block even if the other
  // family is also unavailable. Uncertainty must never dilute known bad evidence.
  if (knownAddresses.some((address) => !address.public)) {
    return {
      state: STRICT_DNS_STATES.BLOCKED,
      reason: "private_or_reserved_address",
      literal: false,
      addresses: knownAddresses.map((address) => address.value),
    };
  }
  if (settled.some((result) => result.status === "rejected")) {
    return { state: STRICT_DNS_STATES.UNAVAILABLE, reason: "resolver_error", literal: false, addresses: [] };
  }
  if (!a.ok || !aaaa.ok) {
    return {
      state: STRICT_DNS_STATES.UNAVAILABLE,
      reason: !a.ok ? a.reason : aaaa.reason,
      literal: false,
      addresses: [],
    };
  }
  if (knownAddresses.length === 0) {
    return {
      state: STRICT_DNS_STATES.UNAVAILABLE,
      reason: "no_terminal_address",
      literal: false,
      addresses: [],
    };
  }
  return {
    state: STRICT_DNS_STATES.PUBLIC,
    reason: null,
    literal: false,
    addresses: knownAddresses.map((address) => address.value),
  };
}
