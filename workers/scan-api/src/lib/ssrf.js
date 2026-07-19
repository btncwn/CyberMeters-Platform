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
