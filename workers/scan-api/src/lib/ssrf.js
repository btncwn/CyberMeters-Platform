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
  // IPv4 loopback / private / link-local / "this network" (0.0.0.0/8) ranges.
  if (/^(0\.|127\.|10\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host)) return true;
  // IPv6 loopback (::1), unspecified (::), ULA (fc00::/7 → fc/fd), link-local (fe80::/10).
  if (host === "::1" || host === "::" || /^f[cd][0-9a-f]*:/i.test(host) || /^fe80:/i.test(host)) return true;
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
