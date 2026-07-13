#!/usr/bin/env node
//
// Reserved prober SSRF + redirect matrix (Tier-1 Commit 3).
//
// Proves makeReservedProbeFetch follows redirects safely: http(s) only, no creds,
// per-hop revalidation with the CANONICAL validator (urlIsBlockedTarget +
// resolvesToPrivateIp), hard hop cap, and a DNS-rebinding guard. Blocked targets are
// NEVER fetched. Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const { makeReservedProbeFetch, RESERVED_MAX_REDIRECT_HOPS } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "reserved-probe.js")).href);

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);
const realFetch = globalThis.fetch;

const isDoh = (u) => /cloudflare-dns\.com|dns\.google|dns\.quad9\.net/.test(u);
const redirect = (loc) => new Response(null, { status: 302, headers: loc ? { location: loc } : {} });
const okResp = () => new Response("<title>x</title>", { status: 200, headers: { "content-type": "text/html" } });

// Build a scripted environment. dohMap: hostname → { A:[ips], AAAA:[ips] }; probeMap:
// url → Response (or a function). Records every non-DoH (probe) URL actually fetched.
function scripted({ dohDefaultA = ["93.184.216.34"], dohMap = {}, probe }) {
  const probeFetches = [];
  globalThis.fetch = async (url) => {
    const s = String(url);
    if (isDoh(s)) {
      const u = new URL(s); const name = u.searchParams.get("name"); const type = u.searchParams.get("type");
      const entry = dohMap[name];
      const ips = entry ? (entry[type] || []) : (type === "A" ? dohDefaultA : []);
      return new Response(JSON.stringify({ Answer: ips.map((ip) => ({ data: ip })) }), { status: 200, headers: { "content-type": "application/dns-json" } });
    }
    probeFetches.push(s);
    return probe(s);
  };
  return probeFetches;
}
const fetcher = () => makeReservedProbeFetch({ cache: null, maxHops: RESERVED_MAX_REDIRECT_HOPS, timeoutMs: 2000 });

// ── 1. relative redirect (same host) ─────────────────────────────────────────
{
  scripted({ probe: (u) => u.endsWith("/next") ? okResp() : redirect("/next") });
  const r = await fetcher()("https://a.example.com/");
  ok("relative redirect followed to 200", r && r.status === 200);
}
// ── 2. absolute same-host redirect ───────────────────────────────────────────
{
  scripted({ probe: (u) => u === "https://a.example.com/x" ? okResp() : redirect("https://a.example.com/x") });
  const r = await fetcher()("https://a.example.com/");
  ok("absolute same-host redirect followed", r && r.status === 200);
}
// ── 3. cross-host public redirect ────────────────────────────────────────────
{
  const probes = scripted({ probe: (u) => u.startsWith("https://b.example.com") ? okResp() : redirect("https://b.example.com/") });
  const r = await fetcher()("https://a.example.com/");
  ok("cross-host public redirect followed", r && r.status === 200);
  ok("cross-host target was fetched", probes.some((u) => u.startsWith("https://b.example.com")));
}
// ── 4. missing Location → return the 3xx ─────────────────────────────────────
{
  scripted({ probe: () => redirect(null) });
  const r = await fetcher()("https://a.example.com/");
  ok("missing Location → returns the 3xx (no follow)", r && r.status === 302);
}
// ── 5. redirect loop → capped ────────────────────────────────────────────────
{
  const probes = scripted({ probe: () => redirect("https://a.example.com/loop") });
  const r = await fetcher()("https://a.example.com/");
  ok("redirect loop is bounded (returns a 3xx, no hang)", r && r.status === 302);
  ok("loop bounded to <= maxHops+1 fetches", probes.length <= RESERVED_MAX_REDIRECT_HOPS + 1, `fetches ${probes.length}`);
}
// ── 6. three-hop success ─────────────────────────────────────────────────────
{
  let n = 0;
  scripted({ probe: () => (++n <= 3 ? redirect(`https://a.example.com/${n}`) : okResp()) });
  const r = await fetcher()("https://a.example.com/");
  ok("three redirects then 200", r && r.status === 200);
}
// ── 7. fourth-hop capped ─────────────────────────────────────────────────────
{
  scripted({ probe: (u) => redirect(u + "/r") }); // always redirects
  const r = await fetcher()("https://a.example.com/");
  eq("fourth hop capped → returns a 3xx", r && r.status, 302);
}
// ── 8. HTTPS→HTTP downgrade to a public host (http allowed) ───────────────────
{
  const probes = scripted({ probe: (u) => u.startsWith("http://a.example.com") && !u.startsWith("https") ? okResp() : redirect("http://a.example.com/") });
  const r = await fetcher()("https://a.example.com/");
  ok("HTTPS→HTTP public downgrade followed (http scheme allowed)", r && r.status === 200);
  ok("downgraded http URL was fetched", probes.some((u) => u.startsWith("http://a.example.com")));
}

// ── 9–13. blocked redirect targets must NEVER be fetched ──────────────────────
const blockedTargets = [
  ["127.0.0.1 loopback", "http://127.0.0.1/"],
  ["RFC1918", "http://10.0.0.5/"],
  ["169.254.169.254 metadata", "http://169.254.169.254/latest/meta-data/"],
  ["IPv6 loopback", "http://[::1]/"],
  ["IPv6 link-local", "http://[fe80::1]/"],
];
for (const [label, target] of blockedTargets) {
  const probes = scripted({ probe: (u) => u === "https://a.example.com/" ? redirect(target) : okResp() });
  const r = await fetcher()("https://a.example.com/");
  ok(`redirect to ${label} refused (null result)`, r === null, `status ${r && r.status}`);
  ok(`redirect to ${label} target NEVER fetched`, !probes.some((u) => u.startsWith(target.replace(/\/$/, "").replace(/\/latest.*/, "").slice(0, 20))) && !probes.includes(target));
}

// ── 14. DNS rebinding: public hostname resolving to a private IP ──────────────
{
  const probes = scripted({
    dohMap: { "rebind.example.com": { A: ["10.0.0.9"] }, "a.example.com": { A: ["93.184.216.34"] } },
    probe: (u) => u === "https://a.example.com/" ? redirect("https://rebind.example.com/") : okResp(),
  });
  const r = await fetcher()("https://a.example.com/");
  ok("DNS-rebinding target (public host → private IP) refused", r === null);
  ok("DNS-rebinding target NEVER fetched (only resolved)", !probes.some((u) => u.startsWith("https://rebind.example.com")));
}

// ── 15. credentials + non-http scheme rejected at the origin ──────────────────
{
  const probes = scripted({ probe: () => okResp() });
  ok("credentialed URL refused", (await fetcher()("https://user:pass@a.example.com/")) === null);
  ok("credentialed URL never fetched", probes.length === 0);
}
{
  const probes = scripted({ probe: () => okResp() });
  ok("non-http scheme refused", (await fetcher()("ftp://a.example.com/")) === null);
  ok("non-http scheme never fetched", probes.length === 0);
}

globalThis.fetch = realFetch;
console.log(`\nreserved-probe-ssrf: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
