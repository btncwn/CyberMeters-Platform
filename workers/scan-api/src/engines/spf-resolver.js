// ── Statically-resolvable SPF PASS-authorisation resolver (RFC 7208) ──────────
//
// Computes the set of source IP ranges that a domain's SPF record would evaluate
// to PASS *using only statically-resolvable mechanisms*. This is deliberately NOT
// a claim of a universally-complete "effective SPF set": macro / exists / ptr and
// any runtime-dependent mechanism are NOT expanded, and their presence downgrades
// the result to `partial` with explicit reasons. Resolution completeness is
// recorded SEPARATELY from the set, so a consumer can never mistake a partial set
// for an exhaustive one.
//
// SAFETY CONTRACT (the whole reason this module is careful):
//   • Only PASS-capable (`+`, or a bare mechanism which defaults to `+`) mechanisms
//     contribute ranges. `-` / `~` / `?` mechanisms are recorded as NON-authorising
//     structured evidence and never enter the set.
//   • A transient DNS failure (timeout / SERVFAIL) in ANY required lookup returns
//     resolution_status = "temperror" with resolved_pass_authorisations = null.
//     The caller MUST NOT diff, MUST NOT emit a change event, and MUST NOT erase a
//     prior successful set. This is the #1 false-positive guard.
//   • RFC 7208 §4.6.4 limits: at most 10 DNS-mechanism lookups (include / a / mx /
//     ptr / exists / redirect — NOT ip4 / ip6 / all) and at most 2 void lookups.
//     Exceeding either, an include cycle, a syntax error, or >1 SPF record at a
//     domain → resolution_status = "permerror" (a CONFIRMED posture state, never a
//     set change).
//   • Membership is CIDR CONTAINMENT (IPv4 + IPv6), never string equality; the
//     stored set is canonical (network address + prefix), sorted and deduped.
//
// The resolver is PURE: all DNS access is injected via a `lookup` function so the
// unit suite runs with a deterministic mock and no network. `lookup(name, type)`
// resolves to `{ status: "ok" | "temperror" | "void", values: string[] }`:
//   status "ok"        → values present (TXT strings, or A/AAAA/MX target strings)
//   status "temperror" → transient failure (timeout / SERVFAIL) — fail safe
//   status "void"      → NXDOMAIN or an empty answer (counts toward the void limit)

import { parseSpfRecord } from "./email-analysis.js";

export const SPF_RESOLUTION_STATUS = Object.freeze({
  COMPLETE: "complete",
  PARTIAL: "partial",
  PERMERROR: "permerror",
  TEMPERROR: "temperror",
});

const MAX_DNS_MECHANISM_LOOKUPS = 10; // RFC 7208 §4.6.4
const MAX_VOID_LOOKUPS = 2;           // RFC 7208 §4.6.4

// ── IP / CIDR canonicalisation + containment ─────────────────────────────────

function parseIpv4(str) {
  const m = String(str).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const octets = m.slice(1, 5).map(Number);
  if (octets.some((o) => o > 255)) return null;
  // Return a BigInt so v4 and v6 share the containment maths.
  return (BigInt(octets[0]) << 24n) | (BigInt(octets[1]) << 16n) | (BigInt(octets[2]) << 8n) | BigInt(octets[3]);
}

function parseIpv6(str) {
  let s = String(str).trim().toLowerCase();
  if (s.includes(".")) {
    // Embedded IPv4 (e.g. ::ffff:1.2.3.4) → convert the tail to two hextets.
    const idx = s.lastIndexOf(":");
    const v4 = parseIpv4(s.slice(idx + 1));
    if (v4 === null) return null;
    const hi = (v4 >> 16n) & 0xffffn, lo = v4 & 0xffffn;
    s = s.slice(0, idx + 1) + hi.toString(16) + ":" + lo.toString(16);
  }
  if (!/^[0-9a-f:]+$/.test(s) || (s.match(/::/g) || []).length > 1) return null;
  let head, tail;
  if (s.includes("::")) {
    const [h, t] = s.split("::");
    head = h ? h.split(":") : [];
    tail = t ? t.split(":") : [];
  } else {
    head = s.split(":"); tail = [];
  }
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (!s.includes("::") && head.length !== 8)) return null;
  const groups = [...head, ...Array(Math.max(0, missing)).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  let val = 0n;
  for (const g of groups) {
    if (g === "" || g.length > 4 || !/^[0-9a-f]+$/.test(g)) return null;
    val = (val << 16n) | BigInt(parseInt(g, 16));
  }
  return val;
}

// Canonicalise an ip4/ip6 CIDR (or bare IP) to `<family>:<network-hex>/<prefix>`.
// Returns null for anything malformed (a malformed literal is a syntax error the
// caller escalates to PermError; it never silently widens the set).
export function canonicalizeCidr(token, family) {
  const [addr, prefixPart] = String(token).split("/");
  const bits = family === "ip6" ? 128 : 32;
  let prefix = prefixPart === undefined ? bits : Number(prefixPart);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;
  const value = family === "ip6" ? parseIpv6(addr) : parseIpv4(addr);
  if (value === null) return null;
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
  const network = value & mask;
  return `${family}:${network.toString(16)}/${prefix}`;
}

function ipv4ForDisplay(value) {
  return [24n, 16n, 8n, 0n]
    .map((shift) => Number((value >> shift) & 0xffn))
    .join(".");
}

function ipv6ForDisplay(value) {
  const groups = Array.from({ length: 8 }, (_, index) =>
    Number((value >> BigInt((7 - index) * 16)) & 0xffffn).toString(16)
  );

  // RFC 5952 §4.2: compress the longest run of two or more zero hextets.
  // When runs tie, the first run wins because bestStart changes only for a
  // strictly longer run.
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < groups.length;) {
    if (groups[start] !== "0") {
      start += 1;
      continue;
    }
    let end = start;
    while (end < groups.length && groups[end] === "0") end += 1;
    const length = end - start;
    if (length >= 2 && length > bestLength) {
      bestStart = start;
      bestLength = length;
    }
    start = end;
  }

  if (bestStart < 0) return groups.join(":");
  const left = groups.slice(0, bestStart).join(":");
  const right = groups.slice(bestStart + bestLength).join(":");
  if (!left && !right) return "::";
  if (!left) return `::${right}`;
  if (!right) return `${left}::`;
  return `${left}::${right}`;
}

// Inverse presentation for the canonical machine form. Prefixes are NEVER
// elided: host ranges remain /32 or /128 and the universal range remains /0.
// Returning null for malformed or non-canonical input prevents display repair
// from silently shifting/widening historical evidence.
export function formatCanonicalCidrForDisplay(canonicalCidr) {
  const canonical = String(canonicalCidr);
  const match = /^(ip4|ip6):([0-9a-f]+)\/(\d+)$/.exec(canonical);
  if (!match) return null;
  const family = match[1];
  const bits = family === "ip6" ? 128 : 32;
  const prefix = Number(match[3]);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > bits) return null;

  let network;
  try {
    network = BigInt(`0x${match[2]}`);
  } catch {
    return null;
  }
  if (network < 0n || network >= (1n << BigInt(bits))) return null;

  const address = family === "ip6"
    ? ipv6ForDisplay(network)
    : ipv4ForDisplay(network);
  const display = `${address}/${prefix}`;

  // Exact inverse guard: only a canonical network/prefix pair may be repaired.
  return canonicalizeCidr(display, family) === canonical ? display : null;
}

// Non-destructive repair for append-only descriptions written before the
// customer-display formatter existed. Only valid canonical SPF CIDR tokens are
// replaced; all other bytes in the returned string are preserved.
export function formatSpfAuthorizationDescriptionForDisplay(description) {
  if (typeof description !== "string" || !description) return description;
  return description.replace(
    /\b(?:ip4|ip6):[0-9a-f]+\/\d+\b/g,
    (canonical) => formatCanonicalCidrForDisplay(canonical) ?? canonical,
  );
}

// Does a canonical CIDR contain a bare IP string? Used by PR-B membership tests.
export function cidrContains(canonicalCidr, ipString) {
  const m = /^(ip4|ip6):([0-9a-f]+)\/(\d+)$/.exec(String(canonicalCidr));
  if (!m) return false;
  const family = m[1], network = BigInt("0x" + m[2]), prefix = Number(m[3]);
  const bits = family === "ip6" ? 128 : 32;
  const value = family === "ip6" ? parseIpv6(ipString) : parseIpv4(ipString);
  if (value === null) return false;
  const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(bits - prefix);
  return (value & mask) === network;
}

export function ipContainedInAnyCidr(ipString, canonicalCidrs) {
  return (canonicalCidrs || []).some((c) => cidrContains(c, ipString));
}

// ── The resolver ─────────────────────────────────────────────────────────────

/**
 * resolveSpfAuthorization — compute the statically-resolvable PASS set.
 *
 * @param {object}   opts
 * @param {string}   opts.domain      the domain whose SPF is being resolved
 * @param {string?}  opts.rootRecord  the already-fetched root SPF TXT (optional; if
 *                                     omitted the resolver fetches it via `lookup`)
 * @param {number?}  opts.recordCount how many SPF records the root lookup returned
 *                                     (>1 → PermError). Ignored if rootRecord absent.
 * @param {Function} opts.lookup      async (name, type) => { status, values }
 * @param {string}   opts.nowIso      injected timestamp (scripts cannot call Date.now)
 * @returns {Promise<object>} snapshot fields (see SAFETY CONTRACT above)
 */
export async function resolveSpfAuthorization({ domain, rootRecord = undefined, recordCount = undefined, lookup, nowIso }) {
  const state = {
    lookupCount: 0,
    voidCount: 0,
    cidrs: new Set(),
    unresolved: [],            // { mechanism, reason } — TRULY unresolvable (ptr/exists/macro) → forces `partial`
    nonAuthorising: [],        // { mechanism, reason } — fully resolved -/~/? evidence (does NOT force partial)
    visited: new Set(),        // include/redirect targets → cycle guard
    tempError: false,
    permError: null,           // first permerror reason (string)
  };

  const finish = (status) => ({
    resolution_status: status,
    resolved_pass_authorisations:
      status === SPF_RESOLUTION_STATUS.COMPLETE || status === SPF_RESOLUTION_STATUS.PARTIAL
        ? [...state.cidrs].sort()
        : null,
    unresolved_mechanisms: state.unresolved,
    non_authorising_mechanisms: state.nonAuthorising,
    lookup_count: state.lookupCount,
    void_lookup_count: state.voidCount,
    resolved_at: nowIso,
  });

  // Fetch + join a domain's single SPF record. Returns { record, count, status }.
  const fetchSpf = async (name) => {
    const res = await lookup(name, "TXT");
    if (res.status === "temperror") return { status: "temperror" };
    if (res.status === "void") return { record: null, count: 0, status: "ok" };
    // A DoH TXT answer may split one record across multiple quoted strings; the
    // injected lookup returns each Answer's data joined already, so treat each
    // value as one candidate record and keep only v=spf1 ones.
    const spfRecords = (res.values || [])
      .map((v) => String(v).trim())
      .filter((v) => /^v=spf1(\s|$)/i.test(v));
    if (spfRecords.length === 0) return { record: null, count: 0, status: "ok" };
    return { record: spfRecords[0], count: spfRecords.length, status: "ok" };
  };

  // Count a DNS-mechanism lookup; return false if the 10-lookup ceiling is hit.
  const chargeLookup = () => {
    state.lookupCount += 1;
    if (state.lookupCount > MAX_DNS_MECHANISM_LOOKUPS) {
      state.permError = "dns_lookup_limit_exceeded";
      return false;
    }
    return true;
  };
  const chargeVoid = () => {
    state.voidCount += 1;
    if (state.voidCount > MAX_VOID_LOOKUPS) {
      state.permError = "void_lookup_limit_exceeded";
      return false;
    }
    return true;
  };

  // Resolve A / AAAA for a name, applying an optional dual-CIDR (a:dom/24//64).
  const addAddressRanges = async (name, v4Cidr, v6Cidr) => {
    for (const [type, family, cidr] of [["A", "ip4", v4Cidr], ["AAAA", "ip6", v6Cidr]]) {
      const res = await lookup(name, type);
      if (res.status === "temperror") { state.tempError = true; return false; }
      if (res.status === "void" || (res.values || []).length === 0) {
        // A void A/AAAA is not itself fatal (mx with only A records is normal);
        // only count a void toward the limit when BOTH families are empty — handled
        // by the caller via the return value. Here, just skip.
        continue;
      }
      for (const ip of res.values) {
        const canon = canonicalizeCidr(cidr ? `${ip}/${cidr}` : ip, family);
        if (canon) state.cidrs.add(canon);
        else state.unresolved.push({ mechanism: `${family}_literal`, reason: `unparseable address ${ip}` });
      }
    }
    return true;
  };

  // Recursively evaluate ONE SPF record for the PASS set.
  const evalRecord = async (name, record, count) => {
    if (state.permError) return;
    if (count > 1) { state.permError = "multiple_spf_records"; return; }
    const parsed = parseSpfRecord(record, count);
    if (!parsed.valid) {
      // No / malformed record at an include target is a PermError per RFC 7208
      // §4.6.4 (include that does not resolve to a valid record). At the ROOT it
      // simply means "no authorised set" — handled by the caller before evalRecord.
      state.permError = "included_record_invalid";
      return;
    }

    // Redirect is used ONLY when there is no `all` mechanism anywhere in the record
    // (RFC 7208 §6.1), regardless of token order. Determine that up front so a
    // redirect appearing after `all` is still ignored.
    const allSeen = parsed.mechanisms.some((m) => m.mechanism === "all");
    let redirectTarget = null;

    for (const mech of parsed.mechanisms) {
      if (state.permError || state.tempError) return;
      const pass = mech.qualifier === "+"; // bare defaults to "+" in parseSpfRecord
      const kind = mech.mechanism;

      if (kind === "all") {
        // Fully resolved policy evidence — never "unresolved", never a partial trigger.
        if (!pass) state.nonAuthorising.push({ mechanism: mech.raw, reason: "non-pass all (senders not matched are not authorised)" });
        continue;
      }
      if (kind === "redirect") {
        if (mech.value && !allSeen) redirectTarget = mech.value;
        continue; // evaluated after the loop
      }
      if (kind === "ip4" || kind === "ip6") {
        if (!pass) { state.nonAuthorising.push({ mechanism: mech.raw, reason: `${mech.qualifier}${kind} is not a PASS-authorised range` }); continue; }
        const canon = canonicalizeCidr(mech.value, kind);
        if (canon) state.cidrs.add(canon);
        else { state.permError = "malformed_ip_literal"; return; }
        continue;
      }
      if (kind === "a" || kind === "mx") {
        if (!chargeLookup()) return;
        if (!pass) { state.nonAuthorising.push({ mechanism: mech.raw, reason: `${mech.qualifier}${kind} is not a PASS-authorised range` }); continue; }
        // parseSpfRecord strips the /cidr from a bare `a/24//64` (no colon), so
        // parse the target + dual-CIDR from the RAW token: [q]a|mx[:target][/v4]["//"v6].
        const rawSpec = String(mech.raw).replace(/^[+\-~?]/, "").replace(/^(a|mx)/i, "");
        const [beforeV6, v6Raw] = rawSpec.includes("//") ? [rawSpec.slice(0, rawSpec.indexOf("//")), rawSpec.slice(rawSpec.indexOf("//") + 2)] : [rawSpec, null];
        let target = name, v4Cidr = null;
        const spec = beforeV6.startsWith(":") ? beforeV6.slice(1) : beforeV6;
        if (beforeV6.startsWith(":")) {
          const slash = spec.indexOf("/");
          target = (slash >= 0 ? spec.slice(0, slash) : spec) || name;
          v4Cidr = slash >= 0 ? spec.slice(slash + 1) : null;
        } else if (beforeV6.startsWith("/")) {
          v4Cidr = beforeV6.slice(1);
        }
        const v6Cidr = v6Raw || null;
        if (kind === "a") {
          if (!(await addAddressRanges(target, v4Cidr, v6Cidr))) return; // temperror
        } else {
          const mx = await lookup(target, "MX");
          if (mx.status === "temperror") { state.tempError = true; return; }
          const hosts = (mx.values || []).map((v) => String(v).replace(/^\d+\s+/, "").replace(/\.$/, "")).filter(Boolean);
          if (hosts.length === 0) { if (!chargeVoid()) return; continue; }
          for (const host of hosts) {
            if (!(await addAddressRanges(host, v4Cidr, v6Cidr))) return; // temperror
          }
        }
        continue;
      }
      if (kind === "include") {
        if (!chargeLookup()) return;
        if (!mech.value) { state.permError = "include_without_domain"; return; }
        if (!pass) { state.nonAuthorising.push({ mechanism: mech.raw, reason: "non-pass include is not an authorised range" }); continue; }
        const target = mech.value.toLowerCase();
        if (target.includes("%{")) { state.unresolved.push({ mechanism: mech.raw, reason: "macro-expanded include not statically resolvable" }); continue; }
        if (state.visited.has(target)) { state.permError = "include_cycle_detected"; return; }
        state.visited.add(target);
        const inc = await fetchSpf(target);
        if (inc.status === "temperror") { state.tempError = true; return; }
        if (inc.count === 0) { if (!chargeVoid()) return; state.permError = "included_domain_no_spf"; return; }
        await evalRecord(target, inc.record, inc.count);
        state.visited.delete(target);
        continue;
      }
      if (kind === "ptr") {
        state.unresolved.push({ mechanism: mech.raw, reason: "ptr is deprecated and not expanded (RFC 7208 §5.5)" });
        if (!chargeLookup()) return; // ptr still consumes a lookup slot
        continue;
      }
      if (kind === "exists") {
        state.unresolved.push({ mechanism: mech.raw, reason: "exists is runtime/macro-dependent and not expanded" });
        if (!chargeLookup()) return;
        continue;
      }
      // Any other token that looks macro-dependent.
      if (String(mech.raw).includes("%{")) {
        state.unresolved.push({ mechanism: mech.raw, reason: "macro-expanded mechanism not statically resolvable" });
      } else {
        state.unresolved.push({ mechanism: mech.raw, reason: "unsupported mechanism" });
      }
    }

    // Redirect (only if reached — i.e. no `all` cleared it).
    if (redirectTarget && !state.permError && !state.tempError) {
      const target = redirectTarget.toLowerCase();
      if (target.includes("%{")) { state.unresolved.push({ mechanism: `redirect=${redirectTarget}`, reason: "macro-expanded redirect not statically resolvable" }); return; }
      if (state.visited.has(target)) { state.permError = "redirect_cycle_detected"; return; }
      state.visited.add(target);
      const red = await fetchSpf(target);
      if (red.status === "temperror") { state.tempError = true; return; }
      if (red.count === 0) { if (!chargeVoid()) return; state.permError = "redirect_domain_no_spf"; return; }
      await evalRecord(target, red.record, red.count);
    }
  };

  // ── Entry: obtain the root record, then evaluate ──────────────────────────
  let root = rootRecord, rootCount = recordCount;
  if (root === undefined) {
    const r = await fetchSpf(domain);
    if (r.status === "temperror") { state.tempError = true; return finish(SPF_RESOLUTION_STATUS.TEMPERROR); }
    root = r.record; rootCount = r.count;
  }
  if (rootCount > 1) { state.permError = "multiple_spf_records"; return finish(SPF_RESOLUTION_STATUS.PERMERROR); }
  const rootParsed = parseSpfRecord(root, rootCount ?? (root ? 1 : 0));
  if (!root || !rootParsed.valid) {
    // No usable root SPF record → there is nothing to authorise. This is a
    // definite, comparable "empty set" only when the lookup itself SUCCEEDED
    // (a missing record is not a transient error). Report complete with empty set.
    return finish(SPF_RESOLUTION_STATUS.COMPLETE);
  }

  await evalRecord(domain, root, rootCount ?? 1);

  if (state.tempError) return finish(SPF_RESOLUTION_STATUS.TEMPERROR);
  if (state.permError) return finish(SPF_RESOLUTION_STATUS.PERMERROR);
  if (state.unresolved.length > 0) return finish(SPF_RESOLUTION_STATUS.PARTIAL);
  return finish(SPF_RESOLUTION_STATUS.COMPLETE);
}

// ── DoH adapter ──────────────────────────────────────────────────────────────
// Maps the raw DoH helper (dnsQuery, which THROWS on timeout/HTTP-error and
// returns { Status, Answer }) to the resolver's { status, values } contract, with
// a per-scan cache so each (name,type) is resolved at most once. Timeout / HTTP
// error / SERVFAIL(2) → "temperror" (fail safe); NXDOMAIN(3) / empty answer →
// "void"; NOERROR(0) with data → "ok". `normalize` joins/cleans TXT strings.
export function makeDohSpfLookup(dnsQuery, normalize, cache = new Map()) {
  return async (name, type) => {
    const key = `${String(name).toLowerCase()}|${type}`;
    if (cache.has(key)) return cache.get(key);
    let out;
    try {
      const res = await dnsQuery(name, type);
      const status = Number(res?.Status);
      if (status === 2) out = { status: "temperror", values: [] };            // SERVFAIL
      else if (status === 3) out = { status: "void", values: [] };            // NXDOMAIN
      else {
        const answers = Array.isArray(res?.Answer) ? res.Answer : [];
        const values = answers
          .map((a) => (type === "TXT" ? normalize(a?.data) : String(a?.data ?? "").replace(/\.$/, "")))
          .filter(Boolean);
        out = values.length > 0 ? { status: "ok", values } : { status: "void", values: [] };
      }
    } catch {
      out = { status: "temperror", values: [] }; // timeout / network / HTTP error
    }
    cache.set(key, out);
    return out;
  };
}

// ── Change detection over two SUCCESSFUL, COMPARABLE snapshots ────────────────
// Returns null when a comparison must NOT be performed (the fail-safe path), or
// { changed, added, removed } when both sides are `complete`. Partial/permerror/
// temperror on EITHER side → null (comparison_performed = false).
export function diffResolvedAuthorizations(prev, curr) {
  const ok = (s) => s && s.resolution_status === SPF_RESOLUTION_STATUS.COMPLETE && Array.isArray(s.resolved_pass_authorisations);
  if (!ok(prev) || !ok(curr)) return null; // comparison NOT performed — fail safe
  const prevSet = new Set(prev.resolved_pass_authorisations);
  const currSet = new Set(curr.resolved_pass_authorisations);
  const added = [...currSet].filter((c) => !prevSet.has(c)).sort();
  const removed = [...prevSet].filter((c) => !currSet.has(c)).sort();
  return { changed: added.length > 0 || removed.length > 0, added, removed };
}
