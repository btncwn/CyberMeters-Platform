#!/usr/bin/env node
//
// SPF static PASS-authorisation resolver — safety-critical unit + change-detection
// suite (PR-A). The resolver is PURE (DNS injected as a mock), so this runs with no
// network. Covers RFC 7208 resolution semantics, the DNS-lookup / void limits, the
// TempError FAIL-SAFE (the #1 false-positive guard), CIDR containment, and the
// posture-events change detection (Q729 root-tamper NON-REGRESSION; include-chain
// change fires email_spf_authorization_changed; a DNS blip fires NOTHING).
// CI-blocking. Requires Node 24+.
//
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const R = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "spf-resolver.js")).href);
const { buildPostureDiffEvents } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "posture-events.js")).href);
const {
  resolveSpfAuthorization,
  diffResolvedAuthorizations,
  canonicalizeCidr,
  formatCanonicalCidrForDisplay,
  formatSpfAuthorizationDescriptionForDisplay,
  cidrContains,
  ipContainedInAnyCidr,
  SPF_RESOLUTION_STATUS,
} = R;

let pass = 0, fail = 0;
const results = [];
const ok = (name, cond) => { cond ? (pass++, results.push(`PASS ${name}`)) : (fail++, results.push(`FAIL ${name}`)); };
const NOW = "2026-07-21T00:00:00.000Z";

// Build a mock `lookup(name, type)` from a fixture map. A missing entry defaults
// to a void answer (NXDOMAIN-equivalent). Values marked { temperror:true } fail safe.
function mockLookup(zone) {
  return async (name, type) => {
    const key = `${String(name).toLowerCase()}|${type}`;
    const entry = zone[key];
    if (!entry) return { status: "void", values: [] };
    if (entry.temperror) return { status: "temperror", values: [] };
    if (entry.void) return { status: "void", values: [] };
    return { status: "ok", values: entry.values };
  };
}
const resolve = (domain, zone, rootRecord) =>
  resolveSpfAuthorization({ domain, rootRecord, recordCount: rootRecord ? 1 : undefined, lookup: mockLookup(zone), nowIso: NOW });

// ── CIDR canonicalisation + containment ──────────────────────────────────────
ok("canonicalize ip4 host → /32", canonicalizeCidr("192.0.2.5", "ip4") === "ip4:c0000205/32");
ok("canonicalize ip4 CIDR masks host bits", canonicalizeCidr("192.0.2.5/24", "ip4") === canonicalizeCidr("192.0.2.0/24", "ip4"));
ok("canonicalize ip6 collapses ::", canonicalizeCidr("2001:db8::1", "ip6") === canonicalizeCidr("2001:0db8:0000:0000:0000:0000:0000:0001", "ip6"));
ok("malformed ip4 → null (never silently widens)", canonicalizeCidr("999.1.1.1", "ip4") === null);
ok("out-of-range prefix → null", canonicalizeCidr("192.0.2.0/33", "ip4") === null);
ok("ip4 containment: /24 contains member", cidrContains(canonicalizeCidr("192.0.2.0/24", "ip4"), "192.0.2.200") === true);
ok("ip4 containment: /24 excludes non-member", cidrContains(canonicalizeCidr("192.0.2.0/24", "ip4"), "192.0.3.1") === false);
ok("ip6 containment: /32 contains member", cidrContains(canonicalizeCidr("2001:db8::/32", "ip6"), "2001:db8:dead:beef::1") === true);
ok("ip6 containment: /32 excludes non-member", cidrContains(canonicalizeCidr("2001:db8::/32", "ip6"), "2001:db9::1") === false);
ok("membership uses containment, not string equality", ipContainedInAnyCidr("10.0.0.7", [canonicalizeCidr("10.0.0.0/8", "ip4")]) === true);

// ── Canonical machine form ↔ customer display form ──────────────────────────
const cidrDisplayFixtures = JSON.parse(
  fs.readFileSync(path.join(root, "scripts", "fixtures", "spf-cidr-display.json"), "utf8"),
);
for (const fixture of cidrDisplayFixtures) {
  const canonical = canonicalizeCidr(fixture.input, fixture.family);
  ok(`${fixture.name}: canonical machine form is pinned`,
    canonical === fixture.canonical);
  const display = formatCanonicalCidrForDisplay(canonical);
  ok(`${fixture.name}: customer display form is exact`,
    display === fixture.display);
  ok(`${fixture.name}: display round-trips to the same canonical range`,
    canonicalizeCidr(display, fixture.family) === canonical);
}
ok("display rejects a canonical token with host bits instead of silently shifting it",
  formatCanonicalCidrForDisplay("ip4:c0000205/24") === null);
ok("legacy description repair changes only valid canonical CIDR tokens",
  formatSpfAuthorizationDescriptionForDisplay(
    "added [ip4:c0000200/24]; invalid [ip4:c0000205/24]",
  ) === "added [192.0.2.0/24]; invalid [ip4:c0000205/24]");

// ── ip4/ip6 only, qualifier exclusion ────────────────────────────────────────
{
  const r = await resolve("q.example", {}, "v=spf1 +ip4:192.0.2.0/24 -ip4:203.0.113.0/24 ~ip4:198.51.100.0/24 ?ip4:10.0.0.0/8 ip6:2001:db8::/32 -all");
  ok("qualifier: only +ip4/ip6 contribute (soft/hard/neutral excluded)",
     r.resolution_status === SPF_RESOLUTION_STATUS.COMPLETE &&
     r.resolved_pass_authorisations.includes(canonicalizeCidr("192.0.2.0/24", "ip4")) &&
     r.resolved_pass_authorisations.includes(canonicalizeCidr("2001:db8::/32", "ip6")) &&
     !r.resolved_pass_authorisations.includes(canonicalizeCidr("203.0.113.0/24", "ip4")) &&
     !r.resolved_pass_authorisations.includes(canonicalizeCidr("198.51.100.0/24", "ip4")) &&
     !r.resolved_pass_authorisations.includes(canonicalizeCidr("10.0.0.0/8", "ip4")));
  ok("ip4/ip6/all consume ZERO DNS lookups", r.lookup_count === 0);
  ok("complete status: non-pass mechanisms do NOT downgrade to partial", r.resolution_status === SPF_RESOLUTION_STATUS.COMPLETE);
  ok("non-pass mechanisms recorded as structured NON-authorising evidence (not 'unresolved')",
     r.non_authorising_mechanisms.some((u) => /not a PASS-authorised range/.test(u.reason)) && r.unresolved_mechanisms.length === 0);
}

// ── include chain (recursive) ────────────────────────────────────────────────
{
  const zone = {
    "spf.provider.com|TXT": { values: ["v=spf1 ip4:198.51.100.0/24 include:spf2.provider.com -all"] },
    "spf2.provider.com|TXT": { values: ["v=spf1 ip4:203.0.113.0/24 -all"] },
  };
  const r = await resolve("acme.example", zone, "v=spf1 ip4:192.0.2.0/24 include:spf.provider.com -all");
  ok("include chain resolves recursively (root + 2 nested ranges)",
     r.resolution_status === SPF_RESOLUTION_STATUS.COMPLETE &&
     r.resolved_pass_authorisations.length === 3 &&
     r.resolved_pass_authorisations.includes(canonicalizeCidr("203.0.113.0/24", "ip4")));
  ok("include chain counts 2 DNS lookups", r.lookup_count === 2);
}

// ── redirect semantics (used only when no `all`) ─────────────────────────────
{
  const zone = { "redir.example|TXT": { values: ["v=spf1 ip4:203.0.113.0/24 -all"] } };
  const withRedirectNoAll = await resolve("r1.example", zone, "v=spf1 ip4:192.0.2.0/24 redirect=redir.example");
  ok("redirect is followed when no `all` is present",
     withRedirectNoAll.resolved_pass_authorisations.includes(canonicalizeCidr("203.0.113.0/24", "ip4")));
  const withRedirectAndAll = await resolve("r2.example", zone, "v=spf1 ip4:192.0.2.0/24 -all redirect=redir.example");
  ok("redirect is IGNORED when `all` is present (RFC 7208 §6.1)",
     !withRedirectAndAll.resolved_pass_authorisations.includes(canonicalizeCidr("203.0.113.0/24", "ip4")));
}

// ── a / mx with dual-CIDR ────────────────────────────────────────────────────
{
  const zone = {
    "acme.example|A": { values: ["192.0.2.10"] },
    "acme.example|AAAA": { values: ["2001:db8::10"] },
    "acme.example|MX": { values: ["10 mail.acme.example"] },
    "mail.acme.example|A": { values: ["203.0.113.10"] },
    "mail.acme.example|AAAA": { void: true },
  };
  const r = await resolve("acme.example", zone, "v=spf1 a/24//64 mx -all");
  ok("a with dual-CIDR applies /24 (v4) and /64 (v6)",
     r.resolved_pass_authorisations.includes(canonicalizeCidr("192.0.2.0/24", "ip4")) &&
     r.resolved_pass_authorisations.includes(canonicalizeCidr("2001:db8::/64", "ip6")));
  ok("mx resolves each MX host's A record (host /32, no CIDR on mx)",
     r.resolved_pass_authorisations.includes(canonicalizeCidr("203.0.113.10", "ip4")));
  ok("a + mx consume 2 DNS lookups", r.lookup_count === 2);
}

// ── circular include guard → PermError ───────────────────────────────────────
{
  const zone = {
    "a.example|TXT": { values: ["v=spf1 include:b.example -all"] },
    "b.example|TXT": { values: ["v=spf1 include:a.example -all"] },
  };
  const r = await resolve("a.example", zone, "v=spf1 include:b.example -all");
  ok("include cycle → PermError (set null, no diff)", r.resolution_status === SPF_RESOLUTION_STATUS.PERMERROR && r.resolved_pass_authorisations === null);
}

// ── 10-lookup limit → PermError ──────────────────────────────────────────────
{
  const zone = {};
  for (let i = 0; i < 12; i++) zone[`inc${i}.example|TXT`] = { values: [`v=spf1 ip4:10.0.${i}.0/24 -all`] };
  const root = "v=spf1 " + Array.from({ length: 12 }, (_, i) => `include:inc${i}.example`).join(" ") + " -all";
  const r = await resolve("many.example", zone, root);
  ok("11th DNS-mechanism lookup → PermError", r.resolution_status === SPF_RESOLUTION_STATUS.PERMERROR);
  ok("lookup ceiling reason recorded", r.lookup_count > 10);
}

// ── void-lookup limit → PermError ────────────────────────────────────────────
{
  // Three includes that all resolve to NXDOMAIN (void). Void limit is 2.
  const zone = {}; // no entries → every include is void
  const r = await resolve("void.example", zone, "v=spf1 include:v1.example include:v2.example include:v3.example -all");
  ok("exceeding the void-lookup limit → PermError", r.resolution_status === SPF_RESOLUTION_STATUS.PERMERROR);
}

// ── multiple SPF records → PermError ─────────────────────────────────────────
{
  const r = await resolveSpfAuthorization({ domain: "dup.example", rootRecord: "v=spf1 ip4:192.0.2.0/24 -all", recordCount: 2, lookup: mockLookup({}), nowIso: NOW });
  ok("multiple SPF records at root → PermError", r.resolution_status === SPF_RESOLUTION_STATUS.PERMERROR);
}

// ── ptr ignored (partial, not expanded) ──────────────────────────────────────
{
  const zone = { "ptr.example|A": { values: ["192.0.2.99"] } };
  const r = await resolve("ptr.example", zone, "v=spf1 ip4:192.0.2.0/24 ptr -all");
  ok("ptr is NOT expanded → partial with a reason",
     r.resolution_status === SPF_RESOLUTION_STATUS.PARTIAL &&
     r.unresolved_mechanisms.some((u) => /ptr/.test(u.mechanism) || /ptr/i.test(u.reason)));
  ok("ptr partial still returns the resolvable subset", r.resolved_pass_authorisations.includes(canonicalizeCidr("192.0.2.0/24", "ip4")));
}

// ── exists / macro → partial (never invents IPs) ─────────────────────────────
{
  const r = await resolve("m.example", {}, "v=spf1 ip4:192.0.2.0/24 exists:%{i}.example include:%{d}.spf.example -all");
  ok("exists + macro-include → partial, no invented IPs",
     r.resolution_status === SPF_RESOLUTION_STATUS.PARTIAL &&
     r.resolved_pass_authorisations.length === 1 &&
     r.unresolved_mechanisms.length >= 2);
}

// ── split-TXT join (multiple candidate strings, one v=spf1) ──────────────────
{
  // The DoH adapter joins each Answer's data; here a value already-joined is the
  // record. Verify a record split into two entries where only one is v=spf1 works.
  const zone = { "split.example|TXT": { values: ["some other txt", "v=spf1 ip4:192.0.2.0/24 -all"] } };
  const r = await resolveSpfAuthorization({ domain: "split.example", lookup: mockLookup(zone), nowIso: NOW });
  ok("root TXT with mixed records selects the v=spf1 one", r.resolution_status === SPF_RESOLUTION_STATUS.COMPLETE && r.resolved_pass_authorisations.length === 1);
}

// ── no SPF record → complete empty set (a definite, comparable absence) ──────
{
  const r = await resolveSpfAuthorization({ domain: "none.example", lookup: mockLookup({}), nowIso: NOW });
  ok("absent SPF (successful lookup) → complete empty set", r.resolution_status === SPF_RESOLUTION_STATUS.COMPLETE && r.resolved_pass_authorisations.length === 0);
}

// ── TempError FAIL-SAFE (the #1 false-positive guard) ─────────────────────────
{
  const zone = { "spf.provider.com|TXT": { temperror: true } };
  const r = await resolve("blip.example", zone, "v=spf1 ip4:192.0.2.0/24 include:spf.provider.com -all");
  ok("a transient DNS error → temperror", r.resolution_status === SPF_RESOLUTION_STATUS.TEMPERROR);
  ok("temperror returns NO set (null), never a partial silently treated as complete", r.resolved_pass_authorisations === null);
  // A root-level temperror.
  const rootBlip = await resolveSpfAuthorization({ domain: "root-blip.example", lookup: mockLookup({ "root-blip.example|TXT": { temperror: true } }), nowIso: NOW });
  ok("root-level transient error → temperror, null set", rootBlip.resolution_status === SPF_RESOLUTION_STATUS.TEMPERROR && rootBlip.resolved_pass_authorisations === null);
}

// ── diffResolvedAuthorizations: comparison gate ──────────────────────────────
{
  const complete = (cidrs) => ({ resolution_status: "complete", resolved_pass_authorisations: cidrs });
  const a = complete([canonicalizeCidr("192.0.2.0/24", "ip4")]);
  const b = complete([canonicalizeCidr("192.0.2.0/24", "ip4"), canonicalizeCidr("203.0.113.0/24", "ip4")]);
  const same = diffResolvedAuthorizations(a, a);
  ok("identical complete sets → not changed", same && same.changed === false);
  const grew = diffResolvedAuthorizations(a, b);
  ok("added CIDR → changed with canonical added list", grew.changed === true && grew.added.length === 1 && grew.removed.length === 0);
  ok("diff carries canonical CIDRs, not rendered strings", /^ip4:[0-9a-f]+\/\d+$/.test(grew.added[0]));
  // Comparison must NOT be performed unless BOTH are complete.
  ok("temperror side → comparison NOT performed (null)", diffResolvedAuthorizations(a, { resolution_status: "temperror", resolved_pass_authorisations: null }) === null);
  ok("partial side → comparison NOT performed (null)", diffResolvedAuthorizations({ resolution_status: "partial", resolved_pass_authorisations: [] }, b) === null);
  ok("permerror side → comparison NOT performed (null)", diffResolvedAuthorizations(a, { resolution_status: "permerror", resolved_pass_authorisations: null }) === null);
  ok("legacy report (no resolved fields) → comparison NOT performed", diffResolvedAuthorizations({}, b) === null);
}

// ── posture-events change detection (integration) ────────────────────────────
const emailMod = (spf) => ({ email_security: { spf } });
const CIDRA = canonicalizeCidr("192.0.2.0/24", "ip4");
const CIDRB = canonicalizeCidr("203.0.113.0/24", "ip4");

// Q729 NON-REGRESSION: a root-record TEXT change STILL fires email_spf_changed.
{
  const prev = emailMod({ present: true, record: "v=spf1 include:old.provider -all", resolution_status: "complete", resolved_pass_authorisations: [CIDRA] });
  const curr = emailMod({ present: true, record: "v=spf1 include:evil.attacker -all", resolution_status: "complete", resolved_pass_authorisations: [CIDRA] });
  const events = buildPostureDiffEvents("q729.example", prev, curr);
  ok("Q729 non-regression: root-record text change STILL fires email_spf_changed",
     events.some((e) => e.event_type === "email_spf_changed"));
}

// The NEW capability: include-chain change (root UNCHANGED) fires authorization_changed.
{
  const root = "v=spf1 include:spf.provider.com -all";
  const prev = emailMod({ present: true, record: root, resolution_status: "complete", resolved_pass_authorisations: [CIDRA] });
  const curr = emailMod({ present: true, record: root, resolution_status: "complete", resolved_pass_authorisations: [CIDRA, CIDRB] });
  const events = buildPostureDiffEvents("inc.example", prev, curr);
  ok("include-chain change (root unchanged) fires email_spf_authorization_changed",
     events.some((e) => e.event_type === "email_spf_authorization_changed"));
  ok("root unchanged → email_spf_changed does NOT fire", !events.some((e) => e.event_type === "email_spf_changed"));
  const authEvt = events.find((e) => e.event_type === "email_spf_authorization_changed");
  ok("authorization_changed carries canonical added CIDR evidence", authEvt?.evidence?.added?.includes(CIDRB));
  ok("authorization_changed carries additive display CIDR evidence",
    authEvt?.evidence?.added_display?.includes("203.0.113.0/24"));
  ok("authorization_changed description embeds the human CIDR",
    authEvt?.description?.includes("203.0.113.0/24") &&
    !authEvt?.description?.includes(CIDRB));
}

// Added + removed in one event preserves canonical evidence while customer text
// uses RFC 5952/dotted-decimal display values. Added presence keeps severity medium.
{
  const previousV4 = canonicalizeCidr("192.0.2.0/24", "ip4");
  const previousV6 = canonicalizeCidr("2001:db8::/32", "ip6");
  const currentV4 = canonicalizeCidr("203.0.113.0/24", "ip4");
  const currentV6 = canonicalizeCidr("2001:db9::/32", "ip6");
  const prev = emailMod({
    present: true,
    record: "v=spf1 include:provider.example -all",
    resolution_status: "complete",
    resolved_pass_authorisations: [previousV4, previousV6],
  });
  const curr = emailMod({
    present: true,
    record: "v=spf1 include:provider.example -all",
    resolution_status: "complete",
    resolved_pass_authorisations: [currentV4, currentV6],
  });
  const authEvt = buildPostureDiffEvents("delta.example", prev, curr)
    .find((event) => event.event_type === "email_spf_authorization_changed");
  ok("added-and-removed delta emits one medium event",
    authEvt?.severity === "medium");
  ok("added-and-removed description shows human IPv4 and RFC 5952 IPv6",
    authEvt?.description ===
      "SPF authorised sending sources changed for delta.example: " +
      "added 2 [203.0.113.0/24, 2001:db9::/32]; " +
      "removed 2 [192.0.2.0/24, 2001:db8::/32]");
  ok("added-and-removed evidence retains canonical machine arrays",
    authEvt?.evidence?.added?.includes(currentV4) &&
    authEvt?.evidence?.added?.includes(currentV6) &&
    authEvt?.evidence?.removed?.includes(previousV4) &&
    authEvt?.evidence?.removed?.includes(previousV6));
  ok("added-and-removed evidence also carries display arrays",
    authEvt?.evidence?.added_display?.includes("2001:db9::/32") &&
    authEvt?.evidence?.removed_display?.includes("192.0.2.0/24"));
}

// The human form can be longer than packed hex, but the row remains bounded by
// exactly 12 displayed entries plus an honest (+N more) suffix.
{
  const added = Array.from({ length: 15 }, (_, index) =>
    canonicalizeCidr(
      `abcd:bcde:cdef:def0:abcd:bcde:cdef:${(0x1000 + index).toString(16)}/128`,
      "ip6",
    )
  ).sort();
  const prev = emailMod({
    present: true,
    record: "v=spf1 include:provider.example -all",
    resolution_status: "complete",
    resolved_pass_authorisations: [],
  });
  const curr = emailMod({
    present: true,
    record: "v=spf1 include:provider.example -all",
    resolution_status: "complete",
    resolved_pass_authorisations: added,
  });
  const authEvt = buildPostureDiffEvents("bounded.example", prev, curr)
    .find((event) => event.event_type === "email_spf_authorization_changed");
  const displayedList = authEvt?.description
    ?.match(/added 15 \[(.*) \(\+3 more\)\]/)?.[1]
    ?.split(", ") || [];
  ok("bounded event reports the full added count and (+N more) suffix",
    authEvt?.description?.includes("added 15 [") &&
    authEvt?.description?.includes("(+3 more)"));
  ok("bounded event writes exactly 12 human CIDRs even when display is longer",
    displayedList.length === 12 &&
    authEvt?.evidence?.added_display?.[0]?.length > authEvt?.evidence?.added?.[0]?.length);
  ok("bounded event keeps complete canonical and display evidence arrays",
    authEvt?.evidence?.added?.length === 15 &&
    authEvt?.evidence?.added_display?.length === 15);
}

// A DNS BLIP (temperror this scan) must fire NOTHING for the authorisation set.
{
  const root = "v=spf1 include:spf.provider.com -all";
  const prev = emailMod({ present: true, record: root, resolution_status: "complete", resolved_pass_authorisations: [CIDRA] });
  const currBlip = emailMod({ present: true, record: root, resolution_status: "temperror", resolved_pass_authorisations: null });
  const events = buildPostureDiffEvents("blip.example", prev, currBlip);
  ok("a DNS blip (temperror) fires NO authorization_changed event",
     !events.some((e) => e.event_type === "email_spf_authorization_changed"));
  ok("a DNS blip fires NO email_spf_changed either (root unchanged)",
     !events.some((e) => e.event_type === "email_spf_changed"));
}

// Legacy previous report (no resolved fields at all) → no false authorization event.
{
  const root = "v=spf1 include:spf.provider.com -all";
  const prevLegacy = emailMod({ present: true, record: root }); // pre-PR-A report shape
  const curr = emailMod({ present: true, record: root, resolution_status: "complete", resolved_pass_authorisations: [CIDRA, CIDRB] });
  const events = buildPostureDiffEvents("legacy.example", prevLegacy, curr);
  ok("legacy previous report → no false authorization_changed (comparison not performed)",
     !events.some((e) => e.event_type === "email_spf_authorization_changed"));
}

// ── report ───────────────────────────────────────────────────────────────────
console.log(`\nSPF resolver + change-detection: ${pass}/${pass + fail} passed`);
if (fail) { for (const r of results.filter((r) => r.startsWith("FAIL"))) console.log("  " + r); console.error("spf-resolver validation FAILED"); process.exit(1); }
console.log("spf-resolver validation passed");
