#!/usr/bin/env node
// Which published provider network an asset's addresses are in.
//
// The ranges ship with the Worker (built by scripts/build-cloud-networks.js from
// the providers' own published lists). This proves: the shipped list is the
// pinned one; the build keeps the most specific range and service; the lookup
// picks the longest matching prefix for IPv4 and IPv6; a damaged list attributes
// nothing; the asset API carries the result without any outbound call.
import assert from "node:assert/strict";
import { CLOUD_NETWORK_LIST } from "../workers/scan-api/src/lib/cloud-networks-data.js";
import {
  addressesFromStored, canonicalCidr, createNetworkLookup, describeHostingNetwork,
  HOSTING_LIMITATIONS, parseIpAddress, summariseHostingNetworks,
} from "../workers/scan-api/src/lib/cloud-networks.js";
import { buildEntries, digest, PARSERS, SOURCES } from "./build-cloud-networks.js";
import { loadWorker, buildDb, makeEnv, makeCaller, makeSeeder } from "./security/lib/worker-harness.js";

let passed = 0;
const test = async (name, fn) => { await fn(); passed++; console.log("PASS " + name); };

// Any outbound call fails the run: attribution is local reference data.
let outbound = 0;
globalThis.fetch = async (url) => { outbound++; throw new Error(`Unexpected outbound call: ${url}`); };

// Pinned here as well as in the generated file: a list that only checks itself
// would accept any list with a recomputed digest.
const PINNED_LIST = Object.freeze({
  version: "2026-10-14.1",
  count: 27516,
  sha256: "ea5d3210f12550ff9983d59e4a91c7c862501c70b5e172dafeeaf7d098aa0829",
});

// Small inputs in each provider's published format.
const FIXTURE_INPUTS = {
  aws: JSON.stringify({
    prefixes: [
      { ip_prefix: "52.94.0.0/16", region: "us-east-1", service: "AMAZON" },
      { ip_prefix: "52.94.5.7/24", region: "us-east-1", service: "EC2" },
      { ip_prefix: "52.94.5.0/24", region: "us-east-1", service: "AMAZON" },
      { ip_prefix: "13.32.0.0/15", region: "GLOBAL", service: "AMAZON" },
      { ip_prefix: "13.32.0.0/15", region: "GLOBAL", service: "CLOUDFRONT" },
    ],
    ipv6_prefixes: [
      { ipv6_prefix: "2600:1f00::/24", region: "us-east-1", service: "AMAZON" },
      { ipv6_prefix: "2600:1F18:4000::/36", region: "us-east-1", service: "EC2" },
    ],
  }),
  gcp: JSON.stringify({ prefixes: [
    { ipv4Prefix: "34.1.208.0/20", service: "Google Cloud", scope: "africa-south1" },
    { ipv6Prefix: "2600:1900:4000::/44", service: "Google Cloud", scope: "us-central1" },
  ] }),
  azure: JSON.stringify({ values: [
    { name: "AzureCloud.uksouth", properties: { region: "uksouth", addressPrefixes: ["20.26.0.0/16", "2603:1020:700::/42"] } },
    { name: "AzureCloud", properties: { region: "", addressPrefixes: ["20.0.0.0/8"] } },
    { name: "AzureFrontDoor.Frontend", properties: { region: "", addressPrefixes: ["13.107.208.0/24"] } },
  ] }),
  cloudflare: "173.245.48.0/20\n104.16.0.0/13\n\n2606:4700::/32\n",
};

const fixtureEntries = () => buildEntries([
  { provider: "aws", rows: PARSERS.aws(FIXTURE_INPUTS.aws) },
  { provider: "gcp", rows: PARSERS.gcp(FIXTURE_INPUTS.gcp) },
  { provider: "azure", rows: PARSERS.azure(FIXTURE_INPUTS.azure) },
  { provider: "cloudflare", rows: PARSERS.list(FIXTURE_INPUTS.cloudflare) },
]);
const listOf = (entries, extra = {}) => ({ version: "fixture", count: entries.length, sha256: digest(entries), entries: entries.join("\n"), ...extra });

await test("the shipped list is the pinned one: version, count and SHA-256", async () => {
  for (const [key, value] of Object.entries(PINNED_LIST)) assert.equal(CLOUD_NETWORK_LIST[key], value, key);
});

await test("the shipped list verifies and covers every source, with its address and input hash", async () => {
  const entries = CLOUD_NETWORK_LIST.entries.split("\n");
  assert.equal(entries.length, CLOUD_NETWORK_LIST.count);
  assert.equal(digest(entries), CLOUD_NETWORK_LIST.sha256);
  assert.deepEqual(entries, [...entries].sort(), "sorted");
  for (const line of entries) {
    const [cidr] = line.split("\t");
    assert.equal(canonicalCidr(cidr), cidr, `canonical: ${cidr}`);
  }
  const providers = new Set(entries.map((l) => l.split("\t")[1]));
  for (const p of ["aws", "azure", "gcp", "cloudflare"]) assert.ok(providers.has(p), `has ${p}`);
  assert.equal(CLOUD_NETWORK_LIST.sources.length, SOURCES.length);
  for (const s of CLOUD_NETWORK_LIST.sources) {
    assert.match(s.sha256, /^[0-9a-f]{64}$/);
    assert.match(s.url, /^https:\/\//);
    assert.ok(s.rows > 0);
  }
  assert.ok(CLOUD_NETWORK_LIST.count > 5000, "not a stub");
});

await test("the shipped list places long-published edge ranges and leaves documentation addresses alone", async () => {
  const lookup = createNetworkLookup(CLOUD_NETWORK_LIST);
  assert.equal((await lookup("104.16.1.1"))?.provider, "cloudflare");
  assert.equal((await lookup("2606:4700::6810:1"))?.provider, "cloudflare");
  for (const doc of ["192.0.2.10", "198.51.100.7", "203.0.113.9", "2001:db8::1", "10.0.0.1"]) {
    assert.equal(await lookup(doc), null, doc);
  }
});

await test("the build keeps one row per network, the most specific service, and normalised text", async () => {
  const entries = fixtureEntries();
  const rows = Object.fromEntries(entries.map((l) => { const [c, p, r, s] = l.split("\t"); return [`${p} ${c}`, { r, s }]; }));
  assert.deepEqual(rows["aws 52.94.5.0/24"], { r: "us-east-1", s: "EC2" }, "host bits cleared; EC2 kept over the umbrella row");
  assert.deepEqual(rows["aws 52.94.0.0/16"], { r: "us-east-1", s: "" });
  assert.deepEqual(rows["aws 13.32.0.0/15"], { r: "", s: "CLOUDFRONT" }, "GLOBAL is no region");
  assert.ok(rows["aws 2600:1f18:4000::/36"], "IPv6 lower-cased and compressed");
  assert.deepEqual(rows["azure 20.26.0.0/16"], { r: "uksouth", s: "" });
  assert.ok(!rows["azure 20.0.0.0/8"] && !rows["azure 13.107.208.0/24"], "only the per-region cloud tags");
  assert.deepEqual(rows["gcp 34.1.208.0/20"], { r: "africa-south1", s: "" });
  assert.ok(rows["cloudflare 2606:4700::/32"]);
  assert.deepEqual(entries, [...entries].sort());
  assert.equal(digest(fixtureEntries()), digest(entries), "deterministic");
  assert.throws(() => buildEntries([{ provider: "aws", rows: [{ cidr: "300.1.1.0/24" }] }]), /not a network/);
  assert.throws(() => buildEntries([{ provider: "nobody", rows: [] }]), /unknown provider/);
  assert.throws(() => buildEntries([
    { provider: "aws", rows: [{ cidr: "198.18.0.0/15" }] },
    { provider: "gcp", rows: [{ cidr: "198.18.0.0/15" }] },
  ]), /published by both/);
});

await test("the lookup picks the longest matching range, IPv4 and IPv6", async () => {
  const lookup = createNetworkLookup(listOf(fixtureEntries()));
  const hit = async (ip) => { const h = await lookup(ip); return h && typeof h === "object" ? `${h.provider}|${h.region}|${h.service}|${h.cidr}` : h; };
  assert.equal(await hit("52.94.5.10"), "aws|us-east-1|EC2|52.94.5.0/24");
  assert.equal(await hit("52.94.6.1"), "aws|us-east-1||52.94.0.0/16");
  assert.equal(await hit("13.33.255.255"), "aws||CLOUDFRONT|13.32.0.0/15");
  assert.equal(await hit("20.26.200.1"), "azure|uksouth||20.26.0.0/16");
  assert.equal(await hit("34.1.223.255"), "gcp|africa-south1||34.1.208.0/20");
  assert.equal(await hit("34.1.224.0"), null, "first address past the range");
  assert.equal(await hit("2600:1f18:4abc::5"), "aws|us-east-1|EC2|2600:1f18:4000::/36");
  assert.equal(await hit("2600:1f00:1::1"), "aws|us-east-1||2600:1f00::/24");
  assert.equal(await hit("2603:1020:73f:ffff::1"), "azure|uksouth||2603:1020:700::/42");
  assert.equal(await hit("2606:4700:10::ac43:1"), "cloudflare|||2606:4700::/32");
  assert.equal(await hit("192.0.2.1"), null);
  assert.equal(await hit("not-an-address"), "invalid");
});

await test("addresses parse strictly", async () => {
  for (const ok of ["0.0.0.0", "255.255.255.255", "::", "::1", "2001:db8::1.2.3.4", "2001:DB8:0:0:0:0:0:1"]) assert.ok(parseIpAddress(ok), ok);
  for (const bad of ["01.2.3.4", "256.1.1.1", "1.2.3", "1.2.3.4.5", "1::2::3", "1:2:3:4:5:6:7:8:9", "12345::1", "fe80::1%eth0", "", " ", "1.2.3.4/24"]) {
    assert.equal(parseIpAddress(bad), null, bad);
  }
  assert.equal(canonicalCidr("2001:DB8:0:0:1::/64"), "2001:db8::/64");
  assert.equal(canonicalCidr("10.1.2.3/8"), "10.0.0.0/8");
  assert.equal(canonicalCidr("10.0.0.0/33"), null);
});

await test("a missing, truncated or altered list attributes nothing", async () => {
  const good = listOf(fixtureEntries());
  const broken = [
    { ...good, entries: "" },
    { ...good, entries: good.entries.split("\n").slice(1).join("\n") },
    { ...good, entries: good.entries.replace("uksouth", "ukwest") },
    { ...good, sha256: "0".repeat(64) },
    { ...good, count: good.count + 1 },
    listOf(["104.16.0.0/13\tsomeone\t\t"]),
    listOf(["104.16.0.0/13\tcloudflare\t\t", "104.16.0.0/13\tcloudflare\t\t"]),
    listOf(["104.16.0.1/13\tcloudflare\t\t"]),
    listOf(["2606:4700::1/32\tcloudflare\t\t"]),
    listOf(["104.16.0.0/33\tcloudflare\t\t"]),
    null,
  ];
  for (const list of broken) {
    const lookup = createNetworkLookup(list);
    assert.equal(await lookup("104.16.1.1"), "unavailable");
    const d = await describeHostingNetwork('["104.16.1.1"]', { lookup });
    assert.equal(d.status, "unavailable");
    assert.deepEqual(d.networks, []);
  }
});

await test("an asset's stored addresses are described honestly, per kind of network", async () => {
  const lookup = createNetworkLookup(listOf(fixtureEntries()));
  const d = (v) => describeHostingNetwork(v, { lookup });
  for (const none of [null, "", "[]"]) assert.equal((await d(none)).status, "no_address", String(none));
  for (const bad of ["not json", '["nope"]', '["fe80::1%eth0"]']) assert.equal((await d(bad)).status, "unreadable", bad);
  assert.equal((await d('["::ffff:104.16.1.1"]')).providers[0], "cloudflare", "IPv4-mapped IPv6 is the IPv4 address");
  const cloud = await d('["52.94.5.10","192.0.2.1"]');
  assert.equal(cloud.status, "attributed");
  assert.deepEqual(cloud.networks.map((n) => [n.address, n.provider, n.kind, n.region, n.service]), [["52.94.5.10", "aws", "cloud", "us-east-1", "EC2"]]);
  assert.deepEqual(cloud.limitations, [HOSTING_LIMITATIONS.cloud]);
  assert.match(HOSTING_LIMITATIONS.cloud, /does not show whose account/);
  const edge = await d("104.16.0.1, 13.32.0.9");
  assert.deepEqual(edge.networks.map((n) => [n.provider, n.kind]), [["cloudflare", "edge"], ["aws", "edge"]], "legacy comma list; CDN ranges are edge");
  assert.deepEqual(edge.limitations, [HOSTING_LIMITATIONS.edge]);
  const mixed = await d(["20.26.0.1", "104.16.0.1"]);
  assert.deepEqual(mixed.providers, ["azure", "cloudflare"]);
  assert.deepEqual(new Set(mixed.limitations), new Set([HOSTING_LIMITATIONS.cloud, HOSTING_LIMITATIONS.edge]));
  const other = await d('["192.0.2.1","198.51.100.1"]');
  assert.equal(other.status, "unattributed");
  assert.deepEqual(other.limitations, [HOSTING_LIMITATIONS.unattributed]);
  for (const name of ["Amazon Web Services", "Microsoft Azure", "Google Cloud", "Cloudflare"]) assert.ok(HOSTING_LIMITATIONS.unattributed.includes(name), name);
  assert.match(HOSTING_LIMITATIONS.unattributed, /may still be hosted by another provider/);
  const umbrella = await d('["52.94.6.1"]');
  assert.ok(umbrella.limitations.includes(HOSTING_LIMITATIONS.unnamed_service), "an Amazon range with no named service says so");
  assert.deepEqual(addressesFromStored('["1.1.1.1","1.1.1.1"," 2.2.2.2 "]'), ["1.1.1.1", "2.2.2.2"]);
  const many = Array.from({ length: 40 }, (_, i) => `52.94.5.${i}`);
  const bounded = await d(many);
  assert.equal(bounded.networks.length, 16, "bounded per asset");
  assert.deepEqual([bounded.addresses_checked, bounded.addresses_total], [16, 40]);
  assert.ok(bounded.limitations.includes(HOSTING_LIMITATIONS.partial), "says only some addresses were checked");
  const hidden = await d([...Array.from({ length: 16 }, (_, i) => `192.0.2.${i}`), "104.16.0.1"]);
  assert.equal(hidden.status, "unattributed");
  assert.ok(hidden.limitations.includes(HOSTING_LIMITATIONS.partial), "an unchecked 17th address is not claimed");
  const summary = summariseHostingNetworks([cloud, edge, mixed, await d(null), await d('["192.0.2.1"]'), { status: "unavailable" }]);
  assert.equal(summary.assets, 6);
  assert.deepEqual(summary.by_provider.map((p) => [p.provider, p.count]), [["aws", 2], ["cloudflare", 2], ["azure", 1]]);
  assert.deepEqual([summary.other_networks, summary.no_address, summary.unavailable], [1, 1, 1]);
});

await test("the asset list and detail carry the network, per workspace, with no outbound call", async () => {
  const mod = await loadWorker();
  const db = buildDb();
  const env = makeEnv(db);
  const seed = await makeSeeder(db, mod);
  const call = makeCaller(mod.default, env);
  seed.user("uA", "a@a.co"); seed.user("uB", "b@b.co");
  await seed.session("sA", "uA", "tok-A"); await seed.session("sB", "uB", "tok-B");
  seed.workspace("wsA", "uA", "A"); seed.workspace("wsB", "uB", "B");
  seed.member("mA", "wsA", "uA", "owner"); seed.member("mB", "wsB", "uB", "owner");
  db.prepare("INSERT INTO domains (id, user_id, domain) VALUES ('dA','uA','alpha-net.co.uk')").run();
  const asset = (id, host, ips) => db.prepare(`INSERT INTO workspace_assets (id, workspace_id, domain_id, hostname, asset_type, source, first_seen, last_seen, status, ip_addresses, created_at, updated_at)
    VALUES (?, 'wsA', 'dA', ?, 'subdomain', 'dns_discovery', datetime('now'), datetime('now'), 'active', ?, datetime('now'), datetime('now'))`).run(id, host, ips);
  asset("a1", "www.alpha-net.co.uk", '["104.16.1.1"]');
  asset("a2", "mail.alpha-net.co.uk", '["192.0.2.10"]');
  asset("a3", "old.alpha-net.co.uk", null);
  asset("a4", "legacy.alpha-net.co.uk", "104.16.0.1, 192.0.2.1");
  asset("a5", "gone.alpha-net.co.uk", '["104.16.9.9"]');
  db.prepare("UPDATE workspace_assets SET status = 'inactive' WHERE id = 'a5'").run();
  const before = outbound;
  const list = await call("GET", "/api/workspaces/wsA/assets", "tok-A");
  assert.equal(list.status, 200);
  const byHost = Object.fromEntries(list.data.assets.map((a) => [a.hostname, a.hosting_network]));
  assert.equal(byHost["www.alpha-net.co.uk"].status, "attributed");
  assert.deepEqual(byHost["www.alpha-net.co.uk"].networks.map((n) => [n.provider, n.kind]), [["cloudflare", "edge"]]);
  assert.equal(byHost["mail.alpha-net.co.uk"].status, "unattributed");
  assert.equal(byHost["old.alpha-net.co.uk"].status, "no_address");
  assert.equal(byHost["legacy.alpha-net.co.uk"].status, "attributed");
  assert.equal(byHost["www.alpha-net.co.uk"].list_version, CLOUD_NETWORK_LIST.version);
  const s = list.data.hosting_summary;
  assert.deepEqual([s.assets, s.other_networks, s.no_address, s.unavailable], [4, 1, 1, 0], "the removed host is not counted");
  assert.equal(byHost["gone.alpha-net.co.uk"].status, "attributed", "its own row still shows its last addresses");
  assert.deepEqual(s.by_provider.map((p) => [p.provider, p.count]), [["cloudflare", 2]]);
  const detail = await call("GET", "/api/workspaces/wsA/assets/a1", "tok-A");
  assert.equal(detail.status, 200);
  assert.equal(detail.data.asset.hosting_network.status, "attributed");
  assert.equal(outbound, before, "no outbound request");
  const foreign = await call("GET", "/api/workspaces/wsA/assets/a1", "tok-B");
  assert.ok([403, 404].includes(foreign.status), "another workspace's owner is refused");
  assert.ok(!JSON.stringify(foreign.data ?? "").includes("104.16.1.1"));
});

await test("first use stays within Worker limits", async () => {
  const lookup = createNetworkLookup(CLOUD_NETWORK_LIST);
  const heap = process.memoryUsage().heapUsed;
  let t = performance.now();
  await lookup("104.16.1.1");
  const first = performance.now() - t;
  const mb = (process.memoryUsage().heapUsed - heap) / 1048576;
  t = performance.now();
  for (let i = 0; i < 1000; i++) await lookup(`104.16.${i % 250}.1`);
  const each = (performance.now() - t) / 1000;
  console.log(`  list ${CLOUD_NETWORK_LIST.count} ranges; first use ${first.toFixed(1)} ms, ~${Math.max(0, mb).toFixed(1)} MB; later lookups ${each.toFixed(3)} ms each`);
  assert.ok(first < 400, `first use ${first} ms`);
  assert.ok(each < 1, `lookup ${each} ms`);
});

console.log(`${passed} cloud-network scenarios passed`);
