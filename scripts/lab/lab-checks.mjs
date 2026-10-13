// Checks run against the lab worlds by scripts/validate-own-observation-discovery.js.
//
// The lab world must behave like the real services it stands in for, or every
// measurement taken with it is fiction; the first block pins that. The second
// block runs the real scan engine against each world and holds the invariants
// that already hold today. Gaps the lab measures but the product does not yet
// close are reported by scripts/lab/run-discovery-lab.mjs, not asserted here.
import { createLabWorld } from "./lab-world.mjs";
import { runLabWorld } from "./lab-scan.mjs";
import { WORLDS } from "./worlds.mjs";

const json = (value) => JSON.stringify(value);

export async function runLabChecks({ ok, root }) {
  // ── The stand-in internet answers like the real one ─────────────────────────
  const lab = createLabWorld(WORLDS.alpha, { root });
  const dns = (name, type) => lab.answerDns(name, type);
  const types = (response) => (response.Answer || []).map((record) => record.type);
  const a = (label) => `${label}.cmlab-alpha.co.uk`;

  const dual = [dns(a("ns1"), "A"), dns(a("ns1"), "AAAA")];
  ok("lab: a dual-stack name answers both families", dual.every((r) => r.Status === 0 && r.Answer.length === 1), json(dual));
  const v6 = [dns(a("v6only"), "A"), dns(a("v6only"), "AAAA")];
  ok("lab: an IPv6-only name is NODATA for A, with an SOA, and answers AAAA",
    v6[0].Status === 0 && v6[0].Answer.length === 0 && v6[0].Authority?.[0]?.type === 6 && v6[1].Answer?.[0]?.data === "2a05:d014:9:1::6", json(v6));
  const nx = dns(a("gone"), "A");
  ok("lab: a name that does not exist is NXDOMAIN with an SOA", nx.Status === 3 && nx.Authority?.[0]?.type === 6, json(nx));
  const alias = dns(a("portal"), "A");
  ok("lab: an alias answers with the CNAME then the target's address", json(types(alias)) === json([5, 1]) && alias.Answer[1].name === "cmlab-alpha.apphost-lab.net", json(alias));
  const loop = dns(a("loop1"), "A");
  ok("lab: an alias loop fails like a resolver does", loop.Status === 2, json(loop));
  const wild = [dns(`pr-9.${a("preview")}`, "A"), dns(`pr-9.${a("preview")}`, "AAAA"), dns(a("preview"), "A")];
  ok("lab: a wildcard answers names below it and its parent exists without data",
    wild[0].Status === 0 && wild[0].Answer.length === 1 && wild[1].Status === 0 && wild[1].Answer.length === 0 && wild[2].Status === 0 && wild[2].Answer.length === 0, json(wild));
  ok("lab: a SERVFAIL fault", dns(a("flaky"), "A").Status === 2);
  let timedOut = false;
  try { dns(a("slow"), "A"); } catch (error) { timedOut = error?.name === "TimeoutError"; }
  ok("lab: a timeout fault throws like an expired request", timedOut);
  ok("lab: every DoH packet carries the header flags", ["TC", "RD", "RA", "AD", "CD"].every((flag) => typeof nx[flag] === "boolean"), json(nx));
  let refused = false;
  try { await lab.fetch("https://unrelated.example.org/"); } catch { refused = true; }
  ok("lab: a request to anything outside the world fails closed and is recorded",
    refused && lab.log.at(-1)?.kind === "unexpected", json(lab.log.at(-1)));
  const blocked = createLabWorld(WORLDS.alpha, { root, egress: "blocked" });
  let blockedNvd = false;
  try { await blocked.fetch("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=nginx"); } catch { blockedNvd = true; }
  ok("lab: blocked egress refuses outside data services and records the attempt",
    blockedNvd && blocked.log.at(-1)?.kind === "outside_data" && blocked.log.at(-1)?.outcome === "blocked", json(blocked.log.at(-1)));

  // ── The real engine against each world ──────────────────────────────────────
  for (const world of Object.values(WORLDS)) {
    const run = await runLabWorld({ root, world, scans: 1 });
    const scan = run.scans[0];
    ok(`lab ${world.name}: the scan completes and stores its report`, scan.status === "completed" && scan.report_stored && !scan.error, json({ status: scan.status, error: scan.error }));
    ok(`lab ${world.name}: no out-of-scope name enters the inventory`, run.inventory.out_of_scope_admitted.length === 0, json(run.inventory.out_of_scope_admitted));
    ok(`lab ${world.name}: every request stays inside the lab`, run.unexpected_hosts.length === 0, json(run.unexpected_hosts));
    ok(`lab ${world.name}: discovery asks DNS through the lab resolver only`, scan.requests.dns_questions > 0, json(scan.requests.by_kind));
  }
  // ── Discovery accuracy: both address families, nothing unconfirmed ───────────
  const alphaRun = await runLabWorld({ root, world: WORLDS.alpha, scans: 1 });
  const inv = alphaRun.inventory;
  ok("lab alpha: every real, named host is found — IPv6-only names included", inv.missed.length === 0, json(inv.missed));
  ok("lab alpha: no name DNS never answered for is listed (stale links, dangling SRV targets)", inv.false_positive.length === 0, json(inv.false_positive));
  ok("lab alpha: dual-stack and IPv6-only names keep the addresses of each family",
    Object.values(inv.families).every((family) => family.A.ok && family.AAAA.ok), json(inv.families));
  ok("lab alpha: an alias target outside the domain is never an asset",
    !inv.rows.some((row) => row.hostname === "cmlab-alpha.apphost-lab.net"), json(inv.rows.map((row) => row.hostname)));
  const alphaScan = alphaRun.scans[0];
  ok("lab alpha: names whose lookups failed are counted as unknown, not as absent",
    alphaScan.discovery.customer?.lookup_failed === 2 && alphaScan.discovery.customer?.not_found === 1, json(alphaScan.discovery.customer));
  const report = JSON.parse(alphaRun.r2.store.get("reports/scan_a_1.json"));
  const budget = report.modules.subdomains.discovery_budget;
  ok("lab alpha: every discovery question is charged to one budget that is never exceeded",
    budget?.total === 786 && budget.spent > 0 && budget.spent <= budget.total &&
      Object.values(budget.by_source).reduce((a, b) => a + b, 0) === budget.spent, json(budget));
  const halfv6 = report.modules.subdomains.customer_hostnames.confirmed.find((row) => row.hostname === "halfv6.cmlab-alpha.co.uk");
  ok("lab alpha: a name whose AAAA lookup fails keeps its IPv4 address and states the uncertainty",
    json(halfv6?.ip_addresses) === json(["34.120.10.10"]) && json(halfv6?.dns?.uncertain) === json(["AAAA"]), json(halfv6));
  const charlieRun = await runLabWorld({ root, world: WORLDS.charlie, scans: 1 });
  ok("lab charlie: every listed name DNS answers for is found, IPv6-only names included",
    charlieRun.inventory.missed.length === 0, json(charlieRun.inventory.missed.slice(0, 5)));
  const charlieDepth = charlieRun.scans[0].discovery.depth;
  ok("lab charlie: guesses the budget left unasked are stated, not dropped",
    charlieDepth.executed === true && (charlieDepth.not_asked === 0 || charlieDepth.incomplete_reason === "question_budget_reached"), json(charlieDepth));

  // ── Outside data: a scan needs none of it (runtime audit) ───────────────────
  // The same world scanned with every outside data service answering and with
  // every one refused: the report, the score and the findings must not move, no
  // vulnerability-data service may be asked at all, and the only outside
  // service asked — the registry's RDAP — must be optional.
  const VULNERABILITY_DATA = new Set(["nvd", "epss", "kev", "osv"]);
  const open = await runLabWorld({ root, world: WORLDS.alpha, egress: "open", scans: 1 });
  const blockedRun = await runLabWorld({ root, world: WORLDS.alpha, egress: "blocked", scans: 1 });
  const openScan = open.scans[0];
  const blockedScan = blockedRun.scans[0];
  for (const [label, run] of [["open", open], ["blocked", blockedRun]]) {
    const asked = Object.entries(run.scans[0].requests.outside_data || {})
      .filter(([service]) => VULNERABILITY_DATA.has(service));
    ok(`lab alpha (outside data ${label}): no vulnerability-data service is asked`, asked.length === 0, json(run.scans[0].requests.outside_data));
  }
  ok("lab alpha (outside data blocked): the scan completes, stores its report and publishes its score",
    blockedScan.status === "completed" && blockedScan.report_stored && Number.isFinite(blockedScan.score), json({ status: blockedScan.status, score: blockedScan.score }));
  ok("lab alpha: refusing outside data changes neither the score nor the findings",
    blockedScan.score === openScan.score && json(blockedScan.finding_types) === json(openScan.finding_types),
    json({ open: [openScan.score, openScan.finding_types.length], blocked: [blockedScan.score, blockedScan.finding_types.length] }));
  const blockedReport = JSON.parse(blockedRun.r2.store.get("reports/scan_a_1.json"));
  const whois = blockedReport.modules.whois_intelligence;
  ok("lab alpha (outside data blocked): an unanswered registry is reported as unavailable, optional and without request URLs",
    whois?.optional === true && whois?.outcome === "unavailable" && !whois?.error &&
      Array.isArray(whois?.registries_asked) && whois.registries_asked.length > 0 &&
      !/https?:\/\//.test(json(whois)), json(whois));
  ok("lab alpha (outside data blocked): registration data never decides whether the scan completed",
    json(blockedScan.incomplete_modules) === json(openScan.incomplete_modules) &&
      !blockedScan.incomplete_modules.some((entry) => entry.startsWith("whois_intelligence")) &&
      blockedReport.monitoring_states.signals.registration_data?.state === "signal_unavailable" &&
      blockedReport.monitoring_states.signals.registration_data?.optional === true,
    json({ open: openScan.incomplete_modules, blocked: blockedScan.incomplete_modules, registration: blockedReport.monitoring_states.signals.registration_data }));
  ok("lab alpha: the report states its check pack, and vulnerability matching as not part of it",
    blockedReport.check_pack?.version === "2026.10.1" &&
      blockedReport.modules.cve_intelligence?.outcome === "not_in_check_pack" &&
      blockedReport.modules.known_exploited_vulnerabilities?.outcome === "not_in_check_pack" &&
      !("vulnerability_intelligence" in blockedReport.monitoring_states.signals),
    json({ check_pack: blockedReport.check_pack?.version, cve: blockedReport.modules.cve_intelligence?.outcome }));
  ok("lab alpha: every finding names the check and check-pack version that produced it",
    blockedReport.findings.length > 0 && blockedReport.findings.every((finding) => finding.check?.version === "2026.10.1" && finding.check?.check_id),
    json(blockedReport.findings.filter((finding) => !finding.check).map((finding) => finding.id)));

  const wildcard = await runLabWorld({ root, world: WORLDS.bravo, scans: 1 });
  ok("lab bravo: a zone that answers every name adds no guessed names", wildcard.inventory.false_positive.length === 0, json(wildcard.inventory.false_positive));
  const again = await runLabWorld({ root, world: WORLDS.bravo, scans: 1 });
  ok("lab: the same world measures the same inventory twice",
    json(again.inventory.rows.map((row) => [row.hostname, row.source])) === json(wildcard.inventory.rows.map((row) => [row.hostname, row.source])));
}
