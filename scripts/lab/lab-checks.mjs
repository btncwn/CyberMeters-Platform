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
  const wildcard = await runLabWorld({ root, world: WORLDS.bravo, scans: 1 });
  ok("lab bravo: a zone that answers every name adds no guessed names", wildcard.inventory.false_positive.length === 0, json(wildcard.inventory.false_positive));
  const again = await runLabWorld({ root, world: WORLDS.bravo, scans: 1 });
  ok("lab: the same world measures the same inventory twice",
    json(again.inventory.rows.map((row) => [row.hostname, row.source])) === json(wildcard.inventory.rows.map((row) => [row.hostname, row.source])));
}
