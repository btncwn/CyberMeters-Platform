// Checks run against the lab worlds by scripts/validate-own-observation-discovery.js.
//
// The lab world must behave like the real services it stands in for, or every
// measurement taken with it is fiction; the first block pins that. The second
// block runs the real scan engine against each world and holds the invariants
// that already hold today. Gaps the lab measures but the product does not yet
// close are reported by scripts/lab/run-discovery-lab.mjs, not asserted here.
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createLabWorld } from "./lab-world.mjs";
import { runLabWorld } from "./lab-scan.mjs";
import { DELTA_SCANS, deltaAt, WORLDS } from "./worlds.mjs";

const json = (value) => JSON.stringify(value);
const parse = (value) => { try { return JSON.parse(value); } catch { return null; } };

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

  // ── Evidence: why each name is listed, measured separately ──────────────────
  // Hint, scope, DNS answer, service answer and finding are separate facts
  // for every name, recorded per workspace and per scan; nothing a page or a
  // script carried in a query string is kept.
  const host = (label) => (label ? `${label}.${WORLDS.alpha.domain}` : WORLDS.alpha.domain);
  const evidenceOf = (run, hostname, workspaceId = "ws_a") => parse(run.db.prepare(
    `SELECT alo.source_detail_json FROM asset_lifecycle_observations alo
       JOIN workspace_assets wa ON wa.id = alo.asset_id AND wa.workspace_id = alo.workspace_id
      WHERE wa.workspace_id = ? AND wa.hostname = ?
      ORDER BY alo.observed_at DESC LIMIT 1`).get(workspaceId, hostname)?.source_detail_json)?.evidence ?? null;
  const assetRow = (run, hostname, workspaceId = "ws_a") =>
    run.db.prepare("SELECT * FROM workspace_assets WHERE workspace_id = ? AND hostname = ?").get(workspaceId, hostname);
  const adminEvidence = evidenceOf(alphaRun, host("admin"));
  ok("lab alpha evidence: an admin page names the protocol and port that answered and the finding's measurement",
    json(adminEvidence?.service?.attempts?.[0]) === json({ protocol: "https", port: 443, outcome: "responded", status: 200 }) &&
      adminEvidence.findings.length > 0 &&
      adminEvidence.findings.every((finding) => finding.check_id && finding.check_version === "2026.10.1" && finding.measured?.kind !== "not_recorded"),
    json(adminEvidence));
  const v6Evidence = evidenceOf(alphaRun, host("v6only"));
  ok("lab alpha evidence: a name the certificate names is listed with that hint and its IPv6-only DNS answer",
    v6Evidence?.named_by?.includes("tls_certificate_name") &&
      v6Evidence.dns?.A?.outcome === "nodata" && json(v6Evidence.dns?.AAAA?.addresses) === json(["2a05:d014:9:1::6"]),
    json(v6Evidence));
  ok("lab alpha evidence: an IPv6 address is not taken as proof the service answers over IPv6",
    v6Evidence?.service?.address_family === "not_recorded" && v6Evidence.not_checked.some((gap) => gap.part === "service_ipv6"),
    json(v6Evidence?.not_checked));
  const appEvidence = evidenceOf(alphaRun, host("app"));
  ok("lab alpha evidence: every place a name was seen is kept — a header and a DNS name list",
    appEvidence?.named_by?.includes("csp_reference") && appEvidence.named_by.some((source) => ["dns_bruteforce", "dns_wordlist"].includes(source)),
    json(appEvidence?.named_by));
  const appSightings = parse(assetRow(alphaRun, host("app"))?.sightings_json);
  ok("lab alpha evidence: the asset row keeps first and last sighting per source from its first scan",
    Object.keys(appSightings?.sources || {}).length >= 2 && appSightings.recorded_since === assetRow(alphaRun, host("app")).first_seen,
    json(appSightings));
  ok("lab alpha evidence: a name only the customer listed says so",
    evidenceOf(alphaRun, host("listed-v6"))?.named_by?.includes("customer_list"), json(evidenceOf(alphaRun, host("listed-v6"))));
  ok("lab alpha evidence: a family whose lookup failed is kept as uncertain beside the address found",
    json(evidenceOf(alphaRun, host("halfv6"))?.dns?.uncertain) === json(["AAAA"]), json(evidenceOf(alphaRun, host("halfv6"))?.dns));
  const rootEvidence = evidenceOf(alphaRun, host(""));
  ok("lab alpha evidence: the domain itself carries its own DNS and web answer",
    json(rootEvidence?.named_by) === json(["scan_root"]) && rootEvidence.dns?.A?.outcome === "answer" &&
      rootEvidence.service?.attempts?.[0]?.protocol === "https" && rootEvidence.service.attempts[0].outcome === "responded",
    json(rootEvidence));
  const storedText = json(alphaRun.db.prepare("SELECT source_detail_json FROM asset_lifecycle_observations").all()) +
    json(alphaRun.db.prepare("SELECT sightings_json, redirect_to, metadata_json FROM workspace_assets").all());
  ok("lab alpha evidence: no query string, session value or page body is stored with the evidence",
    !/lab-session|session=|<html|<form/i.test(storedText), storedText.match(/.{0,40}(lab-session|session=|<html|<form).{0,40}/i)?.[0] ?? "");
  const { loadAssetEvidence } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "asset-evidence.js")).href);
  const adminView = await loadAssetEvidence(alphaRun.env, "ws_a", assetRow(alphaRun, host("admin")));
  ok("lab alpha evidence: the asset view states scope, DNS, the answering service, findings and what was not checked",
    adminView.status === "recorded" && adminView.scope?.state === "in_scope" && /verified with a DNS TXT record/.test(adminView.scope.label) &&
      adminView.dns?.status === "checked" && adminView.service?.attempts?.[0]?.label === "Answered with HTTP 200" &&
      adminView.findings?.items?.length > 0 && adminView.findings.items.every((finding) => finding.measured_label && finding.rule) &&
      adminView.not_checked.some((gap) => gap.part === "other_ports"),
    json(adminView));
  const foreignView = await loadAssetEvidence(alphaRun.env, "ws_elsewhere", assetRow(alphaRun, host("admin")));
  ok("lab alpha evidence: another workspace reading the same asset id gets no evidence",
    foreignView.status !== "recorded" && foreignView.dns?.status !== "checked", json(foreignView));

  // ── Workspaces sharing a domain never share assets or evidence ──────────────
  // Two workspaces of one owner on the same domain row: the first has a
  // customer list, the second none. Each scan writes and re-checks only its own
  // workspace's inventory.
  const shared = await runLabWorld({
    root, world: WORLDS.alpha, scans: 2, tenant: "s",
    linkedWorkspaces: [{ workspaceId: "ws_s_other" }],
    scanAs: (i) => (i === 0 ? "ws_s" : "ws_s_other"),
  });
  const names = (workspaceId) => shared.db.prepare("SELECT hostname FROM workspace_assets WHERE workspace_id = ? ORDER BY hostname").all(workspaceId).map((row) => row.hostname);
  const scansWriting = (workspaceId) => shared.db.prepare("SELECT DISTINCT scan_id FROM asset_lifecycle_observations WHERE workspace_id = ? ORDER BY scan_id").all(workspaceId).map((row) => row.scan_id);
  ok("lab shared domain: a name only one workspace listed never appears in the other's inventory",
    names("ws_s").includes(host("listed-v6")) && !names("ws_s_other").includes(host("listed-v6")),
    json({ first: names("ws_s").length, other: names("ws_s_other") }));
  ok("lab shared domain: each workspace's evidence comes only from its own scans",
    json(scansWriting("ws_s")) === json(["scan_s_1"]) && json(scansWriting("ws_s_other")) === json(["scan_s_2"]),
    json({ first: scansWriting("ws_s"), other: scansWriting("ws_s_other") }));
  const secondScanLog = shared.log.slice(...shared.scans[1].log_range);
  ok("lab shared domain: the other workspace's scan never asks about a name only the first listed",
    !secondScanLog.some((entry) => entry.name === host("listed-v6") || entry.host === host("listed-v6")),
    json(secondScanLog.filter((entry) => entry.name === host("listed-v6") || entry.host === host("listed-v6")).slice(0, 3)));

  // ── Change notifications: real changes, once ───────────────────────────────
  // Delta changes between scans (worlds.mjs). The owner has a paid plan, so
  // notifications are really sent — to the lab's stand-in email provider. The
  // third scan's steps are replayed the way a queue redelivery would.
  const { sendAssetChangeAlert } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "asset-alert-delivery.js")).href);
  const { upsertAssetInventory } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "asset-inventory.js")).href);
  const { runScanEngine, insertAdminSurfaceEvents } = await import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "scan-engine.js")).href);
  const replay = {};
  const delta = await runLabWorld({
    root, worldAt: deltaAt, scans: DELTA_SCANS, tenant: "d", subscription: "professional",
    linkedWorkspaces: [{ workspaceId: "ws_d_other" }],
    scanAs: (i) => (i === DELTA_SCANS - 1 ? "ws_d_other" : "ws_d"),
    env: { RESEND_API_KEY: "lab", ALERT_EMAIL_FROM: "alerts@lab.invalid" },
    afterScan: async (i, { env, scanId, workspaceId, domainId, domain }) => {
      if (i !== 2) return;
      const eventCount = () => env.cybermeters_db.prepare("SELECT COUNT(*) AS n FROM asset_events").first("n");
      replay.before = await eventCount();
      replay.engine = await runScanEngine(scanId, domainId, workspaceId, domain, env, { now: () => Date.now(), executionContext: "queue", trigger: "manual" }).catch((error) => ({ error: error.message }));
      const report = JSON.parse(await (await env.cybermeters_reports.get(`reports/${scanId}.json`)).text());
      await upsertAssetInventory(scanId, domainId, domain, report.modules, env, { currentReport: report, workspaceId });
      await insertAdminSurfaceEvents(scanId, domainId, report.modules.admin_surface_detection, env, { currentReport: report });
      await sendAssetChangeAlert(domainId, domain, scanId, env, "complete", { modules: report.modules });
      replay.after = await eventCount();
    },
  });
  const dScan = (n) => delta.scans[n - 1];
  const eventTypes = (n) => dScan(n).changes.events.map((event) => event.event_type);
  const changeEmails = (n) => dScan(n).emails.filter((email) => /^(?:🚨 |⚠ )?CyberMeters: /.test(email.subject || ""));
  const allChangeEmails = delta.scans.flatMap((scan, index) => changeEmails(index + 1).map((email) => ({ scan: scan.scan_id, ...email })));
  ok("lab delta: every scan completes and every request stays inside the lab",
    delta.scans.every((scan) => scan.status === "completed" && !scan.error) && delta.unexpected_hosts.length === 0,
    json({ scans: delta.scans.map((scan) => [scan.scan_id, scan.status, scan.error]), unexpected: delta.unexpected_hosts }));
  ok("lab delta: the first scan is the starting inventory — names recorded, nothing announced",
    eventTypes(1).length === 0 && dScan(1).changes.notification === null && changeEmails(1).length === 0 &&
      delta.db.prepare("SELECT COUNT(*) AS n FROM workspace_assets WHERE workspace_id = 'ws_d'").get().n >= 5,
    json(dScan(1).changes));
  ok("lab delta: a new name alone is an inventory event — recorded, not notified",
    json(eventTypes(2)) === json(["new_asset_discovered"]) && dScan(2).changes.events[0].severity === "info" &&
      dScan(2).changes.notification?.status === "skipped" && dScan(2).changes.notification?.error === "inventory_changes_only" &&
      changeEmails(2).length === 0,
    json(dScan(2).changes));
  const adminRecord = parse(delta.db.prepare("SELECT event_counts FROM asset_alert_records WHERE scan_id = 'scan_d_3'").get()?.event_counts)?._changes;
  const adminChange = adminRecord?.changes?.[0];
  const adminEmail = delta.log.find((entry) => entry.kind === "email" && /Management page now reachable/.test(entry.email?.subject || ""))?.email;
  ok("lab delta: a newly reachable management page is one notification",
    eventTypes(3).filter((type) => type === "admin_surface_detected").length === 1 &&
      dScan(3).changes.notification?.status === "sent" && changeEmails(3).length === 1 && Boolean(adminEmail),
    json({ events: eventTypes(3), notification: dScan(3).changes.notification, emails: dScan(3).emails }));
  ok("lab delta: the notification states before, now, time, evidence, why this severity and the recommended action",
    ["Before: Not reachable as phpMyAdmin in the previous scan (2026-10-02 10:00 UTC)", "Now: phpMyAdmin answered on admin.cmlab-delta.co.uk",
      "Observed: 2026-10-03 11:00 UTC", "Evidence: HTTPS port 443 answered with HTTP 200", "Why this severity:", "Recommended: Limit each admin interface"]
      .every((part) => adminEmail?.text?.includes(part)) &&
      adminEmail.text.includes("Also in the inventory: 1 new name (admin.cmlab-delta.co.uk)."),
    adminEmail?.text ?? "no email");
  ok("lab delta: severity, match confidence and reachability are kept apart, and reachable is not called a compromise",
    adminChange?.severity === "critical" && adminRecord?.severity === "critical" &&
      /matched on the page title \(high confidence\)/.test(adminChange?.evidence || "") &&
      /Reachable does not mean anyone has signed in/.test(adminChange?.severity_reason || "") &&
      !/\b(?:attacker|compromise(?:d)?|breach(?:ed)?)\b/i.test(adminEmail?.text || ""),
    json(adminChange));
  ok("lab delta: a redelivered scan and replayed steps add no event, record or email",
    replay.engine?.completed === true && replay.before === replay.after &&
      delta.db.prepare("SELECT COUNT(*) AS n FROM asset_alert_records WHERE scan_id = 'scan_d_3'").get().n === 1 &&
      allChangeEmails.filter((email) => email.scan === "scan_d_3").length === 1,
    json({ replay, emails: allChangeEmails }));
  const adminEventsFor = (n, label) => dScan(n).changes.events
    .filter((event) => event.event_type === "admin_surface_detected" && event.hostname === `${label}.cmlab-delta.co.uk`);
  ok("lab delta: a management page that stays reachable is not announced again",
    [4, 5, 6, 7, 8, 9].every((n) => adminEventsFor(n, "admin").length === 0), json([4, 5, 6, 7, 8, 9].map((n) => eventTypes(n))));
  ok("lab delta: a DNS failure is stated, and is neither a disappearance nor a return",
    dScan(4).incomplete_modules.includes("asset_exposure:dns_resolution_unavailable") &&
      eventTypes(4).length === 0 && changeEmails(4).length === 0 &&
      [4, 5].every((n) => !dScan(n).changes.events.some((event) => event.hostname === "app.cmlab-delta.co.uk")),
    json([4, 5].map((n) => ({ incomplete: dScan(n).incomplete_modules, events: dScan(n).changes.events }))));
  ok("lab delta: a change right after a partial scan is compared with the last complete scan and announced once",
    adminEventsFor(5, "grafana").length === 1 && adminEventsFor(5, "admin").length === 0 &&
      changeEmails(5).length === 1 && /^⚠ CyberMeters: Management page now reachable/.test(changeEmails(5)[0].subject) &&
      [6, 7, 8, 9].every((n) => adminEventsFor(n, "grafana").length === 0),
    json({ events: dScan(5).changes.events, emails: dScan(5).emails }));
  ok("lab delta: a name gone for one or two scans is not yet removed; three checks over two days confirm it, as an inventory event",
    [6, 7].every((n) => !eventTypes(n).includes("asset_no_longer_seen")) &&
      json(eventTypes(8)) === json(["asset_no_longer_seen"]) &&
      dScan(8).changes.notification?.error === "inventory_changes_only" && changeEmails(8).length === 0,
    json([6, 7, 8].map((n) => ({ events: eventTypes(n), notification: dScan(n).changes.notification }))));
  ok("lab delta: a name confirmed gone that answers again is one notification",
    json(eventTypes(9)) === json(["asset_reappeared"]) && changeEmails(9).length === 1 &&
      /A name confirmed gone answers again/.test(changeEmails(9)[0].subject),
    json({ events: eventTypes(9), emails: dScan(9).emails }));
  ok("lab delta: another workspace's first scan of the same domain is its own starting inventory",
    dScan(10).workspace_id === "ws_d_other" && eventTypes(10).length === 0 && dScan(10).changes.notification === null && changeEmails(10).length === 0,
    json(dScan(10).changes));
  ok("lab delta: change notifications go only to the workspace whose scan found the change — three in ten scans",
    allChangeEmails.length === 3 &&
      delta.db.prepare("SELECT DISTINCT workspace_id FROM asset_alert_records").all().every((row) => row.workspace_id === "ws_d") &&
      delta.db.prepare("SELECT COUNT(*) AS n FROM asset_events WHERE workspace_id = 'ws_d_other'").get().n === 0,
    json(allChangeEmails));

  const wildcard = await runLabWorld({ root, world: WORLDS.bravo, scans: 1 });
  ok("lab bravo: a zone that answers every name adds no guessed names", wildcard.inventory.false_positive.length === 0, json(wildcard.inventory.false_positive));
  const again = await runLabWorld({ root, world: WORLDS.bravo, scans: 1 });
  ok("lab: the same world measures the same inventory twice",
    json(again.inventory.rows.map((row) => [row.hostname, row.source])) === json(wildcard.inventory.rows.map((row) => [row.hostname, row.source])));
}
