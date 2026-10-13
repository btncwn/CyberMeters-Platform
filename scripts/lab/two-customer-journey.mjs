// Two customers, end to end, through the Worker's own routes.
//
// Each customer signs up, verifies their email from the message the product
// sent, signs in, creates a workspace, adds their domain, publishes the DNS
// record the product asked for and verifies it, starts a scan, reads the
// evidence for what was found, is notified when a management tool appears on
// their estate, takes the case, marks it fixed, is shown the fix confirmed by
// the next scan, and sees the case come back when the tool does. A third
// person tries to use the first customer's domain and data.
//
// Everything a customer does goes through worker.default.fetch with the
// session the product issued; scans go through the real queue consumer and
// scan engine against lab worlds. The only stand-ins are the lab's: DNS, the
// websites, the TLS collector, the email provider and the breached-password
// service. Screens are not exercised here.
import path from "node:path";
import { pathToFileURL } from "node:url";
import { createLabWorld, DNS_RESOLVER_HOSTS, EMAIL_PROVIDER_HOST, outsideDataLabel } from "./lab-world.mjs";
import { buildLoadDb, compressedR2, meteredD1, meter, virtualClock } from "./load-lab.mjs";

const DAY = 86_400_000;
const page = (title, extra = "") => `<!doctype html><html><head><title>${title}</title></head><body>${extra}</body></html>`;
const PHPMYADMIN = { status: 200, body: page("phpMyAdmin", '<form><input type="password" name="pma_password"></form>') };

// One small business's domain. Phase by phase: as found; a management tool
// appears; the tool's host now sends visitors to the main site; the tool is back.
export function journeyWorld(domain, octet, { phase = 0, txt = [] } = {}) {
  const at = (label) => (label ? `${label}.${domain}` : domain);
  const ip = (k) => `34.126.${octet}.${k}`;
  const admin = [null, PHPMYADMIN, { status: 302, headers: { location: `https://${domain}/` } }, PHPMYADMIN][phase];
  return {
    name: `journey-${octet}`,
    domain,
    zones: {
      [at()]: { SOA: true, A: [ip(1)], NS: [at("ns1")], MX: ["10 " + at("mail")], TXT: ["v=spf1 mx -all"] },
      [at("_dmarc")]: { TXT: ["v=DMARC1; p=quarantine"] },
      ...(txt.length ? { [at("_cybermeters")]: { TXT: txt } } : {}),
      [at("ns1")]: { A: [ip(2)] },
      [at("mail")]: { A: [ip(3)] },
      [at("www")]: { CNAME: at() },
      [at("app")]: { A: [ip(4)] },
      ...(admin ? { [at("admin")]: { A: [ip(5)] } } : {}),
    },
    sites: {
      [at()]: { routes: { "/": { status: 200, headers: { server: "nginx" }, body: page(domain) } }, fallback: { status: 404, body: "" } },
      [at("www")]: { fallback: { status: 301, headers: { location: `https://${domain}/` } } },
      [at("app")]: { fallback: { status: 200, body: page("App") } },
      ...(admin ? { [at("admin")]: { fallback: admin } } : {}),
      [at("mail")]: { refuse: true },
      [at("ns1")]: { refuse: true },
    },
    defaultSite: { status: 404, body: "" },
    tls: { [domain]: { days: 80, dnsNames: [domain, at("www")] } },
  };
}

export async function runTwoCustomerJourney({ root, startAt = "2026-10-20T09:00:00.000Z" } = {}) {
  const clock = virtualClock(Date.parse(startAt));
  const realFetch = globalThis.fetch;
  const realConsole = { log: console.log, info: console.info, warn: console.warn, error: console.error };
  const db = await buildLoadDb(root, clock);
  const r2 = compressedR2();
  const log = [];
  const steps = [];
  const step = (customer, name, ok, detail = null) => { steps.push({ customer, step: name, ok: Boolean(ok), detail }); return ok; };

  // ── The stand-in internet ────────────────────────────────────────────────
  const estates = {
    a: { domain: "cmlab-golf.co.uk", octet: 1, phase: 0, txt: [] },
    b: { domain: "cmlab-hotel.co.uk", octet: 2, phase: 0, txt: [] },
  };
  const labs = new Map();
  const labFor = (estate) => {
    const key = `${estate.domain}|${estate.phase}|${estate.txt.join(",")}`;
    if (!labs.has(key)) {
      const lab = createLabWorld(journeyWorld(estate.domain, estate.octet, estate), { root, log });
      lab.setClock(() => Date.now());
      labs.set(key, lab);
    }
    return labs.get(key);
  };
  let currentEstate = null;
  const estateOf = (name) => Object.values(estates).find((e) => name === e.domain || String(name).endsWith(`.${e.domain}`)) || null;
  const breachedStandIn = () => new Response("0018A45C4D1DEF81644B54AB7F969B88D65:0\n", { status: 200, headers: { "content-type": "text/plain" } });
  globalThis.fetch = async (input, init) => {
    const url = new URL(String(input instanceof Request ? input.url : input));
    if (url.hostname === "api.pwnedpasswords.com") {
      log.push({ at: Date.now(), host: url.hostname, kind: "password_screening", outcome: "not_found" });
      return breachedStandIn();
    }
    // Names under a customer's domain go to that customer's world; questions
    // about any other name, the registry and the email provider go to the
    // world of the scan in progress, which answers them as the lab does.
    const shared = DNS_RESOLVER_HOSTS.includes(url.hostname) || outsideDataLabel(url.hostname) || url.hostname === EMAIL_PROVIDER_HOST;
    const estate = estateOf(url.searchParams.get("name") || url.hostname) || (shared ? currentEstate || estates.a : null);
    if (!estate) {
      log.push({ at: Date.now(), host: url.hostname, kind: "unexpected", outcome: "refused" });
      throw new TypeError(`journey lab: no route to ${url.hostname}`);
    }
    return labFor(estate).fetch(input, init);
  };
  const probe = {
    async fetch(url, init) {
      let host = null;
      try { host = JSON.parse(init?.body || "{}")?.targets?.[0]?.hostname; } catch { host = null; }
      return labFor(estateOf(host) || estates.a).probe.fetch(url, init);
    },
  };

  // ── The queue: every message is delivered once, in order, to the real consumer ─
  const queue = [];
  const env = {
    cybermeters_db: meteredD1(db, meter()),
    cybermeters_reports: r2,
    SCAN_QUEUE: { send: async (body) => { queue.push(body); } },
    NETWORK_PROBE: probe,
    SCAN_DISPATCH_MODE: "queue",
    SCHEDULED_DISPATCH_MODE: "queue",
    SCAN_CAPACITY_MODE: "legacy",
    SCAN_SUBREQUEST_LIMIT: "200",
    APP_VERSION: "journey-lab",
    ALLOWED_ORIGIN: "https://app.cybermeters.com",
    FRONTEND_URL: "https://app.cybermeters.com",
    RESEND_API_KEY: "lab",
    ALERT_EMAIL_FROM: "alerts@lab.invalid",
    HELLO_EMAIL_FROM: "hello@lab.invalid",
    SAFE_EMAIL_FROM: "hello@lab.invalid",
  };
  const src = (...p) => pathToFileURL(path.join(root, "workers", "scan-api", "src", ...p)).href;
  const worker = await import(src("index.js"));
  const { handleScanDispatchBatch } = await import(src("engines", "scan-dispatch.js"));
  const outcomes = [];
  const drainQueue = async () => {
    while (queue.length) {
      const body = queue.shift();
      const decision = {};
      currentEstate = estateOf(body.domain);
      clock.flow();
      await handleScanDispatchBatch({ queue: "cybermeters-scan-dispatch", messages: [{ id: body.request_id, body, attempts: 1, ack() { decision.action = "ack"; }, retry() { decision.action = "retry"; } }] },
        env, {}, { onScheduledScanSettled: worker.settleScheduledQueueScan });
      clock.freeze();
      currentEstate = null;
      outcomes.push({ scan_id: body.scan_id, ...decision });
    }
  };

  // ── Calling the API as a person would ────────────────────────────────────
  const call = async (who, method, route, body) => {
    clock.flow();
    const waits = [];
    const response = await worker.default.fetch(new Request(`https://api.cybermeters.com${route}`, {
      method,
      redirect: "manual",
      headers: { ...(who?.token ? { Authorization: `Bearer ${who.token}` } : {}), ...(body ? { "Content-Type": "application/json" } : {}), "CF-Connecting-IP": who?.ip || "198.51.100.10" },
      body: body ? JSON.stringify(body) : undefined,
    }), env, { waitUntil: (p) => waits.push(p), passThroughOnException() {} });
    for (const p of waits) await p.catch(() => {});
    clock.freeze();
    let json = null;
    try { json = await response.clone().json(); } catch { json = null; }
    return { status: response.status, body: json, location: response.headers.get("location") };
  };
  const emailsTo = (address) => log.filter((entry) => entry.kind === "email" && [].concat(entry.email?.to || []).includes(address)).map((entry) => entry.email);

  const people = {
    a: { label: "a", name: "Golf Owner", email: "owner@cmlab-golf.co.uk", ip: "198.51.100.21", estate: estates.a },
    b: { label: "b", name: "Hotel Owner", email: "owner@cmlab-hotel.co.uk", ip: "198.51.100.22", estate: estates.b },
    c: { label: "c", name: "Someone Else", email: "someone@cmlab-other.co.uk", ip: "198.51.100.23", estate: null },
  };
  const password = "lab-journey-passphrase-7341";

  for (const level of Object.keys(realConsole)) console[level] = () => {};
  try {
    // ── Sign-up, email verification, sign-in, workspace, domain ─────────────
    for (const who of [people.a, people.b, people.c]) {
      const signup = await call(who, "POST", "/api/auth/signup", { email: who.email, password, name: who.name });
      step(who.label, "sign up", signup.status === 201, signup.status);
      const verifyMail = emailsTo(who.email).find((mail) => /Verify your CyberMeters email/.test(mail.subject || ""));
      const link = verifyMail?.text?.match(/https:\/\/\S+\/api\/auth\/verify-email\?token=\S+/)?.[0];
      step(who.label, "verification email received", Boolean(link));
      const verified = link ? await call(null, "GET", new URL(link).pathname + new URL(link).search) : null;
      step(who.label, "email verified from the link", db.prepare("SELECT email_verified FROM users WHERE email = ?").get(who.email)?.email_verified === 1, verified?.location);
      const login = await call(who, "POST", "/api/auth/login", { email: who.email, password });
      who.token = login.body?.token;
      step(who.label, "signed in", login.status === 200 && Boolean(who.token), login.status);
      const ws = await call(who, "POST", "/api/workspaces", { name: `${who.name}'s workspace` });
      who.workspaceId = ws.body?.workspace?.id;
      step(who.label, "workspace created with a trial", ws.status === 201 &&
        db.prepare("SELECT subscription_status FROM subscriptions s JOIN users u ON u.id = s.owner_user_id WHERE u.email = ?").get(who.email)?.subscription_status === "trialing", ws.status);
    }
    for (const who of [people.a, people.b]) {
      const added = await call(who, "POST", `/api/workspaces/${who.workspaceId}/domains`, { domain: who.estate.domain });
      who.domainId = added.body?.domain?.domain_id;
      step(who.label, "domain added", added.status === 200 || added.status === 201, added.status);
      const before = await call(who, "POST", "/api/scan", { domain: who.estate.domain, workspace_id: who.workspaceId });
      step(who.label, "a scan before verification is refused", before.status === 403 && before.body?.error === "domain_verification_required", before.status);
      const started = await call(who, "POST", `/api/domains/${who.domainId}/verification`, { workspace_id: who.workspaceId });
      const record = started.body?.dns_txt || started.body?.methods?.dns_txt || started.body?.instructions?.dns_txt || null;
      const value = record?.value || (started.body?.token ? `cybermeters-verification=${started.body.token}` : null);
      step(who.label, "verification record issued", started.status === 200 && Boolean(value), started.status);
      who.estate.txt = [value];
      const verified = await call(who, "POST", `/api/domains/${who.domainId}/verify`, { workspace_id: who.workspaceId });
      step(who.label, "domain verified from DNS", verified.status === 200 && verified.body?.verification_status === "verified", verified.body?.outcome ?? verified.status);
    }

    // ── Someone else claims the first customer's domain ──────────────────────
    {
      const c = people.c;
      const added = await call(c, "POST", `/api/workspaces/${c.workspaceId}/domains`, { domain: estates.a.domain });
      const cDomainId = added.body?.domain?.domain_id;
      await call(c, "POST", `/api/domains/${cDomainId}/verification`, { workspace_id: c.workspaceId });
      const verify = await call(c, "POST", `/api/domains/${cDomainId}/verify`, { workspace_id: c.workspaceId });
      const scan = await call(c, "POST", "/api/scan", { domain: estates.a.domain, workspace_id: c.workspaceId });
      step("c", "another person cannot verify or scan a domain whose DNS they do not control",
        verify.body?.verification_status !== "verified" && scan.status === 403 && scan.body?.error === "domain_verification_required" &&
          db.prepare("SELECT COUNT(*) AS n FROM scans WHERE workspace_id = ?").get(c.workspaceId).n === 0,
        { verify: verify.body?.verification_status ?? verify.status, scan: scan.status });
    }

    // ── Day by day: first scan, a change, the fix, the return ────────────────
    const scanAll = async (label) => {
      for (const who of [people.a, people.b]) {
        const started = await call(who, "POST", "/api/scan", { domain: who.estate.domain, workspace_id: who.workspaceId });
        who.lastScan = started.body?.scan_id;
        step(who.label, `${label}: scan queued`, started.status === 202 && Boolean(who.lastScan), started.status);
      }
      await drainQueue();
      for (const who of [people.a, people.b]) {
        const row = db.prepare("SELECT status, scan_quality FROM scans WHERE id = ?").get(who.lastScan);
        step(who.label, `${label}: scan completed`, row?.status === "completed", row);
      }
    };
    const caseOf = async (who) => {
      const listed = await call(who, "GET", `/api/workspaces/${who.workspaceId}/managed-cases`);
      const cases = listed.body?.cases || listed.body?.managed_cases || [];
      return cases.find((row) => (row.finding_id || row.source_finding_type) === "asset_exposure_sensitive_tool") || null;
    };

    await scanAll("first scan");
    for (const who of [people.a, people.b]) {
      const assets = await call(who, "GET", `/api/workspaces/${who.workspaceId}/assets`);
      const app = (assets.body?.assets || []).find((asset) => asset.hostname === `app.${who.estate.domain}`);
      const detail = app ? await call(who, "GET", `/api/workspaces/${who.workspaceId}/assets/${app.id}`) : null;
      const evidence = detail?.body?.evidence;
      step(who.label, "an asset is listed with its evidence (scope, DNS answer, the service that answered)",
        evidence?.status === "recorded" && evidence.scope?.state === "in_scope" && evidence.dns?.status === "checked" && evidence.service?.attempts?.length > 0,
        evidence ? { scope: evidence.scope?.state, dns: evidence.dns?.status, service: evidence.service?.attempts?.[0]?.label } : assets.status);
    }

    clock.set(clock.now() + DAY);
    people.a.estate.phase = 1;
    people.b.estate.phase = 1;
    await scanAll("management tool appears");
    for (const who of [people.a, people.b]) {
      const mails = emailsTo(who.email).filter((mail) => /Management page now reachable/.test(mail.subject || ""));
      step(who.label, "notified once that a management page became reachable, on their own domain",
        mails.length === 1 && mails[0].text.includes(`admin.${who.estate.domain}`), mails.map((mail) => mail.subject));
      who.case = await caseOf(who);
      step(who.label, "a case is open for the exposed tool", who.case && ["open", "triage"].includes(who.case.status), who.case?.status);
      const assigned = await call(who, "POST", `/api/workspaces/${who.workspaceId}/managed-cases/${who.case?.id}/assign`, { owner_type: "team", owner_ref: "IT" });
      const working = await call(who, "POST", `/api/workspaces/${who.workspaceId}/managed-cases/${who.case?.id}/transition`, { status: "remediation_in_progress" });
      const done = await call(who, "POST", `/api/workspaces/${who.workspaceId}/managed-cases/${who.case?.id}/transition`, { status: "verification_requested", action: "fix_completed" });
      const selfClose = await call(who, "POST", `/api/workspaces/${who.workspaceId}/managed-cases/${who.case?.id}/transition`, { status: "resolved" });
      step(who.label, "takes the case, names an owner, marks the fix done — and cannot close it by saying so",
        assigned.status === 200 && working.status === 200 && done.status === 200 && selfClose.status === 400 &&
          (await caseOf(who))?.status === "verification_requested",
        { assigned: assigned.status, working: working.status, done: done.status, selfClose: selfClose.status });
    }

    clock.set(clock.now() + DAY);
    people.a.estate.phase = 2;
    people.b.estate.phase = 2;
    await scanAll("fix in place");
    for (const who of [people.a, people.b]) {
      const after = await caseOf(who);
      const history = await call(who, "GET", `/api/workspaces/${who.workspaceId}/managed-cases/${who.case?.id}`);
      const events = history.body?.events || history.body?.case?.events || [];
      const verifiedEvent = events.find((event) => event.action === "verified_resolved");
      const detail = typeof verifiedEvent?.detail_json === "string" ? JSON.parse(verifiedEvent.detail_json) : verifiedEvent?.detail;
      step(who.label, "the next scan re-tests the host and closes the case with dated evidence",
        after?.status === "resolved" && verifiedEvent?.actor_type === "system" &&
          detail?.verification_evidence?.verification_method === "rescan" && Boolean(detail?.verification_evidence?.observed_at),
        { status: after?.status, actor: verifiedEvent?.actor_type, method: detail?.verification_evidence?.verification_method });
    }

    clock.set(clock.now() + DAY);
    people.a.estate.phase = 3;
    people.b.estate.phase = 3;
    await scanAll("tool returns");
    for (const who of [people.a, people.b]) {
      const back = await caseOf(who);
      step(who.label, "the tool coming back reopens the case and keeps its history",
        back?.id === who.case?.id && Number(back?.reopened_count) === 1 && !["resolved", "closed"].includes(back?.status),
        { id: back?.id === who.case?.id, status: back?.status, reopened: back?.reopened_count });
    }

    // ── Each customer sees only their own ───────────────────────────────────
    const a = people.a, b = people.b, c = people.c;
    const probes = [
      ["assets", await call(b, "GET", `/api/workspaces/${a.workspaceId}/assets`)],
      ["cases", await call(b, "GET", `/api/workspaces/${a.workspaceId}/managed-cases`)],
      ["scan", await call(b, "GET", `/api/scans/${a.lastScan}`)],
      ["case transition", await call(c, "POST", `/api/workspaces/${a.workspaceId}/managed-cases/${a.case?.id}/transition`, { status: "risk_accepted", reason: "not mine" })],
    ];
    step("b", "another customer reading the first customer's assets, cases or scan is refused, and cannot act on a case",
      probes.every(([, response]) => [401, 403, 404].includes(response.status)), probes.map(([what, response]) => [what, response.status]));
    const aMail = emailsTo(a.email).map((mail) => `${mail.subject} ${mail.text}`).join("\n");
    const bMail = emailsTo(b.email).map((mail) => `${mail.subject} ${mail.text}`).join("\n");
    step("both", "no message to one customer names the other's domain",
      !aMail.includes(b.estate.domain) && !bMail.includes(a.estate.domain) && emailsTo(c.email).every((mail) => !/Management page/.test(mail.subject || "")));
    const crossRows = db.prepare(`SELECT COUNT(*) AS n FROM asset_events e JOIN workspace_domains wd ON wd.workspace_id = e.workspace_id AND wd.domain_id = e.domain_id
      JOIN domains d ON d.id = wd.domain_id WHERE (e.workspace_id = ? AND d.domain <> ?) OR (e.workspace_id = ? AND d.domain <> ?)`)
      .get(a.workspaceId, a.estate.domain, b.workspaceId, b.estate.domain).n;
    step("both", "every recorded change sits in the workspace of the domain it is about", crossRows === 0, crossRows);
  } finally {
    Object.assign(console, realConsole);
    globalThis.fetch = realFetch;
    clock.restore();
  }
  return {
    db,
    steps,
    queue_outcomes: outcomes,
    unexpected: log.filter((entry) => entry.kind === "unexpected").map((entry) => entry.host),
    emails: log.filter((entry) => entry.kind === "email").map((entry) => ({ to: entry.email?.to, subject: entry.email?.subject })),
  };
}
