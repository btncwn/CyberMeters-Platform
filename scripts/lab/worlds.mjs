// Lab worlds. Each is a small, invented organisation whose DNS, website and
// certificate exercise one family of discovery questions. `truth` says what a
// careful observer could know: names that exist and are reachable through the
// sources CyberMeters reads (discoverable), names that exist but nothing points
// to (hidden: an honest tool cannot be expected to find them), and names that
// merely appear somewhere without existing (decoys: listing one is a false
// positive). Addresses are public-looking but nothing here touches a network.

const ALPHA = "cmlab-alpha.co.uk";
const a = (label) => (label ? `${label}.${ALPHA}` : ALPHA);

const page = (title, extra = "") =>
  `<!doctype html><html><head><title>${title}</title></head><body>${extra}</body></html>`;

const ALPHA_LINKS = [`https://${a("www")}/about`, `https://${a("gone")}/old?session=lab-session-1`, "https://partner.partner-lab.org/"]
  .map((href) => `<a href="${href}">link</a>`).join("");
// nosemgrep: javascript.lang.security.audit.unknown-value-with-script-tag.unknown-value-with-script-tag -- INTENTIONAL: inert HTML fixture served by the lab's stand-in web server to the scanner under test; never rendered.
const ALPHA_HOME = page("Alpha Ltd", ALPHA_LINKS + '<script src="/static/app.js"></script>');

// Alpha: one small business with mail, a website, a hosted portal, an admin
// tool and an IPv6-only name server — and the usual mess of stale references.
export const alpha = {
  name: "alpha",
  domain: ALPHA,
  zones: {
    [a()]: {
      SOA: true,
      A: ["34.120.10.1"], AAAA: ["2a05:d014:9:1::1"],
      MX: ["10 " + a("mail")],
      NS: [a("ns1"), a("ns2")],
      TXT: ["v=spf1 mx include:_spf." + ALPHA + " -all"],
    },
    [a("_dmarc")]: { TXT: [`v=DMARC1; p=quarantine; rua=mailto:dmarc@${a("reports")}`] },
    [a("_spf")]: { TXT: ["v=spf1 ip4:34.120.10.0/24 -all"] },
    [a("_autodiscover._tcp")]: { SRV: ["0 0 443 " + a("autodiscover")] },   // points at a name that does not exist
    [a("www")]: { CNAME: a() },
    [a("mail")]: { A: ["34.120.10.2"] },                                   // MX target, IPv4 only
    [a("ns1")]: { A: ["34.120.10.3"], AAAA: ["2a05:d014:9:1::3"] },         // dual stack
    [a("ns2")]: { AAAA: ["2a05:d014:9:1::4"] },                             // IPv6 only
    [a("reports")]: { MX: ["10 inbound.mailvendor-lab.net"] },             // mail only, no address
    [a("v6only")]: { AAAA: ["2a05:d014:9:1::6"] },                          // named by the certificate
    [a("app")]: { A: ["34.120.10.7"], AAAA: ["2a05:d014:9:1::7"] },         // CSP + word list
    [a("api")]: { A: ["34.120.10.8"] },                                     // script reference + word list
    [a("shop")]: { A: ["34.120.10.11"] },                                   // sitemap + word list
    [a("admin")]: { A: ["34.120.10.20"] },                                  // admin login page
    [a("portal")]: { CNAME: "cmlab-alpha.apphost-lab.net" },         // alias to a provider
    "cmlab-alpha.apphost-lab.net": { A: ["20.50.1.1"] },
    [a("loop1")]: { CNAME: a("loop2") },                                    // broken alias loop
    [a("loop2")]: { CNAME: a("loop1") },
    [a("txtonly")]: { TXT: ["site-verification=abc"] },                     // exists, no address
    [a("halfv6")]: { A: ["34.120.10.10"], AAAA: ["2a05:d014:9:1::10"] },    // AAAA lookups fail
    [a("flaky")]: { A: ["34.120.10.12"] },                                  // every lookup fails
    [a("slow")]: { A: ["34.120.10.13"] },                                   // every lookup times out
    [a("listed-v6")]: { AAAA: ["2a05:d014:9:1::14"] },                       // customer list, IPv6 only
    [a("xn--bcher-kva")]: { A: ["34.120.10.15"] },                          // "bücher", listed in Unicode
    [a("hidden-db")]: { A: ["34.120.10.30"] },                               // exists; nothing names it
    "inbound.mailvendor-lab.net": { A: ["52.10.0.1"] },
    "cdn.vendor-cdn-lab.net": { A: ["52.10.0.2"] },
    "partner.partner-lab.org": { A: ["52.10.0.3"] },
  },
  wildcards: {
    [a("preview")]: { A: ["34.120.10.99"] },                                // *.preview
  },
  faults: {
    [a("halfv6")]: { AAAA: "servfail" },
    [a("flaky")]: { "*": "servfail" },
    [a("slow")]: { "*": "timeout" },
  },
  sites: {
    [a()]: {
      routes: {
        "/": {
          status: 200,
          headers: {
            server: "nginx/1.18.0",
            "content-security-policy": `default-src 'self'; connect-src https://${a("app")} https://cdn.vendor-cdn-lab.net`,
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
          },
          body: ALPHA_HOME,
        },
        "/robots.txt": { status: 200, headers: { "content-type": "text/plain" }, body: `User-agent: *\nSitemap: https://${ALPHA}/sitemap.xml\n` },
        "/sitemap.xml": {
          status: 200, headers: { "content-type": "application/xml" },
          body: `<?xml version="1.0"?><urlset>` +
            [`https://${a("shop")}/`, `https://${a("loop1")}/`, `https://pr-123.${a("preview")}/`]
              .map((loc) => `<url><loc>${loc}</loc></url>`).join("") + `</urlset>`,
        },
        "/static/app.js": {
          status: 200, headers: { "content-type": "application/javascript" },
          body: `fetch("https://${a("api")}/v1/items?session=lab-session-2");`,
        },
      },
      fallback: { status: 404, body: page("Not found") },
    },
    [a("www")]: { fallback: { status: 301, headers: { location: `https://${ALPHA}/` } } },
    [a("admin")]: { fallback: { status: 200, body: page("phpMyAdmin", '<form><input type="password" name="pma_password"></form>') } },
    [a("app")]: { fallback: { status: 200, body: page("App") } },
    [a("api")]: { fallback: { status: 404, body: "" } },
    [a("shop")]: { fallback: { status: 200, body: page("Shop") } },
    [a("v6only")]: { fallback: { status: 200, body: page("Status") } },
    [a("portal")]: { fallback: { status: 200, body: page("Customer portal") } },
    [a("mail")]: { refuse: true },
    [a("ns1")]: { refuse: true },
    [a("ns2")]: { refuse: true },
  },
  defaultSite: { status: 404, body: "" },
  tls: {
    [ALPHA]: {
      days: 60,
      dnsNames: [ALPHA, a("www"), a("v6only"), a("legacy"), `*.apps.${ALPHA}`],
    },
  },
  customerList: ["flaky", "slow", "txtonly", "bücher", "listed-v6", "notreal", "halfv6"].map((label) => a(label)),
  truth: {
    // Exist, are in scope and are named by a source CyberMeters reads.
    discoverable: ["www", "mail", "ns1", "ns2", "reports", "v6only", "app", "api", "shop", "admin", "portal",
      "halfv6", "listed-v6", "xn--bcher-kva", "pr-123.preview"].map(a),
    // Exist but the lab only names them through faulty DNS: finding them is
    // welcome, missing them is not a defect of reasoning.
    unconfirmable: ["flaky", "slow"].map(a),
    // Exist but nothing names them.
    hidden: ["hidden-db", "txtonly"].map(a),
    // Named somewhere but not real hosts of this organisation.
    decoys: [a("gone"), a("legacy"), a("loop1"), a("loop2"), a("notreal"), a("autodiscover"),
      "cdn.vendor-cdn-lab.net", "partner.partner-lab.org", "cmlab-alpha.apphost-lab.net",
      "inbound.mailvendor-lab.net"],
    // Expected address families for names that must keep both.
    families: {
      [a("ns1")]: { A: ["34.120.10.3"], AAAA: ["2a05:d014:9:1::3"] },
      [a("ns2")]: { A: [], AAAA: ["2a05:d014:9:1::4"] },
      [a("v6only")]: { A: [], AAAA: ["2a05:d014:9:1::6"] },
      [a("app")]: { A: ["34.120.10.7"], AAAA: ["2a05:d014:9:1::7"] },
      [a("halfv6")]: { A: ["34.120.10.10"], AAAA: null },
    },
  },
  outsideData: {
    nvd: {
      vulnerabilities: [{
        cve: {
          id: "CVE-2099-10001",
          vulnStatus: "Analyzed",
          published: "2099-01-01T00:00:00.000",
          descriptions: [{ lang: "en", value: "Lab-only record: an invented flaw in the lab's web server version." }],
          metrics: { cvssMetricV31: [{ cvssData: { baseScore: 8.1, baseSeverity: "HIGH" } }] },
          configurations: [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", versionEndExcluding: "1.21.0" }] }] }],
        },
      }],
    },
    epss: { data: [{ cve: "CVE-2099-10001", epss: "0.42", percentile: "0.97", date: "2099-01-01" }] },
    kev: { vulnerabilities: [{ cveID: "CVE-2099-10002", vendorProject: "nginx", product: "nginx", vulnerabilityName: "Lab-only entry", dateAdded: "2099-01-01" }] },
  },
};

// Bravo: a zone answering every name (apex wildcard). Word-list guesses must
// not become assets just because the wildcard answers them.
const BRAVO = "cmlab-bravo.co.uk";
const b = (label) => (label ? `${label}.${BRAVO}` : BRAVO);
export const bravo = {
  name: "bravo",
  domain: BRAVO,
  zones: {
    [b()]: { SOA: true, A: ["34.121.0.1"], NS: [b("ns1")], MX: ["10 " + b("mail")] },
    [b("ns1")]: { A: ["34.121.0.2"] },
    [b("mail")]: { A: ["34.121.0.3"] },
    [b("vpn")]: { A: ["34.121.0.4"] },                       // real, also matched by the word list
  },
  wildcards: { [BRAVO]: { A: ["34.121.0.99"], AAAA: ["2a05:d014:a::99"] } },
  sites: {
    [b()]: { routes: { "/": { status: 200, headers: { server: "cloud" }, body: page("Bravo") } }, fallback: { status: 404, body: "" } },
    [b("vpn")]: { fallback: { status: 200, body: page("VPN sign-in") } },
  },
  defaultSite: { status: 200, body: page("Parked") },
  tls: { [BRAVO]: { days: 200, dnsNames: [BRAVO, `*.${BRAVO}`] } },
  customerList: [],
  truth: {
    discoverable: ["ns1", "mail", "vpn"].map(b),
    unconfirmable: [],
    hidden: [],
    // Any other name under the zone is the wildcard talking.
    decoysPattern: new RegExp(`\\.${BRAVO.replace(/\./g, "\\.")}$`),
    decoys: [],
    families: {},
  },
};

// Charlie: a customer who listed far more names than one scan can ask about.
const CHARLIE = "cmlab-charlie.co.uk";
const c = (label) => (label ? `${label}.${CHARLIE}` : CHARLIE);
const charlieHosts = Array.from({ length: 200 }, (_, i) => `h${String(i).padStart(3, "0")}`);
export const charlie = {
  name: "charlie",
  domain: CHARLIE,
  zones: {
    [c()]: { SOA: true, A: ["34.122.0.1"], NS: [c("ns1")] },
    [c("ns1")]: { A: ["34.122.0.2"] },
    ...Object.fromEntries(charlieHosts.map((label, i) => [c(label),
      i % 3 === 0 ? { AAAA: [`2a05:d014:c::${(i + 16).toString(16)}`] } : { A: [`34.122.1.${i % 250}`] }])),
  },
  sites: { [c()]: { routes: { "/": { status: 200, body: page("Charlie") } } } },
  defaultSite: { status: 404, body: "" },
  tls: { [CHARLIE]: { days: 120, dnsNames: [CHARLIE] } },
  customerList: charlieHosts.map(c),
  truth: {
    discoverable: [c("ns1"), ...charlieHosts.map(c)],
    unconfirmable: [],
    hidden: [],
    decoys: [],
    families: {},
  },
};

// Delta: one small organisation scanned ten times, a day apart, while it
// changes — for change notifications. Scan by scan (deltaAt): the starting
// inventory; a shop appears (a new name, nothing more); a management page
// appears; the app's DNS fails once (a partial scan); everything answers again
// and a monitoring dashboard appears in the same scan; the shop is taken down
// and stays gone for three scans (a confirmed removal); the shop comes back;
// then a second workspace on the same domain takes its first scan.
const DELTA = "cmlab-delta.co.uk";
const d = (label) => (label ? `${label}.${DELTA}` : DELTA);
function deltaWorld({ shop = false, admin = false, grafana = false, appFault = null } = {}) {
  return {
    name: "delta",
    domain: DELTA,
    zones: {
      [d()]: { SOA: true, A: ["34.123.0.1"], NS: [d("ns1")], MX: ["10 " + d("mail")] },
      [d("ns1")]: { A: ["34.123.0.2"] },
      [d("mail")]: { A: ["34.123.0.3"] },
      [d("www")]: { CNAME: d() },
      [d("app")]: { A: ["34.123.0.4"], AAAA: ["2a05:d014:d::4"] },
      ...(shop ? { [d("shop")]: { A: ["34.123.0.6"] } } : {}),
      ...(admin ? { [d("admin")]: { A: ["34.123.0.5"] } } : {}),
      ...(grafana ? { [d("grafana")]: { A: ["34.123.0.7"] } } : {}),
    },
    faults: appFault ? { [d("app")]: { "*": appFault } } : {},
    sites: {
      [d()]: { routes: { "/": { status: 200, headers: { server: "nginx" }, body: page("Delta Ltd") } }, fallback: { status: 404, body: "" } },
      [d("www")]: { fallback: { status: 301, headers: { location: `https://${DELTA}/` } } },
      [d("app")]: { fallback: { status: 200, body: page("App") } },
      ...(shop ? { [d("shop")]: { fallback: { status: 200, body: page("Shop") } } } : {}),
      ...(admin ? { [d("admin")]: { fallback: { status: 200, body: page("phpMyAdmin", '<form><input type="password" name="pma_password"></form>') } } } : {}),
      ...(grafana ? { [d("grafana")]: { fallback: { status: 200, body: page("Grafana") } } } : {}),
      [d("mail")]: { refuse: true },
      [d("ns1")]: { refuse: true },
    },
    defaultSite: { status: 404, body: "" },
    tls: { [DELTA]: { days: 90, dnsNames: [DELTA, d("www")] } },
    customerList: [],
    truth: {
      discoverable: ["www", "mail", "ns1", "app", ...(shop ? ["shop"] : []), ...(admin ? ["admin"] : []), ...(grafana ? ["grafana"] : [])].map(d),
      unconfirmable: appFault ? [d("app")] : [],
      hidden: [],
      decoys: [],
      families: {},
    },
  };
}
const DELTA_STEPS = [
  {},
  { shop: true },
  { shop: true, admin: true },
  { shop: true, admin: true, appFault: "servfail" },
  { shop: true, admin: true, grafana: true },
  { admin: true, grafana: true },
  { admin: true, grafana: true },
  { admin: true, grafana: true },
  { shop: true, admin: true, grafana: true },
  { shop: true, admin: true, grafana: true },
];
export const DELTA_SCANS = DELTA_STEPS.length;
export const deltaAt = (i) => deltaWorld(DELTA_STEPS[Math.min(i, DELTA_STEPS.length - 1)]);
export const delta = deltaAt(0);

// Echo: one exposed management tool, fixed and re-checked — for closing a case
// only on a re-test of the problem. Scan by scan (echoAt): phpMyAdmin answers
// (a case opens); the host stops answering in time (a timeout); it refuses
// connections; a filter answers 403; the host now sends visitors to the main
// site (fixed); phpMyAdmin is back (the same case reopens); the name is taken
// down and stays gone (removal confirmed over three scans, then re-observed).
const ECHO = "cmlab-echo.co.uk";
const e = (label) => (label ? `${label}.${ECHO}` : ECHO);
const PHPMYADMIN = { status: 200, body: page("phpMyAdmin", '<form><input type="password" name="pma_password"></form>') };
function echoWorld({ admin = "tool" } = {}) {
  const adminSite = {
    tool: { fallback: PHPMYADMIN },
    timeout: { timeout: true },
    refuse: { refuse: true },
    filtered: { fallback: { status: 403, body: page("Forbidden") } },
    moved: { fallback: { status: 302, headers: { location: `https://${ECHO}/` } } },
  }[admin];
  return {
    name: "echo",
    domain: ECHO,
    zones: {
      [e()]: { SOA: true, A: ["34.124.0.1"], NS: [e("ns1")] },
      [e("ns1")]: { A: ["34.124.0.2"] },
      [e("www")]: { CNAME: e() },
      ...(admin === "removed" ? {} : { [e("admin")]: { A: ["34.124.0.5"] } }),
    },
    sites: {
      [e()]: { routes: { "/": { status: 200, headers: { server: "nginx" }, body: page("Echo Ltd") } }, fallback: { status: 404, body: "" } },
      [e("www")]: { fallback: { status: 301, headers: { location: `https://${ECHO}/` } } },
      ...(adminSite ? { [e("admin")]: adminSite } : {}),
      [e("ns1")]: { refuse: true },
    },
    defaultSite: { status: 404, body: "" },
    tls: { [ECHO]: { days: 90, dnsNames: [ECHO, e("www")] } },
    customerList: [],
    truth: {
      discoverable: ["www", "ns1", ...(admin === "removed" ? [] : ["admin"])].map(e),
      unconfirmable: [],
      hidden: [],
      decoys: [],
      families: {},
    },
  };
}
const ECHO_STEPS = ["tool", "timeout", "refuse", "filtered", "moved", "tool", "removed", "removed", "removed", "removed"];
export const ECHO_SCANS = ECHO_STEPS.length;
export const echoAt = (i) => echoWorld({ admin: ECHO_STEPS[Math.min(i, ECHO_STEPS.length - 1)] });

export const WORLDS = Object.freeze({ alpha, bravo, charlie });
