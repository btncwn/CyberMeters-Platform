#!/usr/bin/env node
//
// Provider-infrastructure classification proof.
//
// Distinguishes EDGE/CDN TECHNOLOGY (server: cloudflare, cf-ray, tech "Cloudflare")
// from provider ASSET OWNERSHIP. Edge/CDN tech alone — including the `server: cloudflare`
// a Cloudflare Worker's own outbound fetch stamps on non-Cloudflare origins — must NOT
// set provider_owned_infrastructure. Ownership requires a provider-suffix CNAME, a
// redirect to a provider host, or the provider's own default/parked page. Regression for
// the BBB admin-surface finding suppression. Node 24+. CI-blocking.
//
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const eng = (f) => import(pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", f)).href);
const { classifyProviderInfrastructure, annotateExposureInfrastructure } = await eng("asset-intel.js");
const { computeScore } = await eng("scoring.js");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const eq = (n, g, w) => ok(n, g === w, `got ${JSON.stringify(g)} want ${JSON.stringify(w)}`);

// The BBB admin fixture as the Worker probes it: real customer content, Cloudflare edge
// header/tech, no CNAME, no provider redirect.
const adminAsset = (over = {}) => ({
  host: "admin.blackbullbarbers.co.uk",
  url: "https://admin.blackbullbarbers.co.uk/",
  status: 200,
  reachable: true,
  title: "Black Bull Barbers Admin Surface Test",
  server: "cloudflare",
  content_type: "text/html",
  tech: ["Cloudflare"],
  ...over,
});

// ── 1. server: cloudflare ONLY → not provider-owned ───────────────────────────
{
  const c = classifyProviderInfrastructure({ ...adminAsset(), tech: [] });
  eq("server:cloudflare only → provider_owned false", c.provider_owned_infrastructure, false);
  eq("→ infrastructure_provider null", c.infrastructure_provider, null);
  eq("→ infrastructure_evidence null", c.infrastructure_evidence, null);
}

// ── 2. cf-ray ONLY (→ tech Cloudflare) → not provider-owned ───────────────────
{
  const c = classifyProviderInfrastructure({ ...adminAsset(), server: null, tech: ["Cloudflare"] });
  eq("cf-ray/tech Cloudflare only → provider_owned false", c.provider_owned_infrastructure, false);
}

// ── 3. Cloudflare tech + customer hostname + customer content → not provider-owned ─
{
  const c = classifyProviderInfrastructure(adminAsset());
  eq("Cloudflare edge + customer content → provider_owned false", c.provider_owned_infrastructure, false);
}

// ── 4. CNAME to a known provider suffix → provider-owned (dns_cname) ───────────
{
  const c = classifyProviderInfrastructure(adminAsset(), "blackbullbarbers.github.io");
  eq("CNAME → provider suffix → provider_owned true", c.provider_owned_infrastructure, true);
  eq("→ evidence dns_cname", c.infrastructure_evidence, "dns_cname");
  eq("→ provider GitHub Pages", c.infrastructure_provider, "GitHub Pages");
}

// ── 5. Redirect to a known provider domain → provider-owned (http_redirect) ────
{
  const c = classifyProviderInfrastructure({ ...adminAsset(), url: "https://foo.netlify.app/" });
  eq("redirect → provider domain → provider_owned true", c.provider_owned_infrastructure, true);
  eq("→ evidence http_redirect", c.infrastructure_evidence, "http_redirect");
}

// ── 6. Provider default/parked page + edge tech → provider-owned (provider_default_page) ─
{
  const c = classifyProviderInfrastructure({ ...adminAsset(), title: "Welcome to nginx!" });
  eq("provider default-page + edge tech → provider_owned true", c.provider_owned_infrastructure, true);
  eq("→ evidence provider_default_page", c.infrastructure_evidence, "provider_default_page");
  // sanity: the SAME default-page WITHOUT edge tech is NOT provider-owned (no corroboration)
  const c2 = classifyProviderInfrastructure({ ...adminAsset(), title: "Welcome to nginx!", server: null, tech: [] });
  eq("default-page WITHOUT edge tech → provider_owned false", c2.provider_owned_infrastructure, false);
}

// ── 7. BBB admin fixture end-to-end → asset_exposure_admin_interface (no dup) ──
{
  let exposure = { checked: 1, reachable: 1, assets: [adminAsset()], source: "http_probe", error: null };
  exposure = annotateExposureInfrastructure(exposure, []); // sets provider_owned_infrastructure via classify
  const admin = exposure.assets[0];
  ok("annotated admin: provider_owned false, tech still Cloudflare", admin.provider_owned_infrastructure === false && (admin.tech || []).includes("Cloudflare"));

  const modules = { dns: { resolves: true }, subdomains: { wildcard_dns: false, items: [] }, asset_exposure: exposure };
  const { findings } = computeScore(modules, "blackbullbarbers.co.uk");
  const adminFindings = findings.filter((f) => f.id === "asset_exposure_admin_interface");
  eq("asset_exposure_admin_interface fires exactly once (no duplicate)", adminFindings.length, 1);
  eq("→ module", adminFindings[0]?.module, "asset_exposure");
  eq("→ severity", adminFindings[0]?.severity, "medium");
  ok("→ no asset_provider_infrastructure_observed for this asset", !findings.some((f) => f.id === "asset_provider_infrastructure_observed"));
}

// ── 8. genuine provider infra STILL suppressed: a provider-CNAME asset gets no admin finding ─
{
  // A CNAME to github.io serving a real admin-looking title is genuinely provider-hosted →
  // provider_owned true → admin-interface finding suppressed (existing behaviour preserved).
  let exposure = { checked: 1, reachable: 1, assets: [adminAsset()], source: "http_probe", error: null };
  exposure = annotateExposureInfrastructure(exposure, [{ host: "admin.blackbullbarbers.co.uk", cname: "someapp.github.io" }]);
  const modules = { dns: { resolves: true }, subdomains: { wildcard_dns: false, items: [] }, asset_exposure: exposure };
  const { findings } = computeScore(modules, "blackbullbarbers.co.uk");
  eq("provider-CNAME asset → admin-interface finding suppressed", findings.filter((f) => f.id === "asset_exposure_admin_interface").length, 0);
  ok("provider-CNAME asset → provider_owned true", exposure.assets[0].provider_owned_infrastructure === true);
}

console.log(`\nprovider-classification: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
