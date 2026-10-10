// ── Domain Connect: one-click DNS for domain verification ──────────────────────
// Domain Connect (https://www.domainconnect.org, IETF dconn) lets a customer's DNS
// provider add a record for us after the customer approves it on the provider's
// own consent screen — no copying a TXT value into a DNS panel.
//
// What this module does NOT change: ownership is still proven only by the
// existing DNS observation in lib/domain-verification.js (checkDnsTxtProof).
// Domain Connect merely writes the same `_cybermeters` TXT record the manual
// instructions describe; the customer still authenticates at their provider.
//
// Trust boundary: the `_domainconnect` TXT record lives in the CUSTOMER's zone, so
// its value is attacker-controllable. It is therefore only ever compared against
// an allowlist of providers whose endpoints are fixed here — we never fetch, and
// never send a browser to, a URL taken from customer DNS or a provider response.
//
// Every failure is an ordinary "not available" answer: the manual flow is always
// the fallback, so a provider outage can never block verification.

export const DC_PROVIDER_ID = "cybermeters.com";
export const DC_SERVICE_ID = "domain-verification";
export const DC_KEY_HOST = "_dck1";
export const DC_REDIRECT_PATH = "/domains/verify-return";

// Providers whose Domain Connect endpoints have been confirmed. `discovery` is the
// value their zones publish at `_domainconnect.<zone>`; the API and consent bases
// are pinned so customer DNS can never redirect either call.
export const DOMAIN_CONNECT_PROVIDERS = Object.freeze([
  Object.freeze({
    id: "cloudflare.com",
    name: "Cloudflare",
    discovery: "api.cloudflare.com/client/v4/dns/domainconnect",
    apiBase: "https://api.cloudflare.com/client/v4/dns/domainconnect",
    syncUxBase: "https://dash.cloudflare.com/domainconnect",
  }),
  Object.freeze({
    id: "vercel.com",
    name: "Vercel",
    discovery: "domainconnect.vercel.com",
    apiBase: "https://vercel.com/api/domain-connect",
    syncUxBase: "https://vercel.com/domain-connect",
  }),
]);

const TOKEN_RE = /^[a-f0-9]{48}$/;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

function isPlainHostname(name) {
  const labels = String(name || "").split(".");
  return labels.length >= 2 && labels.every((l) => LABEL_RE.test(l));
}

// `shop.example.co.uk` → ["shop.example.co.uk", "example.co.uk", "co.uk"]. The
// zone is wherever the provider answers `_domainconnect`; at most a handful of
// lookups, never a single-label name.
export function zoneCandidates(fqdn) {
  const labels = String(fqdn || "").toLowerCase().replace(/\.$/, "").split(".");
  const out = [];
  for (let i = 0; i <= labels.length - 2; i++) out.push(labels.slice(i).join("."));
  return out.slice(0, 6);
}

export function normaliseDiscoveryValue(raw) {
  return String(raw || "").replace(/^"+|"+$/g, "").trim().toLowerCase().replace(/\/+$/, "");
}

export function providerForDiscovery(raw) {
  const value = normaliseDiscoveryValue(raw);
  return DOMAIN_CONNECT_PROVIDERS.find((p) => p.discovery === value) || null;
}

function bytesToBase64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function pemToDer(pem) {
  const body = String(pem || "")
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s+/g, "");
  if (!body || /[^A-Za-z0-9+/=]/.test(body)) throw new Error("domain_connect_key_invalid");
  const bin = atob(body);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) der[i] = bin.charCodeAt(i);
  return der;
}

// PKCS#8 PEM ("BEGIN PRIVATE KEY") → CryptoKey for RS256 signing.
export async function importSigningKey(pem) {
  return crypto.subtle.importKey(
    "pkcs8", pemToDer(pem), { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"],
  );
}

export function encodeState(domainId, workspaceId) {
  const json = JSON.stringify({ d: String(domainId), w: String(workspaceId) });
  return btoa(json).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// The signed query string is exactly what is sent (minus key/sig), in a fixed
// order. `key` and `sig` are appended last — Cloudflare requires `sig` last.
export async function buildSignedApplyUrl({ provider, zone, host, token, redirectUri, state, signingKey }) {
  const params = new URLSearchParams();
  params.set("domain", zone);
  if (host) params.set("host", host);
  params.set("verificationToken", token);
  params.set("redirect_uri", redirectUri);
  params.set("state", state);
  const query = params.toString();
  const signature = await crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" }, signingKey, new TextEncoder().encode(query),
  );
  const sig = encodeURIComponent(bytesToBase64(new Uint8Array(signature)));
  return `${provider.syncUxBase}/v2/domainTemplates/providers/${DC_PROVIDER_ID}/services/${DC_SERVICE_ID}/apply`
    + `?${query}&key=${DC_KEY_HOST}&sig=${sig}`;
}

async function fetchStatusAndJson(fetchImpl, url) {
  const res = await fetchImpl(url, { headers: { accept: "application/json" }, redirect: "manual" });
  if (!res) return { status: 0, body: null };
  let body = null;
  try { body = await res.json(); } catch { body = null; }
  return { status: res.status, body };
}

// Resolve whether one-click verification can be offered for `domain`.
// deps: { txtLookup(name) → string[] , fetchImpl(url, init) → Response }
// Returns { available:true, provider, apply_url } or { available:false, reason }.
export async function resolveDomainConnectOffer({ domain, token, frontendOrigin, domainId, workspaceId, privateKeyPem }, deps) {
  if (!privateKeyPem) return { available: false, reason: "not_configured" };
  const fqdn = String(domain || "").toLowerCase();
  if (!isPlainHostname(fqdn)) return { available: false, reason: "invalid_domain" };
  if (!TOKEN_RE.test(String(token || ""))) return { available: false, reason: "no_pending_token" };
  let origin;
  try { origin = new URL(frontendOrigin); } catch { origin = null; }
  if (!origin || origin.protocol !== "https:") return { available: false, reason: "not_configured" };

  let zone = null;
  let provider = null;
  for (const candidate of zoneCandidates(fqdn)) {
    let values;
    try { values = await deps.txtLookup(`_domainconnect.${candidate}`); } catch { values = []; }
    if (!values || values.length === 0) continue;
    zone = candidate;
    provider = values.map(providerForDiscovery).find(Boolean) || null;
    break;
  }
  if (!zone) return { available: false, reason: "provider_not_discoverable" };
  if (!provider) return { available: false, reason: "provider_not_supported" };

  try {
    const settings = await fetchStatusAndJson(deps.fetchImpl, `${provider.apiBase}/v2/${zone}/settings`);
    if (settings.status !== 200 || settings.body?.providerId !== provider.id) {
      return { available: false, reason: "provider_settings_unavailable" };
    }
    const template = await fetchStatusAndJson(
      deps.fetchImpl,
      `${provider.apiBase}/v2/domainTemplates/providers/${DC_PROVIDER_ID}/services/${DC_SERVICE_ID}`,
    );
    if (template.status !== 200) return { available: false, reason: "template_not_onboarded" };
  } catch {
    return { available: false, reason: "provider_unreachable" };
  }

  let signingKey;
  try { signingKey = await importSigningKey(privateKeyPem); } catch { return { available: false, reason: "not_configured" }; }
  const host = fqdn === zone ? "" : fqdn.slice(0, -(zone.length + 1));
  const apply_url = await buildSignedApplyUrl({
    provider, zone, host, token,
    redirectUri: `${origin.origin}${DC_REDIRECT_PATH}`,
    state: encodeState(domainId, workspaceId),
    signingKey,
  });
  return { available: true, provider: { id: provider.id, name: provider.name }, apply_url };
}
