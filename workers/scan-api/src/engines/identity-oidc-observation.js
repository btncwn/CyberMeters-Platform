// Public metadata only. Reuses the canonical DNS/SSRF guard and scan accounting;
// never follows redirects, advertised endpoints, keys, login or token flows.
import { makeReservedProbeFetch } from "./reserved-probe.js";
import { urlIsBlockedTarget } from "../lib/ssrf.js";
import { runIdentityDiscoveryModule } from "./identity-scan.js";

export const OIDC_LIMITS = Object.freeze({ hosts: 2, bytes: 32768, module_ms: 2000, physical_attempts: 10 });
const PATH = "/.well-known/openid-configuration";
const hostName = (value) => typeof value === "string" && /^(?=.{1,253}$)[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?$/i.test(value)
  && !value.includes("..") ? value.toLowerCase() : null;
const ownHost = (host, root) => host === root || host.endsWith(`.${root}`);

function publicHttps(value) {
  if (typeof value !== "string" || value.length > 1024 || /[\u0000-\u0020\u007f]/.test(value) || urlIsBlockedTarget(value)) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.port) return null;
    return url;
  } catch { return null; }
}

// A complete JSON body is required. The existing page snippet reader permits
// partial bodies, so it cannot establish that a discovery document completed.
async function completeJson(response, signal) {
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > OIDC_LIMITS.bytes)) return null;
  const reader = response.body?.getReader();
  if (!reader) return null;
  let timer, abort;
  const stopped = new Promise((_, reject) => {
    abort = () => reject(new Error("metadata_body_unavailable"));
    timer = setTimeout(abort, 500);
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) abort();
  });
  const chunks = [];
  let bytes = 0;
  try {
    for (;;) {
      const part = await Promise.race([reader.read(), stopped]);
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > OIDC_LIMITS.bytes) return null;
      chunks.push(part.value);
    }
    if (length !== null && !response.headers.get("content-encoding") && bytes !== Number(length)) return null;
    const buffer = new Uint8Array(bytes);
    let offset = 0;
    for (const chunk of chunks) { buffer.set(chunk, offset); offset += chunk.byteLength; }
    const document = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer));
    return document && typeof document === "object" && !Array.isArray(document) ? document : null;
  } catch { return null; }
  finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
    void reader.cancel().catch(() => {});
  }
}

export function oidcReceipt(document, host) {
  const issuer = publicHttps(document?.issuer);
  const authorization = publicHttps(document?.authorization_endpoint);
  // Root-issuer discovery only; realm/path-specific issuers are not guessed.
  // Discovery 1.0 §4.3 requires exact issuer identity for the requested document.
  if (!issuer || ![`https://${host}`, `https://${host}/`].includes(document.issuer) || !authorization || authorization.hash) return null;
  authorization.search = ""; // advertised query values may contain identifiers
  return { source_url: `https://${host}${PATH}`, issuer: document.issuer,
    authorization_endpoint: authorization.href, endpoint_query_omitted: Boolean(new URL(document.authorization_endpoint).search) };
}

export async function observeOidcMetadata(domain, modules, opts = {}) {
  const root = hostName(domain);
  const result = { schema_version: "identity_oidc.v1", domain: root, verified_scope: opts.verified === true,
    observed_at: opts.observedAt, state: "not_assessed", checked: 0, observations: [] };
  if (!root || opts.verified !== true) return { ...result, reason: "verified_workspace_required" };
  const candidates = runIdentityDiscoveryModule(modules, root).portals.map((row) => row.hostname);
  const hosts = [...new Set([root, ...candidates.map(hostName).filter((host) => host && ownHost(host, root))])].slice(0, OIDC_LIMITS.hosts);
  const fetcher = opts.fetcher || makeReservedProbeFetch({ cache: opts.cache, accounting: opts.accounting, maxHops: 0, timeoutMs: 1000 });
  let unavailable = false;
  for (const host of hosts) {
    if (opts.signal?.aborted) { unavailable = true; break; }
    try {
      const response = await fetcher(`https://${host}${PATH}`, { signal: opts.signal, accounting: opts.accounting });
      result.checked++;
      if (!response) { unavailable = true; continue; }
      if ([404, 410].includes(response.status)) { void response.body?.cancel().catch(() => {}); continue; }
      if (response.status !== 200 || !/^application\/json(?:\s*;|$)/i.test(response.headers.get("content-type") || "")) {
        void response.body?.cancel().catch(() => {}); unavailable = true; continue;
      }
      const receipt = oidcReceipt(await completeJson(response, opts.signal), host);
      if (receipt) result.observations.push(receipt);
      else unavailable = true;
    } catch { unavailable = true; }
  }
  return { ...result, state: unavailable ? "partial" : "observed", incomplete: unavailable };
}

export function oidcMetadataFindings(result, { domain, verified = false } = {}) {
  if (verified !== true || result?.verified_scope !== true || result?.schema_version !== "identity_oidc.v1"
      || result.domain !== hostName(domain) || !["observed", "partial"].includes(result.state)) return [];
  const observations = (Array.isArray(result.observations) ? result.observations : []).slice(0, OIDC_LIMITS.hosts).filter((row) => {
    try {
      const source = new URL(row.source_url);
      return ownHost(source.hostname, result.domain) && source.href === `https://${source.hostname}${PATH}`
        && Boolean(oidcReceipt(row, source.hostname)) && !new URL(row.authorization_endpoint).search;
    } catch { return false; }
  });
  if (observations.length === 0) return [];
  return [{ id: "identity_oidc_observation", module: "identity_discovery", severity: "info",
    finding_type: "observation", score_impact: 0, confidence: 90,
    title: "Public identity-provider metadata observed",
    description: "An OpenID Connect discovery document advertised the issuer and sign-in endpoints below. These are published configuration facts; endpoint reachability, account access and authentication controls were not tested. Endpoint query values are omitted.",
    evidence: observations.flatMap((row) => [
      { type: "http_probe", value: `Discovery document observed: ${row.source_url}` },
      { type: "identity_discovery", value: `Issuer advertised: ${row.issuer}` },
      { type: "identity_discovery", value: `Sign-in endpoint advertised: ${row.authorization_endpoint}` },
    ]),
  }];
}
