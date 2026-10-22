import { assertProbeFetch } from './probe-contract-fixture.mjs';
// Shared validator fixture: an SSL module carrying a live TLS observation, built
// through the production attachLiveTlsToSsl() so fixtures cannot drift from the
// collector receipt contract. Certificates reach the product only this way.
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const { attachLiveTlsToSsl } = await import(
  pathToFileURL(path.join(root, "workers", "scan-api", "src", "engines", "network-probe.js")).href
);

const DAY_MS = 86_400_000;
const TRUST_STORE_SHA256 = "b".repeat(64);

export function liveTlsReceipt({
  domain = "example.com",
  days = 90,
  finishedAt = "2026-08-30T12:00:00.000Z",
  notAfter = null,
  notBefore = null,
  issuer = "CN=Fixture CA\nO=Fixture",
  subject = null,
  dnsNames = null,
  hostnameMatch = "matched",
  trust = "valid",
  identity = "a",
  address = "93.184.216.34",
} = {}) {
  const finishedMs = Date.parse(finishedAt);
  const leaf = {
    certificate_identity: `sha256:${identity.repeat(64).slice(0, 64)}`,
    subject: subject ?? `CN=${domain}`,
    issuer,
    serial_number: "01",
    der_base64: "AAAA",
    not_before: notBefore ?? new Date(finishedMs - 30 * DAY_MS).toISOString(),
    not_after: notAfter ?? new Date(finishedMs + (days + 0.5) * DAY_MS).toISOString(),
    dns_names: dnsNames ?? [domain, `www.${domain}`],
    subject_alt_name: (dnsNames ?? [domain, `www.${domain}`]).map((name) => `DNS:${name}`).join(", "),
    public_key_algorithm: "ec",
    public_key_size_bits: 256,
    signature_algorithm: null,
    collection_performed: true,
    collection_complete: true,
    source: "cloudflare_container_node_tls",
    method: "peer_x509_capture",
  };
  const trustStoreContext = { name: "Node.js bundled Mozilla CA roots", version: "fixture", sha256: TRUST_STORE_SHA256 };
  const tls = {
    leaf_collected: true,
    chain_collected: false,
    reason: null,
    observed_at: finishedAt,
    endpoint: { address, port: 443, hostname: domain },
    source: "cloudflare_container_node_tls",
    method: "pinned_public_address_tls_handshake",
    protocol: "TLSv1.3",
    cipher: "TLS_AES_128_GCM_SHA256",
    alpn: null,
    leaf_certificate: leaf,
    runtime_chain: { collection_performed: true, collection_complete: false, observation_scope: "node_tls_issuer_chain", certificates: [] },
    presented_chain: { collection_performed: false, collection_complete: false, presentation_state: "unknown", intermediates: [] },
    hostname_match: {
      assessment_performed: true,
      source: "cloudflare_container_node_tls",
      method: "node_tls_check_server_identity",
      result: hostnameMatch,
      reference_hostname: domain,
      presented_identifiers: [leaf.subject_alt_name],
      certificate_identity: leaf.certificate_identity,
    },
    trust_store_context: trustStoreContext,
    trust_store_validation: {
      validation_performed: true,
      validation_result: trust,
      certificate_identity: leaf.certificate_identity,
      trust_store_context: trustStoreContext,
      reason: trust === "valid" ? null : "certificate_validation_failed",
    },
    revocation_assurance: {
      assessment_performed: false,
      response_validated: false,
      stapled_ocsp: null,
      status: "unknown",
      certificate_identity: leaf.certificate_identity,
    },
  };
  return {
    schema_version: "network-probe-receipt-v1",
    request_id: "fixture_request",
    workspace_id: "fixture_workspace",
    scan_id: "fixture_scan",
    profile: "live_tls",
    collector: {
      name: "cybermeters-cloudflare-network-probe",
      version: "1",
      node_version: "v22.0.0",
      openssl_version: "fixture",
      trust_store: trustStoreContext,
    },
    started_at: new Date(finishedMs - 1000).toISOString(),
    finished_at: finishedAt,
    coverage: { planned: 1, attempted: 1, completed: 1, not_run: 0 },
    quality: "complete",
    observations: [{ address, hostname: domain, port: 443, transport: "tcp", state: "open", service: null, tls }],
    limitations: ["Synthetic validator fixture; one live TLS endpoint."],
  };
}

// An SSL module with one complete live TLS observation of `domain`.
export function liveTlsSsl(options = {}, base = { tls_state: "observed_present", https_available: true }) {
  return attachLiveTlsToSsl(base, { receipt: liveTlsReceipt(options) });
}

// A NETWORK_PROBE service binding that answers the engine's live TLS request
// with a receipt bound to that request and the current clock. `days` (or an
// explicit `notAfter`) positions the served certificate's expiry. `options` may
// be a function of the request, so a multi-scan trace can serve a replacement.
export function liveTlsProbeBinding(optionsOrFactory = {}) {
  const calls = [];
  return {
    calls,
    fetch: async (_url, init) => {
      const request = assertProbeFetch(init);
      calls.push(request);
      const options = typeof optionsOrFactory === "function"
        ? optionsOrFactory(request)
        : optionsOrFactory;
      // Date.now() so a validator that pins the clock pins the receipt too.
      const now = new Date(Date.now()).toISOString();
      const hostname = request.targets?.[0]?.hostname || options.domain || "example.com";
      const receipt = liveTlsReceipt({ ...options, domain: hostname, finishedAt: now });
      return Response.json({
        ...receipt,
        request_id: request.request_id,
        workspace_id: request.workspace_id,
        scan_id: request.scan_id,
        profile: request.profile,
        started_at: now,
      });
    },
  };
}
