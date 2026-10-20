// ── Free SSL/TLS certificate check (F2) ──
// The one scan-api caller of the network-probe `free_tool` profile. The
// collector makes one TLS handshake to port 443 on one pinned public address
// and returns certificate and negotiated-protocol facts only. Call it only
// from the free-tools route, after Turnstile and the rolling limiter have
// admitted the request (a CI guard pins that this module has no other
// importer). There is no retry here or in the collector.
import { FREE_TOOL_TLS_LIMITS, readBoundedJson, validateNetworkProbeRequest } from "../../../../network-probe/src/contract.js";
import { validateFreeToolTlsReceipt } from "../../../../network-probe/src/receipt.js";
import { createId } from "../../lib/util.js";

export { FREE_TOOL_TLS_LIMITS };

export function buildFreeToolTlsRequest(hostname, { now = Date.now(), requestId = createId("ftls") } = {}) {
  return {
    schema_version: "network-probe-request-v1",
    request_id: requestId,
    workspace_id: null,
    scan_id: null,
    profile: "free_tool",
    deadline_at: new Date(now + FREE_TOOL_TLS_LIMITS.deadlineMs).toISOString(),
    targets: [{ address: null, hostname }],
    ports: [443],
  };
}

// Returns { receipt, error }. error is a code, never collector detail:
// invalid_target | collector_not_configured | collector_unavailable |
// collector_busy | collector_aborted | invalid_receipt.
export async function runFreeToolTlsCheck(env, hostname, { signal, now, requestId } = {}) {
  const request = buildFreeToolTlsRequest(hostname, { now, requestId });
  if (!validateNetworkProbeRequest(request).ok) return { receipt: null, error: "invalid_target" };
  if (!env?.NETWORK_PROBE?.fetch) return { receipt: null, error: "collector_not_configured" };
  if (signal?.aborted) return { receipt: null, error: "collector_aborted" };
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener("abort", abort, { once: true });
  const aborted = new Promise((_, reject) => controller.signal.addEventListener("abort", () => reject(new Error("collector_aborted")), { once: true }));
  aborted.catch(() => {});
  const timeout = setTimeout(abort, Math.max(1, Date.parse(request.deadline_at) - Date.now()));
  try {
    const response = await Promise.race([aborted, env.NETWORK_PROBE.fetch("https://network-probe.internal/free-tool-tls", {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(request), signal: controller.signal,
    })]);
    if (!response.ok) {
      await response.body?.cancel();
      return { receipt: null, error: response.status === 503 ? "collector_busy" : "collector_unavailable" };
    }
    const receipt = await Promise.race([aborted, readBoundedJson(response.body, FREE_TOOL_TLS_LIMITS.responseBytes)]);
    if (!validateFreeToolTlsReceipt(request, receipt).ok) return { receipt: null, error: "invalid_receipt" };
    return { receipt, error: null };
  } catch {
    return { receipt: null, error: controller.signal.aborted ? "collector_aborted" : "collector_unavailable" };
  } finally {
    clearTimeout(timeout);
    signal?.removeEventListener("abort", abort);
  }
}
