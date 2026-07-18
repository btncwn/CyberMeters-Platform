// ── Timeline Trust helpers ──────────────────────────────────────────────────
// Shared comparability and presentation-collapse contract for customer-facing
// asset_events. Raw asset_events remain append-only; these helpers only decide
// whether a go-forward producer may emit a change event and what customer
// surfaces should show.

export const ASSET_TIMELINE_PRODUCER_VERSION = "asset-timeline-trust-v1";

export const TIMELINE_COMPARISON_STATUS = Object.freeze({
  COMPARABLE: "comparable",
  INSUFFICIENT_HISTORY: "insufficient_history",
  NOT_COMPARABLE: "not_comparable",
  UNAVAILABLE: "unavailable",
});

export const CUSTOMER_CHANGE_EVENT_TYPES = new Set([
  "new_asset_discovered",
  "asset_reappeared",
  "asset_no_longer_seen",
  "dns_ip_changed",
  "dns_cname_changed",
  "dns_redirect_changed",
  "email_spf_changed",
  "email_dmarc_policy_changed",
  "email_dkim_changed",
  "exposed_service_detected",
  "exposed_service_resolved",
  "certificate_new_detected",
  "certificate_new_san_detected",
  "certificate_new_issuer_detected",
]);

export const FLIP_FLOP_EVENT_TYPES = new Set([
  "new_asset_discovered",
  "asset_reappeared",
  "asset_no_longer_seen",
]);

const DEFAULT_FLIP_FLOP_WINDOW_MS = 24 * 60 * 60 * 1000;

export function buildAssetTimelineTrustMetadata() {
  return {
    asset_timeline_producer_version: ASSET_TIMELINE_PRODUCER_VERSION,
  };
}

export function assetTimelineProducerVersion(report) {
  return report?.timeline_trust?.asset_timeline_producer_version
    ?? report?.methodology?.asset_timeline_producer_version
    ?? null;
}

function scanQualityStatus(report, row) {
  return report?.scan_quality?.status ?? row?.scan_quality ?? null;
}

function comparison(status, reason, extra = {}) {
  return {
    comparable: status === TIMELINE_COMPARISON_STATUS.COMPARABLE,
    comparison_status: status,
    reason,
    ...extra,
  };
}

export function assessTimelineComparison({ currentReport, previousReport, currentScan, previousScan } = {}) {
  const currentQuality = scanQualityStatus(currentReport, currentScan);
  const previousQuality = scanQualityStatus(previousReport, previousScan);
  if (currentQuality !== "complete") {
    return comparison(
      TIMELINE_COMPARISON_STATUS.UNAVAILABLE,
      "The current scan did not complete with full evidence, so asset timeline changes are not customer-facing.",
      { current_scan_quality: currentQuality ?? null, previous_scan_quality: previousQuality ?? null }
    );
  }
  if (!previousScan || !previousReport) {
    return comparison(
      TIMELINE_COMPARISON_STATUS.INSUFFICIENT_HISTORY,
      "No previous report with producer provenance exists for this domain.",
      { current_scan_quality: currentQuality ?? null, previous_scan_quality: previousQuality ?? null }
    );
  }
  if (previousQuality !== "complete") {
    return comparison(
      TIMELINE_COMPARISON_STATUS.NOT_COMPARABLE,
      "The previous scan did not complete with full evidence, so its absence/presence signals cannot anchor customer-facing changes.",
      { current_scan_quality: currentQuality ?? null, previous_scan_quality: previousQuality ?? null }
    );
  }

  const currentVersion = assetTimelineProducerVersion(currentReport);
  const previousVersion = assetTimelineProducerVersion(previousReport);
  if (!currentVersion || !previousVersion || currentVersion !== previousVersion) {
    return comparison(
      TIMELINE_COMPARISON_STATUS.NOT_COMPARABLE,
      "The asset timeline producer changed between scans, so the difference is an operator diagnostic rather than a customer security event.",
      {
        current_scan_quality: currentQuality ?? null,
        previous_scan_quality: previousQuality ?? null,
        current_producer_version: currentVersion,
        previous_producer_version: previousVersion,
      }
    );
  }

  return comparison(
    TIMELINE_COMPARISON_STATUS.COMPARABLE,
    "The current and previous scans share complete evidence and the same asset timeline producer.",
    {
      current_scan_quality: currentQuality,
      previous_scan_quality: previousQuality,
      current_producer_version: currentVersion,
      previous_producer_version: previousVersion,
    }
  );
}

export async function loadTimelineComparisonContext(env, { scanId, domainId, currentReport } = {}) {
  if (!env?.cybermeters_db || !scanId || !domainId) {
    return comparison(TIMELINE_COMPARISON_STATUS.UNAVAILABLE, "Timeline comparison inputs are incomplete.");
  }

  const currentScan = await env.cybermeters_db
    .prepare("SELECT id, scan_quality, created_at FROM scans WHERE id = ?")
    .bind(scanId)
    .first()
    .catch(() => null);
  if (!currentScan) {
    return comparison(TIMELINE_COMPARISON_STATUS.UNAVAILABLE, "The current scan row is unavailable.");
  }

  const previousScan = await env.cybermeters_db
    .prepare(
      `SELECT id, scan_quality, created_at FROM scans
       WHERE domain_id = ? AND status = 'completed' AND id != ?
         AND (created_at < ? OR ? IS NULL)
       ORDER BY created_at DESC, id DESC LIMIT 1`
    )
    .bind(domainId, scanId, currentScan.created_at ?? null, currentScan.created_at ?? null)
    .first()
    .catch(() => null);
  if (!previousScan?.id) {
    return comparison(TIMELINE_COMPARISON_STATUS.INSUFFICIENT_HISTORY, "Only one completed scan exists for this domain.", { currentScan });
  }

  const previousReport = await env.cybermeters_reports
    ?.get(`reports/${previousScan.id}.json`)
    .then((obj) => obj?.json?.() ?? null)
    .catch(() => null);

  const assessed = assessTimelineComparison({ currentReport, previousReport, currentScan, previousScan });
  return { ...assessed, currentScan, previousScan, previousReport };
}

function eventMs(row) {
  const t = Date.parse(row?.created_at || "");
  return Number.isFinite(t) ? t : 0;
}

function eventOrder(row) {
  if (row?.event_type === "new_asset_discovered") return 0;
  if (row?.event_type === "asset_no_longer_seen") return 1;
  if (row?.event_type === "asset_reappeared") return 2;
  return 3;
}

function suppressPairedFlipFlops(events, windowMs) {
  const suppress = new Set();
  const byHost = new Map();
  for (const indexed of events) {
    if (!FLIP_FLOP_EVENT_TYPES.has(indexed.row?.event_type)) continue;
    const host = String(indexed.row?.hostname || "").toLowerCase();
    if (!host) continue;
    if (!byHost.has(host)) byHost.set(host, []);
    byHost.get(host).push(indexed);
  }

  for (const hostEvents of byHost.values()) {
    hostEvents.sort((a, b) =>
      eventMs(a.row) - eventMs(b.row)
      || eventOrder(a.row) - eventOrder(b.row)
      || String(a.row?.id || "").localeCompare(String(b.row?.id || ""))
    );
    for (let i = 0; i < hostEvents.length - 1; i++) {
      const a = hostEvents[i];
      if (suppress.has(a.index)) continue;
      for (let j = i + 1; j < hostEvents.length; j++) {
        const b = hostEvents[j];
        if (suppress.has(b.index)) continue;
        if (eventMs(b.row) - eventMs(a.row) > windowMs) break;
        const pair = `${a.row.event_type}->${b.row.event_type}`;
        if (
          pair === "new_asset_discovered->asset_no_longer_seen" ||
          pair === "asset_no_longer_seen->asset_reappeared" ||
          pair === "asset_reappeared->asset_no_longer_seen"
        ) {
          suppress.add(a.index);
          suppress.add(b.index);
          break;
        }
      }
    }
  }
  return suppress;
}

export function collapseCustomerTimelineEvents(rows, opts = {}) {
  const windowMs = opts.flipFlopWindowMs ?? DEFAULT_FLIP_FLOP_WINDOW_MS;
  const indexed = (rows || []).map((row, index) => ({ row, index }));
  const suppress = suppressPairedFlipFlops(indexed, windowMs);
  return indexed
    .filter((item) => !suppress.has(item.index))
    .map((item) => item.row);
}

export function filterCustomerTimelineEventsForScan(rows, scanId, opts = {}) {
  const collapsed = collapseCustomerTimelineEvents(rows, opts);
  return collapsed.filter((row) => row?.scan_id === scanId || (opts.missingScanIdMatches && row?.scan_id == null));
}
