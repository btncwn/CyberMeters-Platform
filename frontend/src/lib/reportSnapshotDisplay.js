// Presentation for GET /api/workspaces/:id/report-snapshots (M5.c canonical
// snapshots). A snapshot is a fixed, checksummed record of all eight domains
// from one completed scan; reports render from it and never recalculate it.

export const SNAPSHOT_QUALITY_TEXT = Object.freeze({
  complete: 'Complete scan',
  partial: 'Partial scan — some evidence was missing',
  degraded: 'Degraded scan — some checks could not run',
})

export function snapshotQualityText(q) {
  return SNAPSHOT_QUALITY_TEXT[q] || 'Scan quality not recorded'
}

/** Rows newest first, with the domain's name (or an honest "no longer in this workspace"). */
export function snapshotRows(snapshots, domains) {
  const names = new Map((domains || []).map((d) => [d.domain_id ?? d.id, d.domain]))
  return (Array.isArray(snapshots) ? snapshots : []).map((s) => ({
    id: s.id,
    scan_id: s.scan_id,
    assessed_at: s.assessed_at,
    domain: names.get(s.domain_id) || null,
    quality: snapshotQualityText(s.scan_quality),
    current: !s.superseded_by,
  }))
}
