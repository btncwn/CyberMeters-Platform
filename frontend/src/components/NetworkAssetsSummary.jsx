// NetworkAssetsSummary — the honest one-liner on the Attack Surface Overview's
// "Network assets" page tile (the tile itself is the area item in WorkspaceNav,
// linking to the Findings tab at #network-assets). Since #650 nothing on
// Overview pointed at the network/port evidence, so it read as gone.
//
// From the data the panel's own API already returns, never invented:
//   • targets and a completed network scan →
//       "N targets · M open ports in the latest network scan"
//     (M counts inventory rows observed open by that scan; "at least" when the
//     inventory page is not complete);
//   • targets but no completed scan → "N targets · no completed network scan yet";
//   • no targets → "Add an IP or network you are authorised to test to see open ports";
//   • read failure → "Network inventory could not be read" (never a number).
import { useEffect, useState } from 'react'
import { api } from '../api'

export const NETWORK_ASSETS_ANCHOR = 'network-assets'
export const NETWORK_ASSETS_TILE_TO = `/assets#${NETWORK_ASSETS_ANCHOR}`

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`

/** Pure: the one-line summary. */
export function networkAssetsSummary({ targets, assets, scans, nextCursor } = {}) {
  const targetCount = Array.isArray(targets) ? targets.length : null
  if (targetCount === null) return { text: 'Network inventory could not be read', state: 'unavailable' }
  if (targetCount === 0) return { text: 'Add an IP or network you are authorised to test to see open ports', state: 'empty' }
  const completed = (Array.isArray(scans) ? scans : [])
    .filter((s) => s?.status === 'completed' && s?.completed_at)
    .sort((a, b) => String(b.completed_at).localeCompare(String(a.completed_at)))
  const latest = completed[0] || null
  if (!latest) return { text: `${plural(targetCount, 'target', 'targets')} · no completed network scan yet`, state: 'no_scan' }
  const open = (Array.isArray(assets) ? assets : []).filter((a) => a?.state === 'open' && (!a.last_scan_id || a.last_scan_id === latest.id)).length
  const prefix = nextCursor ? 'at least ' : ''
  return { text: `${plural(targetCount, 'target', 'targets')} · ${prefix}${plural(open, 'open port', 'open ports')} in the latest network scan`, state: 'measured' }
}

export default function NetworkAssetsSummary({ workspaceId }) {
  const [data, setData] = useState({ workspaceId: null, loading: true, summary: null })

  useEffect(() => {
    if (!workspaceId) return undefined
    const controller = new AbortController()
    setData({ workspaceId, loading: true, summary: null })
    // Resolved lazily so a client without these methods (an older bundle, a
    // partial test double) lands in .catch as "could not be read", never a crash.
    Promise.resolve()
      .then(() => Promise.all([
        api.getNetworkTargets(workspaceId, { signal: controller.signal }),
        api.getNetworkAssets(workspaceId, { signal: controller.signal }),
        api.getNetworkScans(workspaceId, { signal: controller.signal }),
      ]))
      .then(([targets, inventory, scans]) => {
        if (controller.signal.aborted) return
        setData({ workspaceId, loading: false, summary: networkAssetsSummary({
          targets: targets?.targets || [], assets: inventory?.assets || [], scans: scans?.scans || [], nextCursor: inventory?.next_cursor ?? null,
        }) })
      })
      .catch(() => { if (!controller.signal.aborted) setData({ workspaceId, loading: false, summary: networkAssetsSummary({}) }) })
    return () => controller.abort()
  }, [workspaceId])

  if (!workspaceId) return null
  const current = data.workspaceId === workspaceId ? data : { loading: true, summary: null }
  const summary = current.loading ? { text: 'Reading the network inventory…', state: 'loading' } : current.summary
  return (
    <span className="block text-xs font-semibold text-gray-700 mt-1" data-testid="network-assets-summary" data-state={summary.state}>
      {summary.text}
    </span>
  )
}
