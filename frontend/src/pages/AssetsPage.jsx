import { parseServerDate, formatDate, formatDay } from '../utils/dates'
import CasesQueue from '../components/CasesQueue'
import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, Cloud, X } from 'lucide-react'
import { useDialog } from '../lib/useDialog'
import { api } from '../api'
import ModuleContract from '../components/module/ModuleContract'
import Spinner from '../components/Spinner'
import StatCard from '../components/StatCard'
import AttackSurfaceAssurance from '../components/AttackSurfaceAssurance'
import NetworkAssetsPanel from '../components/NetworkAssetsPanel'
import NetworkAssetsSummary, { NETWORK_ASSETS_TILE_TO } from '../components/NetworkAssetsSummary'
import HostnameListPanel from '../components/HostnameListPanel'
import AssetEvidence from '../components/AssetEvidence'
import { assetLifecycleClaimDisplay, projectedCountDisplay } from '../lib/assetLifecycleClaimDisplay'
import { assetSourceLabel } from '../lib/assetSourceLabel'
import { hostingNetworkRows, hostingNetworkShort, hostingSummaryItems } from '../lib/hostingNetworkDisplay'
import { useLatestScanReport } from '../lib/useLatestScanReport'
import AttackSurfaceScanEvidence, { criticalNamesFromReport, criticalPrefixCoverageText } from '../components/AttackSurfaceScanEvidence'

// ── Formatters ─────────────────────────────────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return '—'
  return formatDay(iso)
}

function fmtDateTime(iso) {
  return formatDate(iso)
}

// ── Badges ─────────────────────────────────────────────────────────────────────

function RiskBadge({ level }) {
  if (!level) return <span className="text-gray-600 text-xs">—</span>
  const cls = {
    critical: 'badge-critical',
    high:     'badge-high',
    medium:   'badge-medium',
    low:      'badge-low',
  }[level] || 'badge-unknown' // M5.e: unknown severity is UNKNOWN, never low-risk blue
  return <span className={cls}>{level}</span>
}

// The asset's lifecycle state, worded by the backend. Colour only separates
// "seen in the latest assessment" from everything else; it adds no verdict.
function StatusPill({ asset }) {
  const label = asset?.lifecycle_state_label || 'Not assessed'
  const cls = asset?.lifecycle_state === 'observed'
    ? 'bg-brand-200 text-brand-900'
    : 'bg-gray-100 text-gray-600'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${cls}`}>
      {label}
    </span>
  )
}

const TYPE_META = {
  root_domain:      { label: 'Root Domain',      cls: 'bg-brand-50 text-brand-700'   },
  subdomain:        { label: 'Subdomain',         cls: 'bg-blue-50 text-blue-700'     },
  exposed_service:  { label: 'Exposed Service',   cls: 'bg-transparent text-brand-700'   },
  cloud_storage:    { label: 'Cloud Storage',     cls: 'bg-purple-50 text-purple-700' },
}

function TypeBadge({ type }) {
  const { label = type, cls = 'bg-gray-100 text-gray-500' } = TYPE_META[type] || {}
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold ${cls}`}>
      {label}
    </span>
  )
}


// ── Summary card ───────────────────────────────────────────────────────────────

function SummaryCard({ icon: Icon, label, value, iconCls = 'text-brand-700', bgCls = 'bg-brand-50' }) {
  return (
    <div className="card p-4 flex items-center gap-3">
      <div className={`w-9 h-9 rounded-xl ${bgCls} flex items-center justify-center shrink-0`}>
        <Icon className={`w-4 h-4 ${iconCls}`} />
      </div>
      <div className="min-w-0">
        <div className="text-2xl font-bold text-gray-900 leading-none">{value ?? '—'}</div>
        <div className="text-xs text-gray-400 mt-0.5 truncate">{label}</div>
      </div>
    </div>
  )
}

// ── Asset Detail Panel ─────────────────────────────────────────────────────────

// Which published provider network the asset's addresses are in. The backend
// decides the match and writes the limits; this only lays them out.
function HostingNetworkDetail({ hostingNetwork }) {
  const short = hostingNetworkShort(hostingNetwork)
  if (!short) return null
  const rows = hostingNetworkRows(hostingNetwork)
  return (
    <div className="col-span-2">
      <div className="label mb-1">Hosting network</div>
      {rows.length === 0 ? (
        <span className="text-xs text-gray-600">{short.text}</span>
      ) : (
        <ul className="space-y-1">
          {rows.map(r => (
            <li key={r.key} className="text-xs text-gray-700">
              <span className="mono">{r.address}</span>
              <span className="text-gray-400"> — </span>
              <span className="font-medium">{r.provider}</span>
              {r.detail && <span className="text-gray-500"> · {r.detail}</span>}
            </li>
          ))}
        </ul>
      )}
      {(hostingNetwork.limitations || []).map(text => (
        <p key={text} className="text-xs text-gray-400 mt-1">{text}</p>
      ))}
    </div>
  )
}

function HostingSummary({ summary }) {
  const items = hostingSummaryItems(summary)
  if (!items.length) return null
  return (
    <div className="card px-5 py-3 flex flex-wrap items-baseline gap-x-5 gap-y-1" aria-label="Hosting networks">
      <span className="text-sm font-semibold text-gray-900">Where these assets answer from</span>
      {items.map(item => (
        <span key={item.key} className="text-sm text-gray-700">
          {item.label} <span className="font-semibold">{item.count}</span>
        </span>
      ))}
      <span className="w-full text-xs text-gray-400">
        Assets still observed, matched against the address ranges each provider publishes
        {summary.checked_providers?.length ? ` (${summary.checked_providers.join(', ')})` : ''}.
        A match does not show whose account runs the server.
      </span>
    </div>
  )
}

function AssetDetailPanel({ workspaceId, assetId, onClose }) {
  const dialogRef = useDialog(onClose)
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    api.getWorkspaceAsset(workspaceId, assetId)
      .then(d  => { if (!cancelled) { setData(d);        setLoading(false) } })
      .catch(e => { if (!cancelled) { setError(e.message); setLoading(false) } })
    return () => { cancelled = true }
  }, [workspaceId, assetId])

  // Parse IP array stored as JSON string
  function parseIps(raw) {
    try { const v = JSON.parse(raw); return Array.isArray(v) ? v : [] }
    catch { return [] }
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/20" onClick={onClose} />
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label="Asset detail" tabIndex={-1} className="relative bg-white shadow-2xl w-full max-w-lg flex flex-col overflow-y-auto">

        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 sticky top-0 bg-white z-10">
          <h2 className="text-base font-semibold text-gray-900">Asset Detail</h2>
          <button
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-lg hover:bg-gray-100 text-gray-400 transition-colors"
            aria-label="Close asset detail"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-6 flex-1 space-y-6">
          {loading && <div className="flex justify-center py-12"><Spinner /></div>}
          {error && (
            <div className="px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">{error}</div>
          )}

          {data && (
            <>
              {/* Hostname */}
              <div>
                <div className="label mb-1">Hostname</div>
                <div className="mono text-sm font-semibold text-gray-900 break-all">{data.asset.hostname}</div>
              </div>

              <AttackSurfaceAssurance presentations={data.attack_surface_assurance || data.asset.attack_surface_assurance} />

              {/* Grid */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="label mb-1">Type</div>
                  <TypeBadge type={data.asset.asset_type} />
                </div>
                <div>
                  <div className="label mb-1">Status</div>
                  <StatusPill asset={data.asset} />
                </div>
                <div>
                  <div className="label mb-1">Source</div>
                  <span className="text-xs text-gray-600">{assetSourceLabel(data.asset.source)}</span>
                </div>
                <div>
                  <div className="label mb-1">Risk</div>
                  <RiskBadge level={data.asset.risk_level} />
                </div>
                <div>
                  <div className="label mb-1">First Seen</div>
                  <span className="text-xs text-gray-600">{fmtDate(data.asset.first_seen)}</span>
                </div>
                <div>
                  <div className="label mb-1">Last Seen</div>
                  <span className="text-xs text-gray-600">{fmtDate(data.asset.last_seen)}</span>
                </div>
                {data.asset.cloud_provider && (
                  <div className="col-span-2">
                    <div className="label mb-1">Cloud Provider</div>
                    <span className="text-xs text-gray-600">{data.asset.cloud_provider}</span>
                  </div>
                )}
                {data.asset.cname && (
                  <div className="col-span-2">
                    <div className="label mb-1">CNAME</div>
                    <span className="mono text-xs text-gray-600">{data.asset.cname}</span>
                  </div>
                )}
                {data.asset.redirect_to && (
                  <div className="col-span-2">
                    <div className="label mb-1">Redirects To</div>
                    <span className="mono text-xs text-gray-600 break-all">{data.asset.redirect_to}</span>
                  </div>
                )}
                {(() => {
                  const ips = parseIps(data.asset.ip_addresses)
                  if (!ips.length) return null
                  return (
                    <div className="col-span-2">
                      <div className="label mb-1">IP Addresses</div>
                      <div className="flex flex-wrap gap-1">
                        {ips.map(ip => (
                          <span key={ip} className="mono text-xs bg-gray-50 border border-gray-200 rounded-sm px-1.5 py-0.5">
                            {ip}
                          </span>
                        ))}
                      </div>
                    </div>
                  )
                })()}
                <HostingNetworkDetail hostingNetwork={data.asset.hosting_network} />
              </div>

              {/* Why the name is listed and what was measured for it */}
              <AssetEvidence evidence={data.evidence} />

              {/* Events */}
              {data.events.length > 0 && (
                <div>
                  <div className="label mb-3">Recent Events ({data.events.length})</div>
                  <div className="space-y-2">
                    {data.events.map(ev => {
                      const claimDisplay = assetLifecycleClaimDisplay(ev)
                      return (
                      <div key={ev.id} className="flex items-start gap-3 px-3 py-2.5 bg-gray-50 rounded-xl">
                        <div className="w-1.5 h-1.5 rounded-full bg-brand-400 mt-1.5 shrink-0" />
                        <div className="min-w-0 flex-1">
                          <div className="text-xs font-medium text-gray-700 capitalize">
                            {claimDisplay.title || ev.event_type.replace(/_/g, ' ')}
                          </div>
                          {claimDisplay.description && (
                            <div className="text-xs text-gray-400 mt-0.5">{claimDisplay.description}</div>
                          )}
                          {claimDisplay.supportLabel && <div className="text-xs text-gray-400 mt-1">{claimDisplay.supportLabel}</div>}
                          <div className="text-xs text-gray-400 mt-1">{fmtDateTime(ev.created_at)}</div>
                        </div>
                      </div>
                    )})}
                  </div>
                </div>
              )}
              {data.events.length === 0 && (
                <p className="text-xs text-gray-400">No events recorded for this asset.</p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Timeline table ─────────────────────────────────────────────────────────────

const TIMELINE_COLS = [
  { key: 'new_asset_discovered',   label: 'New'       },
  { key: 'asset_reappeared',       label: 'Reappeared'},
  { key: 'no_longer_observed_assets', label: 'No longer observed', projected: true },
  { key: 'takeover_risk_detected', label: 'Takeover'  },
  { key: 'wildcard_dns_detected',  label: 'Wildcard'  },
  { key: 'cloud_storage_detected', label: 'Cloud'     },
]

function Timeline({ rows, projection }) {
  if (!rows || rows.length === 0) {
    return (
      <p className="text-sm text-gray-400 py-8 text-center">
        No timeline data yet. Run a scan to start tracking asset changes.
      </p>
    )
  }

  const sorted = [...rows].sort((a, b) => b.day.localeCompare(a.day)).slice(0, 30)

  return (
    <div className="overflow-x-auto">
      <table className="data-table w-full">
        <thead>
          <tr>
            <th>Date</th>
            {TIMELINE_COLS.map(c => <th key={c.key} className="text-center">{c.label}</th>)}
          </tr>
        </thead>
        <tbody>
          {sorted.map(row => (
            <tr key={row.day}>
              <td className="mono text-xs">{row.day}</td>
              {TIMELINE_COLS.map(c => {
                const count = c.projected
                  ? projectedCountDisplay(row[c.key], projection)
                  : { value: row[c.key] ?? 0, label: '' }
                return (
                  <td key={c.key} className="text-center">
                    {count.value == null
                      ? <span className="text-gray-400 text-xs">{count.label}</span>
                      : count.value > 0
                      ? (
                        <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-brand-50 text-brand-700 text-xs font-semibold">
                          {count.value}
                        </span>
                      )
                      : <span className="text-gray-600 text-xs">—</span>
                    }
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Filter button ──────────────────────────────────────────────────────────────

function FilterBtn({ active, onClick, children }) {
  return (
    <button
      onClick={onClick}
      className={active
        ? 'px-3 py-1 rounded-lg text-xs font-semibold bg-brand-200 text-brand-900 transition-colors'
        : 'px-3 py-1 rounded-lg text-xs font-semibold bg-white border border-gray-200 text-gray-600 hover:border-brand-300 transition-colors'
      }
    >
      {children}
    </button>
  )
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function AssetsPage() {
  const workspaceId   = localStorage.getItem('cybermeters_workspace_id')
  const workspaceName = localStorage.getItem('cybermeters_workspace_name')

  const [summary,      setSummary]      = useState(null)
  const [assets,       setAssets]       = useState([])
  const [hostingSummary, setHostingSummary] = useState(null)
  const [assurance,    setAssurance]    = useState([])
  const [assuranceCoverage, setAssuranceCoverage] = useState(null)
  const [timeline,     setTimeline]     = useState([])
  const [timelineProjection, setTimelineProjection] = useState(null)
  const [loading,      setLoading]      = useState(true)
  const [refreshing,   setRefreshing]   = useState(false)
  const [error,        setError]        = useState(null)
  const [statusFilter, setStatusFilter] = useState('all')
  const [typeFilter,   setTypeFilter]   = useState('all')
  const [selectedId,   setSelectedId]   = useState(null)
  const [refreshTick,  setRefreshTick]  = useState(0)
  const [scanDomain,   setScanDomain]   = useState('')
  // The latest scan report: registration, public content, deep TLS, the check
  // pack's vulnerability-data statement and the critical names the DNS pass found.
  const latest = useLatestScanReport(workspaceId, { refresh: refreshTick, domain: scanDomain })
  const criticalNames = criticalNamesFromReport(latest.report)
  const criticalCoverage = criticalPrefixCoverageText(latest.report)

  const load = useCallback(async (silent = false) => {
    if (!workspaceId) { setLoading(false); return }
    if (!silent) setLoading(true); else setRefreshing(true)
    setError(null)
    setRefreshTick((n) => n + 1)
    try {
      const [sumData, assetsData, timelineData] = await Promise.all([
        api.getWorkspaceAssetsSummary(workspaceId),
        api.getWorkspaceAssets(workspaceId),
        api.getWorkspaceAssetsTimeline(workspaceId),
      ])
      setSummary(sumData)
      setAssets(assetsData.assets || [])
      setHostingSummary(assetsData.hosting_summary || null)
      setAssurance(assetsData.attack_surface_assurance || [])
      setAssuranceCoverage(assetsData.attack_surface_assurance_coverage || null)
      setTimeline(timelineData.timeline || [])
      setTimelineProjection(timelineData.lifecycle_claim_projection || null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [workspaceId])

  useEffect(() => { load() }, [load])

  // ── No workspace selected ─────────────────────────────────────────────────
  if (!workspaceId) {
    return (
      <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8">
        <div className="card p-12 text-center">
          <h2 className="text-lg font-semibold text-gray-900 mb-2">Select a Workspace</h2>
          <p className="text-sm text-gray-400 mb-6">
            Asset inventory is scoped to a workspace. Select one from the top navigation.
          </p>
          <Link to="/workspaces" className="btn-primary">
            Go to Workspaces
          </Link>
        </div>
      </div>
    )
  }

  // ── Client-side filters ───────────────────────────────────────────────────
  const filtered = assets.filter(a => {
    if (statusFilter !== 'all' && a.lifecycle_state !== statusFilter) return false
    if (typeFilter   !== 'all' && a.asset_type !== typeFilter)   return false
    return true
  })

  return (
    <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8 space-y-6">

      <ModuleContract
        domainKey="attack_surface"
        workspaceId={workspaceId}
        workspaceName={workspaceName}
        /* The area template (18 Oct 2026): four inventory counts are "What we
           observed" — the backend's lifecycle counts, never the legacy active flag. */
        figures={summary ? [
          { key: 'observed', label: 'Seen in latest scan', value: summary.lifecycle_counts?.observed ?? '—', explanation: 'Found through DNS or a web service in the latest assessment' },
          { key: 'removed', label: 'No longer observed', value: summary.lifecycle_counts?.confirmed_removed ?? '—', explanation: 'Not seen for at least 48 hours across repeated scans; not proof it was removed' },
          { key: 'services', label: 'Exposed services', value: summary.exposed_services ?? '—', explanation: 'Internet-facing services to review', tone: (summary.exposed_services ?? 0) > 0 ? 'text-brand-700' : undefined },
          { key: 'takeover', label: 'Takeover risks', value: summary.takeover_risks ?? '—', explanation: 'Possible subdomain takeovers', tone: (summary.takeover_risks ?? 0) > 0 ? 'text-red-700' : undefined },
        ] : null}
        description="Your externally reachable hosts and services, tracked across scans: what appeared, what changed and what is exposed."
        /* The "Network assets" page tile (Findings · #network-assets) carries an
           honest one-liner from the network panel's own API. */
        tileSummaries={{ [NETWORK_ASSETS_TILE_TO]: <NetworkAssetsSummary workspaceId={workspaceId} /> }}
        actions={(
          <button onClick={() => load(true)} disabled={refreshing || loading} className="btn-secondary shrink-0">
            {refreshing && <RefreshCw className="w-4 h-4 animate-spin" />}
            Reload results
          </button>
        )}
        overview={loading ? (
          <div className="flex items-center justify-center min-h-[20vh]"><Spinner size="lg" /></div>
        ) : (
          <>
            {error && (
              <div className="px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
                <span className="font-semibold">Error:</span> {error}
              </div>
            )}
            {/* Coverage honesty: which signals the latest scan did and did not observe. */}
            <AttackSurfaceAssurance
              presentations={assurance}
              coverage={assuranceCoverage}
            />

          </>
        )}
      >
      {/* Error */}
      {error && (
        <div className="px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
          <span className="font-semibold">Error:</span> {error}
        </div>
      )}

      {loading ? (
        <div className="flex items-center justify-center min-h-[40vh]">
          <Spinner size="lg" />
        </div>
      ) : (
        <>
          <HostnameListPanel key={`hostnames-${workspaceId}`} workspaceId={workspaceId} />

          <NetworkAssetsPanel key={workspaceId} workspaceId={workspaceId} />

          {/* What the latest scan recorded for the domain itself: registration,
              public content and management surfaces, deep TLS and the check
              pack's vulnerability-data statement. Full detail stays on the scan page. */}
          <AttackSurfaceScanEvidence latest={latest} selectedDomain={scanDomain} onSelectDomain={setScanDomain} />

          <HostingSummary summary={hostingSummary} />

          {/* ── Filters ───────────────────────────────────────────────────── */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="label">Status</span>
              {['all', 'observed', 'confirmed_removed'].map(v => (
                <FilterBtn key={v} active={statusFilter === v} onClick={() => setStatusFilter(v)}>
                  {v === 'all' ? 'All' : v === 'observed' ? 'Seen in latest scan' : 'No longer observed'}
                </FilterBtn>
              ))}
            </div>

            <div className="w-px h-4 bg-gray-200" />

            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="label">Type</span>
              {[
                { v: 'all',             label: 'All'             },
                { v: 'root_domain',     label: 'Root Domain'     },
                { v: 'subdomain',       label: 'Subdomain'       },
                { v: 'exposed_service', label: 'Exposed Service' },
                { v: 'cloud_storage',   label: 'Cloud Storage'   },
              ].map(({ v, label }) => (
                <FilterBtn key={v} active={typeFilter === v} onClick={() => setTypeFilter(v)}>
                  {label}
                </FilterBtn>
              ))}
            </div>

            <span className="ml-auto text-xs text-gray-400">
              {filtered.length} asset{filtered.length !== 1 ? 's' : ''}
            </span>
          </div>

          {/* The critical-prefix DNS pass (admin, login, portal, vpn…) is the
              backend's own list; a listed name is tagged in the table below. */}
          {criticalCoverage && (
            <p className="text-xs text-gray-500" data-testid="critical-prefix-coverage">{criticalCoverage} A critical name is tagged in the table; the tag records that the name answers in DNS, not that it is exposed.</p>
          )}

          {/* ── Asset lifecycle table ─────────────────────────────────────── */}
          {/* One reading guide for the whole table (founder, 18 Oct 2026), never repeated per row. */}
          <details className="card p-4 text-sm text-gray-700" data-testid="asset-lifecycle-howto">
            <summary className="cursor-pointer font-semibold text-gray-900">How to read this</summary>
            <dl className="mt-3 space-y-2">
              <div><dt className="font-medium text-gray-900">Observed</dt><dd className="text-gray-600">Seen in the latest assessment through DNS or a web service.</dd></div>
              <div><dt className="font-medium text-gray-900">Not observed in this scan</dt><dd className="text-gray-600">Missing from the latest assessment only; one scan is not enough to say it went away.</dd></div>
              <div><dt className="font-medium text-gray-900">No longer externally observed</dt><dd className="text-gray-600">Not seen for at least 48 hours across repeated scans. That is not proof it was removed.</dd></div>
              <div><dt className="font-medium text-gray-900">Not assessed</dt><dd className="text-gray-600">No assessment has recorded this name yet.</dd></div>
              <div><dt className="font-medium text-gray-900">Latest evidence</dt><dd className="text-gray-600">How the name was found and, where measured, the network it answers from. Open a row for the full record.</dd></div>
            </dl>
          </details>
          <div className="card p-0 overflow-hidden">
            {filtered.length === 0 ? (
              <div className="text-center py-12 text-sm text-gray-400">
                No assets match the current filter.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="data-table w-full">
                  <thead>
                    <tr>
                      <th>Hostname</th>
                      <th>Lifecycle state</th>
                      <th>Latest evidence</th>
                      <th>Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map(asset => (
                      <tr
                        key={asset.id}
                        className="cursor-pointer hover:bg-brand-50/40 transition-colors"
                        onClick={() => setSelectedId(asset.id)}
                      >
                        <td>
                          <button type="button" onClick={(e) => { e.stopPropagation(); setSelectedId(asset.id) }} className="mono text-xs font-medium text-gray-800 text-left hover:underline">{asset.hostname}</button>
                          {asset.wildcard_dns === 1 && (
                            <span className="ml-2 text-xs text-brand-700 font-semibold">WILDCARD</span>
                          )}
                          {criticalNames.has(String(asset.hostname || '').toLowerCase()) && (
                            <span className="ml-2 inline-flex items-center rounded-full border border-red-100 bg-red-50 px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide text-red-700" title="Found by the critical-name DNS pass in the latest scan">Critical name</span>
                          )}
                          {/* Type and risk stay with the name, so neither is lost from the row. */}
                          <span className="mt-1 flex flex-wrap items-center gap-1.5">
                            <TypeBadge type={asset.asset_type} />
                            <RiskBadge level={asset.risk_level} />
                          </span>
                        </td>
                        <td><StatusPill asset={asset} /></td>
                        <td className="text-xs text-gray-600">
                          {assetSourceLabel(asset.source)}
                          {/* The network the name answers from, or a dash when it was not checked. */}
                          <span className="block text-gray-600">{hostingNetworkShort(asset.hosting_network)?.text ?? '—'}</span>
                        </td>
                        <td className="text-xs text-gray-600">{fmtDate(asset.last_seen)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* ── Timeline ──────────────────────────────────────────────────── */}
          <div className="card p-0 overflow-hidden">
            <div className="flex items-center gap-3 px-5 py-3 border-b border-gray-100">
              <div className="flex items-baseline gap-2">
                <span className="text-sm font-semibold text-gray-900">Asset Timeline</span>
                <span className="text-xs text-gray-400">daily change counts · most recent 30 days with changes</span>
              </div>
            </div>
            <Timeline rows={timeline} projection={timelineProjection} />
          </div>

          {/* TEMPORARY integration mount of the reusable cross-domain CasesQueue.
              The Attack Surface page is NOT the permanent home for all-domain
              cases; the queue component is workspace-scoped and standalone, ready
              to move to its own route/nav in a later IA pass (not this episode). */}
          <div className="mt-4">
            <CasesQueue workspaceId={workspaceId} />
          </div>
        </>
      )}

      </ModuleContract>

      {/* ── Detail panel ────────────────────────────────────────────────────── */}
      {selectedId && (
        <AssetDetailPanel
          workspaceId={workspaceId}
          assetId={selectedId}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  )
}
