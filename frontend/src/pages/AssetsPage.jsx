import { useState, useEffect, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, ScanLine, Server, ExternalLink, AlertTriangle, Globe } from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'
import AssetSummary from '../components/AssetSummary'
import AssetInventory from '../components/AssetInventory'
import AssetEmptyState from '../components/AssetEmptyState'

/**
 * Assets Page — /assets
 *
 * Data source (v1): latest completed scan's report via GET /api/scans/:id/report
 * Reads modules.subdomains from the report to populate the asset view.
 *
 * Future: dedicated GET /api/assets endpoint aggregating across all scans.
 */

// ─── Data mapping ─────────────────────────────────────────────────────────────

/**
 * Build the AssetSummary + AssetInventory data structures from a scan report.
 * Only modules.subdomains is populated in v1; other categories are zeros/empty.
 */
function buildAssetData(report) {
  const sub = report?.modules?.subdomains

  // Subdomains
  const subItems = (sub?.items || []).map((hostname) => ({
    id:            hostname,
    hostname,
    parent_domain: report.domain,
    ip:            null,   // not available from CT source
    risk:          sub?.sensitive?.includes(hostname) ? 'medium' : null,
    last_seen:     report.completed_at
      ? new Date(report.completed_at).toLocaleDateString(undefined, { dateStyle: 'medium' })
      : null,
  }))

  const exposure = report?.modules?.asset_exposure ?? null

  const summary = {
    domains:         1,
    subdomains:      sub?.count ?? 0,
    certificates:    0,                                // future module
    exposedServices: exposure?.reachable ?? 0,         // live HTTP probe count
    hiddenAssets:    sub?.sensitive?.length ?? 0,
  }

  const inventory = {
    domains: [{
      id:        report.domain,
      domain:    report.domain,
      status:    'active',
      risk:      report.risk_level === 'critical' ? 'critical'
               : report.risk_level === 'high'     ? 'high'
               : report.risk_level === 'moderate' ? 'medium'
               : 'low',
      last_seen: report.completed_at
        ? new Date(report.completed_at).toLocaleDateString(undefined, { dateStyle: 'medium' })
        : null,
    }],
    subdomains:   subItems,
    certificates: [],
    services:     [],
  }

  const takeover = report?.modules?.subdomain_takeover ?? null

  return { summary, inventory, report, takeover, exposure }
}

// HTTP status pill shown in the exposed assets table
function StatusBadge({ status }) {
  if (!status) return <span className="text-xs text-gray-400">Unreachable</span>
  if (status === 200)
    return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-green-100 text-green-700">200 OK</span>
  if (status >= 301 && status <= 308)
    return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-blue-100 text-blue-700">{status} Redirect</span>
  if (status === 401)
    return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-700">401 Auth Required</span>
  if (status === 403)
    return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-700">403 Forbidden</span>
  if (status === 404)
    return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-gray-100 text-gray-500">404 Not Found</span>
  return <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-gray-100 text-gray-600">{status}</span>
}

function hasAnyAssets(summary) {
  return (
    summary.subdomains > 0    ||
    summary.certificates > 0  ||
    summary.exposedServices > 0
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AssetsPage() {
  const [assetData,  setAssetData]  = useState(null)
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [sourceInfo, setSourceInfo] = useState(null)  // { scanId, domain, completedAt }
  const reportFetchedRef = useRef(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)

    try {
      // Step 1: get scan list and find latest completed scan
      const listData = await api.getScans()
      const scans    = listData.scans || []
      const latest   = scans.find(s => s.status === 'completed')

      if (!latest) {
        setAssetData(null)
        setLoading(false)
        setRefreshing(false)
        return
      }

      // Step 2: fetch the report — skip if already fetched for this scan
      if (reportFetchedRef.current !== latest.id) {
        reportFetchedRef.current = latest.id
        const report = await api.getScanReport(latest.id)
        setAssetData(buildAssetData(report))
        setSourceInfo({
          scanId:      latest.id,
          domain:      latest.domain,
          completedAt: report.completed_at,
        })
      }
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // ── Loading ────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Spinner size="lg" />
      </div>
    )
  }

  const isEmpty = !assetData || !hasAnyAssets(assetData.summary)

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-8">

      {/* Page header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <div className="w-8 h-8 rounded-xl bg-brand-50 flex items-center justify-center">
              <Server className="w-4 h-4 text-brand-600" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900">Asset Intelligence</h1>
          </div>
          <p className="text-sm text-gray-400 mt-0.5 ml-10">
            {isEmpty
              ? 'Discover and monitor your full external attack surface'
              : `${assetData.summary.subdomains} subdomains discovered across ${assetData.summary.domains} domain${assetData.summary.domains !== 1 ? 's' : ''}`}
          </p>
        </div>

        <div className="flex items-center gap-2 flex-shrink-0">
          <button
            onClick={() => load(true)}
            disabled={refreshing}
            className="btn-secondary"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <Link to="/scans/new" className="btn-primary">
            <ScanLine className="w-4 h-4" />
            New Scan
          </Link>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-3 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-700">
          <span className="font-semibold">Error loading assets:</span> {error}
        </div>
      )}

      {/* Data source attribution */}
      {sourceInfo && !isEmpty && (
        <div className="flex items-center justify-between px-4 py-2.5 bg-brand-50 border border-brand-100 rounded-xl">
          <p className="text-xs text-brand-700">
            <span className="font-semibold">Asset data source:</span>{' '}
            Certificate Transparency logs via crt.sh · Last scanned:{' '}
            <span className="font-semibold">{sourceInfo.domain}</span>
            {sourceInfo.completedAt && (
              <> · {new Date(sourceInfo.completedAt).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}</>
            )}
          </p>
          <Link
            to={`/scans/${sourceInfo.scanId}`}
            className="text-xs font-semibold text-brand-700 hover:text-brand-800 flex items-center gap-1 flex-shrink-0 ml-4"
          >
            View scan <ExternalLink className="w-3 h-3" />
          </Link>
        </div>
      )}

      {isEmpty ? (
        <AssetEmptyState />
      ) : (
        <>
          <AssetSummary
            domains={assetData.summary.domains}
            subdomains={assetData.summary.subdomains}
            certificates={assetData.summary.certificates}
            exposedServices={assetData.summary.exposedServices}
            hiddenAssets={assetData.summary.hiddenAssets}
          />

          {/* Subdomain Takeover Risks */}
          {assetData.takeover?.risks?.length > 0 && (
            <div className="card p-0 overflow-hidden border border-red-100">
              <div className="flex items-center gap-3 px-5 py-3 bg-red-50 border-b border-red-100">
                <div className="w-7 h-7 rounded-lg bg-red-100 flex items-center justify-center flex-shrink-0">
                  <AlertTriangle className="w-4 h-4 text-red-600" />
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-sm font-semibold text-red-800">
                    Subdomain Takeover Risk{assetData.takeover.risks.length > 1 ? 's' : ''} Detected
                  </span>
                  <span className="text-xs text-red-500">
                    {assetData.takeover.risks.length} vulnerable subdomain{assetData.takeover.risks.length > 1 ? 's' : ''} · {assetData.takeover.checked} checked
                  </span>
                </div>
              </div>
              <div className="overflow-x-auto">
                <table className="data-table w-full">
                  <thead>
                    <tr>
                      <th>Host</th>
                      <th>Vulnerable Service</th>
                      <th>CNAME Target</th>
                      <th>Evidence</th>
                      <th>Severity</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assetData.takeover.risks.map((risk) => (
                      <tr key={risk.host}>
                        <td><span className="mono text-xs">{risk.host}</span></td>
                        <td className="font-medium">{risk.service}</td>
                        <td><span className="mono text-xs text-gray-500">{risk.cname}</span></td>
                        <td className="text-xs text-gray-400 italic">"{risk.evidence}"</td>
                        <td><span className="badge-high">High</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Exposed Assets */}
          {(() => {
            const exp = assetData.exposure
            if (!exp || !exp.assets) return null
            const reachable = exp.assets.filter(a => a.reachable)
            if (reachable.length === 0) return null
            return (
              <div className="card p-0 overflow-hidden">
                <div className="flex items-center gap-3 px-5 py-3 border-b border-gray-100">
                  <div className="w-7 h-7 rounded-lg bg-amber-50 flex items-center justify-center flex-shrink-0">
                    <Globe className="w-4 h-4 text-amber-500" />
                  </div>
                  <div className="flex items-baseline gap-2 min-w-0">
                    <span className="text-sm font-semibold text-gray-900">Exposed Assets</span>
                    <span className="text-xs text-gray-400">
                      {reachable.length} reachable · {exp.checked} checked
                    </span>
                  </div>
                </div>
                <div className="overflow-x-auto">
                  <table className="data-table w-full">
                    <thead>
                      <tr>
                        <th>Host</th>
                        <th>Status</th>
                        <th>Title</th>
                        <th>Server</th>
                        <th>Tech</th>
                      </tr>
                    </thead>
                    <tbody>
                      {reachable.map((asset) => (
                        <tr key={asset.host}>
                          <td>
                            <a
                              href={asset.url}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="mono text-xs text-brand-600 hover:underline"
                            >
                              {asset.host}
                            </a>
                          </td>
                          <td><StatusBadge status={asset.status} /></td>
                          <td className="text-xs text-gray-600 max-w-[200px] truncate">
                            {asset.title || <span className="text-gray-300">—</span>}
                          </td>
                          <td className="text-xs text-gray-500">
                            {asset.server || <span className="text-gray-300">—</span>}
                          </td>
                          <td>
                            <div className="flex flex-wrap gap-1">
                              {(asset.tech || []).map(t => (
                                <span
                                  key={t}
                                  className="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600"
                                >
                                  {t}
                                </span>
                              ))}
                              {(!asset.tech || asset.tech.length === 0) && (
                                <span className="text-gray-300 text-xs">—</span>
                              )}
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )
          })()}

          <AssetInventory
            domains={assetData.inventory.domains}
            subdomains={assetData.inventory.subdomains}
            certificates={assetData.inventory.certificates}
            services={assetData.inventory.services}
          />
        </>
      )}
    </div>
  )
}
