import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { RefreshCw, ScanLine, Server } from 'lucide-react'
import Spinner from '../components/Spinner'
import AssetSummary from '../components/AssetSummary'
import AssetInventory from '../components/AssetInventory'
import AssetEmptyState from '../components/AssetEmptyState'

/**
 * Assets Page — /assets
 *
 * Current state: frontend-only, no API calls.
 * All data props are empty/zero — shows professional empty state with feature preview.
 *
 * API integration checklist (future):
 *   □ Add api.getAssets() to src/api.js pointing at GET /api/assets
 *   □ Replace `assetData` constant below with the useCallback + useEffect fetch pattern
 *   □ Remove `loading = false` override once real fetch is wired
 *   □ Pass real data into <AssetSummary /> and <AssetInventory /> props
 */

// ─── Placeholder data structure ───────────────────────────────────────────────
// Replace this with the API response once GET /api/assets is implemented.

const EMPTY_ASSETS = {
  summary: {
    domains:         0,
    subdomains:      0,
    certificates:    0,
    exposedServices: 0,
    hiddenAssets:    0,
  },
  inventory: {
    domains:      [],
    subdomains:   [],
    certificates: [],
    services:     [],
  },
  // trends will come from the API — e.g. { domains: 'up', trendValues: { domains: '+2 this week' } }
  trends:      {},
  trendValues: {},
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function hasAnyAssets(data) {
  const s = data.summary
  return (
    s.domains > 0       ||
    s.subdomains > 0    ||
    s.certificates > 0  ||
    s.exposedServices > 0 ||
    s.hiddenAssets > 0
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AssetsPage() {
  // When the API is ready, replace these with real fetch state:
  const [assetData,  setAssetData]  = useState(EMPTY_ASSETS)
  const [loading,    setLoading]    = useState(false)   // set to true when real fetch is added
  const [error,      setError]      = useState(null)
  const [refreshing, setRefreshing] = useState(false)

  /**
   * load() — wire this to api.getAssets() when the endpoint exists.
   *
   * Example:
   *   const data = await api.getAssets()
   *   setAssetData(data)
   */
  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      // TODO: const data = await api.getAssets()
      // TODO: setAssetData(data)
      // For now: no-op — shows empty state
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const isEmpty = !hasAnyAssets(assetData)

  // ── Loading ────────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <Spinner size="lg" />
      </div>
    )
  }

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
              : `${
                  assetData.summary.domains +
                  assetData.summary.subdomains +
                  assetData.summary.certificates +
                  assetData.summary.exposedServices +
                  assetData.summary.hiddenAssets
                } assets across all categories`}
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

      {isEmpty ? (
        /* ── Empty state ── */
        <AssetEmptyState />
      ) : (
        /* ── Populated view ── */
        <>
          {/* Asset Summary cards */}
          <AssetSummary
            domains={assetData.summary.domains}
            subdomains={assetData.summary.subdomains}
            certificates={assetData.summary.certificates}
            exposedServices={assetData.summary.exposedServices}
            hiddenAssets={assetData.summary.hiddenAssets}
            trends={assetData.trends}
            trendValues={assetData.trendValues}
          />

          {/* Asset Inventory + Risk Indicators */}
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
