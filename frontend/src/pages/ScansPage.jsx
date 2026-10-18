import { useState, useEffect, useCallback, useRef } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { RefreshCw } from 'lucide-react'
import { api } from '../api'
import StatusBadge from '../components/StatusBadge'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'
import InternalIdCopyButton from '../components/InternalIdCopyButton'
import { formatDate } from '../utils/dates'
import { useWorkspaceRole } from '../hooks/useWorkspaceRole'
import { scanNotPermittedMessage, RESCAN_ONLY_MESSAGE } from '../lib/workspaceRole'

// Statuses that indicate a scan is still in progress and the list needs to refresh.
const ACTIVE_STATUSES = new Set(['queued', 'running', 'processing'])
const POLL_MS = 6000

export default function ScansPage() {
  const [scans, setScans]     = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const pollRef = useRef(null)
  const navigate = useNavigate()
  // New Scan is offered only to roles that can add domains; a member who may
  // rescan verified domains is offered Rescan instead (18 Oct 2026).
  const [wsId] = useState(() => localStorage.getItem('cybermeters_workspace_id'))
  const { scanAccess, ownerName } = useWorkspaceRole(wsId)
  const canScanNewDomain = scanAccess === 'full'

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const data = await api.getScans()
      setScans(data.scans || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Auto-poll while any scan is in an active state so the list stays current
  // without requiring a manual Refresh click or navigation to the detail page.
  useEffect(() => {
    clearInterval(pollRef.current)
    const hasActive = scans.some(s => ACTIVE_STATUSES.has(s.status))
    if (hasActive) {
      pollRef.current = setInterval(() => load(true), POLL_MS)
    }
    return () => clearInterval(pollRef.current)
  }, [scans, load])

  return (
    <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8 space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scans</h1>
          <p className="text-sm text-gray-400 mt-0.5">{scans.length} total scan{scans.length !== 1 ? 's' : ''}</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
            {refreshing && <RefreshCw className="w-4 h-4 animate-spin" />}
            Refresh
          </button>
          {canScanNewDomain && (
            <Link to="/scans/new" className="btn-primary">
              New Scan
            </Link>
          )}
          {scanAccess === 'rescan' && (
            <Link to="/scans/new" className="btn-primary">
              Rescan a domain
            </Link>
          )}
        </div>
      </div>

      {error && <ErrorAlert message={error} onRetry={() => load()} />}

      <div className="card overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-24"><Spinner size="lg" /></div>
        ) : scans.length === 0 ? (
          <div className="p-8 space-y-6">
            {/* Hero */}
            <div className="flex flex-col sm:flex-row sm:items-center gap-5">
              <div className="flex-1 min-w-0">
                <p className="text-base font-bold text-gray-900 mb-1">No scans yet</p>
                <p className="text-sm text-gray-500 leading-relaxed">
                  A Cyber MOT runs CyberMeters' Intelligence Engines across your domain — Website Security, Email Protection,
                  Brand Protection, and Certificates &amp; Trust, then turns the evidence into a scored Executive Report in minutes. Run your first
                  Cyber MOT to start monitoring what is visible from outside.
                </p>
                {scanAccess === 'rescan' && (
                  <p className="text-sm text-gray-600 mt-2" data-testid="scan-rescan-only">{RESCAN_ONLY_MESSAGE}</p>
                )}
                {scanAccess === 'none' && (
                  <p className="text-sm text-gray-600 mt-2" data-testid="scan-not-permitted">{scanNotPermittedMessage(ownerName)}</p>
                )}
              </div>
              {scanAccess !== 'none' && (
                <Link to="/scans/new" className="btn-primary shrink-0 inline-flex items-center gap-2">
                  {canScanNewDomain ? 'New Scan' : 'Rescan a domain'}
                </Link>
              )}
            </div>
            {/* What you get */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 border-t border-gray-100 pt-6">
              {[
                { title: 'Cyber Metrics Score', desc: 'A single 0–100 score summarising your external posture'               },
                { title: 'Observed Findings',   desc: 'Issues ranked by severity — Critical, High, Medium, Low'              },
                { title: 'Trend History',     desc: 'Compare scores over time and track remediation progress'              },
              ].map(({ title, desc }) => (
                <div key={title} className="flex items-start gap-3 p-4 rounded-xl bg-gray-50/60">
                  <div>
                    <p className="text-sm font-semibold text-gray-900">{title}</p>
                    <p className="text-xs text-gray-400 leading-relaxed mt-0.5">{desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <table className="w-full data-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Status</th>
                <th>Created</th>
                <th className="text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map(scan => (
                <tr
                  key={scan.id}
                  onClick={() => navigate(`/scans/${scan.id}`)}
                  className="hover:bg-brand-50/40 cursor-pointer transition-colors group"
                >
                  <td>
                    <div className="flex items-center gap-2.5">
                      <div>
                        <p className="font-semibold text-gray-900">{scan.domain}</p>
                        <InternalIdCopyButton id={scan.id} label="scan" />
                      </div>
                    </div>
                  </td>
                  <td><StatusBadge status={scan.status} quality={scan.scan_quality} /></td>
                  <td>
                    <div className="flex items-center gap-1.5 text-xs text-gray-500">
                      {formatDate(scan.created_at)}
                    </div>
                  </td>
                  <td>
                    <div className="flex items-center justify-end gap-1">
                      <button
                        onClick={e => { e.stopPropagation(); navigate(`/domain/${encodeURIComponent(scan.domain)}/history`) }}
                        className="btn-ghost text-xs"
                      >
                        History
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
