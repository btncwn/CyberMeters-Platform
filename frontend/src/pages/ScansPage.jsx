import { useState, useEffect, useCallback } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { RefreshCw, ScanLine, Globe, Clock, ChevronRight, CheckCircle, XCircle, Shield, AlertTriangle, TrendingUp } from 'lucide-react'
import { api } from '../api'
import StatusBadge from '../components/StatusBadge'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'

function formatDate(str) {
  if (!str) return '—'
  return new Date(str.replace(' ', 'T') + 'Z')
    .toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export default function ScansPage() {
  const [scans, setScans]     = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const navigate = useNavigate()

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

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scans</h1>
          <p className="text-sm text-gray-400 mt-0.5">{scans.length} total scan{scans.length !== 1 ? 's' : ''}</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <Link to="/scans/new" className="btn-primary">
            <ScanLine className="w-4 h-4" />
            New Scan
          </Link>
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
              <div className="w-14 h-14 rounded-2xl bg-brand-50 flex items-center justify-center flex-shrink-0">
                <ScanLine className="w-7 h-7 text-brand-600" />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-base font-bold text-gray-900 mb-1">No scans yet</p>
                <p className="text-sm text-gray-500 leading-relaxed">
                  A security scan analyses a domain's DNS, SSL, headers, email posture, subdomains, and exposed assets —
                  producing a scored risk report in minutes. Run your first scan to start monitoring your attack surface.
                </p>
              </div>
              <Link to="/scans/new" className="btn-primary flex-shrink-0 inline-flex items-center gap-2">
                <ScanLine className="w-4 h-4" /> New Scan
              </Link>
            </div>
            {/* What you get */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 border-t border-gray-100 pt-6">
              {[
                { icon: Shield,        color: 'bg-brand-50 text-brand-600', title: 'Risk Score',      desc: '0–100 Cyber Metrics Score across DNS, SSL, email and headers'           },
                { icon: AlertTriangle, color: 'bg-red-50 text-red-500',     title: 'Findings',        desc: 'Issues ranked by severity — Critical, High, Medium, Low'                },
                { icon: TrendingUp,    color: 'bg-purple-50 text-purple-600', title: 'Trend History', desc: 'Compare scores over time and track remediation progress'                 },
              ].map(({ icon: Icon, color, title, desc }) => (
                <div key={title} className="flex items-start gap-3 p-4 rounded-xl bg-gray-50/60">
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${color}`}>
                    <Icon className="w-4 h-4" />
                  </div>
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
                      <div className="w-7 h-7 rounded-lg bg-gray-100 flex items-center justify-center flex-shrink-0">
                        <Globe className="w-3.5 h-3.5 text-gray-400" />
                      </div>
                      <div>
                        <p className="font-semibold text-gray-900">{scan.domain}</p>
                        <p className="mono text-[11px] text-gray-300 truncate max-w-[200px]">{scan.id}</p>
                      </div>
                    </div>
                  </td>
                  <td><StatusBadge status={scan.status} /></td>
                  <td>
                    <div className="flex items-center gap-1.5 text-xs text-gray-500">
                      <Clock className="w-3.5 h-3.5" />
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
                      <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-brand-500 transition-colors" />
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
