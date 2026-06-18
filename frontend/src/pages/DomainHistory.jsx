import { useState, useEffect, useCallback } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, RefreshCw, Globe, Clock, ScanLine,
  ChevronRight, Activity, CheckCircle, CalendarDays,
} from 'lucide-react'
import { api } from '../api'
import StatusBadge from '../components/StatusBadge'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'
import EmptyState from '../components/EmptyState'

function formatDate(str) {
  if (!str) return '—'
  return new Date(str.replace(' ', 'T') + 'Z')
    .toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function relativeTime(str) {
  if (!str) return ''
  const diff = Date.now() - new Date(str.replace(' ', 'T') + 'Z').getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export default function DomainHistory() {
  const { domain } = useParams()
  const navigate   = useNavigate()
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]     = useState(null)
  const [refreshing, setRefreshing] = useState(false)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const res = await api.getDomainHistory(domain)
      setData(res)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [domain])

  useEffect(() => { load() }, [load])

  const scans     = data?.scans || []
  const completed = scans.filter(s => s.status === 'completed').length
  const latest    = scans[0]

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">
      <Link to="/scans" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-brand-600 transition-colors font-medium">
        <ArrowLeft className="w-4 h-4" />
        Back to Scans
      </Link>

      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <div className="w-8 h-8 rounded-lg bg-brand-50 border border-brand-100 flex items-center justify-center">
              <Globe className="w-4 h-4 text-brand-600" />
            </div>
            <h1 className="text-xl font-bold text-gray-900">{domain}</h1>
          </div>
          <p className="text-sm text-gray-400">Scan history for this domain</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <Link to="/scans/new" className="btn-primary" state={{ domain }}>
            <ScanLine className="w-4 h-4" />
            New Scan
          </Link>
        </div>
      </div>

      {!loading && scans.length > 0 && (
        <div className="grid grid-cols-3 gap-4">
          <div className="card p-5">
            <div className="w-8 h-8 rounded-lg bg-brand-50 flex items-center justify-center mb-3">
              <Activity className="w-4 h-4 text-brand-600" />
            </div>
            <p className="text-3xl font-bold text-brand-700">{scans.length}</p>
            <p className="text-sm font-semibold text-gray-700 mt-1">Total Scans</p>
          </div>
          <div className="card p-5">
            <div className="w-8 h-8 rounded-lg bg-green-50 flex items-center justify-center mb-3">
              <CheckCircle className="w-4 h-4 text-green-600" />
            </div>
            <p className="text-3xl font-bold text-green-700">{completed}</p>
            <p className="text-sm font-semibold text-gray-700 mt-1">Completed</p>
          </div>
          <div className="card p-5">
            <div className="w-8 h-8 rounded-lg bg-blue-50 flex items-center justify-center mb-3">
              <CalendarDays className="w-4 h-4 text-blue-600" />
            </div>
            <p className="text-sm font-bold text-blue-700 mt-1">{latest ? relativeTime(latest.created_at) : '—'}</p>
            <p className="text-sm font-semibold text-gray-700 mt-1">Last Scan</p>
          </div>
        </div>
      )}

      {error && <ErrorAlert message={error} onRetry={() => load()} />}

      <div className="card overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100 bg-gray-50">
          <h2 className="text-sm font-bold text-gray-900">Scan Timeline</h2>
          {scans.length > 0 && (
            <span className="text-xs font-medium text-gray-400 mono">{scans.length} scan{scans.length !== 1 ? 's' : ''}</span>
          )}
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-20"><Spinner size="lg" /></div>
        ) : scans.length === 0 ? (
          <EmptyState
            icon={Globe}
            title="No scan history"
            description={`No scans found for ${domain}`}
            action={<Link to="/scans/new" className="btn-primary"><ScanLine className="w-4 h-4" />Start first scan</Link>}
          />
        ) : (
          <div className="relative">
            <div className="absolute left-[45px] top-5 bottom-5 w-px bg-gray-100" />
            <ul className="divide-y divide-gray-50">
              {scans.map((scan, i) => (
                <li
                  key={scan.id}
                  onClick={() => navigate(`/scans/${scan.id}`)}
                  className="flex items-start gap-4 px-6 py-4 hover:bg-brand-50/40 cursor-pointer transition-colors group"
                >
                  <div className="relative z-10 flex-shrink-0 mt-0.5">
                    <div className={`w-6 h-6 rounded-full border-2 flex items-center justify-center ${
                      i === 0 ? 'border-brand-500 bg-brand-50' : 'border-gray-200 bg-white'
                    }`}>
                      {i === 0 && <span className="w-2 h-2 rounded-full bg-brand-500" />}
                    </div>
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <StatusBadge status={scan.status} />
                      {i === 0 && (
                        <span className="text-[10px] text-brand-700 bg-brand-50 border border-brand-100 rounded-full px-2 py-0.5 font-bold uppercase tracking-wider">
                          Latest
                        </span>
                      )}
                    </div>
                    <p className="mono text-[11px] text-gray-300 mt-1.5 truncate">{scan.id}</p>
                    <div className="flex items-center gap-3 mt-1">
                      <span className="text-xs text-gray-400 flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {formatDate(scan.created_at)}
                      </span>
                      <span className="text-xs text-gray-300">{relativeTime(scan.created_at)}</span>
                    </div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-brand-500 transition-colors flex-shrink-0 mt-1" />
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}
