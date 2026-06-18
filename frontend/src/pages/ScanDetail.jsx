import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import {
  ArrowLeft, RefreshCw, Globe, Hash,
  AlertCircle, ScanLine, ChevronRight, Shield, FileText,
} from 'lucide-react'
import { api } from '../api'
import StatusBadge from '../components/StatusBadge'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'

const ACTIVE  = new Set(['queued', 'running', 'processing'])
const POLL_MS = 4000

function formatDate(str) {
  if (!str) return '—'
  return new Date(str.replace(' ', 'T') + 'Z')
    .toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function SectionHeader({ icon: Icon, title }) {
  return (
    <div className="flex items-center gap-2.5 px-6 py-4 border-b border-gray-100 bg-gray-50">
      <div className="w-6 h-6 rounded-md bg-brand-100 flex items-center justify-center">
        <Icon className="w-3.5 h-3.5 text-brand-700" />
      </div>
      <h2 className="text-sm font-bold text-gray-900">{title}</h2>
    </div>
  )
}

function KV({ label, value }) {
  return (
    <div className="flex items-start justify-between gap-4 px-6 py-3 border-b border-gray-50 last:border-0">
      <span className="text-xs font-semibold text-gray-400 uppercase tracking-wide min-w-[130px] pt-0.5">{label}</span>
      <span className="text-sm text-gray-900 text-right flex-1 font-medium">{value ?? '—'}</span>
    </div>
  )
}

function ResultsBody({ results }) {
  if (!results || typeof results !== 'object') {
    return <pre className="bg-gray-900 text-gray-100 rounded-xl m-5 p-4 overflow-x-auto text-xs mono max-h-96">{JSON.stringify(results, null, 2)}</pre>
  }
  const entries = Object.entries(results)
  if (entries.length === 0) {
    return (
      <div className="flex items-center gap-2 px-6 py-6 text-gray-400 text-sm">
        <AlertCircle className="w-4 h-4" />
        No result data available
      </div>
    )
  }
  return (
    <div className="divide-y divide-gray-50">
      {entries.map(([key, val]) => (
        <div key={key} className="px-6 py-4">
          <p className="label mb-2">{key}</p>
          {typeof val === 'object' && val !== null
            ? <pre className="bg-gray-900 text-gray-100 rounded-xl p-4 overflow-x-auto text-xs mono max-h-80">{JSON.stringify(val, null, 2)}</pre>
            : <p className="text-sm text-gray-900 mono">{String(val)}</p>}
        </div>
      ))}
    </div>
  )
}

export default function ScanDetail() {
  const { id }  = useParams()
  const navigate = useNavigate()
  const [scan, setScan]         = useState(null)
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const pollRef = useRef(null)

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const data = await api.getScan(id)
      setScan(data.scan || data)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [id])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    if (!scan) return
    if (ACTIVE.has(scan.status)) {
      pollRef.current = setInterval(() => load(true), POLL_MS)
    } else {
      clearInterval(pollRef.current)
    }
    return () => clearInterval(pollRef.current)
  }, [scan?.status, load])

  const isActive = scan && ACTIVE.has(scan.status)

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">
      <Link to="/scans" className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-brand-600 transition-colors font-medium">
        <ArrowLeft className="w-4 h-4" />
        Back to Scans
      </Link>

      {loading ? (
        <div className="flex items-center justify-center py-32"><Spinner size="lg" /></div>
      ) : error ? (
        <ErrorAlert message={error} onRetry={() => load()} />
      ) : !scan ? null : (
        <>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <h1 className="text-xl font-bold text-gray-900 truncate">{scan.domain}</h1>
                <StatusBadge status={scan.status} />
              </div>
              <p className="mono text-xs text-gray-300">{scan.id}</p>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <button onClick={() => navigate(`/domain/${encodeURIComponent(scan.domain)}/history`)} className="btn-secondary">
                <Globe className="w-4 h-4" />
                Domain History
              </button>
              <button onClick={() => load(true)} disabled={refreshing} className="btn-secondary">
                <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                Refresh
              </button>
            </div>
          </div>

          {isActive && (
            <div className="flex items-center gap-3 px-4 py-3 bg-amber-50 border border-amber-100 rounded-xl text-sm">
              <Spinner size="sm" />
              <span className="text-amber-800 font-medium">
                Scan is {scan.status} — auto-refreshing every {POLL_MS / 1000}s
              </span>
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 card overflow-hidden">
              <SectionHeader icon={FileText} title="Scan Results" />
              {scan.status === 'completed' ? (
                <ResultsBody results={scan.results} />
              ) : scan.status === 'failed' ? (
                <div className="flex items-start gap-3 px-6 py-6 text-red-700">
                  <AlertCircle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                  <div>
                    <p className="font-bold text-sm">Scan failed</p>
                    {scan.error && <p className="text-xs text-red-400 mono mt-1">{scan.error}</p>}
                  </div>
                </div>
              ) : (
                <div className="flex flex-col items-center gap-4 py-16 text-center">
                  <div className="w-12 h-12 rounded-2xl bg-brand-50 flex items-center justify-center">
                    <ScanLine className="w-5 h-5 text-brand-600" />
                  </div>
                  <div>
                    <p className="text-sm font-bold text-gray-900">Scan in progress</p>
                    <p className="text-xs text-gray-400 mt-1">Results will appear here once complete</p>
                  </div>
                  <Spinner />
                </div>
              )}
            </div>

            <div className="space-y-4">
              <div className="card overflow-hidden">
                <SectionHeader icon={Hash} title="Scan Information" />
                <div>
                  <KV label="Scan ID"   value={<span className="mono text-xs text-brand-600">{scan.id}</span>} />
                  <KV label="Domain"    value={scan.domain} />
                  <KV label="Status"    value={<StatusBadge status={scan.status} />} />
                  <KV label="Created"   value={formatDate(scan.created_at)} />
                  <KV label="Updated"   value={formatDate(scan.updated_at)} />
                  {scan.completed_at && <KV label="Completed" value={formatDate(scan.completed_at)} />}
                </div>
              </div>

              <div className="card overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-100">
                  <h3 className="text-sm font-bold text-gray-900">Quick Actions</h3>
                </div>
                <div className="divide-y divide-gray-50">
                  {[
                    { icon: Globe,   label: 'View domain history',    action: () => navigate(`/domain/${encodeURIComponent(scan.domain)}/history`), color: 'bg-blue-50 text-blue-600'   },
                    { icon: ScanLine, label: 'Scan this domain again', action: () => navigate('/scans/new'), color: 'bg-brand-50 text-brand-600'  },
                    { icon: Shield,   label: 'Back to dashboard',      action: () => navigate('/dashboard'), color: 'bg-gray-100 text-gray-500'   },
                  ].map(({ icon: Icon, label, action, color }) => (
                    <button key={label} onClick={action} className="w-full flex items-center gap-3 px-6 py-3.5 text-sm text-gray-700 hover:bg-brand-50 transition-colors group">
                      <div className={`w-7 h-7 rounded-lg ${color} flex items-center justify-center`}>
                        <Icon className="w-3.5 h-3.5" />
                      </div>
                      <span className="flex-1 text-left">{label}</span>
                      <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-brand-500" />
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
