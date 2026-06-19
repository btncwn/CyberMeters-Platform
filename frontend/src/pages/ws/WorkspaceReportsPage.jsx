import { useState, useEffect, useCallback, useRef } from 'react'
import { FileText, Download, Plus, RefreshCw, AlertTriangle, Clock } from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDateTime(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return new Date(s).toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function fmtType(type) {
  if (!type) return '—'
  return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function StatusBadge({ status }) {
  const cfg = {
    completed: 'bg-brand-50 text-brand-700 border-brand-100',
    failed:    'bg-red-50 text-red-700 border-red-100',
    pending:   'bg-amber-50 text-amber-700 border-amber-100',
    running:   'bg-amber-50 text-amber-700 border-amber-100',
  }[status] ?? 'bg-gray-50 text-gray-500 border-gray-100'

  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${cfg}`}>
      {(status === 'pending' || status === 'running') && (
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
      )}
      {status}
    </span>
  )
}

// ── Report type selector ──────────────────────────────────────────────────────

const REPORT_TYPES = [
  { value: 'manual',              label: 'Manual Snapshot' },
  { value: 'scan_snapshot',       label: 'Scan Snapshot'   },
  { value: 'weekly_executive',    label: 'Weekly Executive' },
  { value: 'monthly_executive',   label: 'Monthly Executive' },
]

// ── Main page ─────────────────────────────────────────────────────────────────

export default function WorkspaceReportsPage() {
  const { wsId, wsName } = useWorkspace()

  const [reports,      setReports]      = useState([])
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState(null)
  const [generating,   setGenerating]   = useState(false)
  const [genError,     setGenError]     = useState(null)
  const [reportType,   setReportType]   = useState('manual')
  const [showTypeMenu, setShowTypeMenu] = useState(false)
  const typeMenuRef = useRef(null)

  // Close type menu on outside click
  useEffect(() => {
    function handler(e) {
      if (typeMenuRef.current && !typeMenuRef.current.contains(e.target)) setShowTypeMenu(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const load = useCallback(async (silent = false) => {
    if (!wsId) { setLoading(false); return }
    if (!silent) { setLoading(true); setError(null) }
    try {
      const data = await api.getWorkspaceReports(wsId)
      setReports(data.reports || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  // Poll while any report is pending/running
  useEffect(() => {
    const hasPending = reports.some(r => r.status === 'pending' || r.status === 'running')
    if (!hasPending) return
    const id = setInterval(() => load(true), 5000)
    return () => clearInterval(id)
  }, [reports, load])

  async function handleGenerate() {
    if (!wsId || generating) return
    setGenerating(true); setGenError(null)
    try {
      await api.generateWorkspaceReport(wsId, reportType)
      await load(true)
    } catch (e) {
      setGenError(e.message)
    } finally {
      setGenerating(false)
    }
  }

  function handleDownload(reportId) {
    const url = api.getWorkspaceReportDownloadUrl(wsId, reportId)
    window.open(url, '_blank', 'noopener,noreferrer')
  }

  if (!wsId) return <NoWorkspaceSelected />

  const pendingCount = reports.filter(r => r.status === 'pending' || r.status === 'running').length
  const completedCount = reports.filter(r => r.status === 'completed').length

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>

      {/* Header */}
      <div className="flex items-start justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <FileText className="w-6 h-6 text-brand-600" />
            Executive Reports
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Generate, archive and download executive security reports.
            {completedCount > 0 && ` · ${completedCount} report${completedCount !== 1 ? 's' : ''} ready`}
            {pendingCount > 0 && ` · ${pendingCount} generating…`}
          </p>
        </div>

        {/* Generate button + type picker */}
        <div className="flex items-center gap-2">
          {/* Type selector */}
          <div className="relative" ref={typeMenuRef}>
            <button
              onClick={() => setShowTypeMenu(v => !v)}
              className="btn-secondary text-xs py-2 px-3"
            >
              {REPORT_TYPES.find(t => t.value === reportType)?.label ?? 'Manual Snapshot'}
              <span className="ml-1 text-gray-400">▾</span>
            </button>
            {showTypeMenu && (
              <div className="absolute right-0 top-full mt-1 w-48 bg-white rounded-xl shadow-lg border border-gray-100 py-1 z-20">
                {REPORT_TYPES.map(t => (
                  <button
                    key={t.value}
                    onClick={() => { setReportType(t.value); setShowTypeMenu(false) }}
                    className={`w-full text-left px-3 py-2 text-sm transition-colors ${
                      t.value === reportType
                        ? 'text-brand-700 bg-brand-50 font-semibold'
                        : 'text-gray-700 hover:bg-gray-50'
                    }`}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          <button
            onClick={handleGenerate}
            disabled={generating}
            className="btn-primary"
          >
            {generating
              ? <><RefreshCw className="w-4 h-4 animate-spin" /> Generating…</>
              : <><Plus className="w-4 h-4" /> Generate Report</>
            }
          </button>
        </div>
      </div>

      {/* Generation error */}
      {genError && (
        <div className="mb-6 flex items-center gap-3 px-4 py-3 bg-red-50 border border-red-100 rounded-xl text-sm text-red-600">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {genError}
          <button onClick={() => setGenError(null)} className="ml-auto text-red-400 hover:text-red-600">✕</button>
        </div>
      )}

      {/* Reports table / empty state */}
      {reports.length === 0 ? (
        <div className="card p-16 text-center">
          <FileText className="w-12 h-12 text-gray-200 mx-auto mb-4" />
          <p className="text-gray-500 font-medium mb-1">No reports generated yet.</p>
          <p className="text-sm text-gray-400 mb-6">Generate your first executive report.</p>
          <button
            onClick={handleGenerate}
            disabled={generating}
            className="btn-primary mx-auto"
          >
            {generating
              ? <><RefreshCw className="w-4 h-4 animate-spin" /> Generating…</>
              : <><Plus className="w-4 h-4" /> Generate Report</>
            }
          </button>
        </div>
      ) : (
        <div className="card overflow-hidden">
          <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
            <h2 className="font-semibold text-gray-900">Report Archive</h2>
            <button
              onClick={() => load(true)}
              className="btn-ghost text-xs py-1.5 px-2.5"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Refresh
            </button>
          </div>

          <div className="overflow-x-auto">
            <table className="data-table w-full">
              <thead>
                <tr>
                  <th className="text-left">Report Type</th>
                  <th className="text-left">Period</th>
                  <th className="text-center">Status</th>
                  <th className="text-left">Generated At</th>
                  <th className="text-left">Created At</th>
                  <th className="text-center">Download</th>
                </tr>
              </thead>
              <tbody>
                {reports.map(report => (
                  <tr key={report.id} className="hover:bg-gray-50/60 transition-colors">
                    <td>
                      <span className="font-medium text-gray-800 text-sm">
                        {fmtType(report.report_type)}
                      </span>
                    </td>
                    <td>
                      <span className="text-sm text-gray-500 font-mono">
                        {report.report_period || '—'}
                      </span>
                    </td>
                    <td className="text-center">
                      <StatusBadge status={report.status} />
                    </td>
                    <td>
                      <span className="text-sm text-gray-500 flex items-center gap-1">
                        {report.status === 'pending' || report.status === 'running'
                          ? <><Clock className="w-3.5 h-3.5 text-amber-400 animate-pulse" /> In progress…</>
                          : fmtDateTime(report.generated_at)
                        }
                      </span>
                    </td>
                    <td>
                      <span className="text-sm text-gray-400">
                        {fmtDateTime(report.created_at)}
                      </span>
                    </td>
                    <td className="text-center">
                      {report.status === 'completed' ? (
                        <button
                          onClick={() => handleDownload(report.id)}
                          className="btn-ghost py-1 px-2.5 text-xs inline-flex items-center gap-1.5 text-brand-600 hover:text-brand-700"
                        >
                          <Download className="w-3.5 h-3.5" />
                          PDF
                        </button>
                      ) : report.status === 'failed' ? (
                        <span className="text-xs text-red-400">Failed</span>
                      ) : (
                        <span className="text-xs text-gray-300">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </WsPage>
  )
}
