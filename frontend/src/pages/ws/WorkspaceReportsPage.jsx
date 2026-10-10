import { parseServerDate } from '../../utils/dates'
import { useState, useEffect, useCallback, useRef } from 'react'
import { Link } from 'react-router-dom'
import { FileText, Download, Plus, RefreshCw, AlertTriangle, Clock, Calendar, Trash2, ToggleLeft, ToggleRight } from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDateTime(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return parseServerDate(s).toLocaleString(undefined, {
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
  { value: 'manual',               label: 'Manual Snapshot'     },
  { value: 'scan_snapshot',        label: 'Scan Snapshot'       },
  { value: 'weekly_executive',     label: 'Weekly Executive'    },
  { value: 'monthly_executive',    label: 'Monthly Executive'   },
  { value: 'quarterly_executive',  label: 'Quarterly Executive' },
]

const SCHEDULE_TYPES = [
  { value: 'weekly_executive',    label: 'Weekly Executive',    freq: 'weekly'    },
  { value: 'monthly_executive',   label: 'Monthly Executive',   freq: 'monthly'   },
  { value: 'quarterly_executive', label: 'Quarterly Executive', freq: 'quarterly' },
]

const FREQ_LABELS = { weekly: 'Weekly', monthly: 'Monthly', quarterly: 'Quarterly' }

function fmtNextRun(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  const d = parseServerDate(s)
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}

// ── Scheduled Reports Card ────────────────────────────────────────────────────

function ScheduledReportsCard({ wsId }) {
  const [schedules,  setSchedules]  = useState([])
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState(null)
  const [creating,   setCreating]   = useState(false)
  const [createErr,  setCreateErr]  = useState(null)
  const [showForm,   setShowForm]   = useState(false)
  const [selType,    setSelType]    = useState('monthly_executive')
  const [selFreq,    setSelFreq]    = useState('monthly')

  const load = async () => {
    if (!wsId) return
    setLoading(true); setError(null)
    try {
      const data = await api.getScheduledReports(wsId)
      setSchedules(data.scheduled_reports || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [wsId])

  async function handleCreate() {
    setCreating(true); setCreateErr(null)
    try {
      await api.createScheduledReport(wsId, selType, selFreq)
      setShowForm(false)
      await load()
    } catch (e) {
      setCreateErr(e.message)
    } finally {
      setCreating(false)
    }
  }

  async function handleToggle(sr) {
    try {
      await api.updateScheduledReport(wsId, sr.id, !sr.enabled)
      await load()
    } catch { /* show nothing — list refreshes */ }
  }

  async function handleDelete(srId) {
    try {
      await api.deleteScheduledReport(wsId, srId)
      await load()
    } catch { /* non-fatal */ }
  }

  return (
    <div className="card p-6 mt-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Calendar className="w-4 h-4 text-gray-400" />
          <h2 className="text-sm font-semibold text-gray-900">Scheduled Reports</h2>
        </div>
        <button
          onClick={() => { setShowForm(v => !v); setCreateErr(null) }}
          className="btn-secondary text-xs py-1.5 px-3 flex items-center gap-1"
        >
          <Plus className="w-3.5 h-3.5" /> New Schedule
        </button>
      </div>

      {/* Create form */}
      {showForm && (
        <div className="mb-4 p-4 bg-gray-50 rounded-xl border border-gray-100">
          <p className="text-xs font-medium text-gray-700 mb-3">New scheduled report</p>
          <div className="flex flex-wrap items-end gap-3">
            <div>
              <label className="block text-xs text-gray-500 mb-1">Report type</label>
              <select
                value={selType}
                onChange={e => setSelType(e.target.value)}
                className="text-sm border border-gray-200 rounded-lg px-2 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                {SCHEDULE_TYPES.map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-gray-500 mb-1">Frequency</label>
              <select
                value={selFreq}
                onChange={e => setSelFreq(e.target.value)}
                className="text-sm border border-gray-200 rounded-lg px-2 py-1.5 bg-white focus:outline-none focus:ring-2 focus:ring-brand-500"
              >
                <option value="weekly">Weekly (Mondays)</option>
                <option value="monthly">Monthly (1st)</option>
                <option value="quarterly">Quarterly (1st of quarter)</option>
              </select>
            </div>
            <div className="flex gap-2">
              <button
                onClick={handleCreate}
                disabled={creating}
                className="btn-primary text-sm py-1.5 px-3"
              >
                {creating ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : 'Create'}
              </button>
              <button
                onClick={() => setShowForm(false)}
                className="btn-ghost text-sm py-1.5 px-3"
              >
                Cancel
              </button>
            </div>
          </div>
          {createErr && (
            <p className="mt-2 text-xs text-red-500">{createErr}</p>
          )}
        </div>
      )}

      {error && <p className="text-xs text-red-500 py-2">{error}</p>}

      {!loading && !error && schedules.length === 0 && (
        <div className="py-8 text-center">
          <Calendar className="w-8 h-8 text-gray-200 mx-auto mb-2" />
          <p className="text-sm text-gray-400">No scheduled reports configured.</p>
        </div>
      )}

      {schedules.length > 0 && (
        <div className="divide-y divide-gray-50">
          {schedules.map(sr => (
            <div key={sr.id} className="flex items-center justify-between py-3 gap-3">
              <div className="flex-1 min-w-0">
                <p className={`text-sm font-medium ${sr.enabled ? 'text-gray-800' : 'text-gray-400'}`}>
                  {fmtType(sr.report_type)}
                  <span className="ml-2 text-xs font-normal text-gray-400">{FREQ_LABELS[sr.frequency] ?? sr.frequency}</span>
                </p>
                <p className="text-xs text-gray-400 mt-0.5">
                  Next run: {fmtNextRun(sr.next_run_at)}
                  {sr.last_run_at && ` · Last: ${fmtDateTime(sr.last_run_at)}`}
                </p>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  onClick={() => handleToggle(sr)}
                  title={sr.enabled ? 'Disable' : 'Enable'}
                  className="text-gray-400 hover:text-brand-600 transition-colors"
                >
                  {sr.enabled
                    ? <ToggleRight className="w-5 h-5 text-brand-500" />
                    : <ToggleLeft  className="w-5 h-5 text-gray-300"  />
                  }
                </button>
                <button
                  onClick={() => handleDelete(sr.id)}
                  title="Delete schedule"
                  className="text-gray-300 hover:text-red-500 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function WorkspaceReportsPage() {
  const { wsId, wsName } = useWorkspace()
  if (!wsId) return <NoWorkspaceSelected />

  // Keep the archive, schedules and action state owned by one workspace.
  return <WorkspaceReports key={wsId} wsId={wsId} wsName={wsName} />
}

function WorkspaceReports({ wsId, wsName }) {
  const [reports,      setReports]      = useState([])
  const [loading,      setLoading]      = useState(true)
  const [error,        setError]        = useState(null)
  const [generating,   setGenerating]   = useState(false)
  const [genError,     setGenError]     = useState(null)
  const [generatedReport, setGeneratedReport] = useState(null)
  const [reportType,   setReportType]   = useState('manual')
  const [scans,        setScans]        = useState([])
  const [scanId,       setScanId]       = useState('')
  const [scansLoading, setScansLoading] = useState(false)
  const [scansError,   setScansError]   = useState(null)
  const [scanRetry,    setScanRetry]    = useState(0)
  const [showTypeMenu, setShowTypeMenu] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState(null)
  const [deleting,     setDeleting]     = useState(false)
  const typeMenuRef = useRef(null)
  const mounted = useRef(false)
  const requestId = useRef(0)
  const requestPending = useRef(false)

  // Close type menu on outside click
  useEffect(() => {
    function handler(e) {
      if (typeMenuRef.current && !typeMenuRef.current.contains(e.target)) setShowTypeMenu(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  useEffect(() => {
    if (reportType !== 'scan_snapshot') return
    let active = true
    setScansLoading(true); setScansError(null); setScans([]); setScanId('')
    api.getWorkspaceScans(wsId).then(data => {
      if (active) setScans((data.scans || []).filter(scan => scan.status === 'completed'))
    }).catch(e => {
      if (active) setScansError(e.message)
    }).finally(() => {
      if (active) setScansLoading(false)
    })
    return () => { active = false }
  }, [wsId, reportType, scanRetry])

  const load = useCallback(async (silent = false) => {
    if (!mounted.current) return
    const id = ++requestId.current
    requestPending.current = true
    const isCurrent = () => mounted.current && id === requestId.current
    if (!silent) { setLoading(true); setError(null) }
    try {
      const data = await api.getWorkspaceReports(wsId)
      if (!isCurrent()) return
      setReports(data.reports || [])
      setError(null)
    } catch (e) {
      if (isCurrent()) setError(e.message)
    } finally {
      if (isCurrent()) {
        requestPending.current = false
        setLoading(false)
      }
    }
  }, [wsId])

  useEffect(() => {
    mounted.current = true
    load()
    return () => {
      mounted.current = false
      requestId.current += 1
    }
  }, [load])

  // Poll while any report is pending/running
  useEffect(() => {
    const hasPending = reports.some(r => r.status === 'pending' || r.status === 'running')
    if (!hasPending) return
    const id = setInterval(() => {
      // A slow response must finish before another poll can supersede it.
      if (!requestPending.current) load(true)
    }, 5000)
    return () => clearInterval(id)
  }, [reports, load])

  async function handleGenerate() {
    if (!wsId || generating) return
    if (reportType === 'scan_snapshot' && !scans.some(scan => scan.id === scanId)) return
    setGenerating(true); setGenError(null); setGeneratedReport(null)
    try {
      const data = reportType === 'scan_snapshot'
        ? await api.generateWorkspaceReport(wsId, reportType, scanId)
        : await api.generateWorkspaceReport(wsId, reportType)
      if (!mounted.current) return
      setGeneratedReport(data.report?.status === 'completed' ? data.report : null)
      await load(true)
    } catch (e) {
      if (mounted.current) setGenError(e.message)
    } finally {
      if (mounted.current) setGenerating(false)
    }
  }

  async function handleDownload(report) {
    try {
      const blob = await api.downloadWorkspaceReport(wsId, report.id)
      const url  = URL.createObjectURL(blob)
      // Programmatic anchor download — saves file to disk rather than opening
      // inline in a new tab. Content-Disposition is lost once we have the blob,
      // so the filename is reconstructed here from the report metadata.
      const period   = report.report_type === 'scan_snapshot' ? report.id : (report.report_period || report.id)
      const filename = `cybermeters-${report.report_type || 'report'}-${period}.pdf`
      const a = document.createElement('a')
      a.href     = url
      a.download = filename
      a.style.display = 'none'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      setTimeout(() => URL.revokeObjectURL(url), 60_000)
    } catch (e) {
      setGenError(e.message)
    }
  }

  async function handleDeleteReport() {
    if (!wsId || !deleteTarget || deleting) return
    setDeleting(true)
    setGenError(null)
    try {
      await api.deleteWorkspaceReport(wsId, deleteTarget.id)
      setReports(prev => prev.filter(r => r.id !== deleteTarget.id))
      setDeleteTarget(null)
      await load(true)
    } catch (e) {
      setGenError(e.message)
    } finally {
      setDeleting(false)
    }
  }

  const pendingCount = reports.filter(r => r.status === 'pending' || r.status === 'running').length
  const completedCount = reports.filter(r => r.status === 'completed').length

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={() => load(false)}>

      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 mb-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <FileText className="w-6 h-6 text-brand-600" />
            PDF Reports
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Generate executive reports and download your saved PDFs.
            {completedCount > 0 && ` · ${completedCount} report${completedCount !== 1 ? 's' : ''} ready`}
            {pendingCount > 0 && ` · ${pendingCount} generating…`}
          </p>
        </div>

        {/* Generate button + type picker */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Type selector */}
          <div className="relative" ref={typeMenuRef}>
            <button
              onClick={() => setShowTypeMenu(v => !v)}
              disabled={generating}
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
                    onClick={() => { setReportType(t.value); setShowTypeMenu(false); setGeneratedReport(null); setGenError(null) }}
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
            disabled={generating || (reportType === 'scan_snapshot' && (scansLoading || !scanId))}
            className="btn-primary"
          >
            {generating
              ? <><RefreshCw className="w-4 h-4 animate-spin" /> Generating…</>
              : <><Plus className="w-4 h-4" /> Generate Report</>
            }
          </button>
        </div>
      </div>

      {reportType === 'scan_snapshot' ? (
        <div className="mb-6 max-w-xl">
          <label htmlFor="report-scan" className="block text-sm font-medium text-gray-700 mb-2">Recent completed scan</label>
          <select id="report-scan" value={scanId} onChange={e => { setScanId(e.target.value); setGeneratedReport(null) }}
            disabled={scansLoading || generating} className="w-full rounded-lg border border-gray-300 bg-white px-3 py-2 text-sm">
            <option value="">{scansLoading ? 'Loading scans…' : 'Choose a scan'}</option>
            {scans.map(scan => <option key={scan.id} value={scan.id}>{scan.domain} · {fmtDateTime(scan.created_at)} · {scan.id.slice(-8)}</option>)}
          </select>
          <p className="text-sm text-gray-500 mt-2">Executive summary of this scan only. Download its technical PDF from the scan details.</p>
          {scansError && <p role="alert" className="text-sm text-red-600 mt-2">{scansError} <button onClick={() => setScanRetry(v => v + 1)} className="underline">Retry scan list</button></p>}
          {!scansLoading && !scansError && scans.length === 0 && <p className="text-sm text-gray-500 mt-2">No completed scans are available in the recent scan history.</p>}
        </div>
      ) : (
        <p className="text-sm text-gray-500 mb-6">Latest available assessment for each domain in this workspace. Reporting periods label the saved summary; they are not historical totals.</p>
      )}

      {generatedReport && (
        <div role="status" className="mb-6 flex flex-wrap items-center gap-3 rounded-xl border border-brand-100 bg-brand-50 px-4 py-3 text-sm text-brand-800">
          <span>{generatedReport.claimed === false ? 'This report already exists. Its saved PDF is ready.' : 'Your report is ready.'}</span>
          <button onClick={() => handleDownload(generatedReport)} className="btn-secondary text-xs">Download generated PDF</button>
        </div>
      )}

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
          <p className="text-sm text-gray-400 mb-6">Complete the guided setup to create your first assessment and report.</p>
          <div className="flex flex-wrap items-center justify-center gap-3">
            <Link to="/onboarding" className="btn-primary">
              Get Started
            </Link>
            <button
              onClick={handleGenerate}
              disabled={generating || (reportType === 'scan_snapshot' && (scansLoading || !scanId))}
              className="btn-secondary"
            >
              {generating
                ? <><RefreshCw className="w-4 h-4 animate-spin" /> Generating…</>
                : <><Plus className="w-4 h-4" /> Generate manually</>
              }
            </button>
          </div>
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
                  <th className="text-center">Actions</th>
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
                      <span className="block max-w-56 truncate text-sm text-gray-500 font-mono" title={report.report_period || undefined}>
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
                      <div className="inline-flex items-center justify-center gap-1.5">
                        {report.status === 'completed' ? (
                          <button
                            onClick={() => handleDownload(report)}
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
                        <button
                          onClick={() => setDeleteTarget(report)}
                          disabled={deleting}
                          className="btn-ghost py-1 px-2.5 text-xs inline-flex items-center gap-1.5 text-red-500 hover:text-red-600 disabled:opacity-50"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Scheduled Reports */}
      <ScheduledReportsCard wsId={wsId} />

      {deleteTarget && (
        <div className="fixed inset-0 z-50 bg-gray-900/30 flex items-center justify-center px-4">
          <div className="w-full max-w-md rounded-xl bg-white border border-gray-100 shadow-xl p-6">
            <div className="flex items-start gap-3">
              <div className="w-9 h-9 rounded-lg bg-red-50 flex items-center justify-center flex-shrink-0">
                <Trash2 className="w-5 h-5 text-red-500" />
              </div>
              <div className="min-w-0">
                <h2 className="text-sm font-bold text-gray-900">Delete this report permanently?</h2>
                <div className="mt-3 space-y-1 text-sm">
                  <p className="break-all"><span className="text-gray-400">Report:</span> <span className="font-medium text-gray-800">{deleteTarget.report_period || deleteTarget.id}</span></p>
                  <p><span className="text-gray-400">Created:</span> <span className="font-medium text-gray-800">{fmtDateTime(deleteTarget.created_at)}</span></p>
                  <p><span className="text-gray-400">Type:</span> <span className="font-medium text-gray-800">{fmtType(deleteTarget.report_type)}</span></p>
                </div>
              </div>
            </div>
            <div className="mt-6 flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setDeleteTarget(null)}
                disabled={deleting}
                className="btn-secondary"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleDeleteReport}
                disabled={deleting}
                className="btn-primary bg-red-600 hover:bg-red-700 disabled:opacity-50"
              >
                {deleting ? 'Deleting…' : 'Delete Report'}
              </button>
            </div>
          </div>
        </div>
      )}

    </WsPage>
  )
}
