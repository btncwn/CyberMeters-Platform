import { useState, useEffect, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
  RefreshCw, Calendar, Globe, Clock, Trash2,
  Plus, CheckCircle, Info, ScanLine,
} from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'
import EmptyState from '../components/EmptyState'

// ── Helpers ───────────────────────────────────────────────────────────────────

function isValidDomain(v) {
  return /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v.trim())
}

function formatDate(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return new Date(s).toLocaleString(undefined, {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

const FREQ_LABELS = { daily: 'Daily', weekly: 'Weekly' }

function FreqBadge({ frequency }) {
  const base = 'inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border'
  if (frequency === 'weekly')
    return <span className={`${base} bg-blue-50 text-blue-700 border-blue-100`}>Weekly</span>
  return <span className={`${base} bg-brand-50 text-brand-700 border-brand-100`}>Daily</span>
}

// ── Add Schedule Form ─────────────────────────────────────────────────────────

function AddScheduleForm({ onCreated }) {
  const [domain,    setDomain]    = useState('')
  const [frequency, setFrequency] = useState('daily')
  const [loading,   setLoading]   = useState(false)
  const [error,     setError]     = useState(null)
  const [success,   setSuccess]   = useState(false)

  const valid = isValidDomain(domain)

  async function handleSubmit(e) {
    e.preventDefault()
    if (!valid) return
    setLoading(true)
    setError(null)
    setSuccess(false)
    try {
      const data = await api.createSchedule(domain.trim().toLowerCase(), frequency)
      setSuccess(true)
      setDomain('')
      setTimeout(() => setSuccess(false), 2000)
      onCreated(data.schedule)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="card p-6 space-y-5">
      <div className="flex items-center gap-2.5 mb-1">
        <div className="w-7 h-7 rounded-lg bg-brand-100 flex items-center justify-center">
          <Plus className="w-3.5 h-3.5 text-brand-700" />
        </div>
        <h2 className="text-sm font-bold text-gray-900">Add Scheduled Scan</h2>
      </div>

      <div>
        <label className="label mb-1.5 block">Domain</label>
        <div className="relative">
          <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            placeholder="example.com"
            className="input pl-10"
            disabled={loading}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
          />
        </div>
        {domain !== '' && !valid && (
          <p className="text-amber-600 text-xs mt-1.5 font-medium">
            ⚠ Enter a valid domain (e.g. example.com)
          </p>
        )}
      </div>

      <div>
        <label className="label mb-1.5 block">Frequency</label>
        <div className="flex gap-3">
          {['daily', 'weekly'].map(f => (
            <label
              key={f}
              className={`flex-1 flex items-center gap-2.5 px-4 py-3 rounded-xl border cursor-pointer transition-colors ${
                frequency === f
                  ? 'border-brand-400 bg-brand-50 text-brand-700'
                  : 'border-gray-200 hover:border-gray-300 text-gray-600'
              }`}
            >
              <input
                type="radio"
                name="frequency"
                value={f}
                checked={frequency === f}
                onChange={() => setFrequency(f)}
                className="sr-only"
              />
              <Clock className="w-4 h-4 flex-shrink-0" />
              <span className="text-sm font-semibold capitalize">{FREQ_LABELS[f]}</span>
            </label>
          ))}
        </div>
        <p className="text-xs text-gray-400 mt-1.5 flex items-center gap-1">
          <Info className="w-3 h-3" />
          {frequency === 'daily' ? 'Runs once every 24 hours.' : 'Runs once every 7 days.'}
        </p>
      </div>

      {error && <ErrorAlert message={error} onRetry={() => setError(null)} />}

      <button
        type="submit"
        disabled={!valid || loading}
        className="btn-primary w-full justify-center disabled:opacity-40 disabled:cursor-not-allowed"
      >
        {loading   ? <><Spinner size="sm" /><span>Scheduling…</span></> :
         success   ? <><CheckCircle className="w-4 h-4" /><span>Schedule added</span></> :
                     <><Calendar className="w-4 h-4" /><span>Add Schedule</span></>}
      </button>
    </form>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function SchedulesPage() {
  const [schedules,  setSchedules]  = useState([])
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [deleting,   setDeleting]   = useState(null) // id being deleted

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const data = await api.getSchedules()
      setSchedules(data.schedules || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function handleCreated(schedule) {
    setSchedules(prev => [schedule, ...prev])
  }

  async function handleDelete(id) {
    setDeleting(id)
    try {
      await api.deleteSchedule(id)
      setSchedules(prev => prev.filter(s => s.id !== id))
    } catch (e) {
      setError(e.message)
    } finally {
      setDeleting(null)
    }
  }

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2.5 mb-1">
            <div className="w-8 h-8 rounded-xl bg-brand-50 flex items-center justify-center">
              <Calendar className="w-4 h-4 text-brand-600" />
            </div>
            <h1 className="text-2xl font-bold text-gray-900">Scheduled Scans</h1>
          </div>
          <p className="text-sm text-gray-400 mt-0.5 ml-10">
            {schedules.length > 0
              ? `${schedules.length} domain${schedules.length !== 1 ? 's' : ''} monitored automatically`
              : 'Set up automatic recurring scans for your domains'}
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
            Manual Scan
          </Link>
        </div>
      </div>

      {error && <ErrorAlert message={error} onRetry={() => load()} />}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">

        {/* Add form — sidebar on large screens */}
        <div className="lg:order-2">
          <AddScheduleForm onCreated={handleCreated} />

          <div className="mt-4 card p-4 space-y-3">
            <p className="label">How it works</p>
            <ul className="space-y-2 text-xs text-gray-500">
              <li className="flex items-start gap-2">
                <span className="w-4 h-4 rounded-full bg-brand-100 text-brand-700 text-[10px] font-bold flex items-center justify-center flex-shrink-0 mt-0.5">1</span>
                Add a domain and choose how often to scan it.
              </li>
              <li className="flex items-start gap-2">
                <span className="w-4 h-4 rounded-full bg-brand-100 text-brand-700 text-[10px] font-bold flex items-center justify-center flex-shrink-0 mt-0.5">2</span>
                CyberMeters automatically runs a full scan on schedule.
              </li>
              <li className="flex items-start gap-2">
                <span className="w-4 h-4 rounded-full bg-brand-100 text-brand-700 text-[10px] font-bold flex items-center justify-center flex-shrink-0 mt-0.5">3</span>
                Each scan appears in your Scans list. Historical changes are tracked automatically.
              </li>
            </ul>
          </div>
        </div>

        {/* Schedule list — main area */}
        <div className="lg:col-span-2 lg:order-1">
          <div className="card overflow-hidden">
            {loading ? (
              <div className="flex items-center justify-center py-24">
                <Spinner size="lg" />
              </div>
            ) : schedules.length === 0 ? (
              <EmptyState
                icon={Calendar}
                title="No scheduled scans"
                description="Add a domain above to start monitoring it automatically."
              />
            ) : (
              <table className="w-full data-table">
                <thead>
                  <tr>
                    <th>Domain</th>
                    <th>Frequency</th>
                    <th>Last Run</th>
                    <th>Next Run</th>
                    <th className="text-right">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {schedules.map(s => (
                    <tr key={s.id}>
                      <td>
                        <div className="flex items-center gap-2.5">
                          <div className="w-7 h-7 rounded-lg bg-gray-100 flex items-center justify-center flex-shrink-0">
                            <Globe className="w-3.5 h-3.5 text-gray-400" />
                          </div>
                          <div>
                            <p className="font-semibold text-gray-900">{s.domain}</p>
                            <p className="mono text-[11px] text-gray-300 truncate max-w-[180px]">{s.id}</p>
                          </div>
                        </div>
                      </td>
                      <td>
                        <FreqBadge frequency={s.frequency} />
                      </td>
                      <td>
                        <div className="flex items-center gap-1.5 text-xs text-gray-500">
                          <Clock className="w-3.5 h-3.5 flex-shrink-0" />
                          {formatDate(s.last_run_at)}
                        </div>
                      </td>
                      <td>
                        <div className="flex items-center gap-1.5 text-xs text-gray-500">
                          <Clock className="w-3.5 h-3.5 flex-shrink-0 text-brand-400" />
                          {formatDate(s.next_run_at)}
                        </div>
                      </td>
                      <td>
                        <div className="flex items-center justify-end">
                          <button
                            onClick={() => handleDelete(s.id)}
                            disabled={deleting === s.id}
                            className="btn-ghost text-xs text-red-500 hover:text-red-700 hover:bg-red-50 disabled:opacity-40"
                            title="Delete schedule"
                          >
                            {deleting === s.id
                              ? <Spinner size="sm" />
                              : <Trash2 className="w-3.5 h-3.5" />}
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
      </div>
    </div>
  )
}
