import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  RefreshCw, Briefcase, Globe, Plus, ChevronRight, X,
} from 'lucide-react'
import { api } from '../api'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDate(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return new Date(s).toLocaleDateString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
  })
}

// ── Create Workspace Modal ────────────────────────────────────────────────────

function CreateWorkspaceModal({ onCreated, onClose }) {
  const [name, setName]       = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError]     = useState(null)

  const valid = name.trim().length > 0

  async function handleSubmit(e) {
    e.preventDefault()
    if (!valid) return
    setLoading(true)
    setError(null)
    try {
      const data = await api.createWorkspace(name.trim())
      onCreated(data.workspace)
    } catch (err) {
      setError(err.message)
      setLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 bg-gray-900/40 backdrop-blur-sm"
        onClick={onClose}
      />
      <div className="relative bg-white rounded-2xl shadow-xl w-full max-w-md p-6 z-10">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold text-gray-900">New Workspace</h2>
          <button
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-lg text-gray-400 hover:text-gray-700 hover:bg-gray-100 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-red-50 text-red-700 text-sm rounded-xl border border-red-100">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="label block mb-1.5">Workspace Name</label>
            <input
              className="input"
              placeholder="e.g. Acme Corp"
              value={name}
              onChange={e => setName(e.target.value)}
              autoFocus
              disabled={loading}
            />
          </div>
          <div className="flex gap-3 pt-1">
            <button
              type="submit"
              disabled={!valid || loading}
              className="btn-primary flex-1 justify-center disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Creating…' : 'Create Workspace'}
            </button>
            <button type="button" onClick={onClose} className="btn-secondary">
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function WorkspacesPage() {
  const [workspaces, setWorkspaces] = useState([])
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState(null)
  const [refreshing, setRefreshing] = useState(false)
  const [showCreate, setShowCreate] = useState(false)
  const navigate = useNavigate()

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true)
    else setRefreshing(true)
    setError(null)
    try {
      const data = await api.getWorkspaces()
      setWorkspaces(data.workspaces || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  function handleCreated(ws) {
    setWorkspaces(prev => [ws, ...prev])
    setShowCreate(false)
    // Set as active workspace and navigate to detail
    localStorage.setItem('cybermeters_workspace_id', ws.id)
    localStorage.setItem('cybermeters_workspace_name', ws.name)
    navigate(`/workspaces/${ws.id}`)
  }

  function openWorkspace(ws) {
    localStorage.setItem('cybermeters_workspace_id', ws.id)
    localStorage.setItem('cybermeters_workspace_name', ws.name)
    navigate(`/workspaces/${ws.id}`)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner />
      </div>
    )
  }

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Workspaces</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            {workspaces.length} workspace{workspaces.length !== 1 ? 's' : ''}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => load(true)}
            disabled={refreshing}
            className="btn-secondary"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button onClick={() => setShowCreate(true)} className="btn-primary">
            <Plus className="w-4 h-4" />
            New Workspace
          </button>
        </div>
      </div>

      {error && <ErrorAlert message={error} />}

      {/* Empty state */}
      {workspaces.length === 0 && !error && (
        <div className="card p-12 flex flex-col items-center text-center">
          <div className="w-14 h-14 rounded-2xl bg-brand-50 flex items-center justify-center mb-4">
            <Briefcase className="w-7 h-7 text-brand-600" />
          </div>
          <h3 className="text-lg font-semibold text-gray-900 mb-1">No workspaces yet</h3>
          <p className="text-sm text-gray-400 mb-6 max-w-sm">
            Create a workspace to group domains together and monitor their
            security posture as a single unit.
          </p>
          <button onClick={() => setShowCreate(true)} className="btn-primary">
            <Plus className="w-4 h-4" />
            Create your first workspace
          </button>
        </div>
      )}

      {/* Workspace grid */}
      {workspaces.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {workspaces.map(ws => (
            <button
              key={ws.id}
              onClick={() => openWorkspace(ws)}
              className="card p-5 text-left hover:shadow-md transition-all cursor-pointer group"
            >
              {/* Icon + name */}
              <div className="flex items-start gap-3 mb-4">
                <div className="w-9 h-9 rounded-xl bg-brand-50 flex items-center justify-center flex-shrink-0">
                  <Briefcase className="w-[18px] h-[18px] text-brand-600" />
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="font-semibold text-gray-900 truncate group-hover:text-brand-700 transition-colors text-base">
                    {ws.name}
                  </h3>
                  <p className="text-xs text-gray-400 mt-0.5">
                    Created {formatDate(ws.created_at)}
                  </p>
                </div>
              </div>

              {/* Footer CTA */}
              <div className="flex items-center text-xs font-semibold text-brand-600 group-hover:text-brand-700 transition-colors">
                <Globe className="w-3.5 h-3.5 mr-1.5 text-gray-400" />
                View domains &amp; scores
                <ChevronRight className="w-3.5 h-3.5 ml-auto transition-transform group-hover:translate-x-0.5" />
              </div>
            </button>
          ))}
        </div>
      )}

      {/* Create modal */}
      {showCreate && (
        <CreateWorkspaceModal
          onCreated={handleCreated}
          onClose={() => setShowCreate(false)}
        />
      )}
    </div>
  )
}
