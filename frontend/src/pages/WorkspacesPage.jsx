import { parseServerDate, formatDay } from '../utils/dates'
import { useState, useEffect, useCallback } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import { RefreshCw, X } from 'lucide-react'
import { useDialog } from '../lib/useDialog'
import { api } from '../api'
import Spinner from '../components/Spinner'
import ErrorAlert from '../components/ErrorAlert'
import DeletedWorkspacesPanel from '../components/DeletedWorkspacesPanel'
import { setActiveWorkspace } from '../lib/activeWorkspace'

// ── Helpers ───────────────────────────────────────────────────────────────────

function formatDate(str) {
  if (!str) return '—'
  const s = str.includes('T') ? str : str.replace(' ', 'T') + 'Z'
  return formatDay(s)
}

// ── Create Workspace Modal ────────────────────────────────────────────────────

function CreateWorkspaceModal({ onCreated, onClose }) {
  const dialogRef = useDialog(onClose)
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
        className="absolute inset-0 bg-gray-900/40 backdrop-blur-xs"
        onClick={onClose}
      />
      <div ref={dialogRef} role="dialog" aria-modal="true" aria-label="New workspace" tabIndex={-1} className="relative bg-white rounded-2xl shadow-xl w-full max-w-md p-6 z-10">
        <div className="flex items-center justify-between mb-5">
          <h2 className="text-lg font-bold text-gray-900">New Workspace</h2>
          <button
            onClick={onClose}
            aria-label="Close new workspace dialog"
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
  const location = useLocation()
  const justDeleted = location.state?.justDeleted ?? null

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
    setActiveWorkspace(ws.id, ws.name)
    navigate(`/workspaces/${ws.id}`)
  }

  function openWorkspace(ws) {
    setActiveWorkspace(ws.id, ws.name)
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
    <div className="max-w-(--breakpoint-xl) mx-auto px-6 py-8 space-y-6">

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Workspaces</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            {workspaces.length} workspace{workspaces.length !== 1 ? 's' : ''}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => load(true)}
            disabled={refreshing}
            className="btn-secondary"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
            Reload results
          </button>
          <button onClick={() => setShowCreate(true)} className="btn-primary">
            New Workspace
          </button>
        </div>
      </div>

      {error && <ErrorAlert message={error} />}

      <DeletedWorkspacesPanel justDeleted={justDeleted} onRestored={() => load(true)} />

      {/* Empty state */}
      {workspaces.length === 0 && !error && (
        <div className="space-y-4">
          {/* Hero */}
          <div className="card p-10 flex flex-col items-center text-center">
            <h3 className="text-xl font-bold text-gray-900 mb-2">Create your first workspace</h3>
            <p className="text-sm text-gray-400 mb-1 max-w-md leading-relaxed">
              A workspace is a container for one organisation or client — holding its domains, scans,
              findings, asset inventory, and reports. You can have multiple workspaces, one per client or
              business unit.
            </p>
            <p className="text-xs text-gray-600 mb-8">Takes less than a minute</p>
            <div className="flex flex-wrap items-center justify-center gap-3">
              <button onClick={() => navigate('/onboarding')} className="btn-primary">
                Get Started Guide
              </button>
              <button onClick={() => setShowCreate(true)} className="btn-secondary">
                Create Workspace
              </button>
            </div>
          </div>
          {/* What workspaces give you */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { title: 'Domain Management', desc: 'Add and verify domains. CyberMeters tracks ownership and monitors for unauthorised changes.'         },
              { title: 'External security monitoring', desc: 'Run on-demand or scheduled security checks to monitor your domains from the outside.'          },
              { title: 'Executive Reports',  desc: 'Generate PDF risk reports for clients, stakeholders, or compliance purposes in one click.'        },
            ].map(({ title, desc }) => (
              <div key={title} className="card p-5">
                <p className="text-sm font-semibold text-gray-900 mb-1">{title}</p>
                <p className="text-xs text-gray-400 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
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
              {/* Name */}
              <div className="flex items-start gap-3 mb-4">
                <div className="min-w-0 flex-1">
                  <h3 className="font-semibold text-gray-900 truncate group-hover:text-brand-800 transition-colors text-base">
                    {ws.name}
                  </h3>
                  <p className="text-xs text-gray-400 mt-0.5">
                    Created {formatDate(ws.created_at)}
                  </p>
                </div>
              </div>

              {/* Footer CTA */}
              <div className="flex items-center text-xs font-semibold text-brand-700 group-hover:text-brand-800 transition-colors">
                View domains &amp; scores
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
