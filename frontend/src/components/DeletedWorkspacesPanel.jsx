import { useCallback, useEffect, useState } from 'react'
import { RotateCcw, Trash2, CheckCircle, AlertTriangle } from 'lucide-react'
import { api } from '../api'
import { parseServerDate } from '../utils/dates'

// Owner's soft-deleted workspaces that can still be restored. The backend
// decides restorability (window, purge state, ownership); this panel only
// lists what it returns and calls the existing restore endpoint.
//
// `justDeleted` ({ id, name }) comes from the delete flow so the owner gets an
// immediate "Undo" for the workspace they just removed.

// The deadline is an exact moment (deletion + window), so show the time too.
function formatDeadline(value) {
  const d = parseServerDate(value)
  if (!d || Number.isNaN(d.getTime())) return null
  return d.toLocaleString(undefined, { day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function restoreErrorMessage(err) {
  if (err?.code === 'plan_limit_exceeded') return err.message || 'Restoring this workspace would exceed your plan.'
  if (err?.status === 409) return err.message || 'This workspace can no longer be restored.'
  if (err?.status === 403) return 'Only the workspace owner can restore this workspace.'
  if (err?.status === 503) return 'Restore is temporarily unavailable. Please try again.'
  return err?.message || 'Unable to restore this workspace.'
}

export default function DeletedWorkspacesPanel({ justDeleted = null, onRestored }) {
  const [items, setItems]       = useState([])
  const [loaded, setLoaded]     = useState(false)
  const [loadError, setLoadError] = useState(null)
  const [busyId, setBusyId]     = useState(null)
  const [rowError, setRowError] = useState({})
  const [restored, setRestored] = useState(null)

  const load = useCallback(async () => {
    setLoadError(null)
    try {
      const data = await api.getDeletedWorkspaces()
      setItems(Array.isArray(data?.workspaces) ? data.workspaces : [])
    } catch (e) {
      setLoadError(e?.message || 'Deleted workspaces could not be loaded.')
    } finally {
      setLoaded(true)
    }
  }, [])

  useEffect(() => { load() }, [load])

  async function handleRestore(ws) {
    if (busyId) return
    setBusyId(ws.id)
    setRowError(prev => ({ ...prev, [ws.id]: null }))
    try {
      const res = await api.restoreWorkspace(ws.id)
      setItems(prev => prev.filter(i => i.id !== ws.id))
      setRestored({ id: ws.id, name: ws.name, note: res?.note || null })
      if (onRestored) onRestored(ws.id)
    } catch (e) {
      setRowError(prev => ({ ...prev, [ws.id]: restoreErrorMessage(e) }))
      if (e?.status === 409) load()
    } finally {
      setBusyId(null)
    }
  }

  const justDeletedItem = justDeleted ? items.find(i => i.id === justDeleted.id) : null
  const others = justDeletedItem ? items.filter(i => i.id !== justDeletedItem.id) : items

  if (!loaded) return null
  if (!loadError && items.length === 0 && !restored) return null

  return (
    <section aria-label="Recently deleted workspaces" className="space-y-3">
      {restored && (
        <div role="status" className="rounded-xl border border-green-100 bg-green-50 p-4 flex items-start gap-3">
          <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
          <div className="text-sm">
            <p className="font-semibold text-green-800">“{restored.name}” was restored.</p>
            <p className="text-green-700 mt-0.5">
              {restored.note || 'Scheduled scans for its current domains are switched back on where your plan allows.'}
            </p>
          </div>
        </div>
      )}

      {justDeletedItem && (
        <div role="status" className="rounded-xl border border-amber-100 bg-amber-50 p-4 flex flex-col sm:flex-row sm:items-center gap-3">
          <div className="flex-1 text-sm">
            <p className="font-semibold text-amber-900">“{justDeletedItem.name}” was deleted.</p>
            <p className="text-amber-800 mt-0.5">
              {formatDeadline(justDeletedItem.restorable_until)
                ? <>You can undo this before {formatDeadline(justDeletedItem.restorable_until)}. After that its data is permanently removed.</>
                : <>You can undo this during the restore window. After that its data is permanently removed.</>}
            </p>
            {rowError[justDeletedItem.id] && <p className="text-red-700 mt-1">{rowError[justDeletedItem.id]}</p>}
          </div>
          <button
            type="button"
            onClick={() => handleRestore(justDeletedItem)}
            disabled={!!busyId}
            className="btn-secondary self-start sm:self-auto"
          >
            <RotateCcw className={`w-4 h-4 ${busyId === justDeletedItem.id ? 'animate-spin' : ''}`} />
            {busyId === justDeletedItem.id ? 'Restoring…' : 'Undo delete'}
          </button>
        </div>
      )}

      {(loadError || others.length > 0) && (
        <div className="card p-5">
          <div className="flex items-center gap-2 mb-1">
            <Trash2 className="w-4 h-4 text-gray-400" />
            <h2 className="text-sm font-bold text-gray-900">Recently deleted</h2>
          </div>
          <p className="text-xs text-gray-500 mb-3">
            Deleted workspaces can be restored before permanent deletion. Restoring switches monitoring back on for the domains still in the workspace, within your plan's limits.
          </p>
          {loadError ? (
            <div className="flex items-center gap-2 text-sm text-red-700">
              <AlertTriangle className="w-4 h-4" />
              <span>Deleted workspaces could not be loaded.</span>
              <button type="button" onClick={load} className="underline font-semibold">Retry</button>
            </div>
          ) : (
            <ul className="divide-y divide-gray-50">
              {others.map(ws => (
                <li key={ws.id} className="py-3 flex flex-col sm:flex-row sm:items-center gap-2">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-gray-900 truncate">{ws.name}</p>
                    <p className="text-xs text-gray-500">
                      {formatDeadline(ws.restorable_until)
                        ? `Can be restored before ${formatDeadline(ws.restorable_until)}`
                        : 'Can be restored during the restore window'}
                    </p>
                    {rowError[ws.id] && <p className="text-xs text-red-700 mt-1">{rowError[ws.id]}</p>}
                  </div>
                  <button
                    type="button"
                    onClick={() => handleRestore(ws)}
                    disabled={!!busyId}
                    className="btn-secondary self-start sm:self-auto"
                    aria-label={`Restore ${ws.name}`}
                  >
                    <RotateCcw className={`w-4 h-4 ${busyId === ws.id ? 'animate-spin' : ''}`} />
                    {busyId === ws.id ? 'Restoring…' : 'Restore'}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </section>
  )
}
