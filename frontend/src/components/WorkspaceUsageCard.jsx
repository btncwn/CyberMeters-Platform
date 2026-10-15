import { useEffect, useState } from 'react'
import { api } from '../api'
import { monthLabel, storageText, usageRows } from '../lib/workspaceUsageDisplay'

// "Usage this month" for one workspace. Plan allowances are shared across all
// workspaces of the owning account, so they are shown as the plan's limit,
// not as this workspace's remaining quota.
export default function WorkspaceUsageCard({ workspaceId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(false)
    Promise.resolve().then(() => api.getWorkspaceUsage(workspaceId))
      .then((res) => { if (!cancelled) setData(res) })
      .catch(() => { if (!cancelled) setError(true) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [workspaceId])

  return (
    <section className="card p-5" aria-label="Usage this month">
      <div className="flex items-center gap-2 mb-1">
        <h2 className="section-title">Usage in {monthLabel(data?.period_start)}</h2>
      </div>
      <p className="text-sm text-gray-600 mb-3">
        What this workspace used this month. Plan allowances are shared by all workspaces of the account that owns this one.
      </p>
      {loading && <p className="text-sm text-gray-500">Loading…</p>}
      {!loading && error && <p role="alert" className="text-sm text-red-700">Usage could not be loaded.</p>}
      {!loading && !error && data && (
        <>
          <dl className="grid gap-4 sm:grid-cols-3">
            {usageRows(data).map((r) => (
              <div key={r.key} className="rounded-sm border border-gray-100 p-3">
                <dt className="text-xs font-medium text-gray-500">{r.label}</dt>
                <dd className="text-2xl font-semibold text-gray-900">{r.value.toLocaleString()}</dd>
                <dd className="text-xs text-gray-500">{r.sub}</dd>
                {r.allowance && <dd className="text-xs text-gray-500 mt-1">Plan: {r.allowance} (shared)</dd>}
              </div>
            ))}
          </dl>
          <p className="text-xs text-gray-500 mt-3">{storageText(data)}</p>
        </>
      )}
    </section>
  )
}
