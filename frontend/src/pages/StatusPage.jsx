import { Link } from 'react-router-dom'
import { useState, useEffect, useCallback } from 'react'
import { Shield, RefreshCw, CheckCircle2, AlertTriangle, Wrench, HelpCircle } from 'lucide-react'
import { BASE } from '../api'

// ─────────────────────────────────────────────────────────────────────────────
// Public status page. Performs a real-time synthetic check against the API's
// /health and /ready probes and reports live component status (API, Database,
// Storage) + planned-maintenance state. This is a point-in-time health check,
// not a historical-uptime SLA record — that needs an external monitor and is
// noted as such. No auth, safe to expose.
// ─────────────────────────────────────────────────────────────────────────────

const ROOT = (BASE || '').replace(/\/api\/?$/, '')

const STATE = {
  operational: { label: 'All systems operational', cls: 'text-green-700', dot: 'bg-green-500', Icon: CheckCircle2, iconCls: 'text-green-500' },
  degraded:    { label: 'Partial service disruption', cls: 'text-amber-700', dot: 'bg-amber-500', Icon: AlertTriangle, iconCls: 'text-amber-500' },
  maintenance: { label: 'Scheduled maintenance', cls: 'text-brand-700', dot: 'bg-brand-500', Icon: Wrench, iconCls: 'text-brand-600' },
  unknown:     { label: 'Unable to reach the service', cls: 'text-gray-600', dot: 'bg-gray-400', Icon: HelpCircle, iconCls: 'text-gray-400' },
}

function Component({ name, ok }) {
  return (
    <div className="flex items-center justify-between py-3 border-b border-gray-100 last:border-0">
      <span className="text-sm font-medium text-gray-800">{name}</span>
      {ok === null
        ? <span className="text-xs font-semibold text-gray-400">Unknown</span>
        : ok
          ? <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-green-600"><span className="w-2 h-2 rounded-full bg-green-500" />Operational</span>
          : <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-amber-600"><span className="w-2 h-2 rounded-full bg-amber-500" />Degraded</span>}
    </div>
  )
}

export default function StatusPage() {
  const [state, setState] = useState('loading')
  const [checks, setChecks] = useState({ api: null, d1: null, r2: null })
  const [version, setVersion] = useState(null)
  const [checkedAt, setCheckedAt] = useState(null)
  const [loading, setLoading] = useState(false)

  const check = useCallback(async () => {
    setLoading(true)
    try {
      const [health, ready] = await Promise.allSettled([
        fetch(`${ROOT}/health`, { cache: 'no-store' }).then(async (r) => ({ status: r.status, body: await r.json() })),
        fetch(`${ROOT}/ready`, { cache: 'no-store' }).then(async (r) => ({ status: r.status, body: await r.json() })),
      ])
      const healthProbe = health.status === 'fulfilled' ? health.value : null
      const readyProbe = ready.status === 'fulfilled' ? ready.value : null
      const h = healthProbe?.body ?? null
      const rd = readyProbe?.body ?? null
      const apiUp = healthProbe?.status === 200 && h?.status === 'ok'
      const readyObserved =
        readyProbe !== null &&
        (readyProbe.status === 200 || readyProbe.status === 503) &&
        typeof rd?.checks?.d1 === 'boolean' &&
        typeof rd?.checks?.r2 === 'boolean'
      const d1 = readyObserved ? rd.checks.d1 : null
      const r2 = readyObserved ? rd.checks.r2 : null
      setChecks({ api: apiUp, d1, r2 })
      setVersion(apiUp ? (h?.version ?? null) : null)
      setCheckedAt(new Date())

      if (!apiUp || !readyObserved) setState('unknown')
      else if (h?.maintenance === true) setState('maintenance')
      else if (readyProbe.status === 200 && rd?.status === 'ready' && d1 === true && r2 === true) setState('operational')
      else setState('degraded')
    } catch {
      setChecks({ api: false, d1: null, r2: null })
      setState('unknown')
      setCheckedAt(new Date())
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    check()
    const id = setInterval(check, 30000)
    return () => clearInterval(id)
  }, [check])

  const s = STATE[state] || STATE.unknown
  const StateIcon = s.Icon

  return (
    <div className="min-h-screen bg-gray-50">
      <main className="max-w-2xl mx-auto px-6 py-12">
        <Link to="/" className="inline-flex items-center gap-2 group mb-8">
          <div className="w-7 h-7 rounded-md bg-brand-600 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" strokeWidth={2.5} />
          </div>
          <span className="font-bold text-gray-900 text-sm group-hover:text-brand-700 transition-colors">CyberMeters</span>
        </Link>

        <div className="bg-white border border-gray-100 rounded-2xl shadow-sm p-8">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3 min-w-0">
              {state === 'loading'
                ? <RefreshCw className="w-6 h-6 text-gray-300 animate-spin flex-shrink-0" />
                : <StateIcon className={`w-6 h-6 flex-shrink-0 ${s.iconCls}`} />}
              <div className="min-w-0">
                <h1 className="text-xl font-bold text-gray-900">System status</h1>
                <p className={`text-sm font-semibold ${state === 'loading' ? 'text-gray-400' : s.cls}`}>
                  {state === 'loading' ? 'Checking…' : s.label}
                </p>
              </div>
            </div>
            <button
              onClick={check}
              disabled={loading}
              className="flex-shrink-0 inline-flex items-center gap-1.5 rounded-full border border-gray-200 px-3 py-1.5 text-xs font-semibold text-gray-600 hover:border-brand-300 hover:text-brand-700 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>

          <div className="mt-6">
            <Component name="API" ok={checks.api} />
            <Component name="Database" ok={checks.d1} />
            <Component name="Report storage" ok={checks.r2} />
          </div>

          <p className="mt-6 text-xs text-gray-400">
            {checkedAt ? `Checked ${checkedAt.toLocaleTimeString()}` : 'Checking…'}
            {version ? ` · version ${version}` : ''} · auto-refreshes every 30s.
          </p>
        </div>

        <p className="mt-4 text-center text-xs text-gray-400">
          Real-time health check. For incident history and disclosure, see our{' '}
          <Link to="/trust" className="text-brand-600 hover:underline">Trust &amp; Security</Link> page.
        </p>
      </main>
    </div>
  )
}
