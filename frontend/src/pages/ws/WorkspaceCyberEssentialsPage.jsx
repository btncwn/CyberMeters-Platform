import { useCallback, useEffect, useState } from 'react'
import {
  AlertCircle, CheckCircle2, HelpCircle, ShieldCheck,
} from 'lucide-react'
import {
  Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import { useWorkspace } from '../../hooks/useWorkspace'
import { PlanGate } from '../../components/PlanUsageCard'

const CATEGORY_LABELS = {
  boundary_protection: 'Boundary Protection',
  secure_configuration: 'Secure Configuration',
  access_control: 'Access Control',
  malware_protection: 'Phishing & Malware Exposure',
  patch_management_readiness: 'Patch Management',
}

function gradeColor(grade) {
  if (grade === 'A' || grade === 'B') return 'text-brand-600 bg-brand-50 border-brand-100'
  if (grade === 'C') return 'text-amber-700 bg-amber-50 border-amber-100'
  return 'text-red-700 bg-red-50 border-red-100'
}

function scoreColor(score) {
  if (score >= 90) return '#00876A'
  if (score >= 75) return '#22C55E'
  if (score >= 55) return '#F59E0B'
  if (score >= 35) return '#F97316'
  return '#EF4444'
}

function statusLabel(status) {
  return String(status || 'unknown').replace(/_/g, ' ')
}

function CategoryCard({ category }) {
  const score = category.score ?? 0
  const gaps = category.gaps ?? []

  return (
    <div className="card p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-gray-900">
            {category.label || CATEGORY_LABELS[category.key] || category.key}
          </p>
          <p className="text-xs text-gray-400 mt-0.5">Weight: {category.weight}%</p>
        </div>
        <div className="text-right">
          <p className="text-2xl font-black text-gray-900">{score}</p>
          <p className="text-[10px] text-gray-400">/100</p>
        </div>
      </div>

      <div className="h-1.5 bg-gray-100 rounded-full mt-4 overflow-hidden">
        <div
          className="h-full rounded-full"
          style={{ width: `${Math.max(0, Math.min(100, score))}%`, backgroundColor: scoreColor(score) }}
        />
      </div>

      <ul className="mt-4 space-y-1.5">
        {(category.reasons ?? []).slice(0, 3).map((reason, index) => (
          <li key={index} className="flex gap-2 text-xs text-gray-500 leading-relaxed">
            {gaps.includes(reason)
              ? <AlertCircle className="w-3.5 h-3.5 text-amber-500 flex-shrink-0 mt-0.5" />
              : <CheckCircle2 className="w-3.5 h-3.5 text-brand-500 flex-shrink-0 mt-0.5" />}
            <span>{reason}</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function ReadinessChart({ categories }) {
  const data = (categories ?? []).map((category) => ({
    name: category.label || CATEGORY_LABELS[category.key] || category.key,
    score: category.score ?? 0,
  }))

  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={data} margin={{ top: 8, right: 16, left: -8, bottom: 8 }} barSize={34}>
        <CartesianGrid strokeDasharray="3 3" stroke="#F3F4F6" vertical={false} />
        <XAxis dataKey="name" tick={{ fontSize: 11, fill: '#6B7280' }} axisLine={false} tickLine={false} />
        <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: '#9CA3AF' }} axisLine={false} tickLine={false} />
        <Tooltip
          cursor={{ fill: '#F9FAFB' }}
          content={({ active, payload }) => {
            if (!active || !payload?.length) return null
            const item = payload[0].payload
            return (
              <div className="bg-white border border-gray-100 rounded-xl shadow-lg px-3 py-2 text-xs">
                <p className="font-semibold text-gray-900">{item.name}</p>
                <p className="text-gray-500">Score: <span className="font-bold text-gray-900">{item.score}/100</span></p>
              </div>
            )
          }}
        />
        <Bar dataKey="score" radius={[6, 6, 0, 0]}>
          {data.map((item) => <Cell key={item.name} fill={scoreColor(item.score)} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export default function WorkspaceCyberEssentialsPage() {
  const { wsId, wsName } = useWorkspace()
  const [readiness, setReadiness] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true)
    setError(null)
    try {
      setReadiness(await api.getWorkspaceCyberEssentialsReadiness(wsId))
    } catch (err) {
      setError(err)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  if (!wsId) return <NoWorkspaceSelected />

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error?.error === 'plan_feature_required' ? null : error?.message} onRetry={load}>
      <PlanGate error={error}>
      <div className="flex items-start justify-between gap-4 flex-wrap mb-8">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Cyber Essentials Readiness</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            A lightweight readiness estimate for UK Cyber Essentials, based on existing CyberMeters signals.
          </p>
        </div>

        <div className={`card px-5 py-4 border ${gradeColor(readiness?.grade)}`}>
          <div className="flex items-center gap-4">
            <ShieldCheck className="w-7 h-7" />
            <div>
              <p className="text-xs uppercase tracking-wide font-semibold opacity-70">Readiness</p>
              <p className="text-3xl font-black">
                {readiness?.score ?? '—'}<span className="text-base font-semibold opacity-60">/100</span>
              </p>
            </div>
            <div className="text-right">
              <p className="text-3xl font-black">{readiness?.grade ?? '—'}</p>
              <p className="text-xs capitalize">{statusLabel(readiness?.status)}</p>
            </div>
          </div>
        </div>
      </div>

      {readiness && (
        <>
          <div className="card p-4 mb-6 border border-blue-100 bg-blue-50">
            <p className="text-sm font-semibold text-blue-900">Score context</p>
            <p className="text-xs text-blue-700 mt-1">
              Business Risk Score measures business impact. Cyber Essentials Readiness measures preparation for Cyber Essentials controls.
            </p>
          </div>

          <div className="card p-6 mb-8">
            <div className="flex items-start gap-3 mb-5">
              <HelpCircle className="w-5 h-5 text-blue-500 flex-shrink-0 mt-0.5" />
              <div>
                <h2 className="font-semibold text-gray-900">Assessment Summary</h2>
                <p className="text-sm text-gray-500 mt-1">{readiness.summary}</p>
                <p className="text-xs text-gray-400 mt-2">
                  CyberMeters does not certify Cyber Essentials. This is readiness guidance only.
                </p>
              </div>
            </div>
            <ReadinessChart categories={readiness.categories} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 mb-8">
            {(readiness.categories ?? []).map((category) => (
              <CategoryCard key={category.key} category={category} />
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="card p-6">
              <h2 className="font-semibold text-gray-900 mb-4">Top Gaps</h2>
              {(readiness.top_gaps ?? []).length > 0 ? (
                <ul className="space-y-3">
                  {readiness.top_gaps.map((gap, index) => (
                    <li key={index} className="flex gap-3 text-sm text-gray-600">
                      <AlertCircle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
                      <span>{gap}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-gray-400">No major readiness gaps detected from available signals.</p>
              )}
            </div>

            <div className="card p-6">
              <h2 className="font-semibold text-gray-900 mb-4">Improvement Recommendations</h2>
              {(readiness.recommendations ?? []).length > 0 ? (
                <ul className="space-y-3">
                  {readiness.recommendations.map((item, index) => (
                    <li key={index} className="flex gap-3 text-sm text-gray-600">
                      <span className="w-5 h-5 rounded-full bg-brand-600 text-white text-xs font-bold flex items-center justify-center flex-shrink-0">
                        {index + 1}
                      </span>
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-gray-400">Continue monitoring and re-run scans after changes.</p>
              )}
            </div>
          </div>
        </>
      )}
      </PlanGate>
    </WsPage>
  )
}
