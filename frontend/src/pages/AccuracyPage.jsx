import { useCallback, useEffect, useState } from 'react'
import { Activity, AlertTriangle, CheckCircle2, ShieldCheck, TrendingUp, Globe, Target, Shield } from 'lucide-react'
import { api } from '../api'
import StatCard from '../components/StatCard'

function MetricBar({ label, value, tone = 'brand', note = null }) {
  const color = tone === 'amber' ? 'bg-amber-500' : tone === 'red' ? 'bg-red-500' : 'bg-brand-500'
  const pct = Math.max(0, Math.min(100, Number(value || 0)))
  return (
    <div>
      <div className="flex items-center justify-between text-sm mb-1.5">
        <span className="text-gray-600 font-medium">{label}</span>
        <span className="text-gray-900 font-bold">{pct}%</span>
      </div>
      <div className="h-2 rounded-full bg-gray-100 overflow-hidden">
        <div className={`h-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      {note && <p className="text-[11px] text-gray-400 mt-1">{note}</p>}
    </div>
  )
}

function AccuracyScoreBadge({ score }) {
  if (score == null) return null
  const color = score >= 80 ? 'text-brand-700 bg-brand-50 border-brand-200'
    : score >= 60 ? 'text-blue-700 bg-blue-50 border-blue-200'
    : score >= 40 ? 'text-amber-700 bg-amber-50 border-amber-200'
    : 'text-red-700 bg-red-50 border-red-200'
  const label = score >= 80 ? 'High' : score >= 60 ? 'Good' : score >= 40 ? 'Fair' : 'Low'
  return (
    <div className={`flex items-center gap-3 rounded-xl border px-5 py-4 ${color}`}>
      <Target className="w-8 h-8 flex-shrink-0" />
      <div>
        <p className="text-xs font-semibold uppercase tracking-wide opacity-70">Accuracy Score</p>
        <p className="text-3xl font-bold leading-tight">{score}<span className="text-base font-normal opacity-60">/100</span></p>
        <p className="text-xs font-medium opacity-70">{label} accuracy</p>
      </div>
    </div>
  )
}

export default function AccuracyPage() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      setData(await api.getPlatformAccuracy())
    } catch (e) {
      setError(e.message || 'Failed to load accuracy metrics')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div className="max-w-screen-xl mx-auto px-6 py-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scanner Accuracy</h1>
          <p className="text-sm text-gray-500 mt-1">Resolver agreement, header validation, evidence quality, and regression health.</p>
        </div>
        <button onClick={load} className="btn-secondary" disabled={loading}>
          Refresh
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-red-100 bg-red-50 px-4 py-3 flex items-center gap-2 text-sm text-red-600 mb-6">
          <AlertTriangle className="w-4 h-4" />
          {error}
        </div>
      )}

      {loading && !data ? (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="card p-5 animate-pulse">
              <div className="h-3 bg-gray-100 rounded w-1/2 mb-4" />
              <div className="h-7 bg-gray-100 rounded w-2/3" />
            </div>
          ))}
        </div>
      ) : (
        <>
          {/* Accuracy Score + summary cards */}
          <div className="flex flex-col md:flex-row gap-4 mb-6">
            <AccuracyScoreBadge score={data?.accuracy_score} />
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 flex-1">
              <StatCard icon={Activity}      label="Total Findings"      value={data?.findings_total ?? 0} />
              <StatCard icon={Globe}         label="Resolver Agreement"  value={data?.resolver_agreement_avg != null ? `${data.resolver_agreement_avg}%` : '—'} />
              <StatCard icon={Shield}        label="Header Validation"   value={`${data?.header_validation_score ?? 75}%`} />
              <StatCard icon={CheckCircle2}  label="Evidence Complete"   value={`${data?.evidence_complete_pct ?? 0}%`} />
              <StatCard icon={TrendingUp}    label="Regression Pass"     value={`${data?.regression_pass_rate ?? 0}%`} danger={(data?.regression_pass_rate ?? 0) < 100} />
              <StatCard icon={Target}        label="Golden Domain Cov."  value={`${data?.golden_domain_coverage ?? 0}%`} note={`${data?.regression_fixture_count ?? 0}/15 fixtures`} />
              <StatCard icon={ShieldCheck}   label="High Confidence"     value={`${data?.high_confidence_pct ?? 0}%`} />
              <StatCard icon={AlertTriangle} label="Low Confidence"      value={`${data?.low_confidence_pct ?? 0}%`} warning={(data?.low_confidence_pct ?? 0) > 20} />
            </div>
          </div>

          {/* Detailed metric bars */}
          <div className="card p-6">
            <h2 className="text-sm font-semibold text-gray-900 mb-5">Accuracy Score Breakdown (v5 Formula)</h2>
            <div className="space-y-5">
              <MetricBar
                label="Resolver agreement average"
                value={data?.resolver_agreement_avg ?? 50}
                note="Weight: 35% — cross-resolver DNS consistency (Cloudflare + Google + Quad9 for A records)"
              />
              <MetricBar
                label="Header validation score"
                value={data?.header_validation_score ?? 75}
                note="Weight: 25% — % of observed headers with valid or unclassified strength (not weak/malformed)"
              />
              <MetricBar
                label="Evidence completeness"
                value={data?.evidence_complete_pct}
                note="Weight: 20% — findings with 'good' or 'excellent' evidence quality"
              />
              <MetricBar
                label="Regression pass rate"
                value={data?.regression_pass_rate}
                note={`Weight: 10% — ${data?.regression_fixture_count ?? 0}/15 fixture scenarios passing`}
                tone={data?.regression_pass_rate < 100 ? 'red' : 'brand'}
              />
              <MetricBar
                label="Golden domain coverage"
                value={data?.golden_domain_coverage ?? 0}
                note="Weight: 10% — regression fixture breadth relative to 15-fixture target"
              />
            </div>

            {/* Secondary metrics (not in score) */}
            <div className="mt-6 pt-5 border-t border-gray-100 space-y-5">
              <h3 className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-3">Supplemental Metrics (not in score)</h3>
              <MetricBar
                label="High confidence findings"
                value={data?.high_confidence_pct}
              />
              <MetricBar
                label="Low confidence findings"
                value={data?.low_confidence_pct}
                tone="amber"
              />
              <MetricBar
                label="Validation uncertain findings"
                value={data?.validation_uncertain_pct}
                tone="red"
                note={`${data?.validation_uncertain_count ?? 0} finding${data?.validation_uncertain_count !== 1 ? 's' : ''} flagged as uncertain`}
              />
            </div>

            <div className="mt-6 pt-5 border-t border-gray-100 text-xs text-gray-400 space-y-1">
              <p><span className="font-medium text-gray-600">Accuracy Score formula (v5):</span> (Resolver Agreement × 0.35) + (Header Validation × 0.25) + (Evidence Complete × 0.20) + (Regression Pass × 0.10) + (Golden Domain Coverage × 0.10)</p>
              <p>Resolver agreement: null defaults to 50 in score calculation. Header validation: defaults to 75 when no header evidence exists.</p>
              <p>Golden domain coverage: regression fixture count / 15 target (v5). Current: {data?.regression_fixture_count ?? 0} fixtures.</p>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
