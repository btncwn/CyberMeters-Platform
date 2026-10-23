import { parseServerDate, formatNumber } from '../../utils/dates'
import { formatReportDay, formatReportTime } from '../../lib/reportTime'

// One time convention on this page: every time in UTC with the zone named,
// every date in UTC (the same report must never show 10:16 UTC and 11:16).
export const pageTime = (value) => (value ? `${formatReportTime(value)} UTC` : null)
import { useAppDialog } from '../../components/AppDialog'
import { MailTransportCard } from '../../components/MailTransportCard'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import { ChevronDown, RefreshCw, X } from 'lucide-react'
import DmarcPolicyEvidenceCard from '../../components/DmarcPolicyEvidenceCard'
import CloudflareDnsChanges from '../../components/CloudflareDnsChanges'
import { api, BASE } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import ModuleContract, { useAreaAnchor } from '../../components/module/ModuleContract'

// ─────────────────────────────────────────────────────────────────────────────
// Managed DMARC / Email Protection Experience v1
//
// Consumes the backend contract under report.modules.email_security:
//   spf_detail · dmarc_detail · dkim_detail · bimi_readiness · mta_sts_detail ·
//   tls_rpt_detail · policy_journey · remediation_actions · applicability
//
// Every field is read defensively — the page degrades to a calm empty state
// rather than crashing when a field is absent.
// ─────────────────────────────────────────────────────────────────────────────

const SEVERITY = {
  critical: { label: 'Critical', pill: 'bg-red-50 text-red-700 border-red-100',       dot: 'bg-red-500',    rank: 0 },
  high:     { label: 'High',     pill: 'bg-red-50 text-red-700 border-red-100', dot: 'bg-red-500', rank: 1 },
  medium:   { label: 'Medium',   pill: 'bg-transparent text-brand-700 border-[1.5px] border-brand-700',  dot: 'bg-brand-700',  rank: 2 },
  low:      { label: 'Low',      pill: 'bg-blue-50 text-blue-700 border-blue-100',     dot: 'bg-blue-500',   rank: 3 },
  info:     { label: 'Info',     pill: 'bg-gray-100 text-gray-600 border-gray-200',    dot: 'bg-gray-400',   rank: 4 },
}
const sevCfg = (s) => SEVERITY[s] || SEVERITY.info

const CONFIDENCE = {
  high:   'bg-brand-50 text-brand-700 border-brand-100',
  medium: 'bg-transparent text-brand-700 border-[1.5px] border-brand-700',
  low:    'bg-gray-100 text-gray-500 border-gray-200',
}

// ── Copy-to-clipboard button for DNS values ───────────────────────────────────
function CopyButton({ value, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)
  if (!value) return null
  function handle() {
    navigator.clipboard?.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    }).catch(() => {})
  }
  return (
    <button
      onClick={handle}
      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-gray-200 bg-white hover:bg-gray-50 text-xs font-semibold text-gray-700 transition-colors shrink-0"
      title="Copy DNS value"
    >
      {copied ? 'Copied' : label}
    </button>
  )
}

// ── DNS value block (monospace + copy) ────────────────────────────────────────
function DnsValue({ value }) {
  if (!value) return null
  return (
    <div className="flex items-start gap-2 mt-2 rounded-lg bg-gray-50 border border-gray-200 p-2.5">
      <code className="mono text-xs text-gray-800 break-all flex-1 leading-relaxed">{value}</code>
      <CopyButton value={value} />
    </div>
  )
}

// ── DMARC policy journey ──────────────────────────────────────────────────────
const JOURNEY_STAGES = [
  { stage: 'missing',             label: 'No DMARC' },
  { stage: 'monitoring',          label: 'No-action policy' },
  { stage: 'partial_enforcement', label: 'Quarantine requested' },
  { stage: 'full_enforcement',    label: 'Rejection requested' },
]

function DmarcJourney({ journey }) {
  if (!journey || !journey.stage) {
    return (
      <EmptyCard title="DMARC journey unavailable"
        body="DMARC journey data is not available for this scan yet. Re-run a scan to generate it." />
    )
  }
  const currentIdx = Math.max(0, JOURNEY_STAGES.findIndex(s => s.stage === journey.stage))
  const isReject = journey.stage === 'full_enforcement'

  return (
    <section className="card-md overflow-hidden">
      <div className="flex items-center gap-2.5 px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <div>
          <span className="eyebrow">DMARC Policy Journey</span>
          <h2 className="section-title leading-tight">Where you are on the requested-policy journey</h2>
        </div>
      </div>

      {/* Track */}
      <div className="px-6 pt-7 pb-2">
        <div className="flex items-center">
          {JOURNEY_STAGES.map((s, i) => {
            const done = i < currentIdx
            const current = i === currentIdx
            return (
              <div key={s.stage} className="flex items-center flex-1 last:flex-none">
                <div className="flex flex-col items-center">
                  <div className={`w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-colors ${
                    current ? 'bg-brand-200 border-brand-200 text-brand-900 ring-4 ring-brand-100'
                    : done ? 'bg-brand-50 border-brand-300 text-brand-700'
                    : 'bg-white border-gray-200 text-gray-600'
                  }`}>
                    {i + 1}
                  </div>
                  <span className={`mt-2 text-xs font-semibold whitespace-nowrap ${
                    current ? 'text-brand-700' : done ? 'text-gray-600' : 'text-gray-400'
                  }`}>{s.label}</span>
                </div>
                {i < JOURNEY_STAGES.length - 1 && (
                  <div className={`h-0.5 flex-1 mx-2 mb-6 rounded-full ${i < currentIdx ? 'bg-brand-400' : 'bg-gray-200'}`} />
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Current stage detail */}
      <div className="px-6 pb-6 pt-3">
        <div className={`rounded-xl border p-4 ${isReject ? 'border-brand-100 bg-brand-50/50' : 'border-[1.5px] border-brand-700 bg-transparent'}`}>
          <div className="flex items-center gap-2 mb-2">
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold ${
              isReject ? 'bg-brand-200 text-brand-900' : 'bg-brand-700 text-white'}`}>
              You are here · {journey.label || JOURNEY_STAGES[currentIdx].label}
            </span>
          </div>
          {journey.business_risk && (
            <div className="mb-3">
              <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-0.5">What this means for your business</p>
              <p className="text-sm text-gray-700 leading-relaxed">{journey.business_risk}</p>
            </div>
          )}
          {journey.next_step && (
            <div>
              <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-0.5">Next recommended step</p>
              <p className="text-sm text-gray-800 font-medium leading-relaxed flex items-start gap-1.5">
                {journey.next_step}
              </p>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

// ── Generic auth card scaffold ────────────────────────────────────────────────
function statusPill(kind) {
  // kind: 'good' | 'warn' | 'bad' | 'info' | 'na'
  const map = {
    good: 'bg-brand-50 text-brand-700 border-brand-100',
    warn: 'bg-transparent text-brand-700 border-[1.5px] border-brand-700',
    bad:  'bg-red-50 text-red-700 border-red-100',
    info: 'bg-blue-50 text-blue-700 border-blue-100',
    na:   'bg-gray-100 text-gray-500 border-gray-200',
  }
  return map[kind] || map.na
}

// Before any email data exists, each sidebar topic still lands on its own named
// section, saying honestly that nothing has been read yet (C-38 S26/S29).
const PENDING_TOPICS = [
  ['auth-dmarc', 'DMARC policy'],
  ['auth-spf', 'SPF'],
  ['auth-dkim', 'DKIM'],
  ['report-history', 'Aggregate reports'],
  ['mail-transport', 'Mail transport (DANE)'],
]
function EmailTopicsPending() {
  return (
    <div className="mt-4 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4" data-testid="email-topics-pending">
      {PENDING_TOPICS.map(([id, title]) => (
        <section key={id} id={id} className="card p-5" aria-label={title}>
          <h3 className="text-sm font-bold text-gray-900">{title}</h3>
          <p className="mt-1 text-sm text-gray-600">Not read yet — this fills after a completed scan.</p>
        </section>
      ))}
    </div>
  )
}

// Each record card is an anchor the sidebar opens (#auth-spf, #auth-dmarc, …).
function AuthCard({ title, status, statusKind = 'na', children }) {
  return (
    <div id={`auth-${String(title).toLowerCase().replace(/[^a-z0-9]+/g, '-')}`} className="card p-5 flex flex-col scroll-mt-28">
      <div className="flex items-center justify-between gap-2 mb-3">
        <h3 className="text-sm font-bold text-gray-900 min-w-0">{title}</h3>
        {status && (
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${statusPill(statusKind)}`}>
            {status}
          </span>
        )}
      </div>
      <div className="text-sm space-y-2.5 flex-1">{children}</div>
    </div>
  )
}

function KV({ k, v, mono }) {
  return (
    <div className="flex items-start justify-between gap-3">
      <span className="text-xs font-semibold text-gray-500 shrink-0">{k}</span>
      <span className={`text-xs text-gray-800 text-right break-all ${mono ? 'mono' : 'font-medium'}`}>{v}</span>
    </div>
  )
}

// Replace raw Cloudflare/Worker/internal platform errors with customer-safe
// copy. Genuine findings (e.g. "No TXT record found") pass through unchanged.
function sanitizeWarning(w) {
  const raw = typeof w === 'string' ? w : (w?.message || w?.text || String(w ?? ''))
  if (/subrequest|cloudflare|workers?\.dev|developers\.cloudflare|internal error|cpu time|script will never|stack trace|exceeded|too many requests by/i.test(raw)) {
    return 'Some email authentication checks could not be completed during this scan. Review the available results or run a new scan.'
  }
  return raw
}
function Warnings({ items }) {
  if (!items || items.length === 0) return null
  // De-dupe after sanitizing so a repeated internal error collapses to one line.
  const safe = [...new Set(items.map(sanitizeWarning).filter(Boolean))]
  if (safe.length === 0) return null
  return (
    <div className="mt-1 space-y-1.5">
      {safe.map((w, i) => (
        <p key={i} className="flex items-start gap-1.5 text-xs text-brand-700 leading-relaxed">
          {w}
        </p>
      ))}
    </div>
  )
}

// ── Individual auth cards ─────────────────────────────────────────────────────
function SpfCard({ spf, detail, wsId, domain }) {
  const [chain, setChain]   = useState(null)   // null | 'loading' | analysis result
  if (!detail && !spf) return <AuthCard title="SPF" status="No data" statusKind="na"><NaNote /></AuthCard>
  const present = spf?.present ?? Boolean(detail?.raw)
  const valid = detail?.valid
  const status = !present ? 'Not found' : valid ? 'Published' : 'Issues found'
  const kind = !present ? 'bad' : valid ? 'good' : 'warn'

  async function analyseChain() {
    setChain('loading')
    try { setChain(await api.getSpfAnalysis(wsId, domain)) }
    catch { setChain({ status: 'dns_lookup_failed' }) }
  }
  const live = chain && chain !== 'loading' ? chain : null

  return (
    <AuthCard title="SPF" status={status} statusKind={kind}>
      <KV k="Record status" v={!present ? 'Not published' : valid ? 'Valid' : 'Published, needs review'} />
      {detail?.all_mechanism != null && <KV k="‘all’ mechanism" v={detail.all_mechanism} mono />}
      {detail?.policy_strength && <KV k="Policy strength" v={<span className="capitalize">{detail.policy_strength}</span>} />}
      {live?.status === 'ok' ? (
        <KV k="DNS lookups (live)" v={
          <span className={live.over_limit ? 'text-red-700 font-bold' : 'text-brand-700 font-semibold'}>
            {live.lookups_used} / {live.lookup_limit}{live.over_limit ? ' — limit exceeded' : ''}{live.truncated ? ' (partial)' : ''}
          </span>} />
      ) : typeof detail?.lookup_count_estimate === 'number' && (
        <KV k="DNS lookups (est.)" v={
          <span className={detail.lookup_count_estimate > 10 ? 'text-red-700 font-bold' : ''}>
            {detail.lookup_count_estimate}{detail.lookup_count_estimate > 10 ? ' / 10 limit exceeded' : ' / 10'}
          </span>} />
      )}
      {detail?.includes?.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-gray-500 mb-1">Includes ({detail.includes.length})</p>
          <div className="flex flex-wrap gap-1">
            {detail.includes.map((inc, i) => (
              <span key={i} className="mono text-xs bg-gray-50 border border-gray-200 rounded-sm px-1.5 py-0.5 text-gray-700">{inc}</span>
            ))}
          </div>
        </div>
      )}
      {detail?.raw && <DnsValue value={detail.raw} />}
      <Warnings items={detail?.warnings} />

      {/* SPF chain analysis — resolves the full include tree live */}
      {present && wsId && domain && (
        <div className="pt-2 border-t border-gray-100">
          {!chain && (
            <button onClick={analyseChain} className="btn-secondary text-xs w-full">
              Analyse full include chain
            </button>
          )}
          {chain === 'loading' && (
            <p className="text-xs text-gray-400 flex items-center gap-1.5">
              <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Resolving the include tree…
            </p>
          )}
          {live && live.status !== 'ok' && (
            <p className="text-xs text-gray-500">The live SPF analysis could not be completed. Try again shortly.</p>
          )}
          {live?.status === 'ok' && (
            <div className="space-y-2">
              {live.tree?.length > 1 && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 mb-1">Resolved chain ({live.tree.length} records)</p>
                  <div className="space-y-0.5 max-h-32 overflow-y-auto">
                    {live.tree.map((n, i) => (
                      <p key={i} className="mono text-xs text-gray-600 truncate" style={{ paddingLeft: `${n.depth * 10}px` }}>
                        {n.domain} <span className="text-gray-400">· {n.lookups_here} lookup{n.lookups_here === 1 ? '' : 's'}{!n.record ? ' · no SPF' : ''}</span>
                      </p>
                    ))}
                  </div>
                </div>
              )}
              <Warnings items={live.warnings} />
              {live.over_limit && live.flattened?.suggested_record && (
                <div>
                  <p className="text-xs font-semibold text-red-700 mb-1">
                    Over the 10-lookup limit — receivers may permerror. Flattened alternative:
                  </p>
                  <DnsValue value={live.flattened.suggested_record} />
                  <p className="text-xs text-gray-400 mt-1 leading-relaxed">
                    Flattened records list IPs directly, so they drift when providers change —
                    re-run this analysis after any sending-provider change.
                  </p>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </AuthCard>
  )
}

function DmarcCard({ dmarc, detail }) {
  if (!detail && !dmarc) return <AuthCard title="DMARC" status="No data" statusKind="na"><NaNote /></AuthCard>
  const present = dmarc?.present ?? Boolean(detail?.raw)
  const policy = detail?.policy || dmarc?.policy
  const status = !present ? 'Not found' : detail?.valid === false ? 'Invalid' : (policy ? `p=${policy}` : 'Published')
  const kind = !present ? 'bad' : detail?.valid === false ? 'warn' : policy === 'reject' ? 'good' : policy === 'none' ? 'warn' : 'info'
  const align = (m) => (m === 's' ? 'Strict' : m === 'r' ? 'Relaxed' : m || '—')
  return (
    <AuthCard title="DMARC" status={status} statusKind={kind}>
      <KV k="Exact-record policy (p)" v={policy ? <code className="mono">{policy}</code> : 'Not set'} />
      <KV k="Subdomain policy (sp)" v={detail?.subdomain_policy ? <code className="mono">{detail.subdomain_policy}</code> : 'Inherits main'} />
      {typeof detail?.percentage === 'number' && <KV k="Legacy pct (not applied by DMARCbis)" v={`${detail.percentage}%`} />}
      <KV k="Alignment" v={`DKIM ${align(detail?.adkim)} · SPF ${align(detail?.aspf)}`} />
      {detail?.rua?.length > 0 && <KV k="Aggregate reports (rua)" v={detail.rua.join(', ')} mono />}
      {detail?.ruf?.length > 0 && <KV k="Forensic reports (ruf)" v={detail.ruf.join(', ')} mono />}
      {present && detail?.rua?.length === 0 && <KV k="Aggregate reports (rua)" v={<span className="text-brand-700">None configured</span>} />}
      {detail?.raw && <DnsValue value={detail.raw} />}
      <Warnings items={detail?.warnings} />
    </AuthCard>
  )
}

function DkimCard({ detail }) {
  const status = detail?.status
  const label = status === 'detected' ? 'Detected' : status === 'uncertain' ? 'Uncertain' : status === 'not_detected' ? 'Not verified' : 'No data'
  const kind = status === 'detected' ? 'good' : status === 'uncertain' ? 'warn' : 'na'
  return (
    <AuthCard title="DKIM" status={label} statusKind={kind}>
      {detail?.selector && <KV k="Selector" v={detail.selector} mono />}
      {detail?.provider && <KV k="Provider (inferred)" v={detail.provider} />}
      <p className="text-xs text-gray-600 leading-relaxed">
        {detail?.explanation || 'DKIM could not be verified using common selectors.'}
      </p>
      {/* Always surface the uncertainty caveat safely */}
      <div className="flex items-start gap-1.5 rounded-lg bg-blue-50 border border-blue-100 p-2.5">
        <p className="text-xs text-blue-800 leading-relaxed">
          {detail?.limitation || 'Full DKIM validation requires a signed email sample or a known selector. A custom selector may be in use even when none is detected.'}
        </p>
      </div>
    </AuthCard>
  )
}

function BimiCard({ readiness }) {
  if (!readiness) return <AuthCard title="BIMI" status="No data" statusKind="na"><NaNote /></AuthCard>
  const found = readiness.record_found
  return (
    <AuthCard title="BIMI" status={found ? 'Record found' : 'Not configured'} statusKind={found ? 'info' : 'na'}>
      <p className="text-xs text-gray-500 -mt-1">Readiness only — BIMI is optional and never replaces SPF, DKIM, or DMARC.</p>
      <KV k="Record" v={found ? 'Published' : 'None'} />
      {readiness.logo_url && <KV k="Logo URL" v={readiness.logo_url} mono />}
      {readiness.certificate_url ? <KV k="Certificate URL" v={readiness.certificate_url} mono />
        : found && <KV k="Certificate URL" v={<span className="text-brand-700">Not listed</span>} />}
      {readiness.blockers?.length > 0 && (
        <div className="rounded-lg bg-transparent border border-[1.5px] border-brand-700 p-2.5 space-y-1">
          <p className="text-xs font-bold text-brand-700 uppercase tracking-wide">Readiness blockers</p>
          {readiness.blockers.map((b, i) => <p key={i} className="text-xs text-brand-700 leading-relaxed">{b}</p>)}
        </div>
      )}
      <Warnings items={readiness.warnings} />
    </AuthCard>
  )
}

function MtaStsCard({ detail }) {
  if (!detail) return <AuthCard title="MTA-STS" status="Not available" statusKind="na">
    <NaNote text="MTA-STS transport details were not returned for this scan." /></AuthCard>
  const enforced = detail.policy_found && detail.mode === 'enforce'
  return (
    <AuthCard title="MTA-STS" status={detail.policy_found ? (detail.mode || 'Found') : 'No policy'} statusKind={enforced ? 'good' : detail.policy_found ? 'warn' : 'na'}>
      <KV k="Policy file" v={detail.policy_found ? 'Confirmed' : 'Not confirmed'} />
      <KV k="Mode" v={<span className="capitalize">{detail.mode || 'unknown'}</span>} />
      <Warnings items={detail.warnings} />
    </AuthCard>
  )
}

function TlsRptCard({ detail }) {
  if (!detail) return <AuthCard title="TLS-RPT" status="Not available" statusKind="na">
    <NaNote text="TLS-RPT details were not returned for this scan." /></AuthCard>
  return (
    <AuthCard title="TLS-RPT" status={detail.record_found ? 'Found' : 'Not found'} statusKind={detail.record_found ? 'good' : 'na'}>
      <KV k="Record" v={detail.record_found ? 'Published' : 'None'} />
      {detail.rua?.length > 0 && <KV k="Reporting (rua)" v={detail.rua.join(', ')} mono />}
      <Warnings items={detail.warnings} />
    </AuthCard>
  )
}

function NaNote({ text }) {
  return <p className="text-xs text-gray-400">{text || 'No data was returned for this protocol.'}</p>
}

// ── Recommended Actions Center ────────────────────────────────────────────────
function ActionCard({ action }) {
  const [open, setOpen] = useState(false)
  const sev = sevCfg(action.severity)
  return (
    <div className="card overflow-hidden">
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-start gap-3 px-5 py-4 text-left hover:bg-gray-50/60 transition-colors">
        <span className={`w-2 h-2 rounded-full shrink-0 mt-2 ${sev.dot}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-bold text-gray-900">{action.title}</p>
            {action.protocol && <span className="text-xs font-bold uppercase tracking-wide text-gray-500 bg-gray-100 border border-gray-200 rounded-sm px-1.5 py-0.5">{action.protocol}</span>}
            <span className={`text-xs font-bold uppercase tracking-wide px-1.5 py-0.5 rounded-sm border ${sev.pill}`}>{sev.label}</span>
            {action.confidence && <span className={`text-xs font-semibold px-1.5 py-0.5 rounded-sm border ${CONFIDENCE[action.confidence] || CONFIDENCE.low}`}>{action.confidence} confidence</span>}
          </div>
          {action.issue && <p className="text-xs text-gray-500 mt-1 leading-relaxed">{action.issue}</p>}
        </div>
        <ChevronDown className={`w-4 h-4 text-gray-600 shrink-0 mt-1 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="px-5 pb-5 pt-1 space-y-3 border-t border-gray-50">
          {action.business_risk && (
            <Field label="Why it matters" body={action.business_risk} />
          )}
          {action.recommended_action && (
            <Field label="What to do next" body={action.recommended_action} accent />
          )}
          {action.copyable_value && (
            <div>
              <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-1">DNS value to publish</p>
              <DnsValue value={action.copyable_value} />
            </div>
          )}
          {action.caution && (
            <div className="flex items-start gap-1.5 rounded-lg bg-transparent border border-[1.5px] border-brand-700 p-2.5">
              <p className="text-xs text-brand-700 leading-relaxed">{action.caution}</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Guided remediation — the ordered path from "no DMARC" to full enforcement ──
// Milestone states are derived from real scan/report signals only. Open
// remediation actions attach to the milestone where the customer fixes them;
// anything that doesn't fit the path renders in an "Also recommended" group.
const ACTION_TO_MILESTONE = {
  email_missing_dmarc:            'publish',
  email_missing_spf:              'align',
  email_dkim_not_detected:        'align',
  high_volume_alignment_failure:  'align',
  unknown_sender_detected:        'classify',
  sender_needs_classification:    'classify',
  email_dmarc_policy_none:        'quarantine',
  ready_for_quarantine_review:    'quarantine',
  ready_for_reject_review:        'reject',
}

function GuidedRemediation({ stage, hasReports, readiness, senders, actions, onGoto }) {
  const senderList   = Array.isArray(senders) ? senders : []
  const unknownCount = senderList.filter(s => (s.classification || 'unknown') === 'unknown').length
  const highVolFail  = senderList.filter(s => (s.total_messages || 0) >= 50 && (s.pass_rate ?? 100) < 90).length
  const enforcing    = ['partial_enforcement', 'full_enforcement'].includes(stage)

  const milestones = [
    {
      key: 'publish', title: 'Publish a DMARC record',
      hint: 'Tell receiving mail servers you have a policy for messages that fail authentication.',
      done: Boolean(stage) && stage !== 'missing', target: 'dmarc-setup', cta: 'Open DMARC setup',
    },
    {
      key: 'reports', title: 'Start receiving DMARC reports',
      hint: 'Reports reveal who is sending email using your domain — legitimate services and impersonators alike.',
      done: hasReports, target: 'connect-reporting', cta: 'Connect reporting',
    },
    {
      key: 'classify', title: 'Classify who sends email as you',
      hint: unknownCount > 0
        ? `${unknownCount} sender${unknownCount === 1 ? '' : 's'} still need${unknownCount === 1 ? 's' : ''} classification. Confirm which senders are yours before requesting stronger handling, because receivers retain final discretion.`
        : 'Confirm which senders are yours before requesting stronger handling, because receivers retain final discretion.',
      done: hasReports && senderList.length > 0 && unknownCount === 0, target: 'sender-inventory', cta: 'Review senders',
    },
    {
      key: 'align', title: 'Fix alignment failures',
      hint: highVolFail > 0
        ? `${highVolFail} high-volume sender${highVolFail === 1 ? ' is' : 's are'} failing alignment. Legitimate senders must pass SPF or DKIM before you tighten policy.`
        : 'Make sure legitimate senders pass SPF or DKIM alignment before tightening policy.',
      done: hasReports && highVolFail === 0 && (readiness?.ready_for_quarantine === true || enforcing),
      target: 'sender-inventory', cta: 'Review failing senders',
    },
    {
      key: 'quarantine', title: 'Consider requesting quarantine',
      hint: 'A quarantine policy asks receivers to quarantine messages that fail DMARC. Receiver handling is not proven by publication.',
      done: enforcing, target: 'dmarc-setup', cta: 'Open DMARC setup',
    },
    {
      key: 'reject', title: 'Consider requesting rejection',
      hint: 'A reject policy asks receivers to reject messages that fail DMARC. It does not prove every receiver applied that request.',
      done: stage === 'full_enforcement', target: 'dmarc-setup', cta: 'Open DMARC setup',
    },
  ]

  const currentIdx = milestones.findIndex(m => !m.done)
  const doneCount  = milestones.filter(m => m.done).length
  const openActions = Array.isArray(actions) ? actions : []
  const attached   = (key) => openActions.filter(a => ACTION_TO_MILESTONE[a.id] === key)
  const additional = openActions.filter(a => !ACTION_TO_MILESTONE[a.id])

  return (
    <section>
      <div className="section-head">
        <div>
          <span className="eyebrow">Guided remediation</span>
          <h2 className="section-title mt-1.5">
            Your path to email protection
            <span className="text-gray-400 font-semibold"> · {doneCount} of {milestones.length} steps complete</span>
          </h2>
        </div>
      </div>

      <div className="card overflow-hidden divide-y divide-gray-50">
        {milestones.map((m, i) => {
          const isCurrent = i === currentIdx
          const isDone    = m.done
          const stepActions = attached(m.key)
          return (
            <div key={m.key} className={isCurrent ? 'bg-brand-50/30' : ''}>
              <div className="flex items-start gap-3 px-5 py-3.5">
                <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                  isCurrent ? 'bg-brand-200 text-brand-900' : 'bg-gray-100 text-gray-400 border border-gray-200'
                }`}>{i + 1}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className={`text-sm font-bold ${isDone ? 'text-gray-400 line-through decoration-gray-300' : isCurrent ? 'text-gray-900' : 'text-gray-500'}`}>
                      {m.title}
                    </p>
                    {isCurrent && (
                      <span className="text-xs font-bold uppercase tracking-wide px-1.5 py-0.5 rounded-sm border bg-brand-50 text-brand-700 border-brand-100">
                        Start here
                      </span>
                    )}
                  </div>
                  {!isDone && (
                    <p className={`text-xs mt-0.5 leading-relaxed ${isCurrent ? 'text-gray-600' : 'text-gray-400'}`}>{m.hint}</p>
                  )}
                  {isCurrent && stepActions.length > 0 && (
                    <div className="mt-3 space-y-2">
                      {stepActions.map((a, j) => <ActionCard key={a.id || j} action={a} />)}
                    </div>
                  )}
                  {isCurrent && (
                    <button onClick={() => onGoto(m.target)} className="btn-primary text-xs mt-3">
                      {m.cta}
                    </button>
                  )}
                </div>
              </div>
            </div>
          )
        })}
      </div>

      {additional.length > 0 && (
        <div className="mt-4">
          <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Also recommended</p>
          <div className="space-y-3">
            {additional.map((a, i) => <ActionCard key={a.id || i} action={a} />)}
          </div>
        </div>
      )}
    </section>
  )
}

function Field({ label, body, accent }) {
  return (
    <div>
      <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-0.5">{label}</p>
      <p className={`text-sm leading-relaxed ${accent ? 'text-gray-900 font-medium' : 'text-gray-700'}`}>{body}</p>
    </div>
  )
}

// ── CyberMeters differentiator ────────────────────────────────────────────────
function DifferentiatorBlock({ wsId }) {
  return (
    <section className="card overflow-hidden">
      <div className="flex flex-col sm:flex-row">
        <div className="flex-1 p-6">
          <div className="mb-2">
            <span className="eyebrow">Email risk is part of your attack surface</span>
          </div>
          <h2 className="section-title mb-2">Impersonation risk doesn't stop at the inbox</h2>
          <p className="text-sm text-gray-600 leading-relaxed max-w-2xl">
            Email sender intelligence is part of your overall security posture. Weak authentication and
            unknown senders can increase impersonation risk — combined with exposed assets or a weak
            external posture, this raises the likelihood of phishing, invoice fraud, or supplier
            impersonation. CyberMeters connects DMARC sender intelligence and authentication remediation
            to your attack surface, SaaS exposure, business risk, and executive reporting. Vendor and
            third-party signals are supporting technical evidence here — not a separate questionnaire platform.
          </p>
          <div className="flex flex-wrap gap-2 mt-4">
            <Link to="/ws/business-risk" className="btn-secondary text-xs py-2">
              View Business Risk Score
            </Link>
            <Link to="/ws/scorecard" className="btn-secondary text-xs py-2">
              External posture
            </Link>
            <Link to="/ws/brand-monitoring" className="btn-secondary text-xs py-2">
              Brand &amp; impersonation
            </Link>
          </div>
        </div>
        <div className="sm:w-56 shrink-0 bg-brand-50/40 border-t sm:border-t-0 sm:border-l border-gray-100 p-6 flex flex-col justify-center gap-2">
          {[
            'DMARC sender intelligence',
            'Email authentication',
            'Exposed external assets',
            'Business Risk Score',
          ].map((t, i) => (
            <div key={t} className="flex items-center gap-2 text-xs font-medium text-gray-700">
              <span className="w-1.5 h-1.5 rounded-full bg-brand-500" />
              {t}
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

// ── Multi-domain summary ──────────────────────────────────────────────────────
const STAGE_LABEL = {
  missing: 'No DMARC',
  monitoring: 'No-action policy',
  partial_enforcement: 'Quarantine requested',
  full_enforcement: 'Rejection requested',
}

const BEC_DOT = { critical: 'text-red-700', high: 'text-red-700', medium: 'text-brand-700', low: 'text-brand-700', minimal: 'text-brand-700' }
function MultiDomainSummary({ rows, selectedDomain, onSelect }) {
  if (!rows || rows.length < 2) return null
  const cell = (ok) => ok === true ? <span className="text-xs font-semibold text-brand-700">Yes</span>
    : ok === false ? <span className="text-gray-600">—</span>
    : <span className="text-gray-600 text-xs">·</span>
  const compCell = (c) => c == null
    ? <span className="text-gray-600 text-xs">not measured</span>
    : <span className={`text-xs font-bold tabular-nums ${c >= 95 ? 'text-brand-700' : c >= 80 ? 'text-brand-700' : 'text-red-700'}`}>{c}%</span>
  const becCell = (b) => !b
    ? <span className="text-gray-600 text-xs">·</span>
    : <span className={`text-xs font-bold ${BEC_DOT[String(b).toLowerCase()] || 'text-gray-500'}`}>{titleCase(b)}</span>
  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <span className="eyebrow">Portfolio</span>
        <h2 className="section-title leading-tight">Email posture across {rows.length} domains</h2>
        <p className="text-xs text-gray-500 mt-0.5">Compliance is the share of mail passing DMARC alignment; business exposure translates it into impersonation risk. Click a row to focus that domain.</p>
      </div>
      <div className="overflow-x-auto">
        <table className="data-table w-full">
          <thead>
            <tr>
              <th className="text-left">Domain</th>
              <th className="text-left">DMARC stage</th>
              <th className="text-center">Compliance</th>
              <th className="text-left">Business exposure</th>
              <th className="text-center">SPF</th>
              <th className="text-center">DKIM</th>
              <th className="text-center">BIMI</th>
              <th className="text-center">Open</th>
              <th className="text-left">Last scan</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.domain} onClick={() => onSelect(r.domain)}
                className={`cursor-pointer transition-colors ${r.domain === selectedDomain ? 'bg-brand-50/50' : 'hover:bg-gray-50/60'}`}>
                <td><button type="button" onClick={(e) => { e.stopPropagation(); onSelect(r.domain) }} aria-pressed={r.domain === selectedDomain} className="font-semibold text-gray-800 text-sm text-left hover:underline">{r.domain}</button></td>
                <td><span className="text-xs font-semibold text-gray-700">{STAGE_LABEL[r.stage] || '—'}</span></td>
                <td className="text-center">{compCell(r.compliance)}</td>
                <td>{becCell(r.bec)}</td>
                <td className="text-center">{cell(r.spf)}</td>
                <td className="text-center">{cell(r.dkim)}</td>
                <td className="text-center">{cell(r.bimi)}</td>
                <td className="text-center"><span className={`text-xs font-bold ${r.openActions > 0 ? 'text-red-700' : 'text-gray-400'}`}>{r.openActions}</span></td>
                <td><span className="text-xs text-gray-400">{r.lastScan ? fmtDate(r.lastScan) : '—'}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function EmptyCard({ title, body, action }) {
  return (
    <div className="card p-10 text-center flex flex-col items-center">
      <p className="text-sm font-bold text-gray-800 mb-1">{title}</p>
      {body && <p className="text-sm text-gray-500 max-w-md leading-relaxed mb-4">{body}</p>}
      {action}
    </div>
  )
}

function fmtDate(str) {
  if (!str) return '—'
  const d = new Date(str.includes('T') ? str : str.replace(' ', 'T') + 'Z')
  if (Number.isNaN(d.getTime())) return '—'
  return formatReportDay(d)
}

const COMPLETED = new Set(['completed'])

// ════════════════════════════════════════════════════════════════════════════
// DMARC Sender Intelligence v1 — consumes the new workspace/domain endpoints:
//   GET  /dmarc-summary   GET /email-senders   POST /email-senders/:id/classify
//   POST /dmarc-reports/import
// All sections are additive and defensive.
// ════════════════════════════════════════════════════════════════════════════

const CLASSIFY = {
  trusted:    { label: 'Trusted',    pill: 'bg-brand-50 text-brand-700 border-brand-100' },
  suspicious: { label: 'Suspicious', pill: 'bg-transparent text-brand-700 border-[1.5px] border-brand-700' },
  threat:     { label: 'Threat',     pill: 'bg-red-50 text-red-700 border-red-100' },
  ignored:    { label: 'Ignored',    pill: 'bg-gray-100 text-gray-500 border-gray-200' },
  unknown:    { label: 'Unknown',    pill: 'bg-blue-50 text-blue-700 border-blue-100' },
}
const AUTO_CLASSIFY = {
  authorised:        { label: 'Authorised',        pill: 'bg-brand-50 text-brand-700 border-brand-100' },
  likely_authorised: { label: 'Likely authorised', pill: 'bg-blue-50 text-blue-700 border-blue-100' },
  forwarder:         { label: 'Forwarder',         pill: 'bg-indigo-50 text-indigo-700 border-indigo-100' },
  mailing_list:      { label: 'Mailing list',      pill: 'bg-purple-50 text-purple-700 border-purple-100' },
  misconfigured:     { label: 'Misconfigured',     pill: 'bg-transparent text-brand-700 border-[1.5px] border-brand-700' },
  unknown:           { label: 'Unknown',           pill: 'bg-gray-100 text-gray-500 border-gray-200' },
  suspicious:        { label: 'Suspicious',        pill: 'bg-red-50 text-red-700 border-red-100' },
  unauthorised:      { label: 'Unauthorised',      pill: 'bg-red-50 text-red-700 border-red-100' },
}
const RISK = {
  critical: 'bg-red-50 text-red-700 border-red-100',
  high:     'bg-red-50 text-red-700 border-red-100',
  medium:   'bg-transparent text-brand-700 border-[1.5px] border-brand-700',
  low:      'bg-gray-100 text-gray-500 border-gray-200',
}
const RISK_RANK = { critical: 0, high: 1, medium: 2, low: 3 }

// ── Policy-change readiness: no-action → quarantine review → reject review ─────
function EnforcementReadiness({ readiness }) {
  if (!readiness) return null
  const stages = [
    { key: 'monitoring', label: 'No-action policy' },
    { key: 'quarantine', label: 'Quarantine Review' },
    { key: 'reject',     label: 'Reject Review' },
  ]
  const currentIdx = readiness.ready_for_reject ? 2 : readiness.ready_for_quarantine ? 1 : 0
  const confPill = readiness.confidence === 'high' ? 'bg-brand-50 text-brand-700 border-brand-100'
    : readiness.confidence === 'medium' ? 'bg-transparent text-brand-700 border-[1.5px] border-brand-700'
    : 'bg-gray-100 text-gray-500 border-gray-200'
  const hasScore = typeof readiness.score === 'number'
  const statusPill = readiness.status === 'ready' ? 'bg-brand-200 text-brand-900 border-brand-200'
    : readiness.status === 'approaching' ? 'bg-transparent text-brand-700 border-[1.5px] border-brand-700'
    : 'bg-gray-100 text-gray-600 border-gray-200'
  const statusLabel = readiness.status === 'ready' ? 'Ready' : readiness.status === 'approaching' ? 'Approaching' : 'Not ready'
  const checkTone = (st) => st === 'pass' ? { dot: 'bg-brand-700', txt: 'text-gray-700' }
    : st === 'warn' ? { dot: 'bg-brand-700', txt: 'text-gray-700' }
    : { dot: 'bg-red-500', txt: 'text-gray-800' }
  return (
    <section className="card-md overflow-hidden">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <div className="flex-1">
          <span className="eyebrow">Policy-change readiness</span>
          <h2 className="section-title leading-tight">Is the evidence ready for a stronger policy request?</h2>
        </div>
        {hasScore && (
          <div className="flex flex-col items-end mr-1">
            <span className="text-2xl font-bold tabular-nums leading-none text-gray-900">{readiness.score}<span className="text-sm font-semibold text-gray-400">/100</span></span>
            <span className={`mt-1 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border ${statusPill}`}>{statusLabel}</span>
          </div>
        )}
        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold border ${confPill}`}>
          {readiness.confidence || 'low'} confidence
        </span>
      </div>
      <div className="px-6 pt-6 pb-2">
        <div className="flex items-center">
          {stages.map((s, i) => {
            const done = i < currentIdx, current = i === currentIdx
            return (
              <div key={s.key} className="flex items-center flex-1 last:flex-none">
                <div className="flex flex-col items-center">
                  <div className={`w-9 h-9 rounded-full flex items-center justify-center text-xs font-bold border-2 ${
                    current ? 'bg-brand-200 border-brand-200 text-brand-900 ring-4 ring-brand-100'
                    : done ? 'bg-brand-50 border-brand-300 text-brand-700'
                    : 'bg-white border-gray-200 text-gray-600'}`}>
                    {i + 1}
                  </div>
                  <span className={`mt-2 text-xs font-semibold whitespace-nowrap ${current ? 'text-brand-700' : done ? 'text-gray-600' : 'text-gray-400'}`}>{s.label}</span>
                </div>
                {i < stages.length - 1 && <div className={`h-0.5 flex-1 mx-2 mb-6 rounded-full ${i < currentIdx ? 'bg-brand-400' : 'bg-gray-200'}`} />}
              </div>
            )
          })}
        </div>
      </div>
      {readiness.checks?.length > 0 && (
        <div className="px-6 pt-4 pb-1">
          <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-2">Readiness checks</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-x-5 gap-y-2">
            {readiness.checks.map((c) => {
              const tone = checkTone(c.status)
              return (
                <div key={c.id} className="flex items-start gap-2" title={c.detail}>
                  <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${tone.dot}`} />
                  <div className="min-w-0">
                    <p className={`text-sm font-medium leading-tight ${tone.txt}`}>{c.label}</p>
                    <p className="text-xs text-gray-500 leading-snug">{c.detail}</p>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
      <div className="px-6 pb-6 pt-4">
        <div className="rounded-xl border border-[1.5px] border-brand-700 bg-transparent p-4">
          {readiness.explanation && <p className="text-sm text-gray-700 leading-relaxed mb-3">{readiness.explanation}</p>}
          {readiness.blockers?.length > 0 && (
            <div className="mb-3">
              <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-1.5">What blocks a stronger policy request</p>
              <ul className="space-y-1.5">
                {readiness.blockers.map((b, i) => (
                  <li key={i} className="flex items-start gap-1.5 text-sm text-gray-700">
                    {b}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {readiness.next_step && (
            <div>
              <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-0.5">Next recommended step</p>
              <p className="text-sm text-gray-900 font-medium leading-relaxed flex items-start gap-1.5">
                {readiness.next_step}
              </p>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

// ── Managed change review queue (Level 3) — analyst approval before enforcement ─
// Governance layer: a proposed policy change waits here for an analyst to
// approve (a different person than the requester) or reject with a reason,
// before it ever touches DNS.
function ChangeReviewQueue({ wsId }) {
  const dialog = useAppDialog()
  const [queue, setQueue]   = useState(null) // null=loading, []=empty
  const [failed, setFailed] = useState(false)
  const [busy, setBusy]     = useState(null) // change-request id being actioned
  const [err, setErr]       = useState(null)

  const load = useCallback(() => {
    if (!wsId) { setQueue([]); return }
    let cancelled = false
    setFailed(false)
    api.listDmarcChangeRequests(wsId, 'pending_review')
      .then(res => { if (!cancelled) setQueue(res?.queue || []) })
      .catch(() => { if (!cancelled) { setQueue([]); setFailed(true) } })
    return () => { cancelled = true }
  }, [wsId])
  useEffect(() => load(), [load])

  const act = async (id, to) => {
    let reason
    if (to === 'rejected') {
      reason = await dialog.prompt({
        title: 'Reject this change',
        label: 'Reason for rejecting',
        confirmLabel: 'Reject change',
        tone: 'danger',
        required: true,
      })
      if (!reason) return
    }
    setBusy(id); setErr(null)
    try {
      await api.transitionDmarcChangeRequest(wsId, id, { to, reason })
      load()
    } catch (e) {
      setErr(e?.message || 'Could not update the change request.')
    } finally { setBusy(null) }
  }

  if (queue === null) return null           // silent while loading — never a flash
  if (failed || queue.length === 0) return null  // no queue → don't clutter the page

  return (
    <section className="card-md overflow-hidden">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <div className="flex-1">
          <span className="eyebrow">Managed change review</span>
          <h2 className="section-title leading-tight">Policy changes awaiting approval</h2>
        </div>
        <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold border bg-transparent text-brand-700 border-[1.5px] border-brand-700">
          {queue.length} pending
        </span>
      </div>
      {err && (
        <div className="mx-6 mt-4 flex items-start gap-2 text-sm text-red-700 bg-red-50 border border-red-200 rounded-lg px-3.5 py-2.5">
          {err}
        </div>
      )}
      <ul className="divide-y divide-gray-100">
        {queue.map((c) => (
          <li key={c.id} className="px-6 py-4">
            <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mb-2">
              <span className="font-semibold text-gray-900">{c.domain}</span>
              <span className="inline-flex items-center gap-1.5 text-sm text-gray-600">
                <span className="font-medium">{c.from_policy || 'none'}</span>
                <span aria-hidden="true" className="text-gray-400">→</span>
                <span className="font-semibold text-gray-900">{c.to_policy}</span>
              </span>
              <span className="text-xs text-gray-400">
                requested by {c.requested_by || 'unknown'} · {pageTime(c.created_at)}
              </span>
            </div>
            {typeof c.evidence?.score === 'number' && (
              <p className="text-xs text-gray-500 mb-2">
                Readiness at proposal: <span className="font-semibold tabular-nums">{c.evidence.score}/100</span>
                {c.evidence.status ? ` (${c.evidence.status.replace('_', ' ')})` : ''}
              </p>
            )}
            <div className="flex items-center gap-2">
              <button onClick={() => act(c.id, 'approved')} disabled={busy === c.id}
                className="btn-primary text-sm inline-flex items-center gap-1.5 disabled:opacity-50">
                Approve
              </button>
              <button onClick={() => act(c.id, 'rejected')} disabled={busy === c.id}
                className="btn-secondary text-sm inline-flex items-center gap-1.5 disabled:opacity-50">
                Reject
              </button>
            </div>
          </li>
        ))}
      </ul>
      <p className="px-6 py-3 text-xs text-gray-400 border-t border-gray-100">
        Approving analyst must differ from the requester. Every decision is recorded in the audit log.
      </p>
      {dialog.element}
    </section>
  )
}

// ── DMARC summary panel ───────────────────────────────────────────────────────
function DmarcSummaryPanel({ summary }) {
  if (!summary) return null
  const t = summary.traffic || {}
  const s = summary.senders || {}
  const d = summary.disposition || {}
  const br = summary.business_risk || {}
  const dispTotal = Math.max(1, (d.none || 0) + (d.quarantine || 0) + (d.reject || 0))
  const brTone = br.level === 'high' ? 'bg-red-50 text-red-700 border-red-100'
    : br.level === 'medium' ? 'bg-transparent text-brand-700 border-[1.5px] border-brand-700'
    : 'bg-brand-50 text-brand-700 border-brand-100'
  const tile = (label, value, sub, tone) => (
    <div className="stat-tile">
      <span className="metric-label">{label}</span>
      {sub && <span className="metric-sub">{sub}</span>}
      <span className={`metric-value ${tone || ''}`}>{value}</span>
    </div>
  )
  return (
    <section className="space-y-4">
      <div className="section-head">
        <div>
          <span className="eyebrow">DMARC summary</span>
          <h2 className="section-title mt-1.5">Sender alignment over the last {summary.period_days || 30} days</h2>
        </div>
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {tile('Total messages', formatNumber(t.total_messages ?? 0), 'observed')}
        {tile('Aligned', formatNumber(t.aligned_messages ?? 0), 'passed SPF/DKIM', 'text-brand-700')}
        {tile('Failed', formatNumber(t.failed_messages ?? 0), 'failed alignment', (t.failed_messages ?? 0) > 0 ? 'text-red-700' : '')}
        {tile('Pass rate', `${t.pass_rate ?? 0}%`, 'aligned share')}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Sender mix */}
        <div className="card p-5">
          <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-3">Sender mix ({s.total ?? 0})</p>
          <div className="space-y-2">
            {[
              ['Trusted', s.trusted, 'bg-brand-500'],
              ['Unknown', s.unknown, 'bg-blue-400'],
              ['Suspicious', s.suspicious, 'bg-brand-700'],
              ['Threat', s.threat, 'bg-red-500'],
            ].map(([label, n, dot]) => (
              <div key={label} className="flex items-center justify-between">
                <span className="flex items-center gap-2 text-sm text-gray-600"><span className={`w-2 h-2 rounded-full ${dot}`} />{label}</span>
                <span className="text-sm font-bold text-gray-900">{n ?? 0}</span>
              </div>
            ))}
          </div>
        </div>
        {/* Disposition */}
        <div className="card p-5">
          <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-3">Disposition</p>
          <div className="flex h-2.5 rounded-full overflow-hidden mb-3 border border-gray-100">
            <div style={{ width: `${(d.none || 0) / dispTotal * 100}%` }} className="bg-gray-300" />
            <div style={{ width: `${(d.quarantine || 0) / dispTotal * 100}%` }} className="bg-brand-700" />
            <div style={{ width: `${(d.reject || 0) / dispTotal * 100}%` }} className="bg-red-500" />
          </div>
          <div className="space-y-1.5 text-sm">
            <div className="flex justify-between"><span className="flex items-center gap-2 text-gray-600"><span className="w-2 h-2 rounded-full bg-gray-300" />None</span><span className="font-semibold">{formatNumber(d.none ?? 0)}</span></div>
            <div className="flex justify-between"><span className="flex items-center gap-2 text-gray-600"><span className="w-2 h-2 rounded-full bg-brand-700" />Quarantine</span><span className="font-semibold">{formatNumber(d.quarantine ?? 0)}</span></div>
            <div className="flex justify-between"><span className="flex items-center gap-2 text-gray-600"><span className="w-2 h-2 rounded-full bg-red-500" />Reject</span><span className="font-semibold">{formatNumber(d.reject ?? 0)}</span></div>
          </div>
        </div>
        {/* Business risk */}
        <div className="card p-5 flex flex-col">
          <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-3">Business risk</p>
          <span className={`self-start inline-flex items-center px-3 py-1 rounded-full text-xs font-bold border capitalize ${brTone}`}>{br.level || 'low'}</span>
          {br.summary && <p className="text-sm text-gray-600 leading-relaxed mt-3">{br.summary}</p>}
        </div>
      </div>
    </section>
  )
}

// ── Sender row (expandable, with classification) ──────────────────────────────
function SenderRow({ sender, onClassify, classifying }) {
  const [open, setOpen] = useState(false)
  const [notes, setNotes] = useState(sender.notes || '')
  const cls = CLASSIFY[sender.classification] || CLASSIFY.unknown
  const autoCls = AUTO_CLASSIFY[sender.auto_classification] || AUTO_CLASSIFY.unknown
  const riskCls = RISK[sender.risk_level] || RISK.low
  const confidencePct = typeof sender.auto_confidence === 'number' ? Math.round(sender.auto_confidence * 100) : null
  return (
    <>
      <tr onClick={() => setOpen(o => !o)} className="cursor-pointer hover:bg-gray-50/60 transition-colors">
        <td><button type="button" onClick={(e) => { e.stopPropagation(); setOpen(o => !o) }} aria-expanded={open} className="mono text-xs font-semibold text-gray-800 text-left hover:underline">{sender.source_ip}</button></td>
        <td>
          <span className="text-sm text-gray-700 capitalize">{sender.provider_guess || 'unknown'}</span>
          {sender.provider_confidence && <span className="block text-xs text-gray-400">{sender.provider_confidence} confidence</span>}
        </td>
        <td className="text-right"><span className="text-sm font-semibold text-gray-900">{formatNumber(sender.total_messages ?? 0)}</span></td>
        <td className="text-right"><span className={`text-sm font-semibold ${(sender.pass_rate ?? 0) < 90 ? 'text-red-700' : 'text-gray-900'}`}>{sender.pass_rate ?? 0}%</span></td>
        <td className="text-right"><span className={`text-sm ${(sender.failed_messages ?? 0) > 0 ? 'text-red-700 font-semibold' : 'text-gray-400'}`}>{formatNumber(sender.failed_messages ?? 0)}</span></td>
        <td><span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide border capitalize ${riskCls}`}>{sender.risk_level || 'low'}</span></td>
        <td><span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${cls.pill}`}>{cls.label}</span></td>
        <td className="text-right"><ChevronDown className={`w-4 h-4 text-gray-600 inline transition-transform ${open ? 'rotate-180' : ''}`} /></td>
      </tr>
      {open && (
        <tr className="bg-gray-50/40">
          <td colSpan={8} className="px-5 py-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-1">Recommended action</p>
                <p className="text-sm text-gray-700 leading-relaxed">{sender.recommended_action || 'Classify this sender if it is a legitimate business email source.'}</p>
                <p className="text-xs text-gray-400 mt-2">First seen {fmtDate(sender.first_seen)} · Last seen {fmtDate(sender.last_seen)}</p>
                {sender.provider_reason && <p className="text-xs text-gray-400 mt-1">{sender.provider_reason}</p>}
                <div className="mt-3 rounded-lg border border-gray-200 bg-white p-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${autoCls.pill}`}>{autoCls.label}</span>
                    <span className="text-xs text-gray-500">
                      {sender.classification_source === 'manual' ? 'Manual decision active' : 'Automated evidence'}
                      {confidencePct != null ? ` · ${confidencePct}% confidence` : ''}
                    </span>
                  </div>
                  <div className="mt-2 grid grid-cols-2 gap-2 text-xs text-gray-600">
                    <div className="rounded-md bg-gray-50 border border-gray-100 p-2">
                      <span className="font-semibold text-gray-700">SPF aligned</span>
                      <span className="block tabular-nums">{sender.spf_aligned_rate ?? 0}% · {formatNumber(sender.spf_aligned_messages ?? 0)} msg</span>
                    </div>
                    <div className="rounded-md bg-gray-50 border border-gray-100 p-2">
                      <span className="font-semibold text-gray-700">DKIM aligned</span>
                      <span className="block tabular-nums">{sender.dkim_aligned_rate ?? 0}% · {formatNumber(sender.dkim_aligned_messages ?? 0)} msg</span>
                    </div>
                  </div>
                  {sender.auto_reasons?.length > 0 && (
                    <ul className="mt-2 space-y-1 text-xs text-gray-500 list-disc pl-4">
                      {sender.auto_reasons.map((reason, idx) => <li key={idx}>{reason}</li>)}
                    </ul>
                  )}
                </div>
              </div>
              <div>
                <p className="text-xs font-bold uppercase tracking-wide text-gray-500 mb-1">Classify this sender</p>
                <textarea
                  value={notes}
                  onChange={e => setNotes(e.target.value)}
                  placeholder="Optional note (e.g. ‘Microsoft 365 outbound mail’)"
                  rows={2}
                  className="input text-xs mb-2"
                  onClick={e => e.stopPropagation()}
                />
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(CLASSIFY).map(([key, c]) => (
                    <button
                      key={key}
                      disabled={classifying}
                      onClick={(e) => { e.stopPropagation(); onClassify(sender.id, key, notes) }}
                      className={`px-2.5 py-1 rounded-lg text-xs font-semibold border transition-colors disabled:opacity-50 ${
                        sender.classification === key ? c.pill : 'bg-white text-gray-600 border-gray-200 hover:bg-gray-50'}`}
                    >
                      {c.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

const SENDER_FILTERS = ['All', 'Unknown', 'Trusted', 'Suspicious', 'Threat', 'Ignored', 'Failing']

// ── Email Protection change history (migration 088) ──────────────────────────
// The read surface 088 never had. Its events were read only by the alert pipeline, and
// the lifecycle columns it added to email_sender_sources are stripped before they leave
// the API — so a customer alerted that their hosted DMARC record had disconnected could
// not see when it began, how often it had happened, or whether it had reconnected.
//
// The event vocabulary is server-owned and shown as-is. A customer's own classification
// appears as a customer action, never as something CyberMeters observed.
const EMAIL_EVENT_LABEL = {
  monitoring_changed:            'Condition changed',
  hosted_record_reconnected:     'Hosted record reconnected',
  hosted_policy_changed:         'Hosted policy changed',
  hosted_rolled_back_manual:     'Rolled back by you',
  sender_failures_recovered:     'Sender failures recovered',
  sender_manual_classification:  'Classified by you',
  baseline_established:          'Pre-existing at activation',
}
const EMAIL_RECORD_TYPE_LABEL = {
  hosted_dns_entry:    'Hosted record',
  email_sender_source: 'Sender',
}

function EmailLifecycleHistory({ data, error }) {
  const items = data?.items || []
  return (
    <div className="card p-5">
      <h2 className="text-base font-bold text-gray-900">What changed, and when</h2>
      <p className="mt-1 text-sm leading-relaxed text-gray-500">
        The record behind your email alerts: when a condition began, recovered, or came back.
      </p>

      {error && <p className="mt-3 text-sm text-red-700">{error}</p>}
      {!data && !error && <p className="mt-3 text-sm text-gray-400">Loading…</p>}
      {data && items.length === 0 && (
        <p className="mt-3 text-sm text-gray-500">
          No changes recorded yet. Entries appear here when a hosted record or sender condition changes.
        </p>
      )}

      {items.length > 0 && (
        <ul className="mt-4 divide-y divide-gray-100">
          {items.map((e) => (
            <li key={e.id} className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2">
              <span className="font-mono text-xs text-gray-400">{e.created_at?.slice(0, 16).replace('T', ' ')}</span>
              <span className="text-sm text-gray-800">{EMAIL_EVENT_LABEL[e.event_type] || String(e.event_type).replace(/_/g, ' ')}</span>
              {e.recurrence_type && (
                <span className="rounded-full border border-[1.5px] border-brand-700 bg-transparent px-2 py-0.5 text-xs text-brand-700">
                  {String(e.recurrence_type).replace(/_/g, ' ')}
                </span>
              )}
              <span className="text-xs text-gray-500">
                {EMAIL_RECORD_TYPE_LABEL[e.record_type] || e.record_type}{e.entity ? ` · ${e.entity}` : ''}
              </span>
              {/* The customer's own action is labelled as theirs, never as an observation. */}
              {e.actor_type === 'customer' && (
                <span className="rounded-full border border-gray-200 bg-gray-100 px-2 py-0.5 text-xs text-gray-600">your action</span>
              )}
            </li>
          ))}
        </ul>
      )}

      {data?.pagination?.total > items.length && (
        <p className="mt-3 text-xs text-gray-400">
          Showing the {items.length} most recent of {data.pagination.total} recorded changes.
        </p>
      )}
      {data?.scope_note && (
        <p className="mt-4 rounded-sm border border-gray-200 bg-gray-50 px-3 py-2 text-xs leading-relaxed text-gray-600">{data.scope_note}</p>
      )}
    </div>
  )
}

function SenderInventory({ data, onClassify, classifyingId, loading }) {
  const [filter, setFilter] = useState('All')
  const senders = data?.senders || []
  const sorted = useMemo(() => {
    const arr = [...senders]
    arr.sort((a, b) =>
      (RISK_RANK[a.risk_level] ?? 9) - (RISK_RANK[b.risk_level] ?? 9) ||
      (b.failed_messages ?? 0) - (a.failed_messages ?? 0) ||
      (b.total_messages ?? 0) - (a.total_messages ?? 0))
    return arr
  }, [senders])
  const filtered = sorted.filter(s => {
    if (filter === 'All') return true
    if (filter === 'Failing') return (s.pass_rate ?? 100) < 90 || (s.failed_messages ?? 0) > 0
    return (s.classification || 'unknown') === filter.toLowerCase()
  })
  return (
    <section className="space-y-4">
      <div className="section-head">
        <div>
          <span className="eyebrow">Sender inventory</span>
          <h2 className="section-title mt-1.5">Who is sending email using this domain {senders.length > 0 && <span className="text-gray-400 font-semibold">· {senders.length}</span>}</h2>
        </div>
      </div>
      {senders.length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap">
          {SENDER_FILTERS.map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors ${
                filter === f ? 'bg-brand-200 text-brand-900' : 'bg-white text-gray-600 border border-gray-200 hover:bg-gray-50'}`}>
              {f}
            </button>
          ))}
        </div>
      )}
      {!data ? (
        <EmptyCard title="Sender list unavailable" body="The sender inventory could not be loaded for this domain. Try refreshing." />
      ) : senders.length === 0 ? (
        <EmptyCard title="No senders observed yet"
          body="Import a DMARC aggregate report below to start building your sending-source inventory." />
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="data-table w-full">
              <thead>
                <tr>
                  <th className="text-left">Source IP</th>
                  <th className="text-left">Provider</th>
                  <th className="text-right">Messages</th>
                  <th className="text-right">Pass rate</th>
                  <th className="text-right">Failed</th>
                  <th className="text-left">Risk</th>
                  <th className="text-left">Classification</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(s => (
                  <SenderRow key={s.id} sender={s} onClassify={onClassify} classifying={classifyingId === s.id} />
                ))}
                {filtered.length === 0 && (
                  <tr><td colSpan={8} className="text-center text-sm text-gray-400 py-6">No senders match this filter.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </section>
  )
}

// ── Instant sender validation ─────────────────────────────────────────────────
// Paste an email's headers and get an immediate SPF/DKIM/DMARC-alignment verdict
// for this domain — no waiting for DMARC aggregate reports (or forwarding to an
// inbox, as point-tools require). Headers are parsed server-side and discarded.
const VS_TONE = {
  authenticated_aligned: { label: 'Authenticated & aligned', cls: 'bg-brand-50 border-brand-200 text-brand-800' },
  passes_not_aligned:    { label: 'Passes, but not aligned', cls: 'bg-transparent border-[1.5px] border-brand-700 text-brand-700' },
  fails:                 { label: 'Fails authentication',     cls: 'bg-red-50 border-red-200 text-red-800' },
  unparseable:           { label: 'Could not read headers',   cls: 'bg-gray-50 border-gray-200 text-gray-600' },
}
function InstantSourceValidator({ wsId, domain }) {
  const [headers, setHeaders] = useState('')
  const [result, setResult]   = useState(null)
  const [busy, setBusy]       = useState(false)
  const [err, setErr]         = useState(null)

  async function validate() {
    if (!headers.trim() || busy) return
    setBusy(true); setErr(null); setResult(null)
    try {
      setResult(await api.validateEmailSource(wsId, domain, headers))
    } catch (e) {
      setErr(e?.message || 'Could not validate the pasted headers.')
    } finally {
      setBusy(false)
    }
  }
  const chip = (label, val) => val ? (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-xs font-semibold bg-white border border-gray-200 text-gray-700">
      <span className="text-gray-400">{label}</span> {val}
    </span>
  ) : null
  const tone = result ? (VS_TONE[result.verdict] || VS_TONE.unparseable) : null

  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <span className="eyebrow">Instant check</span>
        <h2 className="section-title leading-tight">Validate a sender now — no waiting for reports</h2>
        <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">
          Paste an email's raw headers and get an immediate SPF/DKIM/DMARC-alignment verdict for {domain}.
          Handy before you enforce, or to check a suspicious message. Headers are parsed and discarded, never stored.
        </p>
      </div>
      <div className="p-6 space-y-3">
        <textarea
          value={headers}
          onChange={e => setHeaders(e.target.value)}
          rows={5}
          placeholder="Paste full email headers here (Gmail: ⋮ → Show original · Outlook: File → Properties → Internet headers)"
          className="w-full text-xs font-mono border border-gray-200 rounded-lg px-3 py-2 focus:outline-hidden focus:border-brand-400 resize-y"
        />
        <div className="flex items-center gap-3">
          <button onClick={validate} disabled={busy || !headers.trim()} className="btn-primary text-sm disabled:opacity-50">
            {busy && <RefreshCw className="w-4 h-4 animate-spin" />}
            {busy ? 'Checking…' : 'Validate sender'}
          </button>
          {headers && !busy && (
            <button onClick={() => { setHeaders(''); setResult(null); setErr(null) }} className="text-xs font-semibold text-gray-400 hover:text-gray-600">Clear</button>
          )}
        </div>
        {err && <p className="text-sm text-red-700">{err}</p>}
        {result && tone && (
          <div className={`rounded-xl border p-4 ${tone.cls}`}>
            <p className="text-sm font-bold">{tone.label}</p>
            <p className="text-xs mt-1.5 leading-relaxed">{result.message}</p>
            {(result.spf || result.dkim || result.dmarc || result.source_ip || result.dkim_domain) && (
              <div className="flex flex-wrap gap-1.5 mt-3">
                {chip('SPF', result.spf && result.spf.toUpperCase())}
                {chip('DKIM', result.dkim && result.dkim.toUpperCase())}
                {chip('DMARC', result.dmarc && result.dmarc.toUpperCase())}
                {chip('From', result.from_domain)}
                {chip('DKIM domain', result.dkim_domain)}
                {chip('Selector', result.dkim_selector)}
                {chip('Source IP', result.source_ip)}
              </div>
            )}
          </div>
        )}
      </div>
    </section>
  )
}

// ── Manual DMARC XML import ───────────────────────────────────────────────────
function ImportDmarcReport({ onImport, importing, result, error }) {
  const [filename, setFilename] = useState('')
  const [xml, setXml] = useState('')
  function submit() {
    if (!xml.trim() || importing) return
    onImport({ filename: filename.trim() || undefined, xml })
    setXml('') // never retain raw XML after submit
  }
  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70 flex items-center gap-2.5">
        <div>
          <span className="eyebrow">Feed the engine</span>
          <h2 className="section-title leading-tight">Import a DMARC report</h2>
        </div>
      </div>
      <div className="p-6 space-y-3">
        <p className="text-sm text-gray-500 leading-relaxed">
          Paste the XML from a DMARC aggregate (RUA) report. CyberMeters extracts the sending sources and
          alignment results, then updates your inventory. The raw report is never stored or shown back.
        </p>
        <input
          value={filename}
          onChange={e => setFilename(e.target.value)}
          placeholder="Filename (optional)"
          className="input text-sm"
        />
        <textarea
          value={xml}
          onChange={e => setXml(e.target.value)}
          placeholder="<feedback> … </feedback>"
          rows={6}
          className="input text-xs mono"
        />
        <div className="flex items-center gap-3">
          <button onClick={submit} disabled={!xml.trim() || importing} className="btn-primary disabled:opacity-50">
            {importing ? <><RefreshCw className="w-4 h-4 animate-spin" /> Importing…</> : 'Import report'}
          </button>
          {error && <span className="text-sm text-red-700">{error}</span>}
        </div>
        {result && (
          <div className={`rounded-xl border p-4 ${result.imported ? 'border-brand-100 bg-brand-50/50' : result.duplicate ? 'border-[1.5px] border-brand-700 bg-transparent' : 'border-gray-200 bg-gray-50'}`}>
            {result.duplicate ? (
              <p className="text-sm text-brand-700">This report was already imported and was not counted again.</p>
            ) : result.imported ? (
              <div className="flex items-start gap-2">
                <p className="text-sm text-gray-700">
                  Imported <b>{result.records_imported}</b> record(s) · <b>{formatNumber(result.messages_imported ?? 0)}</b> message(s) ·
                  <b> {result.sources_updated}</b> sending source(s) updated.
                </p>
              </div>
            ) : (
              <p className="text-sm text-gray-600">{result.message || 'The report could not be imported.'}</p>
            )}
          </div>
        )}
      </div>
    </section>
  )
}

// ── Connect DMARC reporting (Assisted RUA Ingestion v1 + signed upload) ───────
// Mode A (recommended): a unique inbound rua=mailto address — reports arrive by
// email automatically. Mode B (advanced): a token-authenticated signed upload
// key for scripts/MSP automation. The raw token is shown exactly once; only its
// hash is stored. The inbound address is opaque and reveals no tenancy.
// (Reuses the shared CopyButton defined near the top of this file.)
// ── DMARC report history — every aggregate report received for this domain ────
function fmtUnixDay(sec) {
  if (!sec) return '—'
  try {
    return formatReportDay(new Date(sec * 1000))
  } catch { return '—' }
}

function DmarcReportHistory({ wsId, domain }) {
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(true)
  const [failed, setFailed]   = useState(false)
  const [showAll, setShowAll] = useState(false)

  useEffect(() => {
    if (!wsId || !domain) { setData(null); setLoading(false); return }
    let cancelled = false
    setLoading(true); setFailed(false); setShowAll(false)
    api.getDmarcReportHistory(wsId, domain)
      .then(res => { if (!cancelled) setData(res || null) })
      .catch(() => { if (!cancelled) { setData(null); setFailed(true) } })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [wsId, domain])

  const reports = data?.reports || []
  const totals  = data?.totals
  const visible = showAll ? reports : reports.slice(0, 10)
  const passCls = (p) => p == null ? 'text-gray-400' : p >= 95 ? 'text-brand-700' : p >= 80 ? 'text-brand-700' : 'text-red-700'

  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <span className="eyebrow">DMARC reports</span>
        <h2 className="section-title leading-tight">Report history</h2>
        <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">
          Every aggregate report received for this domain — who reported it, the period it covers, and how much mail aligned.
        </p>
      </div>

      {loading ? (
        <div className="p-6 flex items-center gap-2 text-sm text-gray-500">
          <RefreshCw className="w-4 h-4 animate-spin" /> Loading report history…
        </div>
      ) : failed ? (
        <p className="p-6 text-sm text-gray-500">Report history could not be loaded right now. Try again later.</p>
      ) : reports.length === 0 ? (
        <div className="p-6">
          <p className="text-sm font-semibold text-gray-800">Waiting for first report</p>
          <p className="text-xs text-gray-500 mt-1 leading-relaxed">
            Once DMARC reporting is connected, each aggregate report that arrives for this domain will appear here.
          </p>
        </div>
      ) : (
        <div>
          {totals && (
            <p className="px-6 pt-4 text-xs text-gray-500">
              <span className="font-bold text-gray-800 tabular-nums">{totals.reports}</span> report{totals.reports === 1 ? '' : 's'} from{' '}
              <span className="font-bold text-gray-800 tabular-nums">{totals.reporters}</span> reporter{totals.reporters === 1 ? '' : 's'} covering{' '}
              <span className="font-bold text-gray-800 tabular-nums">{formatNumber(totals.total_messages || 0)}</span> messages
              {totals.first_seen ? <> since <span className="font-semibold text-gray-700">{fmtUnixDay(totals.first_seen)}</span></> : null}
            </p>
          )}
          <div className="overflow-x-auto p-6 pt-3">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs font-semibold text-gray-500 uppercase tracking-wide border-b border-gray-100">
                  <th className="py-2 pr-4">Reporter</th>
                  <th className="py-2 pr-4">Period covered</th>
                  <th className="py-2 pr-4 text-right">Messages</th>
                  <th className="py-2 pr-4 text-right">Aligned</th>
                  <th className="py-2">Policy applied</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((r) => (
                  <tr key={r.id} className="border-b border-gray-50 last:border-0">
                    <td className="py-2.5 pr-4 font-semibold text-gray-800">{r.reporter}</td>
                    <td className="py-2.5 pr-4 text-xs text-gray-600 whitespace-nowrap">
                      {fmtUnixDay(r.date_range_begin)}{r.date_range_end && r.date_range_end !== r.date_range_begin ? ` – ${fmtUnixDay(r.date_range_end)}` : ''}
                    </td>
                    <td className="py-2.5 pr-4 text-right tabular-nums text-gray-800">{formatNumber(r.message_count || 0)}</td>
                    <td className={`py-2.5 pr-4 text-right tabular-nums font-bold ${passCls(r.pass_rate)}`}>
                      {r.pass_rate == null ? '—' : `${r.pass_rate}%`}
                    </td>
                    <td className="py-2.5 text-xs text-gray-600">{r.policy_applied ? `p=${r.policy_applied}` : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {reports.length > 10 && (
              <button onClick={() => setShowAll(v => !v)}
                className="mt-3 text-xs font-semibold text-brand-700 hover:text-brand-800">
                {showAll ? 'Show fewer' : `Show all ${reports.length} reports`}
              </button>
            )}
          </div>
        </div>
      )}
    </section>
  )
}

function ConnectDmarcReporting({ wsId, domain, dmarcDetail }) {
  const dialog = useAppDialog()
  const [endpoint, setEndpoint] = useState(null)
  const [rawToken, setRawToken] = useState(null) // shown once after create/rotate
  const [loading, setLoading]   = useState(true)
  const [busy, setBusy]         = useState(false)
  const [err, setErr]           = useState(null)
  const [showAdvanced, setShowAdvanced] = useState(false)

  const load = useCallback(async () => {
    if (!domain) return
    setLoading(true); setErr(null)
    try {
      const res = await api.getDmarcIngestEndpoint(wsId, domain)
      setEndpoint(res?.endpoint || null)
    } catch (e) { setErr(e.message || 'Could not load DMARC reporting settings.') }
    finally { setLoading(false) }
  }, [wsId, domain])

  useEffect(() => { setRawToken(null); setShowAdvanced(false); load() }, [load])

  async function run(fn, confirmOptions) {
    if (confirmOptions && !(await dialog.confirm(confirmOptions))) return
    setBusy(true); setErr(null)
    try {
      const res = await fn()
      setEndpoint(res?.endpoint || null)
      setRawToken(res?.endpoint?.token || null)
      return res
    } catch (e) { setErr(e.message || 'The request failed.') }
    finally { setBusy(false) }
  }

  const hasActive = endpoint && endpoint.status === 'active'
  const inboundAddress = endpoint?.inbound_address || null
  const ruaValue = endpoint?.rua_mailto || (inboundAddress ? `rua=mailto:${inboundAddress}` : null)
  const lastInbound = endpoint?.last_inbound_at
  const fmt = pageTime
  // DNS-verified = the live DMARC record (from the latest scan) lists our address.
  // "Connected" requires BOTH this AND a received report — same rule as the top
  // overview, so the two panels never contradict each other.
  const _inboundMailto = inboundAddress ? `mailto:${inboundAddress}`.toLowerCase() : null
  const _ruaList = (Array.isArray(dmarcDetail?.rua) ? dmarcDetail.rua : [])
    .map(r => (String(r).startsWith('mailto:') ? String(r) : `mailto:${r}`).toLowerCase())
  const dnsVerified = _inboundMailto ? _ruaList.includes(_inboundMailto) : false
  const reportsReceived = Boolean(lastInbound)
  const fullyConnected = dnsVerified && reportsReceived
  // The fallback stands in for BASE, so it carries BASE's trailing /api — the route
  // is /api/dmarc-ingest. Without it the customer copies a curl that 404s.
  const curl = `curl -X POST ${BASE || 'https://api.cybermeters.com/api'}/dmarc-ingest \\
  -H "Authorization: Bearer <your-upload-token>" \\
  -H "Content-Type: application/xml" \\
  --data-binary @report.xml`

  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70 flex items-center gap-2.5">
        <div>
          <span className="eyebrow">Automate ingestion</span>
          <h2 className="section-title leading-tight">Connect DMARC reporting</h2>
        </div>
      </div>
      <div className="p-6 space-y-4">
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-gray-500"><RefreshCw className="w-4 h-4 animate-spin" /> Loading…</div>
        ) : !hasActive ? (
          <>
            <p className="text-sm text-gray-500 leading-relaxed">
              Activate automatic DMARC reporting for <b>{domain}</b>. You’ll get a unique inbound address to add to
              your DMARC record — aggregate reports then flow in and update sender intelligence without manual paste.
            </p>
            <button onClick={() => run(() => api.createDmarcIngestEndpoint(wsId, domain))} disabled={busy} className="btn-primary disabled:opacity-50">
              {busy ? <><RefreshCw className="w-4 h-4 animate-spin" /> Working…</> : 'Activate DMARC reporting'}
            </button>
          </>
        ) : (
          <>
            {/* Mode A — Inbound RUA (recommended) */}
            <div className="rounded-xl border border-brand-100 bg-brand-50/40 p-4 space-y-3">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-brand-200 text-brand-900 text-xs font-semibold">Recommended</span>
                <h3 className="text-sm font-semibold text-gray-800">Inbound RUA address</h3>
                <span className={`ml-auto inline-flex items-center gap-1.5 text-xs font-medium ${
                  fullyConnected ? 'text-brand-700' : reportsReceived ? 'text-brand-700' : 'text-gray-500'
                }`}>
                  {fullyConnected
                    ? 'Connected'
                    : reportsReceived
                      ? 'Receiving reports · DNS update required'
                      : 'Not receiving yet'}
                </span>
              </div>
              <p className="text-sm text-gray-600 leading-relaxed">Add this value to your DMARC record:</p>
              <div className="flex items-center gap-2">
                <code className="mono text-xs flex-1 break-all bg-white border border-gray-200 rounded-lg px-3 py-2">{ruaValue || '—'}</code>
                {ruaValue && <CopyButton value={ruaValue} label="Copy" />}
              </div>
              {reportsReceived && !dnsVerified && (
                <div className="rounded-lg border border-[1.5px] border-brand-700 bg-transparent p-2.5 text-xs text-brand-700 flex items-start gap-1.5">
                  Reports are arriving, but your DMARC record does not yet include the CyberMeters reporting address. Add the value above to finish setup.
                </div>
              )}
              <p className="text-xs text-gray-500">
                CyberMeters receives aggregate DMARC reports for this domain and updates sender intelligence automatically.
                {reportsReceived ? null : ' We have not received a report at this address yet — providers usually send the first report within 24 hours of a DNS change.'}
              </p>
              <dl className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 text-xs">
                <div className="rounded-lg bg-white border border-gray-200 px-3 py-2">
                  <dt className="text-gray-400 uppercase tracking-wide font-semibold text-xs">Last received</dt>
                  <dd className="text-gray-700 font-medium mt-0.5">{fmt(lastInbound) || 'Not yet'}</dd>
                </div>
                <div className="rounded-lg bg-white border border-gray-200 px-3 py-2">
                  <dt className="text-gray-400 uppercase tracking-wide font-semibold text-xs">Last upload</dt>
                  <dd className="text-gray-700 font-medium mt-0.5">{fmt(endpoint.last_signed_upload_at) || 'Never'}</dd>
                </div>
                <div className="rounded-lg bg-white border border-gray-200 px-3 py-2">
                  <dt className="text-gray-400 uppercase tracking-wide font-semibold text-xs">Last used</dt>
                  <dd className="text-gray-700 font-medium mt-0.5">{fmt(endpoint.last_used_at) || 'Never'}</dd>
                </div>
              </dl>
            </div>

            {/* Mode B — Signed upload (advanced) */}
            <div className="rounded-xl border border-gray-200 bg-gray-50 p-4 space-y-3">
              <button onClick={() => setShowAdvanced(v => !v)} className="w-full flex items-center gap-2 text-left">
                <h3 className="text-sm font-semibold text-gray-800">Signed upload key</h3>
                <span className="text-xs text-gray-400">Advanced · scripts &amp; MSP automation</span>
                <ChevronDown className={`w-4 h-4 text-gray-400 ml-auto transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
              </button>
              {showAdvanced && (
                <div className="space-y-3 pt-1">
                  <p className="text-xs text-gray-500 leading-relaxed">
                    Inbound RUA is the recommended setup. A signed upload key is useful for scripts or MSP automation that
                    POST report XML directly. Last upload: <b className="text-gray-700">{endpoint.last_signed_upload_at ? pageTime(endpoint.last_signed_upload_at) : 'never'}</b>.
                  </p>
                  {rawToken && (
                    <div className="rounded-lg border border-[1.5px] border-brand-700 bg-transparent p-3 space-y-2">
                      <p className="text-sm text-brand-700">Copy this token now — it is shown only once and cannot be retrieved later.</p>
                      <div className="flex items-center gap-2">
                        <code className="mono text-xs flex-1 break-all bg-white border border-[1.5px] border-brand-700 rounded-lg px-3 py-2">{rawToken}</code>
                        <CopyButton value={rawToken} label="Copy" />
                      </div>
                    </div>
                  )}
                  <div className="flex items-center gap-3">
                    <button onClick={() => run(() => api.rotateDmarcIngestEndpoint(wsId, domain), { title: 'Rotate the upload key?', message: 'The current token stops working immediately.', confirmLabel: 'Rotate key', tone: 'danger' })} disabled={busy} className="btn-secondary text-sm disabled:opacity-50">
                      {rawToken ? 'Rotate again' : 'Generate token'}
                    </button>
                    <button onClick={() => run(() => api.revokeDmarcIngestEndpoint(wsId, domain), { title: 'Revoke this endpoint?', message: 'Inbound email and signed uploads will be rejected.', confirmLabel: 'Revoke endpoint', tone: 'danger' })} disabled={busy} className="text-sm text-red-700 hover:text-red-800 font-medium inline-flex items-center gap-1.5 disabled:opacity-50">
                      Revoke
                    </button>
                  </div>
                  <div className="space-y-1.5">
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Example upload</p>
                    <pre className="mono text-xs bg-gray-900 text-white/80 rounded-xl p-4 overflow-x-auto whitespace-pre">{curl}</pre>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
        {err && <span className="text-sm text-red-700">{err}</span>}
      </div>
      {dialog.element}
    </section>
  )
}

// ── DMARC Setup Wizard (public-beta guided DNS setup) ─────────────────────────
// Helps a non-technical customer connect DMARC reporting: pick DNS provider →
// copy the DNS record → verify → wait → Connected. Customer-safe copy only; the
// customer edits their own DNS here; CyberMeters changes DNS only after an explicit
// confirmation (hosted records, a connected DNS provider). Never suggests
// enforcement (p=quarantine/p=reject) — default stays p=none.
const DNS_PROVIDERS = [
  { id: 'cloudflare',  label: 'Cloudflare',                 copy: 'Open your Cloudflare dashboard, select the domain, go to DNS Records, and add or edit the TXT record named _dmarc.' },
  { id: 'godaddy',     label: 'GoDaddy',                    copy: 'Open your GoDaddy domain DNS settings and add or edit the TXT record named _dmarc.' },
  { id: 'namecheap',   label: 'Namecheap',                  copy: 'Open Advanced DNS for your domain and add or edit a TXT record with host _dmarc.' },
  { id: '123reg',      label: '123-reg',                    copy: 'Open DNS Management and add or edit a TXT record for _dmarc.' },
  { id: 'wix',         label: 'Wix',                        copy: 'Open domain DNS settings and add or edit the TXT record for _dmarc. DNS changes may take longer to appear.' },
  { id: 'squarespace', label: 'Squarespace',                copy: 'Open domain DNS settings and add or edit the TXT record for _dmarc. DNS changes may take longer to appear.' },
  { id: 'microsoft',   label: 'Microsoft 365 / domain host', copy: 'Microsoft 365 may manage your email, but your DNS host controls the DMARC TXT record. Open the domain host shown in your Microsoft 365 domain settings.' },
  { id: 'other',       label: 'Other',                      copy: 'Open your DNS provider and add or edit a TXT record named _dmarc.' },
]

function CopyField({ label, value }) {
  return (
    <div className="space-y-1">
      <p className="text-xs uppercase tracking-wide font-semibold text-gray-400">{label}</p>
      <div className="flex items-center gap-2">
        <code className="mono text-xs flex-1 break-all bg-white border border-gray-200 rounded-lg px-3 py-2">{value || '—'}</code>
        {value && <CopyButton value={value} label="Copy" />}
      </div>
    </div>
  )
}

// Per-step completion (not strictly linear): a later step can be incomplete
// even when an earlier one is done (e.g. reports received but DNS not verified).
function WizardStepper({ steps, completed, current }) {
  return (
    <ol className="flex flex-wrap items-center gap-x-2 gap-y-2">
      {steps.map((label, i) => {
        const done = !!completed[i], isCurrent = i === current
        return (
          <li key={label} className="flex items-center gap-2">
            <span className={`flex items-center justify-center w-6 h-6 rounded-full text-xs font-semibold ${done ? 'bg-brand-200 text-brand-900' : isCurrent ? 'bg-brand-100 text-brand-700 ring-2 ring-brand-300' : 'bg-gray-100 text-gray-400'}`}>
              {i + 1}
            </span>
            <span className={`text-xs ${isCurrent ? 'font-semibold text-gray-800' : done ? 'text-gray-600' : 'text-gray-500'}`}>{label}</span>
          </li>
        )
      })}
    </ol>
  )
}

// Managed DMARC (Hosted Records Engine, Phase A): one CNAME, then CyberMeters
// manages the record value. Reads/creates via the hosted-dmarc endpoints.
const HOSTED_STATUS_META = {
  pending_dns:     { label: 'Preparing…',          kind: 'na',   hint: 'We are publishing your managed record. This usually takes under a minute — check again shortly.' },
  awaiting_cname:  { label: 'Waiting for CNAME',   kind: 'warn', hint: 'Add the CNAME below at your DNS provider, then check the connection.' },
  connected:       { label: 'Connected',           kind: 'good', hint: 'Your DMARC record is managed by CyberMeters. Reporting keeps flowing to your address.' },
  disconnected:    { label: 'Disconnected',        kind: 'bad',  hint: 'The CNAME no longer points at CyberMeters, so your policy may not be published. Restore the CNAME or review your DNS.' },
  pending_removal: { label: 'Removing…',           kind: 'na',   hint: 'Remove the CNAME at your DNS provider; the hosted value stays live until your DNS no longer depends on it.' },
}
// The connected/disconnected hints name the record; the rest are shared.
const HOSTED_STATUS_HINTS = {
  tlsrpt: {
    connected: 'Your TLS-RPT record is hosted by CyberMeters. TLS failure reports go to your reporting address.',
    disconnected: 'The CNAME no longer points at CyberMeters, so your TLS-RPT record may not be published. Restore the CNAME or review your DNS.',
  },
  mtasts: {
    connected: 'Your MTA-STS policy ID is managed by CyberMeters. The HTTPS policy file is still published by you or your web provider.',
    disconnected: 'The CNAME no longer points at CyberMeters, so your MTA-STS policy ID may not be published. Restore the CNAME or review your DNS.',
  },
}
export function hostedStatusMeta(kind, status) {
  const base = HOSTED_STATUS_META[status] || HOSTED_STATUS_META.pending_dns
  const hint = HOSTED_STATUS_HINTS[kind]?.[status]
  return hint ? { ...base, hint } : base
}

function TlsRptHealthCard({ wsId, domain }) {
  const [data, setData] = useState(undefined) // undefined=loading, null=none
  useEffect(() => {
    let alive = true
    api.getTlsRptReports(wsId, domain)
      .then(r => { if (alive) setData(r?.summary?.report_count > 0 ? r.summary : null) })
      .catch(() => { if (alive) setData(null) })
    return () => { alive = false }
  }, [wsId, domain])

  if (!data) return null // self-hide while loading or when no reports yet
  const rate = data.success_rate
  const rateCls = rate == null ? 'text-gray-400' : rate >= 99 ? 'text-brand-700' : rate >= 95 ? 'text-brand-700' : 'text-red-700'
  return (
    <div className="mx-6 mt-4 rounded-xl border border-gray-200 bg-white p-5">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <p className="text-sm font-bold text-gray-900">SMTP TLS delivery health</p>
          <p className="text-xs text-gray-500 mt-1 leading-relaxed">
            From TLS-RPT reports — is mail being delivered to you securely over TLS, and where is it failing.
          </p>
        </div>
        <div className="text-right">
          <p className={`text-3xl font-black tabular-nums leading-none ${rateCls}`}>{rate != null ? `${rate}%` : '—'}</p>
          <p className="text-xs text-gray-400 mt-0.5">success rate</p>
        </div>
      </div>
      <div className="mt-3 grid grid-cols-3 gap-3 text-center">
        <div><p className="text-lg font-bold text-gray-900 tabular-nums">{formatNumber(data.total_sessions)}</p><p className="text-xs text-gray-400">sessions</p></div>
        <div><p className="text-lg font-bold text-gray-900 tabular-nums">{formatNumber(data.failed_sessions)}</p><p className="text-xs text-gray-400">failed</p></div>
        <div><p className="text-lg font-bold text-gray-900 tabular-nums">{data.report_count}</p><p className="text-xs text-gray-400">reports</p></div>
      </div>
      {data.top_failures?.length > 0 && (
        <div className="mt-4 pt-3 border-t border-gray-100">
          <p className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-wide">Top failures</p>
          <div className="space-y-1.5">
            {data.top_failures.map((f, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className="text-gray-700 font-medium">{(f.result_type || 'unknown').replace(/-/g, ' ')}</span>
                <span className="text-gray-400 tabular-nums">{formatNumber(f.sessions || 0)} sessions</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function ManagedTlsRptCard({ wsId, domain, endpointReady }) {
  const dialog = useAppDialog()
  const [rec, setRec]     = useState(undefined) // undefined=loading, null=none
  const [busy, setBusy]   = useState(null)      // 'create' | 'verify' | 'remove'
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    if (!wsId || !domain) return
    try { const r = await api.getHostedTlsRpt(wsId, domain); setRec(r?.record ?? null) }
    catch { setRec(null) }
  }, [wsId, domain])
  useEffect(() => { setRec(undefined); setError(null); load() }, [load])

  async function act(kind, fn) {
    setBusy(kind); setError(null)
    try { const r = await fn(); setRec(r?.record ?? null) }
    catch (e) { setError(e?.message || 'The request could not be completed.') }
    finally { setBusy(null) }
  }

  if (rec === undefined) return null
  const meta = rec ? hostedStatusMeta('tlsrpt', rec.status) : null

  return (
    <div className="mx-6 mt-4 rounded-xl border border-gray-200 bg-gray-50/50 p-5">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm font-bold text-gray-900">
            Host your TLS reporting (TLS-RPT)
            {!rec && <span className="ml-2 text-xs font-bold uppercase tracking-wide text-gray-600 bg-gray-100 rounded-sm px-1.5 py-0.5">Optional</span>}
          </p>
          <p className="text-xs text-gray-500 mt-1 leading-relaxed">
            Add one CNAME and we host the <code className="text-xs">_smtp._tls</code> record for you, so you get
            reports when someone can’t deliver mail to you over TLS.
          </p>
        </div>
        {rec && meta && (
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border ${
            meta.kind === 'good' ? 'bg-brand-50 text-brand-700 border-brand-200'
            : meta.kind === 'warn' ? 'bg-transparent text-brand-700 border-[1.5px] border-brand-700'
            : meta.kind === 'bad' ? 'bg-red-50 text-red-700 border-red-200'
            : 'bg-gray-50 text-gray-500 border-gray-200'}`}>
            {meta.label}
          </span>
        )}
      </div>

      {error && <p className="mt-2 text-xs text-red-700">{error}</p>}

      {!rec ? (
        <div className="mt-3">
          <button
            onClick={() => act('create', () => api.createHostedTlsRpt(wsId, domain))}
            disabled={!endpointReady || busy === 'create'}
            className="btn-secondary text-sm disabled:opacity-50"
          >
            {busy === 'create' && <RefreshCw className="w-4 h-4 animate-spin" />}
            Host TLS-RPT
          </button>
          {!endpointReady && (
            <p className="text-xs text-gray-400 mt-2">Activate DMARC reporting in the setup above first — TLS-RPT reuses the same reporting address.</p>
          )}
        </div>
      ) : (
        <div className="mt-3 space-y-2.5">
          <p className="text-xs text-gray-600">{meta.hint}</p>
          {rec.status !== 'connected' && rec.status !== 'pending_removal' && (
            <div className="space-y-1.5">
              <div className="grid grid-cols-[70px_1fr] gap-2 items-center">
                <span className="text-xs font-semibold text-gray-500">Type / Name</span>
                <DnsValue value={`CNAME  ${rec.cname_name}`} />
              </div>
              <div className="grid grid-cols-[70px_1fr] gap-2 items-center">
                <span className="text-xs font-semibold text-gray-500">Target</span>
                <DnsValue value={rec.cname_target} />
              </div>
              <p className="text-xs text-gray-400">Add this CNAME at {rec.cname_name}.</p>
            </div>
          )}
          <div className="flex items-center gap-2 flex-wrap">
            {rec.status !== 'pending_removal' && (
              <button
                onClick={() => act('verify', () => api.verifyHostedTlsRpt(wsId, domain))}
                disabled={Boolean(busy)}
                className="btn-secondary text-xs disabled:opacity-50"
              >
                {busy === 'verify' && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                Check connection
              </button>
            )}
            {rec.status !== 'pending_removal' && (
              <button
                onClick={async () => {
                  if (await dialog.confirm({ title: 'Stop hosting TLS-RPT?', message: 'You will need to publish your own TLS-RPT TXT record again.', confirmLabel: 'Stop hosting', tone: 'danger' })) {
                    act('remove', () => api.deleteHostedTlsRpt(wsId, domain))
                  }
                }}
                disabled={Boolean(busy)}
                className="text-xs text-gray-400 hover:text-red-800 disabled:opacity-50"
              >
                Stop hosting
              </button>
            )}
          </div>
          {rec.current_value && rec.status === 'connected' && (
            <div>
              <p className="text-xs font-semibold text-gray-500 mb-1">Hosted value (live)</p>
              <DnsValue value={rec.current_value} />
            </div>
          )}
        </div>
      )}
      {dialog.element}
    </div>
  )
}

export function ManagedMtaStsCard({ wsId, domain }) {
  const dialog = useAppDialog()
  const [rec, setRec]     = useState(undefined) // undefined=loading, null=none
  const [busy, setBusy]   = useState(null)      // 'create' | 'verify' | 'remove'
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    if (!wsId || !domain) return
    try { const r = await api.getHostedMtaSts(wsId, domain); setRec(r?.record ?? null) }
    catch { setRec(null) }
  }, [wsId, domain])
  useEffect(() => { setRec(undefined); setError(null); load() }, [load])

  async function act(kind, fn) {
    setBusy(kind); setError(null)
    try { const r = await fn(); setRec(r?.record ?? null) }
    catch (e) { setError(e?.message || 'The request could not be completed.') }
    finally { setBusy(null) }
  }

  if (rec === undefined) return null
  const meta = rec ? hostedStatusMeta('mtasts', rec.status) : null
  const policyVerified = rec?.https_policy?.state === 'reachable_valid' && rec?.https_policy?.matches_pinned_policy
  const dnsConnected = rec?.dns_txt?.state === 'connected' || rec?.status === 'connected'
  const complete = Boolean(rec?.complete)
  // DNS connected but the HTTPS policy file not verified is incomplete, never
  // "Connected". The reason follows the API's policy-file state.
  const policyState = rec?.https_policy?.state
  const policyPath = rec?.https_policy?.path || rec?.policy_path || null
  const incompleteReason = rec && !complete && !rec.review_required && dnsConnected
    ? (!policyState || policyState === 'not_checked' ? 'policy file not checked yet'
      : policyState === 'not_published' ? 'policy file not published'
      : 'policy file does not match')
    : null

  return (
    <div id="mta-sts-setup" className="mx-6 mt-4 rounded-xl border border-gray-200 bg-white p-5 scroll-mt-24">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm font-bold text-gray-900">
            MTA-STS readiness
            {!rec && <span className="ml-2 text-xs font-bold uppercase tracking-wide text-gray-600 bg-gray-100 rounded-sm px-1.5 py-0.5">Guided</span>}
          </p>
          <p className="text-xs text-gray-500 mt-1 leading-relaxed">
            CyberMeters manages the MTA-STS DNS policy ID. Your organisation or web provider hosts the HTTPS policy file.
          </p>
        </div>
        {rec && (
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border ${
            complete ? 'bg-brand-50 text-brand-700 border-brand-200'
            : rec.review_required ? 'bg-transparent text-brand-700 border-[1.5px] border-brand-700'
            : 'bg-gray-50 text-gray-600 border-gray-200'}`}>
            {complete ? 'MTA-STS active in testing mode' : rec.review_required ? 'Review needed'
              : incompleteReason ? `Incomplete — ${incompleteReason}` : meta?.label || 'Not checked'}
          </span>
        )}
      </div>
      {incompleteReason && policyPath && (
        <p className="mt-2 text-xs text-gray-600 leading-relaxed" data-testid="mta-sts-incomplete-line">
          MTA-STS stays incomplete until <span className="font-mono break-all">{policyPath}</span> serves this exact file.
        </p>
      )}

      {error && <p className="mt-2 text-xs text-red-700">{error}</p>}

      {!rec ? (
        <div className="mt-3">
          <button
            onClick={() => act('create', () => api.createHostedMtaSts(wsId, domain))}
            disabled={busy === 'create'}
            className="btn-secondary text-sm disabled:opacity-50"
          >
            {busy === 'create' && <RefreshCw className="w-4 h-4 animate-spin" />}
            Set up MTA-STS
          </button>
          <p className="text-xs text-gray-400 mt-2">Starts in testing mode. CyberMeters will not switch this to enforce automatically.</p>
        </div>
      ) : (
        <div className="mt-4 space-y-3">
          <div className="grid sm:grid-cols-2 gap-2">
            <div className={`rounded-lg border p-3 ${dnsConnected ? 'border-brand-100 bg-brand-50/40' : 'border-gray-200 bg-gray-50'}`}>
              <p className="text-xs font-bold text-gray-700">DNS policy ID</p>
              <p className="text-xs text-gray-500 mt-1">{dnsConnected ? 'CNAME connected to the CyberMeters TXT value.' : meta?.hint}</p>
            </div>
            <div className={`rounded-lg border p-3 ${policyVerified ? 'border-brand-100 bg-brand-50/40' : 'border-gray-200 bg-gray-50'}`}>
              <p className="text-xs font-bold text-gray-700">HTTPS policy file</p>
              <p className="text-xs text-gray-500 mt-1">{policyVerified ? 'Policy file is reachable and matches the pinned content.' : 'Publish the exact policy file below, then check again.'}</p>
            </div>
          </div>

          {rec.review_required && (
            <div className="rounded-lg border border-[1.5px] border-brand-700 bg-transparent p-3 text-xs text-brand-700">
              {rec.mx_drift?.message || 'Your mail servers changed. Review and republish the MTA-STS policy before changing the DNS policy ID.'}
            </div>
          )}

          {rec.status !== 'connected' && rec.status !== 'pending_removal' && (
            <div className="space-y-1.5">
              <div className="grid grid-cols-[86px_1fr] gap-2 items-center">
                <span className="text-xs font-semibold text-gray-500">Type / Name</span>
                <DnsValue value={`CNAME  ${rec.cname_name}`} />
              </div>
              <div className="grid grid-cols-[86px_1fr] gap-2 items-center">
                <span className="text-xs font-semibold text-gray-500">Target</span>
                <DnsValue value={rec.cname_target} />
              </div>
            </div>
          )}

          <div>
            <p className="text-xs font-semibold text-gray-500 mb-1">HTTPS policy path</p>
            <DnsValue value={rec.policy_path} />
          </div>
          {rec.policy_content && (
            <div>
              <div className="flex items-center justify-between mb-1">
                <p className="text-xs font-semibold text-gray-500">Policy file content</p>
                <CopyButton value={rec.policy_content} />
              </div>
              <pre className="mono text-xs text-gray-800 whitespace-pre-wrap rounded-lg bg-gray-50 border border-gray-200 p-3 leading-relaxed">{rec.policy_content}</pre>
            </div>
          )}

          <div className="flex items-center gap-2 flex-wrap">
            {rec.status !== 'pending_removal' && (
              <button
                onClick={() => act('verify', () => api.verifyHostedMtaSts(wsId, domain))}
                disabled={Boolean(busy)}
                className="btn-secondary text-xs disabled:opacity-50"
              >
                {busy === 'verify' && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                Check DNS and policy
              </button>
            )}
            {rec.status !== 'pending_removal' && (
              <button
                onClick={async () => {
                  if (await dialog.confirm({ title: 'Stop managing the MTA-STS policy ID?', message: 'Your HTTPS policy file is not changed by CyberMeters.', confirmLabel: 'Stop DNS management', tone: 'danger' })) {
                    act('remove', () => api.deleteHostedMtaSts(wsId, domain))
                  }
                }}
                disabled={Boolean(busy)}
                className="text-xs text-gray-400 hover:text-red-800 disabled:opacity-50"
              >
                Stop DNS management
              </button>
            )}
          </div>
        </div>
      )}
      {dialog.element}
    </div>
  )
}

// The line under the 7-day compliance figure. The backend says why the pass
// rate is absent (compliance.pass_rate_unavailable_reason); this only words it.
export function complianceDetail(compliance) {
  if (compliance?.pass_rate != null) return `${formatNumber(compliance.total_messages)} messages`
  const reason = compliance?.pass_rate_unavailable_reason
  if (reason === 'reports_not_used_for_pass_rate') {
    const last = compliance.last_report_received_at
      ? pageTime(parseServerDate(compliance.last_report_received_at))
      : null
    return `Reports are arriving${last ? ` (last: ${last})` : ''}. The pass rate is not calculated from these reports.`
  }
  if (reason === 'no_reports') return 'No reports in the last 7 days'
  return 'Pass rate not calculated'
}

export function ManagedDmarcCard({ wsId, domain, endpointReady }) {
  const dialog = useAppDialog()
  const [rec, setRec]         = useState(undefined) // undefined=loading, null=none
  const [ramp, setRamp]       = useState(null)      // { policyAllowed, compliance, readiness }
  const [busy, setBusy]       = useState(null)      // 'create' | 'verify' | 'remove' | 'policy' | 'step_back' | 'rollback' | 'autopilot'
  const [error, setError]     = useState(null)

  const load = useCallback(async () => {
    if (!wsId || !domain) return
    try {
      const r = await api.getHostedDmarc(wsId, domain)
      setRec(r?.record ?? null)
      setRamp({
        policyAllowed: Boolean(r?.policy_management_available),
        compliance: r?.compliance || null,
        readiness: r?.readiness || null,
        interpretation: r?.hosted_dmarc_interpretation || null,
      })
    } catch { setRec(null); setRamp(null) }
  }, [wsId, domain])
  useEffect(() => { setRec(undefined); setError(null); load() }, [load])

  async function act(kind, fn, { reloadAll = false } = {}) {
    setBusy(kind); setError(null)
    try {
      const r = await fn()
      if (reloadAll) await load()
      else setRec(r?.record ?? null)
    } catch (e) { setError(e?.message || 'The request could not be completed.') }
    finally { setBusy(null) }
  }

  if (rec === undefined) return null
  const meta = rec ? hostedStatusMeta('dmarc', rec.status) : null
  const automationSuspended = ramp?.interpretation?.automation_status === 'suspended'
  // A ladder step by its key; a step from an older API (no key) by policy and pct.
  const requestStep = (step, confirm = false) => (step.key
    ? api.setHostedDmarcStep(wsId, domain, step.key, confirm)
    : api.setHostedDmarcPolicy(wsId, domain, step.policy, step.pct, confirm))

  return (
    <div className="mx-6 mt-5 rounded-xl border border-brand-200 bg-brand-50/40 p-5">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm font-bold text-gray-900">
            Let CyberMeters manage this record
            {!rec && <span className="ml-2 text-xs font-bold uppercase tracking-wide text-brand-700 bg-brand-100 rounded-sm px-1.5 py-0.5">Recommended</span>}
          </p>
          <p className="text-xs text-gray-500 mt-1 leading-relaxed">
            Add one CNAME and we manage the DMARC value for you — no more DNS edits when your
            policy evolves. Reporting keeps flowing to your CyberMeters address.
          </p>
        </div>
        {rec && meta && (
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border ${
            meta.kind === 'good' ? 'bg-brand-50 text-brand-700 border-brand-200'
            : meta.kind === 'warn' ? 'bg-transparent text-brand-700 border-[1.5px] border-brand-700'
            : meta.kind === 'bad' ? 'bg-red-50 text-red-700 border-red-200'
            : 'bg-gray-50 text-gray-500 border-gray-200'}`}>
            {meta.label}
          </span>
        )}
      </div>

      {rec?.issue && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-[1.5px] border-brand-700 bg-transparent px-3 py-2">
          <p className="text-xs text-brand-700 leading-relaxed">
            {rec.issue === 'config_error'
              ? 'Publishing is delayed on our side — no action needed from you. We’ve been notified and will complete setup automatically.'
              : 'Finishing setup — publishing your managed record can take a few minutes. This will clear on its own.'}
          </p>
        </div>
      )}

      {!rec ? (
        <div className="mt-3">
          <button
            onClick={() => act('create', () => api.createHostedDmarc(wsId, domain))}
            disabled={!endpointReady || busy === 'create'}
            className="btn-primary text-sm disabled:opacity-50"
          >
            {busy === 'create' && <RefreshCw className="w-4 h-4 animate-spin" />}
            Set up managed DMARC
          </button>
          {!endpointReady && (
            <p className="text-xs text-gray-400 mt-2">Activate DMARC reporting in the setup above first — the managed record includes your reporting address.</p>
          )}
        </div>
      ) : (
        <div className="mt-3 space-y-2.5">
          <p className="text-xs text-gray-600">{meta.hint}</p>
          {rec.status !== 'connected' && rec.status !== 'pending_removal' && (
            <div className="space-y-1.5">
              <div className="grid grid-cols-[70px_1fr] gap-2 items-center">
                <span className="text-xs font-semibold text-gray-500">Type / Name</span>
                <DnsValue value={`CNAME  ${rec.cname_name}`} />
              </div>
              <div className="grid grid-cols-[70px_1fr] gap-2 items-center">
                <span className="text-xs font-semibold text-gray-500">Target</span>
                <DnsValue value={rec.cname_target} />
              </div>
              <p className="text-xs text-gray-400">Replace any existing TXT at {rec.cname_name} with this CNAME.</p>
            </div>
          )}
          <div className="flex items-center gap-2 flex-wrap">
            {rec.status !== 'pending_removal' && (
              <button
                onClick={() => act('verify', () => api.verifyHostedDmarc(wsId, domain))}
                disabled={Boolean(busy)}
                className="btn-secondary text-xs disabled:opacity-50"
              >
                {busy === 'verify' && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                Check connection
              </button>
            )}
            {rec.status !== 'pending_removal' && (
              <button
                onClick={async () => {
                  if (await dialog.confirm({ title: 'Stop managing this DMARC record?', message: 'You will need to publish your own DMARC TXT record again.', confirmLabel: 'Stop managing', tone: 'danger' })) {
                    act('remove', () => api.deleteHostedDmarc(wsId, domain))
                  }
                }}
                disabled={Boolean(busy)}
                className="text-xs text-gray-400 hover:text-red-800 disabled:opacity-50"
              >
                Stop managing
              </button>
            )}
          </div>
          {rec.current_value && rec.status === 'connected' && (
            <div>
              <p className="text-xs font-semibold text-gray-500 mb-1">Managed value (live)</p>
              <DnsValue value={rec.current_value} />
            </div>
          )}

          {rec.status === 'connected' && automationSuspended && (
            <div className="mt-4 rounded-xl border border-[1.5px] border-brand-700 bg-transparent px-4 py-3">
              <p className="text-sm font-bold text-brand-700">Managed policy automation is suspended</p>
              <p className="mt-1 text-xs leading-relaxed text-brand-700">
                Automatic policy advancement and rollback from inbound DMARC (RUA) reports are suspended. Governed manual changes remain available below and require your explicit action.
              </p>
            </div>
          )}

          {/* Manual governed changes remain available while external/RUA-driven
              automation is suspended. Self-Driving DMARC is gated separately. */}
          {rec.status === 'connected' && rec.policy_step && (
            <div id="dmarc-enforcement" className="pt-5 mt-4 border-t border-brand-100 space-y-5 scroll-mt-24">
              <div className="flex items-end justify-between gap-3 flex-wrap">
                <div>
                  <h4 className="text-base font-bold text-gray-900">Enforcement journey</h4>
                  <p className="text-sm text-gray-500 mt-0.5">Review evidence before requesting stronger receiver handling. Publication does not prove receiver action.</p>
                </div>
                {ramp?.compliance && (
                  <div className="text-right">
                    <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">7-day compliance</p>
                    <p className={`text-2xl font-black tabular-nums leading-none mt-1 ${
                      ramp.compliance.pass_rate == null ? 'text-gray-600'
                      : ramp.compliance.pass_rate >= 97 ? 'text-brand-700' : 'text-brand-700'}`}>
                      {ramp.compliance.pass_rate != null ? `${ramp.compliance.pass_rate}%` : '—'}
                    </p>
                    <p className="text-xs text-gray-500 mt-0.5 max-w-[17rem] ml-auto" data-testid="compliance-detail">
                      {complianceDetail(ramp.compliance)}
                    </p>
                  </div>
                )}
              </div>

              {rec.legacy_pct?.message && (
                <div className="rounded-xl border border-gray-200 bg-gray-50 px-4 py-3" data-testid="legacy-pct-notice">
                  <p className="text-sm font-semibold text-gray-800">Older DMARC tag on this record</p>
                  <p className="mt-1 text-sm leading-relaxed text-gray-600">{rec.legacy_pct.message}</p>
                </div>
              )}

              {/* Ladder track: the steps come from the API (rec.ladder). Without
                  a ladder, only the current step the API names is shown. */}
              <div className="flex items-stretch gap-1.5 overflow-x-auto pb-1" data-testid="dmarc-ladder">
                {(Array.isArray(rec.ladder) && rec.ladder.length ? rec.ladder : [rec.policy_step]).map((step) => {
                  const state = step.index === rec.policy_step.index ? 'current' : step.index < rec.policy_step.index ? 'done' : 'future'
                  return (
                    <div key={step.key || step.index} aria-current={state === 'current' ? 'step' : undefined} className={`flex-1 min-w-[120px] rounded-xl border px-3 py-2.5 text-center ${
                      state === 'current' ? 'bg-brand-200 border-brand-200 text-brand-900 shadow-xs ring-2 ring-brand-200'
                      : state === 'done' ? 'bg-brand-50 border-brand-200 text-brand-700'
                      : 'bg-white border-gray-200 text-gray-400'}`}>
                      <p className="text-[14px] font-bold leading-tight">{step.label}</p>
                      {state === 'current' && <p className="text-xs font-semibold text-brand-900 mt-0.5">You are here</p>}
                      {state === 'done' && <p className="text-xs text-brand-700 mt-0.5">✓ passed</p>}
                    </div>
                  )
                })}
              </div>
              {rec.policy_step.description && (
                <p className="text-sm text-gray-600 leading-relaxed">{rec.policy_step.description}</p>
              )}

              {rec.change_pending && (
                <p className="text-sm text-brand-700 font-medium bg-transparent border border-[1.5px] border-brand-700 rounded-lg px-3.5 py-2.5">
                  A change is being confirmed — controls unlock automatically once it settles.
                </p>
              )}

              {!ramp?.policyAllowed ? (
                <div className="rounded-xl border border-gray-200 bg-gray-50 px-4 py-3.5">
                  <p className="text-sm text-gray-700">
                    No-action policy monitoring is free. <span className="font-bold">Managed policy-change tools are on paid plans</span> — upgrade to review a stronger requested policy.
                  </p>
                </div>
              ) : (
                <>
                  {rec.next_step && !rec.change_pending && (
                    <div className="space-y-2.5">
                      {rec.projected_impact && (
                        <div className={`rounded-xl border px-4 py-3 ${
                          rec.projected_impact.insufficient_data ? 'border-gray-200 bg-gray-50' : 'border-blue-100 bg-blue-50/60'}`}>
                          <p className="text-xs font-bold uppercase tracking-wide text-gray-500">Projected impact</p>
                          <p className="text-sm text-gray-700 mt-1 leading-relaxed">
                            Advancing to {rec.next_step.label} would affect about{' '}
                            <span className="font-bold tabular-nums">{formatNumber(rec.projected_impact.affected_messages || 0)}</span>
                            {' '}message{rec.projected_impact.affected_messages === 1 ? '' : 's'},
                            including{' '}
                            <span className="font-bold tabular-nums">{formatNumber(rec.projected_impact.legitimate_affected_messages || 0)}</span>
                            {' '}from legitimate senders.
                          </p>
                          {rec.projected_impact.insufficient_data && (
                            <p className="text-xs text-gray-500 mt-1">Not enough recent DMARC volume yet for a confident forecast.</p>
                          )}
                          {rec.projected_impact.legitimate_affected_senders?.length > 0 && (
                            <p className="text-xs text-gray-500 mt-1">
                              Review: {rec.projected_impact.legitimate_affected_senders.slice(0, 3).map(s => `${s.provider || s.source_ip} (${s.affected})`).join(', ')}
                            </p>
                          )}
                        </div>
                      )}
                      {rec.impact_assessment && !rec.impact_assessment.insufficient_data && (
                        <div className={`rounded-xl border px-4 py-3 ${
                          rec.impact_assessment.rollbackRecommended ? 'border-[1.5px] border-brand-700 bg-transparent' : 'border-brand-100 bg-brand-50/40'}`}>
                          <p className="text-xs font-bold uppercase tracking-wide text-gray-500">Post-change monitor</p>
                          <p className="text-sm text-gray-700 mt-1 leading-relaxed">
                            Legitimate failed-mail rate changed by {rec.impact_assessment.delta?.legitimate_failed_rate_increase ?? 0} percentage points after the last change.
                            {rec.impact_assessment.rollbackRecommended ? ' Review rollback before continuing.' : ' No rollback signal from legitimate mail at this stage.'}
                          </p>
                        </div>
                      )}
                      <button
                        onClick={() => act('policy', async () => {
                          try {
                            return await requestStep(rec.next_step)
                          } catch (e) {
                            if (e?.code === 'readiness_check_failed' || /not ready/i.test(e?.message || '')) {
                              const reasons = (e?.readiness?.reasons || []).map((r) => `• ${r}`).join('\n')
                              if (await dialog.confirm({
                                title: `Move to ${rec.next_step.label} anyway?`,
                                message: `Compliance is not ready yet:\n${reasons}`,
                                confirmLabel: `Move to ${rec.next_step.label} anyway`,
                                cancelLabel: `Stay at ${rec.policy_step?.label || 'the current step'}`,
                                tone: 'danger',
                              })) {
                                return await requestStep(rec.next_step, true)
                              }
                              return null
                            }
                            throw e
                          }
                        }, { reloadAll: true })}
                        disabled={Boolean(busy)}
                        className="btn-primary w-full justify-center py-3 text-sm disabled:opacity-50"
                      >
                        {busy === 'policy' && <RefreshCw className="w-4 h-4 animate-spin" />}
                        Advance to {rec.next_step.label}
                      </button>
                      {ramp?.readiness && !ramp.readiness.ready && (
                        <div className="flex items-start gap-2 text-sm text-brand-700 bg-transparent border border-[1.5px] border-brand-700 rounded-lg px-3.5 py-2.5">
                          <span><span className="font-semibold">Safety interlock:</span> {ramp.readiness.reasons[0]}</span>
                        </div>
                      )}
                      {ramp?.readiness?.ready && (
                        <p className="flex items-center gap-1.5 text-sm text-brand-700 font-semibold">
                          Compliance is healthy — ready for the next step.
                        </p>
                      )}
                    </div>
                  )}

                  {/* Self-Driving remains completely unrendered while the
                      canonical external-automation interpretation is suspended. */}
                  {!automationSuspended && (
                    <label className={`flex items-start gap-3 rounded-xl border px-4 py-3.5 cursor-pointer transition-colors ${
                      rec.autopilot ? 'border-brand-300 bg-brand-50/50' : 'border-gray-200 hover:border-gray-300'}`}>
                      <input
                        type="checkbox"
                        checked={rec.autopilot}
                        disabled={Boolean(busy)}
                        onChange={(e) => act('autopilot', () => api.setHostedDmarcAutopilot(wsId, domain, e.target.checked), { reloadAll: true })}
                        className="mt-0.5 w-4 h-4 rounded-sm border-gray-300 text-brand-700"
                      />
                      <span>
                        <span className="block text-sm font-bold text-gray-900">Self-Driving DMARC</span>
                        <span className="block text-sm text-gray-500 mt-0.5">Advance automatically while compliance stays healthy, and roll back on regressions.</span>
                      </span>
                    </label>
                  )}

                  {rec.previous_step?.key && !rec.change_pending && (
                    <button
                      onClick={async () => {
                        if (await dialog.confirm({
                          title: `Step back to ${rec.previous_step.label}?`,
                          message: 'Receivers will be asked for less strict handling of mail that fails DMARC.',
                          confirmLabel: `Step back to ${rec.previous_step.label}`,
                        })) {
                          act('step_back', () => requestStep(rec.previous_step), { reloadAll: true })
                        }
                      }}
                      disabled={Boolean(busy)}
                      className="btn-secondary text-sm disabled:opacity-50"
                    >
                      {busy === 'step_back' && <RefreshCw className="w-4 h-4 animate-spin" />}
                      {busy === 'step_back' ? 'Stepping back…' : 'Step back one level'}
                    </button>
                  )}

                  {rec.can_rollback && (
                    <button
                      onClick={async () => {
                        if (await dialog.confirm({ title: 'Roll back the last change?', message: 'The previous policy value is restored.', confirmLabel: 'Restore previous value' })) {
                          act('rollback', () => api.rollbackHostedDmarc(wsId, domain), { reloadAll: true })
                        }
                      }}
                      disabled={Boolean(busy)}
                      className="btn-secondary text-sm disabled:opacity-50"
                    >
                      {busy === 'rollback' && <RefreshCw className="w-4 h-4 animate-spin" />}
                      {busy === 'rollback' ? 'Rolling back…' : 'Roll back last change'}
                    </button>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}
      {error && <p className="text-xs text-red-700 mt-2">{error}</p>}
      {dialog.element}
    </div>
  )
}

export function DmarcSetupWizard({ wsId, domain, dmarcDetail, hasScanData, totalMessages }) {
  const [endpoint, setEndpoint] = useState(null)
  const [loading, setLoading]   = useState(true)
  const [busy, setBusy]         = useState(false)
  const [err, setErr]           = useState(null)
  const [provider, setProvider] = useState('cloudflare')
  const [checking, setChecking] = useState(false)
  const [liveStatus, setLiveStatus] = useState(null) // live DNS-check result status

  const load = useCallback(async () => {
    if (!domain) return
    setLoading(true); setErr(null)
    try {
      const res = await api.getDmarcIngestEndpoint(wsId, domain)
      setEndpoint(res?.endpoint || null)
    } catch (e) { setErr(e.message || 'Could not load DMARC reporting settings.') }
    finally { setLoading(false) }
  }, [wsId, domain])

  // Reset the live verification result whenever the selected domain changes.
  useEffect(() => { setLiveStatus(null); load() }, [load])

  async function activate() {
    setBusy(true); setErr(null)
    try {
      const res = await api.createDmarcIngestEndpoint(wsId, domain)
      setEndpoint(res?.endpoint || null)
    } catch (e) { setErr(e.message || 'Could not start DMARC setup.') }
    finally { setBusy(false) }
  }
  // Live DNS verification — calls the backend DMARC DNS check and maps the
  // returned status to wizard state. Raw errors are never surfaced.
  async function verifyDns() {
    setChecking(true); setErr(null)
    try {
      const res = await api.verifyDmarcDns(wsId, domain)
      setLiveStatus(res?.status || 'dns_lookup_failed')
    } catch {
      setLiveStatus('dns_lookup_failed')
    } finally {
      setChecking(false)
    }
    // Silently refresh the endpoint so report-receiving state stays current
    // (no loading flicker on the whole wizard).
    try {
      const r = await api.getDmarcIngestEndpoint(wsId, domain)
      setEndpoint(r?.endpoint || null)
    } catch { /* non-fatal */ }
  }

  const inboundAddress = endpoint?.inbound_address || null
  const inboundMailto  = inboundAddress ? `mailto:${inboundAddress}` : null

  // Existing DMARC awareness from the latest scan (safe if fields are missing).
  const existingRaw = dmarcDetail?.raw || null
  const existingRua = Array.isArray(dmarcDetail?.rua) ? dmarcDetail.rua : []
  const present     = Boolean(dmarcDetail?.present) || Boolean(existingRaw)
  const ruaNorm     = existingRua.map(r => (String(r).startsWith('mailto:') ? String(r) : `mailto:${r}`))
  const already     = inboundMailto ? ruaNorm.some(r => r.toLowerCase() === inboundMailto.toLowerCase()) : false

  // ── Two independent states ──────────────────────────────────────────────────
  // 1) DNS setup: verified only when the live DMARC record already lists our
  //    reporting address. Unknown when we have no current DMARC data.
  // 2) Report receiving: connected once an inbound report has arrived.
  // Fully connected requires BOTH — receiving alone is NOT "Connected".
  // The live DNS check (when run) is authoritative for DNS-verified state;
  // before any check, fall back to the latest scan's DMARC record.
  const dnsKnown       = liveStatus != null || Boolean(hasScanData)
  const dnsVerified    = liveStatus != null ? liveStatus === 'verified' : (Boolean(hasScanData) && present && already)
  const receiving      = Boolean(endpoint?.last_inbound_at)
  const fullyConnected = dnsVerified && receiving
  const needsDnsAction = receiving && !dnsVerified

  // Recommended value — never suggests enforcement; preserves any existing policy.
  let recommendedValue = inboundMailto ? `v=DMARC1; p=none; rua=${inboundMailto}` : '—'
  if (present && existingRaw && inboundMailto && !already) {
    const mergedRua = [...ruaNorm, inboundMailto].join(',')
    recommendedValue = /rua=/i.test(existingRaw)
      ? existingRaw.replace(/rua=[^;]*/i, `rua=${mergedRua}`)
      : existingRaw.replace(/;?\s*$/, '') + `; rua=${mergedRua}`
  } else if (present && existingRaw && already) {
    recommendedValue = existingRaw
  }

  // Map the live DNS-check status to a wizard message key. Before any live
  // check, derive a sensible state from the latest scan's DMARC record.
  const LIVE_MAP = {
    verified:               'configured',
    missing_cybermeters_rua:'missing_rua',
    no_dmarc:               'no_dmarc',
    invalid_dmarc:          'invalid',
    multiple_dmarc_records: 'multiple',
    endpoint_missing:       'endpoint_missing',
    dns_lookup_failed:      'lookup_failed',
  }
  const verifyState = liveStatus
    ? (LIVE_MAP[liveStatus] || 'lookup_failed')
    : (!hasScanData ? 'unavailable' : (!present ? 'no_dmarc' : (already ? 'configured' : 'missing_rua')))
  const VERIFY_MSG = {
    configured:       { kind: 'good', text: 'DNS looks correctly configured. Your CyberMeters reporting address is in the DMARC record.' },
    missing_rua:      { kind: 'warn', text: 'DMARC exists, but CyberMeters reporting address is not included yet. Add it to the rua= tag (see the value above) — do not delete your existing record.' },
    no_dmarc:         { kind: 'warn', text: 'No DMARC record found yet. Add the TXT record above, then check again.' },
    invalid:          { kind: 'warn', text: 'We found a DMARC record, but it could not be read as valid. Check the record value above, then re-check.' },
    multiple:         { kind: 'warn', text: 'More than one DMARC record was found at _dmarc. DNS allows only one — remove the extra record, then re-check.' },
    endpoint_missing: { kind: 'na',   text: 'Create your reporting address first (use “Activate DMARC reporting” above), then add it to your DMARC record and re-check.' },
    lookup_failed:    { kind: 'na',   text: 'We couldn’t check your DNS just now. This is common while DNS is updating — please try again in a few minutes.' },
    unavailable:      { kind: 'na',   text: 'Click “Verify setup” to check your DNS now, or it will be confirmed automatically once your record includes the CyberMeters address.' },
  }
  const vm = VERIFY_MSG[verifyState]

  const providerCopy = DNS_PROVIDERS.find(p => p.id === provider)?.copy
  const fmt = pageTime

  // Per-step completion — explicitly non-linear.
  const steps = ['Choose DNS provider', 'Copy DNS record', 'Verify setup', 'Wait for reports', 'Connected']
  const stepDone = [Boolean(provider), Boolean(inboundMailto), dnsVerified, receiving, fullyConnected]
  const firstIncomplete = stepDone.findIndex(d => !d)
  const currentStep = firstIncomplete === -1 ? steps.length - 1 : firstIncomplete

  return (
    <div className="space-y-6">
    <section className="card overflow-hidden" aria-labelledby="dmarc-reporting-setup-title">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70 flex items-center gap-2.5">
        <div>
          <span className="eyebrow">Get connected</span>
          <h2 id="dmarc-reporting-setup-title" className="section-title leading-tight">DMARC reporting setup</h2>
        </div>
        {fullyConnected ? (
          <span className="ml-auto inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-brand-50 border border-brand-100 text-xs font-semibold text-brand-700">
            Connected
          </span>
        ) : needsDnsAction ? (
          <span className="ml-auto inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-transparent border border-[1.5px] border-brand-700 text-xs font-semibold text-brand-700">
            Receiving reports · DNS not verified
          </span>
        ) : null}
      </div>

      <div className="p-6 space-y-5">
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-gray-500"><RefreshCw className="w-4 h-4 animate-spin" /> Loading DMARC setup…</div>
        ) : !endpoint || endpoint.status !== 'active' ? (
          <>
            <p className="text-sm text-gray-500 leading-relaxed">
              Set up automatic DMARC reports for <b>{domain}</b> in a few steps. You’ll get a reporting address to add to
              your DNS — then reports flow in on their own. You make this DNS change yourself; CyberMeters changes a DNS record only after you explicitly confirm the change.
            </p>
            <button onClick={activate} disabled={busy} className="btn-primary disabled:opacity-50">
              {busy ? <><RefreshCw className="w-4 h-4 animate-spin" /> Starting…</> : 'Start DMARC setup'}
            </button>
          </>
        ) : (
          <>
            <WizardStepper steps={steps} completed={stepDone} current={currentStep} />

            {/* Action-required banner — reports arriving but DNS not verified */}
            {needsDnsAction && (
              <div className="rounded-xl border border-[1.5px] border-brand-700 bg-transparent p-4 flex gap-2.5">
                <p className="text-sm text-brand-700">
                  {dnsKnown
                    ? 'Reports have been received, but your current DNS record does not include the CyberMeters reporting address yet. Add the recommended value below to complete setup.'
                    : 'Reports have been received. We couldn’t read your DNS record on the last scan to confirm the reporting address — add the recommended value below, then re-check after your next scan.'}
                </p>
              </div>
            )}

            {/* Step 1 — choose provider */}
            <div className="space-y-2">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">1 · Choose your DNS provider</p>
              <div className="flex flex-wrap gap-2">
                {DNS_PROVIDERS.map(p => (
                  <button key={p.id} onClick={() => setProvider(p.id)}
                    className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${provider === p.id ? 'border-brand-300 bg-brand-50 text-brand-700' : 'border-gray-200 bg-white text-gray-600 hover:bg-gray-50'}`}>
                    {p.label}
                  </button>
                ))}
              </div>
              {providerCopy && <p className="text-sm text-gray-600 leading-relaxed bg-gray-50 border border-gray-200 rounded-lg p-3">{providerCopy}</p>}
            </div>

            {/* Step 2 — copy the DNS record */}
            <div className="space-y-3">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">2 · Copy the DNS record</p>
              {present && existingRaw && !already && (
                <div className="rounded-lg border border-[1.5px] border-brand-700 bg-transparent p-3 text-sm text-brand-700 flex gap-2">
                  <span>You already have a DMARC record. <b>Do not delete it.</b> Just add the CyberMeters reporting address to the existing <code className="mono">rua=</code> tag — the value below already includes both.</span>
                </div>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-[auto_auto_1fr] gap-3">
                <CopyField label="Type" value="TXT" />
                <CopyField label="Name / Host" value="_dmarc" />
                <CopyField label="Value" value={recommendedValue} />
              </div>
              {present && existingRaw && (
                <p className="text-xs text-gray-500">Your current record: <code className="mono break-all">{existingRaw}</code></p>
              )}
              {!inboundAddress && <p className="text-xs text-gray-500">Your reporting address is being prepared — reopen this page in a moment if the value is blank.</p>}
            </div>

            {/* Step 3 — verify (auto-derived; button re-checks current data) */}
            <div className="space-y-2">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">3 · Verify setup{dnsVerified && <span className="ml-1.5 text-brand-700 normal-case font-medium">· verified</span>}</p>
              <div className={`rounded-lg border p-3 text-sm flex gap-2 ${vm.kind === 'good' ? 'border-brand-100 bg-brand-50/50 text-brand-800' : vm.kind === 'warn' ? 'border-[1.5px] border-brand-700 bg-transparent text-brand-700' : 'border-gray-200 bg-gray-50 text-gray-600'}`}>
                <span>{vm.text}</span>
              </div>
              <button onClick={verifyDns} disabled={checking} className="btn-secondary text-sm disabled:opacity-50">
                {checking ? <><RefreshCw className="w-4 h-4 animate-spin" /> Checking DNS…</> : 'Verify setup'}
              </button>
            </div>

            {/* Steps 4 & 5 — wait for reports / connected */}
            <div className="space-y-2">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
                4 · {fullyConnected ? 'Connected' : receiving ? 'Reports arriving · finish DNS' : 'Wait for reports'}
              </p>
              {fullyConnected ? (
                <div className="rounded-lg border border-brand-100 bg-brand-50/50 p-3 space-y-1.5">
                  <p className="text-sm text-brand-800">Connected — DMARC reports are arriving and your DNS record is verified for {domain}.</p>
                  <p className="text-xs text-gray-600">
                    Last report received: <b className="text-gray-700">{fmt(endpoint.last_inbound_at)}</b>.
                    {typeof totalMessages === 'number' && totalMessages > 0 && <> {formatNumber(totalMessages)} message(s) observed so far.</>} Your sender inventory has started below.
                  </p>
                </div>
              ) : receiving ? (
                <div className="rounded-lg border border-[1.5px] border-brand-700 bg-transparent p-3 space-y-1.5">
                  <p className="text-sm text-brand-700">Reports are arriving, but DNS is not verified yet.</p>
                  <p className="text-xs text-gray-600">
                    Last report received: <b className="text-gray-700">{fmt(endpoint.last_inbound_at)}</b>. Add the recommended value above to your DMARC record to finish setup — this becomes <b>Connected</b> once your record includes the CyberMeters address.
                  </p>
                </div>
              ) : (
                <p className="text-sm text-gray-600 leading-relaxed">
                  After you update DNS, reports may take <b>24–48 hours</b> to arrive — some providers send them once a day.
                  This card updates automatically once the first report is received.
                </p>
              )}
            </div>
          </>
        )}
        {err && <span className="text-sm text-red-700">{err}</span>}
      </div>
    </section>

    {/* Records CyberMeters can host: kept out of the reporting stepper above so
        its steps never read as belonging to MTA-STS or TLS-RPT. */}
    <section className="card overflow-hidden pb-5" aria-labelledby="hosted-email-records-title">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <span className="eyebrow">Hosted records</span>
        <h2 id="hosted-email-records-title" className="section-title leading-tight">Records CyberMeters can host for you</h2>
      </div>
      <ManagedDmarcCard wsId={wsId} domain={domain} endpointReady={Boolean(inboundMailto)} />
      <ManagedTlsRptCard wsId={wsId} domain={domain} endpointReady={Boolean(inboundMailto)} />
      <ManagedMtaStsCard wsId={wsId} domain={domain} />
      <TlsRptHealthCard wsId={wsId} domain={domain} />
    </section>
    </div>
  )
}

// ── Email Protection overview: connection status + checklist + ingestion ──────
// Customer-facing answer to "is automated DMARC/RUA ingestion working, and what
// do I do next?" Fetches the ingestion endpoint and derives DNS-verified from
// the latest scan's DMARC record (refined by a live check). Never shows
// "Connected" unless the CyberMeters RUA is in DNS AND a report has arrived.
function epFmt(t) { return pageTime(t) }

function EpStatusChecklist({ items }) {
  const ICON = {
    done:    { cls: 'text-brand-700',  txt: 'Done' },
    needs:   { cls: 'text-brand-700',  txt: 'Needs action' },
    waiting: { cls: 'text-gray-400',   txt: 'Waiting' },
    unknown: { cls: 'text-gray-600',   txt: 'Unknown' },
  }
  return (
    <div className="card p-5">
      <h3 className="section-title mb-3">Setup progress</h3>
      <ul className="space-y-2.5">
        {items.map(it => {
          const c = ICON[it.status] || ICON.unknown
          return (
            <li key={it.label} className="flex items-center gap-2.5">
              <span className="text-sm text-gray-700 flex-1">{it.label}</span>
              <span className={`text-xs font-medium ${c.cls}`}>{c.txt}</span>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

function EpMetric({ label, explanation, value }) {
  const known = value !== null && value !== undefined && value !== ''
  return (
    <div className="card p-5">
      <p className="text-sm font-semibold text-gray-900 leading-snug">{label}</p>
      <p className="text-xs text-gray-500 mt-1 leading-snug">{explanation}</p>
      <p className={`text-[14px] font-bold mt-2 tabular-nums ${known ? 'text-gray-800' : 'text-gray-400'}`}>
        {known ? (typeof value === 'number' ? formatNumber(value) : value) : 'Waiting'}
      </p>
    </div>
  )
}

const EP_MODE = {
  automatic:     { label: 'Automatic RUA',  tone: 'ok',   desc: 'Mailbox providers send aggregate DMARC reports directly to CyberMeters.' },
  assisted:      { label: 'Assisted upload', tone: 'info', desc: 'You can upload provider reports securely while DNS changes propagate.' },
  manual:        { label: 'Manual upload',  tone: 'info',  desc: 'Manual upload is useful for testing or importing historical reports.' },
  not_receiving: { label: 'Not receiving yet', tone: 'na', desc: 'No DMARC aggregate reports have been received yet.' },
}

// ── Zone divider — gives the long page a scannable rhythm ─────────────────────
// Remediation Registry surface: every hygiene gap with live detection and the
// exact one-click-copy fix. Where a competitor says "missing", we hand over the
// precise record and (for DMARC) offer to host + self-drive it.
function RemediationsPanel({ wsId, domain }) {
  const [items, setItems] = useState(null)
  const [openId, setOpenId] = useState(null)
  const [fix, setFix] = useState(null)

  useEffect(() => {
    if (!wsId || !domain) { setItems(null); return }
    let cancelled = false
    setItems(null); setOpenId(null); setFix(null)
    api.getRemediations(wsId, domain)
      .then(r => { if (!cancelled) setItems(r?.remediations || []) })
      .catch(() => { if (!cancelled) setItems([]) })
    return () => { cancelled = true }
  }, [wsId, domain])

  async function toggle(id) {
    if (openId === id) { setOpenId(null); setFix(null); return }
    setOpenId(id); setFix(null)
    try { setFix(await api.getRemediationFix(wsId, domain, id)) }
    catch { setFix({ error: true }) }
  }

  if (!items) return null
  const gaps = items.filter(i => i.applicable && !i.ok)
  const good = items.filter(i => i.applicable && i.ok)

  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70 flex items-center gap-2.5">
        <div>
          <span className="eyebrow">Auto-fix</span>
          <h2 className="section-title leading-tight">Security gaps &amp; one-click fixes</h2>
        </div>
        {gaps.length === 0 && good.length > 0 && (
          <span className="ml-auto inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-brand-50 border border-brand-100 text-xs font-semibold text-brand-700">
            All checks pass
          </span>
        )}
      </div>
      <div className="p-4 space-y-2">
        {[...gaps, ...good].map(item => {
          const open = openId === item.id
          return (
            <div key={item.id} className="rounded-lg border border-gray-200">
              <button onClick={() => toggle(item.id)} className="w-full flex items-center gap-3 px-4 py-3 text-left">
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-gray-900">{item.title}</p>
                  <p className="text-xs text-gray-400">
                    {/* Present-but-not-ok (e.g. DMARC at p=none) must not read as
                        "Not configured" — it exists, it just isn't protective yet. */}
                    {item.ok ? 'In place' : item.present ? 'Needs attention' : 'Not configured'}
                    {item.capability === 'hosted' && <span className="ml-1.5 text-brand-700 font-semibold">· CyberMeters can host this</span>}
                    {item.capability === 'guided' && <span className="ml-1.5 text-gray-500">· exact fix below</span>}
                  </p>
                </div>
                {!item.ok && <span className="text-xs text-brand-700 font-semibold">{open ? 'Hide' : 'Show fix'}</span>}
              </button>
              {open && (
                <div className="px-4 pb-4 border-t border-gray-100 pt-3 space-y-2">
                  {!fix ? (
                    <p className="text-xs text-gray-400 flex items-center gap-1.5"><RefreshCw className="w-3.5 h-3.5 animate-spin" /> Generating the exact fix…</p>
                  ) : fix.error ? (
                    <p className="text-xs text-gray-500">The fix could not be generated right now.</p>
                  ) : (
                    <>
                      {item.managed_via === 'hosted-dmarc' && (
                        <p className="text-xs text-brand-700 font-medium">Use the managed DMARC card above — CyberMeters hosts and self-drives this record for you.</p>
                      )}
                      {(fix.fix?.records || []).map((r, i) => (
                        <div key={i}>
                          <p className="text-xs font-semibold text-gray-500 mb-1">{r.type} · {r.name}</p>
                          <DnsValue value={r.value} />
                        </div>
                      ))}
                      {(fix.fix?.files || []).map((f, i) => (
                        <div key={`f${i}`}>
                          <p className="text-xs font-semibold text-gray-500 mb-1">Serve at {f.path}</p>
                          <DnsValue value={f.content} />
                        </div>
                      ))}
                      {fix.fix?.note && <p className="text-sm text-gray-500 leading-relaxed">{fix.fix.note}</p>}
                    </>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </section>
  )
}

// Section header without a number: #639 removed section numbering from the
// area pages, and it must not come back.
function ZoneHeader({ title, hint }) {
  return (
    <div className="flex items-center gap-3 pt-3">
      <div className="min-w-0 shrink-0">
        <h2 className="text-base font-bold text-gray-900 leading-tight">{title}</h2>
        {hint && <p className="text-xs text-gray-400 leading-tight mt-0.5">{hint}</p>}
      </div>
      <div className="flex-1 h-px bg-gray-100" />
    </div>
  )
}

// ── Email posture hero ────────────────────────────────────────────────────────
// One-glance answer that combines what competitors show separately: the DMARC
// compliance rate (technical), the policy state, AND the business impersonation
// exposure (business) — the last of which point-tools do not translate. Leads
// with meaning, ends with the single next action.
export function EmailPostureHero({ wsId, domain, dmarc, policyJourney, dmarcPresentation, onGoto }) {
  const [bec, setBec] = useState(null)
  const [liveDns, setLiveDns] = useState(null)
  const [rescan, setRescan] = useState(null) // null | 'starting' | 'started' | 'error'
  useEffect(() => {
    if (!wsId || !domain) { setBec(null); setLiveDns(null); return }
    let cancelled = false
    api.getBecExposureScore(wsId, domain).then(r => { if (!cancelled) setBec(r || null) }).catch(() => { if (!cancelled) setBec(null) })
    // Live DNS truth — lets us reconcile a stale scan against a now-published record.
    api.verifyDmarcDns(wsId, domain).then(r => { if (!cancelled) setLiveDns(r || null) }).catch(() => { if (!cancelled) setLiveDns(null) })
    setRescan(null)
    return () => { cancelled = true }
  }, [wsId, domain])

  async function handleRescan() {
    setRescan('starting')
    try { await api.createScan(domain, wsId); setRescan('started') }
    catch { setRescan('error') }
  }

  const total    = dmarc?.traffic_by_source?.auto_ingested?.total_messages ?? 0
  const passRate = dmarc?.traffic_by_source?.auto_ingested?.pass_rate
  const hasCompliance = total > 0 && passRate != null
  const scanStage = policyJourney?.stage || null
  // Reconcile against live DNS: the live record is more current than the last
  // scan, so whenever it's healthy we trust IT for the policy state — covering
  // both a just-published record (scan said "No DMARC") and a just-changed
  // policy (scan said "monitoring" but it's now quarantine/reject). Only a
  // SINGLE valid record counts — multiple_dmarc_records and invalid_dmarc are
  // "present but broken". Live-lookup failures fall back to the scan (fail-safe).
  const liveDmarcHealthy = liveDns?.status === 'verified' || liveDns?.status === 'missing_cybermeters_rua'
  const livePolicyStage  = liveDns?.policy === 'reject' ? 'full_enforcement'
    : liveDns?.policy === 'quarantine' ? 'partial_enforcement'
    : liveDmarcHealthy ? 'monitoring' : null
  const stage = (liveDmarcHealthy && livePolicyStage != null) ? livePolicyStage : scanStage
  // The scan is "stale" whenever live DNS disagrees with it — nudge a re-scan
  // so compliance/exposure catch up to the current record.
  const staleScan = liveDmarcHealthy && livePolicyStage != null && livePolicyStage !== scanStage
  const currentPresentation = dmarcPresentation?.status === 'current'
  const effectiveRequestedPolicy =
    currentPresentation
      ? dmarcPresentation?.policy?.effective_requested
      : null
  const stageLabel = currentPresentation
    ? (dmarcPresentation?.policy?.effective_requested_label || 'Not determined')
    : ({ missing: 'No DMARC', monitoring: 'No-action policy',
        partial_enforcement: 'Quarantine requested',
        full_enforcement: 'Rejection requested' }[stage] || 'Unknown')
  const strongerRequested = currentPresentation
    ? ['quarantine', 'reject'].includes(effectiveRequestedPolicy)
    : ['partial_enforcement', 'full_enforcement'].includes(stage)
  const cCol = !hasCompliance ? 'text-gray-400' : passRate >= 95 ? 'text-brand-700'
    : passRate >= 80 ? 'text-brand-700' : 'text-red-700'
  const sev = bec ? becSev(bec.exposure_level) : null

  const next = staleScan ? { label: `Re-scan ${domain}`, rescan: true }
    : scanStage === 'missing' ? { label: 'Publish a DMARC record', to: 'dmarc-setup' }
    : !hasCompliance ? { label: 'Connect DMARC reporting', to: 'connect-reporting' }
    : !strongerRequested ? { label: 'Review a stronger policy', to: 'dmarc-setup' }
    : (passRate != null && passRate < 95) ? { label: 'Fix sender alignment', to: 'sender-inventory' }
    : { label: 'Review sender inventory', to: 'sender-inventory' }

  const pill = (txt, tone) => (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold border ${
      tone === 'ok' ? 'bg-brand-50 text-brand-700 border-brand-100'
      : tone === 'warn' ? 'bg-transparent text-brand-700 border-[1.5px] border-brand-700'
      : tone === 'bad' ? 'bg-red-50 text-red-700 border-red-200'
      : 'bg-gray-50 text-gray-500 border-gray-200'}`}>{txt}</span>
  )

  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70 flex items-center gap-2.5">
        <div className="min-w-0">
          <span className="eyebrow">Email protection posture</span>
          <h2 className="section-title leading-tight truncate">What did CyberMeters observe for {domain}?</h2>
        </div>
      </div>

      <div className="p-6 grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Compliance — the technical number email teams live by */}
        <div>
          <p className="text-sm font-semibold text-gray-900">Automatically ingested RUA · DMARC compliance</p>
          <p className={`text-3xl font-black mt-1 tabular-nums ${cCol}`}>{hasCompliance ? `${passRate}%` : '—'}</p>
          <p className="text-xs text-gray-500 mt-1 leading-relaxed">
            {hasCompliance
              ? `of ${formatNumber(total)} messages passed SPF/DKIM alignment over the reporting window.`
              : staleScan ? 'Re-scan to measure compliance against your newly published DMARC record.'
              : 'Not measured yet — connect DMARC reporting to see who is sending as you.'}
          </p>
        </div>
        {/* Policy state */}
        <div className="md:border-l md:border-gray-100 md:pl-5">
          <p className="text-sm font-semibold text-gray-900">DMARC policy</p>
          <div className="mt-1.5 flex items-center gap-1.5 flex-wrap">
            {pill(stageLabel, strongerRequested ? 'ok' : stage === 'missing' ? 'bad' : 'warn')}
            {staleScan && (
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700">
                Live in DNS
              </span>
            )}
          </div>
          <p className="text-xs text-gray-500 mt-2 leading-relaxed">
            {currentPresentation
              ? dmarcPresentation.policy?.message
              : staleScan ? 'Your DMARC record is published and was just observed in live DNS — your last scan predates it. Re-scan for a complete current policy assessment.'
              : stage === 'missing' ? 'No exact-domain policy was observed in the legacy scan projection.'
              : strongerRequested ? 'The published policy requests stronger receiver handling; actual receiver handling was not observed.'
              : 'The legacy scan projection shows a no-action policy.'}
          </p>
        </div>
        {/* Business exposure — the layer point-tools do not translate */}
        <div className="md:border-l md:border-gray-100 md:pl-5">
          <p className="text-sm font-semibold text-gray-900">Business exposure</p>
          {sev ? (
            <>
              <p className={`text-xl font-bold mt-1 ${sev.text}`}>{titleCase(bec.exposure_level)}</p>
              <p className="text-xs text-gray-500 mt-1 leading-relaxed">
                Impersonation &amp; invoice-fraud exposure. The BEC assessment below shows the score and its source.
              </p>
            </>
          ) : (
            <p className="text-xs text-gray-400 mt-2">Calculating business exposure…</p>
          )}
        </div>
      </div>

      <div className="px-6 py-3 border-t border-gray-100 bg-brand-50/40 flex items-center justify-between gap-3">
        <p className="text-xs font-semibold text-brand-700 uppercase tracking-wide">
          {rescan === 'started' ? 'Re-scan started' : 'Do this next'}
        </p>
        {rescan === 'started' ? (
          <span className="text-sm text-brand-700 font-medium">Results refresh once the scan completes.</span>
        ) : (
          <div className="flex items-center gap-2">
            {rescan === 'error' && <span className="text-xs text-red-700 font-medium">Couldn’t start — retry</span>}
            <button
              onClick={() => (next.rescan ? handleRescan() : onGoto?.(next.to))}
              disabled={rescan === 'starting'}
              className="btn-primary text-sm disabled:opacity-60"
            >
              {rescan === 'starting'
                ? (<>Starting… <RefreshCw className="w-4 h-4 animate-spin" /></>)
                : next.label}
            </button>
          </div>
        )}
      </div>
    </section>
  )
}

export function dmarcTrafficSourceLabel(dmarc) {
  const sources = dmarc?.traffic_by_source
  const automatic = Number(sources?.auto_ingested?.total_messages) || 0
  const uploaded = Number(sources?.customer_uploaded?.total_messages) || 0
  if (automatic > 0 && uploaded > 0) return 'automatically received RUA and customer-uploaded reports'
  if (automatic > 0) return 'automatically received RUA reports'
  if (uploaded > 0) return 'customer-uploaded reports'
  return 'report source not recorded'
}

export function EmailProtectionOverview({ wsId, domain, dmarcDetail, dmarc, senderData, onGotoSetup, onGotoSenders }) {
  const [endpoint, setEndpoint] = useState(null)
  const [liveStatus, setLiveStatus] = useState(null)
  const [checking, setChecking] = useState(false)

  const refreshEndpoint = useCallback(async () => {
    if (!domain) return
    try { const r = await api.getDmarcIngestEndpoint(wsId, domain); setEndpoint(r?.endpoint || null) }
    catch { setEndpoint(null) }
  }, [wsId, domain])
  useEffect(() => { setLiveStatus(null); refreshEndpoint() }, [refreshEndpoint])

  async function verify() {
    setChecking(true)
    try { const r = await api.verifyDmarcDns(wsId, domain); setLiveStatus(r?.status || 'dns_lookup_failed') }
    catch { setLiveStatus('dns_lookup_failed') }
    finally { setChecking(false) }
    refreshEndpoint()
  }

  // ── derive state from real data ──
  const inboundAddress = endpoint?.inbound_address || null
  const inboundMailto  = inboundAddress ? `mailto:${inboundAddress}`.toLowerCase() : null
  const existingRua    = Array.isArray(dmarcDetail?.rua) ? dmarcDetail.rua : []
  const ruaNorm        = existingRua.map(r => (String(r).startsWith('mailto:') ? String(r) : `mailto:${r}`).toLowerCase())
  const dnsHasRua      = inboundMailto ? ruaNorm.includes(inboundMailto) : false
  const dmarcPresent   = Boolean(dmarcDetail?.present) || Boolean(dmarcDetail?.raw)
  const dnsVerified    = liveStatus ? liveStatus === 'verified' : dnsHasRua
  const reportsRcvd    = Boolean(endpoint?.last_inbound_at)
  const sendersCount   = senderData?.senders?.length ?? senderData?.summary?.total_senders ?? null
  // Keep all three message counts in one reporting window and evidence scope.
  // Sender inventory counters can cover different reports; never fill gaps from them.
  const messages       = dmarc?.traffic?.total_messages ?? null
  const aligned        = dmarc?.traffic?.aligned_messages ?? null
  const unaligned      = dmarc?.traffic?.failed_messages ?? null
  const trafficPeriod  = `${dmarc?.period_days ? `Last ${dmarc.period_days} days` : 'Selected reporting window'} · ${dmarcTrafficSourceLabel(dmarc)}`
  const hasData        = (messages || 0) > 0 || (sendersCount || 0) > 0

  let state
  if (reportsRcvd && dnsVerified) state = 'connected'
  else if (reportsRcvd) state = 'receiving'
  else if (dnsVerified) state = 'waiting'
  else if (dmarcPresent && inboundAddress) state = 'dns_not_verified'
  else state = 'not_configured'

  const STATE = {
    not_configured:   { tone: 'na',   title: 'Not configured',         msg: 'Add the CyberMeters RUA address to your DMARC record so reports can be received.' },
    dns_not_verified: { tone: 'warn', title: 'DNS not verified',      msg: 'CyberMeters is not listed in your DMARC rua tag yet.' },
    waiting:          { tone: 'info', title: 'Waiting for reports',     msg: 'DNS is ready. Reports usually arrive after mailbox providers send aggregate DMARC reports.' },
    receiving:        { tone: 'warn', title: 'Receiving reports · DNS not verified', msg: 'CyberMeters has received DMARC reports for this domain. Finish DNS verification to fully connect.' },
    connected:        { tone: 'ok',   title: 'Connected',               msg: 'DMARC reporting is connected and receiving data.' },
  }[state]
  const PANEL = {
    ok:   'border-brand-100 bg-brand-50/50',
    warn: 'border-[1.5px] border-brand-700 bg-transparent',
    info: 'border-blue-100 bg-blue-50/40',
    na:   'border-gray-200 bg-gray-50',
  }[STATE.tone]

  const VERIFY_MSG = {
    verified:               { ok: true,  text: 'CyberMeters RUA found in your DMARC record.' },
    missing_cybermeters_rua:{ ok: false, text: 'DMARC exists, but the CyberMeters RUA address is missing.' },
    no_dmarc:               { ok: false, text: 'No DMARC record found.' },
    invalid_dmarc:          { ok: false, text: 'A DMARC record was found but could not be read as valid.' },
    multiple_dmarc_records: { ok: false, text: 'Multiple DMARC records found — DNS allows only one.' },
    endpoint_missing:       { ok: false, text: 'Create your reporting address first, then re-check.' },
    dns_lookup_failed:      { ok: false, text: 'DNS lookup failed. This is common while DNS updates — try again shortly.' },
  }
  const vr = liveStatus ? (VERIFY_MSG[liveStatus] || VERIFY_MSG.dns_lookup_failed) : null

  const checklist = [
    { label: 'DMARC record found',           status: dmarcDetail == null ? 'unknown' : dmarcPresent ? 'done' : 'needs' },
    { label: 'CyberMeters RUA address added', status: dnsHasRua ? 'done' : inboundAddress ? 'needs' : 'waiting' },
    { label: 'DNS verification completed',    status: dnsVerified ? 'done' : inboundAddress ? 'needs' : 'waiting' },
    { label: 'First report received',         status: reportsRcvd ? 'done' : 'waiting' },
    { label: 'Sender inventory populated',    status: (sendersCount || 0) > 0 ? 'done' : 'waiting' },
  ]

  const mode = reportsRcvd ? 'automatic' : endpoint?.last_signed_upload_at ? 'assisted' : hasData ? 'manual' : 'not_receiving'
  const modeCfg = EP_MODE[mode]
  const modeChip = { ok: 'bg-brand-50 text-brand-700 border-brand-100', info: 'bg-blue-50 text-blue-700 border-blue-100', na: 'bg-gray-50 text-gray-500 border-gray-200' }[modeCfg.tone]

  const next = state === 'connected'
    ? { text: 'Review your sender inventory.', cta: 'Review sender inventory', act: onGotoSenders }
    : state === 'waiting'
      ? { text: 'Your DNS is ready — reports will appear automatically once providers send them.', cta: null }
      : { text: 'Add the CyberMeters RUA address to your DMARC record, then verify.', cta: 'Go to DMARC setup', act: onGotoSetup }

  return (
    <div className="space-y-4">
      {/* Connection status panel */}
      <section className={`card p-5 border ${PANEL}`}>
        <div className="flex items-start gap-3">
          <div className="flex-1 min-w-0">
            <p className="text-base font-bold text-gray-900">{STATE.title}</p>
            <p className="text-sm text-gray-600 mt-0.5 leading-relaxed">{STATE.msg}</p>
            {next?.text && <p className="text-xs text-gray-500 mt-2">{next.text}</p>}
          </div>
          <div className="flex flex-col items-end gap-2 shrink-0">
            <button onClick={verify} disabled={checking || !domain} className="btn-secondary text-sm disabled:opacity-50">
              {checking ? <><RefreshCw className="w-4 h-4 animate-spin" /> Checking DNS…</> : 'Verify setup'}
            </button>
            {next?.cta && next.act && (
              <button onClick={next.act} className="text-xs font-medium text-brand-700 hover:text-brand-800">{next.cta} →</button>
            )}
          </div>
        </div>
        {vr && (
          <div className={`mt-3 rounded-lg border p-2.5 text-sm flex items-center gap-2 ${vr.ok ? 'border-brand-100 bg-brand-50/60 text-brand-800' : 'border-[1.5px] border-brand-700 bg-transparent text-brand-700'}`}>
            {vr.text}
          </div>
        )}
      </section>

      {/* Metric cards (label-led, numbers below & smaller) */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <EpMetric label="Messages observed" explanation={`${trafficPeriod} · DMARC reports`} value={messages} />
        <EpMetric label="Aligned messages"  explanation={`${trafficPeriod} · passed alignment`} value={aligned} />
        <EpMetric label="Unaligned messages" explanation={`${trafficPeriod} · failed alignment`} value={unaligned} />
        <EpMetric label="Known senders"      explanation="Sources seen in reports"       value={hasData ? (sendersCount || 0) : null} />
        <EpMetric label="Last report received" explanation="Most recent inbound report"  value={epFmt(endpoint?.last_inbound_at)} />
      </div>

      {/* Setup progress checklist (ingestion status now lives in its own card below) */}
      <EpStatusChecklist items={checklist} />
    </div>
  )
}

// ── Business Email Compromise exposure (backend source of truth) ──────────────
// EXPOSURE/RISK score: higher = worse. Never styled like the Cyber Metrics
// Score (where higher is better). Meaning leads; the number is small + below.
const BEC_SEV = {
  critical: { text: 'text-red-700',   chip: 'bg-red-50 text-red-700 border-red-200',     accent: 'accent-danger' },
  high:     { text: 'text-red-700',   chip: 'bg-red-50 text-red-700 border-red-200',     accent: 'accent-danger' },
  medium:   { text: 'text-brand-700', chip: 'bg-transparent text-brand-700 border-[1.5px] border-brand-700', accent: 'accent-warning' },
  low:      { text: 'text-brand-700', chip: 'bg-brand-50 text-brand-700 border-brand-100', accent: '' },
  minimal:  { text: 'text-brand-700', chip: 'bg-brand-50 text-brand-700 border-brand-100', accent: '' },
}
const becSev = (l) => BEC_SEV[String(l || '').toLowerCase()] || BEC_SEV.medium
const titleCase = (s) => (s ? String(s).replace(/[_-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : '—')
const becChipCls = (tone) => tone === 'ok' ? 'bg-brand-50 text-brand-700 border-brand-100'
  : tone === 'warn' ? 'bg-transparent text-brand-700 border-[1.5px] border-brand-700' : 'bg-gray-50 text-gray-600 border-gray-200'

function becEvidenceChips(ev) {
  if (!ev || typeof ev !== 'object') return []
  const out = []
  const has = (k) => ev[k] !== undefined && ev[k] !== null
  if (has('dmarc_policy'))   out.push({ label: `DMARC: ${ev.dmarc_policy}`, tone: ev.dmarc_policy === 'none' ? 'warn' : 'neutral' })
  if (Object.hasOwn(ev, 'pass_rate')) out.push(Number(ev.total_messages) > 0 && typeof ev.pass_rate === 'number'
    ? { label: `Pass rate in reports you uploaded: ${ev.pass_rate}%`, tone: ev.pass_rate < 90 ? 'warn' : 'neutral' }
    : { label: 'Pass rate in reports you uploaded: not measured', tone: 'neutral' })
  if (has('failed_messages'))out.push({ label: `${ev.failed_messages} failed`, tone: ev.failed_messages > 0 ? 'warn' : 'neutral' })
  if (has('unknown_senders'))out.push({ label: `${ev.unknown_senders} unknown sender${ev.unknown_senders === 1 ? '' : 's'}`, tone: ev.unknown_senders > 0 ? 'warn' : 'neutral' })
  if (has('suspicious_senders')) out.push({ label: `${ev.suspicious_senders} suspicious`, tone: ev.suspicious_senders > 0 ? 'warn' : 'neutral' })
  if (has('high_volume_failing_senders')) out.push({ label: `${ev.high_volume_failing_senders} high-volume failing`, tone: ev.high_volume_failing_senders > 0 ? 'warn' : 'neutral' })
  if (has('reports_received')) out.push({ label: ev.reports_received ? 'Customer-submitted reports available' : 'No customer-submitted reports for this assessment', tone: ev.reports_received ? 'ok' : 'neutral' })
  if (has('cybermeters_rua_verified')) out.push({ label: ev.cybermeters_rua_verified ? 'RUA verified in DNS' : 'RUA not verified in DNS', tone: ev.cybermeters_rua_verified ? 'ok' : 'warn' })
  return out
}

export function BecExposure({ wsId, domain }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [errState, setErrState] = useState(null) // 'not_available' | 'forbidden' | 'failed'

  useEffect(() => {
    let cancelled = false
    if (!wsId || !domain) { setLoading(false); setData(null); return }
    setLoading(true); setErrState(null); setData(null)
    api.getBecExposureScore(wsId, domain)
      .then(res => { if (!cancelled) setData(res || null) })
      .catch(e => {
        if (cancelled) return
        if (e.status === 404) setErrState('not_available')
        else if (e.status === 403) setErrState('forbidden')
        else setErrState('failed')
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [wsId, domain])

  const sev = becSev(data?.exposure_level)
  const chips = becEvidenceChips(data?.evidence)
  const reasons = (Array.isArray(data?.reasons) ? data.reasons.slice(0, 4) : []).map(reason => reason.code === 'no_dmarc_reports'
    ? { ...reason, label: 'No customer-submitted reports for this assessment', detail: 'Automatically received reports remain visible in sender activity. This assessment uses reports uploaded through your workspace.' }
    : reason)
  const actions = (Array.isArray(data?.recommended_actions) ? data.recommended_actions.slice(0, 3) : []).map(action => action.code === 'enable_dmarc_reporting'
    ? { ...action, label: 'Add a report to this assessment', detail: 'Upload an existing DMARC report through your workspace to include its sender evidence here.' }
    : action)

  return (
    <section className={`card overflow-hidden ${data ? sev.accent : ''}`}>
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <span className="eyebrow">Email risk</span>
        <h2 className="section-title leading-tight">Business Email Compromise exposure</h2>
        <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">Estimated from customer-uploaded DMARC reports, sender alignment, RUA verification and brand impersonation evidence.</p>
      </div>

      <div className="p-6">
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-gray-500"><RefreshCw className="w-4 h-4 animate-spin" /> Calculating BEC exposure from current email evidence…</div>
        ) : errState ? (
          <p className="text-sm text-gray-500">
            {errState === 'not_available' ? 'BEC Exposure is not available for this domain yet.'
              : errState === 'forbidden' ? 'You do not have permission to view BEC Exposure for this workspace.'
              : 'BEC Exposure could not be calculated right now. Review the available Email Protection evidence or try again later.'}
          </p>
        ) : !data ? (
          <p className="text-sm text-gray-500">BEC Exposure is not available for this domain yet.</p>
        ) : (
          <div className="space-y-5">
            {/* Core: meaning first, number small & below */}
            <div className="flex flex-col lg:flex-row lg:items-start gap-5">
              <div className="lg:w-72 shrink-0">
                <p className="text-sm font-semibold text-gray-900">Exposure level</p>
                <p className={`text-lg font-bold ${sev.text}`}>{titleCase(data.exposure_level)}</p>
                <p className="text-sm text-gray-600 mt-1 leading-relaxed">
                  BEC Exposure measures how exposed this domain is to spoofing, supplier impersonation and invoice-fraud abuse.
                </p>
                <p className="text-[14px] font-bold text-gray-700 mt-2 tabular-nums">
                  Score {data.exposure_score}/100 <span className="font-medium text-gray-500">· Higher means more exposed</span>
                </p>
                {data.confidence && (
                  <span className="inline-flex items-center mt-2 px-2 py-0.5 rounded-full text-xs font-semibold border bg-gray-50 text-gray-600 border-gray-200">
                    Confidence: {titleCase(data.confidence)}
                  </span>
                )}
              </div>
              {data.summary && <p className="text-sm text-gray-600 leading-relaxed flex-1">{data.summary}</p>}
            </div>

            {/* Evidence chips */}
            {chips.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">Evidence from reports you uploaded</p>
                <p className="text-xs text-gray-500 mb-2">Sender figures here use customer-submitted reports. Automatically received reports appear separately in sender activity and do not establish trust in the sender.</p>
                <div className="flex flex-wrap gap-1.5">
                  {chips.map((c, i) => (
                    <span key={i} className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold border ${becChipCls(c.tone)}`}>{c.label}</span>
                  ))}
                </div>
              </div>
            )}

            {/* Reasons + recommended actions */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {reasons.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Why this domain is exposed</p>
                  <ul className="space-y-2.5">
                    {reasons.map((r, i) => (
                      <li key={r.code || i} className="text-sm">
                        <div className="flex items-center gap-2">
                          <span className={`inline-flex px-1.5 py-0.5 rounded-sm text-xs font-bold uppercase border ${becSev(r.severity).chip}`}>{r.severity || '—'}</span>
                          <span className="font-semibold text-gray-800">{r.label}</span>
                        </div>
                        {r.detail && <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{r.detail}</p>}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {actions.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">Reduce exposure</p>
                  <ul className="space-y-2.5">
                    {actions.map((a, i) => (
                      <li key={a.code || i} className="text-sm">
                        <div className="flex items-center gap-2">
                          <span className={`inline-flex px-1.5 py-0.5 rounded-sm text-xs font-bold uppercase border ${becSev(a.priority).chip}`}>{a.priority || '—'}</span>
                          <span className="font-semibold text-gray-800">{a.label}</span>
                        </div>
                        {a.detail && <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{a.detail}</p>}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  )
}

// Receipt comes from completed DMARC history, independently of BEC eligibility.
// The endpoint timestamp also covers TLS-RPT and cannot prove DMARC receipt.
export function DmarcIngestionStatus({ wsId, domain, onGotoSetup, onGotoSenders }) {
  const [bec, setBec] = useState(null)
  const [history, setHistory] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    if (!wsId || !domain) { setLoading(false); return }
    setLoading(true); setBec(null); setHistory(null)
    Promise.allSettled([api.getBecExposureScore(wsId, domain), api.getDmarcReportHistory(wsId, domain, 1)])
      .then(([b, h]) => {
        if (cancelled) return
        setBec(b.status === 'fulfilled' ? (b.value || null) : null)
        setHistory(h.status === 'fulfilled' ? (h.value || null) : null)
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [wsId, domain])

  const ev = bec?.evidence || {}
  const reportsReceived = history?.totals?.reports != null ? Number(history.totals.reports) > 0 : null
  const dnsVerified = ev.cybermeters_rua_verified != null ? Boolean(ev.cybermeters_rua_verified) : null // null = unknown
  const lastReportPeriod = history?.totals?.last_seen
  const hasMeasuredMessages = Number(ev.total_messages) > 0
  const passRate = hasMeasuredMessages ? ev.pass_rate : null
  const failed = ev.failed_messages
  const known = ev.known_senders
  const unknown = ev.unknown_senders
  const suspicious = ev.suspicious_senders
  const hiVolFail = ev.high_volume_failing_senders

  // States A–D. DNS unknown is treated as "not verified" for labelling so we
  // never overclaim — but the chip shows "Unknown" rather than asserting a fault.
  let state
  if (reportsReceived === null) state = 'U'
  else if (!reportsReceived && dnsVerified === true) state = 'D'
  else if (!reportsReceived) state = 'A'
  else if (dnsVerified === true) state = 'B'
  else state = 'C'

  const STATE = {
    U: { tone: 'na', label: 'Report status unavailable',
         msg: 'DMARC report history could not be loaded.',
         next: 'Refresh this page to check report receipt.' },
    // "Waiting for first report" (founder-approved wording, S1-SHELL-V2).
    A: { tone: 'na',   label: 'Waiting for first report',
         msg: 'CyberMeters has not received DMARC aggregate reports for this domain yet.',
         next: 'Add the CyberMeters reporting address to your DMARC record.', cta: 'View setup instructions', act: onGotoSetup },
    B: { tone: 'ok',   label: 'Reports received',
         msg: 'DMARC reports have been received or imported, and the reporting address is present in DNS.',
         next: 'Review who is sending email using this domain.', cta: 'Review sender activity', act: onGotoSenders },
    C: { tone: 'warn', label: 'Reports received · DNS not verified',
         msg: 'DMARC reports have been received or imported, but the reporting address is not verified in DNS. Report receipt alone does not verify the setup.',
         next: 'Update your DMARC record to include the CyberMeters reporting address.', cta: 'Finish DNS setup', act: onGotoSetup },
    D: { tone: 'info', label: 'DNS verified · waiting for reports',
         msg: 'Your DMARC record includes the CyberMeters reporting address. Reports may take 24–48 hours to arrive depending on mail volume and receivers.',
         next: 'No action needed — reports will appear automatically.', cta: 'Review setup', act: onGotoSetup },
  }[state]
  const PANEL = { ok: 'border-brand-100 bg-brand-50/50', warn: 'border-[1.5px] border-brand-700 bg-transparent', info: 'border-blue-100 bg-blue-50/40', na: 'border-gray-200 bg-gray-50' }[STATE.tone]
  const dnsLabel = dnsVerified === true ? 'Verified' : dnsVerified === false ? 'Not verified' : 'Unknown'

  const tiles = [
    { label: 'Reports received', value: reportsReceived === null ? 'Unknown' : reportsReceived ? 'Yes' : 'No', tone: reportsReceived ? 'ok' : 'na' },
    { label: 'Latest report period', value: lastReportPeriod ? formatReportDay(new Date(Number(lastReportPeriod) * 1000)) : reportsReceived === false ? 'Not yet' : 'Not available' },
    { label: 'DNS verification', value: dnsLabel, tone: dnsVerified === false ? 'warn' : dnsVerified ? 'ok' : 'na' },
  ]
  if (bec) tiles.push({ label: 'DMARC pass rate in reports you uploaded', value: passRate != null ? `${passRate}%` : 'Not measured', tone: passRate == null ? 'na' : passRate < 90 ? 'warn' : 'ok' })

  const hasSenders = hasMeasuredMessages && (known != null || unknown != null || suspicious != null)
  const senderSummary = hasSenders ? [
    { label: 'Known', value: known ?? 0 },
    { label: 'Unknown', value: unknown ?? 0, tone: (unknown ?? 0) > 0 ? 'warn' : '' },
    { label: 'Suspicious', value: suspicious ?? 0, tone: (suspicious ?? 0) > 0 ? 'warn' : '' },
    { label: 'High-volume failing', value: hiVolFail ?? 0, tone: (hiVolFail ?? 0) > 0 ? 'warn' : '' },
  ] : null

  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <span className="eyebrow">Email reporting</span>
        <h2 className="section-title leading-tight">DMARC report ingestion</h2>
      </div>
      <div className="p-6 space-y-5">
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-gray-500"><RefreshCw className="w-4 h-4 animate-spin" /> Checking report ingestion…</div>
        ) : (
          <>
            <div className={`rounded-xl border p-4 ${PANEL}`}>
              <div className="flex flex-col sm:flex-row sm:items-start gap-3">
                <div className="flex-1 min-w-0">
                  <p className="text-base font-bold text-gray-900">{STATE.label}</p>
                  <p className="text-sm text-gray-600 mt-0.5 leading-relaxed">{STATE.msg}</p>
                </div>
                {STATE.act && <button onClick={STATE.act} className="btn-secondary text-sm shrink-0">{STATE.cta}</button>}
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {tiles.map(t => (
                <div key={t.label} className="rounded-xl border border-gray-200 bg-white px-3 py-2.5">
                  <p className="text-xs font-semibold text-gray-700 leading-snug">{t.label}</p>
                  <p className={`text-[14px] font-bold mt-1 tabular-nums ${t.tone === 'warn' ? 'text-brand-700' : t.tone === 'ok' ? 'text-brand-700' : t.tone === 'na' ? 'text-gray-400' : 'text-gray-800'}`}>
                    {typeof t.value === 'number' ? formatNumber(t.value) : t.value}
                  </p>
                </div>
              ))}
            </div>

            <div className="rounded-xl border border-gray-200 bg-gray-50 p-4 flex flex-col sm:flex-row sm:items-center gap-3">
              <div className="flex-1">
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Recommended next step</p>
                <p className="text-sm text-gray-700 mt-0.5">{STATE.next}</p>
              </div>
              {STATE.act && <button onClick={STATE.act} className="btn-primary text-sm shrink-0">{STATE.cta}</button>}
            </div>

            {senderSummary && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Customer-submitted sender activity · BEC assessment</p>
                  <button onClick={onGotoSenders} className="text-xs font-medium text-brand-700 hover:text-brand-800">View full inventory →</button>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {senderSummary.map(s => (
                    <div key={s.label} className="rounded-lg border border-gray-200 bg-white px-3 py-2">
                      <p className="text-xs font-semibold text-gray-700 leading-snug">{s.label} senders</p>
                      <p className={`text-[14px] font-bold mt-1 tabular-nums ${s.tone === 'warn' ? 'text-brand-700' : 'text-gray-800'}`}>{s.value}</p>
                    </div>
                  ))}
                </div>
                {(passRate != null || failed != null) && (
                  <p className="text-xs text-gray-500 mt-2 leading-relaxed">
                    {passRate != null && <>DMARC pass rate <b className="text-gray-700">{passRate}%</b>. </>}
                    {failed != null && <><b className="text-gray-700">{formatNumber(Number(failed))}</b> message(s) failed alignment. </>}
                    Reports can arrive from previous or partial DMARC configurations, so review senders before tightening policy.
                  </p>
                )}
              </div>
            )}

            {state === 'C' && (
              <p className="text-xs text-gray-500 leading-relaxed">
                <b>Why this matters:</b> received or uploaded reports show available data. They do not authenticate the report producer or confirm that automatic reporting is correctly configured.
              </p>
            )}
          </>
        )}
      </div>
    </section>
  )
}

// ── Lightweight toast ─────────────────────────────────────────────────────────
function Toast({ toast, onClose }) {
  if (!toast) return null
  const ok = toast.kind === 'ok'
  return (
    <div className={`flex items-center gap-2.5 px-4 py-3 rounded-xl border text-sm ${ok ? 'bg-brand-50 border-brand-100 text-brand-800' : 'bg-red-50 border-red-100 text-red-700'}`}>
      <span className="flex-1">{toast.msg}</span>
      <button onClick={onClose} className="text-gray-400 hover:text-gray-700" aria-label="Close sender detail"><X className="w-4 h-4" /></button>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export function MxRecordsCard({ intelligence, transport }) {
  const records = intelligence?.starttls?.mx_records ?? intelligence?.mx_records
  return <div className="card p-5" data-testid="email-mx-records">
    <h3 className="text-sm font-semibold text-gray-900">MX records</h3>
    {!Array.isArray(records) ? (
      <p className="text-sm text-gray-500 mt-2">MX evidence was not available in this assessment.</p>
    ) : records.length === 0 ? (
      <p className="text-sm text-gray-500 mt-2">No MX records were recorded in this assessment.</p>
    ) : (
      <ul className="mt-2 space-y-1 text-sm text-gray-700">
        {records.map((record, index) => <li key={`${record.host}-${record.priority}-${index}`} className="break-all">
          {record.host || 'Host not recorded'}{record.priority != null && ` · priority ${record.priority}`}
        </li>)}
      </ul>
    )}
    <p className="text-xs text-gray-500 mt-2">These are DNS MX records from the scan. {transport?.coverage?.tested ? 'See the mail transport test below.' : 'Mail transport was not tested in this scan.'}</p>
  </div>
}

// Shared with the scan's Technical Details tab (components/MailTransportCard.jsx).
export { MailTransportCard }

export default function WorkspaceEmailProtectionPage() {
  const { wsId, wsName } = useWorkspace()

  const [scans, setScans]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [selectedDomain, setSelectedDomain] = useState(null)
  const [report, setReport]     = useState(null)
  const [reportLoading, setReportLoading] = useState(false)
  const goToAnchor = useAreaAnchor()
  const [summaryRows, setSummaryRows] = useState([])

  // DMARC Sender Intelligence (new endpoints, keyed by selected domain)
  const [dmarc, setDmarc]         = useState(null)   // dmarc-summary response
  const [senderData, setSenderData] = useState(null) // email-senders response
  const [siLoading, setSiLoading] = useState(false)
  // Migration 088's append-only history. Loaded independently so this additive section can
  // never break the page a customer came here to use.
  const [lifecycle, setLifecycle] = useState(null)
  const [lifecycleError, setLifecycleError] = useState(null)
  const [classifyingId, setClassifyingId] = useState(null)
  const [importing, setImporting] = useState(false)
  const [importResult, setImportResult] = useState(null)
  const [importError, setImportError]   = useState(null)
  const [toast, setToast]         = useState(null)

  // Latest completed scan per domain
  const domainScans = useMemo(() => {
    const map = new Map()
    for (const s of scans) {
      if (!s.domain || !COMPLETED.has(s.status)) continue
      const prev = map.get(s.domain)
      if (!prev || parseServerDate(s.created_at) > parseServerDate(prev.created_at)) map.set(s.domain, s)
    }
    return [...map.values()].sort((a, b) => parseServerDate(b.created_at) - parseServerDate(a.created_at))
  }, [scans])

  const loadScans = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const data = await api.getWorkspaceScans(wsId)
      setScans(data.scans || [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { loadScans() }, [loadScans])

  // Default selected domain → most recent completed scan
  useEffect(() => {
    if (!selectedDomain && domainScans.length > 0) setSelectedDomain(domainScans[0].domain)
  }, [domainScans, selectedDomain])

  // Load the report for the selected domain
  useEffect(() => {
    const scan = domainScans.find(s => s.domain === selectedDomain)
    if (!scan) { setReport(null); return }
    let cancelled = false
    setReportLoading(true)
    api.getScanReport(scan.id)
      .then(r => { if (!cancelled) setReport(r) })
      .catch(() => { if (!cancelled) setReport(null) })
      .finally(() => { if (!cancelled) setReportLoading(false) })
    return () => { cancelled = true }
  }, [selectedDomain, domainScans])

  // Build multi-domain portfolio (bounded parallel fetches). Enriches each
  // domain with DMARC compliance % (from RUA) and business exposure (BEC) —
  // the columns email-only portfolio views do not carry.
  useEffect(() => {
    if (domainScans.length < 2) { setSummaryRows([]); return }
    let cancelled = false
    const targets = domainScans.slice(0, 10)
    Promise.allSettled(targets.map(async (s) => {
      const [rep, summ, bec] = await Promise.allSettled([
        api.getScanReport(s.id),
        api.getDmarcSummary(wsId, s.domain),
        api.getBecExposureScore(wsId, s.domain),
      ])
      return {
        scan:    s,
        report:  rep.status === 'fulfilled' ? rep.value : null,
        summary: summ.status === 'fulfilled' ? summ.value : null,
        bec:     bec.status === 'fulfilled' ? bec.value : null,
      }
    })).then(results => {
      if (cancelled) return
      const rows = results.map(res => {
        if (res.status !== 'fulfilled') return null
        const { scan, report, summary, bec } = res.value
        const es = report?.modules?.email_security
        const applicable = es?.applicability ? es.applicability.applicable !== false : true
        const total = summary?.traffic?.total_messages ?? 0
        return {
          domain: scan.domain,
          lastScan: scan.created_at,
          stage: es?.policy_journey?.stage || (applicable ? null : 'na'),
          spf: es?.spf_detail ? Boolean(es.spf_detail.valid) : (es?.spf ? Boolean(es.spf.present) : null),
          dkim: es?.dkim_detail ? es.dkim_detail.status === 'detected' : null,
          bimi: es?.bimi_readiness ? Boolean(es.bimi_readiness.record_found) : null,
          openActions: Array.isArray(es?.remediation_actions) ? es.remediation_actions.filter(a => a.status !== 'resolved').length : 0,
          compliance: total > 0 ? (summary?.traffic?.pass_rate ?? null) : null,
          bec: bec?.exposure_level || null,
        }
      }).filter(Boolean)
      setSummaryRows(rows)
    })
    return () => { cancelled = true }
  }, [domainScans, wsId])

  // Load DMARC sender intelligence (summary + senders) for the selected domain.
  const loadSenderIntel = useCallback(async (domain) => {
    if (!wsId || !domain) { setDmarc(null); setSenderData(null); return }
    setSiLoading(true)
    const [sumR, senR] = await Promise.allSettled([
      api.getDmarcSummary(wsId, domain),
      api.getEmailSenders(wsId, domain),
    ])
    setDmarc(sumR.status === 'fulfilled' ? sumR.value : null)
    setSenderData(senR.status === 'fulfilled' ? senR.value : null)
    setSiLoading(false)
  }, [wsId])

  useEffect(() => {
    setImportResult(null); setImportError(null)
    if (selectedDomain) loadSenderIntel(selectedDomain)
  }, [selectedDomain, loadSenderIntel])

  async function handleClassify(sourceId, classification, notes) {
    setClassifyingId(sourceId)
    try {
      await api.classifyEmailSender(wsId, selectedDomain, sourceId, { classification, notes: notes || undefined })
      setToast({ kind: 'ok', msg: 'Sender classified.' })
      await loadSenderIntel(selectedDomain) // refresh senders + summary
    } catch (e) {
      setToast({ kind: 'err', msg: e.message || 'Classification failed.' })
    } finally {
      setClassifyingId(null)
    }
  }

  async function handleImport(payload) {
    setImporting(true); setImportError(null); setImportResult(null)
    try {
      const res = await api.importDmarcReport(wsId, selectedDomain, payload)
      setImportResult(res)
      if (res.imported) {
        setToast({ kind: 'ok', msg: 'DMARC report imported.' })
        await loadSenderIntel(selectedDomain)
      }
    } catch (e) {
      setImportError(e.message || 'Import failed.')
    } finally {
      setImporting(false)
    }
  }

  if (!wsId) return <NoWorkspaceSelected />

  const es = report?.modules?.email_security || null
  const moduleErrored = es?.error
  const notApplicable = es?.applicability && es.applicability.applicable === false
  // Plain computation (not a hook) — safe to run after the early return above.
  // Merge scan-time remediation actions with DMARC-report-derived actions, dedup by id.
  const reportActions = Array.isArray(dmarc?.report_remediation_actions) ? dmarc.report_remediation_actions : []
  const seenIds = new Set()
  const actions = [...(Array.isArray(es?.remediation_actions) ? es.remediation_actions : []), ...reportActions]
    .filter(a => { const k = a.id || JSON.stringify(a); if (seenIds.has(k)) return false; seenIds.add(k); return true })
    .sort((x, y) => sevCfg(x.severity).rank - sevCfg(y.severity).rank)

  const hasReports = dmarc && ((dmarc.traffic?.total_messages || 0) > 0 || (dmarc.senders?.total || 0) > 0)

  const gotoSetup   = () => goToAnchor('dmarc-setup', { tab: 'settings' })
  const gotoSenders = () => goToAnchor('sender-inventory')

  // Migration 088's history (mig 088). Workspace-scoped, not per-domain: a hosted record
  // and a sender both live under the workspace, and the server owns the filtering.
  useEffect(() => {
    if (!wsId) return
    let cancelled = false
    api.getEmailProtectionLifecycle(wsId)
      .then((res) => { if (!cancelled) { setLifecycle(res); setLifecycleError(null) } })
      .catch(() => { if (!cancelled) setLifecycleError('Could not load the change history.') })
    return () => { cancelled = true }
  }, [wsId])

  // Alert deep link: /ws/email-protection?lifecycle=<record_id> scrolls the history into
  // view. The history is the record for this domain — mig 088 created no state row — so
  // the section itself is the destination, and a stale id still lands somewhere useful.
  useEffect(() => {
    if (!lifecycle?.items?.length) return
    if (!new URLSearchParams(window.location.search).get('lifecycle')) return
    document.getElementById('lifecycle-history')?.scrollIntoView({ block: 'start' })
  }, [lifecycle])

  // Settings tab (the area template, 18 Oct 2026): everything configurable about
  // reporting — connection status, ingestion, the DMARC reporting setup, connecting
  // report delivery and importing a report by hand.
  const emailReady = domainScans.length > 0 && !reportLoading && Boolean(es) && !moduleErrored && !notApplicable
  const emailSettings = !emailReady ? (
    <EmptyCard
      title="Nothing to configure yet"
      body={domainScans.length === 0 ? 'Email reporting settings appear after a scan of a domain in this workspace.' : 'Email reporting settings appear once the latest scan returns email-security data for this domain.'}
    />
  ) : (
    <div className="space-y-6">
      <EmailProtectionOverview
        wsId={wsId}
        domain={selectedDomain}
        dmarcDetail={es?.dmarc_detail}
        dmarc={dmarc}
        senderData={senderData}
        onGotoSetup={gotoSetup}
        onGotoSenders={gotoSenders}
      />
      <DmarcIngestionStatus wsId={wsId} domain={selectedDomain} onGotoSetup={gotoSetup} onGotoSenders={gotoSenders} />
      <div id="dmarc-setup" className="scroll-mt-20">
        <DmarcSetupWizard
          wsId={wsId}
          domain={selectedDomain}
          dmarcDetail={es?.dmarc_detail}
          hasScanData
          totalMessages={dmarc?.traffic?.total_messages ?? null}
        />
      </div>
      <div id="connect-reporting" className="scroll-mt-20">
        <ConnectDmarcReporting wsId={wsId} domain={selectedDomain} dmarcDetail={es?.dmarc_detail} />
      </div>
      <section id="report-import" className="scroll-mt-20">
        <ImportDmarcReport onImport={handleImport} importing={importing} result={importResult} error={importError} />
      </section>
    </div>
  )

  const headerActions = (
    <>
        {domainScans.length > 1 && (
          <div className="relative">
            <select
              value={selectedDomain || ''}
              onChange={e => setSelectedDomain(e.target.value)}
              className="appearance-none input py-2 pr-9 text-sm font-medium cursor-pointer"
            >
              {domainScans.map(s => <option key={s.domain} value={s.domain}>{s.domain}</option>)}
            </select>
            <ChevronDown className="w-4 h-4 text-gray-400 absolute right-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          </div>
        )}
        {/* Reloads what is already recorded; "Scan now" (top right) starts a scan. */}
        <button type="button" onClick={loadScans} className="btn-ghost text-sm" disabled={loading}>
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} aria-hidden="true" />
          <span>Reload results</span>
        </button>
    </>
  )

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={loadScans}>
      <ModuleContract
        domainKey="email_protection"
        workspaceId={wsId}
        workspaceName={wsName}
        scanDomain={selectedDomain}
        // Founder-approved copy (S1-SHELL-V2, 22 Oct 2026).
        description={`Checks the published policies used to authenticate email from ${selectedDomain || 'your domains'} — SPF, DKIM, DMARC, MTA-STS and TLS reporting — as read from your DNS.`}
        actions={headerActions}
        nextAction={domainScans.length === 0 ? {
          title: 'Run a scan to start email protection',
          body: 'This page fills after a scan of a domain in this workspace: DMARC, SPF, DKIM and BIMI guidance.',
          label: 'Run a scan',
          to: '/scans/new',
        } : null}
        settings={emailSettings}
        overview={
          // The posture summary — the same guards as the body, so Overview never
          // shows a hero for a domain whose email module did not run.
          domainScans.length === 0 ? (
            <EmptyCard
              title="No email authentication guidance yet"
              body="This page fills after a scan of a domain in this workspace: DMARC, SPF, DKIM and BIMI guidance."
            />
          ) : reportLoading ? (
            <EmptyCard title="Loading email posture…" body="Fetching the latest scan report for this domain." />
          ) : !es ? (
            <EmptyCard title="Email guidance unavailable"
              body="The latest scan for this domain did not return email-security data. Try re-running the scan." />
          ) : moduleErrored ? (
            <EmptyCard title="Email module did not complete"
              body="The email-security module reported an error on the last scan. Re-run the scan to try again." />
          ) : notApplicable ? (
            <EmptyCard title="Email guidance not applicable for this domain"
              body={es.applicability?.reason ? `${es.applicability.reason}. This domain is not expected to send mail, so email-authentication findings are not raised.` : 'This domain is not expected to send mail, so email guidance does not apply.'} />
          ) : (
            <>
              {/* The area template (18 Oct 2026): Overview reduces to the BEC exposure
                  card — rendered once. The posture figures are "What we observed", the
                  one action is "Do this next"; connection status, ingestion, the DMARC
                  setup wizard and report import are configuration (Settings tab); the
                  journey, senders, sender validation, report history and records are
                  their own sections on Findings. */}
              <BecExposure wsId={wsId} domain={selectedDomain} />
            </>
          )
        }
      >
      <CloudflareDnsChanges workspaceId={wsId} onDomainChange={setSelectedDomain} />

      {/* No completed scans at all */}
      {domainScans.length === 0 ? (
        <>
          <EmptyCard
            title="No email authentication guidance yet"
            body="This page fills after a scan of a domain in this workspace: DMARC, SPF, DKIM and BIMI guidance."
          />
          <EmailTopicsPending />
        </>
      ) : reportLoading ? (
        <EmptyCard title="Loading email posture…" body="Fetching the latest scan report for this domain." />
      ) : !es ? (
        <>
          <EmptyCard title="Email guidance unavailable"
            body="The latest scan for this domain did not return email-security data. Try re-running the scan." />
          <EmailTopicsPending />
        </>
      ) : moduleErrored ? (
        <>
          <EmptyCard title="Email module did not complete"
            body="The email-security module reported an error on the last scan. Re-run the scan to try again." />
          <EmailTopicsPending />
        </>
      ) : notApplicable ? (
        <EmptyCard title="Email guidance not applicable for this domain"
          body={es.applicability?.reason ? `${es.applicability.reason}. This domain is not expected to send mail, so email-authentication findings are not raised.` : 'This domain is not expected to send mail, so email guidance does not apply.'} />
      ) : (
        <div className="space-y-6">
          {toast && <Toast toast={toast} onClose={() => setToast(null)} />}

          {/* The posture hero, evidence card, connection overview, BEC exposure and
              ingestion status are the Overview tab's summary; the journey, senders,
              setup and detail lists stay here. */}
          {/* The DMARC policy evidence — kept on Findings (moved from the old Overview). */}
          <DmarcPolicyEvidenceCard
            presentation={dmarc?.dmarc_policy_presentation || report?.dmarc_policy_presentation}
            showTechnical
          />

          <ZoneHeader title="Requested-policy journey" hint="Where you are, and the evidence to review before requesting stronger receiver handling." />

          {/* 1. DMARC journey */}
          <DmarcJourney journey={es.policy_journey} />

          {/* 1b. Enforcement readiness (DMARC sender intelligence) */}
          {dmarc && hasReports && <EnforcementReadiness readiness={dmarc.readiness} />}

          {/* 1b-2. Managed change review queue — analyst approval gate (Level 3) */}
          <ChangeReviewQueue wsId={wsId} />

          {/* 1c. DMARC summary or get-started hint */}
          {siLoading && !dmarc ? (
            <EmptyCard title="Loading DMARC sender intelligence…" body="Fetching imported report data for this domain." />
          ) : !dmarc ? (
            <EmptyCard title="DMARC summary unavailable"
              body="Sender intelligence could not be loaded for this domain. You can still import a report below." />
          ) : !hasReports ? (
            <EmptyCard title="No DMARC reports imported yet"
              body="Import a DMARC aggregate (RUA) report to reveal who is sending email using this domain, whether they pass alignment, and when you can safely tighten policy. Use the import panel below to get started." />
          ) : (
            <DmarcSummaryPanel summary={dmarc} />
          )}

          {/* 2. Guided remediation — the ordered path to enforcement */}
          <GuidedRemediation
            stage={es?.policy_journey?.stage || null}
            hasReports={hasReports}
            readiness={dmarc?.readiness}
            senders={senderData?.senders}
            actions={actions}
            onGoto={goToAnchor}
          />

          <ZoneHeader title="Senders, setup & validation" hint="Who sends as you, connect reporting, and check any message instantly." />

          {/* 2b. Sender inventory + classification */}
          <div id="sender-inventory" className="scroll-mt-20">
            <SenderInventory data={senderData} onClassify={handleClassify} classifyingId={classifyingId} loading={siLoading} />
          </div>

          {/* 2b-ii. What changed and when — migration 088's history, which had no read
              surface at all: customers were alerted that a hosted record disconnected and
              could not see when it started or whether it came back. */}
          <div id="lifecycle-history" className="scroll-mt-20">
            <EmailLifecycleHistory data={lifecycle} error={lifecycleError} />
          </div>

          {/* Sender validation — its own section (the DMARC reporting setup, connect
              reporting and report import moved to the Settings tab, 18 Oct 2026). */}
          <section id="sender-validation" className="scroll-mt-20 space-y-3" aria-labelledby="sender-validation-heading">
            <ZoneHeader title="Sender validation" hint="Check whether a sending source passes SPF and DKIM for this domain — no waiting for reports." />
            <InstantSourceValidator wsId={wsId} domain={selectedDomain} />
          </section>

          {/* DMARC report history — its own section. */}
          <section id="report-history" className="scroll-mt-20 space-y-3">
            <ZoneHeader title="Report history" hint="The DMARC aggregate reports received or imported for this domain." />
            <DmarcReportHistory wsId={wsId} domain={selectedDomain} />
          </section>

          <ZoneHeader title="Authentication detail & reference" hint="Records, status and how email risk connects to the rest of your attack surface." />

          {/* 3. Authentication cards */}
          <section id="auth-detail" className="scroll-mt-20">
            <div className="section-head">
              <div>
                <span className="eyebrow">Authentication detail</span>
                <h2 className="section-title mt-1.5">Records &amp; status</h2>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              <SpfCard spf={es.spf} detail={es.spf_detail} wsId={wsId} domain={selectedDomain} />
              <DmarcCard dmarc={es.dmarc} detail={es.dmarc_detail} />
              <DkimCard detail={es.dkim_detail} />
              <BimiCard readiness={es.bimi_readiness} />
              <MtaStsCard detail={es.mta_sts_detail} />
              <TlsRptCard detail={es.tls_rpt_detail} />
              <MxRecordsCard intelligence={report?.modules?.email_security_intelligence} transport={report?.modules?.mail_transport} />
            </div>
            <div id="mail-transport" className="mt-4 scroll-mt-28"><MailTransportCard transport={report?.modules?.mail_transport} mtaSts={es.mta_sts_detail} tlsRpt={es.tls_rpt_detail} /></div>
          </section>

          {/* 4. Auto-fix registry — every gap + the exact fix */}
          <RemediationsPanel wsId={wsId} domain={selectedDomain} />

          {/* 5. Differentiator */}
          <DifferentiatorBlock wsId={wsId} />

          {/* 6. Multi-domain summary */}
          <MultiDomainSummary rows={summaryRows} selectedDomain={selectedDomain} onSelect={setSelectedDomain} />
        </div>
      )}
      </ModuleContract>
    </WsPage>
  )
}
