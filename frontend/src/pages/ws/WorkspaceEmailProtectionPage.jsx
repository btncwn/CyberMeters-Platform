import { parseServerDate } from '../../utils/dates'
import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  Mail, ShieldCheck, ShieldAlert, KeyRound, Image as ImageIcon, Lock, FileText,
  Copy, Check, AlertTriangle, CheckCircle, ChevronDown, Info, RefreshCw, Globe,
  ArrowRight, Megaphone, Upload, Users, Filter, Gauge, X, Inbox,
} from 'lucide-react'
import { api, BASE } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'

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
  high:     { label: 'High',     pill: 'bg-orange-50 text-orange-700 border-orange-100', dot: 'bg-orange-500', rank: 1 },
  medium:   { label: 'Medium',   pill: 'bg-amber-50 text-amber-700 border-amber-100',  dot: 'bg-amber-500',  rank: 2 },
  low:      { label: 'Low',      pill: 'bg-blue-50 text-blue-700 border-blue-100',     dot: 'bg-blue-500',   rank: 3 },
  info:     { label: 'Info',     pill: 'bg-gray-100 text-gray-600 border-gray-200',    dot: 'bg-gray-400',   rank: 4 },
}
const sevCfg = (s) => SEVERITY[s] || SEVERITY.info

const CONFIDENCE = {
  high:   'bg-brand-50 text-brand-700 border-brand-100',
  medium: 'bg-amber-50 text-amber-700 border-amber-100',
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
      className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-gray-200 bg-white hover:bg-gray-50 text-xs font-semibold text-gray-700 transition-colors flex-shrink-0"
      title="Copy DNS value"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-brand-600" /> : <Copy className="w-3.5 h-3.5" />}
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
  { stage: 'monitoring',          label: 'Monitoring' },
  { stage: 'partial_enforcement', label: 'Quarantine' },
  { stage: 'full_enforcement',    label: 'Reject' },
]

function DmarcJourney({ journey }) {
  if (!journey || !journey.stage) {
    return (
      <EmptyCard icon={ShieldAlert} title="DMARC journey unavailable"
        body="DMARC journey data is not available for this scan yet. Re-run a scan to generate it." />
    )
  }
  const currentIdx = Math.max(0, JOURNEY_STAGES.findIndex(s => s.stage === journey.stage))
  const isReject = journey.stage === 'full_enforcement'

  return (
    <section className="card-md overflow-hidden">
      <div className="flex items-center gap-2.5 px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <div className="w-8 h-8 rounded-lg bg-brand-600 flex items-center justify-center flex-shrink-0">
          <ShieldCheck className="w-4 h-4 text-white" />
        </div>
        <div>
          <span className="eyebrow">DMARC Policy Journey</span>
          <h2 className="section-title leading-tight">Where you are on the path to enforcement</h2>
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
                    current ? 'bg-brand-600 border-brand-600 text-white ring-4 ring-brand-100'
                    : done ? 'bg-brand-50 border-brand-300 text-brand-700'
                    : 'bg-white border-gray-200 text-gray-300'
                  }`}>
                    {done ? <Check className="w-4 h-4" /> : i + 1}
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
        <div className={`rounded-xl border p-4 ${isReject ? 'border-brand-100 bg-brand-50/50' : 'border-amber-100 bg-amber-50/40'}`}>
          <div className="flex items-center gap-2 mb-2">
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-bold ${
              isReject ? 'bg-brand-600 text-white' : 'bg-amber-500 text-white'}`}>
              You are here · {journey.label || JOURNEY_STAGES[currentIdx].label}
            </span>
          </div>
          {journey.business_risk && (
            <div className="mb-3">
              <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-0.5">What this means for your business</p>
              <p className="text-sm text-gray-700 leading-relaxed">{journey.business_risk}</p>
            </div>
          )}
          {journey.next_step && (
            <div>
              <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-0.5">Next recommended step</p>
              <p className="text-sm text-gray-800 font-medium leading-relaxed flex items-start gap-1.5">
                <ArrowRight className="w-4 h-4 text-brand-600 flex-shrink-0 mt-0.5" />
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
    warn: 'bg-amber-50 text-amber-700 border-amber-100',
    bad:  'bg-red-50 text-red-700 border-red-100',
    info: 'bg-blue-50 text-blue-700 border-blue-100',
    na:   'bg-gray-100 text-gray-500 border-gray-200',
  }
  return map[kind] || map.na
}

function AuthCard({ icon: Icon, title, status, statusKind = 'na', children }) {
  return (
    <div className="card p-5 flex flex-col">
      <div className="flex items-center justify-between gap-2 mb-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div className="w-8 h-8 rounded-lg bg-gray-100 flex items-center justify-center flex-shrink-0">
            <Icon className="w-4 h-4 text-brand-600" />
          </div>
          <h3 className="text-sm font-bold text-gray-900">{title}</h3>
        </div>
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
      <span className="text-xs font-semibold text-gray-500 flex-shrink-0">{k}</span>
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
        <p key={i} className="flex items-start gap-1.5 text-xs text-amber-700 leading-relaxed">
          <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" /> {w}
        </p>
      ))}
    </div>
  )
}

// ── Individual auth cards ─────────────────────────────────────────────────────
function SpfCard({ spf, detail, wsId, domain }) {
  const [chain, setChain]   = useState(null)   // null | 'loading' | analysis result
  if (!detail && !spf) return <AuthCard icon={ShieldCheck} title="SPF" status="No data" statusKind="na"><NaNote /></AuthCard>
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
    <AuthCard icon={ShieldCheck} title="SPF" status={status} statusKind={kind}>
      <KV k="Record status" v={!present ? 'Not published' : valid ? 'Valid' : 'Published, needs review'} />
      {detail?.all_mechanism != null && <KV k="‘all’ mechanism" v={detail.all_mechanism} mono />}
      {detail?.policy_strength && <KV k="Policy strength" v={<span className="capitalize">{detail.policy_strength}</span>} />}
      {live?.status === 'ok' ? (
        <KV k="DNS lookups (live)" v={
          <span className={live.over_limit ? 'text-red-600 font-bold' : 'text-brand-700 font-semibold'}>
            {live.lookups_used} / {live.lookup_limit}{live.over_limit ? ' — limit exceeded' : ''}{live.truncated ? ' (partial)' : ''}
          </span>} />
      ) : typeof detail?.lookup_count_estimate === 'number' && (
        <KV k="DNS lookups (est.)" v={
          <span className={detail.lookup_count_estimate > 10 ? 'text-red-600 font-bold' : ''}>
            {detail.lookup_count_estimate}{detail.lookup_count_estimate > 10 ? ' / 10 limit exceeded' : ' / 10'}
          </span>} />
      )}
      {detail?.includes?.length > 0 && (
        <div>
          <p className="text-xs font-semibold text-gray-500 mb-1">Includes ({detail.includes.length})</p>
          <div className="flex flex-wrap gap-1">
            {detail.includes.map((inc, i) => (
              <span key={i} className="mono text-xs bg-gray-50 border border-gray-200 rounded px-1.5 py-0.5 text-gray-700">{inc}</span>
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
              <RefreshCw className="w-3.5 h-3.5" /> Analyse full include chain
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
                  <p className="text-xs font-semibold text-red-600 mb-1">
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
  if (!detail && !dmarc) return <AuthCard icon={ShieldCheck} title="DMARC" status="No data" statusKind="na"><NaNote /></AuthCard>
  const present = dmarc?.present ?? Boolean(detail?.raw)
  const policy = detail?.policy || dmarc?.policy
  const status = !present ? 'Not found' : detail?.valid === false ? 'Invalid' : (policy ? `p=${policy}` : 'Published')
  const kind = !present ? 'bad' : detail?.valid === false ? 'warn' : policy === 'reject' ? 'good' : policy === 'none' ? 'warn' : 'info'
  const align = (m) => (m === 's' ? 'Strict' : m === 'r' ? 'Relaxed' : m || '—')
  return (
    <AuthCard icon={ShieldCheck} title="DMARC" status={status} statusKind={kind}>
      <KV k="Policy (p)" v={policy ? <code className="mono">{policy}</code> : 'Not set'} />
      <KV k="Subdomain policy (sp)" v={detail?.subdomain_policy ? <code className="mono">{detail.subdomain_policy}</code> : 'Inherits main'} />
      {typeof detail?.percentage === 'number' && <KV k="Coverage (pct)" v={`${detail.percentage}%`} />}
      <KV k="Alignment" v={`DKIM ${align(detail?.adkim)} · SPF ${align(detail?.aspf)}`} />
      {detail?.rua?.length > 0 && <KV k="Aggregate reports (rua)" v={detail.rua.join(', ')} mono />}
      {detail?.ruf?.length > 0 && <KV k="Forensic reports (ruf)" v={detail.ruf.join(', ')} mono />}
      {present && detail?.rua?.length === 0 && <KV k="Aggregate reports (rua)" v={<span className="text-amber-700">None configured</span>} />}
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
    <AuthCard icon={KeyRound} title="DKIM" status={label} statusKind={kind}>
      {detail?.selector && <KV k="Selector" v={detail.selector} mono />}
      {detail?.provider && <KV k="Provider (inferred)" v={detail.provider} />}
      <p className="text-xs text-gray-600 leading-relaxed">
        {detail?.explanation || 'DKIM could not be verified using common selectors.'}
      </p>
      {/* Always surface the uncertainty caveat safely */}
      <div className="flex items-start gap-1.5 rounded-lg bg-blue-50 border border-blue-100 p-2.5">
        <Info className="w-3.5 h-3.5 text-blue-500 flex-shrink-0 mt-0.5" />
        <p className="text-xs text-blue-800 leading-relaxed">
          {detail?.limitation || 'Full DKIM validation requires a signed email sample or a known selector. A custom selector may be in use even when none is detected.'}
        </p>
      </div>
    </AuthCard>
  )
}

function BimiCard({ readiness }) {
  if (!readiness) return <AuthCard icon={ImageIcon} title="BIMI" status="No data" statusKind="na"><NaNote /></AuthCard>
  const found = readiness.record_found
  return (
    <AuthCard icon={ImageIcon} title="BIMI" status={found ? 'Record found' : 'Not configured'} statusKind={found ? 'info' : 'na'}>
      <p className="text-xs text-gray-500 -mt-1">Readiness only — BIMI is optional and never replaces SPF, DKIM, or DMARC.</p>
      <KV k="Record" v={found ? 'Published' : 'None'} />
      {readiness.logo_url && <KV k="Logo URL" v={readiness.logo_url} mono />}
      {readiness.certificate_url ? <KV k="Certificate URL" v={readiness.certificate_url} mono />
        : found && <KV k="Certificate URL" v={<span className="text-amber-700">Not listed</span>} />}
      {readiness.blockers?.length > 0 && (
        <div className="rounded-lg bg-amber-50 border border-amber-100 p-2.5 space-y-1">
          <p className="text-[11px] font-bold text-amber-700 uppercase tracking-wide">Readiness blockers</p>
          {readiness.blockers.map((b, i) => <p key={i} className="text-xs text-amber-800 leading-relaxed">{b}</p>)}
        </div>
      )}
      <Warnings items={readiness.warnings} />
    </AuthCard>
  )
}

function MtaStsCard({ detail }) {
  if (!detail) return <AuthCard icon={Lock} title="MTA-STS" status="Not available" statusKind="na">
    <NaNote text="MTA-STS transport details were not returned for this scan." /></AuthCard>
  const enforced = detail.policy_found && detail.mode === 'enforce'
  return (
    <AuthCard icon={Lock} title="MTA-STS" status={detail.policy_found ? (detail.mode || 'Found') : 'No policy'} statusKind={enforced ? 'good' : detail.policy_found ? 'warn' : 'na'}>
      <KV k="Policy file" v={detail.policy_found ? 'Confirmed' : 'Not confirmed'} />
      <KV k="Mode" v={<span className="capitalize">{detail.mode || 'unknown'}</span>} />
      <Warnings items={detail.warnings} />
    </AuthCard>
  )
}

function TlsRptCard({ detail }) {
  if (!detail) return <AuthCard icon={FileText} title="TLS-RPT" status="Not available" statusKind="na">
    <NaNote text="TLS-RPT details were not returned for this scan." /></AuthCard>
  return (
    <AuthCard icon={FileText} title="TLS-RPT" status={detail.record_found ? 'Found' : 'Not found'} statusKind={detail.record_found ? 'good' : 'na'}>
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
        <span className={`w-2 h-2 rounded-full flex-shrink-0 mt-2 ${sev.dot}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p className="text-sm font-bold text-gray-900">{action.title}</p>
            {action.protocol && <span className="text-xs font-bold uppercase tracking-wide text-gray-500 bg-gray-100 border border-gray-200 rounded px-1.5 py-0.5">{action.protocol}</span>}
            <span className={`text-xs font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${sev.pill}`}>{sev.label}</span>
            {action.confidence && <span className={`text-xs font-semibold px-1.5 py-0.5 rounded border ${CONFIDENCE[action.confidence] || CONFIDENCE.low}`}>{action.confidence} confidence</span>}
          </div>
          {action.issue && <p className="text-xs text-gray-500 mt-1 leading-relaxed">{action.issue}</p>}
        </div>
        <ChevronDown className={`w-4 h-4 text-gray-300 flex-shrink-0 mt-1 transition-transform ${open ? 'rotate-180' : ''}`} />
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
              <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-1">DNS value to publish</p>
              <DnsValue value={action.copyable_value} />
            </div>
          )}
          {action.caution && (
            <div className="flex items-start gap-1.5 rounded-lg bg-amber-50 border border-amber-100 p-2.5">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-500 flex-shrink-0 mt-0.5" />
              <p className="text-xs text-amber-800 leading-relaxed">{action.caution}</p>
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
        ? `${unknownCount} sender${unknownCount === 1 ? '' : 's'} still need${unknownCount === 1 ? 's' : ''} classification. Confirm which senders are yours so enforcement never blocks legitimate mail.`
        : 'Confirm which senders are yours so enforcement never blocks legitimate mail.',
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
      key: 'quarantine', title: 'Move your policy to quarantine',
      hint: 'Messages that fail authentication go to spam instead of the inbox — real protection starts here.',
      done: enforcing, target: 'dmarc-setup', cta: 'Open DMARC setup',
    },
    {
      key: 'reject', title: 'Enforce with reject',
      hint: 'Messages that fail authentication are refused outright. This is full protection against spoofing.',
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
                {isDone ? (
                  <CheckCircle className="w-6 h-6 text-brand-600 flex-shrink-0" />
                ) : (
                  <span className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold flex-shrink-0 ${
                    isCurrent ? 'bg-brand-600 text-white' : 'bg-gray-100 text-gray-400 border border-gray-200'
                  }`}>{i + 1}</span>
                )}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <p className={`text-sm font-bold ${isDone ? 'text-gray-400 line-through decoration-gray-300' : isCurrent ? 'text-gray-900' : 'text-gray-500'}`}>
                      {m.title}
                    </p>
                    {isCurrent && (
                      <span className="text-xs font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border bg-brand-50 text-brand-700 border-brand-100">
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
                      {m.cta} <ArrowRight className="w-3.5 h-3.5" />
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
          <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wide mb-2">Also recommended</p>
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
      <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-0.5">{label}</p>
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
          <div className="flex items-center gap-2 mb-2">
            <Megaphone className="w-4 h-4 text-brand-600" />
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
        <div className="sm:w-56 flex-shrink-0 bg-brand-50/40 border-t sm:border-t-0 sm:border-l border-gray-100 p-6 flex flex-col justify-center gap-2">
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
const STAGE_LABEL = { missing: 'No DMARC', monitoring: 'Monitoring', partial_enforcement: 'Quarantine', full_enforcement: 'Reject' }

const BEC_DOT = { critical: 'text-red-700', high: 'text-red-700', medium: 'text-amber-700', low: 'text-brand-700', minimal: 'text-brand-700' }
function MultiDomainSummary({ rows, selectedDomain, onSelect }) {
  if (!rows || rows.length < 2) return null
  const cell = (ok) => ok === true ? <CheckCircle className="w-4 h-4 text-brand-600 mx-auto" />
    : ok === false ? <span className="text-gray-300">—</span>
    : <span className="text-gray-300 text-xs">·</span>
  const compCell = (c) => c == null
    ? <span className="text-gray-300 text-xs">not measured</span>
    : <span className={`text-xs font-bold tabular-nums ${c >= 95 ? 'text-brand-700' : c >= 80 ? 'text-amber-600' : 'text-red-700'}`}>{c}%</span>
  const becCell = (b) => !b
    ? <span className="text-gray-300 text-xs">·</span>
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
                <td><span className="font-semibold text-gray-800 text-sm flex items-center gap-1.5"><Globe className="w-3.5 h-3.5 text-gray-400" />{r.domain}</span></td>
                <td><span className="text-xs font-semibold text-gray-700">{STAGE_LABEL[r.stage] || '—'}</span></td>
                <td className="text-center">{compCell(r.compliance)}</td>
                <td>{becCell(r.bec)}</td>
                <td className="text-center">{cell(r.spf)}</td>
                <td className="text-center">{cell(r.dkim)}</td>
                <td className="text-center">{cell(r.bimi)}</td>
                <td className="text-center"><span className={`text-xs font-bold ${r.openActions > 0 ? 'text-orange-600' : 'text-gray-400'}`}>{r.openActions}</span></td>
                <td><span className="text-xs text-gray-400">{r.lastScan ? fmtDate(r.lastScan) : '—'}</span></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  )
}

function EmptyCard({ icon: Icon = Mail, title, body, action }) {
  return (
    <div className="card p-10 text-center flex flex-col items-center">
      <div className="w-12 h-12 rounded-2xl bg-gray-50 border border-gray-100 flex items-center justify-center mb-3">
        <Icon className="w-6 h-6 text-gray-300" />
      </div>
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
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
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
  suspicious: { label: 'Suspicious', pill: 'bg-amber-50 text-amber-700 border-amber-100' },
  threat:     { label: 'Threat',     pill: 'bg-red-50 text-red-700 border-red-100' },
  ignored:    { label: 'Ignored',    pill: 'bg-gray-100 text-gray-500 border-gray-200' },
  unknown:    { label: 'Unknown',    pill: 'bg-blue-50 text-blue-700 border-blue-100' },
}
const RISK = {
  critical: 'bg-red-50 text-red-700 border-red-100',
  high:     'bg-orange-50 text-orange-700 border-orange-100',
  medium:   'bg-amber-50 text-amber-700 border-amber-100',
  low:      'bg-gray-100 text-gray-500 border-gray-200',
}
const RISK_RANK = { critical: 0, high: 1, medium: 2, low: 3 }

// ── Enforcement readiness: Monitoring → Quarantine Review → Reject Review ──────
function EnforcementReadiness({ readiness }) {
  if (!readiness) return null
  const stages = [
    { key: 'monitoring', label: 'Monitoring' },
    { key: 'quarantine', label: 'Quarantine Review' },
    { key: 'reject',     label: 'Reject Review' },
  ]
  const currentIdx = readiness.ready_for_reject ? 2 : readiness.ready_for_quarantine ? 1 : 0
  const confPill = readiness.confidence === 'high' ? 'bg-brand-50 text-brand-700 border-brand-100'
    : readiness.confidence === 'medium' ? 'bg-amber-50 text-amber-700 border-amber-100'
    : 'bg-gray-100 text-gray-500 border-gray-200'
  return (
    <section className="card-md overflow-hidden">
      <div className="flex items-center gap-3 px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <div className="w-8 h-8 rounded-lg bg-brand-600 flex items-center justify-center flex-shrink-0">
          <Gauge className="w-4 h-4 text-white" />
        </div>
        <div className="flex-1">
          <span className="eyebrow">Enforcement readiness</span>
          <h2 className="section-title leading-tight">Are you ready to tighten policy?</h2>
        </div>
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
                    current ? 'bg-brand-600 border-brand-600 text-white ring-4 ring-brand-100'
                    : done ? 'bg-brand-50 border-brand-300 text-brand-700'
                    : 'bg-white border-gray-200 text-gray-300'}`}>
                    {done ? <Check className="w-4 h-4" /> : i + 1}
                  </div>
                  <span className={`mt-2 text-xs font-semibold whitespace-nowrap ${current ? 'text-brand-700' : done ? 'text-gray-600' : 'text-gray-400'}`}>{s.label}</span>
                </div>
                {i < stages.length - 1 && <div className={`h-0.5 flex-1 mx-2 mb-6 rounded-full ${i < currentIdx ? 'bg-brand-400' : 'bg-gray-200'}`} />}
              </div>
            )
          })}
        </div>
      </div>
      <div className="px-6 pb-6 pt-2">
        <div className="rounded-xl border border-amber-100 bg-amber-50/40 p-4">
          {readiness.explanation && <p className="text-sm text-gray-700 leading-relaxed mb-3">{readiness.explanation}</p>}
          {readiness.blockers?.length > 0 && (
            <div className="mb-3">
              <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-1.5">What's blocking enforcement</p>
              <ul className="space-y-1.5">
                {readiness.blockers.map((b, i) => (
                  <li key={i} className="flex items-start gap-1.5 text-sm text-gray-700">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-500 flex-shrink-0 mt-0.5" /> {b}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {readiness.next_step && (
            <div>
              <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-0.5">Next recommended step</p>
              <p className="text-sm text-gray-900 font-medium leading-relaxed flex items-start gap-1.5">
                <ArrowRight className="w-4 h-4 text-brand-600 flex-shrink-0 mt-0.5" /> {readiness.next_step}
              </p>
            </div>
          )}
        </div>
      </div>
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
    : br.level === 'medium' ? 'bg-amber-50 text-amber-700 border-amber-100'
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
        {tile('Total messages', (t.total_messages ?? 0).toLocaleString(), 'observed')}
        {tile('Aligned', (t.aligned_messages ?? 0).toLocaleString(), 'passed SPF/DKIM', 'text-brand-600')}
        {tile('Failed', (t.failed_messages ?? 0).toLocaleString(), 'failed alignment', (t.failed_messages ?? 0) > 0 ? 'text-orange-600' : '')}
        {tile('Pass rate', `${t.pass_rate ?? 0}%`, 'aligned share')}
      </div>
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Sender mix */}
        <div className="card p-5">
          <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-3">Sender mix ({s.total ?? 0})</p>
          <div className="space-y-2">
            {[
              ['Trusted', s.trusted, 'bg-brand-500'],
              ['Unknown', s.unknown, 'bg-blue-400'],
              ['Suspicious', s.suspicious, 'bg-amber-500'],
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
          <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-3">Disposition</p>
          <div className="flex h-2.5 rounded-full overflow-hidden mb-3 border border-gray-100">
            <div style={{ width: `${(d.none || 0) / dispTotal * 100}%` }} className="bg-gray-300" />
            <div style={{ width: `${(d.quarantine || 0) / dispTotal * 100}%` }} className="bg-amber-400" />
            <div style={{ width: `${(d.reject || 0) / dispTotal * 100}%` }} className="bg-red-500" />
          </div>
          <div className="space-y-1.5 text-sm">
            <div className="flex justify-between"><span className="flex items-center gap-2 text-gray-600"><span className="w-2 h-2 rounded-full bg-gray-300" />None</span><span className="font-semibold">{(d.none ?? 0).toLocaleString()}</span></div>
            <div className="flex justify-between"><span className="flex items-center gap-2 text-gray-600"><span className="w-2 h-2 rounded-full bg-amber-400" />Quarantine</span><span className="font-semibold">{(d.quarantine ?? 0).toLocaleString()}</span></div>
            <div className="flex justify-between"><span className="flex items-center gap-2 text-gray-600"><span className="w-2 h-2 rounded-full bg-red-500" />Reject</span><span className="font-semibold">{(d.reject ?? 0).toLocaleString()}</span></div>
          </div>
        </div>
        {/* Business risk */}
        <div className="card p-5 flex flex-col">
          <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-3">Business risk</p>
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
  const riskCls = RISK[sender.risk_level] || RISK.low
  return (
    <>
      <tr onClick={() => setOpen(o => !o)} className="cursor-pointer hover:bg-gray-50/60 transition-colors">
        <td><span className="mono text-xs font-semibold text-gray-800">{sender.source_ip}</span></td>
        <td>
          <span className="text-sm text-gray-700 capitalize">{sender.provider_guess || 'unknown'}</span>
          {sender.provider_confidence && <span className="block text-xs text-gray-400">{sender.provider_confidence} confidence</span>}
        </td>
        <td className="text-right"><span className="text-sm font-semibold text-gray-900">{(sender.total_messages ?? 0).toLocaleString()}</span></td>
        <td className="text-right"><span className={`text-sm font-semibold ${(sender.pass_rate ?? 0) < 90 ? 'text-orange-600' : 'text-gray-900'}`}>{sender.pass_rate ?? 0}%</span></td>
        <td className="text-right"><span className={`text-sm ${(sender.failed_messages ?? 0) > 0 ? 'text-orange-600 font-semibold' : 'text-gray-400'}`}>{(sender.failed_messages ?? 0).toLocaleString()}</span></td>
        <td><span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold uppercase tracking-wide border capitalize ${riskCls}`}>{sender.risk_level || 'low'}</span></td>
        <td><span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${cls.pill}`}>{cls.label}</span></td>
        <td className="text-right"><ChevronDown className={`w-4 h-4 text-gray-300 inline transition-transform ${open ? 'rotate-180' : ''}`} /></td>
      </tr>
      {open && (
        <tr className="bg-gray-50/40">
          <td colSpan={8} className="px-5 py-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-1">Recommended action</p>
                <p className="text-sm text-gray-700 leading-relaxed">{sender.recommended_action || 'Classify this sender if it is a legitimate business email source.'}</p>
                <p className="text-xs text-gray-400 mt-2">First seen {fmtDate(sender.first_seen)} · Last seen {fmtDate(sender.last_seen)}</p>
                {sender.provider_reason && <p className="text-xs text-gray-400 mt-1">{sender.provider_reason}</p>}
              </div>
              <div>
                <p className="text-[11px] font-bold uppercase tracking-wide text-gray-500 mb-1">Classify this sender</p>
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
          <Filter className="w-3.5 h-3.5 text-gray-400" />
          {SENDER_FILTERS.map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition-colors ${
                filter === f ? 'bg-brand-600 text-white' : 'bg-white text-gray-600 border border-gray-200 hover:bg-gray-50'}`}>
              {f}
            </button>
          ))}
        </div>
      )}
      {!data ? (
        <EmptyCard icon={AlertTriangle} title="Sender list unavailable" body="The sender inventory could not be loaded for this domain. Try refreshing." />
      ) : senders.length === 0 ? (
        <EmptyCard icon={Users} title="No senders observed yet"
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
  authenticated_aligned: { label: 'Authenticated & aligned', cls: 'bg-brand-50 border-brand-200 text-brand-800', icon: CheckCircle, ic: 'text-brand-600' },
  passes_not_aligned:    { label: 'Passes, but not aligned', cls: 'bg-amber-50 border-amber-200 text-amber-800', icon: AlertTriangle, ic: 'text-amber-500' },
  fails:                 { label: 'Fails authentication',     cls: 'bg-red-50 border-red-200 text-red-800',       icon: ShieldAlert, ic: 'text-red-500' },
  unparseable:           { label: 'Could not read headers',   cls: 'bg-gray-50 border-gray-200 text-gray-600',    icon: Info, ic: 'text-gray-400' },
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
  const Icon = tone?.icon

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
          className="w-full text-xs font-mono border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:border-brand-400 resize-y"
        />
        <div className="flex items-center gap-3">
          <button onClick={validate} disabled={busy || !headers.trim()} className="btn-primary text-sm disabled:opacity-50">
            {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            {busy ? 'Checking…' : 'Validate sender'}
          </button>
          {headers && !busy && (
            <button onClick={() => { setHeaders(''); setResult(null); setErr(null) }} className="text-xs font-semibold text-gray-400 hover:text-gray-600">Clear</button>
          )}
        </div>
        {err && <p className="text-sm text-red-700 flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> {err}</p>}
        {result && tone && (
          <div className={`rounded-xl border p-4 ${tone.cls}`}>
            <div className="flex items-center gap-2">
              <Icon className={`w-5 h-5 flex-shrink-0 ${tone.ic}`} />
              <p className="text-sm font-bold">{tone.label}</p>
            </div>
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
        <div className="w-8 h-8 rounded-lg bg-brand-100 flex items-center justify-center"><Upload className="w-4 h-4 text-brand-700" /></div>
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
            {importing ? <><RefreshCw className="w-4 h-4 animate-spin" /> Importing…</> : <><Upload className="w-4 h-4" /> Import report</>}
          </button>
          {error && <span className="text-sm text-red-600 flex items-center gap-1.5"><AlertTriangle className="w-4 h-4" /> {error}</span>}
        </div>
        {result && (
          <div className={`rounded-xl border p-4 ${result.imported ? 'border-brand-100 bg-brand-50/50' : result.duplicate ? 'border-amber-100 bg-amber-50/40' : 'border-gray-200 bg-gray-50'}`}>
            {result.duplicate ? (
              <p className="text-sm text-amber-800 flex items-center gap-1.5"><Info className="w-4 h-4" /> This report was already imported and was not counted again.</p>
            ) : result.imported ? (
              <div className="flex items-start gap-2">
                <CheckCircle className="w-4 h-4 text-brand-600 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-gray-700">
                  Imported <b>{result.records_imported}</b> record(s) · <b>{(result.messages_imported ?? 0).toLocaleString()}</b> message(s) ·
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
    return new Date(sec * 1000).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' })
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
  const passCls = (p) => p == null ? 'text-gray-400' : p >= 95 ? 'text-brand-700' : p >= 80 ? 'text-amber-700' : 'text-red-700'

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
          <p className="text-sm font-semibold text-gray-800">No reports received yet</p>
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
              <span className="font-bold text-gray-800 tabular-nums">{(totals.total_messages || 0).toLocaleString('en-GB')}</span> messages
              {totals.first_seen ? <> since <span className="font-semibold text-gray-700">{fmtUnixDay(totals.first_seen)}</span></> : null}
            </p>
          )}
          <div className="overflow-x-auto p-6 pt-3">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-[11px] font-semibold text-gray-500 uppercase tracking-wide border-b border-gray-100">
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
                    <td className="py-2.5 pr-4 text-right tabular-nums text-gray-800">{(r.message_count || 0).toLocaleString('en-GB')}</td>
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

  async function run(fn, confirmMsg) {
    if (confirmMsg && !window.confirm(confirmMsg)) return
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
  const fmt = (t) => (t ? parseServerDate(t).toLocaleString() : null)
  // DNS-verified = the live DMARC record (from the latest scan) lists our address.
  // "Connected" requires BOTH this AND a received report — same rule as the top
  // overview, so the two panels never contradict each other.
  const _inboundMailto = inboundAddress ? `mailto:${inboundAddress}`.toLowerCase() : null
  const _ruaList = (Array.isArray(dmarcDetail?.rua) ? dmarcDetail.rua : [])
    .map(r => (String(r).startsWith('mailto:') ? String(r) : `mailto:${r}`).toLowerCase())
  const dnsVerified = _inboundMailto ? _ruaList.includes(_inboundMailto) : false
  const reportsReceived = Boolean(lastInbound)
  const fullyConnected = dnsVerified && reportsReceived
  const curl = `curl -X POST ${BASE || 'https://api.cybermeters.com'}/dmarc-ingest \\
  -H "Authorization: Bearer YOUR_UPLOAD_TOKEN" \\
  -H "Content-Type: application/xml" \\
  --data-binary @report.xml`

  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70 flex items-center gap-2.5">
        <div className="w-8 h-8 rounded-lg bg-brand-100 flex items-center justify-center"><Inbox className="w-4 h-4 text-brand-700" /></div>
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
              {busy ? <><RefreshCw className="w-4 h-4 animate-spin" /> Working…</> : <><Inbox className="w-4 h-4" /> Activate DMARC reporting</>}
            </button>
          </>
        ) : (
          <>
            {/* Mode A — Inbound RUA (recommended) */}
            <div className="rounded-xl border border-brand-100 bg-brand-50/40 p-4 space-y-3">
              <div className="flex items-center gap-2">
                <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md bg-brand-600 text-white text-xs font-semibold">Recommended</span>
                <h3 className="text-sm font-semibold text-gray-800">Inbound RUA address</h3>
                <span className={`ml-auto inline-flex items-center gap-1.5 text-xs font-medium ${
                  fullyConnected ? 'text-brand-700' : reportsReceived ? 'text-amber-700' : 'text-gray-500'
                }`}>
                  {fullyConnected
                    ? <><CheckCircle className="w-3.5 h-3.5" /> Connected</>
                    : reportsReceived
                      ? <><AlertTriangle className="w-3.5 h-3.5" /> Receiving reports · DNS update required</>
                      : <><Info className="w-3.5 h-3.5" /> Not receiving yet</>}
                </span>
              </div>
              <p className="text-sm text-gray-600 leading-relaxed">Add this value to your DMARC record:</p>
              <div className="flex items-center gap-2">
                <code className="mono text-xs flex-1 break-all bg-white border border-gray-200 rounded-lg px-3 py-2">{ruaValue || '—'}</code>
                {ruaValue && <CopyButton value={ruaValue} label="Copy" />}
              </div>
              {reportsReceived && !dnsVerified && (
                <div className="rounded-lg border border-amber-200 bg-amber-50/60 p-2.5 text-xs text-amber-900 flex items-start gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
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
                <KeyRound className="w-4 h-4 text-gray-500" />
                <h3 className="text-sm font-semibold text-gray-800">Signed upload key</h3>
                <span className="text-xs text-gray-400">Advanced · scripts &amp; MSP automation</span>
                <ChevronDown className={`w-4 h-4 text-gray-400 ml-auto transition-transform ${showAdvanced ? 'rotate-180' : ''}`} />
              </button>
              {showAdvanced && (
                <div className="space-y-3 pt-1">
                  <p className="text-xs text-gray-500 leading-relaxed">
                    Inbound RUA is the recommended setup. A signed upload key is useful for scripts or MSP automation that
                    POST report XML directly. Last upload: <b className="text-gray-700">{endpoint.last_signed_upload_at ? parseServerDate(endpoint.last_signed_upload_at).toLocaleString() : 'never'}</b>.
                  </p>
                  {rawToken && (
                    <div className="rounded-lg border border-amber-200 bg-amber-50/60 p-3 space-y-2">
                      <p className="text-sm text-amber-900 flex items-center gap-1.5"><Info className="w-4 h-4" /> Copy this token now — it is shown only once and cannot be retrieved later.</p>
                      <div className="flex items-center gap-2">
                        <code className="mono text-xs flex-1 break-all bg-white border border-amber-200 rounded-lg px-3 py-2">{rawToken}</code>
                        <CopyButton value={rawToken} label="Copy" />
                      </div>
                    </div>
                  )}
                  <div className="flex items-center gap-3">
                    <button onClick={() => run(() => api.rotateDmarcIngestEndpoint(wsId, domain), 'Rotate the upload key? The current token stops working immediately.')} disabled={busy} className="btn-secondary text-sm disabled:opacity-50">
                      <RefreshCw className="w-4 h-4" /> {rawToken ? 'Rotate again' : 'Generate token'}
                    </button>
                    <button onClick={() => run(() => api.revokeDmarcIngestEndpoint(wsId, domain), 'Revoke this endpoint? Inbound email and signed uploads will be rejected.')} disabled={busy} className="text-sm text-red-600 hover:text-red-700 font-medium inline-flex items-center gap-1.5 disabled:opacity-50">
                      <X className="w-4 h-4" /> Revoke
                    </button>
                  </div>
                  <div className="space-y-1.5">
                    <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Example upload</p>
                    <pre className="mono text-xs bg-gray-900 text-gray-100 rounded-xl p-4 overflow-x-auto whitespace-pre">{curl}</pre>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
        {err && <span className="text-sm text-red-600 flex items-center gap-1.5"><AlertTriangle className="w-4 h-4" /> {err}</span>}
      </div>
    </section>
  )
}

// ── DMARC Setup Wizard (public-beta guided DNS setup) ─────────────────────────
// Helps a non-technical customer connect DMARC reporting: pick DNS provider →
// copy the DNS record → verify → wait → Connected. Customer-safe copy only; the
// customer always edits their own DNS (we never touch it). Never suggests
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
            <span className={`flex items-center justify-center w-6 h-6 rounded-full text-xs font-semibold ${done ? 'bg-brand-600 text-white' : isCurrent ? 'bg-brand-100 text-brand-700 ring-2 ring-brand-300' : 'bg-gray-100 text-gray-400'}`}>
              {done ? <Check className="w-3.5 h-3.5" /> : i + 1}
            </span>
            <span className={`text-xs ${isCurrent ? 'font-semibold text-gray-800' : done ? 'text-gray-600' : 'text-gray-500'}`}>{label}</span>
            {i < steps.length - 1 && <ChevronDown className="w-3.5 h-3.5 text-gray-300 -rotate-90 hidden sm:block" />}
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
  const rateCls = rate == null ? 'text-gray-400' : rate >= 99 ? 'text-brand-700' : rate >= 95 ? 'text-amber-600' : 'text-red-600'
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
        <div><p className="text-lg font-bold text-gray-900 tabular-nums">{data.total_sessions.toLocaleString()}</p><p className="text-xs text-gray-400">sessions</p></div>
        <div><p className="text-lg font-bold text-gray-900 tabular-nums">{data.failed_sessions.toLocaleString()}</p><p className="text-xs text-gray-400">failed</p></div>
        <div><p className="text-lg font-bold text-gray-900 tabular-nums">{data.report_count}</p><p className="text-xs text-gray-400">reports</p></div>
      </div>
      {data.top_failures?.length > 0 && (
        <div className="mt-4 pt-3 border-t border-gray-100">
          <p className="text-xs font-semibold text-gray-500 mb-2 uppercase tracking-wide">Top failures</p>
          <div className="space-y-1.5">
            {data.top_failures.map((f, i) => (
              <div key={i} className="flex items-center justify-between text-xs">
                <span className="text-gray-700 font-medium">{(f.result_type || 'unknown').replace(/-/g, ' ')}</span>
                <span className="text-gray-400 tabular-nums">{(f.sessions || 0).toLocaleString()} sessions</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function ManagedTlsRptCard({ wsId, domain, endpointReady }) {
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
  const meta = rec ? (HOSTED_STATUS_META[rec.status] || HOSTED_STATUS_META.pending_dns) : null

  return (
    <div className="mx-6 mt-4 rounded-xl border border-gray-200 bg-gray-50/50 p-5">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm font-bold text-gray-900">
            Host your TLS reporting (TLS-RPT)
            {!rec && <span className="ml-2 text-xs font-bold uppercase tracking-wide text-gray-600 bg-gray-100 rounded px-1.5 py-0.5">Optional</span>}
          </p>
          <p className="text-xs text-gray-500 mt-1 leading-relaxed">
            Add one CNAME and we host the <code className="text-[11px]">_smtp._tls</code> record for you, so you get
            reports when someone can’t deliver mail to you over TLS.
          </p>
        </div>
        {rec && meta && (
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border ${
            meta.kind === 'good' ? 'bg-brand-50 text-brand-700 border-brand-200'
            : meta.kind === 'warn' ? 'bg-amber-50 text-amber-800 border-amber-200'
            : meta.kind === 'bad' ? 'bg-red-50 text-red-700 border-red-200'
            : 'bg-gray-50 text-gray-500 border-gray-200'}`}>
            {meta.label}
          </span>
        )}
      </div>

      {error && <p className="mt-2 text-xs text-red-600">{error}</p>}

      {!rec ? (
        <div className="mt-3">
          <button
            onClick={() => act('create', () => api.createHostedTlsRpt(wsId, domain))}
            disabled={!endpointReady || busy === 'create'}
            className="btn-secondary text-sm disabled:opacity-50"
          >
            {busy === 'create' ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            Host TLS-RPT
          </button>
          {!endpointReady && (
            <p className="text-xs text-gray-400 mt-2">Activate DMARC reporting below first — TLS-RPT reuses the same reporting address.</p>
          )}
        </div>
      ) : (
        <div className="mt-3 space-y-2.5">
          <p className="text-xs text-gray-600">{meta.hint}</p>
          {rec.status !== 'connected' && rec.status !== 'pending_removal' && (
            <div className="space-y-1.5">
              <div className="grid grid-cols-[70px,1fr] gap-2 items-center">
                <span className="text-xs font-semibold text-gray-500">Type / Name</span>
                <DnsValue value={`CNAME  ${rec.cname_name}`} />
              </div>
              <div className="grid grid-cols-[70px,1fr] gap-2 items-center">
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
                <RefreshCw className={`w-3.5 h-3.5 ${busy === 'verify' ? 'animate-spin' : ''}`} />
                Check connection
              </button>
            )}
            {rec.status !== 'pending_removal' && (
              <button
                onClick={() => {
                  if (window.confirm('Stop hosting this record? You will need to publish your own TLS-RPT TXT again.')) {
                    act('remove', () => api.deleteHostedTlsRpt(wsId, domain))
                  }
                }}
                disabled={Boolean(busy)}
                className="text-xs text-gray-400 hover:text-red-600 disabled:opacity-50"
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
    </div>
  )
}

function ManagedMtaStsCard({ wsId, domain }) {
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
  const meta = rec ? (HOSTED_STATUS_META[rec.status] || HOSTED_STATUS_META.pending_dns) : null
  const policyVerified = rec?.https_policy?.state === 'reachable_valid' && rec?.https_policy?.matches_pinned_policy
  const dnsConnected = rec?.dns_txt?.state === 'connected' || rec?.status === 'connected'
  const complete = Boolean(rec?.complete)

  return (
    <div className="mx-6 mt-4 rounded-xl border border-gray-200 bg-white p-5">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm font-bold text-gray-900">
            MTA-STS readiness
            {!rec && <span className="ml-2 text-xs font-bold uppercase tracking-wide text-gray-600 bg-gray-100 rounded px-1.5 py-0.5">Guided</span>}
          </p>
          <p className="text-xs text-gray-500 mt-1 leading-relaxed">
            CyberMeters manages the MTA-STS DNS policy ID. Your organisation or web provider hosts the HTTPS policy file.
          </p>
        </div>
        {rec && (
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border ${
            complete ? 'bg-brand-50 text-brand-700 border-brand-200'
            : rec.review_required ? 'bg-amber-50 text-amber-800 border-amber-200'
            : 'bg-gray-50 text-gray-600 border-gray-200'}`}>
            {complete ? 'MTA-STS active in testing mode' : rec.review_required ? 'Review needed' : meta?.label || 'Not checked'}
          </span>
        )}
      </div>

      {error && <p className="mt-2 text-xs text-red-600">{error}</p>}

      {!rec ? (
        <div className="mt-3">
          <button
            onClick={() => act('create', () => api.createHostedMtaSts(wsId, domain))}
            disabled={busy === 'create'}
            className="btn-secondary text-sm disabled:opacity-50"
          >
            {busy === 'create' ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Lock className="w-4 h-4" />}
            Generate MTA-STS guidance
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
            <div className="rounded-lg border border-amber-200 bg-amber-50 p-3 text-xs text-amber-800">
              {rec.mx_drift?.message || 'Your mail servers changed. Review and republish the MTA-STS policy before changing the DNS policy ID.'}
            </div>
          )}

          {rec.status !== 'connected' && rec.status !== 'pending_removal' && (
            <div className="space-y-1.5">
              <div className="grid grid-cols-[86px,1fr] gap-2 items-center">
                <span className="text-xs font-semibold text-gray-500">Type / Name</span>
                <DnsValue value={`CNAME  ${rec.cname_name}`} />
              </div>
              <div className="grid grid-cols-[86px,1fr] gap-2 items-center">
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
                <RefreshCw className={`w-3.5 h-3.5 ${busy === 'verify' ? 'animate-spin' : ''}`} />
                Check DNS and policy
              </button>
            )}
            {rec.status !== 'pending_removal' && (
              <button
                onClick={() => {
                  if (window.confirm('Stop managing the MTA-STS DNS policy ID? Your HTTPS policy file is not changed by CyberMeters.')) {
                    act('remove', () => api.deleteHostedMtaSts(wsId, domain))
                  }
                }}
                disabled={Boolean(busy)}
                className="text-xs text-gray-400 hover:text-red-600 disabled:opacity-50"
              >
                Stop DNS management
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function ManagedDmarcCard({ wsId, domain, endpointReady }) {
  const [rec, setRec]         = useState(undefined) // undefined=loading, null=none
  const [ramp, setRamp]       = useState(null)      // { policyAllowed, compliance, readiness }
  const [busy, setBusy]       = useState(null)      // 'create' | 'verify' | 'remove' | 'policy' | 'rollback' | 'autopilot'
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
  const meta = rec ? (HOSTED_STATUS_META[rec.status] || HOSTED_STATUS_META.pending_dns) : null

  return (
    <div className="mx-6 mt-5 rounded-xl border border-brand-200 bg-brand-50/40 p-5">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <p className="text-sm font-bold text-gray-900">
            Let CyberMeters manage this record
            {!rec && <span className="ml-2 text-xs font-bold uppercase tracking-wide text-brand-700 bg-brand-100 rounded px-1.5 py-0.5">Recommended</span>}
          </p>
          <p className="text-xs text-gray-500 mt-1 leading-relaxed">
            Add one CNAME and we manage the DMARC value for you — no more DNS edits when your
            policy evolves. Reporting keeps flowing to your CyberMeters address.
          </p>
        </div>
        {rec && meta && (
          <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold border ${
            meta.kind === 'good' ? 'bg-brand-50 text-brand-700 border-brand-200'
            : meta.kind === 'warn' ? 'bg-amber-50 text-amber-800 border-amber-200'
            : meta.kind === 'bad' ? 'bg-red-50 text-red-700 border-red-200'
            : 'bg-gray-50 text-gray-500 border-gray-200'}`}>
            {meta.label}
          </span>
        )}
      </div>

      {rec?.issue && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2">
          <Info className="w-3.5 h-3.5 text-amber-700 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-amber-800 leading-relaxed">
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
            {busy === 'create' ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            Set up managed DMARC
          </button>
          {!endpointReady && (
            <p className="text-xs text-gray-400 mt-2">Activate DMARC reporting below first — the managed record includes your reporting address.</p>
          )}
        </div>
      ) : (
        <div className="mt-3 space-y-2.5">
          <p className="text-xs text-gray-600">{meta.hint}</p>
          {rec.status !== 'connected' && rec.status !== 'pending_removal' && (
            <div className="space-y-1.5">
              <div className="grid grid-cols-[70px,1fr] gap-2 items-center">
                <span className="text-xs font-semibold text-gray-500">Type / Name</span>
                <DnsValue value={`CNAME  ${rec.cname_name}`} />
              </div>
              <div className="grid grid-cols-[70px,1fr] gap-2 items-center">
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
                {busy === 'verify' ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
                Check connection
              </button>
            )}
            {rec.status !== 'pending_removal' && (
              <button
                onClick={() => {
                  if (window.confirm('Stop managing this record? You will need to publish your own DMARC TXT again.')) {
                    act('remove', () => api.deleteHostedDmarc(wsId, domain))
                  }
                }}
                disabled={Boolean(busy)}
                className="text-xs text-gray-400 hover:text-red-600 disabled:opacity-50"
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

          {/* ── Self-Driving DMARC: policy ramp (Phase B) ── */}
          {rec.status === 'connected' && rec.policy_step && (
            <div className="pt-5 mt-4 border-t border-brand-100 space-y-5">
              <div className="flex items-end justify-between gap-3 flex-wrap">
                <div>
                  <h4 className="text-base font-bold text-gray-900">Enforcement journey</h4>
                  <p className="text-sm text-gray-500 mt-0.5">Move safely from monitoring to blocking spoofed mail.</p>
                </div>
                {ramp?.compliance && (
                  <div className="text-right">
                    <p className="text-xs font-semibold text-gray-400 uppercase tracking-wide">7-day compliance</p>
                    <p className={`text-2xl font-black tabular-nums leading-none mt-1 ${
                      ramp.compliance.pass_rate == null ? 'text-gray-300'
                      : ramp.compliance.pass_rate >= 97 ? 'text-brand-700' : 'text-amber-600'}`}>
                      {ramp.compliance.pass_rate != null ? `${ramp.compliance.pass_rate}%` : '—'}
                    </p>
                    <p className="text-xs text-gray-400 mt-0.5">
                      {ramp.compliance.pass_rate == null ? 'no reports yet'
                        : `${ramp.compliance.total_messages.toLocaleString()} messages`}
                    </p>
                  </div>
                )}
              </div>

              {/* Ladder track — generous, legible steps */}
              <div className="flex items-stretch gap-1.5 overflow-x-auto pb-1">
                {['Monitor', 'Quarantine 5%', 'Quarantine 25%', 'Quarantine 50%', 'Quarantine', 'Reject'].map((label, i) => {
                  const state = i === rec.policy_step.index ? 'current' : i < rec.policy_step.index ? 'done' : 'future'
                  return (
                    <div key={label} className={`flex-1 min-w-[92px] rounded-xl border px-3 py-2.5 text-center ${
                      state === 'current' ? 'bg-brand-600 border-brand-600 text-white shadow-sm ring-2 ring-brand-200'
                      : state === 'done' ? 'bg-brand-50 border-brand-200 text-brand-700'
                      : 'bg-white border-gray-200 text-gray-400'}`}>
                      <p className="text-[13px] font-bold leading-tight">{label}</p>
                      {state === 'current' && <p className="text-xs font-semibold text-brand-100 mt-0.5">You are here</p>}
                      {state === 'done' && <p className="text-xs text-brand-600 mt-0.5">✓ passed</p>}
                    </div>
                  )
                })}
              </div>

              {rec.change_pending && (
                <p className="text-sm text-amber-700 font-medium bg-amber-50 border border-amber-200 rounded-lg px-3.5 py-2.5">
                  A change is being confirmed — controls unlock automatically once it settles.
                </p>
              )}

              {!ramp?.policyAllowed ? (
                <div className="rounded-xl border border-gray-200 bg-gray-50 px-4 py-3.5">
                  <p className="text-sm text-gray-700">
                    Monitoring is free. <span className="font-bold">Policy changes and Self-Driving DMARC are on paid plans</span> — upgrade to move toward enforcement from here.
                  </p>
                </div>
              ) : (
                <>
                  {rec.next_step && !rec.change_pending && (
                    <div className="space-y-2.5">
                      <button
                        onClick={() => act('policy', async () => {
                          try {
                            return await api.setHostedDmarcPolicy(wsId, domain, rec.next_step.policy, rec.next_step.pct)
                          } catch (e) {
                            if (e?.code === 'readiness_check_failed' || /not ready/i.test(e?.message || '')) {
                              const reasons = (e?.readiness?.reasons || []).join('\n• ')
                              if (window.confirm(`Compliance is not ready yet:\n\n• ${reasons}\n\nMove to ${rec.next_step.label} anyway?`)) {
                                return await api.setHostedDmarcPolicy(wsId, domain, rec.next_step.policy, rec.next_step.pct, true)
                              }
                              return null
                            }
                            throw e
                          }
                        }, { reloadAll: true })}
                        disabled={Boolean(busy)}
                        className="btn-primary w-full justify-center py-3 text-sm disabled:opacity-50"
                      >
                        {busy === 'policy' ? <RefreshCw className="w-4 h-4 animate-spin" /> : <ArrowRight className="w-4 h-4" />}
                        Advance to {rec.next_step.label}
                      </button>
                      {ramp?.readiness && !ramp.readiness.ready && (
                        <div className="flex items-start gap-2 text-sm text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3.5 py-2.5">
                          <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                          <span><span className="font-semibold">Safety interlock:</span> {ramp.readiness.reasons[0]}</span>
                        </div>
                      )}
                      {ramp?.readiness?.ready && (
                        <p className="flex items-center gap-1.5 text-sm text-brand-700 font-semibold">
                          <CheckCircle className="w-4 h-4" /> Compliance is healthy — ready for the next step.
                        </p>
                      )}
                    </div>
                  )}

                  {/* Self-Driving toggle — a real, legible control row */}
                  <label className={`flex items-start gap-3 rounded-xl border px-4 py-3.5 cursor-pointer transition-colors ${
                    rec.autopilot ? 'border-brand-300 bg-brand-50/50' : 'border-gray-200 hover:border-gray-300'}`}>
                    <input
                      type="checkbox"
                      checked={rec.autopilot}
                      disabled={Boolean(busy)}
                      onChange={(e) => act('autopilot', () => api.setHostedDmarcAutopilot(wsId, domain, e.target.checked), { reloadAll: true })}
                      className="mt-0.5 w-4 h-4 rounded border-gray-300 text-brand-600"
                    />
                    <span>
                      <span className="block text-sm font-bold text-gray-900">Self-Driving DMARC</span>
                      <span className="block text-sm text-gray-500 mt-0.5">Advance automatically while compliance stays healthy, and roll back on regressions.</span>
                    </span>
                  </label>

                  {rec.can_rollback && (
                    <button
                      onClick={() => {
                        if (window.confirm('Restore the previous policy value?')) {
                          act('rollback', () => api.rollbackHostedDmarc(wsId, domain), { reloadAll: true })
                        }
                      }}
                      disabled={Boolean(busy)}
                      className="btn-secondary text-sm disabled:opacity-50"
                    >
                      <RefreshCw className={`w-4 h-4 ${busy === 'rollback' ? 'animate-spin' : ''}`} />
                      {busy === 'rollback' ? 'Rolling back…' : 'Roll back last change'}
                    </button>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}
      {error && <p className="text-xs text-red-600 mt-2">{error}</p>}
    </div>
  )
}

function DmarcSetupWizard({ wsId, domain, dmarcDetail, hasScanData, totalMessages }) {
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
    configured:       { kind: 'good', icon: CheckCircle, text: 'DNS looks correctly configured. Your CyberMeters reporting address is in the DMARC record.' },
    missing_rua:      { kind: 'warn', icon: AlertTriangle, text: 'DMARC exists, but CyberMeters reporting address is not included yet. Add it to the rua= tag (see the value above) — do not delete your existing record.' },
    no_dmarc:         { kind: 'warn', icon: Info, text: 'No DMARC record found yet. Add the TXT record above, then check again.' },
    invalid:          { kind: 'warn', icon: AlertTriangle, text: 'We found a DMARC record, but it could not be read as valid. Check the record value above, then re-check.' },
    multiple:         { kind: 'warn', icon: AlertTriangle, text: 'More than one DMARC record was found at _dmarc. DNS allows only one — remove the extra record, then re-check.' },
    endpoint_missing: { kind: 'na',   icon: Info, text: 'Create your reporting address first (use “Activate DMARC reporting” above), then add it to your DMARC record and re-check.' },
    lookup_failed:    { kind: 'na',   icon: Info, text: 'We couldn’t check your DNS just now. This is common while DNS is updating — please try again in a few minutes.' },
    unavailable:      { kind: 'na',   icon: Info, text: 'Click “Verify setup” to check your DNS now, or it will be confirmed automatically once your record includes the CyberMeters address.' },
  }
  const vm = VERIFY_MSG[verifyState]

  const providerCopy = DNS_PROVIDERS.find(p => p.id === provider)?.copy
  const fmt = (t) => (t ? parseServerDate(t).toLocaleString() : null)

  // Per-step completion — explicitly non-linear.
  const steps = ['Choose DNS provider', 'Copy DNS record', 'Verify setup', 'Wait for reports', 'Connected']
  const stepDone = [Boolean(provider), Boolean(inboundMailto), dnsVerified, receiving, fullyConnected]
  const firstIncomplete = stepDone.findIndex(d => !d)
  const currentStep = firstIncomplete === -1 ? steps.length - 1 : firstIncomplete

  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70 flex items-center gap-2.5">
        <div className="w-8 h-8 rounded-lg bg-brand-100 flex items-center justify-center"><ShieldCheck className="w-4 h-4 text-brand-700" /></div>
        <div>
          <span className="eyebrow">Get connected</span>
          <h2 className="section-title leading-tight">DMARC setup wizard</h2>
        </div>
        {fullyConnected ? (
          <span className="ml-auto inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-brand-50 border border-brand-100 text-xs font-semibold text-brand-700">
            <CheckCircle className="w-3.5 h-3.5" /> Connected
          </span>
        ) : needsDnsAction ? (
          <span className="ml-auto inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-50 border border-amber-200 text-xs font-semibold text-amber-800">
            <AlertTriangle className="w-3.5 h-3.5" /> Receiving reports · DNS not verified
          </span>
        ) : null}
      </div>

      <ManagedDmarcCard wsId={wsId} domain={domain} endpointReady={Boolean(inboundMailto)} />
      <ManagedTlsRptCard wsId={wsId} domain={domain} endpointReady={Boolean(inboundMailto)} />
      <ManagedMtaStsCard wsId={wsId} domain={domain} />
      <TlsRptHealthCard wsId={wsId} domain={domain} />

      <div className="p-6 space-y-5">
        {loading ? (
          <div className="flex items-center gap-2 text-sm text-gray-500"><RefreshCw className="w-4 h-4 animate-spin" /> Loading DMARC setup…</div>
        ) : !endpoint || endpoint.status !== 'active' ? (
          <>
            <p className="text-sm text-gray-500 leading-relaxed">
              Set up automatic DMARC reports for <b>{domain}</b> in a few steps. You’ll get a reporting address to add to
              your DNS — then reports flow in on their own. You always make the DNS change yourself; CyberMeters never edits your DNS.
            </p>
            <button onClick={activate} disabled={busy} className="btn-primary disabled:opacity-50">
              {busy ? <><RefreshCw className="w-4 h-4 animate-spin" /> Starting…</> : <><ArrowRight className="w-4 h-4" /> Start DMARC setup</>}
            </button>
          </>
        ) : (
          <>
            <WizardStepper steps={steps} completed={stepDone} current={currentStep} />

            {/* Action-required banner — reports arriving but DNS not verified */}
            {needsDnsAction && (
              <div className="rounded-xl border border-amber-200 bg-amber-50/70 p-4 flex gap-2.5">
                <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-amber-900">
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
                <div className="rounded-lg border border-amber-200 bg-amber-50/60 p-3 text-sm text-amber-900 flex gap-2">
                  <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>You already have a DMARC record. <b>Do not delete it.</b> Just add the CyberMeters reporting address to the existing <code className="mono">rua=</code> tag — the value below already includes both.</span>
                </div>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-[auto,auto,1fr] gap-3">
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
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">3 · Verify setup{dnsVerified && <span className="ml-1.5 text-brand-600 normal-case font-medium">· verified</span>}</p>
              <div className={`rounded-lg border p-3 text-sm flex gap-2 ${vm.kind === 'good' ? 'border-brand-100 bg-brand-50/50 text-brand-800' : vm.kind === 'warn' ? 'border-amber-200 bg-amber-50/50 text-amber-900' : 'border-gray-200 bg-gray-50 text-gray-600'}`}>
                <vm.icon className="w-4 h-4 flex-shrink-0 mt-0.5" /><span>{vm.text}</span>
              </div>
              <button onClick={verifyDns} disabled={checking} className="btn-secondary text-sm disabled:opacity-50">
                {checking ? <><RefreshCw className="w-4 h-4 animate-spin" /> Checking DNS…</> : <><ShieldCheck className="w-4 h-4" /> Verify setup</>}
              </button>
            </div>

            {/* Steps 4 & 5 — wait for reports / connected */}
            <div className="space-y-2">
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">
                4 · {fullyConnected ? 'Connected' : receiving ? 'Reports arriving · finish DNS' : 'Wait for reports'}
              </p>
              {fullyConnected ? (
                <div className="rounded-lg border border-brand-100 bg-brand-50/50 p-3 space-y-1.5">
                  <p className="text-sm text-brand-800 flex items-center gap-1.5"><CheckCircle className="w-4 h-4" /> Connected — DMARC reports are arriving and your DNS record is verified for {domain}.</p>
                  <p className="text-xs text-gray-600">
                    Last report received: <b className="text-gray-700">{fmt(endpoint.last_inbound_at)}</b>.
                    {typeof totalMessages === 'number' && totalMessages > 0 && <> {totalMessages.toLocaleString()} message(s) observed so far.</>} Your sender inventory has started below.
                  </p>
                </div>
              ) : receiving ? (
                <div className="rounded-lg border border-amber-200 bg-amber-50/50 p-3 space-y-1.5">
                  <p className="text-sm text-amber-900 flex items-center gap-1.5"><AlertTriangle className="w-4 h-4" /> Reports are arriving, but DNS is not verified yet.</p>
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
        {err && <span className="text-sm text-red-600 flex items-center gap-1.5"><AlertTriangle className="w-4 h-4" /> {err}</span>}
      </div>
    </section>
  )
}

// ── Email Protection overview: connection status + checklist + ingestion ──────
// Customer-facing answer to "is automated DMARC/RUA ingestion working, and what
// do I do next?" Fetches the ingestion endpoint and derives DNS-verified from
// the latest scan's DMARC record (refined by a live check). Never shows
// "Connected" unless the CyberMeters RUA is in DNS AND a report has arrived.
function epFmt(t) { return t ? parseServerDate(t).toLocaleString() : null }

function EpStatusChecklist({ items }) {
  const ICON = {
    done:    { I: CheckCircle,   cls: 'text-brand-600',  txt: 'Done' },
    needs:   { I: AlertTriangle, cls: 'text-amber-500',  txt: 'Needs action' },
    waiting: { I: Info,          cls: 'text-gray-400',   txt: 'Waiting' },
    unknown: { I: Info,          cls: 'text-gray-300',   txt: 'Unknown' },
  }
  return (
    <div className="card p-5">
      <h3 className="section-title mb-3">Setup progress</h3>
      <ul className="space-y-2.5">
        {items.map(it => {
          const c = ICON[it.status] || ICON.unknown
          return (
            <li key={it.label} className="flex items-center gap-2.5">
              <c.I className={`w-4 h-4 flex-shrink-0 ${c.cls}`} />
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
      <p className={`text-[13px] font-bold mt-2 tabular-nums ${known ? 'text-gray-800' : 'text-gray-400'}`}>
        {known ? (typeof value === 'number' ? value.toLocaleString() : value) : 'Waiting'}
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
        <div className="w-8 h-8 rounded-lg bg-brand-600 flex items-center justify-center"><ShieldCheck className="w-4 h-4 text-white" /></div>
        <div>
          <span className="eyebrow">Auto-fix</span>
          <h2 className="section-title leading-tight">Security gaps &amp; one-click fixes</h2>
        </div>
        {gaps.length === 0 && good.length > 0 && (
          <span className="ml-auto inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-brand-50 border border-brand-100 text-xs font-semibold text-brand-700">
            <CheckCircle className="w-3.5 h-3.5" /> All checks pass
          </span>
        )}
      </div>
      <div className="p-4 space-y-2">
        {[...gaps, ...good].map(item => {
          const open = openId === item.id
          return (
            <div key={item.id} className="rounded-lg border border-gray-200">
              <button onClick={() => toggle(item.id)} className="w-full flex items-center gap-3 px-4 py-3 text-left">
                {item.ok
                  ? <CheckCircle className="w-4 h-4 text-brand-600 flex-shrink-0" />
                  : <AlertTriangle className="w-4 h-4 text-amber-600 flex-shrink-0" />}
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

function ZoneHeader({ n, title, hint }) {
  return (
    <div className="flex items-center gap-3 pt-3">
      <div className="w-7 h-7 rounded-lg bg-gray-900 text-white text-xs font-bold flex items-center justify-center flex-shrink-0">{n}</div>
      <div className="min-w-0 flex-shrink-0">
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
function EmailPostureHero({ wsId, domain, dmarc, policyJourney, onGoto }) {
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

  const total    = dmarc?.traffic?.total_messages ?? 0
  const passRate = dmarc?.traffic?.pass_rate
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
  const stageLabel = { missing: 'No DMARC', monitoring: 'Monitoring (p=none)',
    partial_enforcement: 'Quarantine', full_enforcement: 'Reject' }[stage] || 'Unknown'
  const enforcing = ['partial_enforcement', 'full_enforcement'].includes(stage)
  const cCol = !hasCompliance ? 'text-gray-400' : passRate >= 95 ? 'text-brand-700'
    : passRate >= 80 ? 'text-amber-600' : 'text-red-700'
  const sev = bec ? becSev(bec.exposure_level) : null

  const next = staleScan ? { label: `Re-scan ${domain}`, rescan: true }
    : scanStage === 'missing' ? { label: 'Publish a DMARC record', to: 'dmarc-setup' }
    : !hasCompliance ? { label: 'Connect DMARC reporting', to: 'connect-reporting' }
    : !enforcing ? { label: 'Move toward enforcement', to: 'dmarc-setup' }
    : (passRate != null && passRate < 95) ? { label: 'Fix sender alignment', to: 'sender-inventory' }
    : { label: 'Review sender inventory', to: 'sender-inventory' }

  const pill = (txt, tone) => (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-bold border ${
      tone === 'ok' ? 'bg-brand-50 text-brand-700 border-brand-100'
      : tone === 'warn' ? 'bg-amber-50 text-amber-700 border-amber-200'
      : tone === 'bad' ? 'bg-red-50 text-red-700 border-red-200'
      : 'bg-gray-50 text-gray-500 border-gray-200'}`}>{txt}</span>
  )

  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70 flex items-center gap-2.5">
        <div className="w-8 h-8 rounded-lg bg-brand-600 flex items-center justify-center flex-shrink-0">
          <Mail className="w-4 h-4 text-white" />
        </div>
        <div className="min-w-0">
          <span className="eyebrow">Email protection posture</span>
          <h2 className="section-title leading-tight truncate">Are attackers able to spoof {domain}?</h2>
        </div>
      </div>

      <div className="p-6 grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Compliance — the technical number email teams live by */}
        <div>
          <p className="text-sm font-semibold text-gray-900">DMARC compliance</p>
          <p className={`text-3xl font-black mt-1 tabular-nums ${cCol}`}>{hasCompliance ? `${passRate}%` : '—'}</p>
          <p className="text-xs text-gray-500 mt-1 leading-relaxed">
            {hasCompliance
              ? `of ${total.toLocaleString()} messages passed SPF/DKIM alignment over the reporting window.`
              : staleScan ? 'Re-scan to measure compliance against your newly published DMARC record.'
              : 'Not measured yet — connect DMARC reporting to see who is sending as you.'}
          </p>
        </div>
        {/* Policy state */}
        <div className="md:border-l md:border-gray-100 md:pl-5">
          <p className="text-sm font-semibold text-gray-900">DMARC policy</p>
          <div className="mt-1.5 flex items-center gap-1.5 flex-wrap">
            {pill(stageLabel, enforcing ? 'ok' : stage === 'missing' ? 'bad' : 'warn')}
            {staleScan && (
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-700">
                <CheckCircle className="w-3 h-3" /> Live in DNS
              </span>
            )}
          </div>
          <p className="text-xs text-gray-500 mt-2 leading-relaxed">
            {staleScan ? 'Your DMARC record is published and was just verified in live DNS — your last scan predates it. Re-scan to refresh compliance and exposure.'
              : stage === 'missing' ? 'No policy — receivers have no instruction for spoofed mail.'
              : enforcing ? 'Enforcing — messages that fail authentication are actively blocked.'
              : 'Monitor-only — reports are collected, but spoofed mail is not yet blocked.'}
          </p>
        </div>
        {/* Business exposure — the layer point-tools do not translate */}
        <div className="md:border-l md:border-gray-100 md:pl-5">
          <p className="text-sm font-semibold text-gray-900">Business exposure</p>
          {sev ? (
            <>
              <p className={`text-xl font-bold mt-1 ${sev.text}`}>{titleCase(bec.exposure_level)}</p>
              <p className="text-xs text-gray-500 mt-1 leading-relaxed">
                Impersonation &amp; invoice-fraud exposure · <span className="font-semibold tabular-nums">{bec.exposure_score}/100</span> · higher = worse.
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
            {rescan === 'error' && <span className="text-xs text-red-600 font-medium">Couldn’t start — retry</span>}
            <button
              onClick={() => (next.rescan ? handleRescan() : onGoto?.(next.to))}
              disabled={rescan === 'starting'}
              className="btn-primary text-sm disabled:opacity-60"
            >
              {rescan === 'starting'
                ? (<>Starting… <RefreshCw className="w-4 h-4 animate-spin" /></>)
                : (<>{next.label} {next.rescan ? <RefreshCw className="w-4 h-4" /> : <ArrowRight className="w-4 h-4" />}</>)}
            </button>
          </div>
        )}
      </div>
    </section>
  )
}

function EmailProtectionOverview({ wsId, domain, dmarcDetail, dmarc, senderData, onGotoSetup, onGotoSenders }) {
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
  const messages       = dmarc?.traffic?.total_messages ?? senderData?.summary?.total_messages ?? null
  const aligned        = senderData?.summary?.aligned_messages ?? null
  const unaligned      = senderData?.summary?.failed_messages ?? null
  const hasData        = (messages || 0) > 0 || (sendersCount || 0) > 0

  let state
  if (reportsRcvd && dnsVerified) state = 'connected'
  else if (reportsRcvd) state = 'receiving'
  else if (dnsVerified) state = 'waiting'
  else if (dmarcPresent && inboundAddress) state = 'dns_not_verified'
  else state = 'not_configured'

  const STATE = {
    not_configured:   { tone: 'na',   icon: Info,        title: 'Not configured',         msg: 'Add the CyberMeters RUA address to your DMARC record so reports can be received.' },
    dns_not_verified: { tone: 'warn', icon: AlertTriangle, title: 'DNS not verified',      msg: 'CyberMeters is not listed in your DMARC rua tag yet.' },
    waiting:          { tone: 'info', icon: Inbox,       title: 'Waiting for reports',     msg: 'DNS is ready. Reports usually arrive after mailbox providers send aggregate DMARC reports.' },
    receiving:        { tone: 'warn', icon: ShieldCheck, title: 'Receiving reports · DNS not verified', msg: 'CyberMeters has received DMARC reports for this domain. Finish DNS verification to fully connect.' },
    connected:        { tone: 'ok',   icon: CheckCircle, title: 'Connected',               msg: 'DMARC reporting is connected and receiving data.' },
  }[state]
  const PANEL = {
    ok:   'border-brand-100 bg-brand-50/50',
    warn: 'border-amber-200 bg-amber-50/50',
    info: 'border-blue-100 bg-blue-50/40',
    na:   'border-gray-200 bg-gray-50',
  }[STATE.tone]
  const ICONCLS = { ok: 'text-brand-600', warn: 'text-amber-600', info: 'text-blue-600', na: 'text-gray-400' }[STATE.tone]

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
    ? { text: 'Review your sender inventory.', cta: 'View sender inventory', act: onGotoSenders }
    : state === 'waiting'
      ? { text: 'Your DNS is ready — reports will appear automatically once providers send them.', cta: null }
      : { text: 'Add the CyberMeters RUA address to your DMARC record, then verify.', cta: 'Go to DMARC setup', act: onGotoSetup }

  return (
    <div className="space-y-4">
      {/* Connection status panel */}
      <section className={`card p-5 border ${PANEL}`}>
        <div className="flex items-start gap-3">
          <STATE.icon className={`w-6 h-6 flex-shrink-0 mt-0.5 ${ICONCLS}`} />
          <div className="flex-1 min-w-0">
            <p className="text-base font-bold text-gray-900">{STATE.title}</p>
            <p className="text-sm text-gray-600 mt-0.5 leading-relaxed">{STATE.msg}</p>
            {next?.text && <p className="text-xs text-gray-500 mt-2">{next.text}</p>}
          </div>
          <div className="flex flex-col items-end gap-2 flex-shrink-0">
            <button onClick={verify} disabled={checking || !domain} className="btn-secondary text-sm disabled:opacity-50">
              {checking ? <><RefreshCw className="w-4 h-4 animate-spin" /> Checking DNS…</> : <><ShieldCheck className="w-4 h-4" /> Verify setup</>}
            </button>
            {next?.cta && next.act && (
              <button onClick={next.act} className="text-xs font-medium text-brand-700 hover:text-brand-800">{next.cta} →</button>
            )}
          </div>
        </div>
        {vr && (
          <div className={`mt-3 rounded-lg border p-2.5 text-sm flex items-center gap-2 ${vr.ok ? 'border-brand-100 bg-brand-50/60 text-brand-800' : 'border-amber-200 bg-amber-50/50 text-amber-900'}`}>
            {vr.ok ? <CheckCircle className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}{vr.text}
          </div>
        )}
      </section>

      {/* Metric cards (label-led, numbers below & smaller) */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <EpMetric label="Messages observed" explanation="Across received DMARC reports" value={messages} />
        <EpMetric label="Aligned messages"  explanation="Passed DMARC alignment"        value={aligned} />
        <EpMetric label="Unaligned messages" explanation="Failed alignment — review"    value={unaligned} />
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
  medium:   { text: 'text-amber-700', chip: 'bg-amber-50 text-amber-700 border-amber-200', accent: 'accent-warning' },
  low:      { text: 'text-brand-700', chip: 'bg-brand-50 text-brand-700 border-brand-100', accent: '' },
  minimal:  { text: 'text-brand-700', chip: 'bg-brand-50 text-brand-700 border-brand-100', accent: '' },
}
const becSev = (l) => BEC_SEV[String(l || '').toLowerCase()] || BEC_SEV.medium
const titleCase = (s) => (s ? String(s).replace(/[_-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) : '—')
const becChipCls = (tone) => tone === 'ok' ? 'bg-brand-50 text-brand-700 border-brand-100'
  : tone === 'warn' ? 'bg-amber-50 text-amber-700 border-amber-200' : 'bg-gray-50 text-gray-600 border-gray-200'

function becEvidenceChips(ev) {
  if (!ev || typeof ev !== 'object') return []
  const out = []
  const has = (k) => ev[k] !== undefined && ev[k] !== null
  if (has('dmarc_policy'))   out.push({ label: `DMARC: ${ev.dmarc_policy}`, tone: ev.dmarc_policy === 'none' ? 'warn' : 'neutral' })
  if (has('pass_rate'))      out.push({ label: `Pass rate ${ev.pass_rate}%`, tone: ev.pass_rate < 90 ? 'warn' : 'neutral' })
  if (has('failed_messages'))out.push({ label: `${ev.failed_messages} failed`, tone: ev.failed_messages > 0 ? 'warn' : 'neutral' })
  if (has('unknown_senders'))out.push({ label: `${ev.unknown_senders} unknown sender${ev.unknown_senders === 1 ? '' : 's'}`, tone: ev.unknown_senders > 0 ? 'warn' : 'neutral' })
  if (has('suspicious_senders')) out.push({ label: `${ev.suspicious_senders} suspicious`, tone: ev.suspicious_senders > 0 ? 'warn' : 'neutral' })
  if (has('high_volume_failing_senders')) out.push({ label: `${ev.high_volume_failing_senders} high-volume failing`, tone: ev.high_volume_failing_senders > 0 ? 'warn' : 'neutral' })
  if (has('reports_received')) out.push({ label: ev.reports_received ? 'Reports received' : 'No reports yet', tone: ev.reports_received ? 'ok' : 'neutral' })
  if (has('cybermeters_rua_verified')) out.push({ label: ev.cybermeters_rua_verified ? 'RUA verified in DNS' : 'RUA not verified in DNS', tone: ev.cybermeters_rua_verified ? 'ok' : 'warn' })
  return out
}

function BecExposure({ wsId, domain }) {
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
  const reasons = Array.isArray(data?.reasons) ? data.reasons.slice(0, 4) : []
  const actions = Array.isArray(data?.recommended_actions) ? data.recommended_actions.slice(0, 3) : []

  return (
    <section className={`card overflow-hidden ${data ? sev.accent : ''}`}>
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <span className="eyebrow">Email risk</span>
        <h2 className="section-title leading-tight">Business Email Compromise exposure</h2>
        <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">Estimated from DMARC reports, sender alignment, RUA verification and brand impersonation evidence.</p>
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
              <div className="lg:w-72 flex-shrink-0">
                <p className="text-sm font-semibold text-gray-900">Exposure level</p>
                <p className={`text-lg font-bold ${sev.text}`}>{titleCase(data.exposure_level)}</p>
                <p className="text-sm text-gray-600 mt-1 leading-relaxed">
                  BEC Exposure measures how exposed this domain is to spoofing, supplier impersonation and invoice-fraud abuse.
                </p>
                <p className="text-[13px] font-bold text-gray-700 mt-2 tabular-nums">
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
                <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wide mb-1.5">Evidence</p>
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
                  <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wide mb-2">Why this domain is exposed</p>
                  <ul className="space-y-2.5">
                    {reasons.map((r, i) => (
                      <li key={r.code || i} className="text-sm">
                        <div className="flex items-center gap-2">
                          <span className={`inline-flex px-1.5 py-0.5 rounded text-xs font-bold uppercase border ${becSev(r.severity).chip}`}>{r.severity || '—'}</span>
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
                  <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wide mb-2">Reduce exposure</p>
                  <ul className="space-y-2.5">
                    {actions.map((a, i) => (
                      <li key={a.code || i} className="text-sm">
                        <div className="flex items-center gap-2">
                          <span className={`inline-flex px-1.5 py-0.5 rounded text-xs font-bold uppercase border ${becSev(a.priority).chip}`}>{a.priority || '—'}</span>
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

// ── DMARC report ingestion status (BEC-evidence authoritative) ────────────────
// Preserves the truth distinction: reports_received (backend imported reports)
// vs cybermeters_rua_verified (live DMARC DNS includes our address). Never says
// "Connected" unless BOTH hold. Sender summary comes from BEC evidence.
function DmarcIngestionStatus({ wsId, domain, onGotoSetup, onGotoSenders }) {
  const [bec, setBec] = useState(null)
  const [endpoint, setEndpoint] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    if (!wsId || !domain) { setLoading(false); return }
    setLoading(true); setBec(null); setEndpoint(null)
    Promise.allSettled([api.getBecExposureScore(wsId, domain), api.getDmarcIngestEndpoint(wsId, domain)])
      .then(([b, e]) => {
        if (cancelled) return
        setBec(b.status === 'fulfilled' ? (b.value || null) : null)
        setEndpoint(e.status === 'fulfilled' ? (e.value?.endpoint || null) : null)
      })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [wsId, domain])

  const ev = bec?.evidence || {}
  const reportsReceived = ev.reports_received != null ? Boolean(ev.reports_received) : Boolean(endpoint?.last_inbound_at)
  const dnsVerified = ev.cybermeters_rua_verified != null ? Boolean(ev.cybermeters_rua_verified) : null // null = unknown
  const lastReport = ev.last_report_received_at || endpoint?.last_inbound_at || null
  const passRate = ev.pass_rate
  const failed = ev.failed_messages
  const known = ev.known_senders
  const unknown = ev.unknown_senders
  const suspicious = ev.suspicious_senders
  const hiVolFail = ev.high_volume_failing_senders

  // States A–D. DNS unknown is treated as "not verified" for labelling so we
  // never overclaim — but the chip shows "Unknown" rather than asserting a fault.
  let state
  if (!reportsReceived && dnsVerified === true) state = 'D'
  else if (!reportsReceived) state = 'A'
  else if (dnsVerified === true) state = 'B'
  else state = 'C'

  const STATE = {
    A: { tone: 'na',   icon: Inbox,        label: 'No reports received yet',
         msg: 'CyberMeters has not received DMARC aggregate reports for this domain yet.',
         next: 'Add the CyberMeters reporting address to your DMARC record.', cta: 'View setup instructions', act: onGotoSetup },
    B: { tone: 'ok',   icon: CheckCircle,  label: 'Reports received',
         msg: 'CyberMeters is receiving DMARC aggregate reports and the reporting address is present in DNS.',
         next: 'Review who is sending email using this domain.', cta: 'Review sender activity', act: onGotoSenders },
    C: { tone: 'warn', icon: AlertTriangle, label: 'Reports received · DNS not verified',
         msg: 'CyberMeters is receiving DMARC reports, but the CyberMeters reporting address was not found in the live DMARC DNS record. Reports received do not prove DNS is correctly configured.',
         next: 'Update your DMARC record to include the CyberMeters reporting address.', cta: 'Finish DNS setup', act: onGotoSetup },
    D: { tone: 'info', icon: Inbox,        label: 'DNS verified · waiting for reports',
         msg: 'Your DMARC record includes the CyberMeters reporting address. Reports may take 24–48 hours to arrive depending on mail volume and receivers.',
         next: 'No action needed — reports will appear automatically.', cta: 'Review setup', act: onGotoSetup },
  }[state]
  const PANEL = { ok: 'border-brand-100 bg-brand-50/50', warn: 'border-amber-200 bg-amber-50/50', info: 'border-blue-100 bg-blue-50/40', na: 'border-gray-200 bg-gray-50' }[STATE.tone]
  const ICONCLS = { ok: 'text-brand-600', warn: 'text-amber-600', info: 'text-blue-600', na: 'text-gray-400' }[STATE.tone]
  const dnsLabel = dnsVerified === true ? 'Verified' : dnsVerified === false ? 'Not verified' : 'Unknown'

  const tiles = [
    { label: 'Reports received', value: reportsReceived ? 'Yes' : 'No', tone: reportsReceived ? 'ok' : 'na' },
    { label: 'Last report',      value: lastReport ? new Date(lastReport).toLocaleDateString() : 'Not yet' },
    { label: 'DNS verification', value: dnsLabel, tone: dnsVerified === false ? 'warn' : dnsVerified ? 'ok' : 'na' },
  ]
  if (passRate != null)  tiles.push({ label: 'DMARC pass rate',      value: `${passRate}%`, tone: passRate < 90 ? 'warn' : 'ok' })
  if (suspicious != null) tiles.push({ label: 'Suspicious senders',   value: suspicious, tone: suspicious > 0 ? 'warn' : '' })
  if (hiVolFail != null)  tiles.push({ label: 'High-volume failures', value: hiVolFail, tone: hiVolFail > 0 ? 'warn' : '' })

  const hasSenders = known != null || unknown != null || suspicious != null
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
                <STATE.icon className={`w-6 h-6 flex-shrink-0 mt-0.5 ${ICONCLS}`} />
                <div className="flex-1 min-w-0">
                  <p className="text-base font-bold text-gray-900">{STATE.label}</p>
                  <p className="text-sm text-gray-600 mt-0.5 leading-relaxed">{STATE.msg}</p>
                </div>
                {STATE.act && <button onClick={STATE.act} className="btn-secondary text-sm flex-shrink-0">{STATE.cta}</button>}
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {tiles.map(t => (
                <div key={t.label} className="rounded-xl border border-gray-200 bg-white px-3 py-2.5">
                  <p className="text-xs font-semibold text-gray-700 leading-snug">{t.label}</p>
                  <p className={`text-[13px] font-bold mt-1 tabular-nums ${t.tone === 'warn' ? 'text-amber-700' : t.tone === 'ok' ? 'text-brand-700' : t.tone === 'na' ? 'text-gray-400' : 'text-gray-800'}`}>
                    {typeof t.value === 'number' ? t.value.toLocaleString() : t.value}
                  </p>
                </div>
              ))}
            </div>

            <div className="rounded-xl border border-gray-200 bg-gray-50 p-4 flex flex-col sm:flex-row sm:items-center gap-3">
              <div className="flex-1">
                <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide">Recommended next step</p>
                <p className="text-sm text-gray-700 mt-0.5">{STATE.next}</p>
              </div>
              {STATE.act && <button onClick={STATE.act} className="btn-primary text-sm flex-shrink-0">{STATE.cta} <ArrowRight className="w-4 h-4" /></button>}
            </div>

            {senderSummary && (
              <div>
                <div className="flex items-center justify-between mb-2">
                  <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wide">Sender activity</p>
                  <button onClick={onGotoSenders} className="text-xs font-medium text-brand-700 hover:text-brand-800">View full inventory →</button>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {senderSummary.map(s => (
                    <div key={s.label} className="rounded-lg border border-gray-200 bg-white px-3 py-2">
                      <p className="text-xs font-semibold text-gray-700 leading-snug">{s.label} senders</p>
                      <p className={`text-[13px] font-bold mt-1 tabular-nums ${s.tone === 'warn' ? 'text-amber-700' : 'text-gray-800'}`}>{s.value}</p>
                    </div>
                  ))}
                </div>
                {(passRate != null || failed != null) && (
                  <p className="text-xs text-gray-500 mt-2 leading-relaxed">
                    {passRate != null && <>DMARC pass rate <b className="text-gray-700">{passRate}%</b>. </>}
                    {failed != null && <><b className="text-gray-700">{Number(failed).toLocaleString()}</b> message(s) failed alignment. </>}
                    Reports can arrive from previous or partial DMARC configurations, so review senders before tightening policy.
                  </p>
                )}
              </div>
            )}

            {state === 'C' && (
              <p className="text-xs text-gray-500 leading-relaxed">
                <b>Why this matters:</b> receiving reports confirms mail receivers are sending DMARC data, but until the CyberMeters address is in your live DMARC record, your setup is not complete and reporting coverage may be partial.
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
      {ok ? <CheckCircle className="w-4 h-4 flex-shrink-0" /> : <AlertTriangle className="w-4 h-4 flex-shrink-0" />}
      <span className="flex-1">{toast.msg}</span>
      <button onClick={onClose} className="text-gray-400 hover:text-gray-700"><X className="w-4 h-4" /></button>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function WorkspaceEmailProtectionPage() {
  const { wsId, wsName } = useWorkspace()

  const [scans, setScans]       = useState([])
  const [loading, setLoading]   = useState(true)
  const [error, setError]       = useState(null)
  const [selectedDomain, setSelectedDomain] = useState(null)
  const [report, setReport]     = useState(null)
  const [reportLoading, setReportLoading] = useState(false)
  const [summaryRows, setSummaryRows] = useState([])

  // DMARC Sender Intelligence (new endpoints, keyed by selected domain)
  const [dmarc, setDmarc]         = useState(null)   // dmarc-summary response
  const [senderData, setSenderData] = useState(null) // email-senders response
  const [siLoading, setSiLoading] = useState(false)
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

  const gotoSetup   = () => document.getElementById('dmarc-setup')?.scrollIntoView({ behavior: 'smooth', block: 'start' })
  const gotoSenders = () => document.getElementById('sender-inventory')?.scrollIntoView({ behavior: 'smooth', block: 'start' })

  const header = (
    <div className="flex flex-col lg:flex-row lg:items-end lg:justify-between gap-4 mb-6">
      <div className="min-w-0">
        <span className="eyebrow" style={{ color: '#1A4FB8' }}>Email Protection</span>
        <h1 className="page-title">Email Protection</h1>
        <p className="page-subtitle">Monitor DMARC alignment, sender authentication and report ingestion for your domains.</p>
        <p className="text-xs text-gray-400 mt-1">
          {wsName || 'Workspace'}{selectedDomain ? <> · <span className="mono text-gray-500">{selectedDomain}</span></> : ''}
        </p>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button onClick={gotoSetup} className="btn-primary text-sm"><ShieldCheck className="w-4 h-4" /> Review DMARC setup</button>
        <button onClick={gotoSenders} className="btn-secondary text-sm"><Users className="w-4 h-4" /> View sender inventory</button>
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
        <button onClick={loadScans} className="btn-ghost text-sm" disabled={loading} title="Refresh">
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>
    </div>
  )

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={loadScans}>
      {header}

      {/* No completed scans at all */}
      {domainScans.length === 0 ? (
        <EmptyCard
          title="No email authentication guidance yet"
          body="Run a scan on a domain in this workspace to generate DMARC, SPF, DKIM and BIMI guidance."
          action={<Link to="/scans/new" className="btn-primary">Run a scan</Link>}
        />
      ) : reportLoading ? (
        <EmptyCard icon={RefreshCw} title="Loading email posture…" body="Fetching the latest scan report for this domain." />
      ) : !es ? (
        <EmptyCard title="Email guidance unavailable"
          body="The latest scan for this domain did not return email-security data. Try re-running the scan." />
      ) : moduleErrored ? (
        <EmptyCard icon={AlertTriangle} title="Email module did not complete"
          body="The email-security module reported an error on the last scan. Re-run the scan to try again." />
      ) : notApplicable ? (
        <EmptyCard icon={Info} title="Email guidance not applicable for this domain"
          body={es.applicability?.reason ? `${es.applicability.reason}. This domain is not expected to send mail, so email-authentication findings are not raised.` : 'This domain is not expected to send mail, so email guidance does not apply.'} />
      ) : (
        <div className="space-y-6">
          {toast && <Toast toast={toast} onClose={() => setToast(null)} />}

          <ZoneHeader n="1" title="Your email posture" hint="Can attackers spoof this domain — and what is the business impact?" />

          {/* 0·hero — compliance % + policy + business exposure in one glance */}
          <EmailPostureHero
            wsId={wsId}
            domain={selectedDomain}
            dmarc={dmarc}
            policyJourney={es?.policy_journey}
            onGoto={(target) => document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
          />

          {/* 0. Connection status, checklist, ingestion + metrics — the customer answer */}
          <EmailProtectionOverview
            wsId={wsId}
            domain={selectedDomain}
            dmarcDetail={es?.dmarc_detail}
            dmarc={dmarc}
            senderData={senderData}
            onGotoSetup={gotoSetup}
            onGotoSenders={gotoSenders}
          />

          {/* 0b. BEC Exposure Score (backend source of truth; higher = worse) */}
          <BecExposure wsId={wsId} domain={selectedDomain} />

          {/* 0c. DMARC report ingestion status (reports_received vs DNS verified) */}
          <DmarcIngestionStatus wsId={wsId} domain={selectedDomain} onGotoSetup={gotoSetup} onGotoSenders={gotoSenders} />

          <ZoneHeader n="2" title="Path to enforcement" hint="Where you are, and the ordered steps to safely block spoofing." />

          {/* 1. DMARC journey */}
          <DmarcJourney journey={es.policy_journey} />

          {/* 1b. Enforcement readiness (DMARC sender intelligence) */}
          {dmarc && hasReports && <EnforcementReadiness readiness={dmarc.readiness} />}

          {/* 1c. DMARC summary or get-started hint */}
          {siLoading && !dmarc ? (
            <EmptyCard icon={RefreshCw} title="Loading DMARC sender intelligence…" body="Fetching imported report data for this domain." />
          ) : !dmarc ? (
            <EmptyCard icon={AlertTriangle} title="DMARC summary unavailable"
              body="Sender intelligence could not be loaded for this domain. You can still import a report below." />
          ) : !hasReports ? (
            <EmptyCard icon={Inbox} title="No DMARC reports imported yet"
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
            onGoto={(target) => document.getElementById(target)?.scrollIntoView({ behavior: 'smooth', block: 'start' })}
          />

          <ZoneHeader n="3" title="Senders, setup & validation" hint="Who sends as you, connect reporting, and check any message instantly." />

          {/* 2b. Sender inventory + classification */}
          <div id="sender-inventory" className="scroll-mt-20">
            <SenderInventory data={senderData} onClassify={handleClassify} classifyingId={classifyingId} loading={siLoading} />
          </div>

          {/* 2c. PRIMARY PATH — guided DMARC setup wizard */}
          <div id="dmarc-setup" className="scroll-mt-20">
            <DmarcSetupWizard
              wsId={wsId}
              domain={selectedDomain}
              dmarcDetail={es?.dmarc_detail}
              hasScanData={Boolean(es) && !moduleErrored && !notApplicable}
              totalMessages={dmarc?.traffic?.total_messages ?? null}
            />
          </div>

          {/* 2c-2. Instant sender validation — no waiting for reports */}
          <InstantSourceValidator wsId={wsId} domain={selectedDomain} />

          {/* 2d. Connect DMARC reporting (inbound RUA status + signed upload advanced) */}
          <div id="connect-reporting" className="scroll-mt-20">
            <ConnectDmarcReporting wsId={wsId} domain={selectedDomain} dmarcDetail={es?.dmarc_detail} />
          </div>

          {/* 2e. SECONDARY — manual DMARC report import */}
          <ImportDmarcReport onImport={handleImport} importing={importing} result={importResult} error={importError} />

          {/* 2f. DMARC report history */}
          <div id="report-history" className="scroll-mt-20">
            <DmarcReportHistory wsId={wsId} domain={selectedDomain} />
          </div>

          <ZoneHeader n="4" title="Authentication detail & reference" hint="Records, status and how email risk connects to the rest of your attack surface." />

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
            </div>
          </section>

          {/* 4. Auto-fix registry — every gap + the exact fix */}
          <RemediationsPanel wsId={wsId} domain={selectedDomain} />

          {/* 5. Differentiator */}
          <DifferentiatorBlock wsId={wsId} />

          {/* 6. Multi-domain summary */}
          <MultiDomainSummary rows={summaryRows} selectedDomain={selectedDomain} onSelect={setSelectedDomain} />
        </div>
      )}
    </WsPage>
  )
}
