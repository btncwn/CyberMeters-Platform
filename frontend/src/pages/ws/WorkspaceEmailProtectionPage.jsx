import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  Mail, ShieldCheck, ShieldAlert, KeyRound, Image as ImageIcon, Lock, FileText,
  Copy, Check, AlertTriangle, CheckCircle, ChevronDown, Info, RefreshCw, Globe,
  ArrowRight, Megaphone, Upload, Users, Filter, Gauge, X, Inbox,
} from 'lucide-react'
import { api } from '../../api'
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
      <code className="mono text-[11px] text-gray-800 break-all flex-1 leading-relaxed">{value}</code>
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
          <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${statusPill(statusKind)}`}>
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

function Warnings({ items }) {
  if (!items || items.length === 0) return null
  return (
    <div className="mt-1 space-y-1.5">
      {items.map((w, i) => (
        <p key={i} className="flex items-start gap-1.5 text-[11px] text-amber-700 leading-relaxed">
          <AlertTriangle className="w-3 h-3 flex-shrink-0 mt-0.5" /> {w}
        </p>
      ))}
    </div>
  )
}

// ── Individual auth cards ─────────────────────────────────────────────────────
function SpfCard({ spf, detail }) {
  if (!detail && !spf) return <AuthCard icon={ShieldCheck} title="SPF" status="No data" statusKind="na"><NaNote /></AuthCard>
  const present = spf?.present ?? Boolean(detail?.raw)
  const valid = detail?.valid
  const status = !present ? 'Not found' : valid ? 'Published' : 'Issues found'
  const kind = !present ? 'bad' : valid ? 'good' : 'warn'
  return (
    <AuthCard icon={ShieldCheck} title="SPF" status={status} statusKind={kind}>
      <KV k="Record status" v={!present ? 'Not published' : valid ? 'Valid' : 'Published, needs review'} />
      {detail?.all_mechanism != null && <KV k="‘all’ mechanism" v={detail.all_mechanism} mono />}
      {detail?.policy_strength && <KV k="Policy strength" v={<span className="capitalize">{detail.policy_strength}</span>} />}
      {typeof detail?.lookup_count_estimate === 'number' && (
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
              <span key={i} className="mono text-[10px] bg-gray-50 border border-gray-200 rounded px-1.5 py-0.5 text-gray-700">{inc}</span>
            ))}
          </div>
        </div>
      )}
      {detail?.raw && <DnsValue value={detail.raw} />}
      <Warnings items={detail?.warnings} />
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
        <p className="text-[11px] text-blue-800 leading-relaxed">
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
      <p className="text-[11px] text-gray-500 -mt-1">Readiness only — BIMI is optional and never replaces SPF, DKIM, or DMARC.</p>
      <KV k="Record" v={found ? 'Published' : 'None'} />
      {readiness.logo_url && <KV k="Logo URL" v={readiness.logo_url} mono />}
      {readiness.certificate_url ? <KV k="Certificate URL" v={readiness.certificate_url} mono />
        : found && <KV k="Certificate URL" v={<span className="text-amber-700">Not listed</span>} />}
      {readiness.blockers?.length > 0 && (
        <div className="rounded-lg bg-amber-50 border border-amber-100 p-2.5 space-y-1">
          <p className="text-[11px] font-bold text-amber-700 uppercase tracking-wide">Readiness blockers</p>
          {readiness.blockers.map((b, i) => <p key={i} className="text-[11px] text-amber-800 leading-relaxed">{b}</p>)}
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
            {action.protocol && <span className="text-[10px] font-bold uppercase tracking-wide text-gray-500 bg-gray-100 border border-gray-200 rounded px-1.5 py-0.5">{action.protocol}</span>}
            <span className={`text-[10px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded border ${sev.pill}`}>{sev.label}</span>
            {action.confidence && <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${CONFIDENCE[action.confidence] || CONFIDENCE.low}`}>{action.confidence} confidence</span>}
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
              <p className="text-[11px] text-amber-800 leading-relaxed">{action.caution}</p>
            </div>
          )}
        </div>
      )}
    </div>
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
            Email sender intelligence is part of your external attack surface. Weak authentication and
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

function MultiDomainSummary({ rows, selectedDomain, onSelect }) {
  if (!rows || rows.length < 2) return null
  const cell = (ok) => ok === true ? <CheckCircle className="w-4 h-4 text-brand-600 mx-auto" />
    : ok === false ? <span className="text-gray-300">—</span>
    : <span className="text-gray-300 text-xs">·</span>
  return (
    <section className="card overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70">
        <span className="eyebrow">Workspace overview</span>
        <h2 className="section-title leading-tight">Email posture across {rows.length} domains</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="data-table w-full">
          <thead>
            <tr>
              <th className="text-left">Domain</th>
              <th className="text-left">DMARC stage</th>
              <th className="text-center">SPF</th>
              <th className="text-center">DKIM</th>
              <th className="text-center">BIMI</th>
              <th className="text-center">Open actions</th>
              <th className="text-left">Last scan</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.domain} onClick={() => onSelect(r.domain)}
                className={`cursor-pointer transition-colors ${r.domain === selectedDomain ? 'bg-brand-50/50' : 'hover:bg-gray-50/60'}`}>
                <td><span className="font-semibold text-gray-800 text-sm flex items-center gap-1.5"><Globe className="w-3.5 h-3.5 text-gray-400" />{r.domain}</span></td>
                <td><span className="text-xs font-semibold text-gray-700">{STAGE_LABEL[r.stage] || '—'}</span></td>
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
        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-semibold border ${confPill}`}>
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
      <span className={`metric-value ${tone || ''}`}>{value}</span>
      <span className="metric-label">{label}</span>
      {sub && <span className="metric-sub">{sub}</span>}
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
          {sender.provider_confidence && <span className="block text-[10px] text-gray-400">{sender.provider_confidence} confidence</span>}
        </td>
        <td className="text-right"><span className="text-sm font-semibold text-gray-900">{(sender.total_messages ?? 0).toLocaleString()}</span></td>
        <td className="text-right"><span className={`text-sm font-semibold ${(sender.pass_rate ?? 0) < 90 ? 'text-orange-600' : 'text-gray-900'}`}>{sender.pass_rate ?? 0}%</span></td>
        <td className="text-right"><span className={`text-sm ${(sender.failed_messages ?? 0) > 0 ? 'text-orange-600 font-semibold' : 'text-gray-400'}`}>{(sender.failed_messages ?? 0).toLocaleString()}</span></td>
        <td><span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold uppercase tracking-wide border capitalize ${riskCls}`}>{sender.risk_level || 'low'}</span></td>
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
                <p className="text-[11px] text-gray-400 mt-2">First seen {fmtDate(sender.first_seen)} · Last seen {fmtDate(sender.last_seen)}</p>
                {sender.provider_reason && <p className="text-[11px] text-gray-400 mt-1">{sender.provider_reason}</p>}
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
      if (!prev || new Date(s.created_at) > new Date(prev.created_at)) map.set(s.domain, s)
    }
    return [...map.values()].sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
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

  // Build multi-domain summary (bounded parallel report fetches)
  useEffect(() => {
    if (domainScans.length < 2) { setSummaryRows([]); return }
    let cancelled = false
    const targets = domainScans.slice(0, 10)
    Promise.allSettled(targets.map(s => api.getScanReport(s.id))).then(results => {
      if (cancelled) return
      const rows = results.map((res, i) => {
        const scan = targets[i]
        const es = res.status === 'fulfilled' ? res.value?.modules?.email_security : null
        const applicable = es?.applicability ? es.applicability.applicable !== false : true
        return {
          domain: scan.domain,
          lastScan: scan.created_at,
          stage: es?.policy_journey?.stage || (applicable ? null : 'na'),
          spf: es?.spf_detail ? Boolean(es.spf_detail.valid) : (es?.spf ? Boolean(es.spf.present) : null),
          dkim: es?.dkim_detail ? es.dkim_detail.status === 'detected' : null,
          bimi: es?.bimi_readiness ? Boolean(es.bimi_readiness.record_found) : null,
          openActions: Array.isArray(es?.remediation_actions) ? es.remediation_actions.filter(a => a.status !== 'resolved').length : 0,
        }
      })
      setSummaryRows(rows)
    })
    return () => { cancelled = true }
  }, [domainScans])

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

  const header = (
    <div className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-4 mb-6">
      <div>
        <div className="flex items-center gap-2 mb-2">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-white border border-gray-200 shadow-card text-xs font-semibold text-gray-700">
            <Mail className="w-3.5 h-3.5 text-brand-600" /> Email Protection
          </span>
        </div>
        <h1 className="page-title">Managed DMARC &amp; Email Protection</h1>
        <p className="text-sm text-gray-500 mt-2">
          Guided email-authentication remediation for {wsName || 'this workspace'}.
        </p>
      </div>
      <div className="flex items-center gap-2">
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
        <button onClick={loadScans} className="btn-secondary text-sm" disabled={loading}>
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
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

          {/* 2. Recommended Actions Center — most important */}
          <section>
            <div className="section-head">
              <div>
                <span className="eyebrow">Recommended actions</span>
                <h2 className="section-title mt-1.5">
                  What to fix first {actions.length > 0 && <span className="text-gray-400 font-semibold">· {actions.length} open</span>}
                </h2>
              </div>
            </div>
            {actions.length === 0 ? (
              <EmptyCard icon={CheckCircle} title="No structured remediation actions"
                body="No structured remediation actions were returned for this scan. Your current email-authentication posture has no outstanding guided fixes." />
            ) : (
              <div className="space-y-3">
                {actions.map((a, i) => <ActionCard key={a.id || i} action={a} />)}
              </div>
            )}
          </section>

          {/* 2b. Sender inventory + classification */}
          <SenderInventory data={senderData} onClassify={handleClassify} classifyingId={classifyingId} loading={siLoading} />

          {/* 2c. Manual DMARC report import */}
          <ImportDmarcReport onImport={handleImport} importing={importing} result={importResult} error={importError} />

          {/* 3. Authentication cards */}
          <section>
            <div className="section-head">
              <div>
                <span className="eyebrow">Authentication detail</span>
                <h2 className="section-title mt-1.5">Records &amp; status</h2>
              </div>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              <SpfCard spf={es.spf} detail={es.spf_detail} />
              <DmarcCard dmarc={es.dmarc} detail={es.dmarc_detail} />
              <DkimCard detail={es.dkim_detail} />
              <BimiCard readiness={es.bimi_readiness} />
              <MtaStsCard detail={es.mta_sts_detail} />
              <TlsRptCard detail={es.tls_rpt_detail} />
            </div>
          </section>

          {/* 4. Differentiator */}
          <DifferentiatorBlock wsId={wsId} />

          {/* 5. Multi-domain summary */}
          <MultiDomainSummary rows={summaryRows} selectedDomain={selectedDomain} onSelect={setSelectedDomain} />
        </div>
      )}
    </WsPage>
  )
}
