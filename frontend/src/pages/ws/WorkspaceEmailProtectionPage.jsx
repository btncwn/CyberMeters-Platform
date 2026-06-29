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

// ── Connect DMARC reporting (Assisted RUA Ingestion v1 + signed upload) ───────
// Mode A (recommended): a unique inbound rua=mailto address — reports arrive by
// email automatically. Mode B (advanced): a token-authenticated signed upload
// key for scripts/MSP automation. The raw token is shown exactly once; only its
// hash is stored. The inbound address is opaque and reveals no tenancy.
// (Reuses the shared CopyButton defined near the top of this file.)
function ConnectDmarcReporting({ wsId, domain }) {
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
  const fmt = (t) => (t ? new Date(t).toLocaleString() : null)
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
                <span className={`ml-auto inline-flex items-center gap-1.5 text-xs font-medium ${lastInbound ? 'text-brand-700' : 'text-gray-500'}`}>
                  {lastInbound ? <><CheckCircle className="w-3.5 h-3.5" /> Connected</> : <><Info className="w-3.5 h-3.5" /> Not receiving yet</>}
                </span>
              </div>
              <p className="text-sm text-gray-600 leading-relaxed">Add this value to your DMARC record:</p>
              <div className="flex items-center gap-2">
                <code className="mono text-xs flex-1 break-all bg-white border border-gray-200 rounded-lg px-3 py-2">{ruaValue || '—'}</code>
                {ruaValue && <CopyButton value={ruaValue} label="Copy" />}
              </div>
              <p className="text-xs text-gray-500">
                CyberMeters receives aggregate DMARC reports for this domain and updates sender intelligence automatically.
                {lastInbound ? null : ' We have not received a report at this address yet — providers usually send the first report within 24 hours of a DNS change.'}
              </p>
              <dl className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-1 text-xs">
                <div className="rounded-lg bg-white border border-gray-200 px-3 py-2">
                  <dt className="text-gray-400 uppercase tracking-wide font-semibold text-[10px]">Last received</dt>
                  <dd className="text-gray-700 font-medium mt-0.5">{fmt(lastInbound) || 'Not yet'}</dd>
                </div>
                <div className="rounded-lg bg-white border border-gray-200 px-3 py-2">
                  <dt className="text-gray-400 uppercase tracking-wide font-semibold text-[10px]">Last upload</dt>
                  <dd className="text-gray-700 font-medium mt-0.5">{fmt(endpoint.last_signed_upload_at) || 'Never'}</dd>
                </div>
                <div className="rounded-lg bg-white border border-gray-200 px-3 py-2">
                  <dt className="text-gray-400 uppercase tracking-wide font-semibold text-[10px]">Last used</dt>
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
                    POST report XML directly. Last upload: <b className="text-gray-700">{endpoint.last_signed_upload_at ? new Date(endpoint.last_signed_upload_at).toLocaleString() : 'never'}</b>.
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
      <p className="text-[10px] uppercase tracking-wide font-semibold text-gray-400">{label}</p>
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
  const fmt = (t) => (t ? new Date(t).toLocaleString() : null)

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

          {/* 2d. Connect DMARC reporting (inbound RUA status + signed upload advanced) */}
          <ConnectDmarcReporting wsId={wsId} domain={selectedDomain} />

          {/* 2e. SECONDARY — manual DMARC report import */}
          <ImportDmarcReport onImport={handleImport} importing={importing} result={importResult} error={importError} />

          {/* 3. Authentication cards */}
          <section id="auth-detail" className="scroll-mt-20">
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
