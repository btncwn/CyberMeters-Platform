import { useState, useEffect, useCallback, useMemo } from 'react'
import { Link } from 'react-router-dom'
import {
  Mail, ShieldCheck, ShieldAlert, KeyRound, Image as ImageIcon, Lock, FileText,
  Copy, Check, AlertTriangle, CheckCircle, ChevronDown, Info, RefreshCw, Globe,
  ArrowRight, Megaphone,
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
            Email authentication weaknesses can increase impersonation risk. Combined with exposed assets
            or a weak external posture, this may increase the likelihood of phishing, invoice fraud, or
            supplier impersonation. CyberMeters connects your email posture to the rest of your external
            attack surface so you can see the whole picture — not just DMARC.
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
            'Email authentication',
            'Exposed external assets',
            'Lookalike / brand abuse',
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

  if (!wsId) return <NoWorkspaceSelected />

  const es = report?.modules?.email_security || null
  const moduleErrored = es?.error
  const notApplicable = es?.applicability && es.applicability.applicable === false
  // Plain computation (not a hook) — safe to run after the early return above.
  const actions = (Array.isArray(es?.remediation_actions) ? [...es.remediation_actions] : [])
    .sort((x, y) => sevCfg(x.severity).rank - sevCfg(y.severity).rank)

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
          {/* 1. DMARC journey */}
          <DmarcJourney journey={es.policy_journey} />

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
