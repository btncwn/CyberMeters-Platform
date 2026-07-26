import { useState, useEffect, useCallback, useRef, useMemo } from 'react'
import {
  Tag, ShieldAlert, AlertTriangle, CheckCircle, Info, RefreshCw, Eye, X,
  ChevronDown, ChevronRight, Globe, Search, Pencil, ArrowRight, Radar,
} from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import { SERVICE_COLORS } from '../../theme/serviceColors'
import RiskBadge from '../../components/RiskBadge'
import StatCard from '../../components/StatCard'

// ── helpers ───────────────────────────────────────────────────────────────────
function asList(v) {
  if (Array.isArray(v)) return v
  if (typeof v === 'string' && v.trim()) { try { const p = JSON.parse(v); return Array.isArray(p) ? p : [v] } catch { return v.split(',').map(s => s.trim()).filter(Boolean) } }
  return []
}
function fmtDate(v) {
  if (!v) return null
  const d = new Date(typeof v === 'number' ? v : (String(v).includes('T') ? v : v.replace(' ', 'T') + 'Z'))
  return isNaN(d) ? null : d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
}
function isRecent(v, days = 7) {
  if (!v) return false
  const d = new Date(typeof v === 'number' ? v : (String(v).includes('T') ? v : v.replace(' ', 'T') + 'Z'))
  return !isNaN(d) && (Date.now() - d.getTime()) < days * 86400000
}
function humanize(s) { return String(s).replace(/[_-]+/g, ' ').replace(/\b\w/g, c => c.toUpperCase()) }
const TYPO_VARIANTS = ['typo', 'typosquat', 'homoglyph', 'lookalike', 'misspelling', 'addition', 'omission', 'transposition', 'replacement', 'bitsquat']
function isIdnCandidate(c) { return c?.variant_type === 'homoglyph_idn' || c?.idn_homograph?.visually_confusable === true }
function variantLabel(c) { return isIdnCandidate(c) ? 'Visually confusable IDN' : (c?.variant_type || 'lookalike').replace(/_/g, ' ') }

// Normalise a candidate across new + legacy field names; never invents data.
function normCandidate(c) {
  const dnsActive = c.dns_active ?? (c.dns_resolves === 1 ? true : c.dns_resolves === 0 ? false : null)
  const httpsActive = c.https_active ?? (c.https_available === 1 ? true : c.https_available === 0 ? false : null)
  return {
    ...c,
    _id: c.id ?? c.candidate_id ?? c.candidate_domain,
    _dns: dnsActive, _https: httpsActive, _mx: c.mx_present ?? null,
    _reasons: asList(c.risk_reasons),
    _evidence: asList(c.evidence),
    _new: isRecent(c.first_seen_at),
  }
}

// Evidence signals that carry their own explicit badge copy — mapped here so the
// generic humaniser never renders a raw signal key or an overclaiming phrase. A CT
// observation means a certificate naming the host was logged; it says nothing about
// the host being live or malicious, so the copy is deliberately factual.
const EVIDENCE_SIGNAL_LABELS = {
  ct_observed: 'Seen in certificate log',
  nested_host: 'Subdomain of a lookalike',
  idn_visual_confusable: 'Visually confusable IDN',
  confusable_skeleton_match: 'Confusable character match',
  punycode_decoded: 'Punycode decoded',
  mixed_script: 'Mixed writing scripts',
  whole_script_confusable: 'Whole-script confusable',
}

// Evidence badges — only emitted when the underlying signal genuinely exists.
function evidenceBadges(c) {
  const out = []
  const variant = String(c.variant_type || '').toLowerCase()
  if (isIdnCandidate(c)) out.push('Visually confusable IDN')
  else if (variant === 'nested_host') out.push('Subdomain of a lookalike')
  else if (TYPO_VARIANTS.some(v => variant.includes(v))) out.push('Similar spelling')
  if (c._dns === true) out.push('DNS active')
  else if (c._dns === false) out.push('DNS inactive')
  else out.push('DNS not yet checked')
  if (c._https === true) out.push('HTTPS active')
  else if (c._https === false) out.push('No HTTPS response observed')
  if (c._mx === true) out.push('MX present')
  else if (c._mx === false) out.push('No MX observed')
  if (c._new) out.push('Newly seen')
  for (const e of c._evidence) {
    const signal = typeof e === 'object' ? e.signal : null
    if (signal && EVIDENCE_SIGNAL_LABELS[signal]) { out.push(EVIDENCE_SIGNAL_LABELS[signal]); continue }
    const label = typeof e === 'object' ? (e.label || e.title || e.type || e.name) : e
    if (label) out.push(humanize(label))
  }
  // de-dupe, preserve order
  return [...new Map(out.map(l => [l.toLowerCase(), l])).values()]
}

const CLASSIFY_OPTIONS = [
  { value: 'owned',           label: 'Mark as owned' },
  { value: 'suspicious',      label: 'Mark suspicious' },
  { value: 'monitor',         label: 'Monitor' },
  { value: 'confirmed_abuse', label: 'Confirm abuse' },
  { value: 'false_positive',  label: 'False positive' },
  { value: 'ignored',         label: 'Ignore' },
]
function classMeta(c) {
  const k = (c.classification || c.status || 'unreviewed').toLowerCase()
  switch (k) {
    case 'owned':           return { label: 'Owned',         tone: 'closed' }
    case 'ignored':         return { label: 'Ignored',       tone: 'closed' }
    case 'false_positive':  return { label: 'False positive', tone: 'closed' }
    case 'suspicious':      return { label: 'Suspicious',    tone: 'warn' }
    case 'confirmed_abuse': return { label: 'Confirmed abuse', tone: 'bad' }
    case 'monitor':         return { label: 'Monitoring',    tone: 'info' }
    default:                return { label: 'Needs review',  tone: 'review' }
  }
}
function isUnreviewed(c) {
  const k = (c.classification || c.status || '').toLowerCase()
  return !k || k === 'unreviewed' || k === 'new' || k === 'pending'
}
// owned / ignored / false_positive are closed — they must not count as high-risk.
function isClosed(c) {
  const k = (c.classification || c.status || '').toLowerCase()
  return k === 'owned' || k === 'ignored' || k === 'false_positive'
}
function isHighRisk(c) {
  return ['high', 'critical'].includes(c.risk_level) && !isClosed(c)
}
const CHIP = {
  closed: 'bg-gray-50 text-gray-500 border-gray-200',
  warn:   'bg-amber-50 text-amber-700 border-amber-200',
  bad:    'bg-red-50 text-red-700 border-red-200',
  info:   'bg-blue-50 text-blue-700 border-blue-100',
  review: 'bg-amber-50 text-amber-700 border-amber-200',
}

function Toast({ toast, onClose }) {
  if (!toast) return null
  const ok = toast.kind === 'ok'
  return (
    <div className={`fixed bottom-5 right-5 z-50 flex items-center gap-2.5 px-4 py-3 rounded-xl border text-sm shadow-card-md ${ok ? 'bg-brand-50 border-brand-100 text-brand-800' : 'bg-red-50 border-red-100 text-red-700'}`}>
      {ok ? <CheckCircle className="w-4 h-4" /> : <AlertTriangle className="w-4 h-4" />}
      <span>{toast.msg}</span>
      <button onClick={onClose} className="text-gray-400 hover:text-gray-700"><X className="w-4 h-4" /></button>
    </div>
  )
}

// ── Candidate row (expandable evidence drawer) ────────────────────────────────
function CandidateRow({ c, busy, onClassify }) {
  const [open, setOpen] = useState(false)
  const cm = classMeta(c)
  const badges = evidenceBadges(c)
  const closed = cm.tone === 'closed'
  const firstSeen = fmtDate(c.first_seen_at)
  const lastSeen = fmtDate(c.last_seen_at || c.last_checked_at || c.first_seen_at)
  return (
    <div className={`border-b border-gray-100 ${closed ? 'opacity-70' : ''}`}>
      <div className="px-4 py-3 grid grid-cols-12 gap-3 items-center">
        <button onClick={() => setOpen(o => !o)} className="col-span-12 sm:col-span-4 flex items-center gap-2 text-left min-w-0">
          {open ? <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" /> : <ChevronRight className="w-4 h-4 text-gray-300 flex-shrink-0" />}
          <span className="min-w-0">
            <span className="block mono text-sm text-gray-900 truncate">{c.candidate_domain || '—'}</span>
            {c.unicode_domain && c.unicode_domain !== c.candidate_domain && (
              <span className="block mono text-xs text-gray-600 truncate">{c.unicode_domain}</span>
            )}
            <span className="block text-xs text-gray-400">{variantLabel(c)}</span>
          </span>
        </button>
        <div className="col-span-4 sm:col-span-2"><RiskBadge level={c.risk_level} /></div>
        <div className="col-span-4 sm:col-span-2">
          <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-semibold border ${CHIP[cm.tone]}`}>{cm.label}</span>
        </div>
        <div className="hidden sm:flex sm:col-span-2 flex-wrap gap-1">
          {badges.slice(0, 2).map(b => <span key={b} className="text-[10px] bg-gray-100 text-gray-600 px-1.5 py-0.5 rounded">{b}</span>)}
          {badges.length > 2 && <span className="text-[10px] text-gray-400">+{badges.length - 2}</span>}
        </div>
        <div className="col-span-4 sm:col-span-2 flex justify-end">
          <ClassifyMenu disabled={busy} onPick={v => onClassify(c, v)} />
        </div>
      </div>

      {open && (
        <div className="px-4 pb-4 pt-1 bg-gray-50/60">
          <div className="rounded-xl border border-gray-200 bg-white p-4 space-y-3">
            <div>
              <p className="text-sm font-semibold text-gray-900">Why this matters</p>
              <p className="text-xs text-gray-500 leading-relaxed mt-0.5">
                {isIdnCandidate(c)
                  ? 'This internationalised domain is visually confusable with your protected brand. That is a lookalike signal, not proof of abuse.'
                  : 'This domain resembles your protected brand and could be used for phishing, supplier impersonation or invoice fraud.'}
              </p>
            </div>
            <dl className="grid grid-cols-2 sm:grid-cols-5 gap-3 text-xs">
              <div><dt className="text-gray-400">Risk</dt><dd className="mt-0.5"><RiskBadge level={c.risk_level} /></dd></div>
              <div><dt className="text-gray-400">Similarity</dt><dd className="mt-0.5 font-semibold text-gray-700">{c.similarity_score != null ? `${Math.round(c.similarity_score * (c.similarity_score <= 1 ? 100 : 1))}%` : '—'}</dd></div>
              <div><dt className="text-gray-400">Variant</dt><dd className="mt-0.5 font-semibold text-gray-700">{variantLabel(c)}</dd></div>
              <div><dt className="text-gray-400">First seen</dt><dd className="mt-0.5 font-semibold text-gray-700">{firstSeen || '—'}</dd></div>
              <div><dt className="text-gray-400">Last seen</dt><dd className="mt-0.5 font-semibold text-gray-700">{lastSeen || '—'}</dd></div>
            </dl>
            {badges.length > 0 && (
              <div>
                <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wide mb-1.5">Evidence</p>
                <div className="flex flex-wrap gap-1.5">
                  {badges.map(b => <span key={b} className="inline-flex items-center gap-1 text-[11px] bg-gray-100 text-gray-700 px-2 py-0.5 rounded-md"><Eye className="w-3 h-3 text-gray-400" />{b}</span>)}
                </div>
              </div>
            )}
            {c._reasons.length > 0 && (
              <div>
                <p className="text-[11px] font-semibold text-gray-500 uppercase tracking-wide mb-1.5">Risk reasons</p>
                <ul className="space-y-1">
                  {c._reasons.map((r, i) => (
                    <li key={i} className="text-xs text-gray-600 flex items-start gap-1.5"><AlertTriangle className="w-3.5 h-3.5 text-amber-400 flex-shrink-0 mt-0.5" />{typeof r === 'object' ? (r.label || r.message || JSON.stringify(r)) : r}</li>
                  ))}
                </ul>
              </div>
            )}
            <div className="flex flex-wrap items-center gap-2 pt-1">
              <span className="text-[11px] text-gray-400">Suggested next step:</span>
              <span className="text-xs text-gray-700">{c.action_required || (isUnreviewed(c) ? 'Review and classify this domain.' : classMeta(c).label === 'Confirmed abuse' ? 'Escalate and consider takedown.' : 'No action needed.')}</span>
            </div>
            <div className="flex flex-wrap gap-2 pt-1">
              {CLASSIFY_OPTIONS.map(o => (
                <button key={o.value} disabled={busy} onClick={() => onClassify(c, o.value)}
                  className="text-xs px-2.5 py-1.5 rounded-lg border border-gray-200 text-gray-600 hover:bg-gray-50 hover:text-gray-900 disabled:opacity-50">
                  {o.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function ClassifyMenu({ onPick, disabled }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    function h(e) { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', h); return () => document.removeEventListener('mousedown', h)
  }, [])
  return (
    <div className="relative" ref={ref}>
      <button disabled={disabled} onClick={() => setOpen(o => !o)} className="btn-secondary text-xs py-1.5 px-2.5 disabled:opacity-50">
        Classify <ChevronDown className="w-3.5 h-3.5" />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 w-44 bg-white rounded-xl border border-gray-200 shadow-card-md py-1 z-20">
          {CLASSIFY_OPTIONS.map(o => (
            <button key={o.value} onClick={() => { setOpen(false); onPick(o.value) }}
              className="w-full text-left px-3 py-2 text-xs text-gray-700 hover:bg-gray-50">{o.label}</button>
          ))}
        </div>
      )}
    </div>
  )
}

// ── Protected brand block (+ inline edit) ─────────────────────────────────────
function ProtectedBrand({ profile, editing, setEditing, onSave, saving }) {
  const [form, setForm] = useState({ brand_name: '', primary_domain: '', keywords: '', protected_domains: '' })
  useEffect(() => {
    if (editing) setForm({
      brand_name: profile?.brand_name || '',
      primary_domain: profile?.primary_domain || '',
      keywords: asList(profile?.keywords).join(', '),
      protected_domains: asList(profile?.protected_domains).join(', '),
    })
  }, [editing, profile])

  if (editing) {
    return (
      <section className="card p-6 mb-6">
        <h2 className="section-title mb-4">Update protected brand</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <label className="block"><span className="label mb-1 block">Brand name</span>
            <input className="input text-sm" value={form.brand_name} onChange={e => setForm(f => ({ ...f, brand_name: e.target.value }))} placeholder="Acme Inc." /></label>
          <label className="block"><span className="label mb-1 block">Primary domain</span>
            <input className="input text-sm" value={form.primary_domain} onChange={e => setForm(f => ({ ...f, primary_domain: e.target.value }))} placeholder="acme.com" /></label>
          <label className="block sm:col-span-2"><span className="label mb-1 block">Keywords (comma separated)</span>
            <input className="input text-sm" value={form.keywords} onChange={e => setForm(f => ({ ...f, keywords: e.target.value }))} placeholder="acme, acmepay, acme support" /></label>
          <label className="block sm:col-span-2"><span className="label mb-1 block">Protected domains (comma separated)</span>
            <input className="input text-sm" value={form.protected_domains} onChange={e => setForm(f => ({ ...f, protected_domains: e.target.value }))} placeholder="acme.com, acme.co.uk" /></label>
        </div>
        <div className="flex items-center gap-3 mt-4">
          <button disabled={saving} onClick={() => onSave({
            brand_name: form.brand_name.trim(),
            primary_domain: form.primary_domain.trim(),
            keywords: form.keywords.split(',').map(s => s.trim()).filter(Boolean),
            protected_domains: form.protected_domains.split(',').map(s => s.trim()).filter(Boolean),
          })} className="btn-primary text-sm disabled:opacity-50">
            {saving ? <><RefreshCw className="w-4 h-4 animate-spin" /> Saving…</> : 'Save brand profile'}
          </button>
          <button onClick={() => setEditing(false)} className="text-sm text-gray-500 hover:text-gray-700">Cancel</button>
        </div>
      </section>
    )
  }

  return (
    <section className="card p-6 mb-6">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <span className="eyebrow">Protected brand</span>
          <h2 className="section-title mt-1">{profile?.brand_name || profile?.primary_domain || 'Your brand'}</h2>
        </div>
        <button onClick={() => setEditing(true)} className="btn-secondary text-sm flex-shrink-0"><Pencil className="w-4 h-4" /> Edit</button>
      </div>

      {!profile ? (
        <p className="text-sm text-gray-500 mt-3 leading-relaxed">
          No brand profile yet. Brand monitoring is currently inferred from your workspace domains — add a brand profile to sharpen detection.
        </p>
      ) : (
        <>
          {profile.inferred && (
            <div className="mt-3 rounded-lg border border-amber-200 bg-amber-50/60 p-3 text-sm text-amber-900 flex gap-2">
              <Info className="w-4 h-4 flex-shrink-0 mt-0.5" />
              CyberMeters is currently inferring brand monitoring from your workspace domains.
            </div>
          )}
          <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-3 mt-4 text-sm">
            <div><dt className="text-xs text-gray-400">Primary domain</dt><dd className="mono text-gray-800 mt-0.5">{profile.primary_domain || '—'}</dd></div>
            <div><dt className="text-xs text-gray-400">Status</dt><dd className="text-gray-800 mt-0.5">{profile.inferred ? 'Inferred from workspace' : 'Configured'}{fmtDate(profile.updated_at || profile.last_updated_at) ? ` · updated ${fmtDate(profile.updated_at || profile.last_updated_at)}` : ''}</dd></div>
            <div className="sm:col-span-2"><dt className="text-xs text-gray-400">Protected domains</dt>
              <dd className="mt-1 flex flex-wrap gap-1.5">{asList(profile.protected_domains).length ? asList(profile.protected_domains).map(d => <span key={d} className="mono text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded">{d}</span>) : <span className="text-gray-400 text-xs">None</span>}</dd></div>
            <div className="sm:col-span-2"><dt className="text-xs text-gray-400">Keywords</dt>
              <dd className="mt-1 flex flex-wrap gap-1.5">{asList(profile.keywords).length ? asList(profile.keywords).map(k => <span key={k} className="text-xs bg-brand-50 text-brand-700 px-2 py-0.5 rounded">{k}</span>) : <span className="text-gray-400 text-xs">None</span>}</dd></div>
          </dl>
        </>
      )}
    </section>
  )
}

const FILTERS = [
  { key: '',           label: 'All' },
  { key: 'high',       label: 'High risk' },
  { key: 'unreviewed', label: 'Unreviewed' },
  { key: 'suspicious', label: 'Suspicious' },
  { key: 'owned',      label: 'Owned' },
  { key: 'ignored',    label: 'Ignored' },
]

const CASE_CHIP = {
  detected: 'bg-amber-50 text-amber-700 border-amber-200',
  triage: 'bg-amber-50 text-amber-700 border-amber-200',
  confirmed_abuse: 'bg-red-50 text-red-700 border-red-200',
  customer_approval: 'bg-blue-50 text-blue-700 border-blue-200',
  evidence_ready: 'bg-brand-50 text-brand-700 border-brand-100',
  takedown_submitted: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  provider_followup: 'bg-indigo-50 text-indigo-700 border-indigo-200',
  verification_pending: 'bg-gray-50 text-gray-700 border-gray-200',
  resolved: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  provider_no_response: 'bg-red-50 text-red-700 border-red-200',
  reappeared: 'bg-red-50 text-red-700 border-red-200',
}

function ManagedBrandCases({ cases, busyId, onReview, onApprove, onSubmit }) {
  if (!cases?.length) return null
  return (
    <section id="managed-brand-cases" className="card p-5 mb-6 scroll-mt-20">
      <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3 mb-4">
        <div>
          <span className="eyebrow">Managed takedown cases</span>
          <h2 className="section-title mt-1">Brand abuse workflow</h2>
          <p className="text-sm text-gray-500 mt-1 max-w-2xl">
            Human review controls classification and approval. CyberMeters only marks removal after technical verification.
          </p>
        </div>
        <span className="text-xs text-gray-400">{cases.length} case{cases.length === 1 ? '' : 's'}</span>
      </div>
      <div className="space-y-3">
        {cases.map((c) => {
          const status = String(c.status || '').replace(/_/g, ' ')
          const bundleReady = c.evidence?.bundle
          return (
            <div key={c.id} id={`case-${c.id}`} className="rounded-xl border border-gray-200 p-4 scroll-mt-20">
              <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="mono text-sm font-semibold text-gray-900">{c.domain}</span>
                    <span className={`inline-flex px-2 py-0.5 rounded-full border text-[11px] font-semibold ${CASE_CHIP[c.status] || 'bg-gray-50 text-gray-600 border-gray-200'}`}>
                      {humanize(status)}
                    </span>
                    <RiskBadge level={c.severity} />
                  </div>
                  <p className="text-xs text-gray-500 mt-1">
                    Protected brand: <span className="mono">{c.asset_ref || '—'}</span>
                  </p>
                  <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-xs text-gray-500">
                    {c.lifecycle?.first_seen_at && <span>Case opened {fmtDate(c.lifecycle.first_seen_at)}</span>}
                    {c.lifecycle?.reappearance_count > 0 && (
                      <span className="font-semibold text-red-700">
                        Reappeared {c.lifecycle.reappearance_count} time{c.lifecycle.reappearance_count === 1 ? '' : 's'}
                      </span>
                    )}
                    {c.campaign_id && (
                      <span>Evidence-linked campaign <span className="mono">{c.campaign_id}</span></span>
                    )}
                  </div>
                  {bundleReady && (
                    <div className="mt-3 rounded-lg bg-gray-50 border border-gray-100 p-3 text-xs text-gray-600">
                      <p className="font-semibold text-gray-800">Evidence bundle ready</p>
                      <p className="mt-1">DNS, registrar/provider contacts and abuse indicators are prepared for takedown submission.</p>
                    </div>
                  )}
                </div>
                <div className="flex flex-wrap gap-2 lg:justify-end">
                  {c.status === 'detected' || c.status === 'triage' ? (
                    <>
                      <button disabled={busyId === c.id} onClick={() => onReview(c, 'confirmed_abuse')} className="btn-primary text-xs py-2 disabled:opacity-50">
                        Confirm abuse
                      </button>
                      <button disabled={busyId === c.id} onClick={() => onReview(c, 'false_positive')} className="btn-secondary text-xs py-2 disabled:opacity-50">
                        False positive
                      </button>
                    </>
                  ) : null}
                  {c.status === 'confirmed_abuse' || c.status === 'customer_approval' ? (
                    <button disabled={busyId === c.id} onClick={() => onApprove(c)} className="btn-primary text-xs py-2 disabled:opacity-50">
                      Approve takedown prep
                    </button>
                  ) : null}
                  {c.status === 'evidence_ready' ? (
                    <button disabled={busyId === c.id} onClick={() => onSubmit(c)} className="btn-primary text-xs py-2 disabled:opacity-50">
                      Record submission
                    </button>
                  ) : null}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </section>
  )
}

export default function BrandMonitoringPage() {
  const { wsId, wsName } = useWorkspace()
  const [profile, setProfile]       = useState(null)
  const [summary, setSummary]       = useState(null)
  const [candidates, setCandidates] = useState([])
  const [cases, setCases]           = useState([])
  const [loading, setLoading]       = useState(true)
  const [error, setError]           = useState(null)
  const [editing, setEditing]       = useState(false)
  const [saving, setSaving]         = useState(false)
  const [busyId, setBusyId]         = useState(null)
  const [filter, setFilter]         = useState('')
  const [toast, setToast]           = useState(null)
  const queueRef = useRef(null)

  const showToast = (kind, msg) => { setToast({ kind, msg }); setTimeout(() => setToast(null), 3500) }

  const load = useCallback(async () => {
    if (!wsId) { setLoading(false); return }
    setLoading(true); setError(null)
    try {
      const [p, s, c, mc] = await Promise.allSettled([
        api.getBrandProfile(wsId),
        api.getBrandSummary(wsId),
        api.getBrandCandidates(wsId, {}),
        api.getBrandCases(wsId, {}),
      ])
      setProfile(p.status === 'fulfilled' ? (p.value?.profile ?? p.value ?? null) : null)
      setSummary(s.status === 'fulfilled' ? (s.value?.summary ?? s.value ?? null) : null)

      let cands = c.status === 'fulfilled' ? (c.value?.candidates ?? (Array.isArray(c.value) ? c.value : null)) : null
      if (!Array.isArray(cands)) {
        // Graceful fallback to legacy brand-monitoring data.
        try { const legacy = await api.getWorkspaceBrandMonitoring(wsId, {}); cands = legacy.candidates || [] }
        catch { cands = [] }
      }
      setCandidates((cands || []).map(normCandidate))
      setCases(mc.status === 'fulfilled' ? (mc.value?.cases || []) : [])
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [wsId])

  useEffect(() => { load() }, [load])

  useEffect(() => {
    const target = new URLSearchParams(window.location.search).get('case')
    if (!target || !cases.some(c => c.id === target)) return
    window.requestAnimationFrame(() => {
      document.getElementById(`case-${target}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    })
  }, [cases])

  async function handleSave(payload) {
    setSaving(true)
    try {
      await api.updateBrandProfile(wsId, payload)
      showToast('ok', 'Brand profile updated.')
      setEditing(false)
      await load()
    } catch (e) {
      if (e.status === 403) showToast('err', 'You need workspace management permission to update the brand profile.')
      else showToast('err', e.message || 'Could not save brand profile.')
    } finally { setSaving(false) }
  }

  async function handleClassify(c, value) {
    setBusyId(c._id)
    try {
      await api.classifyBrandCandidate(wsId, c._id, value)
      showToast('ok', 'Classification updated.')
      await load()
    } catch (e) {
      if (e.status === 403) showToast('err', 'You need workspace management permission to classify brand risks.')
      else showToast('err', e.message || 'Could not update classification.')
    } finally { setBusyId(null) }
  }

  async function handleCaseReview(caseRow, classification) {
    const reason = classification === 'confirmed_abuse'
      ? 'Confirmed from Brand Protection review.'
      : 'Reviewed and marked as false positive.'
    setBusyId(caseRow.id)
    try {
      await api.reviewBrandCase(wsId, caseRow.id, { classification, reason })
      showToast('ok', 'Brand case updated.')
      await load()
    } catch (e) {
      if (e.status === 403) showToast('err', 'You need workspace management permission to review brand cases.')
      else showToast('err', e.message || 'Could not update brand case.')
    } finally { setBusyId(null) }
  }

  async function handleCaseApprove(caseRow) {
    setBusyId(caseRow.id)
    try {
      await api.approveBrandTakedown(wsId, caseRow.id, { reason: 'Approved for takedown preparation.' })
      showToast('ok', 'Evidence bundle prepared.')
      await load()
    } catch (e) {
      if (e.status === 403) showToast('err', 'You need workspace management permission to approve takedown prep.')
      else showToast('err', e.message || 'Could not prepare evidence bundle.')
    } finally { setBusyId(null) }
  }

  async function handleCaseSubmit(caseRow) {
    const submission_reference = window.prompt('Submission reference from the registrar or provider')
    if (!submission_reference?.trim()) return
    setBusyId(caseRow.id)
    try {
      await api.recordBrandTakedownSubmission(wsId, caseRow.id, { submission_reference: submission_reference.trim() })
      showToast('ok', 'Takedown submission recorded.')
      await load()
    } catch (e) {
      if (e.status === 403) showToast('err', 'You need workspace management permission to record submissions.')
      else showToast('err', e.message || 'Could not record takedown submission.')
    } finally { setBusyId(null) }
  }

  // Whenever candidates are loaded, the displayed summary is computed FROM the
  // candidate list so the cards always match the table. /brand/summary is used
  // only as a fallback before candidate data is available (e.g. transient load).
  const metrics = useMemo(() => {
    if (candidates.length > 0) {
      // Tri-state DNS truth: _dns === true active, === false checked-inactive,
      // null/undefined not yet checked. Unchecked is NEVER folded into inactive.
      return {
        lookalike:   candidates.length,
        activeDns:   candidates.filter(c => c._dns === true).length,
        inactiveDns: candidates.filter(c => c._dns === false).length,
        uncheckedDns: candidates.filter(c => c._dns == null).length,
        highRisk:    candidates.filter(isHighRisk).length,
        suspicious:  candidates.filter(c => (c.classification || c.status) === 'suspicious').length,
        unreviewed:  candidates.filter(isUnreviewed).length,
      }
    }
    const num = v => (typeof v === 'number' ? v : 0)
    return {
      lookalike:   num(summary?.total_candidates ?? summary?.candidates ?? summary?.lookalike_candidates),
      activeDns:   num(summary?.active_dns ?? summary?.dns_active),
      inactiveDns: num(summary?.inactive_dns),
      uncheckedDns: num(summary?.unchecked_dns),
      highRisk:    num(summary?.high_risk),
      suspicious:  num(summary?.suspicious),
      unreviewed:  num(summary?.unreviewed ?? summary?.needs_review),
    }
  }, [summary, candidates])

  const filtered = useMemo(() => candidates.filter(c => {
    if (filter === 'high') return isHighRisk(c)
    if (filter === 'unreviewed') return isUnreviewed(c)
    if (filter === 'suspicious') return (c.classification || c.status) === 'suspicious'
    if (filter === 'owned') return (c.classification || c.status) === 'owned'
    if (filter === 'ignored') return ['ignored', 'false_positive'].includes(c.classification || c.status)
    return true
  }), [candidates, filter])

  const actions = useMemo(() => {
    const a = []
    if (metrics.highRisk > 0)   a.push({ icon: ShieldAlert, tone: 'bad',  text: `Review ${metrics.highRisk} high-risk lookalike domain${metrics.highRisk === 1 ? '' : 's'}.`, to: 'high' })
    if (metrics.unreviewed > 0) a.push({ icon: Search,      tone: 'warn', text: `Classify ${metrics.unreviewed} unreviewed candidate${metrics.unreviewed === 1 ? '' : 's'}.`, to: 'unreviewed' })
    if (metrics.suspicious > 0) a.push({ icon: Eye,         tone: 'warn', text: `Keep monitoring ${metrics.suspicious} suspicious domain${metrics.suspicious === 1 ? '' : 's'}.`, to: 'suspicious' })
    if (metrics.unreviewed > 0) a.push({ icon: CheckCircle, tone: 'info', text: 'Mark owned domains and false positives to reduce noise.', to: '' })
    return a
  }, [metrics])

  if (!wsId) return <NoWorkspaceSelected />
  const scrollToQueue = () => queueRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading} error={error} onRetry={load}>

      {/* 1 · Hero */}
      <div className="card p-6 mb-6 flex flex-col lg:flex-row lg:items-center gap-5">
        <div className="w-12 h-12 rounded-2xl flex items-center justify-center flex-shrink-0" style={{ background: SERVICE_COLORS.brand.chip }}>
          <Radar className="w-6 h-6" style={{ color: SERVICE_COLORS.brand.icon }} />
        </div>
        <div className="flex-1 min-w-0">
          <span className="eyebrow" style={{ color: SERVICE_COLORS.brand.text }}>Brand Protection</span>
          <h1 className="page-title">Brand Protection</h1>
          <p className="page-subtitle">Monitor lookalike domains, typosquats, impersonation risk and brand-abuse signals.</p>
        </div>
        <div className="flex flex-wrap items-center gap-3 flex-shrink-0">
          <button onClick={scrollToQueue} className="btn-primary text-sm"><ShieldAlert className="w-4 h-4" /> Review suspicious domains</button>
          <button onClick={() => setEditing(true)} className="btn-secondary text-sm"><Pencil className="w-4 h-4" /> Update protected brand</button>
        </div>
      </div>

      {/* 2 · Protected brand */}
      <ProtectedBrand profile={profile} editing={editing} setEditing={setEditing} onSave={handleSave} saving={saving} />

      {/* 3 · Risk overview (label-led, numbers below & smaller) */}
      <div id="brand-summary" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4 mb-6 scroll-mt-20">
        <StatCard icon={Globe}       label="Lookalike candidates" explanation="Domains resembling your brand"        value={metrics.lookalike} />
        <StatCard icon={Globe}       label="Active DNS"           explanation={
          metrics.uncheckedDns > 0
            ? `${metrics.uncheckedDns} not yet checked${metrics.inactiveDns > 0 ? ` · ${metrics.inactiveDns} inactive` : ''}`
            : (metrics.inactiveDns > 0 ? `${metrics.inactiveDns} checked, not resolving` : 'Candidates currently resolving')
        } value={metrics.activeDns} tone={metrics.activeDns > 0 ? 'info' : undefined} />
        <StatCard icon={ShieldAlert} label="High-risk candidates" explanation="May need immediate review"            value={metrics.highRisk}   danger={metrics.highRisk > 0} />
        <StatCard icon={Eye}         label="Suspicious"           explanation="Flagged for impersonation risk"       value={metrics.suspicious} warning={metrics.suspicious > 0} />
        <StatCard icon={Search}      label="Unreviewed"           explanation="Awaiting your classification"         value={metrics.unreviewed} warning={metrics.unreviewed > 0} />
      </div>

      {/* 4 · Recommended actions */}
      {actions.length > 0 && (
        <section className="mb-6">
          <h2 className="section-title mb-3">Recommended actions</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {actions.map((a, i) => (
              <button key={i} onClick={() => { if (a.to !== undefined) setFilter(a.to); scrollToQueue() }}
                className="card p-4 flex items-center gap-3 text-left hover:border-brand-200 hover:shadow-card-md transition-all">
                <span className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${a.tone === 'bad' ? 'bg-red-50 text-red-600' : a.tone === 'warn' ? 'bg-amber-50 text-amber-600' : 'bg-brand-50 text-brand-600'}`}>
                  <a.icon className="w-4 h-4" />
                </span>
                <span className="text-sm text-gray-700 flex-1">{a.text}</span>
                <ArrowRight className="w-4 h-4 text-gray-300" />
              </button>
            ))}
          </div>
        </section>
      )}

      <ManagedBrandCases
        cases={cases}
        busyId={busyId}
        onReview={handleCaseReview}
        onApprove={handleCaseApprove}
        onSubmit={handleCaseSubmit}
      />

      {/* 5 · Investigation queue */}
      <section ref={queueRef} id="typosquats" className="card overflow-hidden scroll-mt-20">
        <div className="px-5 py-4 border-b border-gray-100 flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="section-title">Suspicious domain queue</h2>
            <p className="text-xs text-gray-400 mt-0.5">{filtered.length} of {candidates.length} shown</p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {FILTERS.map(f => (
              <button key={f.key} onClick={() => setFilter(f.key)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${filter === f.key ? 'bg-brand-600 text-white' : 'text-gray-500 hover:bg-gray-100 border border-gray-200'}`}>
                {f.label}
              </button>
            ))}
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="py-14 text-center">
            <Globe className="w-10 h-10 text-gray-200 mx-auto mb-3" />
            <p className="text-sm font-medium text-gray-600">{candidates.length === 0 ? 'No lookalike domains found yet.' : 'No candidates match this filter.'}</p>
            <p className="text-xs text-gray-400 mt-1">{candidates.length === 0 ? 'CyberMeters will continue monitoring brand-abuse signals as new scans run.' : 'Try a different filter above.'}</p>
          </div>
        ) : (
          <>
            <div className="hidden sm:grid grid-cols-12 gap-3 px-4 py-2 bg-gray-50/70 text-[10px] font-semibold text-gray-400 uppercase tracking-wide">
              <span className="col-span-4">Candidate domain</span>
              <span className="col-span-2">Risk</span>
              <span className="col-span-2">Classification</span>
              <span className="col-span-2">Evidence</span>
              <span className="col-span-2 text-right">Action</span>
            </div>
            {filtered.map(c => <CandidateRow key={c._id} c={c} busy={busyId === c._id} onClassify={handleClassify} />)}
          </>
        )}
      </section>

      <Toast toast={toast} onClose={() => setToast(null)} />
    </WsPage>
  )
}
