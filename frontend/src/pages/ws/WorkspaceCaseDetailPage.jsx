// Universal Case Detail — the ONE canonical customer-facing case surface across
// all eight Cyber MOT domains. It is ADDITIVE: it coexists with the bespoke ASM,
// Brand and per-domain lifecycle panels (which keep their domain-specific side
// effects) and links out to them for domain-specific actions. It never decides a
// transition — the backend universal validator does — and it never re-derives a
// verification verdict: `verification_support` arrives from the backend and the
// honest label comes from the shared caseDisplay vocabulary.
import { useCallback, useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { ArrowLeft, ExternalLink, Clock, FileSearch, MapPin, RefreshCw, ShieldCheck, Info } from 'lucide-react'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import OwnerPicker from '../../components/OwnerPicker'
import {
  phaseMeta, phaseClass, domainKeyLabel,
  ATTESTED_LABEL, EXTERNAL_EVIDENCE_LABEL,
} from '../../lib/caseDisplay'
import { SERVICE_COLORS } from '../../theme/serviceColors'

// domain_key → { service-colour key, bespoke domain workflow route }.
const DOMAIN_META = {
  email_protection:               { svc: 'email',            route: '/ws/email-protection',        actionLabel: 'Email Protection workflow' },
  brand_protection:               { svc: 'brand',            route: '/ws/brand-monitoring',        actionLabel: 'Brand Monitoring workflow' },
  attack_surface:                 { svc: 'surface',          route: '/assets',                     actionLabel: 'Attack Surface workflow' },
  certificates_trust:             { svc: 'certs',            route: '/ws/certificates/lifecycle',  actionLabel: 'Certificate Lifecycle workflow' },
  cyber_essentials_readiness:     { svc: 'cyber_essentials', route: '/ws/cyber-essentials',        actionLabel: 'Cyber Essentials workflow' },
  website_security:               { svc: 'website',          route: '/ws/website-security',        actionLabel: 'Website Security workflow' },
  identity_exposure:              { svc: 'identity',         route: '/ws/identity-exposure',       actionLabel: 'Identity Exposure workflow' },
  shadow_it_unmanaged_technology: { svc: 'shadow_it',        route: '/ws/shadow-it',               actionLabel: 'Shadow IT workflow' },
}

// The customer-assertion-vs-verification explainer, driven by the backend's
// per-finding verification_support. This is the heart of the honesty contract:
// completion is never silently upgraded to "verified".
const SUPPORT_EXPLAINER = {
  automated: { tone: 'green', text: 'CyberMeters re-observes this fix itself. When resolved, this case can be marked “Verified by CyberMeters”.' },
  manual:    { tone: 'blue',  text: `CyberMeters cannot observe this fix externally. Your completion is recorded as an attestation — “${ATTESTED_LABEL}” — and is never shown as Verified.` },
  external:  { tone: 'blue',  text: `${EXTERNAL_EVIDENCE_LABEL}: resolution is confirmed by an independent third party (for example a certification body), not by a CyberMeters scan or by your own confirmation.` },
  unsupported: { tone: 'slate', text: 'There is no verification path for this finding on the platform today.' },
}

const CARD = 'rounded-xl border border-slate-200 bg-white p-5'
const SUPPORT_TONE = {
  green: 'bg-green-50 text-green-800 border-green-200',
  blue:  'bg-blue-50 text-blue-800 border-blue-200',
  slate: 'bg-slate-50 text-slate-700 border-slate-200',
}

function fmt(ts) {
  if (!ts) return '—'
  return String(ts).replace('T', ' ').replace('Z', '').slice(0, 16)
}

// Present one append-only history event honestly (assignment, creation, transitions).
function eventLabel(ev) {
  const a = ev.action || ''
  if (a === 'case_created') return 'Case opened'
  if (a === 'assignment_changed') return 'Owner assigned'
  if (a.startsWith('transition_')) return `Moved to ${a.replace('transition_', '').replace(/_/g, ' ')}`
  if (a === 'status_changed') return `Status changed ${ev.from_status || '?'} → ${ev.to_status || '?'}`
  if (a === 'case_reopened' || ev.to_status === 'reopened') return 'Reopened (condition re-observed)'
  return a.replace(/_/g, ' ') || 'Update'
}

export default function WorkspaceCaseDetailPage() {
  const { caseId } = useParams()
  const navigate = useNavigate()
  const { wsId, wsName, workspaces, loading: wsLoading } = useWorkspace()

  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const role = workspaces.find((w) => w.id === wsId)?.role || null
  const canManage = role === 'owner' || role === 'admin'

  const load = useCallback(() => {
    if (!wsId || !caseId) return
    setLoading(true)
    api.getCase(wsId, caseId)
      .then((res) => { setData(res); setError(null) })
      .catch(() => setError('Could not load this case.'))
      .finally(() => setLoading(false))
  }, [wsId, caseId])

  useEffect(() => { load() }, [load])

  if (!wsLoading && !wsId) return <NoWorkspaceSelected />

  const c = data?.case
  const events = data?.events || []
  const meta = c ? phaseMeta(c.canonical_phase, c.verification_support) : null
  const dmeta = c ? (DOMAIN_META[c.domain_key] || null) : null
  const svc = dmeta ? SERVICE_COLORS[dmeta.svc] : null
  const support = c ? (SUPPORT_EXPLAINER[c.verification_support] || SUPPORT_EXPLAINER.unsupported) : null

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading || wsLoading} error={error} onRetry={load}>
      {c && (
        <div className="space-y-5">
          <button onClick={() => navigate(-1)} className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-700">
            <ArrowLeft className="w-4 h-4" /> Back
          </button>

          {/* ── Header ─────────────────────────────────────────────────── */}
          <div className={CARD}>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <span
                  className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium border mb-2"
                  style={svc ? { backgroundColor: svc.chip, color: svc.text, borderColor: svc.ring } : undefined}
                >
                  {domainKeyLabel(c.domain_key)}
                </span>
                <h1 className="text-lg font-semibold text-slate-900 truncate">{c.title || c.source_finding_type || c.case_id}</h1>
                {c.summary && <p className="text-sm text-slate-600 mt-1">{c.summary}</p>}
              </div>
              <span className={`inline-block rounded-full border px-2.5 py-1 text-xs font-medium whitespace-nowrap ${phaseClass(c.canonical_phase, c.verification_support)}`}>
                {meta.label}
              </span>
            </div>
            <div className="flex flex-wrap gap-x-6 gap-y-1 mt-3 text-xs text-slate-500">
              <span>Severity: <span className="text-slate-700 capitalize">{c.severity || '—'}</span></span>
              <span>Opened: {fmt(c.created_at)}</span>
              <span>Updated: {fmt(c.updated_at)}</span>
              <span className="font-mono text-slate-400">{c.case_id}</span>
            </div>
          </div>

          {/* ── Observed evidence & affected resource ──────────────────── */}
          <div className={CARD}>
            <div className="flex items-center gap-2 mb-3">
              <FileSearch className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-slate-800">Observed evidence</h2>
            </div>
            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
              <div>
                <dt className="text-xs text-slate-400">Evidence source (finding)</dt>
                <dd className="text-slate-700 font-mono text-xs mt-0.5 break-all">{c.source_finding_type || c.source_finding_id || '—'}</dd>
              </div>
              <div>
                <dt className="text-xs text-slate-400 flex items-center gap-1"><MapPin className="w-3 h-3" /> Affected resource</dt>
                <dd className="text-slate-700 mt-0.5 break-all">{c.asset_ref || c.domain || '—'}</dd>
              </div>
              <div>
                <dt className="text-xs text-slate-400">Canonical remediation</dt>
                <dd className="text-slate-700 font-mono text-xs mt-0.5 break-all">{c.remediation_id || '— (unmapped finding — no invented remediation)'}</dd>
              </div>
              <div>
                <dt className="text-xs text-slate-400">Source scan</dt>
                <dd className="text-slate-700 mt-0.5">
                  {c.source_scan_id ? <Link className="text-brand-600 hover:underline font-mono text-xs" to={`/scans/${c.source_scan_id}`}>{c.source_scan_id}</Link> : '—'}
                </dd>
              </div>
            </dl>
          </div>

          {/* ── Remediation state & verification honesty ───────────────── */}
          <div className={CARD}>
            <div className="flex items-center gap-2 mb-3">
              <ShieldCheck className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-slate-800">Remediation & verification</h2>
            </div>
            <p className="text-sm text-slate-600 mb-3">
              Current state: <span className={`inline-block rounded-full border px-2 py-0.5 text-xs ${phaseClass(c.canonical_phase, c.verification_support)}`}>{meta.label}</span>
            </p>
            {support && (() => {
              // The explainer describes HOW this case may be verified — it is not a
              // claim that it already is. Green (reads as "settled") is reserved for a
              // case that has ACTUALLY reached verified with automated support; every
              // other state uses a neutral/informational tone so nothing looks settled
              // before it is. (Founder honesty rule: tone must not over-claim.)
              const settled = c.canonical_phase === 'verified' && c.verification_support === 'automated'
              const tone = support.tone === 'green' && !settled ? 'slate' : support.tone
              return (
                <div className={`rounded-lg border px-3 py-2.5 text-xs flex gap-2 ${SUPPORT_TONE[tone]}`}>
                  <Info className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{support.text}</span>
                </div>
              )
            })()}
            <p className="text-xs text-slate-400 mt-3">
              A customer-declared completion is an assertion — it moves the case to “Awaiting verification”, never to a verified state.
              Verification is decided by CyberMeters’ own observation (or, where noted, an independent third party).
            </p>
          </div>

          {/* ── Owner ──────────────────────────────────────────────────── */}
          <div className={CARD}>
            <OwnerPicker
              wsId={wsId}
              caseId={c.case_id}
              caseRow={c}
              canManage={canManage}
              onAssigned={() => load()}
            />
          </div>

          {/* ── Recurrence / reopen ────────────────────────────────────── */}
          <div className={CARD}>
            <div className="flex items-center gap-2 mb-2">
              <RefreshCw className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-slate-800">Recurrence</h2>
            </div>
            {c.reopened_count > 0 ? (
              <p className="text-sm text-slate-700">
                This case has been reopened <span className="font-semibold">{c.reopened_count}</span> time{c.reopened_count === 1 ? '' : 's'} after the condition was re-observed. Reopen history is preserved below.
              </p>
            ) : (
              <p className="text-sm text-slate-500">Not reopened. If the condition returns after resolution, this case reopens rather than a duplicate being created.</p>
            )}
          </div>

          {/* ── Append-only history ────────────────────────────────────── */}
          <div className={CARD}>
            <div className="flex items-center gap-2 mb-3">
              <Clock className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-slate-800">History</h2>
            </div>
            {events.length === 0 ? (
              <p className="text-xs text-slate-400">No history recorded yet.</p>
            ) : (
              <ol className="space-y-2.5">
                {events.map((ev) => (
                  <li key={ev.id} className="flex items-start gap-3 text-sm">
                    <span className="text-xs text-slate-400 font-mono whitespace-nowrap mt-0.5 w-28 shrink-0">{fmt(ev.created_at)}</span>
                    <span className="text-slate-700">
                      {eventLabel(ev)}
                      <span className="text-slate-400 text-xs"> · {ev.actor_type || 'system'}{ev.actor_id ? ` (${ev.actor_id})` : ''}</span>
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </div>

          {/* ── Link-out to domain-specific actions (coexist, never replace) ── */}
          {dmeta && (
            <div className={`${CARD} flex items-center justify-between gap-3`}>
              <p className="text-sm text-slate-600">Domain-specific actions (evidence bundles, takedown, renewal and verification) live in the domain workflow.</p>
              <Link to={dmeta.route} className="btn-secondary text-sm px-3 py-1.5 inline-flex items-center gap-1.5 whitespace-nowrap">
                {dmeta.actionLabel} <ExternalLink className="w-3.5 h-3.5" />
              </Link>
            </div>
          )}
        </div>
      )}
    </WsPage>
  )
}
