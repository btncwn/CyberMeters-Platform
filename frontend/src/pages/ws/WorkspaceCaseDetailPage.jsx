// Universal Case Detail — the ONE canonical customer-facing case surface across
// all eight Cyber MOT domains. It is ADDITIVE: it coexists with the bespoke ASM,
// Brand and per-domain lifecycle panels (which keep their domain-specific side
// effects) and links out to them for domain-specific actions. It never decides a
// transition — the backend universal validator does — and it never re-derives a
// verification verdict: `verification_support` arrives from the backend and the
// honest label comes from the shared caseDisplay vocabulary.
import { useCallback, useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { ArrowLeft, ArrowRight, ExternalLink, Clock, FileSearch, MapPin, RefreshCw, ShieldCheck, Info, AlertTriangle } from 'lucide-react'
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
// A reopen event's honest meaning depends on WHO reopened it — the persisted
// actor_type already records this: 'system' = an automatic evidence-driven
// recurrence; anything else ('customer') = a manual reopen by a workspace member.
// A manual reopen must never be described as a re-observation.
function isReopenEvent(ev) {
  return ev.to_status === 'reopened' || ev.action === 'case_reopened' || ev.action === 'transition_reopened'
}
function isAutomaticReopen(ev) {
  return (ev.actor_type || 'system') === 'system'
}

function eventLabel(ev) {
  const a = ev.action || ''
  if (a === 'case_created') return 'Case opened'
  if (a === 'assignment_changed') return 'Owner assigned'
  if (isReopenEvent(ev)) {
    return isAutomaticReopen(ev)
      ? 'Reopened automatically after the condition was re-observed'
      : 'Manually reopened by a workspace member'
  }
  if (a.startsWith('transition_')) return `Moved to ${a.replace('transition_', '').replace(/_/g, ' ')}`
  if (a === 'status_changed') return `Status changed ${ev.from_status || '?'} → ${ev.to_status || '?'}`
  return a.replace(/_/g, ' ') || 'Update'
}

// ── Next action ─────────────────────────────────────────────────────────────
// Renders ONLY the transitions the backend advertised in available_transitions —
// it never derives the state machine and never invents a shortcut. A transition
// that needs NO extra input executes DIRECTLY on one click (no redundant confirm
// panel). A transition that requires a reason, an expiry, an owner or a structured
// attestation opens an inline form that collects ONLY those fields (no native
// prompt/confirm). Manual verification is recorded honestly as a customer
// attestation, never as "Verified by CyberMeters".
function NextActionSection({ wsId, caseId, transitions, onDone }) {
  const [selected, setSelected] = useState(null)   // the transition whose input form is open
  const [note, setNote] = useState('')
  const [expiry, setExpiry] = useState('')
  const [attestation, setAttestation] = useState('')
  const [busy, setBusy] = useState(null)           // target_status of the in-flight request; null = idle
  const [actionError, setActionError] = useState(null)

  // A form is needed ONLY when the backend advertises a required input (or an
  // owner the case does not yet have). Everything else is a direct one-click move.
  const needsForm = (t) => Boolean(t.requires_note || t.requires_expiry || t.requires_attestation || t.requires_owner)

  const resetForm = () => { setNote(''); setExpiry(''); setAttestation('') }
  const cancel = () => { setSelected(null); resetForm(); setActionError(null) }

  // The single transition executor — used by both the direct buttons and the
  // form. `busy` guards against duplicate/concurrent submissions (double-click).
  async function run(target, payload) {
    if (busy) return
    setBusy(target); setActionError(null)
    try {
      await api.transitionCase(wsId, caseId, payload)
      setSelected(null); resetForm()
      onDone?.()
    } catch {
      setActionError('Could not complete this action. Please try again.')
    } finally {
      setBusy(null)
    }
  }

  function onButtonClick(t) {
    if (busy) return
    setActionError(null)
    if (needsForm(t)) { setSelected(t); resetForm() }
    else run(t.target_status, { target_status: t.target_status })   // no input required → execute directly
  }

  const noteOk        = !selected?.requires_note        || note.trim().length > 0
  const expiryOk      = !selected?.requires_expiry      || Boolean(expiry)
  const attestationOk = !selected?.requires_attestation || attestation.trim().length > 0
  const ownerOk       = !selected?.requires_owner // owner is set separately, in the Owner section
  const canSubmit = Boolean(selected) && noteOk && expiryOk && attestationOk && ownerOk && !busy

  function submitForm() {
    if (!canSubmit) return
    const payload = { target_status: selected.target_status }
    if (selected.requires_note)   payload.reason = note.trim()
    if (selected.requires_expiry) payload.risk_accepted_until = new Date(expiry).toISOString()
    if (selected.requires_attestation) {
      const nowIso = new Date().toISOString()
      payload.evidence = {
        verification_method: 'manual_attestation',
        verification_result: 'fixed',
        evidence_type: 'customer_attestation',
        observed_at: nowIso,
        attestation: { statement: attestation.trim(), attested_at: nowIso },
      }
    }
    run(selected.target_status, payload)
  }

  return (
    <div className={CARD}>
      <div className="flex items-center gap-2 mb-3">
        <ArrowRight className="w-4 h-4 text-slate-400" />
        <h2 className="text-sm font-semibold text-slate-800">Next action</h2>
      </div>

      {transitions.length === 0 ? (
        <p className="text-base text-slate-500">No further actions are available for this case in its current state.</p>
      ) : !selected ? (
        <>
          <div className="flex flex-wrap gap-2">
            {transitions.map((t) => (
              <button
                key={t.target_status}
                type="button"
                onClick={() => onButtonClick(t)}
                disabled={Boolean(busy)}
                aria-busy={busy === t.target_status}
                className="inline-flex items-center rounded-lg border border-slate-300 bg-white px-4 min-h-[40px] text-sm font-medium text-slate-700 hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-brand-300 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {busy === t.target_status ? 'Working…' : t.label}
              </button>
            ))}
          </div>
          {actionError && <p className="mt-3 text-sm text-red-600" role="alert">{actionError}</p>}
        </>
      ) : (
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 space-y-3">
          <p className="text-base font-medium text-slate-800">{selected.label}</p>

          {selected.requires_owner && (
            <div className="flex items-start gap-2 rounded-md border border-amber-200 bg-amber-50 p-3">
              <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0 mt-0.5" />
              <p className="text-sm text-amber-800">Assign an owner in the Owner section above before moving this case to Assigned.</p>
            </div>
          )}

          {selected.requires_note && (
            <label className="block">
              <span className="block text-sm font-medium text-slate-700 mb-1">Reason <span className="text-red-500">*</span></span>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={3}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-base min-h-[40px] focus:outline-none focus:ring-2 focus:ring-brand-300"
                placeholder="Why is this the right outcome? Recorded in the case history."
              />
            </label>
          )}

          {selected.requires_expiry && (
            <label className="block">
              <span className="block text-sm font-medium text-slate-700 mb-1">Accepted until <span className="text-red-500">*</span></span>
              <input
                type="date"
                value={expiry}
                onChange={(e) => setExpiry(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-base min-h-[40px] focus:outline-none focus:ring-2 focus:ring-brand-300"
              />
            </label>
          )}

          {selected.requires_attestation && (
            <div className="space-y-2">
              <div className="flex items-start gap-2 rounded-md border border-blue-200 bg-blue-50 p-3">
                <Info className="w-4 h-4 text-blue-500 shrink-0 mt-0.5" />
                <p className="text-sm text-blue-800">
                  {ATTESTED_LABEL}. This records your confirmation only — it is never presented as CyberMeters-verified.
                </p>
              </div>
              <label className="block">
                <span className="block text-sm font-medium text-slate-700 mb-1">Attestation statement <span className="text-red-500">*</span></span>
                <textarea
                  value={attestation}
                  onChange={(e) => setAttestation(e.target.value)}
                  rows={3}
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-base min-h-[40px] focus:outline-none focus:ring-2 focus:ring-brand-300"
                  placeholder="Describe what you changed and confirm the remediation is in place."
                />
              </label>
            </div>
          )}

          {actionError && <p className="text-sm text-red-600" role="alert">{actionError}</p>}

          <div className="flex flex-wrap gap-2 pt-1">
            <button
              type="button"
              onClick={submitForm}
              disabled={!canSubmit}
              className="inline-flex items-center rounded-lg bg-brand-600 px-4 min-h-[40px] text-sm font-semibold text-white hover:bg-brand-700 focus:outline-none focus:ring-2 focus:ring-brand-300 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {busy ? 'Working…' : 'Confirm'}
            </button>
            <button
              type="button"
              onClick={cancel}
              disabled={Boolean(busy)}
              className="inline-flex items-center rounded-lg border border-slate-300 bg-white px-4 min-h-[40px] text-sm font-medium text-slate-700 hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-brand-300 disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
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

          {/* ── Next action — server-authoritative; managers only ──────── */}
          {/* can_manage + available_transitions come from the backend (the
              canonical machine). A viewer/analyst gets neither, so this section
              does not render for them — they still see all state and history. */}
          {data?.can_manage && (
            <NextActionSection
              wsId={wsId}
              caseId={c.case_id}
              transitions={data?.available_transitions || []}
              onDone={() => load()}
            />
          )}

          {/* ── Recurrence / reopen ────────────────────────────────────── */}
          {/* Honest per-cause copy, derived from the persisted reopen events'
              actor_type — a manual/customer reopen is NOT a re-observation, and
              the re-observation counter describes only automatic recurrences. */}
          <div className={CARD}>
            <div className="flex items-center gap-2 mb-2">
              <RefreshCw className="w-4 h-4 text-slate-400" />
              <h2 className="text-sm font-semibold text-slate-800">Recurrence</h2>
            </div>
            {(() => {
              const reopens = events.filter(isReopenEvent)
              const autoCount = reopens.filter(isAutomaticReopen).length
              const manualCount = reopens.length - autoCount
              if (reopens.length === 0 && !(c.reopened_count > 0)) {
                return <p className="text-sm text-slate-500">Not reopened. If the condition returns after resolution, this case reopens rather than a duplicate being created.</p>
              }
              const plural = (n) => (n === 1 ? '' : 's')
              return (
                <div className="text-sm text-slate-700 space-y-1">
                  {autoCount > 0 && (
                    <p className="font-medium">{`Automatically reopened ${autoCount} time${plural(autoCount)} after the condition was re-observed.`}</p>
                  )}
                  {manualCount > 0 && (
                    <p className="font-medium">{`Manually reopened ${manualCount} time${plural(manualCount)} by a workspace member.`}</p>
                  )}
                  {/* Fallback: reopened_count records a reopen we have no event for — never attribute it to a re-observation. */}
                  {reopens.length === 0 && c.reopened_count > 0 && (
                    <p className="font-medium">{`This case has been reopened ${c.reopened_count} time${plural(c.reopened_count)}. See history below.`}</p>
                  )}
                  <p className="text-slate-500">Reopen history is preserved below.</p>
                </div>
              )
            })()}
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
