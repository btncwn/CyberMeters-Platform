// Universal Case Detail — the ONE canonical customer-facing case surface across
// all eight security domains. It is ADDITIVE: it coexists with the bespoke ASM,
// Brand and per-domain lifecycle panels (which keep their domain-specific side
// effects) and links out to them for domain-specific actions. It never decides a
// transition — the backend universal validator does — and it never re-derives a
// verification verdict: `verification_support` arrives from the backend and the
// honest label comes from the shared caseDisplay vocabulary.
import { useCallback, useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'
import OwnerPicker from '../../components/OwnerPicker'
import CaseGuidance from '../../components/CaseGuidance'
import InternalIdCopyButton from '../../components/InternalIdCopyButton'
import StatusChip from '../../components/StatusChip'
import ScanNowButton from '../../components/ScanNowButton'
import { caseChipStatus, caseAssessmentMessage } from '../../lib/caseAssessment'
import {
  domainKeyLabel,
  ATTESTED_LABEL, EXTERNAL_EVIDENCE_LABEL,
  caseDisplayTitle,
} from '../../lib/caseDisplay'
import { SERVICE_COLORS } from '../../theme/serviceColors'
import { formatDate, formatDay } from '../../utils/dates'
import { affectedLabel } from '../../lib/keyLabel'
import { useScopedDomain } from '../../components/shell/WorkspaceContext'

// domain_key → { service-colour key, the area page that handles a case the
// universal page cannot move (Brand Protection) }.
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
  green: 'bg-brand-200 text-brand-900 border-brand-200',
  blue:  'bg-blue-50 text-blue-800 border-blue-200',
  slate: 'bg-slate-50 text-slate-700 border-slate-200',
}

// Human dates, one formatter for the product (utils/dates: server timestamps are UTC).
function fmt(ts) {
  return formatDate(ts, '—')
}

// Present one append-only history event honestly (assignment, creation, transitions).
// A reopen event's honest meaning depends on WHO reopened it — the persisted
// actor_type already records this: 'system' = an automatic evidence-driven
// recurrence; anything else ('customer') = a manual reopen by a workspace member.
// A manual reopen must never be described as a re-observation.
// Who acted, by name: the API resolves workspace members to their name or
// email (actor_name). A raw user id is never shown.
function actorLabel(ev) {
  if ((ev.actor_type || 'system') === 'system') return 'CyberMeters'
  return ev.actor_name || 'A workspace member'
}

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
  if (a.startsWith('transition_')) return transitionLabel(a.replace('transition_', ''))
  if (a === 'status_changed') return `Status changed from ${sentence(ev.from_status || 'unknown').toLowerCase()} to ${sentence(ev.to_status || 'unknown').toLowerCase()}`
  // One event per meaning: two system moves that share an action (e.g. a
  // withdrawn claim moving a case to review and then closing it) are told apart
  // by where each one went.
  if (a && ev.to_status) return `${sentence(a)} — ${OUTCOME[ev.to_status] || `moved to ${outcome(ev.to_status)}`}`
  return a ? sentence(a) : 'Update'
}

const OUTCOME = {
  triage: 'moved to review', triaged: 'moved to review',
  false_positive: 'closed as false positive', closed: 'closed', closed_no_action: 'closed — no action needed',
  rejected: 'closed as rejected', superseded: 'closed as superseded',
  owner_assigned: 'owner assigned', assigned: 'owner assigned',
  remediation_in_progress: 'remediation started', action_in_progress: 'remediation started',
  verification_requested: 'verification requested', awaiting_verification: 'verification requested',
  resolved: 'verified', verified: 'verified', reopened: 'reopened',
  risk_accepted: 'risk accepted', accepted_risk: 'risk accepted',
}
function transitionLabel(status) {
  const o = OUTCOME[status]
  if (!o) return `Moved to ${sentence(status).toLowerCase()}`
  return o.startsWith('moved to ') ? `Moved to ${o.slice(9)}` : sentence(o)
}
const outcome = (status) => sentence(status).toLowerCase()
const CLOSED_PHASES = new Set(['rejected', 'false_positive', 'closed_no_action', 'superseded'])

// "monitoring_changed" → "Monitoring changed": an event key is never shown raw.
function sentence(key) {
  const words = String(key || '').replace(/[_.]+/g, ' ').trim()
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : ''
}

// ── Which advertised move is the primary, and what it is called ─────────────
// S1-CASE-STALE (Executive 00:00, 23 Oct 2026; Codex C-37 audit): the backend
// advertises every LEGAL move, including moves backwards. A backwards or
// consequential move (it leaves a waiting state, reopens, withdraws a risk
// decision, cancels a running check, closes the workflow) is never the
// primary, and its label says what it really does — "Start remediation" on an
// awaiting-verification case undid the customer's own submission, three times
// live. Keyed by "<current status>><target status>" (base and Attack Surface).
export const SECONDARY_MOVES = Object.freeze({
  'awaiting_verification>action_in_progress': 'Not fixed yet — reopen work',
  'monitoring>reopened': 'Reopen case',
  'accepted_risk>triaged': 'Withdraw the risk acceptance and re-triage',
  'verifying>verification_requested': 'Restart verification (cancels the running check)',
  'resolved>closed': 'Close case',
  'risk_acceptance_requested>remediation_in_progress': 'Withdraw the risk request and resume work',
  'risk_accepted>triage': 'Withdraw the risk acceptance and re-triage',
})
// A forward move whose generic label hides that it is a retry.
const RELABELLED_MOVES = Object.freeze({
  'verification_failed>remediation_in_progress': 'Resume remediation',
})

/** [{ t, label, primary }] in the backend's order; at most one primary, never a backwards move. */
export function presentTransitions(caseRecord, transitions = []) {
  const from = [caseRecord?.status, caseRecord?.canonical_phase].filter(Boolean)
  const keyOf = (t) => from.map((f) => `${f}>${t.target_status}`)
  const secondaryLabel = (t) => keyOf(t).map((k) => SECONDARY_MOVES[k]).find(Boolean) || null
  const relabel = (t) => keyOf(t).map((k) => RELABELLED_MOVES[k]).find(Boolean) || null
  let primaryTaken = false
  return transitions.map((t) => {
    const backwards = secondaryLabel(t)
    const primary = !backwards && !primaryTaken
    if (primary) primaryTaken = true
    return { t, label: backwards || relabel(t) || t.label, primary }
  })
}

// Awaiting verification is a waiting state: it says what happens next and when
// it was submitted, instead of offering a primary (manual cases keep their
// attestation form, which really records the customer's evidence).
const WAITING_TEXT = {
  automated: 'CyberMeters verifies this on the next complete scan.',
  external: 'An independent party certifies this; record their evidence when you have it.',
  unsupported: 'CyberMeters cannot observe this fix from outside, so it cannot verify it.',
}
export function submittedForVerificationText(caseRecord, events = []) {
  if (caseRecord?.canonical_phase !== 'awaiting_verification' || caseRecord?.verification_support === 'manual') return null
  const submitted = [...events].filter((e) => e?.to_status === 'awaiting_verification' || e?.to_status === 'verification_requested')
    .sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')))[0]?.created_at || caseRecord.updated_at
  const day = submitted ? formatDay(submitted, '') : ''
  return `Submitted for verification${day ? ` on ${day}` : ''} — ${WAITING_TEXT[caseRecord.verification_support] || WAITING_TEXT.unsupported}`
}

// ── Next action ─────────────────────────────────────────────────────────────
// Renders ONLY the transitions the backend advertised in available_transitions —
// it never derives the state machine and never invents a shortcut. A transition
// that needs NO extra input executes DIRECTLY on one click (no redundant confirm
// panel). A transition that requires a reason, an expiry, an owner or a structured
// attestation opens an inline form that collects ONLY those fields (no native
// prompt/confirm). Manual verification is recorded honestly as a customer
// attestation, never as "Verified by CyberMeters".
function NextActionSection({ wsId, caseId, caseRecord, events = [], transitions, onDone, phase, domainRoute, domainLabel, canManage = false }) {
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
      // Attack Surface cases move through their own endpoint (domain side effects);
      // the backend says which one each advertised move uses.
      if (selected?.endpoint === 'attack_surface' || payload.endpoint === 'attack_surface') {
        const { target_status: status, endpoint: _e, ...rest } = payload
        await api.transitionManagedCase(wsId, caseId, { status, ...rest })
      } else {
        const { endpoint: _e, ...rest } = payload
        // Name the status this button was rendered for (#912): if the case has
        // moved since, the server changes nothing and says so.
        await api.transitionCase(wsId, caseId, caseRecord?.status ? { ...rest, expected_status: caseRecord.status } : rest)
      }
      setSelected(null); resetForm()
      // Stay busy until the server's state is back on screen: the old buttons
      // can never take a second click while the case reloads.
      await onDone?.()
    } catch (e) {
      if (e?.code === 'case_status_changed') {
        // The case moved since this page was loaded: nothing was changed; show where it is now.
        setSelected(null); resetForm()
        setActionError('This case changed since the page was loaded, so nothing was changed. It now shows its current status.')
        await onDone?.()
      } else {
        setActionError('Could not complete this action. Please try again.')
      }
    } finally {
      setBusy(null)
    }
  }

  function onButtonClick(t) {
    if (busy) return
    setActionError(null)
    if (needsForm(t)) { setSelected(t); resetForm() }
    else run(t.target_status, { target_status: t.target_status, endpoint: t.endpoint })   // no input required → execute directly
  }

  const noteOk        = !selected?.requires_note        || note.trim().length > 0
  const expiryOk      = !selected?.requires_expiry      || Boolean(expiry)
  const attestationOk = !selected?.requires_attestation || attestation.trim().length > 0
  // An owner can be assigned right here (C-46 rank 4); once the case has one, the move may go ahead.
  const ownerOk       = !selected?.requires_owner || Boolean(caseRecord?.owner_ref)
  const canSubmit = Boolean(selected) && noteOk && expiryOk && attestationOk && ownerOk && !busy
  const presented = presentTransitions(caseRecord, transitions)
  const waitingText = submittedForVerificationText(caseRecord, events)

  function submitForm() {
    if (!canSubmit) return
    const payload = { target_status: selected.target_status, endpoint: selected.endpoint }
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
        <h2 className="text-sm font-semibold text-slate-800">Next action</h2>
      </div>

      {waitingText && <p className="mb-3 text-base text-slate-700" data-testid="case-waiting-verification">{waitingText}</p>}
      {/* C-46 rank 1: an automated verification waits for the next complete scan —
          so the next step is to run it, visibly, not a hunt for the Scan control. */}
      {waitingText && caseRecord?.verification_support === 'automated' && caseRecord?.domain && (
        <div className="mb-3" data-testid="case-run-next-scan">
          <Link to={`/scans/new?domain=${encodeURIComponent(caseRecord.domain)}`} className="btn-primary min-h-[40px]">Run the next scan</Link>
          <p className="mt-1.5 text-sm text-slate-600">After you apply the fix, a complete scan of {caseRecord.domain} checks it.</p>
        </div>
      )}
      {transitions.length === 0 ? (
        // Never "no further actions" on a case that still needs action: a closed
        // case says it is closed; an open one says where it is handled.
        CLOSED_PHASES.has(phase) ? (
          <p className="text-base text-slate-600">This case is closed. If the condition returns, it reopens here.</p>
        ) : domainRoute ? (
          <p className="text-base text-slate-600">This case is handled on the {domainLabel} page. <Link to={domainRoute} className="font-semibold text-brand-700 hover:text-brand-800">Open {domainLabel}</Link></p>
        ) : (
          <p className="text-base text-slate-600">CyberMeters is handling the next step for this case; it updates here when the evidence changes.</p>
        )
      ) : !selected ? (
        <>
          <div className="flex flex-wrap gap-2">
            {presented.map(({ t, label, primary }) => (
              <button
                key={t.target_status}
                type="button"
                onClick={() => onButtonClick({ ...t, label })}
                disabled={Boolean(busy)}
                aria-busy={busy === t.target_status}
                data-primary={primary ? 'true' : undefined}
                className={primary
                  ? 'btn-primary min-h-[40px] disabled:opacity-50 disabled:cursor-not-allowed'
                  : 'inline-flex items-center rounded-lg border border-slate-300 bg-white px-4 min-h-[40px] text-sm font-medium text-slate-700 hover:bg-slate-50 focus:outline-hidden focus:ring-2 focus:ring-brand-300 disabled:opacity-50 disabled:cursor-not-allowed'}
              >
                {busy === t.target_status ? 'Working…' : label}
              </button>
            ))}
          </div>
          {actionError && <p className="mt-3 text-sm text-red-700" role="alert">{actionError}</p>}
        </>
      ) : (
        <div className="rounded-lg border border-slate-200 bg-slate-50 p-4 space-y-3">
          <p className="text-base font-medium text-slate-800">{selected.label}</p>

          {selected.requires_owner && !caseRecord?.owner_ref && (
            // C-46 rank 4: the owner is chosen right here, not in another section.
            <div className="rounded-md border border-[1.5px] border-brand-700 bg-white p-3 space-y-2" data-testid="next-action-owner">
              <p className="text-sm text-brand-700">This step needs an accountable owner. Choose one, then confirm.</p>
              <OwnerPicker wsId={wsId} caseId={caseId} caseRow={caseRecord} canManage={canManage} onAssigned={() => onDone?.()} closed={false} />
            </div>
          )}

          {selected.requires_note && (
            <label className="block">
              <span className="block text-sm font-medium text-slate-700 mb-1">Reason <span className="text-red-700">*</span></span>
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                rows={3}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-base min-h-[40px] focus:outline-hidden focus:ring-2 focus:ring-brand-300"
                placeholder="Why is this the right outcome? Recorded in the case history."
              />
            </label>
          )}

          {selected.requires_expiry && (
            <label className="block">
              <span className="block text-sm font-medium text-slate-700 mb-1">Accepted until <span className="text-red-700">*</span></span>
              <input
                type="date"
                value={expiry}
                onChange={(e) => setExpiry(e.target.value)}
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-base min-h-[40px] focus:outline-hidden focus:ring-2 focus:ring-brand-300"
              />
            </label>
          )}

          {selected.requires_attestation && (
            <div className="space-y-2">
              <div className="flex items-start gap-2 rounded-md border border-blue-200 bg-blue-50 p-3">
                <p className="text-sm text-blue-800">
                  {ATTESTED_LABEL}. This records your confirmation only — it is never presented as CyberMeters-verified.
                </p>
              </div>
              <label className="block">
                <span className="block text-sm font-medium text-slate-700 mb-1">Attestation statement <span className="text-red-700">*</span></span>
                <textarea
                  value={attestation}
                  onChange={(e) => setAttestation(e.target.value)}
                  rows={3}
                  className="w-full rounded-lg border border-slate-300 px-3 py-2 text-base min-h-[40px] focus:outline-hidden focus:ring-2 focus:ring-brand-300"
                  placeholder="Describe what you changed and confirm the remediation is in place."
                />
              </label>
            </div>
          )}

          {actionError && <p className="text-sm text-red-700" role="alert">{actionError}</p>}

          <div className="flex flex-wrap gap-2 pt-1">
            <button
              type="button"
              onClick={submitForm}
              disabled={!canSubmit}
              className="inline-flex items-center rounded-lg bg-brand-200 px-4 min-h-[40px] text-sm font-semibold text-brand-900 hover:bg-brand-300 focus:outline-hidden focus:ring-2 focus:ring-brand-300 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {busy ? 'Working…' : selected.label}
            </button>
            <button
              type="button"
              onClick={cancel}
              disabled={Boolean(busy)}
              className="inline-flex items-center rounded-lg border border-slate-300 bg-white px-4 min-h-[40px] text-sm font-medium text-slate-700 hover:bg-slate-50 focus:outline-hidden focus:ring-2 focus:ring-brand-300 disabled:opacity-50"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// The condition is already gone but the case has not been moved on (Executive
// 16:20 product decision: no auto-close — the customer moves the case, then
// CyberMeters verifies). The case API's condition_state / last_observed_absent_at
// (Seat 3) say so; until those fields are present nothing is shown, never guessed.
const BEFORE_READY = new Set(['detected', 'triaged', 'assigned', 'approved', 'action_in_progress', 'reopened'])
export function noLongerObservedText(c) {
  if (c?.condition_state !== 'no_longer_observed' || !BEFORE_READY.has(c?.canonical_phase)) return null
  const when = c.last_observed_absent_at ? formatDay(c.last_observed_absent_at, '') : ''
  return `CyberMeters no longer observes this issue${when ? ` (last check ${when})` : ''}. Mark the case ready to verify and the next scan will confirm it.`
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

  // Returns the request, so an action can wait for the server's state to render.
  const load = useCallback(() => {
    if (!wsId || !caseId) return Promise.resolve()
    setLoading(true)
    return api.getCase(wsId, caseId)
      .then((res) => { setData(res); setError(null) })
      .catch(() => setError('Could not load this case.'))
      .finally(() => setLoading(false))
  }, [wsId, caseId])

  useEffect(() => { load() }, [load])
  // The context bar names the case's domain (founder, 23 Oct 2026).
  useScopedDomain(data?.case?.domain, { workspaceId: data?.case?.workspace_id })

  if (!wsLoading && !wsId) return <NoWorkspaceSelected />

  const c = data?.case
  const events = data?.events || []
  const dmeta = c ? (DOMAIN_META[c.domain_key] || null) : null
  const svc = dmeta ? SERVICE_COLORS[dmeta.svc] : null
  const support = c ? (SUPPORT_EXPLAINER[c.verification_support] || SUPPORT_EXPLAINER.unsupported) : null

  return (
    <WsPage wsId={wsId} wsName={wsName} loading={loading || wsLoading} error={error} onRetry={load}>
      {c && (
        <div className="space-y-5" data-testid="case-detail">
          <button type="button" onClick={() => navigate(-1)} className="inline-flex items-center gap-1.5 text-sm text-slate-500 hover:text-slate-700">
            Back
          </button>

          {/* ── 1 · What it is + status (one badge, the list's vocabulary) ── */}
          <div className={CARD}>
            <span
              className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium border mb-2"
              style={svc ? { backgroundColor: svc.chip, color: svc.text, borderColor: svc.ring } : undefined}
            >
              {domainKeyLabel(c.domain_key)}
            </span>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <h1 className="text-lg font-semibold text-slate-900 min-w-0 wrap-break-word">{c.display_title || caseDisplayTitle(c)}</h1>
              <StatusChip status={caseChipStatus(c)} className="shrink-0" />
            </div>
            {caseAssessmentMessage(c) && <p className="text-sm text-slate-700 mt-2" data-testid="case-assessment">{caseAssessmentMessage(c)}</p>}
            <div className="flex flex-wrap gap-x-6 gap-y-1 mt-3 text-xs text-slate-500">
              <span>Severity: <span className="text-slate-700 capitalize">{c.severity || '—'}</span></span>
              <span>Opened: {fmt(c.created_at)}</span>
              <span>Updated: {fmt(c.updated_at)}</span>
            </div>
          </div>

          {/* ── 2 · What we saw ───────────────────────────────────────────── */}
          <div className={CARD}>
            <h2 className="text-sm font-semibold text-slate-800 mb-2">What we saw</h2>
            <p className="text-sm text-slate-700">
              {c.summary || 'CyberMeters recorded this condition in a scan of your external posture.'}
            </p>
            <p className="text-sm text-slate-600 mt-2">
              Affected: <span className="text-slate-800 break-all">{affectedLabel(c) || 'not recorded'}</span>
            </p>
            {c.traceability && (
              <p className="text-sm text-slate-600 mt-2">
                <span className="font-medium text-slate-700">{c.traceability.relationship_label}</span>{' · '}{c.traceability.customer_message}
              </p>
            )}
            <details className="mt-3 text-sm" data-testid="case-evidence">
              <summary className="cursor-pointer text-slate-600 hover:text-slate-800">Evidence</summary>
              <div className="mt-2 space-y-1 text-slate-600">
                <p>{c.source_scan_id ? <Link className="text-brand-700 hover:underline" to={`/scans/${encodeURIComponent(c.source_scan_id)}`}>Open the scan that observed this</Link> : 'The observing scan was not recorded.'}</p>
                {!c.remediation_id && <p>No registered remediation is mapped for this finding, so none is invented here.</p>}
                <p className="flex flex-wrap items-center gap-2 text-xs text-slate-500">For support: <InternalIdCopyButton id={c.case_id} label="case" />{c.source_scan_id && <InternalIdCopyButton id={c.source_scan_id} label="scan" />}</p>
              </div>
            </details>
          </div>

          {/* ── 3 · What to do (backend guidance) + the one action ─────────── */}
          {noLongerObservedText(c) && (
            <p className="rounded-xl border border-brand-200 bg-brand-50 px-4 py-3 text-base text-brand-900" data-testid="case-no-longer-observed">{noLongerObservedText(c)}</p>
          )}
          <CaseGuidance guidance={c.guidance} />
          {data?.can_manage && (
            <NextActionSection
              canManage={canManage}
              wsId={wsId}
              caseId={c.case_id}
              transitions={data?.available_transitions || []}
              caseRecord={c}
              events={events}
              onDone={() => load()}
              phase={c.canonical_phase}
              domainRoute={dmeta?.route || null}
              domainLabel={domainKeyLabel(c.domain_key)}
            />
          )}

          {/* ── 4 · How the fix is checked (verification honesty) ──────────── */}
          {support && (() => {
            // Green (reads as "settled") only for a case that ACTUALLY reached
            // verified with automated support; otherwise neutral (founder honesty rule).
            const settled = c.canonical_phase === 'verified' && c.verification_support === 'automated'
            const tone = support.tone === 'green' && !settled ? 'slate' : support.tone
            return (
              <div className={CARD}>
                <h2 className="text-sm font-semibold text-slate-800 mb-2">How verification works</h2>
                {settled && <p className="text-sm font-semibold text-brand-800 mb-2">Verified by CyberMeters</p>}
                <div className={`rounded-lg border px-3 py-2.5 text-sm ${SUPPORT_TONE[tone]}`}>{support.text}</div>
                {/* The re-check is this page's one action only when no customer move is
                    left: CyberMeters verifies from its own observation, so a scan is
                    what moves the case on. Never beside the transition buttons. */}
                {c.verification_support === 'automated' && c.domain && !settled &&
                  !CLOSED_PHASES.has(c.canonical_phase) &&
                  (data?.available_transitions || []).length === 0 && (
                  <div className="mt-3" data-testid="case-recheck"><ScanNowButton workspaceId={wsId} domain={c.domain} label="Run scan to re-check" align="start" /></div>
                )}
                <p className="text-xs text-slate-500 mt-2">
                  Your completion is an assertion: it moves the case to awaiting verification, never to verified.
                </p>
              </div>
            )
          })()}

          {/* ── 5 · Owner ─────────────────────────────────────────────────── */}
          <div className={CARD}>
            <OwnerPicker
              wsId={wsId}
              caseId={c.case_id}
              caseRow={c}
              canManage={canManage}
              onAssigned={() => load()}
              closed={CLOSED_PHASES.has(c.canonical_phase)}
            />
          </div>

          {/* ── 6 · History (append-only), with the reopen record ─────────── */}
          <div className={CARD}>
            <h2 className="text-sm font-semibold text-slate-800 mb-1">History</h2>
            {(() => {
              // Honest per-cause copy from the persisted reopen events' actor_type:
              // a manual reopen is NOT a re-observation.
              const reopens = events.filter(isReopenEvent)
              const autoCount = reopens.filter(isAutomaticReopen).length
              const manualCount = reopens.length - autoCount
              const plural = (n) => (n === 1 ? '' : 's')
              const lines = []
              if (autoCount > 0) lines.push(`Automatically reopened ${autoCount} time${plural(autoCount)} after the condition was re-observed.`)
              if (manualCount > 0) lines.push(`Manually reopened ${manualCount} time${plural(manualCount)} by a workspace member.`)
              if (reopens.length === 0 && c.reopened_count > 0) lines.push(`This case has been reopened ${c.reopened_count} time${plural(c.reopened_count)}.`)
              if (lines.length === 0) lines.push('Not reopened. If the condition returns after resolution, this case reopens rather than a duplicate being created.')
              return lines.map((l) => <p key={l} className="text-xs text-slate-500">{l}</p>)
            })()}
            {events.length === 0 ? (
              <p className="text-xs text-slate-500 mt-3">No history recorded yet.</p>
            ) : (
              <ol className="mt-3 divide-y divide-slate-100" data-testid="case-history">
                {events.map((ev) => (
                  // Time and event never overlap: stacked on a phone, a fixed
                  // column from sm up.
                  <li key={ev.id} className="py-2 grid grid-cols-1 sm:grid-cols-[10rem_1fr] gap-x-4 gap-y-0.5 text-sm">
                    <time className="text-xs text-slate-500 tabular-nums sm:pt-0.5" dateTime={ev.created_at || undefined}>{fmt(ev.created_at)}</time>
                    <span className="text-slate-700 min-w-0 wrap-break-word">
                      {eventLabel(ev)}
                      <span className="text-slate-500 text-xs"> · {actorLabel(ev)}</span>
                    </span>
                  </li>
                ))}
              </ol>
            )}
          </div>
        </div>
      )}
    </WsPage>
  )
}
