// Active Checks permission (S1-A, founder decision 22 Oct 2026). The customer
// authorises named active checks against named hosts of one verified domain.
//
// Everything here is the S2-A API's (GET/POST /workspaces/:id/active-check-
// consents, POST …/:id/revoke): the catalogue and its labels, the authority text
// and its version, who may manage, and every stored fact on a receipt. The page
// invents no field. A grant is immutable once made; revoking adds a record and
// never edits the grant. Nothing here starts a check, and there is no schedule.
import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../../api'
import { useWorkspace } from '../../hooks/useWorkspace'
import { useAuth } from '../../context/AuthContext'
import { useAppDialog } from '../../components/AppDialog'
import { NoWorkspaceSelected } from '../../components/WsPage'
import { isAuthoritativeVerified } from '../../lib/newScanVerification'
import { formatDate } from '../../utils/dates'

const MAX_HOSTS = 32

// Server reasons the customer can act on, in words. Anything else stays generic.
const ERROR_TEXT = {
  active_check_authority_required: 'Confirm the authority statement before authorising.',
  signer_name_and_title_required: 'Enter your name and your title.',
  invalid_active_checks: 'Choose at least one check.',
  active_check_not_available: 'A chosen check is not available yet, so it cannot be authorised. Untick it and try again.',
  invalid_active_check_hosts: `Each host must be the domain itself or a name under it, up to ${MAX_HOSTS} hosts.`,
  consent_already_revoked: 'This permission was already revoked.',
  invalid_revocation_reason: 'The reason can be up to 240 characters.',
}

const REASON_MAX = 240

const utcNow = () => formatDate(new Date().toISOString(), '—', { timeZone: 'UTC' }) + ' UTC'

function hostsFromText(text) {
  return [...new Set(String(text || '').split(/[\s,]+/).map((h) => h.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean))]
}

function Receipt({ consent, labels, authority, canManage, busy, onRevoke }) {
  const revoked = consent.status === 'revoked'
  return (
    <li className="card p-5 space-y-3" data-testid="consent-receipt">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="font-semibold text-gray-900">{consent.domain}</h3>
          <p className="text-xs text-gray-500 mt-0.5">
            {revoked ? `Revoked ${formatDate(consent.revoked_at, '—', { timeZone: 'UTC' })} UTC` : 'Checks run only when started'}
          </p>
        </div>
        <span className={`text-xs font-semibold px-2 py-1 rounded-full ${revoked ? 'bg-gray-100 text-gray-600' : 'bg-brand-50 text-brand-800'}`}>
          {revoked ? 'Revoked' : 'Active'}
        </span>
      </div>
      <dl className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[10rem_1fr]">
        <dt className="text-gray-500">Hosts</dt>
        <dd className="text-gray-800 break-words">{consent.hosts?.length ? consent.hosts.join(', ') : `${consent.domain} only`}</dd>
        <dt className="text-gray-500">Checks</dt>
        <dd className="text-gray-800"><ul className="space-y-0.5">{(consent.checks || []).map((id) => <li key={id}>{labels[id] || 'A check no longer offered'}</li>)}</ul></dd>
        <dt className="text-gray-500">Authorised by</dt>
        <dd className="text-gray-800">{consent.signer?.name}, {consent.signer?.title}{consent.signer?.workspace_role ? ` (workspace ${consent.signer.workspace_role})` : ''}</dd>
        <dt className="text-gray-500">Authorised at</dt>
        <dd className="text-gray-800">{formatDate(consent.granted_at, '—', { timeZone: 'UTC' })} UTC</dd>
        {/* The signer's IP is returned to workspace admins only (S2-A2). */}
        {consent.signer?.ip_address && <>
          <dt className="text-gray-500">IP address</dt>
          <dd className="text-gray-800 break-all">{consent.signer.ip_address}</dd>
        </>}
        <dt className="text-gray-500">Statement</dt>
        <dd className="text-gray-800">
          {/* The receipt's own stored words; an older record never borrows today's. */}
          {consent.authority_text
            ? <span className="italic">“{consent.authority_text}”</span>
            : authority && consent.authority_version === authority.version
              ? <span className="italic">“{authority.text}”</span>
              : 'An earlier version of the authority statement, kept with this record.'}
        </dd>
        {revoked && <>
          <dt className="text-gray-500">Reason for revoking</dt>
          <dd className="text-gray-800 break-words">{consent.revocation_reason || 'No reason given'}</dd>
        </>}
      </dl>
      {canManage && !revoked && (
        <button type="button" className="btn-secondary text-sm" disabled={busy} onClick={() => onRevoke(consent)}>
          Revoke permission
        </button>
      )}
    </li>
  )
}

export default function ActiveCheckPermissionsPage() {
  const { wsId, wsName, loading } = useWorkspace()
  const { user } = useAuth()
  const dialog = useAppDialog()
  const [data, setData] = useState(null)
  const [domains, setDomains] = useState(null)
  const [state, setState] = useState('loading') // loading | ok | unavailable | error
  const [form, setForm] = useState({ domain_id: '', hosts: '', checks: [], signer_name: '', signer_title: '', confirmed: false })
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [clock, setClock] = useState(utcNow)
  const scope = useRef(wsId)
  scope.current = wsId

  const load = useCallback(async () => {
    if (!wsId) return
    const requested = wsId
    setState('loading')
    try {
      const [consents, domainList] = await Promise.all([
        api.getActiveCheckConsents(requested),
        api.getWorkspaceDomains(requested).catch(() => ({ domains: [] })),
      ])
      if (scope.current !== requested) return
      setData(consents)
      setDomains((domainList?.domains || []).filter((d) => isAuthoritativeVerified(d, { domain_id: d.domain_id })))
      setState('ok')
    } catch (failure) {
      if (scope.current !== requested) return
      // Until the permission service is live the route answers 404: say so plainly.
      setState(failure?.status === 404 ? 'unavailable' : 'error')
    }
  }, [wsId])

  useEffect(() => {
    setData(null); setDomains(null); setError(null); setNotice(null)
    setForm({ domain_id: '', hosts: '', checks: [], signer_name: '', signer_title: '', confirmed: false })
    load()
  }, [load])

  useEffect(() => {
    const timer = setInterval(() => setClock(utcNow()), 30_000)
    return () => clearInterval(timer)
  }, [])

  if (!loading && !wsId) return <NoWorkspaceSelected />

  const canManage = data?.capabilities?.can_manage === true
  const catalogue = data?.catalogue || []
  const labels = Object.fromEntries(catalogue.map((c) => [c.id, c.label]))
  const authority = data?.authority || null
  const consents = data?.consents || []
  const domain = (domains || []).find((d) => d.domain_id === form.domain_id) || null
  const hosts = hostsFromText(form.hosts)
  const ready = canManage && !busy && domain && form.checks.length > 0 && form.signer_name.trim() && form.signer_title.trim() && form.confirmed && authority && hosts.length <= MAX_HOSTS
  // Why Authorise is not available yet, in one sentence (founder, 23 Oct 2026: a
  // disabled button that looked enabled read as "nothing happens").
  const anyAvailable = (data?.catalogue || []).some((c) => c.available === true)
  const notReadyReason = ready || busy ? null
    : !anyAvailable ? 'None of these checks can be authorised yet. They become available here when CyberMeters starts running them.'
      : form.checks.length === 0 ? 'Tick at least one check to authorise.'
        : !domain ? 'Choose a verified domain to authorise.'
          : hosts.length > MAX_HOSTS ? `List up to ${MAX_HOSTS} hosts.`
            : !form.signer_name.trim() || !form.signer_title.trim() ? 'Enter your name and your title to authorise.'
              : !form.confirmed ? 'Confirm the authority statement to authorise.'
                : 'Complete the form above to authorise.'

  const set = (key, value) => { setForm((f) => ({ ...f, [key]: value })); setError(null) }
  const toggleCheck = (id) => set('checks', form.checks.includes(id) ? form.checks.filter((c) => c !== id) : [...form.checks, id])

  async function authorise(event) {
    event.preventDefault()
    if (!ready) return
    const requested = wsId
    setBusy(true); setError(null); setNotice(null)
    try {
      await api.grantActiveCheckConsent(requested, {
        domain_id: domain.domain_id,
        hosts,
        // Never send a check the catalogue does not mark available (#929 refuses it anyway).
        checks: form.checks.filter((id) => catalogue.find((c) => c.id === id)?.available === true),
        signer_name: form.signer_name.trim(),
        signer_title: form.signer_title.trim(),
        authority_confirmed: true,
        authority_version: authority.version,
      })
      if (scope.current !== requested) return
      setForm({ domain_id: '', hosts: '', checks: [], signer_name: '', signer_title: '', confirmed: false })
      setNotice('Permission recorded. No check was started.')
      await load()
    } catch (failure) {
      if (scope.current === requested) setError(ERROR_TEXT[failure?.error || failure?.code] || 'The permission could not be recorded. Nothing was saved. Try again.')
    } finally {
      if (scope.current === requested) setBusy(false)
    }
  }

  async function revoke(consent) {
    const reason = await dialog.prompt({
      title: `Revoke permission for ${consent.domain}?`,
      message: 'CyberMeters will not start any of these checks again under this permission. The permission and its revocation stay on record; results already recorded are kept.',
      label: 'Reason (optional)',
      hint: `Kept with the revocation. Up to ${REASON_MAX} characters.`,
      pattern: new RegExp(`^[\\s\\S]{0,${REASON_MAX}}$`),
      patternMessage: `The reason can be up to ${REASON_MAX} characters.`,
      confirmLabel: 'Revoke permission',
      tone: 'danger',
    })
    if (reason === null) return
    const requested = wsId
    setBusy(true); setError(null); setNotice(null)
    try {
      await api.revokeActiveCheckConsent(requested, consent.id, reason)
      if (scope.current !== requested) return
      setNotice('Permission revoked.')
      await load()
    } catch (failure) {
      if (scope.current === requested) setError(ERROR_TEXT[failure?.error || failure?.code] || 'The permission could not be revoked. Try again.')
    } finally {
      if (scope.current === requested) setBusy(false)
    }
  }

  return (
    <div className="max-w-(--breakpoint-lg) mx-auto px-4 sm:px-6 py-8">
      <div className="mb-6">
        <h1 className="text-xl font-semibold text-gray-900">Active Checks permission</h1>
        <p className="text-sm text-gray-600 mt-1">
          Authorise CyberMeters to run named active checks against your own hosts{wsName ? ` for ${wsName}` : ''}. Checks run only when started; nothing is scheduled.
        </p>
      </div>

      {state === 'loading' && <p className="text-sm text-gray-500" role="status">Reading permissions…</p>}
      {state === 'unavailable' && (
        <p className="card p-5 text-sm text-gray-700" role="status">Active Checks permissions are not available yet. Nothing has been authorised and no active check runs.</p>
      )}
      {state === 'error' && (
        <div className="card p-5 text-sm text-red-700" role="alert">
          Permissions could not be read. Nothing is assumed in the meantime.{' '}
          <button type="button" className="underline" onClick={load}>Reload permissions</button>
        </div>
      )}

      {state === 'ok' && (
        <div className="space-y-8">
          {notice && <p role="status" className="text-sm text-gray-700">{notice}</p>}
          {error && <p role="alert" className="text-sm text-red-700">{error}</p>}

          {canManage ? (
            <form onSubmit={authorise} className="card p-5 sm:p-6 space-y-5" aria-label="Authorise active checks">
              <h2 className="font-semibold text-gray-900">New permission</h2>

              <label className="block text-sm">
                <span className="font-medium text-gray-800">Verified domain</span>
                <select className="input mt-1" value={form.domain_id} onChange={(e) => set('domain_id', e.target.value)} disabled={busy} required>
                  <option value="">Choose a verified domain</option>
                  {(domains || []).map((d) => <option key={d.domain_id} value={d.domain_id}>{d.domain}</option>)}
                </select>
                {domains && domains.length === 0 && <span className="block text-xs text-gray-500 mt-1">No domain in this workspace is verified yet. A permission can only name a verified domain.</span>}
              </label>

              <label className="block text-sm">
                <span className="font-medium text-gray-800">Hosts <span className="font-normal text-gray-500">(optional)</span></span>
                <textarea className="input mt-1 min-h-20" value={form.hosts} onChange={(e) => set('hosts', e.target.value)} disabled={busy}
                  placeholder={domain ? `e.g. mail.${domain.domain}` : 'e.g. mail.example.co.uk'} aria-describedby="hosts-help" />
                <span id="hosts-help" className="block text-xs text-gray-500 mt-1">
                  One per line. Leave empty to authorise {domain ? domain.domain : 'the domain'} itself only. Up to {MAX_HOSTS} hosts, each the domain or a name under it.
                </span>
              </label>

              <fieldset className="text-sm">
                <legend className="font-medium text-gray-800">Checks</legend>
                <p className="text-xs text-gray-500 mt-0.5">None are selected for you. A permission covers only the checks you tick, never checks added later.</p>
                <div className="mt-2 grid gap-2 sm:grid-cols-2">
                  {catalogue.map((c) => {
                    // The catalogue says whether a released engine runs the check today
                    // (#929). Only `available: true` is offered — an offer never comes
                    // from an absent field (Executive 14:40, as the backend's === true).
                    const unavailable = c.available !== true
                    return (
                      <label key={c.id} className={`flex items-start gap-2 rounded-lg border p-3 ${unavailable ? 'border-gray-100 bg-gray-50 text-gray-500' : 'border-gray-200'}`} data-testid={`active-check-${c.id}`}>
                        <input type="checkbox" className="mt-0.5" checked={!unavailable && form.checks.includes(c.id)} onChange={() => toggleCheck(c.id)} disabled={busy || unavailable}
                          aria-describedby={unavailable ? `active-check-${c.id}-na` : undefined} />
                        <span>
                          {c.label}
                          {unavailable && <span id={`active-check-${c.id}-na`} className="block text-xs text-gray-600 mt-0.5">Not available yet — CyberMeters does not run this check today, so it cannot be authorised.</span>}
                        </span>
                      </label>
                    )
                  })}
                </div>
              </fieldset>

              <div className="grid gap-4 sm:grid-cols-2">
                <label className="block text-sm">
                  <span className="font-medium text-gray-800">Your name</span>
                  <input className="input mt-1" value={form.signer_name} maxLength={120} onChange={(e) => set('signer_name', e.target.value)} disabled={busy} required autoComplete="name" />
                </label>
                <label className="block text-sm">
                  <span className="font-medium text-gray-800">Your title</span>
                  <input className="input mt-1" value={form.signer_title} maxLength={120} onChange={(e) => set('signer_title', e.target.value)} disabled={busy} required autoComplete="organization-title" placeholder="e.g. IT manager" />
                </label>
              </div>

              <dl className="grid gap-x-6 gap-y-1 text-sm sm:grid-cols-[10rem_1fr] rounded-lg bg-gray-50 p-3">
                <dt className="text-gray-500">Account</dt>
                <dd className="text-gray-800 break-words">{user?.email || 'Your signed-in account'}</dd>
                <dt className="text-gray-500">Time (UTC)</dt>
                <dd className="text-gray-800">{clock}</dd>
                <dt className="text-gray-500">Also recorded</dt>
                <dd className="text-gray-800">Your workspace role, your IP address and your browser, at the moment you authorise.</dd>
              </dl>

              {authority && (
                <label className="flex items-start gap-2 text-sm rounded-lg border border-gray-200 p-3">
                  <input type="checkbox" className="mt-0.5" checked={form.confirmed} onChange={(e) => set('confirmed', e.target.checked)} disabled={busy} />
                  <span>{authority.text}</span>
                </label>
              )}
              <p className="text-xs text-gray-500">This records your own statement of authority; CyberMeters does not independently verify it. Authorising does not start a check.</p>

              <div className="flex flex-wrap items-center gap-3">
                <button type="submit" className="btn-primary" disabled={!ready} aria-describedby={notReadyReason ? 'authorise-reason' : undefined}>{busy ? 'Recording…' : 'Authorise'}</button>
                {notReadyReason && <p id="authorise-reason" className="text-sm text-gray-700" data-testid="authorise-reason">{notReadyReason}</p>}
              </div>
            </form>
          ) : (
            <p className="card p-5 text-sm text-gray-700">A workspace admin can authorise or revoke active checks. You can see every permission below.</p>
          )}

          <section aria-labelledby="consents-heading" className="space-y-3">
            <h2 id="consents-heading" className="font-semibold text-gray-900">Permissions on record</h2>
            {consents.length === 0
              ? <p className="text-sm text-gray-500">No permission has been recorded for this workspace. No active check runs.</p>
              : <ul className="space-y-3">{consents.map((c) => <Receipt key={c.id} consent={c} labels={labels} authority={authority} canManage={canManage} busy={busy} onRevoke={revoke} />)}</ul>}
          </section>

          <p className="text-xs text-gray-500">Passive checks need no permission and keep running on your scans. <Link to="/guide" className="underline">Field Guide</Link></p>
        </div>
      )}
    </div>
  )
}
