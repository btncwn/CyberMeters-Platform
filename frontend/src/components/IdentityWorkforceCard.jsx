import { useEffect, useRef, useState } from 'react'
import { api } from '../api'

const when = value => value ? new Date(value).toLocaleString() : 'Not available'
const statusLabel = {
  previewed: 'Awaiting your confirmation', applying: 'Outcome unresolved — check before another request',
  provider_accepted: 'Microsoft accepted the request', uncertain: 'Provider outcome uncertain', not_completed: 'Request not completed',
}

export default function IdentityWorkforceCard({ workspaceId }) {
  const [data, setData] = useState(null), [error, setError] = useState(''), [busy, setBusy] = useState(false)
  const [upn, setUpn] = useState(''), [name, setName] = useState(''), [vip, setVip] = useState(false)
  const [tenant, setTenant] = useState(''), [client, setClient] = useState(''), [secret, setSecret] = useState('')
  const [selected, setSelected] = useState(''), [concern, setConcern] = useState(''), [confirmation, setConfirmation] = useState('')
  const mounted = useRef(true)
  useEffect(() => {
    mounted.current = true
    api.getIdentityWorkforce(workspaceId).then(value => { if (mounted.current) setData(value) })
      .catch(() => { if (mounted.current) setError('Workforce details are available to workspace owners and administrators.') })
    return () => { mounted.current = false }
  }, [workspaceId])
  const credentials = () => ({ tenantId: tenant.trim(), clientId: client.trim(), clientSecret: secret })
  const hasCredentials = !!tenant.trim() && !!client.trim() && !!secret
  const run = async operation => {
    if (busy) return
    setBusy(true); setError('')
    try {
      await operation()
      const value = await api.getIdentityWorkforce(workspaceId)
      if (mounted.current) { setData(value); setConfirmation('') }
    } catch (e) {
      if (mounted.current) {
        setError(e.message || 'The operation could not be confirmed. Check its recorded status before retrying.')
        // A dropped response may follow a completed provider call. Refresh the
        // action record; never automatically repeat an intervention.
        try { setData(await api.getIdentityWorkforce(workspaceId)) } catch { /* keep visible prior evidence */ }
      }
    } finally { if (mounted.current) { setSecret(''); setBusy(false) } }
  }
  const choose = person => { setSelected(person.id); setUpn(person.upn); setTenant(person.tenant_id || ''); setClient(person.client_id || ''); setSecret(''); setConfirmation('') }
  const chosen = data?.accounts?.find(a => a.id === selected)
  const actions = data?.actions?.filter(a => a.account_id === selected) || []
  if (!data) return <section className="card p-5 mb-6"><h2 className="font-semibold">People & identity response</h2><p className="text-sm text-gray-500 mt-2">{error || 'Loading workforce…'}</p></section>
  return <section className="card p-5 mb-6">
    <h2 className="text-lg font-semibold text-gray-900">People & identity response</h2>
    <p className="text-sm text-gray-500 mt-1">Keep important accounts in view and record an explicit response when you have a concern.</p>
    {error && <p role="alert" className="text-sm text-red-700 mt-3">{error}</p>}
    <fieldset disabled={busy} className="mt-4">
      <form className="flex flex-wrap gap-3 items-end" onSubmit={event => {
        event.preventDefault(); run(() => api.addIdentityAccount(workspaceId, { upn: upn.trim(), display_name: name.trim(), vip }))
      }}>
        <label className="text-xs text-gray-600">Work email / Entra sign-in name
          <input aria-label="Work email" type="email" required maxLength={254} className="input-base block mt-1" value={upn} onChange={e => setUpn(e.target.value)} />
        </label>
        <label className="text-xs text-gray-600">Name
          <input aria-label="Person name" maxLength={256} className="input-base block mt-1" value={name} onChange={e => setName(e.target.value)} />
        </label>
        <label className="text-sm flex gap-2 items-center"><input type="checkbox" checked={vip} onChange={e => setVip(e.target.checked)} />VIP / important account</label>
        <button className="btn-secondary text-sm" type="submit">Add account</button>
      </form>
      <details className="mt-4 rounded-lg border border-gray-200 p-3" open={selected ? true : undefined}>
        <summary className="text-sm font-medium cursor-pointer">Microsoft Entra connection for this operation</summary>
        <div className="grid md:grid-cols-3 gap-3 mt-3">
          <label className="text-xs">Tenant ID<input aria-label="Entra tenant ID" className="input-base block w-full mt-1" value={tenant} onChange={e => setTenant(e.target.value)} /></label>
          <label className="text-xs">Application ID<input aria-label="Entra application ID" className="input-base block w-full mt-1" value={client} onChange={e => setClient(e.target.value)} /></label>
          <label className="text-xs">Client secret value<input aria-label="Entra client secret" type="password" autoComplete="off" maxLength={2048} className="input-base block w-full mt-1" value={secret} onChange={e => setSecret(e.target.value)} /></label>
        </div>
        <p className="text-xs text-gray-500 mt-2">The secret is used for this request and cleared from this form. It is not saved by CyberMeters. Use your own approved Entra application.</p>
        <details className="text-xs text-gray-500 mt-2"><summary>Microsoft permissions and coverage</summary>
          <p className="mt-1">User.Read.All reads the exact user. User.RevokeSessions.All permits an explicitly confirmed session request. Microsoft application permissions apply across the directory and require your administrator’s consent.</p>
          <p className="mt-1">Optional Directory.Read.All enables direct role names; AuditLog.Read.All and an eligible Microsoft licence enable MFA registration reports. Missing data stays unavailable. Registration does not prove MFA enforcement; indirect or eligible roles are not assessed.</p>
        </details>
        <button className="btn-secondary text-sm mt-3" type="button" disabled={!upn || !hasCredentials} onClick={() => run(() => api.observeIdentityAccount(workspaceId, { upn: upn.trim(), credentials: credentials() }))}>Read this account from Entra</button>
      </details>
      <div className="space-y-3 mt-5">
        {data.accounts.length === 0 && <p className="text-sm text-gray-500">Add an account on a verified domain, or read the exact account from your Entra directory.</p>}
        {data.accounts.map(person => <article key={person.id} className={`border rounded-lg p-3 ${selected === person.id ? 'border-brand-500' : 'border-gray-200'}`}>
          <div className="flex flex-wrap gap-3 items-center justify-between">
            <button type="button" className="text-sm text-left break-all font-medium" onClick={() => choose(person)}>{person.display_name || person.upn}{person.display_name && <span className="block text-xs text-gray-500 font-normal">{person.upn}</span>}</button>
            <label className="text-xs flex gap-2 items-center"><input type="checkbox" aria-label={`VIP ${person.upn}`} checked={person.vip} onChange={e => run(() => api.updateIdentityAccount(workspaceId, person.id, { vip: e.target.checked }))} />VIP</label>
          </div>
          <p className="text-xs text-gray-500 mt-1">{person.source === 'entra' ? 'Microsoft account observed' : 'Customer-supplied account'} · {when(person.updated_at)}</p>
          {person.observation && <div className="text-xs text-gray-600 mt-2 space-y-1">
            <p>Direct roles: {person.observation.roles.state === 'unavailable' ? 'Not available' : person.observation.roles.items.map(r => r.name || 'Name unavailable').join(', ') || 'None returned'}{person.observation.roles.state === 'partial' ? ' (partial)' : ''}</p>
            <p>MFA registration: {person.observation.authentication.state !== 'observed' ? 'Not available' : person.observation.authentication.mfaRegistered ? 'Registered' : 'Not registered'} · Enforcement not assessed</p>
            <p>Observed {when(person.observation.checkedAt)}</p>
          </div>}
        </article>)}
      </div>
      {chosen && <div className="border-t mt-5 pt-4">
        <h3 className="font-medium text-sm break-all">Response for {chosen.upn}</h3>
        <p className="text-xs text-gray-500 mt-1">Your stated concern is recorded as customer-reported evidence. Adding an account or marking it VIP does not establish a breach.</p>
        <label className="block text-xs mt-3">Reason for this response
          <textarea aria-label="Response reason" className="input-base block w-full mt-1" rows={2} maxLength={500} value={concern} onChange={e => setConcern(e.target.value)} placeholder="Describe the finding or concern. Do not paste passwords or tokens." />
        </label>
        <button className="btn-secondary text-sm mt-2" disabled={!chosen.provider_user_id || !hasCredentials || !concern.trim()} onClick={() => run(() => api.previewIdentityResponse(workspaceId, { account_id: chosen.id, concern: concern.trim(), credentials: credentials() }))}>Preview session response</button>
        {!chosen.provider_user_id && <p className="text-xs text-gray-500 mt-2">Read this account from Entra before preparing a session response.</p>}
        {actions.map(item => <article key={item.id} className="mt-4 rounded-lg bg-gray-50 p-3 border border-gray-200">
          <p className="font-medium text-sm">{statusLabel[item.status] || 'Unknown outcome'}</p>
          <p className="text-xs text-gray-600 mt-1">Customer-reported concern: {item.concern}</p>
          <p className="text-xs text-gray-500 mt-1">{when(item.created_at)} · Requested by {item.requested_by}</p>
          <p className="text-xs break-all mt-2">Target: {item.preview.upn} · User ID: {item.preview.id}</p>
          {item.status === 'previewed' && <div className="mt-2">
            <p className="text-xs text-gray-500">This asks Microsoft to revoke sign-in sessions. Existing access tokens and sessions managed by individual apps may persist. Preview expires {when(item.expires_at)}.</p>
            <label className="text-xs block mt-2">Type the exact sign-in name to confirm
              <input aria-label={`Confirm ${item.id}`} className="input-base block w-full mt-1" value={confirmation} onChange={e => setConfirmation(e.target.value)} />
            </label>
            <button className="btn-primary text-sm mt-2" disabled={!hasCredentials || confirmation !== item.preview.upn || Date.now() >= Date.parse(item.expires_at)} onClick={() => run(() => api.applyIdentityResponse(workspaceId, item.id, { confirmed_upn: confirmation, credentials: credentials() }))}>Request session revocation</button>
          </div>}
          {item.outcome?.note && <p className="text-xs text-gray-600 mt-2">{item.outcome.note}</p>}
          {item.outcome?.code && <p className="text-xs mt-2">Recorded result: {item.outcome.code.replaceAll('_', ' ')}</p>}
          {['provider_accepted', 'uncertain', 'applying'].includes(item.status) && <>
            <button className="btn-secondary text-sm mt-2" disabled={!hasCredentials} onClick={() => run(() => api.verifyIdentityResponse(workspaceId, item.id, { credentials: credentials() }))}>Check Microsoft session timestamp</button>
            <p className="text-xs text-gray-500 mt-2">Logout from every application has not been independently verified.</p>
          </>}
          {item.verification && <p className="text-xs text-gray-600 mt-2">{item.verification.state === 'provider_timestamp_advanced' ? 'Microsoft’s session timestamp advanced.' : 'No session timestamp advance observed.'} Checked {when(item.verification.checkedAt)}. {item.verification.note}</p>}
        </article>)}
      </div>}
    </fieldset>
    {busy && <p role="status" className="text-sm mt-3">Checking the requested operation…</p>}
    <p className="text-xs text-gray-500 mt-4">{data.scope_note}</p>
  </section>
}
