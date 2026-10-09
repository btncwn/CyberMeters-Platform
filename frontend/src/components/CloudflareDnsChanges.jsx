import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { parseServerDate } from '../utils/dates'

const ACTIONS = {
  spf_publish: 'Publish missing SPF',
  dmarc_reporting: 'Add the reporting address to existing DMARC',
  tls_rpt: 'Publish missing TLS reporting',
}
const STATES = {
  preview: 'Preview only — not applied', applying: 'Application in progress',
  provider_accepted: 'Accepted by Cloudflare — public DNS not yet confirmed',
  dns_verified: 'Record observed in public DNS', uncertain: 'Provider outcome uncertain',
  conflict: 'Record changed — action refused', unavailable: 'Change unavailable',
  rolling_back: 'Undo in progress', rolled_back: 'Undo accepted by Cloudflare',
  rollback_uncertain: 'Undo outcome uncertain',
}
const ERRORS = {
  record_drift: 'The DNS record has changed. Review the current record and create a fresh preview.',
  preview_expired: 'This preview has expired. Create a fresh preview before applying.',
  action_in_progress: 'An action is already in progress. Refresh this change to see its outcome.',
  reporting_endpoint_required: 'Activate DMARC reporting below first, then create a fresh preview.',
  existing_record_conflict: 'An existing record prevents this supported correction. Use the guided instructions below.',
  unsupported_input: 'These inputs are not supported. Review the sender details or use the guided instructions below.',
  domain_not_verified: 'Verify this domain in the current workspace before making a change.',
  plan_required: 'DNS changes are not available on the current plan.',
  session_role_required: 'A current owner or administrator session is required.',
  provider_unavailable: 'Cloudflare could not confirm the request. Refresh the change before trying another action.',
  key_unavailable: 'The DNS connection is unavailable. No change has been confirmed.',
  connection_required: 'Connect this domain’s Cloudflare zone before continuing.',
  connection_changed: 'The DNS connection changed. Refresh the saved state before continuing.',
  provider_access_denied: 'Cloudflare did not grant access to this zone. Check the selected zone and the token’s Zone Read and DNS Edit permissions.',
}
const date = value => {
  const parsed = parseServerDate(value)
  return parsed && Number.isFinite(parsed.getTime()) ? parsed.toLocaleString() : 'Not recorded'
}
const list = value => value.split(/[\s,]+/).map(s => s.trim()).filter(Boolean)

// Scope is keyed by workspace/domain below. Abort and ignore late responses,
// including a return to the same workspace after navigating elsewhere.
function useScopedRequest() {
  const alive = useRef(false)
  const controllers = useRef(new Set())
  const active = useRef(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    alive.current = true
    return () => { alive.current = false; active.current = false; for (const c of controllers.current) c.abort(); controllers.current.clear() }
  }, [])
  async function run(operation, accept, onFailure) {
    if (active.current) return
    const controller = new AbortController()
    controllers.current.add(controller)
    active.current = true; setBusy(true); setError('')
    try {
      const result = await operation({ signal: controller.signal })
      if (alive.current && !controller.signal.aborted) accept(result)
    } catch (failure) {
      // Do not echo a provider/request error that could contain the submitted token.
      if (alive.current && !controller.signal.aborted) {
        setError(ERRORS[failure?.code] || 'The request could not be confirmed. Refresh the saved state before trying again.')
        onFailure?.()
      }
    } finally {
      controllers.current.delete(controller)
      if (alive.current && !controller.signal.aborted) { active.current = false; setBusy(false) }
    }
  }
  return { busy, error, run }
}

export default function CloudflareDnsChanges({ workspaceId, onDomainChange }) {
  return workspaceId ? <WorkspaceDns key={workspaceId} workspaceId={workspaceId} onDomainChange={onDomainChange} /> : null
}

function WorkspaceDns({ workspaceId, onDomainChange }) {
  const [data, setData] = useState(null)
  const [domain, setDomain] = useState('')
  const { busy, error, run } = useScopedRequest()
  const load = () => run(options => api.getDnsConnections(workspaceId, options), result => { setData(result); setDomain('') })
  useEffect(() => { load() }, [workspaceId])
  if (!data && busy) return <p className="text-sm text-gray-500 mb-6">Loading DNS connection options…</p>
  if (!data) return <div className="mb-6">{error && <p role="alert" className="text-sm text-red-700">{error}</p>}<button type="button" onClick={load} disabled={busy} className="text-sm underline">Load DNS connection options</button></div>
  if (data.can_manage !== true) return null
  const domains = Array.isArray(data.domains) ? data.domains : []
  const actions = (data.supported_actions || []).filter(action => ACTIONS[action.id])
  return <section className="card p-5 sm:p-6 mb-6" aria-labelledby="cloudflare-dns-heading">
    <h2 id="cloudflare-dns-heading" className="section-title">Cloudflare DNS corrections</h2>
    <p className="text-sm text-gray-600 mt-2">Connect one verified domain, preview a supported correction, then choose whether to apply it.</p>
    <p className="text-xs text-gray-500 mt-2">{data.scope_note || 'Cloudflare accepting a record is separate from observing it in public DNS. This does not prove mail delivery or close a security case.'}</p>
    {!domains.length ? <p className="text-sm text-gray-600 mt-4">Verify a domain in this workspace first. A completed scan is not required to connect DNS.</p> : <label className="block text-sm text-gray-700 mt-4 max-w-md">Domain for this DNS change
      <select className="input mt-1" value={domain} onChange={event => { setDomain(event.target.value); if (event.target.value) onDomainChange?.(event.target.value) }}>
        <option value="">Select a verified domain</option>
        {domains.map(item => <option key={item.id} value={item.domain}>{item.domain}</option>)}
      </select>
    </label>}
    {domain && domains.some(item => item.domain === domain) && <DomainDns key={domain} workspaceId={workspaceId} domain={domain} actions={actions} workspaceCanApply={data.can_apply === true} />}
    <p className="text-xs text-gray-500 mt-4">Other DNS fixes remain available through the <a href="#dmarc-setup" className="underline text-brand-700">guided setup instructions below</a>. This is not a general DNS editor.</p>
  </section>
}

function DomainDns({ workspaceId, domain, actions, workspaceCanApply }) {
  const [data, setData] = useState(null)
  const [zoneId, setZoneId] = useState('')
  const [token, setToken] = useState('')
  const [connectConsent, setConnectConsent] = useState(false)
  const [actionId, setActionId] = useState('')
  const [mailMode, setMailMode] = useState('')
  const [includes, setIncludes] = useState('')
  const [ip4, setIp4] = useState('')
  const [ip6, setIp6] = useState('')
  const [all, setAll] = useState('')
  const [sendersConfirmed, setSendersConfirmed] = useState(false)
  const [change, setChange] = useState(null)
  const [approved, setApproved] = useState(false)
  const { busy, error, run } = useScopedRequest()
  function acceptData(result) { setData(result); if (result.can_manage !== true) { setToken(''); setConnectConsent(false); setChange(null) } }
  const load = () => run(options => api.getDnsConnection(workspaceId, domain, options), acceptData)
  useEffect(() => { load() }, [workspaceId, domain])
  const canManage = data?.can_manage === true
  const canApply = canManage && workspaceCanApply && data?.can_apply === true
  const supported = actions.some(action => action.id === actionId)
  const spfReady = mailMode === 'no_mail' ? sendersConfirmed : mailMode === 'senders' && sendersConfirmed && ['~all', '-all'].includes(all) && Boolean(list(includes).length + list(ip4).length + list(ip6).length)
  const previewReady = canManage && data?.connection && supported && (actionId === 'spf_publish' ? spfReady : data.reporting_ready === true)
  const exactPreview = Array.isArray(change?.before) && change.before.every(record => record.type === 'TXT' && typeof record.name === 'string' && typeof record.content === 'string') && change?.after?.type === 'TXT' && typeof change.after.name === 'string' && typeof change.after.content === 'string'
  const allowApply = canApply && change?.status === 'preview' && change.can_apply === true && exactPreview
  function edit(setter, value) { setter(value); setChange(null); setApproved(false); setSendersConfirmed(false) }
  function acceptChange(result) { setChange(result.change || null); setApproved(false) }
  function connect(event) {
    event.preventDefault()
    if (!canManage || !connectConsent || !/^[a-f0-9]{32}$/i.test(zoneId.trim()) || !token.trim() || busy) return
    const body = { zone_id: zoneId.trim().toLowerCase(), token: token.trim() }
    setToken(''); setConnectConsent(false); setChange(null); setApproved(false)
    run(options => api.connectDns(workspaceId, domain, body, options), acceptData)
  }
  function preview(event) {
    event.preventDefault()
    if (!previewReady || busy) return
    const inputs = actionId !== 'spf_publish' ? {} : mailMode === 'no_mail' ? { mail_mode: 'no_mail', no_mail_confirmed: true } : { mail_mode: 'senders', includes: list(includes), ip4: list(ip4), ip6: list(ip6), all, senders_confirmed: true }
    setChange(null); setApproved(false)
    run(options => api.previewDnsChange(workspaceId, domain, { action_id: actionId, request_id: crypto.randomUUID(), inputs }, options), acceptChange)
  }
  function operate(method) {
    if (!canManage || busy || !change?.id) return
    const permitted = method === 'applyDnsChange' ? allowApply && approved : method === 'rollbackDnsChange' ? change.can_rollback === true && approved : change.can_verify === true
    if (!permitted) return
    setApproved(false)
    // A lost response must be reconciled before another write is offered.
    setChange(previous => ({ ...previous, can_apply: false, can_rollback: false, ...(method === 'applyDnsChange' ? { status: 'applying' } : method === 'rollbackDnsChange' ? { status: 'rolling_back' } : {}) }))
    run(options => api[method](workspaceId, domain, change.id, { request_id: crypto.randomUUID(), ...(method !== 'verifyDnsChange' ? { confirm: true } : {}) }, options), acceptChange, () => {
      if (method !== 'verifyDnsChange') setChange(previous => ({ ...previous, status: method === 'rollbackDnsChange' ? 'rollback_uncertain' : 'uncertain' }))
    })
  }
  if (!data) return <div className="mt-4">{busy ? <p className="text-sm text-gray-500">Loading this domain’s connection…</p> : <button type="button" onClick={load} className="underline text-sm">Reload domain connection</button>}{error && <p role="alert" className="text-sm text-red-700">{error}</p>}</div>
  if (!canManage) return null
  return <div className="mt-4 space-y-4">
    <div className="flex flex-wrap justify-between items-center gap-2">
      <p className="text-sm text-gray-700">{data.connection ? <>Connected zone: <b>{data.connection.zone_name}</b></> : 'No Cloudflare connection saved for this domain.'}</p>
      <button type="button" onClick={() => { setChange(null); setApproved(false); load() }} disabled={busy} className="text-xs underline text-brand-700">Refresh connection and history</button>
    </div>
    {!canApply && <p className="text-sm text-amber-800">{data.reason === 'plan_required' ? 'Applying a new DNS correction requires an eligible paid plan or trial. Preview, status checks and undo remain available.' : 'Applying new DNS changes is currently unavailable. You can still check saved changes and use guided setup.'}</p>}
    {!data.connection ? <form onSubmit={connect} className="space-y-3" autoComplete="off">
      <ol className="list-decimal pl-5 space-y-1 text-xs text-gray-600">
        <li>Open <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener noreferrer" className="underline text-brand-700">Cloudflare API tokens</a>, choose Create Token, then the Edit zone DNS template.</li>
        <li>Set Zone → DNS → Edit and Zone → Zone → Read. Under Zone Resources, select only the specific zone containing <b>{domain}</b>.</li>
        <li>Find its Zone ID on the domain’s Cloudflare Overview page, in the API section. <a href="https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/" target="_blank" rel="noopener noreferrer" className="underline text-brand-700">Where to find it</a>.</li>
      </ol>
      <p className="text-xs text-gray-500">Check those restrictions in Cloudflare before connecting. CyberMeters checks access to this zone; it cannot prove the token has no wider permissions. The saved token is encrypted and never returned here.</p>
      <label className="block text-sm text-gray-700">Cloudflare zone ID<input className="input mt-1" value={zoneId} onChange={event => { setZoneId(event.target.value); setConnectConsent(false) }} required maxLength={32} autoComplete="off" disabled={busy} /></label>
      <label className="block text-sm text-gray-700">Restricted Cloudflare API token<input className="input mt-1" type="password" value={token} onChange={event => { setToken(event.target.value); setConnectConsent(false) }} required maxLength={1024} autoComplete="off" disabled={busy} /></label>
      <label className="flex gap-2 text-sm text-gray-600"><input type="checkbox" checked={connectConsent} onChange={event => setConnectConsent(event.target.checked)} disabled={busy} /><span>I control this zone and authorise CyberMeters to save this restricted token for changes I explicitly approve.</span></label>
      <button type="submit" className="btn-secondary" disabled={busy || !connectConsent || !/^[a-f0-9]{32}$/i.test(zoneId.trim()) || !token.trim()}>Connect Cloudflare</button>
    </form> : <>
      <p className="text-xs text-gray-500">Disconnecting removes this saved connection. It does not undo DNS records or revoke the token in Cloudflare.</p>
      <button type="button" disabled={busy} onClick={() => { setChange(null); setApproved(false); run(options => api.disconnectDns(workspaceId, domain, options), () => setData(previous => ({ ...previous, connection: null }))) }} className="text-xs underline text-gray-600">Disconnect saved token</button>
      <form onSubmit={preview} className="space-y-3 border-t border-gray-100 pt-4">
        <label className="block text-sm text-gray-700">Supported correction<select className="input mt-1" value={actionId} onChange={event => edit(setActionId, event.target.value)} disabled={busy}><option value="">Select a correction</option>{actions.map(action => <option key={action.id} value={action.id}>{ACTIONS[action.id]}</option>)}</select></label>
        {actionId === 'spf_publish' && <>
          <p className="text-xs text-gray-500">Creates SPF only when none exists. Sender details must come from your actual mail services; CyberMeters does not guess them.</p>
          <label className="block text-sm text-gray-700">Does this domain send email?<select className="input mt-1" value={mailMode} onChange={event => edit(setMailMode, event.target.value)} disabled={busy}><option value="">Choose explicitly</option><option value="senders">Yes — specify authorised senders</option><option value="no_mail">No — this domain sends no email</option></select></label>
          {mailMode === 'senders' && <>
            <label className="block text-sm text-gray-700">SPF include domains<textarea className="input mt-1" value={includes} onChange={event => edit(setIncludes, event.target.value)} disabled={busy} placeholder="One domain per line, supplied by your mail service" /></label>
            <label className="block text-sm text-gray-700">Authorised IPv4 addresses or ranges<textarea className="input mt-1" value={ip4} onChange={event => edit(setIp4, event.target.value)} disabled={busy} /></label>
            <label className="block text-sm text-gray-700">Authorised IPv6 addresses or ranges<textarea className="input mt-1" value={ip6} onChange={event => edit(setIp6, event.target.value)} disabled={busy} /></label>
            <label className="block text-sm text-gray-700">Other senders<select className="input mt-1" value={all} onChange={event => edit(setAll, event.target.value)} disabled={busy}><option value="">Choose explicitly</option><option value="~all">Soft fail (~all)</option><option value="-all">Fail (-all)</option></select></label>
          </>}
          {mailMode && <label className="flex gap-2 text-sm text-gray-600"><input type="checkbox" checked={sendersConfirmed} onChange={event => { setSendersConfirmed(event.target.checked); setChange(null); setApproved(false) }} disabled={busy} /><span>{mailMode === 'no_mail' ? 'I confirm this domain sends no email. The proposed -all record denies all senders.' : 'I confirm these are the authorised mail senders and I have reviewed the policy for other senders.'}</span></label>}
        </>}
        {actionId && actionId !== 'spf_publish' && <p className="text-xs text-gray-600">{actionId === 'dmarc_reporting' ? 'Adds only your CyberMeters reporting address to the existing DMARC record. Its policy is preserved.' : 'Creates TLS reporting only when the record is missing, using your active reporting address.'}</p>}
        {actionId && actionId !== 'spf_publish' && data.reporting_ready !== true && <p className="text-sm text-amber-800">Activate DMARC reporting below before previewing this correction.</p>}
        <button type="submit" className="btn-primary" disabled={busy || !previewReady}>Preview exact DNS change</button>
      </form>
    </>}
    {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
    {change && <div className="rounded-lg border border-gray-200 p-4 space-y-3">
      <h3 className="font-semibold text-gray-800">{ACTIONS[change.action_id] || 'Saved DNS change'}</h3>
      <p className="text-sm text-gray-700">{STATES[change.status] || 'Outcome not established'}</p>
      <div className="grid sm:grid-cols-2 gap-3"><Record title="Before" records={change.before} /><Record title="After" records={change.after ? [change.after] : null} /></div>
      {change.status === 'preview' && <p className="text-xs text-gray-500">Preview expires: {date(change.expires_at)}. Apply rechecks the current record and domain permission.</p>}
      <p className="text-sm text-gray-600">Public DNS: {change.verification?.state === 'observed' ? 'record observed' : change.verification?.state === 'pending' ? 'not observed yet' : change.verification?.state === 'unavailable' ? 'check unavailable' : 'not checked'}{change.verification?.checked_at ? ` · ${date(change.verification.checked_at)}` : ''}</p>
      <p className="text-xs text-gray-500">This does not prove mail delivery or close a security case.{change.case_status ? ` Linked case: ${change.case_status.replace(/_/g, ' ')}.` : ''}</p>
      {canManage && (allowApply || change.can_rollback === true) && <label className="flex gap-2 text-sm text-gray-700"><input type="checkbox" checked={approved} onChange={event => setApproved(event.target.checked)} disabled={busy} /><span>{change.status === 'preview' ? 'I have reviewed this exact before-and-after change and approve applying it.' : 'I approve undoing this change only if the DNS record is still unchanged.'}</span></label>}
      <div className="flex flex-wrap gap-3">
        {allowApply && <button type="button" className="btn-primary" disabled={busy || !approved} onClick={() => operate('applyDnsChange')}>Apply this exact change</button>}
        {canManage && change.can_verify === true && <button type="button" className="btn-secondary" disabled={busy} onClick={() => operate('verifyDnsChange')}>Check public DNS and saved outcome</button>}
        {canManage && change.can_rollback === true && <button type="button" className="btn-secondary" disabled={busy || !approved} onClick={() => operate('rollbackDnsChange')}>Undo this change</button>}
        <button type="button" className="underline text-sm" disabled={busy} onClick={() => run(options => api.getDnsChange(workspaceId, domain, change.id, options), acceptChange)}>Refresh this change</button>
      </div>
    </div>}
    {Array.isArray(data.changes) && data.changes.length > 0 && <details className="text-sm"><summary className="cursor-pointer">Saved DNS changes ({data.changes.length})</summary><ul className="mt-2 space-y-2">{data.changes.map(item => <li key={item.id}><button type="button" className="underline text-brand-700" disabled={busy} onClick={() => { setApproved(false); run(options => api.getDnsChange(workspaceId, domain, item.id, options), acceptChange) }}>{ACTIONS[item.action_id] || 'DNS change'} · {date(item.created_at)}</button></li>)}</ul></details>}
  </div>
}

function Record({ title, records }) {
  return <div className="min-w-0"><h4 className="text-sm font-semibold text-gray-700">{title}</h4>{!Array.isArray(records) ? <p className="text-xs text-amber-800">Record evidence unavailable</p> : records.length === 0 ? <p className="text-xs text-gray-500">No matching record</p> : records.map((record, index) => <div key={record.id || index} className="text-xs bg-gray-50 rounded p-2 mt-1"><p className="break-all">{record.type} · {record.name}</p><pre className="whitespace-pre-wrap break-all mt-1">{record.content}</pre><p className="text-gray-500 mt-1">TTL: {record.ttl ?? 'Not recorded'}</p></div>)}</div>
}
