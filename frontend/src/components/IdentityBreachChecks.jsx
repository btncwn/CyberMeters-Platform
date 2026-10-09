import { useEffect, useRef, useState } from 'react'
import { api } from '../api'
import { parseServerDate } from '../utils/dates'

const CONSENT_VERSION = '2026-10-09'
const STATUS = {
  sources_found: 'Sources found',
  no_matches: 'No matches returned',
  unavailable: 'Check unavailable',
  rate_limited: 'Check rate limited',
  pending: 'Check pending',
}
const date = value => {
  const parsed = parseServerDate(value)
  return parsed && Number.isFinite(parsed.getTime()) ? parsed.toLocaleString() : 'Not recorded'
}

function SavedSources({ sources }) {
  const [expanded, setExpanded] = useState(false)
  if (!Array.isArray(sources) || !sources.length) return null
  return <details className="mt-2 text-xs text-slate-600">
    <summary className="cursor-pointer">Source names in this saved result: {sources.length}</summary>
    <ul className="list-disc pl-5 mt-2">{(expanded ? sources : sources.slice(0, 10)).map((source, index) => <li key={index}>{source.name || 'Unnamed source'}{source.date ? ` · ${source.date}` : ''}</li>)}</ul>
    {sources.length > 10 && <button type="button" onClick={() => setExpanded(value => !value)} className="underline mt-2">{expanded ? 'Show first 10 source names' : `Show all ${sources.length} saved source names`}</button>}
  </details>
}

// A workspace change unmounts every input/result and invalidates in-flight work,
// including an A → B → A transition whose first A request finishes late.
export default function IdentityBreachChecks({ workspaceId }) {
  return workspaceId ? <WorkspaceChecks key={workspaceId} workspaceId={workspaceId} /> : null
}

function WorkspaceChecks({ workspaceId }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [domainId, setDomainId] = useState('')
  const [email, setEmail] = useState('')
  const [consent, setConsent] = useState(false)
  const [busy, setBusy] = useState(false)
  const alive = useRef(false)
  const busyRef = useRef(false)
  const loadId = useRef(0)
  const requests = useRef(new Set())

  async function refresh() {
    const controller = new AbortController()
    requests.current.add(controller)
    const id = ++loadId.current
    setLoading(true)
    setError('')
    try {
      const result = await api.getIdentityBreachChecks(workspaceId, { signal: controller.signal })
      if (!alive.current || controller.signal.aborted || id !== loadId.current) return
      if (result?.can_check === true) setData(result)
      else { setData({ can_check: false }); setEmail(''); setConsent(false); setDomainId('') }
    } catch (failure) {
      if (!alive.current || controller.signal.aborted || id !== loadId.current) return
      setData(null)
      if (failure?.status !== 403) setError('Saved checks could not be loaded. No conclusion can be drawn from this error.')
    } finally {
      requests.current.delete(controller)
      if (alive.current && !controller.signal.aborted && id === loadId.current) setLoading(false)
    }
  }

  useEffect(() => {
    alive.current = true
    refresh()
    return () => {
      alive.current = false
      loadId.current += 1
      for (const controller of requests.current) controller.abort()
      requests.current.clear()
    }
  }, [workspaceId])

  const allowed = data?.can_check === true
  const domains = Array.isArray(data?.domains) ? data.domains : []
  const items = Array.isArray(data?.items) ? data.items : []
  const selectedDomain = domains.find(domain => domain.id === domainId)
  const supportedConsent = data?.consent_version === CONSENT_VERSION
  const addressDomain = email.trim().split('@')
  const matchesDomain = addressDomain.length === 2 && addressDomain[0].length > 0 &&
    addressDomain[1].toLowerCase() === selectedDomain?.domain?.toLowerCase()
  const ready = allowed && supportedConsent && consent && matchesDomain && !busy && !loading

  async function submit(event) {
    event.preventDefault()
    if (!ready || busyRef.current) return
    busyRef.current = true
    const controller = new AbortController()
    requests.current.add(controller)
    setBusy(true)
    setError('')
    const body = {
      domain_id: domainId,
      email: email.trim(),
      consent: true,
      consent_version: CONSENT_VERSION,
      request_id: crypto.randomUUID(),
    }
    // Keep the raw address only in the submitted request, never in saved UI state.
    setEmail('')
    setConsent(false)
    try {
      const result = await api.createIdentityBreachCheck(workspaceId, body, { signal: controller.signal })
      if (!alive.current || controller.signal.aborted) return
      if (!result?.item?.id) throw new Error('Missing check result')
      setData(previous => ({ ...previous, items: [result.item, ...(previous?.items || []).filter(item => item.id !== result.item.id)] }))
    } catch {
      if (alive.current && !controller.signal.aborted) setError('The check did not complete. This is not a no-match result. Refresh saved checks before trying again.')
    } finally {
      requests.current.delete(controller)
      if (alive.current && !controller.signal.aborted) { busyRef.current = false; setBusy(false) }
    }
  }

  async function remove(id) {
    if (!allowed || busyRef.current) return
    busyRef.current = true
    const controller = new AbortController()
    requests.current.add(controller)
    setBusy(true)
    setError('')
    try {
      await api.deleteIdentityBreachCheck(workspaceId, id, { signal: controller.signal })
      if (alive.current && !controller.signal.aborted) setData(previous => ({ ...previous, items: previous.items.filter(item => item.id !== id) }))
    } catch {
      if (alive.current && !controller.signal.aborted) setError('The saved result could not be deleted. It remains in the list.')
    } finally {
      requests.current.delete(controller)
      if (alive.current && !controller.signal.aborted) { busyRef.current = false; setBusy(false) }
    }
  }

  if (loading && !data) return <p className="text-sm text-slate-500 my-4">Loading saved address checks…</p>
  if (!allowed) return error ? <p role="alert" className="text-sm text-red-700 my-4">{error}</p> : null

  return <section aria-labelledby="identity-breach-heading" className="rounded-xl border border-slate-200 bg-white p-4 my-6">
    <div className="flex flex-wrap justify-between items-start gap-3">
      <div>
        <h2 id="identity-breach-heading" className="font-semibold text-slate-800">Known address breach check</h2>
        <p className="text-sm text-slate-600 mt-1">Check one corporate email address you already know and are authorised to check.</p>
      </div>
      <button type="button" onClick={refresh} disabled={busy || loading} className="text-sm underline text-brand-700 disabled:opacity-50">{loading ? 'Refreshing…' : 'Refresh saved checks'}</button>
    </div>
    <p className="text-xs text-slate-500 mt-3">{data.scope_note || 'This checks known addresses, not an entire domain. It is not dark-web or password monitoring. A source match does not prove a current compromise; no match does not prove the address is safe.'}</p>
    <p className="text-xs mt-2"><a href="https://leakcheck.io" target="_blank" rel="noopener noreferrer" className="text-brand-700 underline">Powered by LeakCheck</a></p>

    {!domains.length ? <p className="text-sm text-slate-600 mt-4">Verify a domain in this workspace before checking a known address.</p> : !supportedConsent ? <p role="alert" className="text-sm text-amber-800 mt-4">The consent notice has changed. Reload this page before starting a check.</p> : <form onSubmit={submit} className="mt-4 space-y-3" autoComplete="off">
      <div className="grid gap-3 sm:grid-cols-2">
        <label className="text-sm text-slate-700">Verified domain
          <select value={domainId} onChange={event => { setDomainId(event.target.value); setEmail(''); setConsent(false) }} disabled={busy} required className="input mt-1 w-full">
            <option value="">Select a verified domain</option>
            {domains.map(domain => <option key={domain.id} value={domain.id}>{domain.domain}</option>)}
          </select>
        </label>
        <label className="text-sm text-slate-700">Known corporate email address
          <input type="email" value={email} onChange={event => { setEmail(event.target.value); setConsent(false) }} disabled={busy || !selectedDomain} required maxLength={254} autoComplete="off" autoCapitalize="none" spellCheck={false} className="input mt-1 w-full" />
        </label>
      </div>
      {email && !matchesDomain && <p className="text-xs text-amber-800">Use an address on the selected verified domain.</p>}
      <label className="flex items-start gap-2 text-sm text-slate-600">
        <input type="checkbox" checked={consent} onChange={event => setConsent(event.target.checked)} disabled={busy} className="mt-1" />
        <span>I have corporate permission to check this address for security exposure. I agree that CyberMeters processes it and sends a truncated SHA-256 hash (first 24 characters) to LeakCheck. This is pseudonymous, not anonymous. I will not enter a password.</span>
      </label>
      <button type="submit" disabled={!ready} className="btn-primary disabled:opacity-50">{busy ? 'Working…' : 'Check this address'}</button>
      <p className="text-xs text-slate-500">The address field clears when submitted. Saved results show a masked address and an expiry when automatic retention is enabled. Delete removes the saved workspace result, not data held by the source.</p>
    </form>}

    {error && <p role="alert" className="text-sm text-red-700 mt-3">{error}</p>}
    <div className="mt-5 space-y-3" aria-live="polite">
      {!items.length && <p className="text-sm text-slate-500">No saved checks. This is not a no-match result.</p>}
      {items.map(item => <article key={item.id} className="border border-slate-200 rounded-lg p-3 text-sm">
        <div className="flex flex-wrap justify-between items-start gap-2">
          <div><h3 className="font-medium text-slate-800 break-all">{item.masked_address || 'Masked address unavailable'}</h3><p className="text-slate-600 mt-1">{STATUS[item.status] || 'Check unavailable'}</p></div>
          <button type="button" onClick={() => remove(item.id)} disabled={busy || loading} className="text-xs text-slate-600 underline disabled:opacity-50" aria-label={`Delete result for ${item.masked_address || 'masked address'}`}>Delete result</button>
        </div>
        {item.status === 'sources_found' && <>
          <p className="text-slate-600 mt-2">{Number.isInteger(item.found_count) && item.found_count > 0 ? `${item.found_count} matching records reported.` : 'The provider reported matching records.'} This is not a count of unique breaches. Review the source context before deciding what to do.</p>
          {Array.isArray(item.fields) && item.fields.length > 0 && <p className="text-xs text-slate-500 mt-1">Reported field types: {item.fields.join(', ')}. Values and passwords are not shown.</p>}
          <SavedSources sources={item.sources} />
        </>}
        {item.status === 'no_matches' ? <p className="text-xs text-slate-500 mt-2">LeakCheck returned no matches for this check at that time. Other sources and later disclosures may differ.</p> : item.status === 'pending' ? <p className="text-xs text-slate-500 mt-2">No conclusion yet. Refresh saved checks for the recorded outcome.</p> : item.status !== 'sources_found' && <p className="text-xs text-amber-800 mt-2">{item.status === 'rate_limited' ? 'The check was limited. No conclusion about exposure is available.' : 'The check could not be completed. No conclusion about exposure is available.'}</p>}
        <p className="text-xs text-slate-400 mt-2">Checked: {date(item.checked_at)} · {item.expires_at === null ? 'No automatic expiry' : `Saved until: ${date(item.expires_at)}`}</p>
      </article>)}
    </div>
  </section>
}
