import { useId, useState } from 'react'

// S1-A declared-range consent (Executive, 22 Oct 2026; backend #906). When
// adding a network target is refused because its addresses are not observed
// in this workspace's verified-domain DNS, an admin may grant a written,
// revocable authorisation for exactly those addresses and ports. Every word
// of the statement is the API's (capabilities.range_authority), shown
// verbatim with its version; the form invents none of it.

export const SHARED_REFUSAL_TEXT = 'CyberMeters cannot accept an authorisation for these addresses: at least one belongs to shared provider infrastructure that other organisations also use. No target was added.'
export const DECLARED_RANGE_TEXT = 'Authorised by declared range consent — not independently verified by CyberMeters'

const NAME_MAX = 120

export default function NetworkRangeConsentForm({ target, authority, allowedPorts = [], maxPorts = null, busy = false, onGrant, onCancel }) {
  const uid = useId()
  const [ports, setPorts] = useState([])
  const [name, setName] = useState('')
  const [title, setTitle] = useState('')
  const [confirmed, setConfirmed] = useState(false)

  // Without the statement there is nothing to agree to: say so, offer no form.
  if (!authority?.text || !authority?.version) {
    return <p role="alert" className="text-sm text-red-700">The authorisation statement could not be loaded, so an authorisation cannot be recorded. Reload the page to try again.</p>
  }

  const atLimit = maxPorts !== null && ports.length >= maxPorts
  const ready = ports.length > 0 && name.trim() && title.trim() && confirmed && !busy

  function submit(event) {
    event.preventDefault()
    if (!ready) return
    onGrant?.({
      ports: [...ports].sort((a, b) => a - b),
      signer_name: name.trim(),
      signer_title: title.trim(),
      authority_confirmed: true,
      authority_version: authority.version,
    })
  }

  return (
    <form onSubmit={submit} aria-label="Grant authorisation" data-testid="range-consent-form" className="rounded-sm border border-brand-200 bg-white p-4 space-y-3">
      <div>
        <h3 className="font-semibold text-sm text-gray-900">Authorise checks on {target}</h3>
        <p className="text-sm text-gray-600 mt-1">CyberMeters did not find these addresses behind a verified domain in this workspace. You can authorise checks on them by declaring that you have permission. The authorisation covers only these addresses and the ports you choose, and you can revoke it at any time.</p>
      </div>
      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Ports you authorise</legend>
        <div className="flex flex-wrap gap-x-4 gap-y-2">
          {allowedPorts.map(port => (
            <label key={port} className="flex items-center gap-1 text-sm">
              <input type="checkbox" checked={ports.includes(port)} disabled={busy || (atLimit && !ports.includes(port))} aria-describedby={`${uid}-count`}
                onChange={event => setPorts(previous => event.target.checked ? (atLimit ? previous : [...new Set([...previous, port])]) : previous.filter(value => value !== port))} />
              {port}
            </label>
          ))}
        </div>
        <p id={`${uid}-count`} className="text-sm text-gray-700" aria-live="polite">
          {maxPorts !== null ? `${ports.length} of ${maxPorts} selected` : `${ports.length} selected`}{atLimit ? ' — the limit. Untick a port to choose another.' : ''}
        </p>
      </fieldset>
      <div className="grid sm:grid-cols-2 gap-3">
        <label className="text-sm font-medium">Your name<input className="input w-full mt-1" value={name} onChange={event => setName(event.target.value)} maxLength={NAME_MAX} autoComplete="name" /></label>
        <label className="text-sm font-medium">Your title<input className="input w-full mt-1" value={title} onChange={event => setTitle(event.target.value)} maxLength={NAME_MAX} autoComplete="organization-title" /></label>
      </div>
      <div className="rounded-sm bg-gray-50 p-3">
        <p className="text-sm text-gray-800" data-testid="range-authority-text">{authority.text}</p>
        <p className="text-xs text-gray-500 mt-1">Statement version {authority.version}</p>
      </div>
      <label className="flex items-start gap-2 text-sm">
        <input type="checkbox" checked={confirmed} onChange={event => setConfirmed(event.target.checked)} className="mt-1" disabled={busy} />
        I confirm the statement above
      </label>
      {authority.declaration && <p className="text-xs text-gray-500">{authority.declaration}</p>}
      <div className="flex flex-wrap gap-2">
        <button type="submit" className="btn-primary text-sm" disabled={!ready}>{busy ? 'Recording…' : 'Grant authorisation'}</button>
        {onCancel && <button type="button" className="btn-secondary text-sm" onClick={onCancel} disabled={busy}>Cancel</button>}
      </div>
    </form>
  )
}
