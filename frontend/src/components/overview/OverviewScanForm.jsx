import { useEffect, useId, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import Spinner from '../Spinner'
import { canonicalDomainInput } from '../../lib/newScanVerification'
import { useScanStarter, isActiveScan, SCAN_STARTED_TEXT } from '../../hooks/useScanStarter'

/**
 * The Overview's ONE scan control (founder, 21 Oct 2026): a domain field with a
 * single "Scan" button, prefilled with the workspace's verified domain. A
 * verified domain is scanned in place and the page updates itself when the scan
 * finishes. A domain not yet verified keeps the existing path — the new-scan
 * page, which checks ownership first — and the field says so before you press.
 * A member who may only rescan picks one of the verified domains.
 */
export default function OverviewScanForm({ workspaceId, preferredDomain = null, hint = null, onScanComplete = null }) {
  const navigate = useNavigate()
  const inputId = useId()
  const listId = useId()
  const { domains, starting, note, started, start, canScanNewDomain, canRescan, roleKnown } = useScanStarter(workspaceId, { onComplete: onScanComplete })
  const [value, setValue] = useState('')
  const [touched, setTouched] = useState(false)
  const verified = domains || []

  // Prefill once the verified domains are known, unless the person has typed.
  useEffect(() => {
    if (touched || !verified.length) return
    const preferred = canonicalDomainInput(preferredDomain || '')
    setValue(verified.includes(preferred) ? preferred : verified[0])
  }, [domains, preferredDomain, touched]) // eslint-disable-line react-hooks/exhaustive-deps

  if (!roleKnown || (!canScanNewDomain && !canRescan)) return null
  const rescanOnly = !canScanNewDomain
  if (rescanOnly && domains !== null && verified.length === 0) return null

  const entered = canonicalDomainInput(value)
  const isVerified = verified.includes(entered)
  const running = started && isActiveScan(started.status)

  function submit(event) {
    event.preventDefault()
    if (starting) return
    if (isVerified) { start(entered); return }
    if (!rescanOnly) navigate(entered ? `/scans/new?domain=${encodeURIComponent(entered)}` : '/scans/new')
  }

  return (
    <div id="overview-scan" className="mt-6 scroll-mt-24" data-testid="overview-scan">
      <form className="cm-hero-input" aria-label="Start a scan" onSubmit={submit}>
        {rescanOnly ? (
          <select id={inputId} aria-label="Domain to scan" value={entered} onChange={(e) => { setTouched(true); setValue(e.target.value) }}>
            {verified.map((d) => <option key={d} value={d}>{d}</option>)}
          </select>
        ) : (
          <>
            <input
              id={inputId}
              type="text"
              inputMode="url"
              autoComplete="off"
              list={verified.length > 1 ? listId : undefined}
              value={value}
              onChange={(e) => { setTouched(true); setValue(e.target.value) }}
              aria-label="Domain to scan"
              placeholder="Enter a domain to scan, e.g. example.co.uk"
            />
            {verified.length > 1 && <datalist id={listId}>{verified.map((d) => <option key={d} value={d} />)}</datalist>}
          </>
        )}
        <button type="submit" className="btn-primary rounded-full px-5 py-2" disabled={starting}>
          {starting ? <><Spinner size="sm" /><span>Starting…</span></> : 'Scan'}
        </button>
      </form>
      <div className="mt-2 space-y-1 text-sm">
        {!rescanOnly && entered && !isVerified && domains !== null && (
          <p className="text-gray-600">{entered} is not verified in this workspace yet. Scan takes you to the new-scan page, which checks you own it first.</p>
        )}
        {hint && !started && <p className="text-gray-600">{hint}</p>}
        {note && <p role="alert" className="text-red-700">{note}</p>}
        {started && (
          <p role="status" className="text-gray-700">
            {started.status === 'completed' ? `The scan of ${started.domain} is complete; the results below are up to date.`
              : started.status === 'failed' ? `The scan of ${started.domain} did not complete.`
                : `${SCAN_STARTED_TEXT} (${started.domain})`}
            {started.id && <> <Link to={`/scans/${encodeURIComponent(started.id)}`} className="font-semibold text-brand-700 hover:text-brand-800">{running ? 'Follow progress' : 'Open the scan'}</Link></>}
          </p>
        )}
      </div>
    </div>
  )
}
