import { useId, useState } from 'react'
import { Link } from 'react-router-dom'
import Spinner from './Spinner'
import { canonicalDomainInput } from '../lib/newScanVerification'
import { useScanStarter, isActiveScan, SCAN_STARTED_TEXT } from '../hooks/useScanStarter'

export { SCAN_STARTED_TEXT }

/**
 * "Scan now" — the one labelled way to start a scan from a module page (founder,
 * 21 Oct 2026: the only control on these pages was an icon that reloaded the
 * list, and it looked like the scan button).
 *
 * It rescans a domain this workspace has already verified (useScanStarter:
 * the same POST /api/scan the new-scan page uses, so plan, rate and role limits
 * are the server's). When it cannot be used it stays visible, disabled, with the
 * reason in words. `domain` is the domain the page is showing; otherwise one
 * verified domain is used directly and several get a labelled picker.
 */
export default function ScanNowButton({ workspaceId, domain = null, align = 'end', label = 'Scan now', variant = 'primary' }) {
  const [choice, setChoice] = useState('')
  const { domains, loadFailed, starting, note, started, refused, start: startScan, canRescan, roleKnown, ownerName } = useScanStarter(workspaceId)
  const reasonId = useId()
  const pickerId = useId()

  const preferred = canonicalDomainInput(domain || '')
  const list = domains || []
  const target = list.includes(preferred) ? preferred
    : list.length === 1 ? list[0]
      : (list.includes(choice) ? choice : '')
  const needsPicker = !list.includes(preferred) && list.length > 1

  let reason = null
  if (domains === null) reason = 'Reading this workspace’s domains…'
  else if (loadFailed) reason = 'The domain list could not be read just now, so a scan cannot be started here. Reload the page to try again.'
  else if (list.length === 0) reason = 'No domain in this workspace is verified yet. A workspace admin verifies a domain before it can be scanned.'
  else if (roleKnown && (!canRescan || refused)) reason = `Your role in this workspace cannot start scans. Ask ${ownerName || 'the workspace owner'} to start one or to change your role.`
  else if (needsPicker && !target) reason = 'Choose the domain to scan.'
  const disabled = Boolean(reason) || starting || !roleKnown

  function start() {
    if (disabled || !target) return
    startScan(target)
  }

  const running = started && isActiveScan(started.status)
  const centre = align === 'center'
  const alignStart = align === 'start'
  const textAlign = centre ? 'text-center' : alignStart ? 'text-left' : 'lg:text-right'
  return (
    <div className={`flex flex-col gap-1.5 ${centre ? 'items-center' : alignStart ? 'items-start' : 'items-stretch lg:items-end'}`} data-testid="scan-now">
      <div className={`flex flex-wrap items-center gap-2 ${centre ? 'justify-center' : alignStart ? 'justify-start' : 'lg:justify-end'}`}>
        {needsPicker && (
          <>
            <label htmlFor={pickerId} className="text-xs font-semibold text-gray-600">Domain to scan</label>
            <select id={pickerId} value={target} onChange={(e) => setChoice(e.target.value)} className="input py-1.5 text-sm w-auto">
              <option value="">Choose…</option>
              {list.map((d) => <option key={d} value={d}>{d}</option>)}
            </select>
          </>
        )}
        <button
          type="button"
          onClick={start}
          disabled={disabled}
          aria-describedby={reason ? reasonId : undefined}
          className={variant === 'secondary' ? 'btn-secondary' : 'btn-primary'}
        >
          {starting ? <><Spinner size="sm" /><span>Starting…</span></> : <span>{label}</span>}
        </button>
      </div>
      {!needsPicker && target && !started && !reason && (
        <p className="text-xs text-gray-500">Scans {target}</p>
      )}
      {reason && <p id={reasonId} className={`text-xs text-gray-600 max-w-xs ${textAlign}`}>{reason}</p>}
      {note && <p role="alert" className={`text-xs text-red-700 max-w-xs ${textAlign}`}>{note}</p>}
      {started && (
        <p role="status" className={`text-xs text-gray-700 max-w-xs ${textAlign}`}>
          {started.status === 'completed' ? `The scan of ${started.domain} is complete. Reload the page to see the new results.`
            : started.status === 'failed' ? (started.outcome === 'domain_not_found' ? `Could not assess ${started.domain}: the domain does not exist in public DNS.` : `The scan of ${started.domain} did not complete.`)
              : `${SCAN_STARTED_TEXT} (${started.domain})`}
          {started.id && (
            <> <Link to={`/scans/${encodeURIComponent(started.id)}`} className="font-semibold text-brand-700 hover:text-brand-800">{running ? 'Follow progress' : 'Open the scan'}</Link></>
          )}
        </p>
      )}
    </div>
  )
}
