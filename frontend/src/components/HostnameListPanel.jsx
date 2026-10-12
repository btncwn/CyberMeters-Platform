import { useCallback, useEffect, useId, useState } from 'react'
import { api } from '../api'
import { parseServerDate } from '../utils/dates'

// "Hostnames you know about" — per verified domain, a list of hostnames every
// scan asks DNS about. The backend owns parsing, scope and every outcome; a
// listed name reaches the inventory only after DNS answers for it in a scan.

export const FORMAT_OPTIONS = [
  { value: 'list', label: 'One hostname per line' },
  { value: 'csv', label: 'CSV with a hostname column' },
  { value: 'zone', label: 'DNS zone file' },
]

const ERROR_TEXT = {
  role_required: 'Only a workspace owner or admin can change hostname lists.',
  domain_not_verified: 'Verify this domain in this workspace first.',
  unsupported_format: 'Choose a list, CSV or zone file format.',
  unsupported_input: 'The list could not be read. Check the format and try again.',
  input_too_large: 'The list is too large. Upload at most 256 KB.',
  no_hostnames_accepted: 'No hostname under this domain was found in the list.',
  rate_limit_exceeded: 'Too many changes in the last hour. Try again later.',
}

const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`

function fmt(value) {
  const d = parseServerDate(value)
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleString(undefined, { day: 'numeric', month: 'short', year: 'numeric' }) : null
}

/** One sentence per fact the backend reported about an upload. */
export function importSummaryLines(result, domain) {
  if (!result) return []
  const lines = []
  if (Number.isInteger(result.accepted) && result.accepted > 0) lines.push(`${plural(result.accepted, 'hostname')} saved.`)
  if (result.out_of_scope > 0) lines.push(`${plural(result.out_of_scope, 'entry', 'entries')} outside ${domain} ${result.out_of_scope === 1 ? 'was' : 'were'} ignored.`)
  if (result.rejected > 0) lines.push(`${plural(result.rejected, 'entry', 'entries')} could not be read as a hostname.`)
  if (result.truncated) lines.push('The list was longer than the limit; only the first names were kept.')
  return lines
}

function errorText(res) {
  return ERROR_TEXT[res?.body?.code] || ERROR_TEXT[res?.body?.error] || 'That did not work. Try again.'
}

function ListEditor({ workspaceId, domain, maxBytes, onSaved, onCancel }) {
  const uid = useId()
  const [format, setFormat] = useState('list')
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [summary, setSummary] = useState([])

  async function readFile(event) {
    const file = event.target.files?.[0]
    if (!file) return
    setError(null)
    if (file.size > maxBytes) { setError(ERROR_TEXT.input_too_large); return }
    if (/\.csv$/i.test(file.name)) setFormat('csv')
    else if (/\.(zone|db)$/i.test(file.name)) setFormat('zone')
    setText(await file.text())
  }

  async function submit(event) {
    event.preventDefault()
    setBusy(true)
    setError(null)
    setSummary([])
    try {
      const res = await api.saveHostnameList(workspaceId, domain, { format, text })
      if (res.ok) onSaved?.(res.body.list, importSummaryLines(res.body.result, domain))
      else { setError(errorText(res)); setSummary(importSummaryLines(res.body?.result, domain)) }
    } catch {
      setError('That did not work. Try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="mt-3 space-y-3 rounded border border-gray-200 p-3">
      <div className="flex flex-col gap-1">
        <label htmlFor={`${uid}-format`} className="text-sm font-medium text-gray-800">Format</label>
        <select id={`${uid}-format`} className="input max-w-xs" value={format} onChange={(e) => setFormat(e.target.value)}>
          {FORMAT_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor={`${uid}-text`} className="text-sm font-medium text-gray-800">Hostnames under {domain}</label>
        <textarea id={`${uid}-text`} className="input font-mono text-xs min-h-[8rem]" value={text} spellCheck={false}
          placeholder={format === 'csv' ? 'hostname\nportal.' + domain : format === 'zone' ? `$ORIGIN ${domain}.\nportal  IN  A  192.0.2.10` : `portal.${domain}\nvpn.${domain}`}
          onChange={(e) => setText(e.target.value)} />
        <p className="text-xs text-gray-500">Up to 200 hostnames. Names outside {domain} are ignored.</p>
      </div>
      <div className="flex flex-col gap-1">
        <label htmlFor={`${uid}-file`} className="text-sm font-medium text-gray-800">Or upload a file</label>
        <input id={`${uid}-file`} type="file" accept=".txt,.csv,.zone,.db,text/plain,text/csv" onChange={readFile} className="text-sm" />
      </div>
      {error && <p role="alert" className="text-sm text-red-700 bg-red-50 rounded p-2">{error}</p>}
      {summary.length > 0 && <ul className="text-xs text-gray-600 list-disc pl-4">{summary.map((line) => <li key={line}>{line}</li>)}</ul>}
      <div className="flex gap-2">
        <button type="submit" className="btn-primary" disabled={busy || !text.trim()}>{busy ? 'Saving…' : 'Save list'}</button>
        <button type="button" className="btn-secondary" onClick={onCancel} disabled={busy}>Cancel</button>
      </div>
    </form>
  )
}

function DomainRow({ workspaceId, entry, canManage, maxBytes, onChanged }) {
  const [editing, setEditing] = useState(false)
  const [confirming, setConfirming] = useState(false)
  const [busy, setBusy] = useState(false)
  const [notice, setNotice] = useState([])
  const [error, setError] = useState(null)
  const list = entry.list

  async function clear() {
    setBusy(true)
    setError(null)
    try {
      const res = await api.clearHostnameList(workspaceId, entry.domain)
      if (res.ok) { setConfirming(false); setNotice(['List removed. Scans no longer check these names.']); onChanged?.() }
      else setError(errorText(res))
    } catch {
      setError('That did not work. Try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="font-medium text-gray-900">{entry.domain}</p>
          <p className="text-xs text-gray-500">
            {list ? `${plural(list.hostname_count, 'hostname')} listed${fmt(list.saved_at) ? ` · saved ${fmt(list.saved_at)}` : ''}` : 'No list'}
          </p>
        </div>
        {canManage && !editing && (
          <div className="flex gap-2">
            <button type="button" className="btn-secondary" onClick={() => { setEditing(true); setNotice([]) }}>{list ? 'Replace list' : 'Add list'}</button>
            {list && !confirming && <button type="button" className="btn-secondary" onClick={() => setConfirming(true)}>Remove list</button>}
            {list && confirming && <button type="button" className="btn-secondary text-red-700" onClick={clear} disabled={busy}>{busy ? 'Removing…' : 'Confirm remove'}</button>}
          </div>
        )}
      </div>
      {error && <p role="alert" className="mt-2 text-sm text-red-700 bg-red-50 rounded p-2">{error}</p>}
      {notice.length > 0 && <ul role="status" className="mt-2 text-xs text-gray-600 list-disc pl-4">{notice.map((line) => <li key={line}>{line}</li>)}</ul>}
      {list && list.hostnames?.length > 0 && (
        <details className="mt-2">
          <summary className="text-sm text-brand-700 cursor-pointer">Show listed hostnames</summary>
          <ul className="mt-1 grid gap-0.5 sm:grid-cols-2" aria-label={`Hostnames listed for ${entry.domain}`}>
            {list.hostnames.map((hostname) => <li key={hostname} className="font-mono text-xs text-gray-700 break-all">{hostname}</li>)}
          </ul>
        </details>
      )}
      {editing && (
        <ListEditor workspaceId={workspaceId} domain={entry.domain} maxBytes={maxBytes}
          onCancel={() => setEditing(false)}
          onSaved={(_, lines) => { setEditing(false); setNotice([...lines, 'The next scan asks DNS about each name.']); onChanged?.() }} />
      )}
    </li>
  )
}

export default function HostnameListPanel({ workspaceId }) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    setError(null)
    try { setData(await api.getHostnameLists(workspaceId)) }
    catch { setError('Hostname lists could not be loaded.') }
  }, [workspaceId])

  useEffect(() => { load() }, [load])

  return (
    <section className="card p-5" aria-labelledby="hostname-list-heading">
      <div className="flex items-center gap-2 mb-1">
        <h2 id="hostname-list-heading" className="text-base font-semibold text-gray-900">Hostnames you know about</h2>
      </div>
      {data?.scope_note && <p className="text-sm text-gray-600">{data.scope_note}</p>}
      {error && <p role="alert" className="mt-3 text-sm text-red-700 bg-red-50 rounded p-3">{error}</p>}
      {!error && !data && <p className="mt-3 text-sm text-gray-500" role="status">Loading…</p>}
      {data && !data.can_manage && <p className="mt-2 text-xs text-gray-500">Only a workspace owner or admin can change hostname lists.</p>}
      {data && (data.domains?.length ? (
        <ul className="mt-2 divide-y divide-gray-100">
          {data.domains.map((entry) => (
            <DomainRow key={entry.domain} workspaceId={workspaceId} entry={entry} canManage={data.can_manage}
              maxBytes={data.limits?.max_bytes ?? 262_144} onChanged={load} />
          ))}
        </ul>
      ) : <p className="mt-3 text-sm text-gray-500">Verify a domain in this workspace to list hostnames for it.</p>)}
    </section>
  )
}
