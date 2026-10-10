import { useEffect, useState } from 'react'
import { api } from '../api'

export default function IdentityPublicSourcesCard({ workspaceId }) {
  const [data, setData] = useState(null)
  const [domainId, setDomainId] = useState('')
  const [sourceUrl, setSourceUrl] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  useEffect(() => {
    let active = true
    api.getIdentityPublicSources(workspaceId).then(value => {
      if (!active) return
      setData(value)
      const domain = value.domains?.[0]
      if (domain) { setDomainId(domain.id); setSourceUrl('https://' + domain.domain + '/') }
    }).catch(() => { if (active) setError('Public source checks are unavailable.') })
    return () => { active = false }
  }, [workspaceId])
  async function check(event) {
    event.preventDefault(); setError(''); setBusy(true)
    try {
      const value = await api.checkIdentityPublicSources(workspaceId, { domain_id: domainId, source_url: sourceUrl })
      setData(previous => ({ ...previous, checks: [value.check, ...(previous?.checks || [])].slice(0, 20) }))
    } catch (e) { setError(e.message || 'The check could not be completed.') }
    finally { setBusy(false) }
  }
  return <section className="card p-5 mb-6" aria-label="Public source secrets">
    <h2 className="text-sm font-semibold text-gray-900">Exposed keys in public web files</h2>
    <p className="text-sm text-gray-500 mt-1">Check a verified website for secret-key patterns. Evidence is masked; candidate keys are never used.</p>
    {error && <p role="alert" className="text-sm text-red-700 mt-3">{error}</p>}
    {data?.can_manage && data.domains?.length > 0 && <form onSubmit={check} className="flex flex-wrap items-end gap-3 my-4">
      <label className="text-xs text-gray-600">Verified domain
        <select aria-label="Verified domain for public source check" className="input-base block mt-1" value={domainId} disabled={busy} onChange={event => {
          setDomainId(event.target.value)
          setSourceUrl('https://' + data.domains.find(d => d.id === event.target.value).domain + '/')
        }}>{data.domains.map(d => <option key={d.id} value={d.id}>{d.domain}</option>)}</select>
      </label>
      <label className="text-xs text-gray-600 flex-1 min-w-[220px]">Public page or JavaScript URL
        <input type="url" required aria-label="Public source URL" className="input-base block w-full mt-1" value={sourceUrl} disabled={busy} onChange={event => setSourceUrl(event.target.value)} />
      </label>
      <button className="btn-primary text-sm" disabled={busy}>{busy ? 'Checking public files…' : 'Check public files'}</button>
    </form>}
    {data?.can_manage && data.domains?.length === 0 && <p className="text-sm text-gray-500 mt-3">Verify a domain to check its public files.</p>}
    {data?.checks?.slice(0, 5).map(check => <article key={check.id} className="border-t border-gray-100 py-4 mt-2">
      <p className="text-sm font-medium break-all">{check.result.source_url}</p>
      <p className="text-xs text-gray-500 mt-1">{new Date(check.created_at).toLocaleString()} · {check.result.coverage === 'partial' ? 'Partial check' : 'Bounded check'}</p>
      <p className="text-sm mt-2">{check.result.findings.length ? `${check.result.findings.length} key candidate(s) need review` : check.result.state === 'unavailable' ? 'Source could not be assessed' : 'No supported key pattern observed in the files checked'}</p>
      {check.result.findings.map((finding, index) => <div key={finding.fingerprint + ':' + index} className="mt-3 rounded-lg bg-amber-50 border border-amber-200 p-3 text-sm">
        <p className="font-semibold">{finding.label} — candidate</p>
        <p className="font-mono my-1">{finding.masked_evidence}</p>
        <p className="text-xs break-all">{finding.source_url} · line {finding.line}</p>
        <p className="mt-2">{finding.recommendation}</p>
        <p className="text-xs text-gray-600 mt-1">Key validity and account compromise have not been tested.</p>
      </div>)}
      <details className="mt-2 text-xs text-gray-500"><summary>Files checked</summary>
        <ul className="mt-2 space-y-1">{check.result.checked_sources.map((s, i) => <li key={i} className="break-all">{s.source_url}: {s.status}{s.http_status ? ` (HTTP ${s.http_status})` : ''}</li>)}</ul>
      </details>
    </article>)}
    <p className="text-xs text-gray-500 mt-3">{data?.scope_note || 'One public page and directly linked same-origin JavaScript. This is not employee breach monitoring.'}</p>
  </section>
}
