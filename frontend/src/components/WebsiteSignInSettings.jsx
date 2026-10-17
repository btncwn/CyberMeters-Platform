import { useEffect, useId, useState } from 'react'
import { api } from '../api'
import { parseServerDate } from '../utils/dates'
import {
  PAUSED_REASON_TEXT, PROOF_TEXT, SIGN_IN_METHOD_LABEL, SIGNED_IN_PAGE_STATUS, sessionFacts, signInErrorText, signInOutcomeMeta,
  signedInCoverageText, signedInPageFacts,
} from '../lib/websiteSignInDisplay'
import { sensitiveLabel } from '../lib/websitePagesDisplay'

// "Signed-in scanning" — set up a test account per verified domain, test the
// sign-in now, and see the login health. The backend owns every outcome; the
// secret is write-only (never returned, never shown again).

function fmt(value) {
  const d = parseServerDate(value)
  return d && !Number.isNaN(d.getTime()) ? d.toLocaleString(undefined, { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : null
}

const TONE = { ok: 'bg-brand-200 text-brand-900', warn: 'bg-transparent text-brand-700', muted: 'bg-gray-100 text-gray-700' }

function OutcomePanel({ outcome, detail, when }) {
  const meta = signInOutcomeMeta(outcome)
  const facts = outcome === 'signed_in' ? sessionFacts(detail) : []
  return (
    <div className="mt-2 rounded-sm border border-gray-200 p-3 text-sm" role="status">
      <p className="flex flex-wrap items-center gap-2">
        <span className={`rounded-sm px-2 py-0.5 text-xs font-medium ${TONE[meta.tone]}`}>{meta.label}</span>
        {when && <span className="text-xs text-gray-500">{when}</span>}
      </p>
      {meta.help && <p className="mt-1 text-gray-700">{meta.help}</p>}
      {outcome === 'signed_in' && PROOF_TEXT[detail?.basis] && <p className="mt-1 text-xs text-gray-500">{PROOF_TEXT[detail.basis]}</p>}
      {facts.length > 0 && (
        <ul className="mt-2 flex flex-wrap gap-1.5" aria-label="Observed at sign-in">
          {facts.map((f) => <li key={f} className="rounded-sm border border-gray-200 px-2 py-0.5 text-xs text-gray-700">{f}</li>)}
        </ul>
      )}
    </div>
  )
}

function SignedInPages({ latest }) {
  const pages = latest?.outcome === 'signed_in' ? (latest.summary?.pages || []) : []
  return (
    <div className="mt-3">
      <h4 className="text-xs font-semibold uppercase tracking-wide text-gray-500">Signed-in pages</h4>
      <p className="text-xs text-gray-500 mb-1">{signedInCoverageText(latest)}{latest?.created_at && fmt(latest.created_at) ? ` (${fmt(latest.created_at)})` : ''}</p>
      {pages.length > 0 && (
        <ul className="divide-y divide-gray-100" aria-label="Signed-in pages checked">
          {pages.map((p) => {
            const facts = signedInPageFacts(p)
            const label = sensitiveLabel({ sensitive_kind: p.sensitive_kind, observation: { sensitive_basis: 'path' } })
            return (
              <li key={p.path} className="py-2 flex flex-col gap-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mono text-sm text-gray-900 break-all">{p.path}</span>
                  {label && <span className="text-xs rounded-sm px-2 py-0.5 bg-brand-50 text-brand-700">{label}</span>}
                  <span className="text-xs rounded-sm px-2 py-0.5 bg-gray-100 text-gray-700">{SIGNED_IN_PAGE_STATUS[p.outcome] || 'Unknown'}</span>
                </div>
                {facts.length > 0 && (
                  <ul className="flex flex-wrap gap-1.5" aria-label={`Observed on ${p.path}`}>
                    {facts.map((f) => <li key={f} className="text-xs rounded-sm border border-gray-200 px-2 py-0.5 text-gray-700">{f}</li>)}
                  </ul>
                )}
              </li>
            )
          })}
        </ul>
      )}
    </div>
  )
}

function Field({ label, hint, children, id }) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-sm font-medium text-gray-800">{label}</label>
      {children}
      {hint && <p className="text-xs text-gray-500">{hint}</p>}
    </div>
  )
}

export function SignInForm({ workspaceId, domain, profile, onSaved, onCancel }) {
  const uid = useId()
  const [method, setMethod] = useState(profile?.method || 'form')
  const [loginUrl, setLoginUrl] = useState(profile?.login_url || `https://${domain}/login`)
  const [startUrl, setStartUrl] = useState(profile?.start_url || '')
  const [signedInText, setSignedInText] = useState(profile?.signed_in_text || '')
  const [usernameField, setUsernameField] = useState(profile?.username_field || '')
  const [passwordField, setPasswordField] = useState(profile?.password_field || '')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [secretName, setSecretName] = useState(profile ? '' : 'Authorization')
  const [secretValue, setSecretValue] = useState('')
  const [attest, setAttest] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const keeping = profile && profile.method === method

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    const body = { method, start_url: startUrl.trim() || null, signed_in_text: signedInText.trim() || null, authorization_confirmed: attest }
    if (method === 'form') {
      Object.assign(body, { login_url: loginUrl.trim(), username_field: usernameField.trim() || null, password_field: passwordField.trim() || null })
      if (username || password) Object.assign(body, { username, password })
    } else if (secretValue) {
      if (method === 'header') Object.assign(body, { header_name: secretName.trim(), header_value: secretValue })
      else Object.assign(body, { cookie_name: secretName.trim(), cookie_value: secretValue })
    }
    try {
      const res = await api.saveWebsiteSignIn(workspaceId, domain, body)
      if (res.ok) { setPassword(''); setSecretValue(''); onSaved?.(res.body.profile) }
      else setError(signInErrorText(res))
    } catch {
      setError('That did not work. Try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} className="mt-3 flex flex-col gap-3 rounded-sm border border-gray-200 p-4" aria-label={`Sign-in details for ${domain}`}>
      <fieldset className="flex flex-col gap-1">
        <legend className="text-sm font-medium text-gray-800">How should CyberMeters sign in?</legend>
        {Object.entries(SIGN_IN_METHOD_LABEL).map(([value, label]) => (
          <label key={value} className="flex items-center gap-2 text-sm text-gray-700">
            <input type="radio" name={`${uid}-method`} value={value} checked={method === value}
              onChange={() => { setMethod(value); setSecretName(value === 'header' && !(profile && profile.method === value) ? 'Authorization' : ''); setSecretValue('') }} />
            {label}
          </label>
        ))}
      </fieldset>
      {method === 'form' && (
        <>
          <Field id={`${uid}-login`} label="Sign-in page" hint={`An https:// address on ${domain}.`}>
            <input id={`${uid}-login`} className="input" type="url" value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} required maxLength={2048} />
          </Field>
          <Field id={`${uid}-user`} label="Test account username or email">
            <input id={`${uid}-user`} className="input" value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="off"
              required={!keeping} maxLength={256} placeholder={keeping ? `Saved (${profile.credential_hint}) — leave blank to keep` : ''} />
          </Field>
          <Field id={`${uid}-pass`} label="Test account password">
            <input id={`${uid}-pass`} className="input" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password"
              required={!keeping} maxLength={512} placeholder={keeping ? 'Saved — leave blank to keep' : ''} />
          </Field>
        </>
      )}
      {method !== 'form' && (
        <>
          <Field id={`${uid}-name`} label={method === 'header' ? 'Header name' : 'Cookie name'}>
            <input id={`${uid}-name`} className="input" value={secretName} onChange={(e) => setSecretName(e.target.value)} autoComplete="off"
              required={!keeping} maxLength={128} placeholder={keeping ? `Saved (${profile.credential_hint}) — leave blank to keep` : ''} />
          </Field>
          <Field id={`${uid}-value`} label={method === 'header' ? 'Header value' : 'Cookie value'} hint="Stored encrypted and never shown again.">
            <input id={`${uid}-value`} className="input" type="password" value={secretValue} onChange={(e) => setSecretValue(e.target.value)} autoComplete="new-password"
              required={!keeping} maxLength={4096} placeholder={keeping ? 'Saved — leave blank to keep' : ''} />
          </Field>
        </>
      )}
      <Field id={`${uid}-start`} label={method === 'form' ? 'A page that needs sign-in (recommended)' : 'A page that needs sign-in'}
        hint="For example https://your-site/account. Used to confirm the sign-in worked.">
        <input id={`${uid}-start`} className="input" type="url" value={startUrl} onChange={(e) => setStartUrl(e.target.value)} required={method !== 'form'} maxLength={2048} />
      </Field>
      <Field id={`${uid}-text`} label="Text only a signed-in user sees (optional)" hint="For example the test account’s name. Makes the sign-in check certain.">
        <input id={`${uid}-text`} className="input" value={signedInText} onChange={(e) => setSignedInText(e.target.value)} maxLength={120} />
      </Field>
      {method === 'form' && (
        <details className="text-sm">
          <summary className="cursor-pointer text-gray-700">Advanced</summary>
          <div className="mt-2 grid gap-3 sm:grid-cols-2">
            <Field id={`${uid}-uf`} label="Username field name"><input id={`${uid}-uf`} className="input" value={usernameField} onChange={(e) => setUsernameField(e.target.value)} maxLength={100} /></Field>
            <Field id={`${uid}-pf`} label="Password field name"><input id={`${uid}-pf`} className="input" value={passwordField} onChange={(e) => setPasswordField(e.target.value)} maxLength={100} /></Field>
          </div>
        </details>
      )}
      <label className="flex items-start gap-2 text-sm text-gray-700">
        <input type="checkbox" className="mt-1" checked={attest} onChange={(e) => setAttest(e.target.checked)} />
        <span>This is a dedicated test account, and I am allowed to let CyberMeters sign in to {domain} with it.</span>
      </label>
      {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
      <div className="flex flex-wrap gap-2">
        <button type="submit" className="btn-primary" disabled={busy || !attest}>{busy ? 'Saving…' : 'Save'}</button>
        <button type="button" className="btn-secondary" onClick={onCancel} disabled={busy}>Cancel</button>
      </div>
    </form>
  )
}

export default function WebsiteSignInSettings({ workspaceId }) {
  const [data, setData] = useState(null)
  const [loadError, setLoadError] = useState(false)
  const [loading, setLoading] = useState(true)
  const [reload, setReload] = useState(0)
  const [editing, setEditing] = useState(null)
  const [busy, setBusy] = useState(null)
  const [results, setResults] = useState({})
  const [notes, setNotes] = useState({})

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setLoadError(false)
    Promise.resolve().then(() => api.getWebsiteSignIn(workspaceId))
      .then((res) => { if (!cancelled) setData(res) })
      .catch(() => { if (!cancelled) setLoadError(true) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [workspaceId, reload])

  async function test(domain) {
    setBusy(domain)
    setNotes((n) => ({ ...n, [domain]: null }))
    try {
      const res = await api.testWebsiteSignIn(workspaceId, domain)
      if (res.ok) setResults((r) => ({ ...r, [domain]: { outcome: res.body.outcome, detail: res.body.detail } }))
      else setNotes((n) => ({ ...n, [domain]: signInErrorText(res) }))
      setReload((x) => x + 1)
    } catch {
      setNotes((n) => ({ ...n, [domain]: 'That did not work. Try again.' }))
    } finally { setBusy(null) }
  }
  async function remove(domain) {
    setBusy(domain)
    try {
      const res = await api.deleteWebsiteSignIn(workspaceId, domain)
      if (!res.ok) setNotes((n) => ({ ...n, [domain]: signInErrorText(res) }))
      else { setResults((r) => ({ ...r, [domain]: null })); setNotes((n) => ({ ...n, [domain]: 'Removed. The stored sign-in details were deleted.' })) }
      setReload((x) => x + 1)
    } catch {
      setNotes((n) => ({ ...n, [domain]: 'That did not work. Try again.' }))
    } finally { setBusy(null) }
  }

  const domains = data?.domains || []
  return (
    <section className="card p-5 mb-6" aria-label="Signed-in scanning">
      <h2 className="section-title mb-1">Signed-in scanning</h2>
      <p className="text-sm text-gray-600 mb-3">
        Give CyberMeters a test account and it will also check pages behind your site’s sign-in — the pages your
        customers’ data lives on — with read-only requests.
      </p>
      {data?.scope_note && (
        <details className="mb-3 text-sm text-gray-600">
          <summary className="cursor-pointer font-medium">What CyberMeters does and never does</summary>
          <p className="mt-2 max-w-3xl leading-relaxed">{data.scope_note}</p>
        </details>
      )}
      {loading && !data && <p className="text-sm text-gray-500">Loading…</p>}
      {loadError && <p role="alert" className="text-sm text-red-700">Signed-in scanning settings could not be loaded.</p>}
      {data && !data.can_manage && <p className="text-sm text-gray-600">Only a workspace owner or admin can set this up.</p>}
      {data?.can_manage && data.reason === 'plan_required' && <p className="text-sm text-gray-600">Signed-in scanning needs an active paid plan or trial.</p>}
      {data?.can_manage && data.reason === 'vault_unavailable' && <p className="text-sm text-gray-600">Signed-in scanning is temporarily unavailable.</p>}
      {data && domains.length === 0 && <p className="text-sm text-gray-600">Verify a domain in this workspace to set up signed-in scanning.</p>}
      {domains.map((d) => {
        const p = d.profile
        const last = d.recent_attempts?.[0]
        const shown = results[d.domain] || (last ? { outcome: last.outcome, detail: last.detail, when: `${last.source === 'test' ? 'Test' : 'Scan'} · ${fmt(last.created_at) || ''}` } : null)
        return (
          <div key={d.domain_id} className="border-t border-gray-100 py-3 first:border-t-0">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-gray-900">{d.domain}</h3>
                <p className="text-xs text-gray-500">
                  {p ? `${p.method === 'form' ? 'Sign-in form' : p.method === 'header' ? 'Header' : 'Cookie'} · ${p.credential_hint} · ${p.status === 'paused' ? 'Paused' : 'On'}`
                    : 'Not set up'}
                  {p?.last_signed_in_at ? ` · last signed in ${fmt(p.last_signed_in_at)}` : ''}
                </p>
              </div>
              {data.can_use && (
                <div className="flex flex-wrap gap-2">
                  <button type="button" className="btn-secondary" onClick={() => setEditing(editing === d.domain ? null : d.domain)} disabled={busy === d.domain}>
                    {p ? 'Edit' : 'Set up'}
                  </button>
                  {p && <button type="button" className="btn-secondary" onClick={() => test(d.domain)} disabled={busy === d.domain}>{busy === d.domain ? 'Working…' : 'Test sign-in'}</button>}
                  {p && <button type="button" className="btn-secondary" onClick={() => remove(d.domain)} disabled={busy === d.domain}>Remove</button>}
                </div>
              )}
            </div>
            {p?.status === 'paused' && <p className="mt-2 text-sm text-brand-700">{PAUSED_REASON_TEXT[p.paused_reason] || 'Paused.'}</p>}
            {notes[d.domain] && <p className="mt-2 text-sm text-gray-700" role="status">{notes[d.domain]}</p>}
            {p && shown && <OutcomePanel outcome={shown.outcome} detail={shown.detail} when={shown.when} />}
            {p && <SignedInPages latest={d.latest_scan} />}
            {editing === d.domain && data.can_use && (
              <SignInForm workspaceId={workspaceId} domain={d.domain} profile={p}
                onCancel={() => setEditing(null)}
                onSaved={() => { setEditing(null); setNotes((n) => ({ ...n, [d.domain]: 'Saved. Use “Test sign-in” to check it now.' })); setReload((x) => x + 1) }} />
            )}
          </div>
        )
      })}
    </section>
  )
}
