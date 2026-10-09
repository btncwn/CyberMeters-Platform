import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'

const MAX_LOGO_BYTES = 512 * 1024
const HEX = /^#[0-9a-fA-F]{6}$/
const safeLogo = value => typeof value === 'string' && value.length <= 710000 && /^data:image\/(png|jpeg);base64,[A-Za-z0-9+/=]+$/.test(value) ? value : null
const errorText = error => error?.status === 403
  ? 'Your current access or plan does not allow this change. Refresh to check availability.'
  : error?.status === 400 ? 'Check the name, colour and image. Use a PNG or JPEG up to 512 KB, 16–4096 pixels per side and no more than 4 million pixels.'
    : 'The saved outcome could not be confirmed. Refresh before making another change.'

// Every read/write belongs to this mounted account or workspace. A lost write
// response locks further writes until a fresh authoritative read succeeds.
function useBranding(load) {
  const [state, setState] = useState({ data: null, loading: true, busy: false, error: '', notice: '', uncertain: false, revision: 0 })
  const current = useRef(null)
  const locked = useRef(false)
  const refresh = useCallback(async () => {
    if (locked.current) return
    current.current?.abort()
    const controller = new AbortController(); current.current = controller
    setState(s => ({ ...s, loading: true, error: '', notice: '' }))
    try {
      const data = await load(controller.signal)
      if (!controller.signal.aborted) setState(s => ({ ...s, data, loading: false, uncertain: false, revision: s.revision + 1 }))
    } catch {
      if (!controller.signal.aborted) setState(s => ({ ...s, data: null, loading: false, uncertain: true, error: 'Branding settings could not be loaded. Try again.' }))
    }
  }, [load])
  useEffect(() => { refresh(); return () => { current.current?.abort() } }, [refresh])
  const perform = async (operation, notice) => {
    if (locked.current || state.uncertain || state.loading) return false
    locked.current = true
    current.current?.abort()
    const controller = new AbortController(); current.current = controller
    setState(s => ({ ...s, busy: true, error: '', notice: '' }))
    try {
      await operation(controller.signal)
      if (controller.signal.aborted) return false
      const data = await load(controller.signal)
      if (controller.signal.aborted) return false
      setState(s => ({ ...s, data, busy: false, notice, uncertain: false, revision: s.revision + 1 }))
      return true
    } catch (error) {
      if (!controller.signal.aborted) setState(s => ({ ...s, busy: false, error: errorText(error), uncertain: true }))
      return false
    } finally { locked.current = false }
  }
  return { ...state, refresh, perform }
}

function Messages({ state }) {
  return <>
    {state.loading && <p className="text-sm text-gray-500" role="status">Loading branding settings…</p>}
    {state.error && <p className="text-sm text-red-700" role="alert">{state.error}</p>}
    {state.notice && <p className="text-sm text-brand-700" role="status">{state.notice}</p>}
    <button type="button" className="btn-secondary text-xs" disabled={state.busy || state.loading} onClick={state.refresh}>Refresh branding settings</button>
  </>
}

function LogoInput({ value, saved, hasSaved, onChange, disabled, onReading }) {
  const [error, setError] = useState('')
  const reading = useRef(null)
  useEffect(() => () => { if (reading.current?.readyState === 1) reading.current.abort() }, [])
  function choose(event) {
    const file = event.target.files?.[0]; event.target.value = ''; setError('')
    if (reading.current?.readyState === 1) reading.current.abort()
    onReading(false)
    if (!file) return
    if (!['image/png', 'image/jpeg'].includes(file.type) || file.size > MAX_LOGO_BYTES || !file.size) {
      setError('Use a PNG or JPEG up to 512 KB.'); return
    }
    const reader = new FileReader(); reading.current = reader; onReading(true)
    reader.onload = () => {
      if (reading.current !== reader) return
      onReading(false)
      const uri = safeLogo(reader.result)
      if (uri) onChange(uri)
      else setError('This image could not be read. Choose a PNG or JPEG.')
    }
    reader.onerror = () => { if (reading.current === reader) { onReading(false); setError('This image could not be read.') } }
    reader.readAsDataURL(file)
  }
  const image = value === undefined ? safeLogo(saved) : safeLogo(value)
  return <div className="space-y-2">
    <label className="label block">Logo <input aria-label="Logo image" className="block mt-2 max-w-full text-xs" type="file" accept="image/png,image/jpeg" disabled={disabled} onChange={choose} /></label>
    <p className="text-xs text-gray-500">PNG or JPEG · up to 512 KB · 16–4096 pixels per side · up to 4 million pixels.</p>
    {image ? <img src={image} alt="Report logo preview" className="h-20 max-w-full max-h-20 object-contain rounded border border-gray-200 p-2" /> : hasSaved && value === undefined ? <p className="text-xs text-gray-500">Saved logo; preview is unavailable.</p> : null}
    {value !== undefined && <button type="button" className="text-xs text-gray-600 underline" disabled={disabled} onClick={() => { setError(''); onChange(undefined) }}>Discard logo change</button>}
    {error && <p role="alert" className="text-sm text-red-700">{error}</p>}
  </div>
}

function ProfileEditor({ profile, logo, disabled, onSave, onCancel }) {
  const [name, setName] = useState(profile?.name || '')
  const [accent, setAccent] = useState(profile?.accent || '')
  const [draftLogo, setLogo] = useState(undefined)
  const [reading, setReading] = useState(false)
  const [isDefault, setDefault] = useState(!!profile?.is_default)
  return <form className="space-y-4 border-t border-gray-200 pt-4" onSubmit={event => {
    event.preventDefault()
    if (disabled || reading || !name.trim() || (accent && !HEX.test(accent))) return
    onSave({ name: name.trim(), accent: accent || null, mode: 'white_label', is_default: isDefault, ...(draftLogo !== undefined ? { logo: draftLogo } : {}) })
  }}>
    <h3 className="font-semibold text-sm">{profile ? 'Edit agency profile' : 'New agency profile'}</h3>
    <label className="label block">Agency name<input className="input mt-1" value={name} onChange={e => setName(e.target.value)} maxLength={120} disabled={disabled} required /></label>
    <label className="label block">Accent colour<input className="input mt-1 max-w-xs" placeholder="#00876A" value={accent} onChange={e => setAccent(e.target.value)} maxLength={7} disabled={disabled} pattern="#[0-9a-fA-F]{6}" /></label>
    <LogoInput value={draftLogo} saved={logo} hasSaved={!!profile?.logo_sha256} onChange={setLogo} disabled={disabled || reading} onReading={setReading} />
    {(profile?.logo_sha256 || draftLogo) && draftLogo !== null && <button type="button" className="text-xs text-red-700 underline" disabled={disabled || reading} onClick={() => setLogo(null)}>Remove logo on save</button>}
    {draftLogo === null && <p className="text-xs text-gray-500">Logo will be removed when you save.</p>}
    <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={isDefault} onChange={e => setDefault(e.target.checked)} disabled={disabled} />Use as my default agency profile</label>
    <div className="flex flex-wrap gap-2"><button className="btn-primary" type="submit" disabled={disabled || reading || !name.trim() || (!!accent && !HEX.test(accent))}>Save agency profile</button><button className="btn-secondary" type="button" disabled={disabled} onClick={onCancel}>Cancel</button></div>
  </form>
}

export function AgencyReportBranding({ accountId }) {
  return <AgencyBranding key={accountId || 'current-session'} />
}
function AgencyBranding() {
  const load = useCallback(signal => api.getBrandingProfiles({ signal }), [])
  const state = useBranding(load)
  const [editor, setEditor] = useState(null)
  const [detailLoading, setDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState('')
  const [deleting, setDeleting] = useState(null)
  const detailRequest = useRef(null)
  useEffect(() => () => detailRequest.current?.abort(), [])
  useEffect(() => { detailRequest.current?.abort(); setDetailLoading(false); setEditor(null); setDeleting(null) }, [state.revision])
  const available = state.data?.white_label_available === true
  const disabled = state.busy || state.loading || state.uncertain || detailLoading
  async function edit(profile) {
    if (disabled || !available) return
    detailRequest.current?.abort(); const controller = new AbortController(); detailRequest.current = controller
    setDetailLoading(true); setDetailError(''); setEditor(null); setDeleting(null)
    try {
      const data = await api.getBrandingProfile(profile.id, { signal: controller.signal })
      if (!controller.signal.aborted) {
        if (data.white_label_available === true && data.profile?.id === profile.id) setEditor({ profile: data.profile, logo: data.logo_data_uri })
        else setDetailError('This profile cannot currently be edited. Refresh branding settings.')
      }
    } catch { if (!controller.signal.aborted) setDetailError('This profile could not be loaded. Try again.') }
    finally { if (!controller.signal.aborted) setDetailLoading(false) }
  }
  return <section className="card p-5 sm:p-6 space-y-4 lg:col-span-2 min-w-0" aria-label="Agency report branding">
    <h2 className="text-sm font-bold text-gray-900">Agency report branding</h2>
    <p className="text-sm text-gray-600">Use your agency name, logo and colour on new reports for workspaces you own. A client logo set on a workspace takes precedence over the agency logo. Reports retain “Powered by CyberMeters”.</p>
    <p className="text-xs text-gray-500">Already saved PDF branding stays unchanged. Newly generated workspace summaries use the current settings. With no default profile, your most recently updated agency profile is used.</p>
    <Messages state={state} />
    {state.data && <>
      {!available && <p className="text-sm text-gray-600">Agency profiles require the Business plan or an eligible trial. Saved profiles stay retained; you can remove them. <Link to="/billing" className="text-brand-700 underline">View billing</Link></p>}
      {(state.data.profiles || []).length === 0 && <p className="text-sm text-gray-500">No agency profiles saved.</p>}
      <ul className="space-y-3">{(state.data.profiles || []).map(profile => <li key={profile.id} className="rounded-xl border border-gray-200 p-3 space-y-2">
        <div className="flex flex-wrap gap-2 items-center"><strong className="text-sm break-all">{profile.name}</strong>{profile.mode === 'white_label' && !!profile.is_default && <span className="text-xs text-brand-700">Default</span>}<span className="text-xs text-gray-500">{profile.logo_sha256 ? 'Logo saved' : 'Text branding'}{profile.accent ? ` · ${profile.accent}` : ''}</span></div>
        {profile.mode !== 'white_label' && <p className="text-xs text-gray-500">Legacy co-brand profile. Edit and save as an agency profile to use it for agency reports.</p>}
        <div className="flex flex-wrap gap-2">{available && <><button type="button" className="btn-secondary text-xs" disabled={disabled} onClick={() => edit(profile)}>Edit {profile.name}</button>{profile.mode === 'white_label' && !profile.is_default && <button type="button" className="btn-secondary text-xs" disabled={disabled} onClick={() => state.perform(signal => api.updateBrandingProfile(profile.id, { is_default: true }, { signal }), 'Default agency profile saved.')}>Make {profile.name} default</button>}</>}
          <button type="button" className="text-xs text-red-700 underline" disabled={disabled} onClick={() => { setEditor(null); setDeleting(profile) }}>Delete {profile.name}</button>
        </div>
      </li>)}</ul>
      {deleting && <div className="rounded-xl border border-amber-200 p-3 space-y-2"><p className="text-sm">Delete “{deleting.name}”? New reports will use the next available branding. Saved PDF branding is retained.</p><div className="flex flex-wrap gap-2"><button type="button" className="btn-secondary" disabled={disabled} onClick={() => state.perform(signal => api.deleteBrandingProfile(deleting.id, { signal }), 'Agency profile deleted.')}>Confirm profile deletion</button><button className="btn-secondary" disabled={disabled} type="button" onClick={() => setDeleting(null)}>Cancel deletion</button></div></div>}
      {available && !editor && <button type="button" className="btn-primary" disabled={disabled} onClick={() => { setDetailError(''); setDeleting(null); setEditor({ profile: null, logo: null }) }}>Add agency profile</button>}
      {detailLoading && <p role="status" className="text-sm text-gray-500">Loading agency profile…</p>}
      {detailError && <p role="alert" className="text-sm text-red-700">{detailError}</p>}
      {editor && available && <ProfileEditor key={editor.profile?.id || 'new'} {...editor} disabled={disabled} onCancel={() => setEditor(null)} onSave={body => state.perform(signal => editor.profile ? api.updateBrandingProfile(editor.profile.id, body, { signal }) : api.createBrandingProfile(body, { signal }), 'Agency profile saved.')} />}
    </>}
  </section>
}

export function WorkspaceReportBranding({ workspaceId }) {
  return workspaceId ? <WorkspaceBranding key={workspaceId} workspaceId={workspaceId} /> : null
}
function WorkspaceBranding({ workspaceId }) {
  const load = useCallback(async signal => {
    const data = await api.getWorkspaceBranding(workspaceId, { signal })
    if (data.has_logo) {
      try { const image = await api.getWorkspaceBrandingLogo(workspaceId, { signal }); data.logo_data_uri = image.logo_data_uri } catch (error) { if (signal.aborted) throw error }
    }
    return data
  }, [workspaceId])
  const state = useBranding(load)
  return <section className="card p-5 sm:p-6 space-y-4 min-w-0" aria-label="Client report branding">
    <h2 className="text-sm font-bold text-gray-900">Client report branding</h2>
    <p className="text-sm text-gray-600">Set this client’s report name and logo. A workspace logo overrides the agency logo; without a client logo, an eligible agency profile also supplies the report name. Agency colours apply when the workspace owner has an eligible profile. Reports retain CyberMeters attribution.</p>
    <p className="text-xs text-gray-500">Changes apply to new branding selections, not saved PDF branding. Newly generated workspace summaries use the current settings.</p>
    <Messages state={state} />
    {state.data && <>
      <p className="text-sm text-gray-600">Current report identity: <strong>{state.data.effective_display_name || 'CyberMeters'}</strong> · {state.data.effective_mode === 'white_label' ? 'Agency branding' : state.data.effective_mode === 'co_brand' ? 'Client and CyberMeters branding' : state.data.effective_mode === 'cybermeters' ? 'CyberMeters branding' : 'Branding mode unavailable'}</p>
      {state.data.can_manage === true ? <WorkspaceBrandingForm key={state.revision} data={state.data} disabled={state.busy || state.loading || state.uncertain} onSave={body => state.perform(signal => body.logo ? api.updateWorkspaceBrandingLogo(workspaceId, body, { signal }) : api.updateWorkspaceBranding(workspaceId, body, { signal }), 'Client report branding saved.')} onRemove={() => state.perform(signal => api.deleteWorkspaceBrandingLogo(workspaceId, { signal }), 'Client logo removed; saved PDF branding is retained.')} /> : <p className="text-sm text-gray-500">A workspace manager can change this client’s branding.</p>}
    </>}
  </section>
}
function WorkspaceBrandingForm({ data, disabled, onSave, onRemove }) {
  const [name, setName] = useState(data.display_name ?? data.logo?.display_name ?? '')
  const [logo, setLogo] = useState(undefined)
  const [reading, setReading] = useState(false)
  return <form className="space-y-4" onSubmit={event => { event.preventDefault(); if (!disabled && !reading) onSave({ display_name: name.trim(), ...(logo ? { logo } : {}) }) }}>
    <label className="label block">Client report name<input className="input mt-1" value={name} maxLength={120} disabled={disabled} onChange={e => setName(e.target.value)} placeholder="Client name" /></label>
    <LogoInput value={logo} saved={data.logo_data_uri} hasSaved={data.has_logo} onChange={setLogo} disabled={disabled || reading} onReading={setReading} />
    <div className="flex flex-wrap gap-2"><button className="btn-primary" type="submit" disabled={disabled || reading}>Save client branding</button>{data.has_logo && <button type="button" className="btn-secondary" disabled={disabled || reading} onClick={onRemove}>Remove client logo</button>}</div>
  </form>
}
