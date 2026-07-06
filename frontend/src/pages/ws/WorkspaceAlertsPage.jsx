/**
 * WorkspaceAlertsPage — /ws/alerts
 *
 * Alert channels: deliver the events that already trigger alert emails
 * (score drops, new critical findings, asset changes, certificate expiry)
 * to Slack, Microsoft Teams, or a signed generic webhook.
 *
 * Sections:
 *  1. Channel list — type, destination preview, delivery health, test/remove
 *  2. Add channel  — type selector with per-provider URL guidance
 *  3. Secret modal — generic-webhook signing secret, shown exactly once
 */

import { useState, useEffect, useCallback } from 'react'
import {
  Bell, Plus, Trash2, Send, CheckCircle, AlertTriangle, X, Copy, Check,
  MessageSquare, Webhook, RefreshCw, Info,
} from 'lucide-react'
import { useWorkspace } from '../../hooks/useWorkspace'
import { api } from '../../api'
import WsPage, { NoWorkspaceSelected } from '../../components/WsPage'

const CHANNEL_META = {
  slack: {
    label: 'Slack',
    icon: MessageSquare,
    hint: 'Paste an incoming-webhook URL from Slack (starts with https://hooks.slack.com/…).',
    placeholder: 'https://hooks.slack.com/services/…',
  },
  teams: {
    label: 'Microsoft Teams',
    icon: MessageSquare,
    hint: 'Paste a Teams incoming-webhook or Workflows URL (*.webhook.office.com or *.logic.azure.com).',
    placeholder: 'https://yourorg.webhook.office.com/…',
  },
  webhook: {
    label: 'Webhook (signed)',
    icon: Webhook,
    hint: 'Any public https endpoint. Every delivery is signed with HMAC-SHA256 (X-CyberMeters-Signature).',
    placeholder: 'https://api.yourservice.com/cybermeters',
  },
}

function DeliveryStatus({ channel }) {
  if (!channel.last_delivery_at) {
    return <span className="text-xs text-gray-400">No deliveries yet</span>
  }
  const ok = channel.last_delivery_status === 'ok'
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-medium ${ok ? 'text-brand-700' : 'text-red-600'}`}>
      {ok ? <CheckCircle className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
      {ok ? 'Delivering' : 'Last delivery failed'}
      {channel.failure_count > 1 && !ok && <span className="text-gray-400">({channel.failure_count} in a row)</span>}
    </span>
  )
}

function SecretModal({ secret, onClose }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try { await navigator.clipboard.writeText(secret); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* ignore */ }
  }
  return (
    <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-white rounded-xl shadow-xl max-w-lg w-full p-6" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-base font-bold text-gray-900">Your signing secret</h3>
            <p className="text-sm text-gray-500 mt-1">
              Shown once, never again. Use it to verify the <code className="text-xs bg-gray-100 px-1 rounded">X-CyberMeters-Signature</code> header
              (hex HMAC-SHA256 of the raw request body, prefixed <code className="text-xs bg-gray-100 px-1 rounded">sha256=</code>).
            </p>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600"><X className="w-5 h-5" /></button>
        </div>
        <div className="mt-4 flex items-center gap-2">
          <code className="flex-1 text-sm bg-gray-50 border border-gray-200 rounded-lg px-3 py-2 break-all">{secret}</code>
          <button onClick={copy} className="btn-secondary text-sm flex-shrink-0">
            {copied ? <Check className="w-4 h-4 text-brand-600" /> : <Copy className="w-4 h-4" />}
          </button>
        </div>
        <button onClick={onClose} className="btn-primary text-sm mt-5 w-full">I have stored it safely</button>
      </div>
    </div>
  )
}

export default function WorkspaceAlertsPage() {
  const { wsId, wsName } = useWorkspace()
  const [channels, setChannels] = useState(null)
  const [error, setError]       = useState(null)

  // add-form state
  const [adding, setAdding]     = useState(false)
  const [type, setType]         = useState('slack')
  const [urlValue, setUrlValue] = useState('')
  const [formError, setFormError] = useState(null)
  const [saving, setSaving]     = useState(false)
  const [newSecret, setNewSecret] = useState(null)

  // per-channel busy state: { [id]: 'testing' | 'deleting' } + test outcome
  const [busy, setBusy] = useState({})
  const [testResult, setTestResult] = useState({})

  const load = useCallback(async () => {
    if (!wsId) return
    try { const r = await api.getAlertChannels(wsId); setChannels(r?.channels || []); setError(null) }
    catch (e) { setError(e?.message || 'Could not load alert channels.'); setChannels([]) }
  }, [wsId])
  useEffect(() => { setChannels(null); load() }, [load])

  async function handleAdd(e) {
    e.preventDefault()
    setSaving(true); setFormError(null)
    try {
      const r = await api.createAlertChannel(wsId, type, urlValue.trim())
      if (r?.secret) setNewSecret(r.secret)
      setUrlValue(''); setAdding(false)
      await load()
    } catch (err) {
      setFormError(err?.message || 'Could not add the channel.')
    } finally { setSaving(false) }
  }

  async function handleTest(id) {
    setBusy((b) => ({ ...b, [id]: 'testing' }))
    try {
      const r = await api.testAlertChannel(wsId, id)
      setTestResult((t) => ({ ...t, [id]: r?.delivered ? 'ok' : 'failed' }))
    } catch { setTestResult((t) => ({ ...t, [id]: 'failed' })) }
    finally {
      setBusy((b) => ({ ...b, [id]: undefined }))
      await load()
    }
  }

  async function handleDelete(id) {
    if (!window.confirm('Remove this alert channel? Deliveries stop immediately.')) return
    setBusy((b) => ({ ...b, [id]: 'deleting' }))
    try { await api.deleteAlertChannel(wsId, id); await load() }
    catch (e) { setError(e?.message || 'Could not remove the channel.') }
    finally { setBusy((b) => ({ ...b, [id]: undefined })) }
  }

  if (!wsId) return <NoWorkspaceSelected />

  const meta = CHANNEL_META[type]

  return (
    <WsPage wsId={wsId} wsName={wsName}>
      {newSecret && <SecretModal secret={newSecret} onClose={() => setNewSecret(null)} />}

      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-900">Alert Channels</h1>
        <p className="text-sm text-gray-400 mt-0.5">
          Send scan, asset and certificate alerts to where your team already works.
        </p>
      </div>

      {/* What gets delivered */}
      <div className="card p-4 mb-6 flex items-start gap-3 bg-gray-50/60">
        <Info className="w-4 h-4 text-brand-600 flex-shrink-0 mt-0.5" />
        <p className="text-xs text-gray-500 leading-relaxed">
          Channels mirror the events that already trigger alert emails: security-score drops, new
          critical or high findings, asset changes, and certificate expiry warnings. Generic
          webhooks are signed so your receiver can verify each delivery came from CyberMeters.
        </p>
      </div>

      {error && (
        <div className="card p-4 mb-6 border-red-200 bg-red-50 text-sm text-red-700 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {error}
        </div>
      )}

      {/* Channel list */}
      <section className="card overflow-hidden mb-6">
        <div className="px-6 py-4 border-b border-gray-200 bg-gray-50/70 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-brand-600 flex items-center justify-center">
              <Bell className="w-4 h-4 text-white" />
            </div>
            <h2 className="section-title">Connected channels</h2>
          </div>
          {!adding && (
            <button onClick={() => setAdding(true)} className="btn-primary text-sm">
              <Plus className="w-4 h-4" /> Add channel
            </button>
          )}
        </div>

        {channels == null ? (
          <div className="p-6 text-sm text-gray-400 flex items-center gap-2">
            <RefreshCw className="w-4 h-4 animate-spin" /> Loading…
          </div>
        ) : channels.length === 0 && !adding ? (
          <div className="p-10 text-center">
            <Bell className="w-8 h-8 text-gray-300 mx-auto" />
            <p className="text-sm font-semibold text-gray-700 mt-3">No channels yet</p>
            <p className="text-xs text-gray-400 mt-1">Add Slack, Teams or a webhook to get alerts where your team works.</p>
          </div>
        ) : (
          <ul className="divide-y divide-gray-100">
            {channels.map((ch) => {
              const m = CHANNEL_META[ch.channel_type] || CHANNEL_META.webhook
              const Icon = m.icon
              return (
                <li key={ch.id} className="px-6 py-4 flex items-center gap-4">
                  <div className="w-9 h-9 rounded-lg bg-gray-100 flex items-center justify-center flex-shrink-0">
                    <Icon className="w-4.5 h-4.5 text-gray-600" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold text-gray-900">{m.label}</p>
                    <p className="text-xs text-gray-400 truncate">{ch.url_preview}</p>
                  </div>
                  <div className="hidden sm:block"><DeliveryStatus channel={ch} /></div>
                  {testResult[ch.id] && (
                    <span className={`text-xs font-semibold ${testResult[ch.id] === 'ok' ? 'text-brand-700' : 'text-red-600'}`}>
                      {testResult[ch.id] === 'ok' ? 'Test delivered ✓' : 'Test failed'}
                    </span>
                  )}
                  <button
                    onClick={() => handleTest(ch.id)}
                    disabled={Boolean(busy[ch.id])}
                    className="btn-secondary text-xs disabled:opacity-50"
                    title="Send a test alert"
                  >
                    {busy[ch.id] === 'testing'
                      ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      : <><Send className="w-3.5 h-3.5" /> Test</>}
                  </button>
                  <button
                    onClick={() => handleDelete(ch.id)}
                    disabled={Boolean(busy[ch.id])}
                    className="text-gray-300 hover:text-red-600 disabled:opacity-50"
                    title="Remove channel"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </li>
              )
            })}
          </ul>
        )}

        {/* Add form */}
        {adding && (
          <form onSubmit={handleAdd} className="px-6 py-5 border-t border-gray-100 bg-gray-50/40">
            <div className="flex flex-wrap gap-2 mb-3">
              {Object.entries(CHANNEL_META).map(([key, m]) => (
                <button
                  type="button"
                  key={key}
                  onClick={() => { setType(key); setFormError(null) }}
                  className={`px-3 py-1.5 rounded-lg text-sm font-semibold border transition-colors ${
                    type === key
                      ? 'bg-brand-600 text-white border-brand-600'
                      : 'bg-white text-gray-600 border-gray-200 hover:border-gray-300'
                  }`}
                >
                  {m.label}
                </button>
              ))}
            </div>
            <p className="text-xs text-gray-500 mb-2">{meta.hint}</p>
            <div className="flex gap-2">
              <input
                type="url"
                required
                value={urlValue}
                onChange={(e) => setUrlValue(e.target.value)}
                placeholder={meta.placeholder}
                className="input flex-1 text-sm"
              />
              <button type="submit" disabled={saving || !urlValue.trim()} className="btn-primary text-sm disabled:opacity-50">
                {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : 'Add'}
              </button>
              <button type="button" onClick={() => { setAdding(false); setFormError(null) }} className="btn-secondary text-sm">
                Cancel
              </button>
            </div>
            {formError && <p className="text-xs text-red-600 mt-2">{formError}</p>}
          </form>
        )}
      </section>
    </WsPage>
  )
}
