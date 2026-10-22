// NotificationPreferencesCard — how often CyberMeters emails about alerts for
// the selected workspace. Moved from the retired Settings page to the Account
// page's Notifications tab (founder, 17 Oct 2026); the channels themselves
// are configured per workspace under Alert channels.
import { useEffect, useState, useCallback } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'

function Status({ error, ok }) {
  if (error) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-red-50 border border-red-100 text-xs text-red-700">
        {error}
      </div>
    )
  }
  if (ok) {
    return (
      <div className="flex items-center gap-2 px-3 py-2 rounded-xl bg-brand-200 border border-brand-200 text-xs text-brand-900">
        Saved
      </div>
    )
  }
  return null
}

// These MUST stay in step with ALERT_EMAIL_FREQUENCIES in the Worker
// (engines/alert-gate.js) — the backend rejects anything outside that set, and the
// GET echoes the supported list so a drift here surfaces immediately.
//
// "Daily digest — One summary email per day. No immediate alerts." was removed:
// no daily digest sender has ever existed. The option was inert while preferences
// were ignored entirely; once they govern delivery, keeping it would either strand
// the customer in silence or make the label a lie. Do not re-add it without a real
// digest sender behind it.
const EMAIL_FREQUENCY_OPTIONS = [
  {
    value: 'all_alerts',
    label: 'All alerts',
    description: 'Email me about every alert for this workspace.',
  },
  {
    value: 'critical_only',
    label: 'Critical only',
    description: 'Email me only about critical alerts. Everything else stays in-app.',
  },
  {
    value: 'disabled',
    label: 'No alert emails',
    description: 'No alert emails. In-app notifications still appear.',
  },
]

export default function NotificationPreferencesCard() {
  const wsId = localStorage.getItem('cybermeters_workspace_id')
  const [freq, setFreq]       = useState('all_alerts')
  const [loading, setLoading] = useState(false)
  const [saving,  setSaving]  = useState(false)
  const [status,  setStatus]  = useState({})

  const load = useCallback(async () => {
    if (!wsId) return
    setLoading(true)
    try {
      const data = await api.getNotificationPreferences(wsId)
      setFreq(data.email_frequency || 'all_alerts')
    } catch { /* silent — use default */ }
    finally { setLoading(false) }
  }, [wsId])

  useEffect(() => { load() }, [load])

  async function handleSave() {
    if (!wsId || saving) return
    setSaving(true)
    setStatus({})
    try {
      await api.updateNotificationPreferences(wsId, { email_frequency: freq })
      setStatus({ ok: true })
      setTimeout(() => setStatus({}), 3000)
    } catch (e) {
      setStatus({ error: e.message || 'Failed to save' })
    } finally {
      setSaving(false)
    }
  }

  if (!wsId) {
    return (
      <div className="card p-6 space-y-4">
        <h2 className="text-sm font-bold text-gray-900">Notifications</h2>
        <p className="text-sm text-gray-400">Select a workspace to configure notification preferences.</p>
      </div>
    )
  }

  return (
    <div className="card p-6 space-y-4">
      <h2 className="text-sm font-bold text-gray-900">Notifications</h2>

      <p className="text-sm text-gray-600">
        Control how often CyberMeters emails you about alerts for this workspace.
        In-app notifications always appear on the globe regardless of this setting.
      </p>

      {loading ? (
        <div className="py-4 text-center">
          <div className="w-5 h-5 border-2 border-brand-700 border-t-transparent rounded-full animate-spin mx-auto" />
        </div>
      ) : (
        <div className="space-y-2">
          {EMAIL_FREQUENCY_OPTIONS.map(opt => (
            <label
              key={opt.value}
              className={`flex items-start gap-3 p-3 rounded-xl border cursor-pointer transition-colors ${
                freq === opt.value
                  ? 'border-brand-300 bg-brand-50/40'
                  : 'border-gray-100 hover:border-gray-200 hover:bg-gray-50/50'
              }`}
            >
              <input
                type="radio"
                name="email_frequency"
                value={opt.value}
                checked={freq === opt.value}
                onChange={() => setFreq(opt.value)}
                className="mt-0.5 accent-brand-700 shrink-0"
              />
              <div>
                <p className="text-sm font-semibold text-gray-800">{opt.label}</p>
                <p className="text-xs text-gray-400 mt-0.5">{opt.description}</p>
              </div>
            </label>
          ))}
        </div>
      )}

      <Status {...status} />

      <button
        type="button"
        onClick={handleSave}
        disabled={saving || loading}
        className="btn-primary disabled:opacity-50"
      >
        {saving ? 'Saving…' : 'Save notification setting'}
      </button>

      <p className="text-sm text-gray-600 pt-3 border-t border-gray-100">
        Where alerts go — email recipients, Slack and Teams channels — is set per workspace under{' '}
        <Link to="/ws/alerts" className="font-semibold text-brand-700 hover:text-brand-800">Alert channels</Link>.
      </p>
    </div>
  )
}

