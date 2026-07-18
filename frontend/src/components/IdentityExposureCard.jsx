import { useState, useEffect } from 'react'
import { Fingerprint, Mail, Users, KeyRound } from 'lucide-react'
import { api } from '../api'

// Consolidated Identity Exposure — "how can an attacker impersonate, steal, or
// abuse your identity?". Explanation-first: the plain-English verdict leads, the
// three real signals (email spoofing, impersonation infrastructure, exposed
// login surfaces) support it. Renders nothing until loaded.

const LEVEL = {
  Low:    { text: 'text-green-700', bg: 'bg-green-50',  ring: 'border-green-200' },
  Medium: { text: 'text-amber-700', bg: 'bg-amber-50',  ring: 'border-amber-200' },
  High:   { text: 'text-red-700',   bg: 'bg-red-50',    ring: 'border-red-200' },
}

function Signal({ icon: Icon, label, value, sub }) {
  return (
    <div className="rounded-xl border border-gray-100 bg-white p-3">
      <div className="flex items-center gap-1.5 text-gray-400 mb-1.5">
        <Icon className="w-3.5 h-3.5" />
        <span className="text-[11px] font-medium uppercase tracking-wide">{label}</span>
      </div>
      <p className="text-sm font-semibold text-gray-900 leading-snug">{value}</p>
      {sub && <p className="text-xs text-gray-400 mt-0.5">{sub}</p>}
    </div>
  )
}

export default function IdentityExposureCard({ workspaceId }) {
  const [data, setData] = useState(null)

  useEffect(() => {
    let cancelled = false
    if (!workspaceId) return
    api.getIdentityExposure(workspaceId)
      .then((d) => { if (!cancelled) setData(d) })
      .catch(() => { if (!cancelled) setData({ error: true }) })
    return () => { cancelled = true }
  }, [workspaceId])

  if (!data || data.error) return null

  // M5.e: an unrecognised exposure level is UNKNOWN (neutral), never green Low.
  const lvl = LEVEL[data.identity_exposure_level] ?? { label: 'Unknown', cls: 'bg-gray-100 text-gray-600 border-gray-200', tone: 'unknown' }
  const s = data.signals || {}
  const email = s.email_spoofing || {}
  const imp = s.impersonation_infrastructure || {}
  const login = s.exposed_login_surfaces || {}
  // B: when the overall verdict is Unavailable / Not Assessed (a source failed or
  // nothing was assessed), the sub-tiles must NOT read "None active" / "None exposed"
  // / "Protected" off zero counts. Real detections still surface (findings never hidden).
  const notObserved = !['Low', 'Medium', 'High'].includes(data.identity_exposure_level)

  return (
    <div className={`card p-5 border ${lvl.ring}`}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2">
          <Fingerprint className="w-4.5 h-4.5 text-brand-600" strokeWidth={2.2} />
          <h2 className="text-sm font-semibold text-gray-900">Identity Exposure</h2>
        </div>
        <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${lvl.bg} ${lvl.text}`}>{data.identity_exposure_level}</span>
      </div>

      <p className="text-sm text-gray-600 leading-relaxed mb-4">{data.summary}</p>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Signal
          icon={Mail}
          label="Email spoofing"
          value={email.spoofable_domains > 0 ? `${email.spoofable_domains} of ${email.checked_domains} spoofable` : notObserved ? '—' : email.checked_domains ? 'Protected' : '—'}
          sub={email.spoofable_domains > 0 ? 'Attackers can send email as you' : notObserved ? 'Could not assess' : email.checked_domains ? 'SPF & DMARC in place' : 'No scan data yet'}
        />
        <Signal
          icon={Users}
          label="Impersonation"
          value={imp.active > 0 ? `${imp.active} active lookalike${imp.active === 1 ? '' : 's'}` : notObserved ? '—' : 'None active'}
          sub={imp.can_send_mail > 0 ? `${imp.can_send_mail} can send mail as you` : imp.active > 0 ? 'Resolving lookalike domains' : notObserved ? 'Could not assess' : 'No live impersonation'}
        />
        <Signal
          icon={KeyRound}
          label="Login surfaces"
          value={login.internet_facing > 0 ? `${login.internet_facing} internet-facing` : notObserved ? '—' : 'None exposed'}
          sub={login.internet_facing > 0 ? 'Where credentials are attacked' : notObserved ? 'Could not assess' : 'No exposed login portals'}
        />
      </div>
    </div>
  )
}
