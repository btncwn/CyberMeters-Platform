import { Zap } from 'lucide-react'

// Renders only when the backend has offered one-click verification. The link is
// a full navigation to the DNS provider's own consent screen (built and signed
// server-side); the customer approves there and is sent back to CyberMeters,
// where the normal DNS check proves ownership.
export default function OneClickDnsButton({ offer, className = '' }) {
  if (!offer?.available || !offer.apply_url) return null
  const provider = offer.provider?.name || 'your DNS provider'
  return (
    <div className={`rounded-lg border border-brand-200 bg-brand-50 p-3.5 space-y-2 ${className}`}>
      <a
        href={offer.apply_url}
        className="btn-primary w-full justify-center py-2.5 text-sm"
        data-testid="one-click-dns"
      >
        <Zap className="w-4 h-4" />
        <span>Add the record automatically with {provider}</span>
      </a>
      <p className="text-xs text-brand-800 leading-relaxed">
        You&rsquo;ll sign in to {provider} and approve one TXT record. Nothing else in your DNS is changed.
        Prefer to do it yourself? The record is below.
      </p>
    </div>
  )
}
