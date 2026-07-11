import { useNavigate } from 'react-router-dom'
import { LifeBuoy } from 'lucide-react'

// ─────────────────────────────────────────────────────────────────────────────
// Support entry point — a single floating "Contact support" button (bottom-right)
// that routes to the in-app support page. Deliberately one action: no bug/feature
// triage menu (that friction wasn't useful during the beta).
// ─────────────────────────────────────────────────────────────────────────────

export default function FeedbackWidget() {
  const navigate = useNavigate()
  return (
    <div className="fixed bottom-5 right-5 z-[90] print:hidden">
      <button
        onClick={() => navigate('/support')}
        className="inline-flex items-center gap-2 pl-3.5 pr-4 py-2.5 bg-brand-600 hover:bg-brand-700 active:bg-brand-800 text-white font-semibold text-sm rounded-full shadow-lg transition-all"
      >
        <LifeBuoy className="w-4 h-4" />
        Contact support
      </button>
    </div>
  )
}
