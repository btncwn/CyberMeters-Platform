import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { MessageSquarePlus, Bug, Lightbulb, LifeBuoy, X } from 'lucide-react'

// ─────────────────────────────────────────────────────────────────────────────
// FeedbackWidget — lightweight beta feedback entry point.
//
// A floating button (bottom-right) that opens a small menu with three quick
// actions: Report a Bug, Suggest a Feature, Contact Support. Bug/Feature open a
// pre-filled email; Support routes to the in-app support page. Intentionally
// simple — the goal is to capture beta feedback with as little friction as
// possible without introducing new infrastructure.
// ─────────────────────────────────────────────────────────────────────────────

const SUPPORT_EMAIL = 'support@cybermeters.com'

function mailto(subject) {
  const body = encodeURIComponent(
    `\n\n— — — — — — — — — —\nPage: ${window.location.pathname}\nSent from CyberMeters Beta`
  )
  return `mailto:${SUPPORT_EMAIL}?subject=${encodeURIComponent(subject)}&body=${body}`
}

export default function FeedbackWidget() {
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    function handler(e) {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    function onKey(e) { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', handler)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', handler)
      document.removeEventListener('keydown', onKey)
    }
  }, [])

  const items = [
    { icon: Bug,       label: 'Report a bug',      hint: 'Something looks broken',  onClick: () => { window.location.href = mailto('[Bug] CyberMeters Beta') } },
    { icon: Lightbulb, label: 'Suggest a feature', hint: 'Share an idea',           onClick: () => { window.location.href = mailto('[Feature] CyberMeters Beta') } },
    { icon: LifeBuoy,  label: 'Contact support',   hint: 'Get help from our team',  onClick: () => { setOpen(false); navigate('/support') } },
  ]

  return (
    <div ref={ref} className="fixed bottom-5 right-5 z-[90] print:hidden">
      {open && (
        <div className="absolute bottom-14 right-0 w-64 bg-white rounded-2xl shadow-xl border border-gray-100 overflow-hidden animate-[fadeIn_120ms_ease-out]">
          <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100 bg-gray-50">
            <div>
              <p className="text-sm font-bold text-gray-900">Share feedback</p>
              <p className="text-[11px] text-gray-400">Help shape the beta</p>
            </div>
            <button
              onClick={() => setOpen(false)}
              className="w-6 h-6 rounded-lg text-gray-400 hover:text-gray-600 hover:bg-gray-100 flex items-center justify-center"
              aria-label="Close feedback menu"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="py-1">
            {items.map(({ icon: Icon, label, hint, onClick }) => (
              <button
                key={label}
                onClick={onClick}
                className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-brand-50 transition-colors group"
              >
                <div className="w-8 h-8 rounded-lg bg-gray-100 group-hover:bg-white flex items-center justify-center flex-shrink-0">
                  <Icon className="w-4 h-4 text-brand-600" />
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-semibold text-gray-800">{label}</p>
                  <p className="text-[11px] text-gray-400">{hint}</p>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      <button
        onClick={() => setOpen(o => !o)}
        className="inline-flex items-center gap-2 pl-3.5 pr-4 py-2.5 bg-brand-600 hover:bg-brand-700 active:bg-brand-800 text-white font-semibold text-sm rounded-full shadow-lg transition-all"
        aria-haspopup="menu"
        aria-expanded={open}
      >
        <MessageSquarePlus className="w-4 h-4" />
        Feedback
      </button>
    </div>
  )
}
