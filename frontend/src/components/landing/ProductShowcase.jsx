import { SERVICE_COLORS } from '../../theme/serviceColors'
import ProductFrame from './ProductFrame'

// A sample of the workspace a customer sees after a check, drawn with the
// product's own vocabulary: coverage states, no score, no live data. The rows
// come from the landing page so its copy stays in one place.
export const TONE = {
  issue: 'bg-[#FFF1D6] text-[#8A5300]',
  ok: 'bg-[#DDF3E7] text-[#11643D]',
  gap: 'bg-[#E9ECF2] text-[#465066]',
  input: 'bg-[#E6E8FD] text-[#3D45A8]',
}

// The app's sidebar order (canonical presentation order).
const NAV_ORDER = ['identity', 'surface', 'email', 'website', 'shadow_it', 'certs', 'brand', 'cyber_essentials']

const NOTES = [
  { title: 'What was observed', copy: 'Every area gets a plain state from public evidence, with the date it was seen.' },
  { title: 'What could not be checked', copy: 'Gaps are named as gaps. Missing evidence is never shown as healthy.' },
  { title: 'What to do next', copy: 'The first thing to fix comes with who usually does it and how CyberMeters checks it again.' },
]

export default function ProductShowcase({ rows }) {
  return (
    <>
      <ProductFrame
        label="Sample report layout"
        path="/dashboard"
        className="mt-14"
        caption="Sample layout to show how results read, not a live result. Each area says what was observed, what could not be assessed and what needs your input."
      >
        <div className="grid grid-cols-1 lg:grid-cols-[230px_minmax(0,1fr)_330px] bg-[#F4F6FA]">
          {/* Workspace navigation, as in the app */}
          <nav aria-label="Sample workspace areas" className="hidden lg:block bg-white border-r border-[#E6EAF3] py-5 px-3">
            <p className="px-3 text-[17px] font-bold text-[#121A2E]">example.co.uk</p>
            <ul className="mt-4 space-y-1">
              {NAV_ORDER.map(key => rows.find(r => r.key === key)).filter(Boolean).map(r => {
                const c = SERVICE_COLORS[r.key]
                const active = r.key === 'email'
                return (
                  <li
                    key={r.key}
                    className="px-3 py-2 rounded-lg border-l-[3px] text-[15px] leading-snug"
                    style={active ? { background: c.chip, borderLeftColor: c.icon, color: c.text, fontWeight: 600 } : { borderLeftColor: 'transparent', color: '#46506A' }}
                  >
                    {r.name}
                  </li>
                )
              })}
            </ul>
          </nav>

          {/* Area states */}
          <div className="p-5 sm:p-6 min-w-0">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="font-cm text-[22px] leading-tight text-[#121A2E]">Sample report</p>
                <p className="text-[14px] text-[#626B80] mt-1">example.co.uk · External security check</p>
              </div>
              <span className="text-[14px] font-semibold text-[#3D45A8] bg-[#E6E8FD] rounded-full px-3 py-1">Sample</span>
            </div>
            <ul className="mt-5 rounded-xl bg-white border border-[#E6EAF3]">
              {rows.map(r => {
                const c = SERVICE_COLORS[r.key]
                return (
                  <li key={r.name} className="flex items-start sm:items-center gap-4 px-4 sm:px-5 py-3.5 border-b border-[#EEF1F7] last:border-b-0">
                    <span className="mt-1.5 sm:mt-0 w-2.5 h-2.5 rounded-full shrink-0" style={{ background: c.icon }} aria-hidden="true" />
                    <div className="flex-1 min-w-0 flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
                      <div className="flex-1 min-w-0">
                        <p className="text-[15px] font-semibold text-[#121A2E]">{r.name}</p>
                        <p className="text-[14px] text-[#626B80]">{r.note}</p>
                      </div>
                      <span className={`self-start sm:self-auto text-[14px] font-semibold rounded-full px-3 py-1 whitespace-nowrap ${TONE[r.tone]}`}>{r.state}</span>
                    </div>
                  </li>
                )
              })}
            </ul>
          </div>

          {/* First action */}
          <div className="p-5 sm:p-6 lg:pl-0 min-w-0">
            <p className="text-[15px] font-semibold text-[#121A2E]">Needs attention first</p>
            <div className="mt-3 rounded-xl bg-white border border-[#E6EAF3] p-5">
              <p className="text-[14px]" style={{ color: SERVICE_COLORS.email.text }}>Email Protection</p>
              <p className="font-cm text-[22px] leading-tight text-[#121A2E] mt-1">Strengthen DMARC enforcement</p>
              <dl className="mt-4 grid grid-cols-2 gap-3 text-[14px]">
                <div><dt className="text-[#626B80]">Severity</dt><dd className="font-semibold text-[#8A5300]">Medium</dd></div>
                <div><dt className="text-[#626B80]">Usually done by</dt><dd className="font-semibold text-[#121A2E]">Your IT provider</dd></div>
              </dl>
              <p className="mt-4 text-[14px] leading-[1.55] text-[#46506A]">
                Confirm legitimate senders pass, then move the policy towards quarantine or reject.
              </p>
              <p className="mt-3 text-[14px] leading-[1.55] text-[#46506A]">
                Checked again by CyberMeters from public DNS after the change.
              </p>
            </div>
          </div>
        </div>
      </ProductFrame>

      <ul className="mt-12 grid grid-cols-1 md:grid-cols-3 gap-8 lg:gap-12">
        {NOTES.map(n => (
          <li key={n.title} className="border-t border-[#C9D1E4] pt-5">
            <p className="font-cm text-[26px] leading-[1.15] text-[#121A2E]">{n.title}</p>
            <p className="mt-2 text-[17px] leading-[1.6] text-[#46506A]">{n.copy}</p>
          </li>
        ))}
      </ul>
    </>
  )
}
