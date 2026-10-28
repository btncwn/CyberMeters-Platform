import { useRef, useState } from 'react'
import { SERVICE_COLORS } from '../../theme/serviceColors'
import ProductFrame from './ProductFrame'

// One sample finding followed from the first observation to the recheck. The
// remediation wording follows the canonical registry entry (email.dmarc.enforce):
// CyberMeters explains and re-observes; it never applies the DNS change itself.
const EMAIL = SERVICE_COLORS.email

const STEPS = [
  {
    id: 'discover',
    tab: 'Discover',
    summary: 'What CyberMeters saw',
    copy: 'CyberMeters reads your public DNS. In this example, the DMARC record is set to monitor only (p=none), so receivers are not asked to quarantine or reject email that fails DMARC.',
    path: '/ws/email-protection',
  },
  {
    id: 'understand',
    tab: 'Understand',
    summary: 'The evidence behind it',
    copy: 'The finding shows the record it came from and when it was seen. Anything that could not be checked from outside is listed as not assessed, not as a pass.',
    path: '/ws/email-protection',
  },
  {
    id: 'prioritise',
    tab: 'Prioritise',
    summary: 'Why it matters and what to do',
    copy: 'Each finding explains the business impact, the recommended change and who usually makes it. You can assign it to an owner and track it as a case.',
    path: '/ws/cases',
  },
  {
    id: 'recheck',
    tab: 'Recheck',
    summary: 'How you know it is fixed',
    copy: 'After your email provider updates the record, CyberMeters checks the public DNS again and marks the case verified only when it sees the new policy itself. If the issue comes back, the case reopens.',
    path: '/ws/cases',
  },
]

function Badge({ tone, children }) {
  const cls = {
    issue: 'bg-[#FFF1D6] text-[#8A5300]',
    gap: 'bg-[#E9ECF2] text-[#465066]',
    wait: 'bg-[#FFF1D6] text-[#8A5300]',
    ok: 'bg-[#DDF3E7] text-[#11643D]',
    info: 'bg-[#E6E8FD] text-[#3D45A8]',
  }[tone]
  return <span className={`inline-block text-[14px] font-semibold rounded-full px-3 py-1 whitespace-nowrap ${cls}`}>{children}</span>
}

function Row({ label, children }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-[170px_minmax(0,1fr)] gap-1 sm:gap-4 px-5 py-3.5 border-b border-[#EEF1F7] last:border-b-0">
      <dt className="text-[14px] text-[#626B80]">{label}</dt>
      <dd className="text-[15px] text-[#121A2E] min-w-0 wrap-break-word">{children}</dd>
    </div>
  )
}

function ScreenHeader({ title, state, tone }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 px-5 pt-5">
      <div className="min-w-0">
        <p className="text-[14px]" style={{ color: EMAIL.text }}>Email Protection · example.co.uk</p>
        <p className="font-cm text-[22px] leading-tight text-[#121A2E] mt-1">{title}</p>
      </div>
      {state && <Badge tone={tone}>{state}</Badge>}
    </div>
  )
}

function DiscoverScreen() {
  return (
    <div className="pb-2">
      <ScreenHeader title="DMARC policy is monitoring only" state="Issue detected" tone="issue" />
      <dl className="mt-4 mx-5 mb-4 rounded-xl border border-[#E6EAF3]">
        <Row label="Record">TXT at <span className="mono">_dmarc.example.co.uk</span></Row>
        <Row label="Published value"><span className="mono">v=DMARC1; p=none; rua=mailto:dmarc@example.co.uk</span></Row>
        <Row label="Requested policy">None (report only)</Row>
        <Row label="Observed">12 Oct 2026, 09:14 UTC</Row>
      </dl>
    </div>
  )
}

function UnderstandScreen() {
  return (
    <div className="pb-2">
      <ScreenHeader title="Evidence and coverage" />
      <ul className="mt-4 mx-5 mb-4 rounded-xl border border-[#E6EAF3]">
        {[
          ['DMARC record', 'Found, one valid record', 'issue', 'Policy: none'],
          ['SPF record', 'One record found; full SPF evaluation not shown', 'info', 'Record observed'],
          ['DKIM public keys', 'No selector evidence in this example', 'gap', 'Not assessed'],
          ['Aggregate reporting', 'Reporting address published; receipt not shown', 'info', 'Address published'],
        ].map(([name, note, tone, state]) => (
          <li key={name} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3.5 border-b border-[#EEF1F7] last:border-b-0">
            <div className="flex-1 min-w-[180px]">
              <p className="text-[15px] font-semibold text-[#121A2E]">{name}</p>
              <p className="text-[14px] text-[#626B80]">{note}</p>
            </div>
            <Badge tone={tone}>{state}</Badge>
          </li>
        ))}
      </ul>
    </div>
  )
}

function PrioritiseScreen() {
  return (
    <div className="pb-2">
      <ScreenHeader title="Strengthen DMARC enforcement" state="Assigned" tone="info" />
      <dl className="mt-4 mx-5 mb-4 rounded-xl border border-[#E6EAF3]">
        <Row label="Severity"><span className="font-semibold text-[#8A5300]">Medium</span></Row>
        <Row label="Why it matters">A no-action policy asks for reports, but does not ask receivers to quarantine or reject email that fails DMARC.</Row>
        <Row label="Recommended action">Confirm legitimate senders pass, then ask your DNS or email administrator to move the policy towards quarantine or reject. Your administrator publishes this policy change.</Row>
        <Row label="Owner">Your IT provider</Row>
        <Row label="Effort">Medium</Row>
      </dl>
    </div>
  )
}

function RecheckScreen() {
  return (
    <div className="pb-2">
      <ScreenHeader title="Strengthen DMARC enforcement" state="Verified by CyberMeters" tone="ok" />
      <ol className="mt-4 mx-5 mb-4 rounded-xl border border-[#E6EAF3]">
        {[
          ['14 Oct, 10:02', 'Owner recorded the change', 'Awaiting verification', 'wait'],
          ['14 Oct, 11:30', 'A complete later DNS recheck observed the requested policy', 'p=quarantine observed', 'info'],
          ['14 Oct, 11:30', 'Published-policy change verified from CyberMeters’ own observation', 'Verified by CyberMeters', 'ok'],
        ].map(([when, what, state, tone]) => (
          <li key={what} className="flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3.5 border-b border-[#EEF1F7] last:border-b-0">
            <span className="w-[110px] text-[14px] text-[#626B80]">{when}</span>
            <span className="flex-1 min-w-[180px] text-[15px] text-[#121A2E]">{what}</span>
            <Badge tone={tone}>{state}</Badge>
          </li>
        ))}
      </ol>
    </div>
  )
}

const SCREENS = { discover: DiscoverScreen, understand: UnderstandScreen, prioritise: PrioritiseScreen, recheck: RecheckScreen }

export default function ProductTour() {
  const [active, setActive] = useState(0)
  const tabs = useRef([])
  const step = STEPS[active]
  const Screen = SCREENS[step.id]
  const next = STEPS[active + 1]

  const select = (i, focus = false) => {
    const n = (i + STEPS.length) % STEPS.length
    setActive(n)
    if (focus) tabs.current[n]?.focus()
  }
  const onKeyDown = (event) => {
    const keys = { ArrowRight: active + 1, ArrowDown: active + 1, ArrowLeft: active - 1, ArrowUp: active - 1, Home: 0, End: STEPS.length - 1 }
    if (event.key in keys) {
      event.preventDefault()
      select(keys[event.key], true)
    }
  }

  return (
    <div className="mt-14 grid grid-cols-1 lg:grid-cols-[360px_minmax(0,1fr)] gap-8 lg:gap-12 items-start">
      <div>
        <div role="tablist" aria-label="Sample finding, step by step" onKeyDown={onKeyDown}
          className="grid grid-cols-2 lg:grid-cols-1 gap-2">
          {STEPS.map((s, i) => {
            const selected = i === active
            return (
              <button
                key={s.id}
                ref={el => { tabs.current[i] = el }}
                id={`tour-tab-${s.id}`}
                role="tab"
                type="button"
                aria-selected={selected}
                aria-controls="tour-panel"
                tabIndex={selected ? 0 : -1}
                onClick={() => select(i)}
                className={`text-left rounded-[12px] border px-5 py-4 transition-colors ${selected ? 'bg-white border-[#2550B6] shadow-[0_12px_30px_-22px_rgba(18,26,46,.55)]' : 'bg-transparent border-[#DDE2EE] hover:bg-white'}`}
              >
                <span className="block font-cm text-[26px] leading-[1.15] text-[#121A2E]">{s.tab}</span>
                <span className="block mt-1 text-[15px] text-[#5A6378]">{s.summary}</span>
              </button>
            )
          })}
        </div>
        <p className="mt-6 text-[17px] leading-[1.6] text-[#46506A]" aria-live="polite">{step.copy}</p>
        {next ? (
          <button type="button" onClick={() => select(active + 1, true)} className="mt-4 text-[16px] font-semibold text-[#1D46A8] hover:underline">
            Next: {next.tab}
          </button>
        ) : (
          <a href="#start" className="mt-4 inline-block text-[16px] font-semibold text-[#1D46A8] hover:underline">See how to start</a>
        )}
      </div>

      <div id="tour-panel" role="tabpanel" aria-labelledby={`tour-tab-${step.id}`} tabIndex={0} className="min-w-0 rounded-[16px]">
        <ProductFrame label={`Sample screen: ${step.tab}`} path={step.path}>
          <div key={step.id} className="cm-tour-in">
            <Screen />
          </div>
          <p className="px-5 py-3 bg-[#F7F8FC] border-t border-[#E6EAF3] text-[14px] text-[#5A6378]">Illustrative example for example.co.uk, not a live result.</p>
        </ProductFrame>
      </div>
    </div>
  )
}
