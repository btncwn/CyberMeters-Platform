import React from 'react'
import { render, screen, within } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import CaseGuidance from '../CaseGuidance'

// Shapes engines/case-guidance.js returns (taken from a lab run of the real
// scan engine: an exposed management tool, re-checked scan by scan).
const remediation = {
  title: 'Restrict exposed management tools',
  explanation: 'Sensitive management tools were reachable directly from the public internet.',
  business_impact: 'Exposed management tooling can leak configuration or provide a foothold for attackers.',
  recommended_action: 'Firewall or VPN-protect the affected interfaces and allow only trusted IP ranges.',
  effort: 'medium',
  owner_label: 'Your IT, DNS or hosting administrator',
}
const recheck = {
  method: 'rescan',
  label: 'The next complete scan re-checks the affected host itself.',
  fixed_when: 'The tool is no longer publicly reachable on a fresh scan.',
  rule: "A timeout, a refused or blocked connection, or a filter's 401, 403 or 429 never closes the case: none of them shows the tool is gone.",
}

describe('CaseGuidance', () => {
  it('lays out what was found, why it matters, what to do and who does it', () => {
    render(<CaseGuidance guidance={{ version: 'case-guidance-v1', remediation, recheck, last_recheck: null, closure: null }} />)
    const todo = screen.getByRole('region', { name: 'What to do' })
    expect(todo).toHaveTextContent('Restrict exposed management tools')
    expect(todo).toHaveTextContent('Why it matters')
    expect(todo).toHaveTextContent('Exposed management tooling can leak configuration')
    expect(todo).toHaveTextContent('Recommended action')
    expect(todo).toHaveTextContent('Firewall or VPN-protect the affected interfaces')
    expect(todo).toHaveTextContent('Your IT, DNS or hosting administrator, medium effort')
    const check = screen.getByRole('region', { name: 'How the fix is checked' })
    expect(check).toHaveTextContent('The next complete scan re-checks the affected host itself.')
    expect(check).toHaveTextContent('Counts as fixed when: The tool is no longer publicly reachable on a fresh scan.')
    expect(check).toHaveTextContent("A timeout, a refused or blocked connection, or a filter's 401, 403 or 429 never closes the case")
  })

  it('shows a re-check that could not confirm the fix as waiting, with each host’s answer, never as fixed', () => {
    render(<CaseGuidance guidance={{
      version: 'case-guidance-v1', remediation, recheck,
      last_recheck: {
        outcome: 'waiting',
        label: 'Not confirmed yet',
        at: '2026-10-04T12:00:00.000Z',
        reason: 'The affected host answered with 401, 403 or 429, which filters often send to scanners only. That is not proof the problem is gone.',
        hosts: [{ hostname: 'admin.example.com', outcome: 'access_restricted', label: 'admin.example.com answered (HTTPS port 443, HTTP 403), as filters often do for scanners.' }],
      },
      closure: null,
    }} />)
    const check = screen.getByRole('region', { name: 'How the fix is checked' })
    expect(check).toHaveTextContent('Last re-check')
    expect(check).toHaveTextContent('2026-10-04 12:00')
    expect(check).toHaveTextContent('Not confirmed yet')
    expect(check).toHaveTextContent('That is not proof the problem is gone.')
    expect(within(check).getByRole('list', { name: 'What each affected host answered' })).toHaveTextContent('HTTP 403')
    expect(check).not.toHaveTextContent(/verified|fixed —/i)
    expect(screen.queryByText(/How this case ended/)).toBeNull()
  })

  it('states a CyberMeters-verified closure with its dated re-check', () => {
    render(<CaseGuidance guidance={{
      version: 'case-guidance-v1', remediation, recheck,
      last_recheck: {
        outcome: 'fixed', label: 'Fixed — verified by CyberMeters', at: '2026-10-05T13:00:00.000Z', reason: null,
        hosts: [{ hostname: 'admin.example.com', outcome: 'answered_without_tool', label: 'admin.example.com sent visitors to example.com, where the tool was not found (HTTP 200).' }],
      },
      closure: { kind: 'verified', label: 'Verified fixed by CyberMeters', at: '2026-10-05T13:00:00.000Z' },
    }} />)
    const check = screen.getByRole('region', { name: 'How the fix is checked' })
    expect(check).toHaveTextContent('Fixed — verified by CyberMeters')
    expect(check).toHaveTextContent('sent visitors to example.com, where the tool was not found')
    expect(check).toHaveTextContent('How this case ended')
    expect(check).toHaveTextContent('Verified fixed by CyberMeters on 2026-10-05 13:00')
  })

  it('keeps a closure your team made apart from a verified one', () => {
    render(<CaseGuidance guidance={{
      version: 'case-guidance-v1', remediation, recheck, last_recheck: null,
      closure: { kind: 'closed_by_customer', label: 'Closed by your team without a CyberMeters re-check', at: '2026-10-06T09:00:00.000Z' },
    }} />)
    const check = screen.getByRole('region', { name: 'How the fix is checked' })
    expect(check).toHaveTextContent('Closed by your team without a CyberMeters re-check on 2026-10-06 09:00')
    expect(check).not.toHaveTextContent(/Verified fixed/)
  })

  it('links the same finding’s earlier and later cases, since a closed case is never reopened in place', () => {
    render(
      <MemoryRouter>
        <CaseGuidance guidance={{
          version: 'case-guidance-v1', remediation, recheck, last_recheck: null, closure: null,
          continuity: {
            previous_case: { case_id: 'mc-old', label: 'This was seen again after an earlier case was closed on 2026-10-06. That case keeps its history.' },
            next_case: null,
            still_seen: null,
          },
        }} />
      </MemoryRouter>,
    )
    const check = screen.getByRole('region', { name: 'How the fix is checked' })
    expect(check).toHaveTextContent('Earlier and later cases')
    expect(check).toHaveTextContent('seen again after an earlier case was closed on 2026-10-06')
    expect(within(check).getByRole('link', { name: 'Open that case' })).toHaveAttribute('href', '/ws/cases/mc-old')
  })

  it('renders nothing without guidance, and no remediation it was not given', () => {
    const { container, rerender } = render(<CaseGuidance guidance={undefined} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<CaseGuidance guidance={{ version: 'case-guidance-v1', remediation: null, recheck: null, last_recheck: null, closure: null }} />)
    expect(container).toBeEmptyDOMElement()
  })
})
