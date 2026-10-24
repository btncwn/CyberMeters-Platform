import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import ExecutiveReportV2 from '../ExecutiveReportV2'
import { trialUrlFor } from '../tools/FreeToolPage'

describe('C-46 rank 3: report recommended actions lead to their managed case', () => {
  it('an action with a case links to it; one without does not', () => {
    const report = { remediation_actions: [
      { remediation_id: 'web.header.hsts', title: 'Add or strengthen HSTS', priority: 'medium', case_id: 'mc_1' },
      { remediation_id: 'email.dmarc', title: 'Publish a DMARC policy', priority: 'high' },
    ] }
    render(<MemoryRouter><ExecutiveReportV2 report={report} /></MemoryRouter>)
    // The report lists actions twice (top priorities, then all): every link leads to
    // the action's own case; the action without a case has none.
    const links = screen.getAllByTestId('report-action-case')
    expect(links.length).toBeGreaterThan(0)
    for (const link of links) {
      expect(link).toHaveAttribute('href', '/ws/cases/mc_1')
      expect(link).toHaveTextContent('Open the case for this action')
    }
    expect(document.body.textContent).not.toContain('mc_1')
  })
})

describe('C-46 rank 8: a free tool\'s trial keeps the checked domain', () => {
  it('adds ?domain= (normalised); none when no domain', () => {
    expect(trialUrlFor(' Example.ORG ')).toBe('https://app.cybermeters.com/signup?domain=example.org')
    expect(trialUrlFor('')).toBe('https://app.cybermeters.com/signup')
  })
})
