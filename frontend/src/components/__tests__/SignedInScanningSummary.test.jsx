import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import SignedInScanningSummary, { signedInFactLine } from '../SignedInScanningSummary'

// S2-SIGNED-IN-REPORT (founder, 22 Oct 2026): the snapshot's sentences verbatim,
// one fact line, null = "not observed" (never "no"), nothing for old reports.
const LIMIT = 'Signed-in checks use the test account you gave CyberMeters: they cover the pages that account can reach within a small read-only crawl, and say nothing about other accounts, roles or pages it cannot reach.'
const recorded = (over = {}) => ({
  status: 'recorded', configured: true, signed_in: true, sign_in_outcome: 'signed_in', pages_checked: 2,
  anonymous_access_refused: true, last_successful_sign_in_at: '2026-10-22T11:16:01.793Z', coverage: 'complete',
  customer_message: 'Signed in with the test account and checked 2 pages behind the sign-in.', limitation: LIMIT, ...over,
})

describe('signed-in scanning in the report', () => {
  it('recorded: one fact line, then the snapshot sentences verbatim', () => {
    render(<SignedInScanningSummary section={recorded()} />)
    expect(screen.getByTestId('signed-in-fact')).toHaveTextContent('Signed-in pages: 2 checked · anonymous access refused: yes · last signed in 22 Oct 2026, 11:16 UTC')
    expect(screen.getByText('Signed in with the test account and checked 2 pages behind the sign-in.')).toBeInTheDocument()
    expect(screen.getByText(LIMIT)).toBeInTheDocument()
  })
  it('anonymous access: false reads "no", null reads "not observed" — never "no"', () => {
    expect(signedInFactLine(recorded({ anonymous_access_refused: false }))).toMatch(/anonymous access refused: no/)
    expect(signedInFactLine(recorded({ anonymous_access_refused: null }))).toMatch(/anonymous access refused: not observed/)
  })
  it('not set up: only the snapshot sentence that says so, no fact line', () => {
    render(<SignedInScanningSummary section={{ status: 'not_configured', configured: false, customer_message: 'Signed-in scanning is not set up for this domain, so only public pages were checked.', limitation: LIMIT }} />)
    expect(screen.getByText(/is not set up for this domain/)).toBeInTheDocument()
    expect(screen.queryByTestId('signed-in-fact')).toBeNull()
  })
  it('a failed sign-in claims no pages and no anonymous-access answer', () => {
    expect(signedInFactLine(recorded({ signed_in: false, pages_checked: 0, anonymous_access_refused: null }))).toBeNull()
  })
  it('a report from before the section existed renders nothing', () => {
    const { container } = render(<SignedInScanningSummary section={null} />)
    expect(container).toBeEmptyDOMElement()
  })
})
