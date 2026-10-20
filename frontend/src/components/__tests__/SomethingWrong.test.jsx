import { afterEach, describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import SomethingWrong from '../SomethingWrong'

afterEach(() => vi.unstubAllGlobals())

function stubFetch(status) {
  const fetch = vi.fn().mockResolvedValue(new Response('{}', { status }))
  vi.stubGlobal('fetch', fetch)
  return fetch
}

async function sendReport(text) {
  fireEvent.click(screen.getByRole('button', { name: 'Something wrong?' }))
  fireEvent.change(screen.getByLabelText('Tell us what looks wrong'), { target: { value: text } })
  fireEvent.click(screen.getByRole('button', { name: 'Send' }))
}

describe('"Something wrong?"', () => {
  it('is a closed link until asked, then one text box', () => {
    render(<SomethingWrong surface="app" />)
    const toggle = screen.getByRole('button', { name: 'Something wrong?' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('textbox')).toBeNull()
    fireEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getAllByRole('textbox')).toHaveLength(1)
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled()
  })

  it('sends the typed message with the tool and the error code shown, and thanks the visitor', async () => {
    const fetch = stubFetch(202)
    render(<SomethingWrong surface="free_tool" tool="dmarc-checker" errorCode="invalid_domain" />)
    await sendReport('It says my record is missing but it is there')
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Thanks, sent.'))
    const body = JSON.parse(fetch.mock.calls[0][1].body)
    expect(body).toMatchObject({ message: 'It says my record is missing but it is there', surface: 'free_tool', tool: 'dmarc-checker', error_code: 'invalid_domain', build: 'dev' })
    expect(screen.getByLabelText('Tell us what looks wrong')).toHaveValue('')
  })

  it('before the endpoint is live (404) it says so and offers email: never a fake "sent"', async () => {
    stubFetch(404)
    render(<SomethingWrong surface="free_scan" />)
    await sendReport('Something odd')
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent('Couldn’t send right now. Email hello@cybermeters.com.'))
    expect(screen.getByRole('status')).not.toHaveTextContent(/Thanks/)
    expect(screen.getByLabelText('Tell us what looks wrong')).toHaveValue('Something odd')
  })

  it('a rate limit is explained', async () => {
    stubFetch(429)
    render(<SomethingWrong surface="app" />)
    await sendReport('Again')
    await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/several reports in the last hour/))
  })
})
