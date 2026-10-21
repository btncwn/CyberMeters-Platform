import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { useState } from 'react'
import { describe, expect, it } from 'vitest'
import { useAppDialog } from '../AppDialog'

function Harness({ run }) {
  const dialog = useAppDialog()
  const [result, setResult] = useState('none')
  return (
    <>
      <button type="button" onClick={async () => setResult(JSON.stringify(await run(dialog)))}>Open</button>
      <output data-testid="result">{result}</output>
      {dialog.element}
    </>
  )
}
const open = () => fireEvent.click(screen.getByRole('button', { name: 'Open' }))
const result = () => screen.getByTestId('result').textContent

describe('useAppDialog', () => {
  it('confirm: titled, labelled buttons, resolves true on the named action', async () => {
    render(<Harness run={(d) => d.confirm({ title: 'Remove this channel?', message: 'Deliveries stop.', confirmLabel: 'Remove channel', tone: 'danger' })} />)
    open()
    const dialog = await screen.findByRole('alertdialog', { name: 'Remove this channel?' })
    expect(dialog).toHaveAttribute('aria-modal', 'true')
    expect(dialog).toHaveAccessibleDescription('Deliveries stop.')
    expect(within(dialog).getByRole('button', { name: 'Cancel' })).toHaveFocus()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Remove channel' }))
    await waitFor(() => expect(result()).toBe('true'))
    expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
  })

  it('confirm: Escape cancels (false) and returns focus to the opener', async () => {
    render(<Harness run={(d) => d.confirm({ title: 'Sure?', confirmLabel: 'Do it' })} />)
    const opener = screen.getByRole('button', { name: 'Open' })
    opener.focus(); open()
    await screen.findByRole('dialog', { name: 'Sure?' })
    fireEvent.keyDown(document, { key: 'Escape' })
    await waitFor(() => expect(result()).toBe('false'))
    expect(opener).toHaveFocus()
  })

  it('prompt: focuses the labelled field, enforces required, returns trimmed text', async () => {
    render(<Harness run={(d) => d.prompt({ title: 'Exception', label: 'Exception reason', confirmLabel: 'Record exception', required: true })} />)
    open()
    const dialog = await screen.findByRole('dialog', { name: 'Exception' })
    const input = within(dialog).getByLabelText('Exception reason')
    expect(input).toHaveFocus()
    fireEvent.click(within(dialog).getByRole('button', { name: 'Record exception' }))
    expect(await within(dialog).findByRole('alert')).toHaveTextContent('Exception reason is required.')
    expect(input).toHaveAttribute('aria-invalid', 'true')
    fireEvent.change(input, { target: { value: '  pending migration  ' } })
    fireEvent.click(within(dialog).getByRole('button', { name: 'Record exception' }))
    await waitFor(() => expect(result()).toBe('"pending migration"'))
  })

  it('prompt: cancel resolves null, and an optional empty answer is allowed', async () => {
    const { unmount } = render(<Harness run={(d) => d.prompt({ title: 'Reason', label: 'Reason', confirmLabel: 'Save' })} />)
    open()
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    await waitFor(() => expect(result()).toBe('null'))
    unmount()
    render(<Harness run={(d) => d.prompt({ title: 'Reason', label: 'Reason', confirmLabel: 'Save' })} />)
    open()
    fireEvent.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Save' }))
    await waitFor(() => expect(result()).toBe('""'))
  })

  it('alert: one named close button, resolves once acknowledged', async () => {
    render(<Harness run={async (d) => { await d.alert({ title: 'Could not remove the member', message: 'Try again.' }); return 'done' }} />)
    open()
    const dialog = await screen.findByRole('dialog', { name: 'Could not remove the member' })
    expect(within(dialog).getAllByRole('button')).toHaveLength(1)
    fireEvent.click(within(dialog).getByRole('button', { name: 'Close' }))
    await waitFor(() => expect(result()).toBe('"done"'))
  })
})
