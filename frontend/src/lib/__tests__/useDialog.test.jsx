import { fireEvent, render, screen } from '@testing-library/react'
import { useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import { useDialog } from '../useDialog'

function Dialog({ onClose }) {
  const ref = useDialog(onClose)
  return (
    <div ref={ref} role="dialog" aria-modal="true" aria-label="Example" tabIndex={-1}>
      <button type="button">First</button>
      <input aria-label="Middle" />
      <button type="button" disabled>Disabled</button>
      <button type="button">Last</button>
    </div>
  )
}

function Harness({ onClose = () => {} }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>Open</button>
      {open && <Dialog onClose={() => { onClose(); setOpen(false) }} />}
    </>
  )
}

describe('useDialog', () => {
  it('moves focus in, keeps Tab inside, closes on Escape and returns focus to the opener', () => {
    const onClose = vi.fn()
    render(<Harness onClose={onClose} />)
    const opener = screen.getByRole('button', { name: 'Open' })
    opener.focus()
    fireEvent.click(opener)

    expect(screen.getByRole('button', { name: 'First' })).toHaveFocus()
    screen.getByRole('button', { name: 'Last' }).focus()
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(screen.getByRole('button', { name: 'First' })).toHaveFocus()
    fireEvent.keyDown(document, { key: 'Tab', shiftKey: true })
    expect(screen.getByRole('button', { name: 'Last' })).toHaveFocus()

    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(opener).toHaveFocus()
  })

  it('stays open on Escape when no close handler is given (e.g. while a delete runs)', () => {
    render(<Dialog onClose={undefined} />)
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.getByRole('dialog')).toBeInTheDocument()
  })
})
