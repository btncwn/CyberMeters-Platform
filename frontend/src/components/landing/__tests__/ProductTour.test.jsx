import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import ProductTour from '../ProductTour'

describe('ProductTour', () => {
  it('changes the screen, the explanation and the next step with the selected tab', () => {
    render(<ProductTour />)
    const tabs = screen.getAllByRole('tab')
    expect(tabs).toHaveLength(4)
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tabpanel')).toHaveTextContent('DMARC policy is monitoring only')
    expect(screen.getByRole('button', { name: 'Next: Understand' })).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Next: Understand' }))
    expect(screen.getAllByRole('tab')[1]).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tabpanel')).toHaveTextContent('Not assessed')
  })

  it('moves between tabs with the arrow, Home and End keys', () => {
    render(<ProductTour />)
    const tabs = screen.getAllByRole('tab')
    fireEvent.keyDown(tabs[0], { key: 'ArrowRight' })
    expect(tabs[1]).toHaveAttribute('aria-selected', 'true')
    expect(document.activeElement).toBe(tabs[1])
    expect(tabs[0]).toHaveAttribute('tabindex', '-1')
    expect(tabs[1]).toHaveAttribute('tabindex', '0')

    fireEvent.keyDown(tabs[1], { key: 'End' })
    expect(tabs[3]).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('link', { name: 'See how to start' })).toHaveAttribute('href', '#start')

    fireEvent.keyDown(tabs[3], { key: 'ArrowRight' })
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
    fireEvent.keyDown(tabs[0], { key: 'ArrowLeft' })
    expect(tabs[3]).toHaveAttribute('aria-selected', 'true')
    fireEvent.keyDown(tabs[3], { key: 'Home' })
    expect(tabs[0]).toHaveAttribute('aria-selected', 'true')
  })

  it('labels every screen as an example and keeps "verified" for what CyberMeters re-observed', () => {
    render(<ProductTour />)
    const tabs = screen.getAllByRole('tab')
    tabs.forEach((tab, i) => {
      fireEvent.click(tab)
      const panel = screen.getByRole('tabpanel')
      expect(panel).toHaveTextContent(/not a live result/i)
      if (i < 3) expect(panel).not.toHaveTextContent(/verified/i)
    })
    expect(screen.getByRole('tabpanel')).toHaveTextContent('Verified by CyberMeters')
    expect(screen.getByRole('tabpanel')).toHaveTextContent('Awaiting verification')
  })

  it('never claims that CyberMeters makes the change itself', () => {
    render(<ProductTour />)
    fireEvent.click(screen.getAllByRole('tab')[2])
    expect(screen.getByRole('tabpanel')).toHaveTextContent('CyberMeters changes a DNS record only after you explicitly confirm the change.')
  })
})
