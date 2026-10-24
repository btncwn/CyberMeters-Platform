import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import StatusChip from '../../components/StatusChip'
import AcademyPage from '../../pages/AcademyPage'
import { STATUS_EXPLANATIONS, statusExplanation, statusExplanationRows } from '../statusExplanations'
import { STATUS_KEYS, domainStatus } from '../statusVocabulary'

// 10d (founder 23 Oct 2026): every status chip says what its word means — one
// sentence, the same in the chip's tooltip, its accessible description and the
// Field Guide table.
describe('status explanations', () => {
  it('every vocabulary word has one sentence', () => {
    expect(Object.keys(STATUS_EXPLANATIONS).sort()).toEqual([...STATUS_KEYS].sort())
    for (const key of STATUS_KEYS) expect(STATUS_EXPLANATIONS[key]).toMatch(/^[A-Z].+\.$/)
  })
  it('the founder\'s three words read as asked', () => {
    expect(statusExplanation('established')).toBe('An authoritative assessment exists for this area; the summary beside it says what was concluded.')
    expect(statusExplanation('provisional')).toBe('No issue was observed, but coverage was incomplete.')
    expect(statusExplanation('evidence_insufficient')).toMatch(/could not be collected.*never treated as healthy/)
  })
  it('a chip carries the sentence as its tooltip and accessible description; its visible word is unchanged', () => {
    render(<StatusChip status="provisional" />)
    const chip = screen.getByText('Provisional')
    expect(chip).toHaveAttribute('title', 'No issue was observed, but coverage was incomplete.')
    expect(chip).toHaveAccessibleDescription('No issue was observed, but coverage was incomplete.')
    expect(chip.textContent).toBe('Provisional')
  })
  it('a caller\'s specific title wins for the tooltip; the description stays the word\'s meaning', () => {
    render(<StatusChip status="action_required" title="HSTS header missing on www" />)
    const chip = screen.getByText('Action required')
    expect(chip).toHaveAttribute('title', 'HSTS header missing on www')
    expect(chip).toHaveAccessibleDescription('An issue was observed and needs action.')
  })
  it('Shadow IT monitoring only (→ Established) is never described as a verdict', () => {
    const word = domainStatus({ domain_key: 'shadow_it', state: 'monitoring_only', coverage: 'complete' })
    expect(word).toBe('established')
    render(<StatusChip status={word} />)
    const description = screen.getByText('Established').getAttribute('title')
    expect(description).not.toMatch(/no (material )?issue|healthy|secure|protected/i)
    expect(screen.getByText('Established')).toHaveAccessibleDescription(description)
  })
  it('an unknown word reads as Error with Error\'s sentence', () => {
    render(<StatusChip status="made_up" />)
    expect(screen.getByText('Error')).toHaveAccessibleDescription('This could not be loaded. It is not a result.')
  })
  it('the Field Guide shows the same table once', () => {
    render(<MemoryRouter><AcademyPage /></MemoryRouter>)
    const table = screen.getByTestId('status-words')
    expect(screen.getAllByTestId('status-words')).toHaveLength(1)
    for (const [, label, sentence] of statusExplanationRows()) {
      expect(table).toHaveTextContent(label)
      expect(table).toHaveTextContent(sentence)
    }
  })
})
