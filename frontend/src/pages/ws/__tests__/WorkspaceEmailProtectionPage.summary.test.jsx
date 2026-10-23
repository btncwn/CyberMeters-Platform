import { describe, expect, it } from 'vitest'
import { emailSummaryFigures } from '../WorkspaceEmailProtectionPage'
import { dmarcRecordStatus, spfRecordStatus, dkimRecordStatus, mtaStsRecordStatus, tlsRptRecordStatus, mailTransportStatus } from '../../../lib/emailRecordStatus'

// S1-SHELL-V2b (C-38 S19): the Email Summary shows the four records the founder
// named, with the same word as each record card; nothing unread reads as clean.

const es = {
  dmarc: { present: true, policy: 'reject' }, dmarc_detail: { raw: 'v=DMARC1; p=reject', policy: 'reject', valid: true },
  spf: { present: true }, spf_detail: { raw: 'v=spf1 -all', valid: true },
  dkim_detail: { status: 'detected' },
}

describe('emailSummaryFigures', () => {
  it('names DMARC policy, SPF, DKIM and Aggregate reports with their record words', () => {
    const f = emailSummaryFigures(es, { reports: 0 })
    expect(f.map((x) => [x.label, x.value])).toEqual([
      ['DMARC policy', 'p=reject'], ['SPF', 'Published'], ['DKIM', 'Detected'], ['Aggregate reports', 'Waiting for first report'],
    ])
  })
  it('counts received reports; an unreadable history is "Not available", never zero', () => {
    expect(emailSummaryFigures(es, { reports: 3 })[3].value).toBe('3 reports received')
    expect(emailSummaryFigures(es, { reports: 1 })[3].value).toBe('1 report received')
    expect(emailSummaryFigures(es, null)[3]).toMatchObject({ value: 'Not available', explanation: 'Report history could not be read' })
  })
  it('a record that was not read is No data, never a clean word', () => {
    expect(emailSummaryFigures({}, null).slice(0, 3).map((x) => x.value)).toEqual(['No data', 'No data', 'No data'])
  })
})

describe('record statuses (shared with the record cards)', () => {
  it('keep the cards’ words and tones', () => {
    expect(dmarcRecordStatus({ present: false }, null)).toEqual({ label: 'Not found', kind: 'bad' })
    expect(dmarcRecordStatus(null, { raw: 'x', policy: 'none', valid: true })).toEqual({ label: 'p=none', kind: 'warn' })
    expect(spfRecordStatus({ present: true }, { raw: 'x', valid: false })).toEqual({ label: 'Issues found', kind: 'warn' })
    expect(dkimRecordStatus({ status: 'not_detected' })).toEqual({ label: 'Not verified', kind: 'na' })
    expect(mtaStsRecordStatus({ policy_found: true, mode: 'enforce' })).toEqual({ label: 'enforce', kind: 'good' })
    expect(tlsRptRecordStatus(null)).toEqual({ label: 'Not available', kind: 'na' })
  })
  it('mail transport never counts an untested server as passing', () => {
    expect(mailTransportStatus(null)).toEqual({ label: 'Not tested', kind: 'na' })
    expect(mailTransportStatus({ hosts: [{ state: 'tested' }, { state: 'tested' }] })).toEqual({ label: 'STARTTLS on 2 of 2', kind: 'good' })
    expect(mailTransportStatus({ hosts: [{ state: 'tested' }, { state: 'error' }] })).toEqual({ label: 'Tested 1 of 2', kind: 'warn' })
    expect(mailTransportStatus({ hosts: [{ state: 'tested' }, { state: 'not_offered' }] })).toEqual({ label: 'STARTTLS missing on 1 of 2', kind: 'bad' })
    // Offered but the upgrade was refused: the module's not_tested + starttls_rejected (Executive 06:05).
    expect(mailTransportStatus({ hosts: [{ state: 'tested' }, { state: 'not_tested', reason: 'starttls_rejected' }] })).toEqual({ label: 'STARTTLS rejected on 1 of 2', kind: 'bad' })
  })
})
