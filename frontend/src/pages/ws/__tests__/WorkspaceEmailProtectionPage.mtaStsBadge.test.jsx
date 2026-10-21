import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { ManagedMtaStsCard } from '../WorkspaceEmailProtectionPage'
import { api } from '../../../api'

vi.mock('../../../api', () => ({
  api: {
    getHostedMtaSts: vi.fn(),
    createHostedMtaSts: vi.fn(),
    verifyHostedMtaSts: vi.fn(),
    deleteHostedMtaSts: vi.fn(),
  },
  BASE: 'https://api.example.test/api',
}))

const PATH = 'https://mta-sts.example.test/.well-known/mta-sts.txt'

// The record as the API projects it (mtaStsRecordToApi).
function record({ status = 'connected', policyState = 'not_published', matches = false, complete = false, review = false } = {}) {
  return {
    record: {
      id: 'hosted_mtasts_1', domain: 'example.test', record_type: 'mtasts', status,
      policy_path: PATH,
      dns_txt: { state: status, checks: null },
      https_policy: { state: policyState, path: PATH, matches_pinned_policy: matches, errors: [] },
      mx_drift: { detected: review, message: review ? 'Your mail servers changed.' : null },
      complete, review_required: review,
      policy_content: 'version: STSv1\nmode: testing\nmx: mx.example.test\nmax_age: 86400',
    },
  }
}

async function badge(response) {
  api.getHostedMtaSts.mockResolvedValue(response)
  render(<ManagedMtaStsCard wsId="ws_1" domain="example.test" />)
  return screen.findByText(/^(Incomplete —|MTA-STS active|Review needed|Connected|Waiting|Not checked)/)
}

beforeEach(() => vi.clearAllMocks())

describe('ManagedMtaStsCard badge', () => {
  it('DNS connected but the policy file not published reads as incomplete, never Connected', async () => {
    expect(await badge(record())).toHaveTextContent('Incomplete — policy file not published')
    expect(screen.queryByText('Connected')).not.toBeInTheDocument()
    expect(screen.getByTestId('mta-sts-incomplete-line'))
      .toHaveTextContent(`MTA-STS stays incomplete until ${PATH} serves this exact file.`)
  })

  it('a published file that differs from the pinned policy says so rather than "not published"', async () => {
    expect(await badge(record({ policyState: 'reachable_valid', matches: false }))).toHaveTextContent('Incomplete — policy file does not match')
    expect(screen.getByTestId('mta-sts-incomplete-line')).toBeInTheDocument()
  })

  it('an unchecked policy file is not claimed as unpublished', async () => {
    expect(await badge(record({ policyState: 'not_checked' }))).toHaveTextContent('Incomplete — policy file not checked yet')
  })

  it('complete comes from the API and drops the incomplete line', async () => {
    expect(await badge(record({ policyState: 'reachable_valid', matches: true, complete: true }))).toHaveTextContent('MTA-STS active in testing mode')
    expect(screen.queryByTestId('mta-sts-incomplete-line')).not.toBeInTheDocument()
  })

  it('a mail-server change still asks for review first', async () => {
    expect(await badge(record({ review: true }))).toHaveTextContent('Review needed')
    expect(screen.queryByTestId('mta-sts-incomplete-line')).not.toBeInTheDocument()
  })

  it('before DNS is connected the status label is unchanged and no incomplete line shows', async () => {
    api.getHostedMtaSts.mockResolvedValue(record({ status: 'pending_dns' }))
    render(<ManagedMtaStsCard wsId="ws_1" domain="example.test" />)
    expect(await screen.findByText('MTA-STS readiness')).toBeInTheDocument()
    expect(screen.queryByText(/^Incomplete —/)).not.toBeInTheDocument()
    expect(screen.queryByTestId('mta-sts-incomplete-line')).not.toBeInTheDocument()
  })
})
