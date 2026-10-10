import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import OneClickDnsButton from '../OneClickDnsButton'
import { useDomainConnectOffer } from '../../hooks/useDomainConnectOffer'
import { api } from '../../api'

const OFFER = {
  available: true,
  provider: { id: 'cloudflare.com', name: 'Cloudflare' },
  apply_url: 'https://dash.cloudflare.com/domainconnect/v2/domainTemplates/providers/cybermeters.com/services/domain-verification/apply?domain=example.com&key=_dck1&sig=abc',
}

function Harness({ domainId = 'd1', workspaceId = 'ws1', tokenKey = 'cybermeters-verification=t' }) {
  const offer = useDomainConnectOffer(domainId, workspaceId, tokenKey)
  return <OneClickDnsButton offer={offer} />
}

beforeEach(() => { vi.restoreAllMocks() })

describe('OneClickDnsButton', () => {
  it('renders nothing without an available offer', () => {
    const { container, rerender } = render(<OneClickDnsButton offer={null} />)
    expect(container).toBeEmptyDOMElement()
    rerender(<OneClickDnsButton offer={{ available: false, reason: 'template_not_onboarded' }} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('links to the server-built consent URL and names the provider', () => {
    render(<OneClickDnsButton offer={OFFER} />)
    const link = screen.getByTestId('one-click-dns')
    expect(link).toHaveAttribute('href', OFFER.apply_url)
    expect(link).toHaveTextContent('Add the record automatically with Cloudflare')
    expect(screen.getByText(/Nothing else in your DNS is changed/)).toBeInTheDocument()
  })
})

describe('useDomainConnectOffer', () => {
  it('shows the button when the backend offers one-click verification', async () => {
    const spy = vi.spyOn(api, 'getDomainConnectOffer').mockResolvedValue(OFFER)
    render(<Harness />)
    await waitFor(() => expect(screen.getByTestId('one-click-dns')).toBeInTheDocument())
    expect(spy).toHaveBeenCalledWith('d1', 'ws1')
  })

  it('stays silent when unavailable or failing — the manual record is the fallback', async () => {
    const spy = vi.spyOn(api, 'getDomainConnectOffer').mockResolvedValue({ available: false, reason: 'provider_not_supported' })
    const { container, rerender } = render(<Harness />)
    await waitFor(() => expect(spy).toHaveBeenCalled())
    expect(container).toBeEmptyDOMElement()
    spy.mockRejectedValue(new Error('network'))
    rerender(<Harness tokenKey="cybermeters-verification=t2" />)
    await waitFor(() => expect(spy).toHaveBeenCalledTimes(2))
    expect(container).toBeEmptyDOMElement()
  })

  it('does not ask before a token exists', () => {
    const spy = vi.spyOn(api, 'getDomainConnectOffer').mockResolvedValue(OFFER)
    render(<Harness tokenKey={null} />)
    expect(spy).not.toHaveBeenCalled()
  })
})
