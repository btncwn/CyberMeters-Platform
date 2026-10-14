import { describe, expect, it } from 'vitest'
import { hostingNetworkRows, hostingNetworkShort, hostingServiceLabel, hostingSummaryItems } from '../hostingNetworkDisplay'

const attributed = {
  status: 'attributed',
  networks: [
    { address: '52.94.5.10', provider: 'aws', provider_label: 'Amazon Web Services', kind: 'cloud', region: 'eu-west-2', service: 'EC2', range: '52.94.5.0/24' },
    { address: '104.16.1.1', provider: 'cloudflare', provider_label: 'Cloudflare', kind: 'edge', region: null, service: null, range: '104.16.0.0/13' },
  ],
  limitations: ['x'],
}

describe('hosting network display', () => {
  it('names only the providers the backend matched', () => {
    expect(hostingNetworkShort(attributed)).toEqual({ text: 'Amazon Web Services, Cloudflare', tone: 'info' })
    expect(hostingNetworkShort({ status: 'unattributed', networks: [] }).text).toBe('Other network')
    expect(hostingNetworkShort({ status: 'no_address', networks: [] }).text).toBe('No address recorded')
  })

  it('says nothing when the list was not checked or the field is missing', () => {
    expect(hostingNetworkShort({ status: 'unavailable', networks: [] })).toBeNull()
    expect(hostingNetworkShort(undefined)).toBeNull()
    expect(hostingNetworkShort({ status: 'attributed', networks: [] })).toBeNull()
  })

  it('lists each matched address with region, service and edge', () => {
    expect(hostingNetworkRows(attributed).map((r) => [r.address, r.provider, r.detail])).toEqual([
      ['52.94.5.10', 'Amazon Web Services', 'eu-west-2 · EC2 compute'],
      ['104.16.1.1', 'Cloudflare', 'edge network'],
    ])
    expect(hostingNetworkRows({ status: 'unattributed', networks: [] })).toEqual([])
  })

  it('labels service codes without inventing them', () => {
    expect(hostingServiceLabel('CLOUDFRONT')).toBe('CloudFront')
    expect(hostingServiceLabel('KINESIS_VIDEO_STREAMS')).toBe('Kinesis Video Streams')
    expect(hostingServiceLabel('')).toBeNull()
  })

  it('summarises counts, leaving zeros out, and hides a list that was never checked', () => {
    const summary = {
      assets: 6,
      by_provider: [{ provider: 'aws', provider_label: 'Amazon Web Services', count: 2 }],
      other_networks: 3, no_address: 0, unavailable: 1,
    }
    expect(hostingSummaryItems(summary).map((i) => [i.label, i.count])).toEqual([['Amazon Web Services', 2], ['Other networks', 3]])
    expect(hostingSummaryItems({ assets: 2, by_provider: [], other_networks: 0, no_address: 0, unavailable: 2 })).toEqual([])
    expect(hostingSummaryItems(null)).toEqual([])
  })
})
