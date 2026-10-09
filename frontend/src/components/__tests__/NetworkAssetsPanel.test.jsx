import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import NetworkAssetsPanel from '../NetworkAssetsPanel'
import { api } from '../../api'
import { TOKEN_KEY } from '../../context/authKeys'

vi.mock('../../api', () => ({ api: {
  getNetworkTargets: vi.fn(), getNetworkAssets: vi.fn(), getNetworkScans: vi.fn(),
  addNetworkTarget: vi.fn(), startNetworkScan: vi.fn(), getNetworkScan: vi.fn(), retestNetworkScan: vi.fn(),
} }))

const capabilities = {
  can_manage: true, can_scan: true, collector_available: true,
  allowed_ports: [22, 80, 443], limits: { max_addresses: 32, max_ports: 16, max_pairs: 256, max_targets: 32 },
}
const target = { id: 'target-1', target: '93.184.216.34', target_type: 'ip', address_count: 1, authorization_status: 'attested', authorized_at: '2026-10-09T00:00:00Z' }
const run = { id: 'run-1', target_id: 'target-1', target: target.target, status: 'completed', quality: 'partial', created_at: '2026-10-09T00:00:00Z', coverage: { planned: 3, attempted: 2, completed: 1, not_run: 1 } }

beforeEach(() => {
  vi.resetAllMocks()
  api.getNetworkTargets.mockResolvedValue({ targets: [target], capabilities })
  api.getNetworkAssets.mockResolvedValue({ assets: [], changes: [] })
  api.getNetworkScans.mockResolvedValue({ scans: [] })
  api.addNetworkTarget.mockResolvedValue({ target })
  api.startNetworkScan.mockResolvedValue({ scan: { ...run, status: 'queued', quality: null } })
  api.retestNetworkScan.mockResolvedValue({ scan: { ...run, id: 'run-2', status: 'queued', quality: null } })
})

async function ready() {
  const view = render(<NetworkAssetsPanel workspaceId="workspace-a" />)
  await screen.findByRole('tab', { name: 'Targets' })
  return view
}

describe('Network assets customer workflow', () => {
  it('records only an explicit authorization declaration and preserves the exact scope', async () => {
    await ready()
    fireEvent.change(screen.getByLabelText('IP address or CIDR'), { target: { value: '93.184.216.0/28' } })
    fireEvent.change(screen.getByLabelText('Label (optional)'), { target: { value: 'Public edge' } })
    expect(screen.getByRole('button', { name: 'Add network target' })).toBeDisabled()
    expect(api.addNetworkTarget).not.toHaveBeenCalled()
    fireEvent.click(screen.getByLabelText('I own this address range or have permission to test it.'))
    fireEvent.click(screen.getByRole('button', { name: 'Add network target' }))
    await waitFor(() => expect(api.addNetworkTarget).toHaveBeenCalledWith('workspace-a', { target: '93.184.216.0/28', label: 'Public edge', authorization_confirmed: true }))
    expect(screen.getByText(/not independent ownership verification/)).toBeInTheDocument()
    expect(screen.queryByText('Ownership verified')).not.toBeInTheDocument()
  })

  it('starts only the selected allowed ports and prevents a duplicate queued scan', async () => {
    await ready()
    fireEvent.click(screen.getByLabelText('22'))
    api.getNetworkScans.mockResolvedValue({ scans: [{ ...run, status: 'queued' }] })
    fireEvent.click(screen.getByRole('button', { name: 'Run scan' }))
    await waitFor(() => expect(api.startNetworkScan).toHaveBeenCalledWith('workspace-a', 'target-1', [443, 80, 22]))
    expect(await screen.findByRole('button', { name: 'Scan in progress' })).toBeDisabled()
  })

  it('does not announce or invent a queued scan when the collector rejects the request', async () => {
    api.startNetworkScan.mockRejectedValue(new Error('Network scanning is unavailable'))
    await ready()
    fireEvent.click(screen.getByRole('button', { name: 'Run scan' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Network scanning is unavailable')
    expect(screen.queryByText(/Network scan queued/)).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Scan in progress' })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'Recent scans' }))
    expect(screen.getByText('No network scans recorded yet.')).toBeInTheDocument()
  })

  it('serializes scans across different targets in the same workspace', async () => {
    api.getNetworkScans.mockResolvedValue({ scans: [{ ...run, target_id: 'different-target', status: 'running' }] })
    await ready()
    expect(screen.getByRole('button', { name: 'Scan in progress' })).toBeDisabled()
    fireEvent.click(screen.getByRole('button', { name: 'Scan in progress' }))
    expect(api.startNetworkScan).not.toHaveBeenCalled()
  })

  it('does not start when the address/port count exceeds the returned limit', async () => {
    api.getNetworkTargets.mockResolvedValue({ targets: [{ ...target, address_count: 32 }], capabilities: { ...capabilities, limits: { ...capabilities.limits, max_pairs: 32 } } })
    await ready()
    expect(screen.getByRole('button', { name: 'Run scan' })).toBeDisabled()
    fireEvent.click(screen.getByLabelText('80'))
    expect(screen.getByRole('button', { name: 'Run scan' })).toBeEnabled()
    expect(api.startNetworkScan).not.toHaveBeenCalled()
  })

  it('hides management and scan actions when server capabilities deny them', async () => {
    api.getNetworkTargets.mockResolvedValue({ targets: [target], capabilities: { ...capabilities, can_manage: false, can_scan: false } })
    await ready()
    expect(screen.queryByRole('button', { name: 'Add network target' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Run scan' })).not.toBeInTheDocument()
    expect(screen.queryByText('Ports to check')).not.toBeInTheDocument()
  })

  it('retains saved targets but never offers a scan while the collector is unavailable', async () => {
    api.getNetworkTargets.mockResolvedValue({ targets: [target], capabilities: { ...capabilities, collector_available: false } })
    await ready()
    expect(screen.getByText(/Network scanning is currently unavailable/)).toBeInTheDocument()
    expect(screen.getByText(target.target)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Run scan' })).toBeDisabled()
  })

  it('does not present a failed inventory load as an empty healthy inventory', async () => {
    api.getNetworkAssets.mockRejectedValue(new Error('Inventory unavailable'))
    render(<NetworkAssetsPanel workspaceId="workspace-a" />)
    expect(await screen.findByRole('alert')).toHaveTextContent('Inventory unavailable')
    expect(screen.queryByText(/No service observations/)).not.toBeInTheDocument()
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
  })

  it('shows unmeasured states independently and never infers a service from a port number', async () => {
    api.getNetworkAssets.mockResolvedValue({ assets: [
      { address: target.target, port: 22, transport: 'tcp', state: 'timeout', last_observed_state: 'open', last_seen_at: '2026-10-09T00:00:00Z', last_checked_at: '2026-10-09T01:00:00Z' },
      { address: target.target, port: 443, transport: 'tcp', state: 'open', last_observed_state: 'open', service: { name: '<img src=x onerror=alert(1)>', basis: 'observed_banner' } },
      { address: target.target, port: 80, transport: 'tcp', state: 'not_run', last_observed_state: 'not_run' },
    ], changes: [] })
    await ready()
    fireEvent.click(screen.getByRole('tab', { name: 'Services' }))
    expect(screen.getByText('Timed out')).toBeInTheDocument()
    expect(screen.getByText('Last observed: open')).toBeInTheDocument()
    expect(screen.getByText('Not run')).toBeInTheDocument()
    expect(screen.getAllByText('Not identified')).toHaveLength(2)
    expect(screen.queryByText('SSH')).not.toBeInTheDocument()
    expect(screen.getByText('<img src=x onerror=alert(1)>')).toBeInTheDocument()
    expect(document.querySelector('img')).toBeNull()
    expect(screen.getByText(/An open port is an observation, not a vulnerability/)).toBeInTheDocument()
  })

  it('shows partial receipt coverage, every selected tuple and recorded changes', async () => {
    api.getNetworkScans.mockResolvedValue({ scans: [run] })
    api.getNetworkScan.mockResolvedValue({ scan: run, receipt: { quality: 'partial', coverage: run.coverage, finished_at: '2026-10-09T00:01:00Z', observations: [
      { address: target.target, port: 22, transport: 'tcp', state: 'open', service: { name: 'SSH', basis: 'SSH-2.0 banner' } },
      { address: target.target, port: 80, transport: 'tcp', state: 'timeout' },
      { address: target.target, port: 443, transport: 'tcp', state: 'not_run', reason: 'deadline' },
    ] }, changes: [{ type: 'opened', address: target.target, port: 22, scan_id: 'run-1', observed_at: '2026-10-09T00:01:00Z' }] })
    await ready()
    fireEvent.click(screen.getByRole('tab', { name: 'Recent scans' }))
    fireEvent.click(screen.getByRole('button', { name: 'View evidence' }))
    const detail = await screen.findByLabelText('Network scan evidence')
    await within(detail).findByText('SSH')
    expect(within(detail).getByText('3 planned · 2 attempted · 1 completed · 1 not run')).toBeInTheDocument()
    expect(within(detail).getByText(/Partial coverage/)).toBeInTheDocument()
    expect(within(detail).getAllByRole('row')).toHaveLength(4)
    expect(within(detail).getByText('Port became open')).toBeInTheDocument()
    expect(within(detail).queryByText(/security clearance/)).not.toBeInTheDocument()
  })

  it('shows actual network TLS receipt details and uses its recorded time for per-scan changes', async () => {
    api.getNetworkScans.mockResolvedValue({ scans: [run] })
    api.getNetworkScan.mockResolvedValue({ scan: run, receipt: { quality: 'complete', finished_at: '2026-10-09T00:01:00Z', observations: [{ address: target.target, port: 443, transport: 'tcp', state: 'open', tls: { leaf_collected: true, leaf_certificate: { collection_performed: true, collection_complete: true, certificate_identity: 'sha256:recorded-network-leaf', subject: 'CN=Recorded service' }, endpoint: { address: target.target, port: 443 } } }] }, changes: [{ type: 'discovered', address: target.target, port: 443 }] })
    await ready()
    fireEvent.click(screen.getByRole('tab', { name: 'Recent scans' }))
    fireEvent.click(screen.getByRole('button', { name: 'View evidence' }))
    const panel = await screen.findByLabelText('Network scan evidence')
    expect(await within(panel).findByText('sha256:recorded-network-leaf')).toBeInTheDocument()
    const change = within(panel).getByText('First observed service').closest('li')
    expect(change).not.toHaveTextContent('Not recorded')
    expect(change).toHaveTextContent('2026')
    expect(within(panel).getByText('Exact presented chain: unknown. Revocation / OCSP status: not assessed.')).toBeInTheDocument()
  })

  it('retests the stored scope instead of substituting current port selections', async () => {
    api.getNetworkScans.mockResolvedValue({ scans: [run] })
    await ready()
    fireEvent.click(screen.getByLabelText('22'))
    fireEvent.click(screen.getByRole('tab', { name: 'Recent scans' }))
    fireEvent.click(screen.getByRole('button', { name: 'Retest same scope' }))
    await waitFor(() => expect(api.retestNetworkScan).toHaveBeenCalledWith('workspace-a', 'run-1'))
    expect(api.startNetworkScan).not.toHaveBeenCalled()
  })

  it('renders unavailable counts as unknown, without invented zero coverage', async () => {
    api.getNetworkScans.mockResolvedValue({ scans: [{ ...run, quality: null, coverage: null }] })
    await ready()
    fireEvent.click(screen.getByRole('tab', { name: 'Recent scans' }))
    expect(screen.getByText('Coverage has not been established.')).toBeInTheDocument()
    expect(screen.queryByText(/0 planned/)).not.toBeInTheDocument()
  })

  it('keeps known observations visible on refresh failure with an explicit stale notice', async () => {
    await ready()
    api.getNetworkTargets.mockRejectedValue(new Error('Refresh failed'))
    fireEvent.click(screen.getByRole('button', { name: 'Refresh network assets' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('Previously loaded observations remain shown')
    expect(screen.getByText(target.target)).toBeInTheDocument()
  })


  it('loads the next inventory page without hiding existing rows or implying all history', async () => {
    const first = { address: '93.184.216.34', port: 443, transport: 'tcp', state: 'open' }
    const second = { address: '93.184.216.35', port: 443, transport: 'tcp', state: 'closed' }
    api.getNetworkAssets.mockResolvedValueOnce({ assets: [first], total: 2, next_cursor: '1', changes: [] })
    await ready()
    fireEvent.click(screen.getByRole('tab', { name: 'Services' }))
    expect(screen.getByText('Showing 1 of 2 recorded service observations.')).toBeInTheDocument()
    api.getNetworkAssets.mockResolvedValueOnce({ assets: [second], total: 2, next_cursor: null, changes: [] })
    fireEvent.click(screen.getByRole('button', { name: 'Load more observations' }))
    await waitFor(() => expect(api.getNetworkAssets).toHaveBeenCalledWith('workspace-a', { cursor: '1' }))
    expect(await screen.findByText('Showing 2 of 2 recorded service observations.')).toBeInTheDocument()
    expect(screen.getByText(first.address)).toBeInTheDocument()
    expect(screen.getByText(second.address)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Load more observations' })).not.toBeInTheDocument()
    expect(screen.getByText('Recent changes')).toBeInTheDocument()
    expect(screen.getByText(/latest 25 completed scans/)).toBeInTheDocument()
  })

  it('labels retained service evidence and distinguishes a later check from its observation time', async () => {
    api.getNetworkAssets.mockResolvedValue({ assets: [{ address: target.target, port: 22, transport: 'tcp', state: 'timeout', last_observed_state: 'open', service: { name: 'SSH', basis: 'SSH-2.0 banner' }, last_seen_at: '2026-10-08T00:00:00Z', last_checked_at: '2026-10-09T00:00:00Z' }], changes: [] })
    await ready()
    fireEvent.click(screen.getByRole('tab', { name: 'Services' }))
    expect(screen.getByText('Timed out')).toBeInTheDocument()
    expect(screen.getByText('Last observed: open')).toBeInTheDocument()
    expect(screen.getByText('Retained from the last observation')).toBeInTheDocument()
    expect(screen.getByText('SSH')).toBeInTheDocument()
    expect(screen.getByText(/Last checked/)).toBeInTheDocument()
    expect(screen.queryByText('Not recorded')).not.toBeInTheDocument()
  })


  it('identifies a truncated scan list and maps the returned change vocabulary without closure claims', async () => {
    api.getNetworkScans.mockResolvedValue({ scans: [run], total: 101, scope: 'latest_100', truncated: true })
    api.getNetworkAssets.mockResolvedValue({ assets: [], total: 0, next_cursor: null, changes: [
      { type: 'discovered', address: target.target, port: 443 }, { type: 'changed', address: target.target, port: 22 },
    ] })
    await ready()
    fireEvent.click(screen.getByRole('tab', { name: 'Recent scans' }))
    expect(screen.getByText(/Showing 1 of 101 network scans/)).toHaveTextContent('latest 100 runs')
    expect(screen.getByText(/Older runs remain accessible/)).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'Services' }))
    expect(screen.getByText('First observed service')).toBeInTheDocument()
    expect(screen.getByText('Observed service details changed')).toBeInTheDocument()
    expect(screen.queryByText(/Case closed/)).not.toBeInTheDocument()
  })

  it('uses the existing authenticated API transport with encoded workspace, target and scan scope', async () => {
    const { api: actualApi } = await vi.importActual('../../api')
    localStorage.setItem(TOKEN_KEY, 'synthetic-session')
    const request = vi.spyOn(globalThis, 'fetch').mockResolvedValue({ ok: true, status: 200, json: async () => ({}) })
    try {
      await actualApi.getNetworkAssets('ws/a', { cursor: '256' })
      expect(request).toHaveBeenLastCalledWith('http://localhost/api/workspaces/ws%2Fa/network-assets?cursor=256', expect.any(Object))
      await actualApi.startNetworkScan('ws/a', 'target/b', [443])
      expect(request).toHaveBeenLastCalledWith('http://localhost/api/workspaces/ws%2Fa/network-targets/target%2Fb/scans', expect.objectContaining({ method: 'POST', body: '{"ports":[443]}', headers: expect.objectContaining({ Authorization: 'Bearer synthetic-session' }) }))
      await actualApi.retestNetworkScan('ws/a', 'run/c')
      expect(request).toHaveBeenLastCalledWith('http://localhost/api/workspaces/ws%2Fa/network-scans/run%2Fc/retest', expect.objectContaining({ method: 'POST', body: '{}' }))
    } finally { request.mockRestore() }
  })

  it('discards a previous workspace response when switching tenants', async () => {
    let finishOld
    api.getNetworkTargets.mockImplementation(ws => ws === 'workspace-a' ? new Promise(resolve => { finishOld = resolve }) : Promise.resolve({ targets: [{ ...target, target: '1.1.1.1' }], capabilities }))
    const view = render(<NetworkAssetsPanel workspaceId="workspace-a" />)
    view.rerender(<NetworkAssetsPanel workspaceId="workspace-b" />)
    expect(await screen.findByText('1.1.1.1')).toBeInTheDocument()
    await act(async () => { finishOld({ targets: [target], capabilities }) })
    expect(screen.queryByText(target.target)).not.toBeInTheDocument()
    expect(api.getNetworkAssets).toHaveBeenCalledWith('workspace-b', expect.objectContaining({ signal: expect.any(AbortSignal) }))
  })
})
