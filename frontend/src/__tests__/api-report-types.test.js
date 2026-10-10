import { afterEach, expect, it, vi } from 'vitest'
import { api } from '../api'

afterEach(() => vi.unstubAllGlobals())

it('sends the selected scan only for Scan Snapshot', async () => {
  const fetchMock = vi.fn().mockImplementation(async () => new Response(JSON.stringify({ report: { id: 'report-a' } }), { headers: { 'Content-Type': 'application/json' } }))
  vi.stubGlobal('fetch', fetchMock)
  await api.generateWorkspaceReport('workspace-a', 'scan_snapshot', 'scan-a')
  expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ report_type: 'scan_snapshot', scan_id: 'scan-a' })
  await api.generateWorkspaceReport('workspace-a', 'weekly_executive', 'scan-a')
  expect(JSON.parse(fetchMock.mock.calls[1][1].body)).toEqual({ report_type: 'weekly_executive' })
})
