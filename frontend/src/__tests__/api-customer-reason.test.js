import { afterEach, expect, it, vi } from 'vitest'
import { api } from '../api'

afterEach(() => vi.unstubAllGlobals())

it.each(['list', 'export'])('translates audit-log plan errors on %s without changing API codes', async path => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
    error: 'plan_feature_required', feature: 'audit_logs', required_plan: 'professional', upgrade_url: '/billing',
  }), { status: 403, headers: { 'content-type': 'application/json' } })))
  const operation = path === 'list' ? api.getWorkspaceAuditEvents('ws-1') : api.exportWorkspaceAuditEvents('ws-1')
  await expect(operation).rejects.toMatchObject({
    message: 'Upgrade your plan to use audit logs.',
    error: 'plan_feature_required', feature: 'audit_logs', required_plan: 'professional', upgrade_url: '/billing',
  })
})
