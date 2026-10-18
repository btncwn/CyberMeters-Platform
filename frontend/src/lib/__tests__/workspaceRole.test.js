import { roleCan, canScanNewDomain, canRescanVerifiedDomain, scanAccessFor, activeWorkspaceRole, scanNotPermittedMessage, RESCAN_ONLY_MESSAGE, isForbidden } from '../workspaceRole'

// One frontend rule for what a workspace role is offered; the backend matrix is
// mirrored exactly (validate-security-contracts.js checks every role/permission).

describe('workspace role rule', () => {
  it('mirrors the backend minimum roles', () => {
    expect(['viewer', 'analyst', 'admin', 'owner'].map((r) => roleCan(r, 'domain:add'))).toEqual([false, false, true, true])
    expect(['viewer', 'analyst', 'admin', 'owner'].map((r) => roleCan(r, 'scan:create'))).toEqual([false, true, true, true])
    expect(['viewer', 'analyst', 'admin', 'owner'].map((r) => roleCan(r, 'domain:remove'))).toEqual([false, false, true, true])
    expect(roleCan('superuser', 'domain:add')).toBeNull()
    expect(roleCan('owner', 'workspace:obliterate')).toBeNull()
  })
  it('offers scanning a new domain only to admins and owners; an unknown role keeps the old UI', () => {
    expect(canScanNewDomain('viewer')).toBe(false)
    expect(canScanNewDomain('analyst')).toBe(false)
    expect(canScanNewDomain('admin')).toBe(true)
    expect(canScanNewDomain('OWNER')).toBe(true)
    expect(canScanNewDomain(null)).toBe(true)
  })
  it('an analyst rescans verified domains; a viewer has no scan action', () => {
    expect(['viewer', 'analyst', 'admin', 'owner'].map(canRescanVerifiedDomain)).toEqual([false, true, true, true])
    expect(['viewer', 'analyst', 'admin', 'owner'].map(scanAccessFor)).toEqual(['none', 'rescan', 'full', 'full'])
    expect(scanAccessFor(null)).toBe('full')
    expect(RESCAN_ONLY_MESSAGE).toBe('Only workspace admins can add new domains. You can rescan domains this workspace has already verified.')
  })
  it('reads the role for the active workspace', () => {
    const list = [{ id: 'a', role: 'owner' }, { id: 'b', role: 'Analyst' }]
    expect(activeWorkspaceRole(list, 'b')).toBe('analyst')
    expect(activeWorkspaceRole(list, 'c')).toBeNull()
    expect(activeWorkspaceRole(null, 'a')).toBeNull()
  })
  it('one plain sentence, naming the owner when known', () => {
    expect(scanNotPermittedMessage('Taylor Owner')).toBe('Only workspace admins can add domains and start scans. Ask Taylor Owner if you need one scanned.')
    expect(scanNotPermittedMessage(null)).toBe('Only workspace admins can add domains and start scans. Ask the workspace owner if you need one scanned.')
  })
  it('recognises a refusal by status or by the server wording', () => {
    expect(isForbidden({ status: 403 })).toBe(true)
    expect(isForbidden({ message: 'Forbidden — admin role required to add domains' })).toBe(true)
    expect(isForbidden({ status: 500, message: 'Internal error' })).toBe(false)
    expect(isForbidden(null)).toBe(false)
  })
  it('a coded 403 is not a role refusal (verification, plan or domain limit keep their own handling)', () => {
    expect(isForbidden({ status: 403, code: 'domain_verification_required', message: 'Verify domain ownership before starting a Cyber MOT.' })).toBe(false)
    expect(isForbidden({ status: 403, code: 'trial_domain_limit', message: 'Your trial includes one domain.' })).toBe(false)
    expect(isForbidden({ status: 403, code: 'x', message: 'Forbidden — admin role required' })).toBe(true)
  })
})
