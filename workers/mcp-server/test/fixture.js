export const workspaceId = 'fixture-workspace-1';
export const scanId = 'scan_fixture_1';

export const domainKeys = [
  'email_protection', 'brand_protection', 'attack_surface', 'certificates_trust',
  'cyber_essentials_readiness', 'website_security', 'identity_exposure',
  'shadow_it_unmanaged_technology',
];
const domainNames = [
  'Email Protection', 'Brand Protection', 'Attack Surface', 'Certificates & Trust',
  'Cyber Essentials Readiness', 'Website Security', 'Identity Exposure',
  'Shadow IT & Unmanaged Technology',
];

export function fixtureWorkspaces(overrides = {}) {
  return { workspaces: [{ workspace_id: workspaceId, display_name: 'Local Fixture Workspace',
    role: 'owner', private_note: 'fixture-note-must-not-escape' }],
  count: 1, secret: 'fixture-secret-must-not-escape', ...overrides };
}

export function fixturePosture(overrides = {}) {
  return { workspace_id: workspaceId, source_scan_id: scanId,
    domains: domainKeys.map((domain_key, index) => ({
      domain_key, display_name: domainNames[index],
      state: 'evidence_insufficient', evidence_strength: 'insufficient',
      coverage: 'partial', last_assessed_at: '2026-10-15T10:00:00Z',
      limitations: ['Evidence is incomplete for this domain.'],
      private_note: 'fixture-note-must-not-escape',
    })), secret: 'fixture-secret-must-not-escape', ...overrides };
}

export function fixtureScan(overrides = {}) {
  return { scan_id: scanId, domain: 'example.invalid', status: 'completed',
    scan_quality: 'partial',
    assessment: { quality: 'partial', authoritative: false, provisional: true, comparable: false },
    measured_at: '2026-10-15T10:00:00Z', score_available: false,
    raw_report: 'fixture-raw-must-not-escape', ...overrides };
}

export function fixtureCases(overrides = {}) {
  return { workspace_id: workspaceId, cases: [{ case_id: 'case_fixture_1',
    domain_key: 'email_protection', canonical_phase: 'detected', severity: 'high',
    verification_support: 'manual', created_at: '2026-10-15T10:00:00Z',
    updated_at: '2026-10-15T10:00:00Z', verified_at: null,
    assigned_user_id: 'fixture-owner-must-not-escape', title: 'fixture-title-must-not-escape',
    notes: 'fixture-note-must-not-escape' }], limit: 10, has_more: false, ...overrides };
}

export function fixtureSummary(overrides = {}) {
  return {
    workspace_id: workspaceId,
    display_name: 'Local Fixture Workspace',
    domain_count: 1,
    open_case_count: 1,
    score_state: 'assessed',
    score_value: 73,
    latest_measurement_at: '2026-10-15T10:00:00Z',
    evidence_state: 'authoritative',
    coverage_state: 'complete',
    limitations: ['Two domains have incomplete evidence.'],
    bearer: 'fixture-bearer-must-not-escape',
    secret: 'fixture-secret-must-not-escape',
    email: 'fixture@example.invalid',
    owner_id: 'fixture-owner-must-not-escape',
    raw_response: 'fixture-raw-must-not-escape',
    private_note: 'fixture-note-must-not-escape',
    ...overrides,
  };
}
