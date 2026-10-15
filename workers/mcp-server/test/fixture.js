export const workspaceId = 'fixture-workspace-1';

export function fixtureSummary(overrides = {}) {
  return {
    workspace_id: workspaceId,
    display_name: 'Local Fixture Workspace',
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
