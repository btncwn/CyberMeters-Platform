import assert from 'node:assert/strict';
import { test } from 'node:test';
import { executiveDashboardRoutes } from '../src/routes/executive-dashboard.js';

async function readActivity(filter) {
  const calls = [];
  const url = new URL(`https://example.test/api/workspaces/ws-1/activity?event_type=${encodeURIComponent(filter)}`);
  const response = await executiveDashboardRoutes({
    request: new Request(url), url,
    env: { cybermeters_db: { prepare(sql) { return { bind(...values) {
      calls.push({ sql, values });
      return { all: async () => ({ results: [] }) };
    } }; } } },
    json: value => new Response(JSON.stringify(value)),
    serverError: (_where, error) => { throw error; },
    requireAuth: async () => ({ id: 'user-1' }),
    requireWorkspaceRole: async () => ({ role: 'owner' }),
  });
  assert.equal(response.status, 200);
  return calls;
}

test('one Cyber Essentials filter includes both historical event names', async () => {
  const [query] = await readActivity('cyber_essentials_alerts');
  assert.match(query.sql, /event_type IN \(\?, \?\)/);
  assert.deepEqual(query.values, ['ws-1', 'cyber_essentials_alert', 'cyber_essentials_readiness_alert', 50, 0]);
});

test('one Shadow IT filter includes both historical event names', async () => {
  const [query] = await readActivity('shadow_it_alerts');
  assert.match(query.sql, /event_type IN \(\?, \?\)/);
  assert.deepEqual(query.values, ['ws-1', 'shadow_it_alert', 'shadow_it_unmanaged_technology_alert', 50, 0]);
});

test('other activity filters retain exact matching and tenant scope', async () => {
  const [query] = await readActivity('scan_completed');
  assert.match(query.sql, /workspace_id = \? AND event_type = \?/);
  assert.deepEqual(query.values, ['ws-1', 'scan_completed', 50, 0]);
});
