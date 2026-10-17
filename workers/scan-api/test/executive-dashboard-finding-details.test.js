import assert from 'node:assert/strict';
import { test } from 'node:test';
import { withEvidenceFreshness } from '../src/routes/executive-dashboard.js';

test('latest assessment finding IDs receive registry detail without changing the resolver state', () => {
  const [entry] = withEvidenceFreshness([{
    domain_key: 'email_protection', state: 'issue_detected', source_scan_id: 'scan_1',
    finding_ids: ['email_missing_spf', 'unmapped_internal_key'],
  }]);
  assert.equal(entry.state, 'issue_detected');
  assert.equal(entry.source_scan_id, 'scan_1');
  assert.deepEqual(entry.finding_details.map((detail) => detail.finding_id), ['email_missing_spf', 'unmapped_internal_key']);
  assert.equal(entry.finding_details[0].status, 'resolved');
  assert.ok(entry.finding_details[0].customer_title);
  assert.ok(entry.finding_details[0].recommended_action);
  assert.ok(entry.finding_details[0].owner_type);
  assert.equal(entry.finding_details[1].status, 'unmapped');
  assert.equal(entry.finding_details[1].recommended_action, undefined);
});
