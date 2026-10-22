// S3-B TLS gating: safe-active vs intrusive classification, the planner never
// schedules an intrusive control without an Active Checks grant AND a released
// engine, and an unauthorised control is stated without making TLS partial.
// Imported by validate-deep-tls-contract.js.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { TLS_CONTROLS, TLS_SAFE_ACTIVE_CONTROLS, TLS_INTRUSIVE_CONTROLS, TLS_AUTHORISATION_REQUIRED_REASON, TLS_AUTHORISED_NOT_RELEASED_REASON } from '../shared/tls/catalog.js';
import { buildBudgetedTlsCheckPlan } from '../workers/scan-api/src/engines/tls-planner.js';
import { blockingTlsNotAuthorized, blockingTlsUnexecutable } from '../workers/scan-api/src/engines/tls-quality.js';

assert.deepEqual([...TLS_INTRUSIVE_CONTROLS].sort(), ['ccs', 'heartbleed', 'robot']);
assert.equal(TLS_SAFE_ACTIVE_CONTROLS.some((control) => TLS_INTRUSIVE_CONTROLS.includes(control)), false);
assert.deepEqual([...TLS_SAFE_ACTIVE_CONTROLS, ...TLS_INTRUSIVE_CONTROLS].sort(), [...TLS_CONTROLS].sort());
for (const safe of ['protocol', 'cipher', 'key_exchange', 'fallback_scsv', 'compression', 'secure_renegotiation']) assert.ok(TLS_SAFE_ACTIVE_CONTROLS.includes(safe));

const endpoint = (special_checks = {}) => ({
  endpoint: { hostname: 'example.com', sni: 'example.com', address: '81.2.69.160', port: 443, transport: 'tcp', application_protocol: 'https' },
  endpoint_identity: 'ep-1', scope: { kind: 'standard_https', special_consent: Object.keys(special_checks).length > 0, special_checks },
});
const plan = (special_checks) => buildBudgetedTlsCheckPlan({ endpoints: [endpoint(special_checks)], observedHttpsHosts: ['example.com'], scanId: 'scan_t' });
const intrusiveSelected = (p) => p.selected.filter((row) => TLS_INTRUSIVE_CONTROLS.includes(row.check.control));

const none = plan({});
assert.equal(intrusiveSelected(none).length, 0, 'no grant: no intrusive control planned');
assert.ok(none.selected.length > 0, 'safe-active controls still planned');
const stated = none.static_results.filter((row) => TLS_INTRUSIVE_CONTROLS.includes(row.check.control));
assert.equal(stated.length, 3);
assert.ok(stated.every((row) => row.state === 'not_authorized' && row.reason === TLS_AUTHORISATION_REQUIRED_REASON));
// Even a recorded grant cannot plan them while the engine is not released.
assert.equal(intrusiveSelected(plan({ heartbleed: 'acc_1', robot: 'acc_2', ccs: 'acc_3' })).length, 0, 'unreleased engine: never planned');

// A grant with the engine withheld reads "Authorised — not yet available".
const grantedEndpoint = { ...endpoint(), scope: { ...endpoint().scope, granted_checks: { heartbleed: 'acc_1' } } };
const granted = buildBudgetedTlsCheckPlan({ endpoints: [grantedEndpoint], observedHttpsHosts: ['example.com'], scanId: 'scan_t' });
const heartbleedRow = granted.static_results.find((row) => row.check.control === 'heartbleed');
assert.equal(heartbleedRow?.state, 'unexecutable');
assert.equal(heartbleedRow?.reason, TLS_AUTHORISED_NOT_RELEASED_REASON);
assert.equal(granted.static_results.find((row) => row.check.control === 'robot')?.reason, TLS_AUTHORISATION_REQUIRED_REASON);
assert.equal(intrusiveSelected(granted).length, 0, 'a grant alone never plans an intrusive control');
assert.equal(blockingTlsUnexecutable(granted.static_results), 0, 'authorised-but-unreleased never makes TLS partial');

// Quality: the stated rows never make TLS partial; a lost authority still does.
assert.equal(blockingTlsNotAuthorized(stated), 0);
assert.equal(blockingTlsNotAuthorized([...stated, { state: 'not_authorized', reason: 'scope_changed' }]), 1);

// Mutation proof.
const plannerSource = readFileSync(new URL('../workers/scan-api/src/engines/tls-planner.js', import.meta.url), 'utf8');
const qualitySource = readFileSync(new URL('../workers/scan-api/src/engines/tls-quality.js', import.meta.url), 'utf8');
const relink = (text, from) => text.replace(/from '(\.{1,2}\/[^']+)'/g, (_m, spec) => `from '${new URL(spec, from)}'`);
const MUTANTS = [
  { name: 'engine release no longer required', file: 'tls-planner.js', source: plannerSource,
    from: "if(TLS_SPECIAL_CONTROLS_AVAILABLE&&entry.scope?.special_checks?.[control])", to: "if(entry.scope?.special_checks?.[control])",
    caught: (m) => m.buildBudgetedTlsCheckPlan({ endpoints: [endpoint({ heartbleed: 'acc_1' })], observedHttpsHosts: ['example.com'], scanId: 'scan_t' })
      .selected.some((row) => row.check.control === 'heartbleed') },
  { name: 'a recorded grant ignored while the engine is withheld', file: 'tls-planner.js', source: plannerSource,
    from: "else if(entry.scope?.granted_checks?.[control]||entry.scope?.special_checks?.[control])", to: "else if(false)",
    caught: (m) => m.buildBudgetedTlsCheckPlan({ endpoints: [grantedEndpoint], observedHttpsHosts: ['example.com'], scanId: 'scan_t' })
      .static_results.find((row) => row.check.control === 'heartbleed')?.reason === TLS_AUTHORISATION_REQUIRED_REASON },
  { name: 'unauthorised intrusive control counted as a gap', file: 'tls-quality.js', source: qualitySource,
    from: "&& row.reason !== TLS_AUTHORISATION_REQUIRED_REASON", to: '',
    caught: (m) => m.blockingTlsNotAuthorized(stated) > 0 },
];
const directory = mkdtempSync(join(tmpdir(), 'cm-tls-gating-mutation-'));
try {
  let index = 0;
  for (const mutant of MUTANTS) {
    assert.equal(mutant.source.split(mutant.from).length, 2, `mutation anchor present once: ${mutant.name}`);
    const base = new URL(`../workers/scan-api/src/engines/${mutant.file}`, import.meta.url);
    const target = join(directory, `tls-gating-mutant-${++index}.mjs`);
    writeFileSync(target, relink(mutant.source.replace(mutant.from, mutant.to), base));
    assert.equal(mutant.caught(await import(`file://${target}`)), true, `mutant caught: ${mutant.name}`);
  }
} finally { rmSync(directory, { recursive: true, force: true }); }
console.log(`tls gating: classification, planner gate, stated rows, quality and ${MUTANTS.length} mutants passed`);
