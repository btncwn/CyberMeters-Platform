import assert from 'node:assert/strict';
import { classifyPhpRuntime, phpRuntimeObservation, phpRuntimeFindings, evaluatePhpRuntimeCondition, PHP_UPSTREAM_FIXES } from '../../workers/scan-api/src/engines/php-runtime.js';
import { runTechModule } from '../../workers/scan-api/src/engines/tech-scan.js';
import { resolveRemediation } from '../../workers/scan-api/src/engines/remediation-registry.js';
import { describeRecurrenceEvent } from '../../workers/scan-api/src/engines/alert-consumers.js';

const counts = { tp: 0, fp: 0, tn: 0, fn: 0, unknown: 0 };
for (const [header, expected] of [
  ['PHP/8.5.11', 'outdated'], ['PHP/8.5.12', 'fixed'], ['PHP/8.5.13', 'fixed'],
  ['PHP/8.4.26', 'outdated'], ['PHP/8.4.27', 'fixed'], ['PHP/8.4.28', 'fixed'],
  ['PHP/8.3.35', 'outdated'], ['PHP/8.3.36', 'fixed'], ['PHP/8.3.37', 'fixed'],
  ['PHP/8.2.34', 'outdated'], ['PHP/8.2.35', 'fixed'], ['PHP/8.2.36', 'fixed'],
  ['PHP/8.1.99', 'outdated'], ['PHP/8.0.30', 'outdated'], ['PHP/7.4.33', 'outdated'],
  ['PHP/5.6.40', 'outdated'], ['PHP/8.2.34-1+deb12u1', 'outdated'],
  ['PHP/8.2.35-1+deb12u1', 'fixed'], ['PHP', 'hidden'], ['PHP; Express', 'hidden'],
  ['PHP-FPM', 'hidden'], ['PHP-CGI', 'hidden'], ['mod_php', 'hidden'],
  ['(PHP)', 'hidden'],
  ['PHP/8.2', 'unreadable'], ['PHP 8.2.34', 'unreadable'], ['PHP/8.2.35garbage', 'unreadable'],
  ['PHP/8.5.12RC1', 'unreadable'], ['PHP/8.5.12-dev', 'unreadable'],
  ['PHP (8.2.34)', 'unreadable'], ['PHP/08.2.35', 'unreadable'],
  ['PHP/8.6.0', 'unreadable'], ['PHP/9.0.0', 'unreadable'], ['PHP/8.4.27, PHP/8.2.34', 'unreadable'],
  ['PHP/8.4.27 PHP/8.2.34', 'unreadable'],
  ['PHP8.2.34', 'unreadable'], ['PHP:8.2.34', 'unreadable'], ['PHP-FPM/8.2.34', 'unreadable'],
  ['NotPHP/8.2.34', 'absent'], ['X-PHP/8.2.34', 'unreadable'], ['Apache/mod_php', 'unreadable'], ['Apache/2.4.63', 'absent'],
]) {
  const observation = phpRuntimeObservation({ poweredBy: header, url: 'https://example.com/shop/' });
  assert.equal(observation.state, expected, header);
  const findings = phpRuntimeFindings(observation);
  const actionable = findings.some(f => f.finding_type === 'finding');
  const truth = expected === 'outdated';
  if (expected === 'unreadable') counts.unknown++;
  else if (actionable) counts[truth ? 'tp' : 'fp']++;
  else counts[truth ? 'fn' : 'tn']++;
  assert.equal(actionable, truth, header);
  if (truth) {
    assert.equal(findings[0].description, `Your website reports PHP version ${observation.reported_version}, which is older than the release that fixes the critical PHP2Shell vulnerabilities (CVE-2026-109618, CVE-2026-109619). Update PHP, or confirm with your hosting provider that their patched build is installed.`);
    assert.equal(findings[0].score_impact, 0);
    assert.equal(resolveRemediation({ finding_type: findings[0].id }).case_type, 'website_case');
  }
  if (expected === 'hidden') {
    assert.equal(findings[0].description, 'Your website appears to run on PHP. Its version is not visible from outside, so confirm with your hosting provider that PHP has been updated for the PHP2Shell vulnerabilities.');
    const remediation = resolveRemediation({ finding_type: findings[0].id });
    assert.equal(remediation.case_type, null);
    assert.equal(remediation.managed_workflow_compatible, false);
  }
}
assert.equal(classifyPhpRuntime({ server: 'Apache/2.4.63 (Unix) PHP/8.2.34' }).state, 'outdated');
assert.equal(classifyPhpRuntime({ poweredBy: 'PHP/8.2.35', server: 'PHP/8.2.34' }).state, 'unreadable');
assert.equal(classifyPhpRuntime({ poweredBy: 'PHP/' + '8'.repeat(2100) }).state, 'unreadable');
assert.equal(classifyPhpRuntime({ poweredBy: 'PHP/8.2.34\nInjected' }).state, 'unreadable');
assert(PHP_UPSTREAM_FIXES.every(row => row.advisory === 'https://www.php.net/archive/2026.php#2026-10-21-5'));
const old = phpRuntimeObservation({ poweredBy: 'PHP/8.2.34', url: 'https://example.com/shop/' });
assert.equal(describeRecurrenceEvent('website_security', 'reported_runtime_outdated', 'example.com', { php_runtime: old }), phpRuntimeFindings(old)[0].description);
for (const [poweredBy, url, expected] of [
  ['PHP/8.2.34', 'https://example.com/shop/', 'present'],
  ['PHP/8.2.35', 'https://example.com/shop/', 'clear'],
  [null, 'https://example.com/shop/', 'clear'],
  ['PHP', 'https://example.com/shop/', 'deferred'],
  ['PHP-FPM', 'https://example.com/shop/', 'deferred'],
  ['PHP/8.2', 'https://example.com/shop/', 'deferred'],
  ['PHP/8.6.0', 'https://example.com/shop/', 'deferred'],
  ['PHP/8.2.35', 'https://example.com/elsewhere/', 'deferred'],
  ['PHP/8.2.35', 'https://other.example.com/shop/', 'deferred'],
  ['PHP/8.2.35', 'http://example.com/shop/', 'deferred'],
]) {
  const tech = { php_runtime: phpRuntimeObservation({ poweredBy, url }), serviceability_contract: { serviceable: true } };
  assert.equal(evaluatePhpRuntimeCondition(old.condition_key, tech).state, expected);
  assert.equal(evaluatePhpRuntimeCondition(old.condition_key, { ...tech, incomplete: true }).state, 'deferred');
}

// Drive the real technology response path. One existing homepage GET; edge and
// origin errors/access restrictions can neither report PHP nor clear a case.
const realFetch = globalThis.fetch;
try {
  for (const status of [200, 401, 403, 404, 429, 500, 503, 530]) {
    let calls = 0;
    globalThis.fetch = async () => {
      calls++;
      const response = new Response('<html>ordinary page</html>', { status, headers: { 'x-powered-by': 'PHP/8.2.34', 'content-type': 'text/html' } });
      Object.defineProperty(response, 'url', { value: 'https://example.com/shop/' });
      return response;
    };
    const result = await runTechModule('example.com');
    assert.equal(calls, 1, 'no additional request');
    assert.equal(result.info_findings.some(f => f.id.startsWith('tech_php2shell_')), status === 200);
    if (status !== 200) assert.equal(evaluatePhpRuntimeCondition(old.condition_key, result).state, 'deferred');
  }
  globalThis.fetch = async () => {
    const response = new Response('ordinary page', { headers: { 'x-powered-by': 'PHP/8.2.34' } });
    Object.defineProperty(response, 'url', { value: 'https://unrelated.example.net/' });
    return response;
  };
  const outOfScope = await runTechModule('example.com');
  assert.equal(outOfScope.php_runtime.state, 'unreadable');
  assert(!outOfScope.info_findings.some(f => f.id.startsWith('tech_php2shell_')));
} finally { globalThis.fetch = realFetch; }
assert.equal(counts.fp, 0); assert.equal(counts.fn, 0);
console.log('php-runtime controlled truth: ' + JSON.stringify(counts));
