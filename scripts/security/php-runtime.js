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
    assert.equal(findings[0].title, 'Website reports a PHP version older than the PHP2Shell fix');
    assert.equal(findings[0].severity, 'high');
    assert.equal(findings[0].score_impact, 0);
    const remediation = resolveRemediation({ finding_type: findings[0].id });
    assert.equal(remediation.customer_title, findings[0].title);
    assert.equal(remediation.technical_explanation, findings[0].title);
    assert.equal(remediation.business_impact, 'The NCSC warned on 21 October 2026 about two critical flaws in PHP itself that can allow code to be run on a web server without signing in; they are being exploited.');
    assert(remediation.recommended_action.startsWith('Update PHP, or confirm with your hosting provider that their patched build is installed.'));
    assert.equal(resolveRemediation({ finding_type: findings[0].id }).case_type, 'website_case');
  }
  if (expected === 'hidden') {
    assert.equal(findings[0].description, 'Your website appears to run on PHP. Its version is not visible from outside, so confirm with your hosting provider that PHP has been updated for the PHP2Shell vulnerabilities.');
    const remediation = resolveRemediation({ finding_type: findings[0].id });
    assert.equal(findings[0].title, 'Website runs on PHP; version not visible');
    assert.equal(findings[0].severity, 'info');
    assert.equal(findings[0].score_impact, 0);
    assert.equal(findings[0].finding_type, 'observation');
    assert.equal(remediation.customer_title, findings[0].title);
    assert.equal(remediation.business_impact, 'The NCSC warned on 21 October 2026 about two critical flaws in PHP itself that can allow code to be run on a web server without signing in; they are being exploited.');
    for (const field of ['technical_explanation', 'recommended_action']) {
      assert.equal(remediation[field], findings[0].description, field);
    }
    assert.equal(remediation.case_type, null);
    assert.equal(remediation.managed_workflow_compatible, false);
  }
}
// Temporary advice is canonical copy only; it cannot establish a patched build
// or change the existing passive recheck contract.
const temporaryAdvice = resolveRemediation({ finding_type: 'tech_php2shell_outdated' });
assert.equal(temporaryAdvice.version, 2);
for (const setting of ['memory_limit=-1', 'php_admin_value', 'post_max_size=8M', 'post_max_size=32M',
  'upload_max_filesize', 'session.upload_progress.enabled=0', 'fatal_error_backtraces=0']) {
  assert(temporaryAdvice.recommended_action.includes(setting), `official temporary guidance: ${setting}`);
}
assert.match(temporaryAdvice.recommended_action, /PHP 8\.5[^.]*fatal_error_backtraces=0/);
assert.match(temporaryAdvice.recommended_action, /Restart all workers/);
assert.match(temporaryAdvice.recommended_action, /container\/cgroup/);
assert.match(temporaryAdvice.recommended_action, /not RLIMIT_AS or RLIMIT_DATA/);
assert.match(temporaryAdvice.recommended_action, /ini_set\(\).*FPM \.user\.ini/);
assert.match(temporaryAdvice.recommended_action, /only complete fix.*customer-asserted.*cannot verify/);
assert.match(temporaryAdvice.limitations.join(' '), /temporary.*updating.*complete fix/i);
assert.match(temporaryAdvice.limitations.join(' '), /customer-asserted.*cannot verify/i);
assert(temporaryAdvice.limitations.includes('Only the reported version is compared. Backported fixes and the actual installed build cannot be verified remotely. This is not a claim of vulnerability or exploitability.'));
assert.equal(temporaryAdvice.verification_method, 'https_recheck');
assert.equal(temporaryAdvice.verification_evidence_requirements, 'A serviceable response at the exact original HTTPS host and path reports a fixed upstream release, or no longer reports PHP. A hidden, ambiguous or unsupported version is inconclusive.');
assert.deepEqual(temporaryAdvice.references, [PHP_UPSTREAM_FIXES[0].advisory]);
for (const surface of ['scan_detail', 'scorecard', 'executive_report', 'pdf', 'managed_case']) {
  const resolved = resolveRemediation({ finding_type: 'tech_php2shell_outdated', surface });
  assert.equal(resolved.recommended_action, temporaryAdvice.recommended_action, surface);
  assert.deepEqual(resolved.limitations, temporaryAdvice.limitations, surface);
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
