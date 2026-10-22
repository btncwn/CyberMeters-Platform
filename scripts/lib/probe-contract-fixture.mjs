// Test doubles must admit exactly the requests admitted by the real probe.
import assert from 'node:assert/strict';
import { validateNetworkProbeRequest } from '../../workers/network-probe/src/contract.js';
import { validateTlsAssessmentRequest } from '../../workers/network-probe/src/tls-contract.js';
import { validateExposureRequest } from '../../workers/network-probe/src/exposure-contract.js';
import { validateWebsiteContentRequest } from '../../workers/network-probe/src/website-content-contract.js';

export function assertProbeRequest(input, now = Date.now()) {
  const validate = input?.schema_version === 'tls-assessment-request-v1' ? validateTlsAssessmentRequest
    : input?.schema_version === 'exposure-request-v1' ? validateExposureRequest
    : input?.schema_version === 'website-content-request-v1' ? validateWebsiteContentRequest
    : validateNetworkProbeRequest;
  const verdict = validate(input, now);
  if (!verdict.ok) {
    // Production callers may catch a thrown collector error. Keep the fixture
    // process red even when that catch correctly returns an unavailable result.
    process.exitCode = 1;
    console.error('PROBE_CONTRACT', input?.schema_version, verdict.reason);
  }
  assert.equal(verdict.ok, true, `Probe request rejected: ${verdict.reason}`);
}

export function assertProbeFetch(init) {
  const input = JSON.parse(init.body);
  assertProbeRequest(input);
  return input;
}
