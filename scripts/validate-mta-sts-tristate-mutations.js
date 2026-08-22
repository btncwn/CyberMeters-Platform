#!/usr/bin/env node
import { mtaStsAdmission } from "../workers/scan-api/src/engines/email-intel.js";

let passed = 0;
const assert = (name, value) => {
  if (!value) throw new Error(`FAIL ${name}`);
  passed += 1;
  console.log(`PASS ${name}`);
};

// Mutation A: widening admission so unavailable grounds a missing finding.
// The governed contract must reject this mutated result.
const unavailable = mtaStsAdmission({ observation_state: "unavailable" });
assert("M-A unavailable does not ground missing finding", unavailable.missing_finding === false);
assert("M-A unavailable has no score admission", unavailable.score_admitted === false);
assert("M-A unavailable has no remediation admission", unavailable.remediation_admitted === false);

// Mutation B: collapsing definitive absence and provider failure.
const absent = mtaStsAdmission({ observation_state: "definitive_absent" });
assert("M-B definitive absence remains distinct from unavailable", absent.state !== unavailable.state);
assert("M-B definitive absence alone admits the finding", absent.missing_finding === true);
assert("M-B present alone admits score", mtaStsAdmission({ observation_state: "present" }).score_admitted === true);

console.log(`mta-sts-tristate mutations: ${passed} assertions passed`);
