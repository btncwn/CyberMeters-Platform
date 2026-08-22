#!/usr/bin/env node
import { fetchMtaSts, mtaStsAdmission } from "../workers/scan-api/src/engines/email-intel.js";
import { buildEmailTransportDetails } from "../workers/scan-api/src/engines/email-analysis.js";

let passed = 0;
const ok = (name, value) => {
  if (!value) throw new Error(`FAIL ${name}`);
  passed += 1;
  console.log(`PASS ${name}`);
};
const originalFetch = globalThis.fetch;
const run = async (responseOrError) => {
  const fetcher = async () => {
    if (responseOrError instanceof Error) throw responseOrError;
    return responseOrError;
  };
  try { return await fetchMtaSts("example.com", { fetcher }); } finally { globalThis.fetch = originalFetch; }
};
const policy = () => new Response("version: STSv1\nmode: enforce\nmax_age: 86400\n", { status: 200 });

for (const [name, response, state, reason] of [
  ["200-valid-policy", policy(), "present", null],
  ["404-served", new Response("not found", { status: 404 }), "definitive_absent", "well_known_404"],
  ["503-origin", new Response("unavailable", { status: 503 }), "unavailable", "http_5xx"],
  ["transport", null, "unavailable", "transport_error"],
  ["timeout", Object.assign(new Error("timed out"), { name: "TimeoutError" }), "unavailable", "timeout"],
]) {
  const result = await run(response);
  ok(`${name}: observation state`, result.observation_state === state);
  ok(`${name}: reason`, result.reason === reason);
  const admission = mtaStsAdmission(result);
  ok(`${name}: score admission`, admission.score_admitted === (state === "present"));
  ok(`${name}: finding admission`, admission.missing_finding === (state === "definitive_absent"));
  ok(`${name}: remediation admission`, admission.remediation_admitted === (state === "definitive_absent"));
  const detail = buildEmailTransportDetails({ mta_sts: result });
  ok(`${name}: unavailable maps to incomplete`, state !== "unavailable" || detail.mta_sts_detail.coverage_state === "incomplete");
}

console.log(`mta-sts-tristate: ${passed} assertions passed`);
