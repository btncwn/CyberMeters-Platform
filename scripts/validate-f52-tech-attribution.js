#!/usr/bin/env node
import { runTechModule } from "../workers/scan-api/src/engines/tech-scan.js";
import { deriveAttackSurfaceSignalCompleteness } from "../workers/scan-api/src/engines/attack-surface-signal-completeness.js";
import { isResolverVersionAtLeast, CYBER_MOT_RESOLVER_VERSION } from "../workers/scan-api/src/engines/cyber-mot-domains.js";

let passed = 0;
const ok = (name, value) => {
  if (!value) throw new Error(`FAIL ${name}`);
  passed += 1;
  console.log(`PASS ${name}`);
};
const originalFetch = globalThis.fetch;
const run = async (response) => {
  globalThis.fetch = async () => response;
  try { return await runTechModule("example.com"); } finally { globalThis.fetch = originalFetch; }
};
const origin = (status, headers = {}, body = "<html><body>ok</body></html>") =>
  new Response(body, { status, headers: { server: "nginx/1.25", ...headers } });

for (const [name, response, unavailable] of [
  ["serviceable-with-tech", origin(200, { "x-powered-by": "PHP/8.2" }), false],
  ["serviceable-empty", origin(200), false],
  ["origin-503", origin(503, { server: "nginx/1.25" }), true],
  ["transport", null, true],
]) {
  const result = await run(response);
  ok(`${name}: marker state`, unavailable ? result.observation_state === "unavailable" : result.observation_state === undefined);
  ok(`${name}: technologies cleared on unavailable`, !unavailable || result.technologies.length === 0);
  ok(`${name}: server cleared on unavailable`, !unavailable || result.server === null);
  if (unavailable) {
    ok(`${name}: incomplete reason`, result.incomplete_reason);
    const signals = deriveAttackSurfaceSignalCompleteness({ technology_detection: result });
    ok(`${name}: resolver is incomplete`, signals.signals.technology.state === "incomplete");
    ok(`${name}: CVE/KEV do not admit input`, signals.signals.cve.state !== "observed" && signals.signals.kev.state !== "observed");
  }
}

// Stored legacy backstop: marker must win even when stale values survive.
const legacy = deriveAttackSurfaceSignalCompleteness({ technology_detection: {
  technologies: ["nginx"], server: "nginx/1.25", status_code: 503,
  observation_state: "unavailable", incomplete: true, incomplete_reason: "origin_error_no_serviceable_response",
} });
ok("stored legacy non-empty value cannot bypass marker", legacy.signals.technology.state === "incomplete");
ok("resolver successor is not read as legacy", isResolverVersionAtLeast(CYBER_MOT_RESOLVER_VERSION));
ok("predecessor remains below successor boundary", !isResolverVersionAtLeast("2026-08-12.1"));
console.log(`f52-tech-attribution: ${passed} assertions passed`);
