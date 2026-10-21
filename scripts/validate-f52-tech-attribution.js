#!/usr/bin/env node
import { runTechModule } from "../workers/scan-api/src/engines/tech-scan.js";
import { deriveAttackSurfaceSignalCompleteness } from "../workers/scan-api/src/engines/attack-surface-signal-completeness.js";
import { isResolverVersionAtLeast, SECURITY_CHECK_RESOLVER_VERSION, FIRST_HONEST_RESOLVER_VERSION } from "../workers/scan-api/src/engines/security-check-domains.js";
import { projectIdentitySnapshotForCustomer } from "../workers/scan-api/src/engines/phase5-evidence.js";

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

// The reason TOKEN is pinned per case, not merely asserted truthy. The two
// unavailable cases are different customer stories and carry different tokens:
// an origin that answered without serving vs an origin that never answered.
// Truthiness alone let a mutant collapse the first into the second and survive.
for (const [name, response, unavailable, expectedReason] of [
  ["serviceable-with-tech", origin(200, { "x-powered-by": "PHP/8.2" }), false, null],
  ["serviceable-empty", origin(200), false, null],
  ["origin-503", origin(503, { server: "nginx/1.25" }), true, "origin_error_no_serviceable_response"],
  // Family B: an access restriction is incomplete with its own reason — never
  // complete, never "no technology observed".
  ["access-401", origin(401), true, "origin_access_restricted"],
  ["access-403", origin(403, { server: "AkamaiGHost" }), true, "origin_access_restricted"],
  ["challenge-403", new Response("<html><title>Just a moment...</title></html>", { status: 403,
    headers: { server: "cloudflare", "cf-ray": "8f00000000000000-LHR", "cf-mitigated": "challenge", "content-type": "text/html" } }),
    true, "origin_access_restricted"],
  ["transport", null, true, "origin_not_observed"],
]) {
  const result = await run(response);
  ok(`${name}: marker state`, unavailable ? result.observation_state === "unavailable" : result.observation_state === undefined);
  ok(`${name}: technologies cleared on unavailable`, !unavailable || result.technologies.length === 0);
  ok(`${name}: server cleared on unavailable`, !unavailable || result.server === null);
  if (unavailable) {
    ok(`${name}: never complete`, result.incomplete === true);
    ok(`${name}: incomplete reason is exactly ${expectedReason}`,
      result.incomplete_reason === expectedReason);
    ok(`${name}: the two unavailable reasons stay distinguishable`,
      result.incomplete_reason !== (expectedReason === "origin_not_observed"
        ? "origin_error_no_serviceable_response" : "origin_not_observed"));
    const signals = deriveAttackSurfaceSignalCompleteness({ technology_detection: result });
    ok(`${name}: resolver is incomplete`, signals.signals.technology.state === "incomplete");
    // No signal reads outside vulnerability data any more (check-pack.js), so
    // an unavailable technology result can feed none.
    ok(`${name}: no vulnerability-data signal exists to admit input`, !("cve" in signals.signals) && !("kev" in signals.signals));
  }
}

// Stored legacy backstop: marker must win even when stale values survive.
const legacy = deriveAttackSurfaceSignalCompleteness({ technology_detection: {
  technologies: ["nginx"], server: "nginx/1.25", status_code: 503,
  observation_state: "unavailable", incomplete: true, incomplete_reason: "origin_error_no_serviceable_response",
} });
ok("stored legacy non-empty value cannot bypass marker", legacy.signals.technology.state === "incomplete");
ok("resolver successor is not read as legacy", isResolverVersionAtLeast(SECURITY_CHECK_RESOLVER_VERSION));
ok("predecessor remains below successor boundary", !isResolverVersionAtLeast("2026-08-12.1"));
// ── FIXED HONESTY FLOOR (P1.2-C successor) ─────────────────────────────────
// The projection must key on a FIXED point in history, not on the moving current
// resolver. Executed proof of the defect this replaces: a snapshot stamped
// 2026-08-12.1 with an `assessed_healthy` identity conclusion was rewritten to
// `evidence_insufficient` and told the customer "Identity reachability was not
// evaluated by a supported producer" — false about that snapshot.
ok("honest floor is a fixed constant, not the moving current version",
  FIRST_HONEST_RESOLVER_VERSION === "2026-08-12.1");
ok("the floor is NOT the moving resolver constant",
  FIRST_HONEST_RESOLVER_VERSION !== SECURITY_CHECK_RESOLVER_VERSION);
{
  const snap = (v) => ({
    methodology: { cyber_mot_resolver_version: v },
    domains: [{ domain_key: "identity_exposure", state: "assessed_healthy", coverage: "complete" }],
  });
  const stateFor = (v) => projectIdentitySnapshotForCustomer(snap(v), {})
    .domains.find((d) => d.domain_key === "identity_exposure").state;
  ok("F52_FLOOR_HONEST_PREDECESSOR_STAYS_HEALTHY", stateFor("2026-08-12.1") === "assessed_healthy");
  ok("F52_FLOOR_CURRENT_VERSION_STAYS_HEALTHY", stateFor(SECURITY_CHECK_RESOLVER_VERSION) === "assessed_healthy");
  // The projection must still BITE below the floor — the fix corrects where the
  // boundary sits, it does not switch the projection off.
  ok("F52_FLOOR_GENUINELY_LEGACY_STILL_PROJECTED", stateFor("2026-07-16.1") === "evidence_insufficient");
  ok("F52_FLOOR_UNSTAMPED_STILL_PROJECTED", stateFor(null) === "evidence_insufficient");
}
console.log(`f52-tech-attribution: ${passed} assertions passed`);
