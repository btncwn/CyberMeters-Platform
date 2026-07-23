#!/usr/bin/env node
//
// Item 5 / PR-5.3: the shared per-scan CT lookup has provider-specific timeouts,
// one bounded transient retry, scan-budget enforcement, and R2-only provider
// health telemetry. Includes executable attempt-cap, deadline, and false-empty
// mutations. CI-blocking. Requires Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
const root = path.join(path.dirname(scriptPath), "..");
const enginePath = (...parts) => path.join(
  root, "workers", "scan-api", "src", "engines", ...parts
);
const engineUrl = (file) => pathToFileURL(enginePath(file)).href;

const {
  createCertificateTransparencyCache,
  CT_PROVIDER_HARD_ATTEMPT_CAP,
  CT_PROVIDER_POLICIES,
} = await import(engineUrl("ct-provider-cache.js"));
const { buildExecutionDiagnostics } = await import(engineUrl("scan-budget.js"));

let pass = 0;
let fail = 0;
const ok = (name, condition, detail = "") => {
  condition ? pass++ : fail++;
  if (!condition) console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
};
const eq = (name, got, want) =>
  ok(name, got === want, `got ${JSON.stringify(got)} want ${JSON.stringify(want)}`);
const same = (name, got, want) =>
  eq(name, JSON.stringify(got), JSON.stringify(want));

const jsonResponse = (body, status = 200) => new Response(JSON.stringify(body), {
  status,
  headers: { "content-type": "application/json" },
});
const unavailableContract = (result) =>
  result?.status === "unavailable" && result?.data === null &&
  typeof result?.error === "string" && result.error.length > 0;
const policy = (provider, overrides = {}) => ({
  ...CT_PROVIDER_POLICIES,
  [provider]: {
    ...CT_PROVIDER_POLICIES[provider],
    ...overrides,
  },
});

async function importCacheSource(source, suffix) {
  const isolated = source.replace(
    'import { customerSafeFailure } from "../lib/errors.js";',
    'const customerSafeFailure = (_context, _error, message) => message;'
  );
  const href = `data:text/javascript;base64,${Buffer.from(isolated).toString("base64")}#${suffix}`;
  return import(href);
}

async function attemptCapContract(createCache) {
  let calls = 0;
  const result = await createCache({
    policies: policy("crt_sh", { maxAttempts: 3, backoffMs: 0 }),
    fetcher: async () => {
      calls++;
      return calls < 3 ? jsonResponse({}, 503) : jsonResponse([{ id: "late-success" }]);
    },
    remainingMs: () => 10_000,
    sleep: async () => {},
  }).get("example.com", "crt_sh");
  return { calls, result };
}

async function deadlineContract(createCache) {
  let calls = 0;
  let remaining = 50;
  const result = await createCache({
    policies: policy("crt_sh", { maxAttempts: 2, backoffMs: 0 }),
    fetcher: async () => {
      calls++;
      remaining = 0;
      return calls === 1 ? jsonResponse({}, 503) : jsonResponse([{ id: "over-budget" }]);
    },
    remainingMs: () => remaining,
    sleep: async () => {},
  }).get("example.com", "crt_sh");
  return { calls, result };
}

async function falseEmptyContract(createCache) {
  const result = await createCache({
    policies: policy("crt_sh", { backoffMs: 0 }),
    fetcher: async () => jsonResponse({}, 503),
    remainingMs: () => 10_000,
    sleep: async () => {},
  }).get("example.com", "crt_sh");
  return result;
}

// Named defaults are intentionally different: crt.sh is historically slower.
eq("hard attempt cap permits exactly one retry", CT_PROVIDER_HARD_ATTEMPT_CAP, 2);
eq("crt.sh named timeout", CT_PROVIDER_POLICIES.crt_sh.timeoutMs, 6_000);
eq("CertSpotter named timeout", CT_PROVIDER_POLICIES.certspotter.timeoutMs, 4_000);
ok("provider timeouts are independently tunable",
  CT_PROVIDER_POLICIES.crt_sh.timeoutMs !== CT_PROVIDER_POLICIES.certspotter.timeoutMs);
{
  const cacheSource = fs.readFileSync(enginePath("ct-provider-cache.js"), "utf8");
  ok("production timeout signal uses the platform AbortSignal timer",
    /timeoutSignal = \(ms\) => AbortSignal\.timeout\(ms\)/.test(cacheSource));
}

// Transient failure then success: one shared logical result, one retry, unchanged data.
{
  const fixture = [{ id: 7, name_value: "example.com\nwww.example.com" }];
  const sleeps = [];
  let calls = 0;
  let clock = 1_000;
  const cache = createCertificateTransparencyCache({
    policies: policy("crt_sh", { backoffMs: 25 }),
    fetcher: async () => {
      calls++;
      clock += calls === 1 ? 20 : 15;
      return calls === 1 ? jsonResponse({}, 503) : jsonResponse(fixture);
    },
    remainingMs: () => 5_000,
    now: () => clock,
    sleep: async (ms) => {
      sleeps.push(ms);
      clock += ms;
    },
  });
  const first = cache.get("Example.COM.", "crt_sh");
  const second = cache.get("example.com", "crt_sh");
  ok("consumers share one in-flight logical lookup", first === second);
  const [a, b] = await Promise.all([first, second]);
  ok("consumers receive one shared logical result", a === b);
  eq("transient failure uses one extra attempt total", calls, 2);
  same("recovered provider data is byte-identical", a.data, fixture);
  same("one short backoff occurs", sleeps, [25]);
  const health = cache.healthSnapshot();
  eq("recovered provider health is available", health.crt_sh.outcome, "available");
  eq("recovered provider health records both attempts", health.crt_sh.attempts, 2);
  eq("recovered provider health records total latency", health.crt_sh.latency_ms, 60);
  eq("recovered provider health clears final error", health.crt_sh.final_error, null);
}

// Persistent transient failure: bounded attempts and explicit unavailable result.
{
  let calls = 0;
  const cache = createCertificateTransparencyCache({
    policies: policy("certspotter", { maxAttempts: 99, backoffMs: 0 }),
    fetcher: async () => {
      calls++;
      return jsonResponse({}, 503);
    },
    remainingMs: () => 5_000,
    sleep: async () => {},
  });
  const result = await cache.get("example.com", "certspotter");
  ok("persistent failure remains explicit unavailable", unavailableContract(result));
  eq("persistent failure never exceeds hard attempt cap", calls, 2);
  const health = cache.healthSnapshot().certspotter;
  eq("persistent failure health is unavailable", health.outcome, "unavailable");
  eq("persistent failure health records bounded attempts", health.attempts, 2);
  eq("persistent failure health records final error", health.final_error, "HTTP 503");
}

// Invalid domain, non-JSON, and invalid shape are non-transient.
{
  let calls = 0;
  const cache = createCertificateTransparencyCache({
    fetcher: async () => {
      calls++;
      return jsonResponse({ certificates: [] });
    },
    remainingMs: () => 5_000,
  });
  const result = await cache.get("example.com", "crt_sh");
  ok("bad response shape is explicit unavailable", unavailableContract(result));
  eq("bad response shape is not retried", calls, 1);
  eq("bad shape health records one attempt", cache.healthSnapshot().crt_sh.attempts, 1);
}
{
  let calls = 0;
  const cache = createCertificateTransparencyCache({
    fetcher: async () => {
      calls++;
      return new Response("<html>not JSON</html>", {
        status: 200,
        headers: { "content-type": "text/html" },
      });
    },
    remainingMs: () => 5_000,
  });
  const result = await cache.get("example.com", "certspotter");
  ok("non-JSON response is explicit unavailable", unavailableContract(result));
  eq("non-JSON response is not retried", calls, 1);
  eq("non-JSON health records one attempt", cache.healthSnapshot().certspotter.attempts, 1);
}
{
  let calls = 0;
  const cache = createCertificateTransparencyCache({
    fetcher: async () => {
      calls++;
      return jsonResponse([]);
    },
  });
  const result = await cache.get(" ", "crt_sh");
  ok("invalid domain is explicit unavailable", unavailableContract(result));
  eq("invalid domain issues no request", calls, 0);
  eq("invalid domain health records no attempt", cache.healthSnapshot().crt_sh.attempts, 0);
}

// Per-attempt timeout is both enforced and capped by the remaining scan budget.
{
  let calls = 0;
  const originalConsoleError = console.error;
  console.error = () => {};
  const keepAlive = setTimeout(() => {}, 50);
  try {
    const cache = createCertificateTransparencyCache({
      policies: policy("certspotter", { timeoutMs: 5, maxAttempts: 1 }),
      fetcher: async (_url, { signal }) => {
        calls++;
        return new Promise((_resolve, reject) => {
          signal.addEventListener("abort", () => reject(signal.reason), { once: true });
        });
      },
      remainingMs: () => 500,
    });
    const result = await cache.get("example.com", "certspotter");
    ok("real provider timer aborts a hanging fetch", unavailableContract(result));
  } finally {
    clearTimeout(keepAlive);
    console.error = originalConsoleError;
  }
  eq("real timeout is bounded to one configured attempt", calls, 1);
}
{
  const observedTimeouts = [];
  let calls = 0;
  const originalConsoleError = console.error;
  console.error = () => {};
  try {
    const cache = createCertificateTransparencyCache({
      policies: policy("crt_sh", { timeoutMs: 9_000, maxAttempts: 1 }),
      fetcher: async (_url, { signal }) => {
        calls++;
        throw signal.reason || new DOMException("timed out", "TimeoutError");
      },
      remainingMs: () => 725,
      timeoutSignal: (ms) => {
        observedTimeouts.push(ms);
        return AbortSignal.abort(new DOMException("timed out", "TimeoutError"));
      },
    });
    const result = await cache.get("example.com", "crt_sh");
    ok("provider timeout becomes explicit unavailable", unavailableContract(result));
  } finally {
    console.error = originalConsoleError;
  }
  eq("timeout fixture performs one configured attempt", calls, 1);
  same("attempt timeout never exceeds remaining budget", observedTimeouts, [725]);
}

// A deadline exhausted by attempt one prevents the otherwise valid retry.
{
  const baseline = await deadlineContract(createCertificateTransparencyCache);
  eq("deadline exhaustion prevents retry", baseline.calls, 1);
  ok("deadline exhaustion remains explicit unavailable", unavailableContract(baseline.result));
}

// Health snapshots are copied into the existing R2-only execution diagnostics.
{
  const cache = createCertificateTransparencyCache({
    fetcher: async (url) => jsonResponse([{
      id: String(url).includes("certspotter") ? "certspotter-healthy" : "crt-healthy",
    }]),
    remainingMs: () => 5_000,
  });
  await Promise.all([
    cache.get("example.com", "crt_sh"),
    cache.get("example.com", "certspotter"),
  ]);
  const health = cache.healthSnapshot();
  const diagnostics = buildExecutionDiagnostics({ providerHealth: health });
  same("execution diagnostics records provider health", diagnostics.provider_health, health);
  eq("diagnostics includes crt.sh health", diagnostics.provider_health.crt_sh.outcome, "available");
  eq("diagnostics includes CertSpotter health",
    diagnostics.provider_health.certspotter.outcome, "available");
  health.certspotter.attempts = 99;
  eq("cache health snapshot is defensive", cache.healthSnapshot().certspotter.attempts, 1);
}

// Engine wiring keeps one cache and one snapshot per terminal path. PR-5.4 reuses
// the completed-path snapshot for customer state; the diagnostics bytes stay the
// same and no provider request or health record is duplicated.
{
  const engineSource = fs.readFileSync(enginePath("scan-engine.js"), "utf8");
  eq("engine creates one per-scan CT cache",
    (engineSource.match(/createCertificateTransparencyCache\(\{/g) || []).length, 1);
  ok("engine supplies live remaining scan budget",
    /remainingMs: \(\) => deadline\.remainingMs\(\)/.test(engineSource));
  eq("completed and failed terminal paths each snapshot provider health once",
    (engineSource.match(/ctCache\.healthSnapshot\(\)/g) || []).length, 2);
  ok("completed diagnostics reuse the canonical completed-path snapshot",
    /const providerHealth = ctCache\.healthSnapshot\(\);/.test(engineSource) &&
      /report\.execution_diagnostics = buildExecutionDiagnostics\(\{[\s\S]{0,220}providerHealth,[\s\S]{0,30}\}\);/.test(engineSource));
  ok("failed diagnostics still snapshot provider health",
    /execution_diagnostics: buildExecutionDiagnostics\(\{[\s\S]{0,220}providerHealth: ctCache\.healthSnapshot\(\),[\s\S]{0,30}\}\),/.test(engineSource));
}

// Each mutation represents the named defect and must violate the executable contract.
{
  const source = fs.readFileSync(enginePath("ct-provider-cache.js"), "utf8");

  const noCapSource = source.replace(
    "    maxAttempts: Math.min(\n      CT_PROVIDER_HARD_ATTEMPT_CAP,\n",
    "    maxAttempts: Math.min(\n      Number.MAX_SAFE_INTEGER,\n"
  );
  ok("attempt-cap mutation was applied", noCapSource !== source);
  const noCap = await importCacheSource(noCapSource, "no-attempt-cap");
  const cappedBaseline = await attemptCapContract(createCertificateTransparencyCache);
  const cappedMutant = await attemptCapContract(noCap.createCertificateTransparencyCache);
  ok("baseline hard cap rejects a third attempt",
    cappedBaseline.calls === 2 && unavailableContract(cappedBaseline.result));
  ok("mutation: removing hard attempt cap makes contract RED",
    cappedMutant.calls === 3 && cappedMutant.result.status === "available");

  const noDeadlineSource = source.replace(
    "  return values.length > 0 ? Math.min(...values) : Infinity;",
    "  return Infinity;"
  );
  ok("deadline mutation was applied", noDeadlineSource !== source);
  const noDeadline = await importCacheSource(noDeadlineSource, "no-deadline");
  const deadlineMutant = await deadlineContract(noDeadline.createCertificateTransparencyCache);
  ok("mutation: ignoring remaining budget makes contract RED",
    deadlineMutant.calls === 2 && deadlineMutant.result.status === "available");

  const falseEmptySource = source
    .replace('    status: "unavailable",', '    status: "available",')
    .replace("    data: null,", "    data: [],");
  ok("false-empty mutation was applied", falseEmptySource !== source);
  const falseEmpty = await importCacheSource(falseEmptySource, "false-empty");
  const baselineFailure = await falseEmptyContract(createCertificateTransparencyCache);
  const falseEmptyMutant = await falseEmptyContract(falseEmpty.createCertificateTransparencyCache);
  ok("baseline bounded failure is unavailable and non-empty", unavailableContract(baselineFailure));
  ok("mutation: bounded failure as empty-available makes contract RED",
    falseEmptyMutant.status === "available" && Array.isArray(falseEmptyMutant.data));
}

console.log(`\nct-provider-resilience: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
