// Run inside the final TLS image with network disabled and a loopback fixture.
// Measures the actual parent/child collector, not the build-stage Python rig.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const iterations = Number(process.argv[2] ?? 20);
if (!Number.isInteger(iterations) || iterations < 1 || iterations > 100) {
  throw new Error("iterations must be 1..100");
}
if (process.env.CM_TLS_TEST_RUNTIME_ROOT !== "/opt/cybermeters" ||
    !process.env.CM_TLS_TEST_CERTIFICATE || !process.env.CM_TLS_TEST_KEY) {
  throw new Error("final runtime root and local fixture certificate/key are required");
}

const test = fileURLToPath(new URL("../workers/network-probe/tls-engine/test-parent.js", import.meta.url));
const cgroup = "/sys/fs/cgroup";
function read(name) {
  try { return readFileSync(join(cgroup, name), "utf8").trim(); }
  catch { return null; }
}
function cpuUsec() {
  const match = /^usage_usec\s+(\d+)$/m.exec(read("cpu.stat") ?? "");
  return match ? Number(match[1]) : null;
}
function numeric(name) {
  const value = read(name);
  return value && /^\d+$/.test(value) ? Number(value) : null;
}
const beforeCpu = cpuUsec();
const memoryBefore = numeric("memory.current");
if (beforeCpu === null || memoryBefore === null || !read("cpu.max") || !read("memory.max")) {
  throw new Error("cgroup v2 CPU and memory counters are required");
}
const started = process.hrtime.bigint();
const durations = [];
const totals = { requests: 0, checks: 0, connections: 0, bytes_sent: 0,
  bytes_received: 0, states: {} };
for (let i = 0; i < iterations; i++) {
  const began = process.hrtime.bigint();
  const run = spawnSync(process.execPath, [test], {
    env: { ...process.env, CM_TLS_TEST_PROFILE: "1" },
    encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024,
  });
  if (run.status !== 0) {
    throw new Error(`loopback iteration ${i + 1} failed: ${String(run.stderr || run.error || "").slice(-500)}`);
  }
  const line = run.stdout.split("\n").find((item) => item.startsWith("TLS parent profile: "));
  if (!line) throw new Error(`loopback iteration ${i + 1} omitted physical accounting`);
  const receipt = JSON.parse(line.slice("TLS parent profile: ".length));
  for (const key of ["requests", "checks", "connections", "bytes_sent", "bytes_received"]) {
    if (!Number.isSafeInteger(receipt[key]) || receipt[key] < 0) throw new Error(`invalid ${key}`);
    totals[key] += receipt[key];
  }
  for (const [state, count] of Object.entries(receipt.states ?? {})) {
    if (!Number.isSafeInteger(count) || count < 0) throw new Error(`invalid ${state} count`);
    totals.states[state] = (totals.states[state] ?? 0) + count;
  }
  durations.push(Number(process.hrtime.bigint() - began) / 1e6);
}
const wallMs = Number(process.hrtime.bigint() - started) / 1e6;
const afterCpu = cpuUsec();
if (afterCpu === null || numeric("memory.peak") === null ||
    Object.values(totals.states).reduce((sum, count) => sum + count, 0) !== totals.checks) {
  throw new Error("incomplete cgroup or collector state accounting");
}
durations.sort((a, b) => a - b);
const rounded = (value) => Math.round(value * 100) / 100;
console.log(JSON.stringify({
  kind: "tls-final-runtime-loopback-profile-v1",
  iterations,
  target_scope: "isolated_loopback_only",
  fixture_image_variant: process.env.CM_TLS_TEST_BASELINE_IMAGE === "1" ? "foundation_without_compression" : "compression_candidate",
  runtime_root: process.env.CM_TLS_TEST_RUNTIME_ROOT,
  cgroup_limits: { cpu_max: read("cpu.max"), memory_max: read("memory.max") },
  duration_ms: {
    wall: rounded(wallMs), min: rounded(durations[0]),
    median: rounded(durations[Math.floor(durations.length / 2)]),
    p95: rounded(durations[Math.ceil(durations.length * 0.95) - 1]),
    max: rounded(durations.at(-1)),
  },
  cpu_usage_usec: afterCpu - beforeCpu,
  memory_current_before_bytes: memoryBefore,
  memory_current_after_bytes: numeric("memory.current"),
  memory_peak_bytes: numeric("memory.peak"),
  totals,
}));
