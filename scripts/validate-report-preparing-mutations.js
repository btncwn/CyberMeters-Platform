#!/usr/bin/env node
//
// A1 report_preparing strict fresh-process mutation proof.
//
// Each carrier mutant is an adjacent temporary copy of the production module.
// The full route/resolver validator runs in a fresh Node process, while its
// direct resolver/frontend imports point at that mutated production copy. A kill
// counts only for the exact expected assertion list and the normal validator
// summary/exit contract.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const validator = path.join(root, "scripts", "validate-report-preparing.js");
const EXPECTED_MUTANTS = 7;
const EXPECTED_VALIDATOR_ASSERTIONS = 54;

let defined = 0;
let killed = 0;
let failures = 0;

function fail(message) {
  failures += 1;
  console.error(`FAIL ${message}`);
}

function replaceExactlyOnce(source, from, to, label) {
  const occurrences = source.split(from).length - 1;
  if (occurrences !== 1) {
    throw new Error(`${label}: anchor count ${occurrences}, expected 1`);
  }
  return source.replace(from, to);
}

function assertionFailures(stdout) {
  return String(stdout || "")
    .split(/\r?\n/)
    .filter((line) => line.startsWith("FAIL "))
    .map((line) => line.slice(5).split(" — ")[0]);
}

function runMutant({
  name,
  relativeSource,
  moduleEnv,
  expectedFailures,
  mutate,
}) {
  defined += 1;
  const sourcePath = path.join(root, relativeSource);
  const source = fs.readFileSync(sourcePath, "utf8");
  const parsed = path.parse(sourcePath);
  const mutantPath = path.join(
    parsed.dir,
    `.${parsed.name}.a1-mutant.${process.pid}.${defined}${parsed.ext}`,
  );

  let mutated;
  try {
    mutated = mutate(source);
  } catch (error) {
    fail(`${name}: ${error?.message || error}`);
    return;
  }

  fs.writeFileSync(mutantPath, mutated);
  try {
    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        [moduleEnv]: pathToFileURL(mutantPath).href,
      },
    });
    const actualFailures = assertionFailures(child.stdout);
    const summary = String(child.stdout || "").match(
      /report-preparing: (\d+) passed, (\d+) failed/,
    );
    const exactFailureList =
      JSON.stringify(actualFailures) === JSON.stringify(expectedFailures);
    const normalValidatorFailure =
      child.error == null &&
      child.signal == null &&
      child.status === 1 &&
      String(child.stderr || "").trim() === "" &&
      summary != null &&
      Number(summary[2]) === expectedFailures.length &&
      Number(summary[1]) + Number(summary[2]) === EXPECTED_VALIDATOR_ASSERTIONS;

    if (normalValidatorFailure && exactFailureList) {
      killed += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(
        `${name}: mutant ${child.status === 0 ? "survived" : "failed for the wrong reason"}`
        + `\nexpected failures: ${JSON.stringify(expectedFailures)}`
        + `\nactual failures: ${JSON.stringify(actualFailures)}`
        + `\nstatus=${child.status} signal=${child.signal} childError=${child.error?.message || "none"}`
        + `\nstdout:\n${String(child.stdout || "").trim()}`
        + `\nstderr:\n${String(child.stderr || "").trim()}`,
      );
    }
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

runMutant({
  name: "completed lifecycle restored as report-ready without evidence",
  relativeSource: "workers/scan-api/src/engines/report-availability.js",
  moduleEnv: "REPORT_PREPARING_RESOLVER_MODULE_URL",
  expectedFailures: [
    "resolver gives terminal integrity errors precedence over preparing",
    "completed status alone never becomes report_ready",
    "failed repair limit is an explicit terminal report error",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    "  const before = await snapshotAttemptState(env, scan.id);",
    `  return {
    availability: { status: "report_ready", retryable: false },
    read: null,
  };
  const before = await snapshotAttemptState(env, scan.id);`,
    "completed requires authoritative report evidence",
  ),
});

runMutant({
  name: "terminal snapshot integrity error converted to report_preparing",
  relativeSource: "workers/scan-api/src/engines/report-availability.js",
  moduleEnv: "REPORT_PREPARING_RESOLVER_MODULE_URL",
  expectedFailures: [
    "resolver gives terminal integrity errors precedence over preparing",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    `  if (read.status === "integrity_error" || read.status === "unsupported_schema_version") {
    return terminalState(
      "report_integrity_error",
      "The report is unavailable because its integrity could not be verified.",
      read.reason ?? read.status,
      { manual_retry_available: false },
    );
  }`,
    `  if (read.status === "integrity_error" || read.status === "unsupported_schema_version") {
    return {
      availability: {
        status: "report_preparing",
        code: "report_preparing",
        message: REPORT_PREPARING_MESSAGE,
        retryable: true,
      },
      read,
    };
  }`,
    "integrity errors outrank preparation",
  ),
});

runMutant({
  name: "legitimate report_preparing presentation branch bypassed",
  relativeSource: "frontend/src/lib/reportAvailability.js",
  moduleEnv: "REPORT_PREPARING_FRONTEND_MODULE_URL",
  expectedFailures: [
    "frontend recognises only explicit retryable report_preparing",
    "legitimate preparing state has dedicated non-error presentation",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    "  return availability?.status === 'report_preparing' && availability?.retryable === true",
    "  return false",
    "explicit report_preparing presentation branch",
  ),
});

runMutant({
  name: "bounded preparation polling permits an extra indefinite step",
  relativeSource: "frontend/src/lib/reportAvailability.js",
  moduleEnv: "REPORT_PREPARING_FRONTEND_MODULE_URL",
  expectedFailures: [
    "preparation polling stops at the configured bound",
  ],
  mutate: (source) => replaceExactlyOnce(
    source,
    "attempt >= REPORT_PREPARING_MAX_ATTEMPTS",
    "attempt > REPORT_PREPARING_MAX_ATTEMPTS",
    "finite preparation polling bound",
  ),
});

{
  const name = "passive technical-report reader regains failed-build retry authority";
  defined += 1;
  const routePath = path.join(
    root,
    "workers",
    "scan-api",
    "src",
    "routes",
    "scans.js",
  );
  const indexPath = path.join(root, "workers", "scan-api", "src", "index.js");
  const routeParsed = path.parse(routePath);
  const indexParsed = path.parse(indexPath);
  const mutantRoutePath = path.join(
    routeParsed.dir,
    `.${routeParsed.name}.a1-mutant.${process.pid}.${defined}${routeParsed.ext}`,
  );
  const mutantIndexPath = path.join(
    indexParsed.dir,
    `.${indexParsed.name}.a1-mutant.${process.pid}.${defined}${indexParsed.ext}`,
  );
  const expectedFailures = [
    "only scan-detail customer action may pass report-availability options",
    "retry authority has one canonical production grant",
    "all four passive renderer callers use resolver default retry policy",
    "passive renderer /report preserves failed report_unavailable",
    "passive renderer /report starts no repair work",
    "passive renderer /executive-report-v2 preserves failed report_unavailable",
    "passive renderer /executive-report-v2 starts no repair work",
    "passive renderer /snapshot preserves failed report_unavailable",
    "passive renderer /snapshot starts no repair work",
    "passive renderer /report/pdf preserves failed report_unavailable",
    "passive renderer /report/pdf starts no repair work",
    "passive renderers preserve the explicit customer retry right",
  ];

  try {
    const routeSource = fs.readFileSync(routePath, "utf8");
    const mutantRouteSource = replaceExactlyOnce(
      routeSource,
      "        resolvedAvailability = await resolveScanReportAvailability(env, scan);",
      `        resolvedAvailability = await resolveScanReportAvailability(env, scan, {
          retryFailed: true,
        });`,
      "passive technical-report retry authority",
    );
    const mutantRouteSpecifier = `./routes/${path.basename(mutantRoutePath)}`;
    const mutantIndexSource = replaceExactlyOnce(
      fs.readFileSync(indexPath, "utf8"),
      'from "./routes/scans.js";',
      `from "${mutantRouteSpecifier}";`,
      "Worker scan-route import",
    );
    fs.writeFileSync(mutantRoutePath, mutantRouteSource);
    fs.writeFileSync(mutantIndexPath, mutantIndexSource);

    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        REPORT_PREPARING_WORKER_MODULE_URL: pathToFileURL(mutantIndexPath).href,
        REPORT_PREPARING_SCAN_ROUTES_SOURCE_PATH: mutantRoutePath,
      },
    });
    const actualFailures = assertionFailures(child.stdout);
    const summary = String(child.stdout || "").match(
      /report-preparing: (\d+) passed, (\d+) failed/,
    );
    const exactFailureList =
      JSON.stringify(actualFailures) === JSON.stringify(expectedFailures);
    const normalValidatorFailure =
      child.error == null &&
      child.signal == null &&
      child.status === 1 &&
      String(child.stderr || "").trim() === "" &&
      summary != null &&
      Number(summary[2]) === expectedFailures.length &&
      Number(summary[1]) + Number(summary[2]) === EXPECTED_VALIDATOR_ASSERTIONS;

    if (normalValidatorFailure && exactFailureList) {
      killed += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(
        `${name}: mutant ${child.status === 0 ? "survived" : "failed for the wrong reason"}`
        + `\nexpected failures: ${JSON.stringify(expectedFailures)}`
        + `\nactual failures: ${JSON.stringify(actualFailures)}`
        + `\nstatus=${child.status} signal=${child.signal} childError=${child.error?.message || "none"}`
        + `\nstdout:\n${String(child.stdout || "").trim()}`
        + `\nstderr:\n${String(child.stderr || "").trim()}`,
      );
    }
  } catch (error) {
    fail(`${name}: ${error?.message || error}`);
  } finally {
    fs.rmSync(mutantIndexPath, { force: true });
    fs.rmSync(mutantRoutePath, { force: true });
  }
}

{
  const name = "await-less shorthand retry grant adds an uncounted passive caller";
  defined += 1;
  const routePath = path.join(
    root,
    "workers",
    "scan-api",
    "src",
    "routes",
    "scans.js",
  );
  const indexPath = path.join(root, "workers", "scan-api", "src", "index.js");
  const routeParsed = path.parse(routePath);
  const indexParsed = path.parse(indexPath);
  const mutantRoutePath = path.join(
    routeParsed.dir,
    `.${routeParsed.name}.a1-mutant.${process.pid}.${defined}${routeParsed.ext}`,
  );
  const mutantIndexPath = path.join(
    indexParsed.dir,
    `.${indexParsed.name}.a1-mutant.${process.pid}.${defined}${indexParsed.ext}`,
  );
  const expectedFailures = [
    "production report-availability caller inventory is complete and route-owned",
    "only scan-detail customer action may pass report-availability options",
    "retry authority has one canonical production grant",
  ];

  try {
    const routeSource = fs.readFileSync(routePath, "utf8");
    const mutantRouteSource = replaceExactlyOnce(
      routeSource,
      "        resolvedAvailability = await resolveScanReportAvailability(env, scan);",
      `        const enableIndirectRetry =
          request.headers.get("X-A1-Mutant-Passive-Retry") === "1";
        let indirectAvailability = null;
        if (enableIndirectRetry) {
          const retryFailed = true;
          indirectAvailability =
            resolveScanReportAvailability(env, scan, { retryFailed });
        }
        resolvedAvailability = indirectAvailability
          ? await indirectAvailability
          : await resolveScanReportAvailability(env, scan);`,
      "await-less shorthand passive retry grant",
    );
    const mutantRouteSpecifier = `./routes/${path.basename(mutantRoutePath)}`;
    const mutantIndexSource = replaceExactlyOnce(
      fs.readFileSync(indexPath, "utf8"),
      'from "./routes/scans.js";',
      `from "${mutantRouteSpecifier}";`,
      "Worker scan-route import",
    );
    fs.writeFileSync(mutantRoutePath, mutantRouteSource);
    fs.writeFileSync(mutantIndexPath, mutantIndexSource);

    const child = spawnSync(process.execPath, [validator], {
      cwd: root,
      encoding: "utf8",
      env: {
        ...process.env,
        REPORT_PREPARING_WORKER_MODULE_URL: pathToFileURL(mutantIndexPath).href,
        REPORT_PREPARING_SCAN_ROUTES_SOURCE_PATH: mutantRoutePath,
      },
    });
    const actualFailures = assertionFailures(child.stdout);
    const summary = String(child.stdout || "").match(
      /report-preparing: (\d+) passed, (\d+) failed/,
    );
    const exactFailureList =
      JSON.stringify(actualFailures) === JSON.stringify(expectedFailures);
    const normalValidatorFailure =
      child.error == null &&
      child.signal == null &&
      child.status === 1 &&
      String(child.stderr || "").trim() === "" &&
      summary != null &&
      Number(summary[2]) === expectedFailures.length &&
      Number(summary[1]) + Number(summary[2]) === EXPECTED_VALIDATOR_ASSERTIONS;

    if (normalValidatorFailure && exactFailureList) {
      killed += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(
        `${name}: mutant ${child.status === 0 ? "survived" : "failed for the wrong reason"}`
        + `\nexpected failures: ${JSON.stringify(expectedFailures)}`
        + `\nactual failures: ${JSON.stringify(actualFailures)}`
        + `\nstatus=${child.status} signal=${child.signal} childError=${child.error?.message || "none"}`
        + `\nstdout:\n${String(child.stdout || "").trim()}`
        + `\nstderr:\n${String(child.stderr || "").trim()}`,
      );
    }
  } catch (error) {
    fail(`${name}: ${error?.message || error}`);
  } finally {
    fs.rmSync(mutantIndexPath, { force: true });
    fs.rmSync(mutantRoutePath, { force: true });
  }
}

{
  const name = "stale Scan A response bypasses the Scan B generation guard";
  defined += 1;
  const componentPath = path.join(
    root,
    "frontend",
    "src",
    "pages",
    "ScanDetail.jsx",
  );
  const testPath = path.join(
    root,
    "frontend",
    "src",
    "pages",
    "__tests__",
    "ScanDetail.reportPreparing.test.jsx",
  );
  const componentParsed = path.parse(componentPath);
  const testParsed = path.parse(testPath);
  const mutantComponentPath = path.join(
    componentParsed.dir,
    `.${componentParsed.name}.a1-mutant.${process.pid}.${defined}${componentParsed.ext}`,
  );
  const mutantTestPath = path.join(
    testParsed.dir,
    `${testParsed.name.replace(/\.test$/, "")}.a1-mutant.${process.pid}.${defined}.test${testParsed.ext}`,
  );
  const targetTest =
    "keeps Scan B state when an aborted Scan A request resolves last";

  try {
    const mutantComponentSource = replaceExactlyOnce(
      fs.readFileSync(componentPath, "utf8"),
      `      if (!requestIsCurrent()) return
      const s    = data.scan || data`,
      "      const s    = data.scan || data",
      "scan-detail stale-response generation guard",
    );
    const mutantComponentImport = `../${path.basename(mutantComponentPath)}`;
    const mutantTestSource = replaceExactlyOnce(
      fs.readFileSync(testPath, "utf8"),
      "import ScanDetail from '../ScanDetail'",
      `import ScanDetail from '${mutantComponentImport}'`,
      "ScanDetail test production-module import",
    );
    fs.writeFileSync(mutantComponentPath, mutantComponentSource);
    fs.writeFileSync(mutantTestPath, mutantTestSource);

    const frontendRoot = path.join(root, "frontend");
    const vitest = path.join(frontendRoot, "node_modules", ".bin", "vitest");
    const relativeTest = path.relative(frontendRoot, mutantTestPath);
    const child = spawnSync(
      vitest,
      ["run", relativeTest, "-t", targetTest, "--reporter=verbose"],
      {
        cwd: frontendRoot,
        encoding: "utf8",
        env: {
          ...process.env,
          FORCE_COLOR: "0",
          NO_COLOR: "1",
        },
      },
    );
    const stdout = String(child.stdout || "");
    const stderr = String(child.stderr || "").trim();
    const targetFailure =
      stdout.includes(`ScanDetail canonical report availability > ${targetTest}`) &&
      /FAIL\s+.*ScanDetail canonical report availability > keeps Scan B state/.test(stderr) &&
      /Unable to find an accessible element with the role "heading" and name "b\.example"/
        .test(stderr) &&
      (stderr.match(/\bFAIL\s+/g) || []).length === 1 &&
      (stderr.match(/TestingLibraryElementError:/g) || []).length === 1;
    const exactSummary =
      /Test Files\s+1 failed \(1\)/.test(stdout) &&
      /Tests\s+1 failed \| 10 skipped \(11\)/.test(stdout);
    const malformedExecution =
      /Failed to resolve import|SyntaxError|Unhandled Error|Failed Suites/
        .test(`${stdout}\n${stderr}`);
    const unexpectedStderr =
      /\bWarning\b|not wrapped in act|ReferenceError|TypeError|NetworkError/
        .test(stderr);
    const normalTargetFailure =
      child.error == null &&
      child.signal == null &&
      child.status === 1 &&
      targetFailure &&
      exactSummary &&
      !malformedExecution &&
      !unexpectedStderr;

    if (normalTargetFailure) {
      killed += 1;
      console.log(`PASS ${name}`);
    } else {
      fail(
        `${name}: mutant ${child.status === 0 ? "survived" : "failed for the wrong reason"}`
        + `\nexpected failing test: ${targetTest}`
        + `\nstatus=${child.status} signal=${child.signal} childError=${child.error?.message || "none"}`
        + `\nstdout:\n${stdout.trim()}`
        + `\nstderr:\n${stderr}`,
      );
    }
  } catch (error) {
    fail(`${name}: ${error?.message || error}`);
  } finally {
    fs.rmSync(mutantTestPath, { force: true });
    fs.rmSync(mutantComponentPath, { force: true });
  }
}

if (defined !== EXPECTED_MUTANTS) {
  fail(`pinned mutant count — defined ${defined}, expected ${EXPECTED_MUTANTS}`);
}
if (killed !== EXPECTED_MUTANTS) {
  fail(`mutation score — killed ${killed}/${EXPECTED_MUTANTS}`);
}

console.log(`\nreport-preparing mutations: ${killed}/${EXPECTED_MUTANTS} killed`);
process.exit(failures > 0 ? 1 : 0);
