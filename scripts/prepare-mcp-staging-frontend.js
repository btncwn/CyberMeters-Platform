#!/usr/bin/env node
// Prepare only the ignored Pages build output for the MCP staging API.
// The tracked production _headers policy is never written by this command.

import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(root, "frontend/dist");
const sourceHeaders = path.join(root, "frontend/public/_headers");
const outputHeaders = path.join(dist, "_headers");
const sourceConnect = "connect-src 'self' https://api.cybermeters.com https://api.stripe.com https://cloudflareinsights.com;";
const stagingConnect = "connect-src 'self' https://api-staging.cybermeters.com https://api.stripe.com https://cloudflareinsights.com;";
const stagingApiBase = "https://api-staging.cybermeters.com/api";

function assertRegularFile(file) {
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Refusing non-regular or linked file: ${file}`);
  }
}

function assertDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    throw new Error(`Refusing non-directory or linked path: ${directory}`);
  }
}

function count(haystack, needle) {
  return haystack.split(needle).length - 1;
}

function main() {
  if (process.argv.length !== 2) {
    throw new Error("No arguments are accepted; only frontend/dist/_headers may be changed");
  }
  assertDirectory(dist);
  assertDirectory(path.join(dist, "assets"));
  assertRegularFile(sourceHeaders);
  assertRegularFile(outputHeaders);
  assertRegularFile(path.join(dist, "index.html"));

  // Refuse an accidental tracked or redirected output path before any write.
  execFileSync("git", ["check-ignore", "--quiet", "--", "frontend/dist/_headers"], { cwd: root });
  const source = fs.readFileSync(sourceHeaders, "utf8");
  const output = fs.readFileSync(outputHeaders, "utf8");
  if (output !== source) {
    throw new Error("Built _headers differs from the production source; rebuild before preparing staging");
  }
  const policies = source.split(/\r?\n/).filter((line) => line.startsWith("  Content-Security-Policy:"));
  if (policies.length !== 1 || count(policies[0], sourceConnect) !== 1 ||
      count(source, sourceConnect) !== 1 || source.includes(stagingConnect)) {
    throw new Error("Production CSP connect-src does not match the expected single API origin");
  }

  // The API URL is compiled into Vite's entry bundle; headers alone cannot
  // safely convert a production build into a staging build.
  const html = fs.readFileSync(path.join(dist, "index.html"), "utf8");
  const entrypoints = [...html.matchAll(/<script\b[^>]*\bsrc="\/assets\/(index-[A-Za-z0-9_-]+\.js)"[^>]*><\/script>/g)];
  if (entrypoints.length !== 1) {
    throw new Error("Expected exactly one Vite entry bundle in frontend/dist/index.html");
  }
  const bundlePath = path.join(dist, "assets", entrypoints[0][1]);
  assertRegularFile(bundlePath);
  const bundle = fs.readFileSync(bundlePath, "utf8");
  if (!bundle.includes(stagingApiBase) || bundle.includes("https://api.cybermeters.com/api")) {
    throw new Error("Vite entry bundle is not built for the exact staging API base URL");
  }

  const prepared = source.replace(sourceConnect, stagingConnect);
  if (prepared === source || count(prepared, stagingConnect) !== 1 ||
      count(prepared, sourceConnect) !== 0) {
    throw new Error("Staging CSP transformation did not produce the exact expected result");
  }
  fs.writeFileSync(outputHeaders, prepared);
  console.log("Prepared ignored frontend/dist/_headers for the staging API; tracked frontend/public/_headers is unchanged.");
}

try {
  main();
} catch (error) {
  console.error(`Staging frontend preparation refused: ${error.message}`);
  process.exitCode = 1;
}
