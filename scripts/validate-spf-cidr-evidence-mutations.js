#!/usr/bin/env node
// Load-bearing mutation proof for SPF CIDR customer-evidence fidelity.
// Five source mutants each reintroduce one founder-pinned defect. Anchor and
// kill assertions are counted separately from the mutant kill count.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const engines = path.join(root, "workers", "scan-api", "src", "engines");
const spfPath = path.join(engines, "spf-resolver.js");
const posturePath = path.join(engines, "posture-events.js");
const sources = new Map([
  [spfPath, fs.readFileSync(spfPath, "utf8")],
  [posturePath, fs.readFileSync(posturePath, "utf8")],
]);

let sequence = 0;
let assertionsPassed = 0;
let assertionsFailed = 0;
let mutantsKilled = 0;

function assertion(name, condition) {
  if (condition) assertionsPassed += 1;
  else {
    assertionsFailed += 1;
    console.error(`FAIL ${name}`);
  }
}

async function loadMutant({ name, sourcePath, from, to }) {
  const original = sources.get(sourcePath);
  const mutated = original.replace(from, to);
  const anchorApplied = mutated !== original;
  assertion(`${name}: mutation anchor applied`, anchorApplied);
  if (!anchorApplied) return null;

  const mutantPath = path.join(
    path.dirname(sourcePath),
    `.${path.basename(sourcePath, ".js")}.mutant.${process.pid}.${++sequence}.js`,
  );
  fs.writeFileSync(mutantPath, mutated);
  try {
    return await import(`${pathToFileURL(mutantPath).href}?mutation=${sequence}`);
  } finally {
    fs.rmSync(mutantPath, { force: true });
  }
}

function emailModules(cidrs) {
  return {
    email_security: {
      spf: {
        present: true,
        record: "v=spf1 include:provider.example -all",
        resolution_status: "complete",
        resolved_pass_authorisations: cidrs,
      },
    },
  };
}

async function recordKill(name, load, ordinaryContract) {
  const mutant = await loadMutant(load);
  let killed = false;
  if (mutant) {
    try {
      killed = !(await ordinaryContract(mutant));
    } catch {
      killed = true;
    }
  }
  assertion(`${name}: ordinary contract goes RED`, killed);
  if (killed) mutantsKilled += 1;
}

await recordKill(
  "M1 canonical hex leaks back into description",
  {
    name: "M1 canonical hex leaks back into description",
    sourcePath: posturePath,
    from: "listOf(displayAdded)",
    to: "listOf(spfDelta.added)",
  },
  (mutant) => {
    const previous = emailModules(["ip4:c0000200/24"]);
    const current = emailModules(["ip4:c0000200/24", "ip4:cb007100/24"]);
    const event = mutant.buildPostureDiffEvents("example.com", previous, current)
      .find((item) => item.event_type === "email_spf_authorization_changed");
    return event?.description?.includes("203.0.113.0/24") &&
      !event?.description?.includes("ip4:cb007100/24");
  },
);

await recordKill(
  "M2 IPv6 RFC 5952 compression is broken",
  {
    name: "M2 IPv6 RFC 5952 compression is broken",
    sourcePath: spfPath,
    from: `    ? ipv6ForDisplay(network)
    : ipv4ForDisplay(network);`,
    to: `    ? Array.from({ length: 8 }, (_, index) =>
        Number((network >> BigInt((7 - index) * 16)) & 0xffffn)
          .toString(16)
          .padStart(4, "0")
      ).join(":")
    : ipv4ForDisplay(network);`,
  },
  (mutant) =>
    mutant.formatCanonicalCidrForDisplay(
      "ip6:20010db8000000000000000000000000/32",
    ) === "2001:db8::/32",
);

await recordKill(
  "M3 display prefix is dropped",
  {
    name: "M3 display prefix is dropped",
    sourcePath: spfPath,
    from: "  const display = `${address}/${prefix}`;",
    to: "  const display = address;",
  },
  (mutant) =>
    mutant.formatCanonicalCidrForDisplay("ip4:c0000205/32") ===
      "192.0.2.5/32" &&
    mutant.formatCanonicalCidrForDisplay(
      "ip6:20010db8000000000000000000000001/128",
    ) === "2001:db8::1/128",
);

await recordKill(
  "M4 description cap is removed",
  {
    name: "M4 description cap is removed",
    sourcePath: posturePath,
    from: "arr.slice(0, cap).join(\", \")",
    to: "arr.slice(0, arr.length).join(\", \")",
  },
  (mutant) => {
    const cidrs = Array.from(
      { length: 13 },
      (_, index) => `ip4:c00002${index.toString(16).padStart(2, "0")}/32`,
    );
    const event = mutant.buildPostureDiffEvents(
      "bounded.example",
      emailModules([]),
      emailModules(cidrs),
    ).find((item) => item.event_type === "email_spf_authorization_changed");
    const displayed = event?.description?.match(
      /\b\d{1,3}(?:\.\d{1,3}){3}\/32\b/g,
    ) || [];
    return displayed.length === 12 && event?.description?.includes("(+1 more)");
  },
);

await recordKill(
  "M5 canonical stored network form is changed",
  {
    name: "M5 canonical stored network form is changed",
    sourcePath: spfPath,
    from: "  const network = value & mask;",
    to: "  const network = value;",
  },
  (mutant) => {
    const host = mutant.canonicalizeCidr("192.0.2.5/24", "ip4");
    const network = mutant.canonicalizeCidr("192.0.2.0/24", "ip4");
    return host === "ip4:c0000200/24" &&
      host === network &&
      new Set([host, network]).size === 1 &&
      mutant.cidrContains(host, "192.0.2.200") === true;
  },
);

console.log(
  `\nSPF CIDR evidence mutations: ${mutantsKilled}/5 mutants killed; ` +
  `${assertionsPassed}/${assertionsPassed + assertionsFailed} assertions passed`,
);
if (mutantsKilled !== 5 || assertionsFailed > 0) process.exit(1);
console.log("SPF CIDR evidence mutation proof passed");
