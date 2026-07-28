#!/usr/bin/env node
// Anchor-guarded mutation proof for the five BRS downstream completeness
// regressions. Every mutation differs, must be killed for its intended reason,
// and is restored in finally.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const supplyChainFile = path.join(root, "workers", "scan-api", "src", "engines", "supply-chain.js");
const supplyChainPage = path.join(root, "frontend", "src", "pages", "ws", "WorkspaceSupplyChainPage.jsx");
const portfolioPage = path.join(root, "frontend", "src", "pages", "PortfolioRiskPage.jsx");
const backendValidator = path.join(root, "scripts", "validate-brs-downstream-completeness.js");
const EXPECTED_MUTANTS = 6;
const EXPECTED_ASSERTIONS = 6;

function replaceExactlyOnce(source, anchor, replacement, label) {
  const first = source.indexOf(anchor);
  if (first < 0 || source.indexOf(anchor, first + anchor.length) >= 0) {
    throw new Error(`${label}: anchor must exist exactly once`);
  }
  const mutated = source.slice(0, first) + replacement + source.slice(first + anchor.length);
  if (mutated === source) throw new Error(`${label}: mutated === original`);
  return mutated;
}

const frontendCommand = (testFile) => ({
  command: "npm",
  args: ["run", "test", "--", "--run", testFile],
  cwd: path.join(root, "frontend"),
});

const mutants = [
  {
    name: "null BRS becomes zero maturity contribution",
    files: [supplyChainFile],
    mutate(files) {
      files.set(supplyChainFile, replaceExactlyOnce(
        files.get(supplyChainFile),
        "if (!Number.isFinite(brs_score)) {",
        "if (false) {",
        this.name,
      ));
    },
    command: process.execPath,
    args: [backendValidator],
    cwd: root,
    env: { BRS_DOWNSTREAM_ASSERT_ONLY: "unavailable maturity score is null" },
    expected: "FAIL unavailable maturity score is null",
  },
  {
    name: "numeric composite emitted with incomplete maturity",
    files: [supplyChainFile],
    mutate(files) {
      files.set(supplyChainFile, replaceExactlyOnce(
        files.get(supplyChainFile),
        "const supplyChainScore = supplyChainScoreState === 'assessed'",
        "const supplyChainScore = true",
        this.name,
      ));
    },
    command: process.execPath,
    args: [backendValidator],
    cwd: root,
    env: { BRS_DOWNSTREAM_ASSERT_ONLY: "unavailable composite score is null" },
    expected: "FAIL unavailable composite score is null",
  },
  {
    name: "frontend null-to-zero fallback",
    files: [supplyChainPage],
    mutate(files) {
      let source = files.get(supplyChainPage);
      source = replaceExactlyOnce(
        source,
        "{supplyChainScoreAssessed ? (",
        "{true ? (",
        this.name,
      );
      source = replaceExactlyOnce(
        source,
        '<ScoreRing score={data.supply_chain_score} label="Supply Chain" size={72} />',
        '<ScoreRing score={data.supply_chain_score ?? 0} label="Supply Chain" size={72} />',
        this.name,
      );
      files.set(supplyChainPage, source);
    },
    ...frontendCommand("src/pages/ws/__tests__/WorkspaceSupplyChainPage.honesty.test.jsx"),
    expected: "does not convert an unavailable BRS-derived composite into 0, initial or low",
  },
  {
    name: "missing BRS compliance becomes low",
    files: [supplyChainFile],
    mutate(files) {
      let source = files.get(supplyChainFile);
      source = replaceExactlyOnce(source, "let gdpr = null;", "let gdpr = 'low';", this.name);
      source = replaceExactlyOnce(source, "let security_governance = null;", "let security_governance = 'low';", this.name);
      source = replaceExactlyOnce(source, "let pci_dss = null;", "let pci_dss = 'low';", this.name);
      files.set(supplyChainFile, source);
    },
    command: process.execPath,
    args: [backendValidator],
    cwd: root,
    env: { BRS_DOWNSTREAM_ASSERT_ONLY: "unavailable compliance families are not low" },
    expected: "FAIL unavailable compliance families are not low",
  },
  {
    name: "fixed never-assessed portfolio tooltip",
    files: [portfolioPage],
    mutate(files) {
      let source = files.get(portfolioPage);
      source = replaceExactlyOnce(
        source,
        "title={unavailableBrs.detail}",
        'title="No completed assessment for this customer environment yet"',
        this.name,
      );
      source = replaceExactlyOnce(
        source,
        "{unavailableBrs.label}",
        "Not assessed",
        this.name,
      );
      files.set(portfolioPage, source);
    },
    ...frontendCommand("src/pages/__tests__/PortfolioRiskPage.honesty.test.jsx"),
    expected: "distinguishes latest-incomplete historical evidence from never assessed",
  },
  {
    name: "assessed zero hidden as unavailable",
    files: [supplyChainPage],
    mutate(files) {
      files.set(supplyChainPage, replaceExactlyOnce(
        files.get(supplyChainPage),
        "Number.isFinite(data.brs_score)",
        "data.brs_score > 0",
        this.name,
      ));
    },
    ...frontendCommand("src/pages/ws/__tests__/WorkspaceSupplyChainPage.honesty.test.jsx"),
    expected: "renders an assessed BRS of zero as a real input without degrading the composites",
  },
];

let killed = 0;
let assertions = 0;
for (const mutant of mutants) {
  const originals = new Map(mutant.files.map((file) => [file, fs.readFileSync(file, "utf8")]));
  const mutated = new Map(originals);
  try {
    mutant.mutate(mutated);
    for (const file of mutant.files) {
      const before = originals.get(file);
      const after = mutated.get(file);
      if (after === before) throw new Error(`${mutant.name}: mutated === original for ${file}`);
      fs.writeFileSync(file, after);
    }
    const child = spawnSync(mutant.command, mutant.args, {
      cwd: mutant.cwd,
      encoding: "utf8",
      env: { ...process.env, ...(mutant.env || {}) },
      timeout: 90_000,
    });
    const output = `${child.stdout || ""}\n${child.stderr || ""}`;
    const nonzero = child.status !== 0;
    const intended = output.includes(mutant.expected);
    if (nonzero && intended) {
      killed += 1;
      assertions += 1;
      console.log(`PASS ${mutant.name}`);
    } else {
      console.error(`FAIL ${mutant.name} — status=${child.status} expected=${JSON.stringify(mutant.expected)}`);
      console.error(output.slice(-4000));
    }
  } finally {
    for (const [file, source] of originals) fs.writeFileSync(file, source);
  }
}

console.log(`BRS downstream mutations: mutants ${killed}/${EXPECTED_MUTANTS}, assertions ${assertions}/${EXPECTED_ASSERTIONS}`);
if (killed !== EXPECTED_MUTANTS || assertions !== EXPECTED_ASSERTIONS) {
  console.error("BRS downstream mutation validation FAILED");
  process.exit(1);
}
console.log("BRS downstream mutation validation passed");
