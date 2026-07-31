#!/usr/bin/env node
// Track A A2+A3 — ScanDetail evidence-honest presentation contract.
//
// This validator combines an AST-backed source guard with the real React fixture
// carrier. The AST guard ignores comments and strings, follows raw `scan` aliases,
// recognises dot/computed/destructured rating reads, proves the canonical frozen
// assessment rating reaches bandMeta(), and pins the strict historical gate.
// The UI carrier then proves the customer-visible partial/complete/legacy matrix.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const frontend = path.join(root, "frontend");
const scanDetailFile = path.join(frontend, "src", "pages", "ScanDetail.jsx");
const frontendRequire = createRequire(path.join(frontend, "package.json"));
const ts = frontendRequire("typescript");

const EXPECTED_ASSERTIONS = 16;
const UI_TEST_TITLES = Object.freeze([
  "A: partial canonical null rating hides the raw good band",
  "B: partial non-comparable history hides every relative claim and explains why",
  "C: missing comparable fails closed",
  "C: null comparable fails closed",
  "C: unknown comparable fails closed",
  "D: complete canonical good rating and comparable history retain positive behavior",
  "E: explicit first scan retains the no-history message",
  "F: missing canonical assessment never falls back to the raw rating",
  "G: observed partial finding stays visible without becoming a new-change claim",
]);

let passed = 0;
let failed = 0;
const ok = (name, condition, detail = "") => {
  if (condition) {
    passed += 1;
    console.log(`PASS ${name}`);
  } else {
    failed += 1;
    console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
};

const sourceText = fs.readFileSync(scanDetailFile, "utf8");
const sourceFile = ts.createSourceFile(
  scanDetailFile,
  sourceText,
  ts.ScriptTarget.Latest,
  true,
  ts.ScriptKind.JSX,
);
const parseClean = sourceFile.parseDiagnostics.length === 0;
ok(
  "AST: ScanDetail customer path parses as JSX",
  parseClean,
  sourceFile.parseDiagnostics.map((d) => String(d.messageText)).join(" | "),
);

const children = (node) => {
  const out = [];
  ts.forEachChild(node, (child) => { out.push(child); });
  return out;
};
const walk = (node, visit) => {
  visit(node);
  for (const child of children(node)) walk(child, visit);
};
const unwrap = (node) => {
  let current = node;
  while (current && (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isNonNullExpression(current)
  )) current = current.expression;
  return current;
};
const memberName = (node) => {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node)) {
    const argument = unwrap(node.argumentExpression);
    return ts.isStringLiteral(argument) || ts.isNoSubstitutionTemplateLiteral(argument)
      ? argument.text
      : null;
  }
  return null;
};
const memberObject = (node) => (
  ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)
    ? unwrap(node.expression)
    : null
);
const isMember = (node) => ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node);
const containsReturn = (node) => {
  let found = false;
  walk(node, (candidate) => { if (ts.isReturnStatement(candidate)) found = true; });
  return found;
};
const findFunction = (name) => {
  let found = null;
  walk(sourceFile, (node) => {
    if (!found && ts.isFunctionDeclaration(node) && node.name?.text === name) found = node;
  });
  return found;
};

const scanDetail = findFunction("ScanDetail");
const scanNodes = [];
if (scanDetail?.body) walk(scanDetail.body, (node) => scanNodes.push(node));

// Follow direct aliases of the `scan` state object. Any raw rating read anywhere
// in this customer component is forbidden; the only permitted band source is the
// frozen report assessment.
const scanAliases = new Set(["scan"]);
const rawRatingBindingReads = [];
let aliasChanged = true;
while (aliasChanged) {
  aliasChanged = false;
  for (const node of scanNodes) {
    if (ts.isVariableDeclaration(node) && node.initializer) {
      const initializer = unwrap(node.initializer);
      if (ts.isIdentifier(node.name) && ts.isIdentifier(initializer) && scanAliases.has(initializer.text)) {
        if (!scanAliases.has(node.name.text)) {
          scanAliases.add(node.name.text);
          aliasChanged = true;
        }
      }
      if (ts.isObjectBindingPattern(node.name) && ts.isIdentifier(initializer) && scanAliases.has(initializer.text)) {
        for (const element of node.name.elements) {
          const property = element.propertyName ?? element.name;
          if (ts.isIdentifier(property) && property.text === "rating") rawRatingBindingReads.push(element);
          if (ts.isStringLiteral(property) && property.text === "rating") rawRatingBindingReads.push(element);
        }
      }
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const left = unwrap(node.left);
      const right = unwrap(node.right);
      if (ts.isIdentifier(left) && ts.isIdentifier(right) && scanAliases.has(right.text) && !scanAliases.has(left.text)) {
        scanAliases.add(left.text);
        aliasChanged = true;
      }
    }
  }
}

const rawRatingMemberReads = scanNodes.filter((node) => {
  if (!isMember(node) || memberName(node) !== "rating") return false;
  const object = memberObject(node);
  return ts.isIdentifier(object) && scanAliases.has(object.text);
});
const rawRatingReads = [...rawRatingMemberReads, ...rawRatingBindingReads];
ok(
  "AST: raw scan.rating cannot feed ScanDetail presentation",
  rawRatingReads.length === 0,
  rawRatingReads.map((node) => sourceText.slice(node.getStart(sourceFile), node.getEnd())).join(" | "),
);

const expressionContains = (expression, predicate) => {
  let found = false;
  walk(expression, (node) => { if (predicate(node)) found = true; });
  return found;
};
const objectNamesAssessment = (node) => expressionContains(node, (candidate) =>
  (ts.isIdentifier(candidate) && candidate.text === "assessment") ||
  (isMember(candidate) && memberName(candidate) === "assessment")
);
const isCanonicalRatingMember = (node) =>
  isMember(node) && memberName(node) === "display_rating" && objectNamesAssessment(memberObject(node));

const canonicalRatingAliases = new Set();
let canonicalAliasChanged = true;
while (canonicalAliasChanged) {
  canonicalAliasChanged = false;
  for (const node of scanNodes) {
    if (!ts.isVariableDeclaration(node) || !ts.isIdentifier(node.name) || !node.initializer) continue;
    const canonical = expressionContains(node.initializer, (candidate) =>
      isCanonicalRatingMember(candidate) ||
      (ts.isIdentifier(candidate) && canonicalRatingAliases.has(candidate.text))
    );
    if (canonical && !canonicalRatingAliases.has(node.name.text)) {
      canonicalRatingAliases.add(node.name.text);
      canonicalAliasChanged = true;
    }
  }
}
const canonicalBandCalls = scanNodes.filter((node) => {
  if (!ts.isCallExpression(node) || !ts.isIdentifier(node.expression) || node.expression.text !== "bandMeta") return false;
  return node.arguments.some((argument) => expressionContains(argument, (candidate) =>
    isCanonicalRatingMember(candidate) ||
    (ts.isIdentifier(candidate) && canonicalRatingAliases.has(candidate.text))
  ));
});
ok(
  "AST: canonical assessment.display_rating feeds band presentation",
  canonicalRatingAliases.size > 0 && canonicalBandCalls.length > 0,
  `canonical aliases=${[...canonicalRatingAliases].join(",") || "none"}; band calls=${canonicalBandCalls.length}`,
);

const changesPanel = findFunction("ChangesPanel");
const changesNodes = [];
if (changesPanel?.body) walk(changesPanel.body, (node) => changesNodes.push(node));
const customerText = (node) => {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isJsxText(node)) return node.getText(sourceFile).trim().replace(/\s+/g, " ");
  return null;
};
const stringValues = new Set(changesNodes.map(customerText).filter(Boolean));
const scoreClaim = changesNodes.find((node) =>
  customerText(node) === "Score Comparison"
);
const claimStart = scoreClaim?.getStart(sourceFile) ?? Number.POSITIVE_INFINITY;

const isBooleanMemberTest = (test, property, operator, boolKind) => {
  if (!ts.isBinaryExpression(test) || test.operatorToken.kind !== operator) return false;
  const left = unwrap(test.left);
  const right = unwrap(test.right);
  return isMember(left) && memberName(left) === property &&
    ts.isIdentifier(memberObject(left)) && memberObject(left).text === "changes" &&
    right.kind === boolKind;
};
const firstScanGuards = changesNodes.filter((node) =>
  ts.isIfStatement(node) &&
  node.getStart(sourceFile) < claimStart &&
  isBooleanMemberTest(
    node.expression,
    "has_previous",
    ts.SyntaxKind.EqualsEqualsEqualsToken,
    ts.SyntaxKind.FalseKeyword,
  ) && containsReturn(node.thenStatement)
);
ok(
  "AST: first scan requires changes.has_previous === false",
  firstScanGuards.length === 1,
  `matching guards=${firstScanGuards.length}`,
);

const comparableGuards = changesNodes.filter((node) =>
  ts.isIfStatement(node) &&
  node.getStart(sourceFile) < claimStart &&
  isBooleanMemberTest(
    node.expression,
    "comparable",
    ts.SyntaxKind.ExclamationEqualsEqualsToken,
    ts.SyntaxKind.TrueKeyword,
  ) && containsReturn(node.thenStatement)
);
ok(
  "AST: comparison claims require changes.comparable === true",
  comparableGuards.length === 1,
  `matching explicit-true gates=${comparableGuards.length}`,
);

const positivePathBlockers = changesNodes.filter((node) =>
  ts.isIfStatement(node) &&
  node.getStart(sourceFile) < claimStart &&
  isBooleanMemberTest(
    node.expression,
    "comparable",
    ts.SyntaxKind.EqualsEqualsEqualsToken,
    ts.SyntaxKind.TrueKeyword,
  ) && containsReturn(node.thenStatement)
);
const requiredClaimStrings = [
  "Score Comparison",
  "New Findings",
  "Resolved Findings",
  "New Takeover Risks",
  "New Exposed Assets",
  "New Subdomains",
  "Removed Subdomains",
  "No changes detected since the previous scan.",
];
const missingClaims = requiredClaimStrings.filter((claim) => !stringValues.has(claim));
ok(
  "AST: comparable=true score and change path remains reachable",
  positivePathBlockers.length === 0 && missingClaims.length === 0,
  `true blockers=${positivePathBlockers.length}; missing=${missingClaims.join(",") || "none"}`,
);

const vitestBin = path.join(frontend, "node_modules", ".bin", "vitest");
const uiRun = spawnSync(vitestBin, [
  "run",
  "src/pages/__tests__/ScanDetail.evidenceHonesty.test.jsx",
  "--reporter=json",
  "--pool=forks",
  "--maxWorkers=1",
  "--no-file-parallelism",
], {
  cwd: frontend,
  encoding: "utf8",
  timeout: 120_000,
});

let uiJson = null;
try {
  uiJson = JSON.parse(String(uiRun.stdout || "").trim());
} catch {
  uiJson = null;
}
const uiAssertions = (uiJson?.testResults ?? []).flatMap((result) => result.assertionResults ?? []);
const uiByTitle = new Map(uiAssertions.map((assertion) => [assertion.title, assertion]));
const gotTitles = [...uiByTitle.keys()].sort();
const expectedTitles = [...UI_TEST_TITLES].sort();
const uiInfrastructureClean =
  !uiRun.error &&
  uiRun.signal === null &&
  (uiRun.status === 0 || uiRun.status === 1) &&
  uiJson != null &&
  JSON.stringify(gotTitles) === JSON.stringify(expectedTitles);
ok(
  "UI: focused fixture process completed with the pinned case set",
  uiInfrastructureClean,
  uiRun.error?.message ||
    (uiRun.signal ? `signal=${uiRun.signal}` : "") ||
    `status=${uiRun.status}; titles=${gotTitles.join(" | ") || "none"}; stderr=${String(uiRun.stderr || "").slice(0, 240)}`,
);
for (const title of UI_TEST_TITLES) {
  const assertion = uiByTitle.get(title);
  ok(
    `UI: ${title}`,
    assertion?.status === "passed",
    String(assertion?.failureMessages?.[0] || "missing fixture result").replaceAll("\n", " ").slice(0, 300),
  );
}

const total = passed + failed;
if (total !== EXPECTED_ASSERTIONS) {
  console.log(`FAIL validator assertion count pinned at ${EXPECTED_ASSERTIONS} — got ${total}`);
  failed += 1;
}
console.log(`ScanDetail presentation: ${passed} passed, ${failed} failed (${passed + failed} total)`);
if (failed > 0) process.exit(1);
console.log("ScanDetail presentation validation passed");
