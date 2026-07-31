#!/usr/bin/env node
// TRACK-A3 — IntelligencePage canonical assessment and comparison presentation.
//
// The source guard uses the TypeScript JSX AST rather than token/regex matching.
// It inventories the complete local renderer/helper closure, follows stored-scan
// selectors and aliases (including JSX/helper propagation), recognises computed
// and destructured reads, and pins the backend-owned assessment/history contract.
// The real React fixture carrier supplies the customer-visible proof matrix.
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const frontend = path.join(root, "frontend");
const targetFile = path.join(frontend, "src", "pages", "IntelligencePage.jsx");
const frontendRequire = createRequire(path.join(frontend, "package.json"));
const ts = frontendRequire("typescript");

const EXPECTED_ASSERTIONS = 26;
const UI_TEST_TITLES = Object.freeze([
  "A: partial raw excellent/99 with null canonical rating and score fails closed",
  "B: partial canonical provisional score remains visible with an explicit label",
  "C: complete authoritative canonical good assessment remains visible",
  "D: comparable true exposes canonical score and finding history",
  "E: comparable false suppresses every historical claim",
  "F1: null comparable fails closed",
  "F2: missing comparable fails closed",
  "F3: unknown comparable fails closed",
  "G: backend non-comparable message is rendered verbatim without frontend causality",
  "H: positive observed finding remains visible without a new or resolved claim",
  "I: missing canonical assessment never falls back to raw report or stored values",
  "J: unknown rating and non-finite canonical score fail closed",
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

const sourceText = fs.readFileSync(targetFile, "utf8");
const sourceFile = ts.createSourceFile(
  targetFile,
  sourceText,
  ts.ScriptTarget.Latest,
  true,
  ts.ScriptKind.JSX,
);
ok(
  "AST: IntelligencePage renderer/helper closure parses as JSX",
  sourceFile.parseDiagnostics.length === 0,
  sourceFile.parseDiagnostics.map(d => String(d.messageText)).join(" | "),
);

const children = node => {
  const out = [];
  ts.forEachChild(node, child => { out.push(child); });
  return out;
};
const walk = (node, visit) => {
  visit(node);
  for (const child of children(node)) walk(child, visit);
};
const allNodes = [];
walk(sourceFile, node => allNodes.push(node));
const unwrap = node => {
  let current = node;
  while (current && (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isNonNullExpression(current)
  )) current = current.expression;
  return current;
};
const isMember = node => ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node);
const memberName = node => {
  if (ts.isPropertyAccessExpression(node)) return node.name.text;
  if (ts.isElementAccessExpression(node)) {
    const argument = unwrap(node.argumentExpression);
    return ts.isStringLiteral(argument) || ts.isNoSubstitutionTemplateLiteral(argument)
      ? argument.text
      : null;
  }
  return null;
};
const memberObject = node => isMember(node) ? unwrap(node.expression) : null;
const expressionContains = (node, predicate) => {
  let found = false;
  if (node) walk(node, candidate => { if (predicate(candidate)) found = true; });
  return found;
};
const findFunction = name => allNodes.find(node =>
  ts.isFunctionDeclaration(node) && node.name?.text === name
) ?? null;
const functionNodes = fn => {
  const nodes = [];
  if (fn?.body) walk(fn.body, node => nodes.push(node));
  return nodes;
};
const sourceSlice = node => sourceText.slice(node.getStart(sourceFile), node.getEnd());
const enclosingFunctionName = node => {
  let current = node?.parent;
  while (current) {
    if (ts.isFunctionDeclaration(current)) return current.name?.text ?? null;
    current = current.parent;
  }
  return null;
};
const containsReturn = node => expressionContains(node, candidate => ts.isReturnStatement(candidate));

// Stored scan provenance. `scans` is the workspace scan-list state; selector
// callback rows/results and aliases remain raw navigation rows even if renamed.
const rawCollections = new Set(["scans"]);
const rawObjects = new Set();
const collectionMethods = new Set(["filter", "map", "find", "findLast", "slice"]);
const selectorMethods = new Set(["find", "findLast", "at"]);
const binaryEither = node => ts.isBinaryExpression(node) && [
  ts.SyntaxKind.QuestionQuestionToken,
  ts.SyntaxKind.BarBarToken,
].includes(node.operatorToken.kind);
const isRawCollectionExpression = node => {
  const expression = unwrap(node);
  if (!expression) return false;
  if (ts.isIdentifier(expression)) return rawCollections.has(expression.text);
  if (isMember(expression) && memberName(expression) === "scans") return true;
  if (binaryEither(expression)) {
    return isRawCollectionExpression(expression.left) || isRawCollectionExpression(expression.right);
  }
  if (ts.isCallExpression(expression) && isMember(expression.expression)) {
    const method = memberName(expression.expression);
    return collectionMethods.has(method) && isRawCollectionExpression(memberObject(expression.expression));
  }
  return false;
};
const isRawObjectExpression = node => {
  const expression = unwrap(node);
  if (!expression) return false;
  if (ts.isIdentifier(expression)) return rawObjects.has(expression.text);
  if (binaryEither(expression)) {
    return isRawObjectExpression(expression.left) || isRawObjectExpression(expression.right);
  }
  if (ts.isConditionalExpression(expression)) {
    return isRawObjectExpression(expression.whenTrue) || isRawObjectExpression(expression.whenFalse);
  }
  if (ts.isElementAccessExpression(expression) && isRawCollectionExpression(expression.expression)) return true;
  if (ts.isCallExpression(expression) && isMember(expression.expression)) {
    const method = memberName(expression.expression);
    return selectorMethods.has(method) && isRawCollectionExpression(memberObject(expression.expression));
  }
  return false;
};
const localFunctions = new Map(allNodes
  .filter(node => ts.isFunctionDeclaration(node) && node.name)
  .map(node => [node.name.text, node]));
const addRawFunctionBinding = (fn, propName, positionalIndex = null) => {
  if (!fn) return false;
  const param = positionalIndex == null ? fn.parameters[0] : fn.parameters[positionalIndex];
  if (!param) return false;
  if (ts.isIdentifier(param.name)) {
    if (positionalIndex != null && !rawObjects.has(param.name.text)) {
      rawObjects.add(param.name.text);
      return true;
    }
    return false;
  }
  if (!ts.isObjectBindingPattern(param.name) || propName == null) return false;
  const binding = param.name.elements.find(element => {
    const property = element.propertyName ?? element.name;
    return (ts.isIdentifier(property) || ts.isStringLiteral(property)) && property.text === propName;
  });
  if (binding && ts.isIdentifier(binding.name) && !rawObjects.has(binding.name.text)) {
    rawObjects.add(binding.name.text);
    return true;
  }
  return false;
};

let provenanceChanged = true;
while (provenanceChanged) {
  provenanceChanged = false;
  for (const node of allNodes) {
    if (ts.isCallExpression(node) && isMember(node.expression)) {
      const method = memberName(node.expression);
      const receiver = memberObject(node.expression);
      if (collectionMethods.has(method) && isRawCollectionExpression(receiver)) {
        const callback = node.arguments[0];
        if ((ts.isArrowFunction(callback) || ts.isFunctionExpression(callback)) &&
            callback.parameters[0] && ts.isIdentifier(callback.parameters[0].name) &&
            !rawObjects.has(callback.parameters[0].name.text)) {
          rawObjects.add(callback.parameters[0].name.text);
          provenanceChanged = true;
        }
      }
    }
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name)) {
      if (isRawCollectionExpression(node.initializer) && !rawCollections.has(node.name.text)) {
        rawCollections.add(node.name.text);
        provenanceChanged = true;
      }
      if (isRawObjectExpression(node.initializer) && !rawObjects.has(node.name.text)) {
        rawObjects.add(node.name.text);
        provenanceChanged = true;
      }
    }
    if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const left = unwrap(node.left);
      if (ts.isIdentifier(left) && isRawObjectExpression(node.right) && !rawObjects.has(left.text)) {
        rawObjects.add(left.text);
        provenanceChanged = true;
      }
    }
    if ((ts.isJsxSelfClosingElement(node) || ts.isJsxOpeningElement(node)) && ts.isIdentifier(node.tagName)) {
      const fn = localFunctions.get(node.tagName.text);
      for (const attribute of node.attributes.properties) {
        if (!ts.isJsxAttribute(attribute) || !attribute.initializer ||
            !ts.isJsxExpression(attribute.initializer) || !attribute.initializer.expression) continue;
        if (isRawObjectExpression(attribute.initializer.expression) &&
            addRawFunctionBinding(fn, attribute.name.text)) provenanceChanged = true;
      }
    }
    if (ts.isCallExpression(node) && ts.isIdentifier(node.expression)) {
      const fn = localFunctions.get(node.expression.text);
      node.arguments.forEach((argument, index) => {
        if (isRawObjectExpression(argument) && addRawFunctionBinding(fn, null, index)) provenanceChanged = true;
      });
    }
  }
}

const rawBindingReads = { rating: [], score: [] };
for (const node of allNodes) {
  if (!ts.isVariableDeclaration(node) || !node.initializer ||
      !ts.isObjectBindingPattern(node.name) || !isRawObjectExpression(node.initializer)) continue;
  for (const element of node.name.elements) {
    const property = element.propertyName ?? element.name;
    const name = (ts.isIdentifier(property) || ts.isStringLiteral(property)) ? property.text : null;
    if (name === "rating" || name === "score") rawBindingReads[name].push(element);
  }
}
const rawMemberReads = { rating: [], score: [] };
const rawDynamicReads = [];
for (const node of allNodes) {
  if (!isMember(node) || !isRawObjectExpression(memberObject(node))) continue;
  const name = memberName(node);
  if (name === "rating" || name === "score") rawMemberReads[name].push(node);
  if (ts.isElementAccessExpression(node) && name == null) rawDynamicReads.push(node);
}
const rawRatingReads = [...rawBindingReads.rating, ...rawMemberReads.rating, ...rawDynamicReads];
const rawScoreReads = [...rawBindingReads.score, ...rawMemberReads.score, ...rawDynamicReads];

// Raw report projection provenance. The canonical `assessment` child is allowed;
// top-level score/rating/band fields are compatibility data, not presentation.
const reportAliases = new Set(["report"]);
const isReportExpression = node => {
  const expression = unwrap(node);
  if (!expression) return false;
  if (ts.isIdentifier(expression)) return reportAliases.has(expression.text);
  if (binaryEither(expression)) return isReportExpression(expression.left) || isReportExpression(expression.right);
  return false;
};
let reportAliasChanged = true;
while (reportAliasChanged) {
  reportAliasChanged = false;
  for (const node of allNodes) {
    if (ts.isVariableDeclaration(node) && node.initializer && ts.isIdentifier(node.name) &&
        isReportExpression(node.initializer) && !reportAliases.has(node.name.text)) {
      reportAliases.add(node.name.text);
      reportAliasChanged = true;
    }
  }
}
const forbiddenReportFields = new Set(["cyber_metrics_score", "risk_level", "score_band", "score", "rating"]);
const rawReportReads = [];
for (const node of allNodes) {
  if (isMember(node) && isReportExpression(memberObject(node))) {
    const name = memberName(node);
    if (forbiddenReportFields.has(name) || (ts.isElementAccessExpression(node) && name == null)) rawReportReads.push(node);
  }
  if (ts.isVariableDeclaration(node) && node.initializer && ts.isObjectBindingPattern(node.name) &&
      isReportExpression(node.initializer)) {
    for (const element of node.name.elements) {
      const property = element.propertyName ?? element.name;
      const name = (ts.isIdentifier(property) || ts.isStringLiteral(property)) ? property.text : null;
      if (forbiddenReportFields.has(name)) rawReportReads.push(element);
    }
  }
}

const memberReadsNamed = name => allNodes.filter(node => isMember(node) && memberName(node) === name);
const displayRatingReads = memberReadsNamed("display_rating");
const displayScoreReads = memberReadsNamed("display_score");
const provisionalReads = memberReadsNamed("provisional");
const modulesSkippedReads = memberReadsNamed("modules_skipped");
const overallRiskReads = memberReadsNamed("overall_risk_level");
const comparableReads = memberReadsNamed("comparable").filter(node => {
  const object = memberObject(node);
  return ts.isIdentifier(object) && object.text === "changes";
});
const inventory = {
  raw_scan_rating: rawRatingReads.length,
  raw_scan_score: rawScoreReads.length,
  raw_report_score_band: rawReportReads.length,
  display_rating: displayRatingReads.length,
  display_score: displayScoreReads.length,
  provisional: provisionalReads.length,
  changes_comparable: comparableReads.length,
  overall_risk_level: overallRiskReads.length,
  modules_skipped: modulesSkippedReads.length,
};
const expectedInventory = {
  raw_scan_rating: 0,
  raw_scan_score: 0,
  raw_report_score_band: 0,
  display_rating: 1,
  display_score: 2,
  provisional: 5,
  changes_comparable: 1,
  overall_risk_level: 1,
  modules_skipped: 0,
};
ok(
  "AST: assessment-critical field inventory is pinned across the local closure",
  JSON.stringify(inventory) === JSON.stringify(expectedInventory),
  `got=${JSON.stringify(inventory)} expected=${JSON.stringify(expectedInventory)} rawObjects=${[...rawObjects].sort().join(",")}`,
);
ok(
  "AST: raw stored scan.rating cannot feed IntelligencePage or child helpers",
  rawRatingReads.length === 0,
  rawRatingReads.map(sourceSlice).join(" | "),
);
ok(
  "AST: raw stored scan.score cannot feed IntelligencePage or child helpers",
  rawScoreReads.length === 0,
  rawScoreReads.map(sourceSlice).join(" | "),
);
ok(
  "AST: raw report score/rating/band compatibility fields cannot feed presentation",
  rawReportReads.length === 0,
  rawReportReads.map(sourceSlice).join(" | "),
);

const ratingBandCalls = allNodes.filter(node =>
  ts.isCallExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === "bandMeta" &&
  node.arguments.some(argument => expressionContains(argument, candidate =>
    isMember(candidate) && memberName(candidate) === "display_rating"
  ))
);
const directRatingJsx = allNodes.filter(node => ts.isJsxExpression(node) && node.expression &&
  expressionContains(node.expression, candidate =>
    isMember(candidate) && memberName(candidate) === "display_rating"
  ));
ok(
  "AST: canonical display_rating reaches bandMeta label metadata and is never printed raw",
  displayRatingReads.length === 1 && ratingBandCalls.length === 1 && directRatingJsx.length === 0,
  `display reads=${displayRatingReads.length}; bandMeta calls=${ratingBandCalls.length}; direct JSX=${directRatingJsx.length}`,
);

const canonicalHelper = findFunction("canonicalAssessmentPresentation");
const canonicalNodes = functionNodes(canonicalHelper);
const finiteScoreCalls = canonicalNodes.filter(node =>
  ts.isCallExpression(node) && isMember(node.expression) &&
  ts.isIdentifier(memberObject(node.expression)) && memberObject(node.expression).text === "Number" &&
  memberName(node.expression) === "isFinite" &&
  node.arguments.some(argument => expressionContains(argument, candidate =>
    isMember(candidate) && memberName(candidate) === "display_score"
  ))
);
const canonicalScoreJsx = allNodes.filter(node => ts.isJsxExpression(node) && node.expression &&
  expressionContains(node.expression, candidate =>
    isMember(candidate) && memberName(candidate) === "score" &&
    ts.isIdentifier(memberObject(candidate)) && ["cms", "assessmentPresentation"].includes(memberObject(candidate).text)
  ));
ok(
  "AST: only finite canonical display_score reaches both score renderers",
  displayScoreReads.length === 2 && finiteScoreCalls.length === 1 && canonicalScoreJsx.length >= 4,
  `display reads=${displayScoreReads.length}; finite gates=${finiteScoreCalls.length}; renderer reads=${canonicalScoreJsx.length}`,
);

const provisionalStrictTrue = provisionalReads.filter(node => {
  const parent = node.parent;
  return ts.isBinaryExpression(parent) && parent.operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken &&
    parent.right.kind === ts.SyntaxKind.TrueKeyword;
});
const customerText = node => {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (ts.isJsxText(node)) return node.getText(sourceFile).trim().replace(/\s+/g, " ");
  return null;
};
const sourceStrings = new Set(allNodes.map(customerText).filter(Boolean));
ok(
  "AST: provisional score requires canonical provisional === true and explicit customer copy",
  provisionalStrictTrue.length === 1 &&
    sourceStrings.has("Provisional Score") && sourceStrings.has("Provisional score ") &&
    sourceStrings.has("Final rating withheld"),
  `strict gates=${provisionalStrictTrue.length}`,
);

ok(
  "AST: risk_intelligence overall level remains confined to its evidence section",
  overallRiskReads.length === 1 && overallRiskReads.every(node => enclosingFunctionName(node) === "RiskIntelligenceSection"),
  overallRiskReads.map(node => `${enclosingFunctionName(node)}:${sourceSlice(node)}`).join(" | "),
);

const reasonFunction = findFunction("nonComparableReason");
const reasonNodes = functionNodes(reasonFunction);
const reasonReturns = reasonNodes.filter(ts.isReturnStatement);
const returnsMember = (returnNode, objectName, propertyName) => {
  const expression = returnNode.expression ? unwrap(returnNode.expression) : null;
  return expression && isMember(expression) && memberName(expression) === propertyName &&
    ts.isIdentifier(memberObject(expression)) && memberObject(expression).text === objectName;
};
const assessmentMessageReturns = reasonReturns.filter(node => returnsMember(node, "assessment", "message"));
const warningReturns = reasonReturns.filter(node => ts.isIdentifier(unwrap(node.expression)) && unwrap(node.expression).text === "warning");
const fallbackReturns = reasonReturns.filter(node => {
  const expression = unwrap(node.expression);
  return (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) &&
    expression.text === "Historical changes are unavailable because this assessment is not explicitly comparable.";
});
const reasonOrder = [assessmentMessageReturns[0], warningReturns[0], fallbackReturns[0]];
ok(
  "AST: non-comparable reason is backend-verbatim priority with no frontend cause inference",
  modulesSkippedReads.length === 0 && assessmentMessageReturns.length === 1 &&
    warningReturns.length === 1 && fallbackReturns.length === 1 && reasonOrder.every(Boolean) &&
    reasonOrder[0].pos < reasonOrder[1].pos && reasonOrder[1].pos < reasonOrder[2].pos,
  `modules_skipped=${modulesSkippedReads.length}; assessment=${assessmentMessageReturns.length}; warnings=${warningReturns.length}; fallback=${fallbackReturns.length}`,
);

const historyFunction = findFunction("HistoricalComparisonSection");
const historyNodes = functionNodes(historyFunction);
const scoreClaim = historyNodes.find(node => customerText(node) === "Score Comparison");
const claimStart = scoreClaim?.getStart(sourceFile) ?? Number.POSITIVE_INFINITY;
const comparableGate = historyNodes.filter(node => {
  if (!ts.isIfStatement(node) || node.getStart(sourceFile) >= claimStart) return false;
  const test = unwrap(node.expression);
  if (!ts.isBinaryExpression(test) || test.operatorToken.kind !== ts.SyntaxKind.ExclamationEqualsEqualsToken) return false;
  const left = unwrap(test.left);
  const right = unwrap(test.right);
  return isMember(left) && memberName(left) === "comparable" &&
    ts.isIdentifier(memberObject(left)) && memberObject(left).text === "changes" &&
    right.kind === ts.SyntaxKind.TrueKeyword && containsReturn(node.thenStatement);
});
ok(
  "AST: all historical claims require changes.comparable === true",
  comparableGate.length === 1,
  `explicit fail-closed gates=${comparableGate.length}`,
);

const positiveBlockers = historyNodes.filter(node => {
  if (!ts.isIfStatement(node) || node.getStart(sourceFile) >= claimStart) return false;
  const test = unwrap(node.expression);
  if (!ts.isBinaryExpression(test) || test.operatorToken.kind !== ts.SyntaxKind.EqualsEqualsEqualsToken) return false;
  const left = unwrap(test.left);
  const right = unwrap(test.right);
  return isMember(left) && memberName(left) === "comparable" && right.kind === ts.SyntaxKind.TrueKeyword &&
    containsReturn(node.thenStatement);
});
const historyStrings = new Set(historyNodes.map(customerText).filter(Boolean));
const requiredClaims = [
  "Score Comparison",
  "New Findings",
  "Resolved Findings",
  "New Subdomains",
  "Removed Subdomains",
  "New Takeover Risks",
  "New Exposed Assets",
  "No changes detected since the previous comparable assessment.",
];
const missingClaims = requiredClaims.filter(claim => !historyStrings.has(claim));
ok(
  "AST: comparable=true score/change/unchanged positive path remains reachable",
  positiveBlockers.length === 0 && missingClaims.length === 0,
  `true blockers=${positiveBlockers.length}; missing=${missingClaims.join(",") || "none"}`,
);

const riskFunction = findFunction("RiskIntelligenceSection");
const riskNodes = functionNodes(riskFunction);
const findingTitleRenderers = riskNodes.filter(node => ts.isJsxExpression(node) && node.expression &&
  expressionContains(node.expression, candidate => isMember(candidate) && memberName(candidate) === "title" &&
    ts.isIdentifier(memberObject(candidate)) && memberObject(candidate).text === "f"));
ok(
  "AST: positive observed risk finding renderer remains present outside history claims",
  findingTitleRenderers.length >= 1,
  `finding title renderers=${findingTitleRenderers.length}`,
);

const vitestBin = path.join(frontend, "node_modules", ".bin", "vitest");
const uiRun = spawnSync(vitestBin, [
  "run",
  "src/pages/__tests__/IntelligencePage.phase5Historical.test.jsx",
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
const uiAssertions = (uiJson?.testResults ?? []).flatMap(result => result.assertionResults ?? []);
const uiByTitle = new Map(uiAssertions.map(assertion => [assertion.title, assertion]));
const gotTitles = [...uiByTitle.keys()].sort();
const expectedTitles = [...UI_TEST_TITLES].sort();
const uiInfrastructureClean =
  !uiRun.error && uiRun.signal === null && (uiRun.status === 0 || uiRun.status === 1) &&
  uiJson != null && JSON.stringify(gotTitles) === JSON.stringify(expectedTitles);
ok(
  "UI: focused fixture process completed with the pinned case set",
  uiInfrastructureClean,
  uiRun.error?.message || (uiRun.signal ? `signal=${uiRun.signal}` : "") ||
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
console.log(`IntelligencePage presentation: ${passed} passed, ${failed} failed (${passed + failed} total)`);
if (failed > 0) process.exit(1);
console.log("IntelligencePage presentation validation passed");
