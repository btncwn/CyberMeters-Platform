#!/usr/bin/env node
// CT-R2 PR-1 — exhaustive scan-quality vocabulary inventory.
//
// The JavaScript/TypeScript side is AST-backed. It follows the canonical
// scan_quality slot through dot/computed access, destructuring, aliases, local
// propagation, helper returns and calls. Comments and string contents are not
// semantic callers. SQL is a separate taxonomy: only strings used as D1 query
// text or named SQL fragments are tokenised, and SET assignments are not
// misreported as predicates.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const frontendRequire = createRequire(path.join(root, "frontend", "package.json"));
const ts = frontendRequire("typescript");

const EXPECTED_ASSERTIONS = 7;
const EXPECTED = Object.freeze({
  runtime: {
    comparison_occurrences: 49,
    source_file_count: 22,
    fingerprint: "2ab8e5c9616fff432cd552aad8ac385d79f25243f51f22b3be50464466012c0b",
    partial_only_fingerprint: "e50e6cfb97a4c582c5562096f6160a58b57034d2c1a4a476b561bc2dcd62aec1",
  },
  sql: {
    predicate_occurrences: 19,
    unique_query_sites: 18,
    source_file_count: 14,
    fingerprint: "26c3424dcdf4575021fa8d7bd8a9c6748eef788c1721169f7cc4ad91c3a478a6",
  },
  governance: {
    comparison_occurrences: 54,
    source_file_count: 18,
    fingerprint: "a55e73b45a218be26fe0644d467ad65c1f08862ac20340c14e0a1e74d03d6e6b",
  },
  runtime_source_file_count: 31,
});

const ALLOWED_QUALITY_STATUSES = new Set([
  "complete", "partial", "degraded", "unknown", "null", "undefined",
]);
const QUALITY_SLOT_NAMES = new Set([
  "scan_quality", "scanQuality",
  "last_scan_quality", "lastScanQuality",
  "latest_scan_quality", "latestScanQuality",
  "current_scan_quality", "currentScanQuality",
  "previous_scan_quality", "previousScanQuality",
  // Immutable report projections of the same canonical quality value.
  "assessment_quality", "assessmentQuality",
]);
const QUALITY_IDENTIFIER_NAMES = new Set(QUALITY_SLOT_NAMES);
const SOURCE_ROOTS = [
  path.join(root, "workers"),
  path.join(root, "frontend", "src"),
  path.join(root, "shared"),
  path.join(root, "scripts"),
];
const SKIPPED_SOURCE_DIRECTORIES = new Set([
  ".git", ".wrangler", "coverage", "dist", "node_modules", "test-results",
]);
const SOURCE_EXTENSION = /\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i;
const SQL_NAME = /(?:SQL|QUERY|SCOPE|CTE|CLAUSE|PREDICATE)$/;
const COMPARISON_OPERATORS = new Set([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
]);
const QUALITY_RETURN_FUNCTION_NAMES = new Set([
  "normalizeQuality", "scanCompletionQualityDisclosure",
  "scanQualityStatus", "incompleteCustomerQuality", "String",
]);
const KNOWN_QUALITY_OBJECT_PRODUCERS = new Map([
  ["buildScanQuality", new Set(["status"])],
]);
const QUALITY_NORMALIZER_METHODS = new Set(["trim", "toLowerCase", "toString"]);
const QUALITY_VALUE_MEMBER_NAMES = new Set([
  "status", "quality", "reportQuality", "persistedQuality", "r2Quality", "d1Quality",
]);

let passed = 0;
let failed = 0;
function ok(name, condition, detail = "") {
  if (condition) {
    passed += 1;
    console.log(`PASS ${name}`);
  } else {
    failed += 1;
    console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

const sha256 = (value) => crypto.createHash("sha256").update(value).digest("hex");
const sorted = (values) => [...values].sort((a, b) => a.localeCompare(b));
const fingerprint = (values) => sha256(JSON.stringify(sorted(values)));
const rel = (filename) => path.relative(root, filename).split(path.sep).join("/");
const isGovernanceFile = (filename) => {
  const relative = rel(filename);
  return relative.startsWith("scripts/") ||
    relative.includes("/__tests__/") ||
    /\.(?:test|spec)\.[^.]+$/i.test(relative);
};
const isRuntimeFile = (filename) => !isGovernanceFile(filename);

function collectSourceFiles() {
  const files = [];
  const visit = (directory) => {
    if (!fs.existsSync(directory)) return;
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory() && !SKIPPED_SOURCE_DIRECTORIES.has(entry.name)) visit(absolute);
      else if (entry.isFile() && SOURCE_EXTENSION.test(entry.name)) files.push(absolute);
    }
  };
  for (const directory of SOURCE_ROOTS) visit(directory);
  return files.sort();
}

function scriptKind(filename) {
  if (filename.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (filename.endsWith(".jsx")) return ts.ScriptKind.JSX;
  if (/\.[cm]?ts$/.test(filename)) return ts.ScriptKind.TS;
  return ts.ScriptKind.JS;
}

function walk(node, visit) {
  visit(node);
  ts.forEachChild(node, (child) => walk(child, visit));
}

function descendants(node) {
  const nodes = [];
  walk(node, (candidate) => nodes.push(candidate));
  return nodes;
}

function unwrap(node) {
  let current = node;
  while (current && (
    ts.isParenthesizedExpression(current) ||
    ts.isAsExpression(current) ||
    ts.isTypeAssertionExpression(current) ||
    ts.isNonNullExpression(current) ||
    ts.isSatisfiesExpression?.(current)
  )) current = current.expression;
  return current;
}

function symbolAt(checker, node) {
  const symbol = checker.getSymbolAtLocation(node);
  if (!symbol) return null;
  return symbol.flags & ts.SymbolFlags.Alias ? checker.getAliasedSymbol(symbol) : symbol;
}

function bindingIdentifiers(name) {
  const out = [];
  if (ts.isIdentifier(name)) return [name];
  for (const element of name.elements || []) {
    if (ts.isOmittedExpression(element)) continue;
    out.push(...bindingIdentifiers(element.name));
  }
  return out;
}

function staticMemberName(node, checker, staticStrings) {
  const value = unwrap(node);
  if (ts.isPropertyAccessExpression(value)) return value.name.text;
  if (!ts.isElementAccessExpression(value)) return null;
  const argument = unwrap(value.argumentExpression);
  if (ts.isStringLiteral(argument) || ts.isNoSubstitutionTemplateLiteral(argument)) {
    return argument.text;
  }
  if (ts.isIdentifier(argument)) {
    return staticStrings.get(symbolAt(checker, argument)) ?? null;
  }
  return null;
}

function propertyNameText(name, checker, staticStrings) {
  if (!name) return null;
  if (ts.isIdentifier(name) || ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }
  if (ts.isComputedPropertyName(name)) {
    const expression = unwrap(name.expression);
    if (ts.isStringLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
      return expression.text;
    }
    if (ts.isIdentifier(expression)) {
      return staticStrings.get(symbolAt(checker, expression)) ?? null;
    }
  }
  return null;
}

function functionSymbol(checker, node) {
  if (ts.isFunctionDeclaration(node) && node.name) return symbolAt(checker, node.name);
  const parent = node.parent;
  if ((ts.isArrowFunction(node) || ts.isFunctionExpression(node)) &&
      ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    return symbolAt(checker, parent.name);
  }
  return null;
}

function sourceLine(sourceFile, node) {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
}

function normalizedSnippet(sourceFile, node) {
  return node.getText(sourceFile).replace(/\s+/g, " ").trim();
}

function analyseSemanticComparisons(sourceFiles, checker) {
  const staticStrings = new Map();
  const staticStatusCollections = new Map();
  const taintedSymbols = new Set();
  const taintedFunctions = new Set();
  const objectSymbolProperties = new Map();
  const functionReturnProperties = new Map();
  const taintReasons = new Map();
  const functionLikes = [];

  const addReason = (symbol, reason) => {
    if (!symbol) return false;
    const existed = taintedSymbols.has(symbol);
    taintedSymbols.add(symbol);
    if (!taintReasons.has(symbol)) taintReasons.set(symbol, new Set());
    taintReasons.get(symbol).add(reason);
    return !existed;
  };
  const mergeProperties = (map, symbol, properties) => {
    if (!symbol || !properties || properties.size === 0) return false;
    if (!map.has(symbol)) map.set(symbol, new Set());
    const target = map.get(symbol);
    const before = target.size;
    for (const property of properties) target.add(property);
    return target.size !== before;
  };

  for (const sourceFile of sourceFiles) {
    walk(sourceFile, (node) => {
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
        const value = unwrap(node.initializer);
        if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) {
          staticStrings.set(symbolAt(checker, node.name), value.text);
        }
        const array = ts.isArrayLiteralExpression(value)
          ? value
          : ts.isNewExpression(value) && ts.isIdentifier(value.expression) &&
              value.expression.text === "Set" && value.arguments?.[0] &&
              ts.isArrayLiteralExpression(value.arguments[0])
            ? value.arguments[0]
            : null;
        if (array && array.elements.every((element) =>
          ts.isStringLiteral(unwrap(element)) || ts.isNoSubstitutionTemplateLiteral(unwrap(element)))) {
          const statuses = array.elements.map((element) => unwrap(element).text.toLowerCase());
          if (statuses.every((status) => ALLOWED_QUALITY_STATUSES.has(status))) {
            staticStatusCollections.set(symbolAt(checker, node.name), statuses);
          }
        }
      }
      if (ts.isFunctionLike(node)) functionLikes.push(node);
    });
  }

  for (const sourceFile of sourceFiles) {
    walk(sourceFile, (node) => {
      if (ts.isIdentifier(node) && QUALITY_IDENTIFIER_NAMES.has(node.text)) {
        const parent = node.parent;
        const declaresBinding =
          (ts.isVariableDeclaration(parent) && parent.name === node) ||
          (ts.isParameter(parent) && parent.name === node) ||
          (ts.isBindingElement(parent) && parent.name === node);
        if (declaresBinding) addReason(symbolAt(checker, node), "named-slot");
      }
      if (ts.isBindingElement(node)) {
        const property = propertyNameText(node.propertyName ?? node.name, checker, staticStrings);
        if (QUALITY_SLOT_NAMES.has(property)) {
          for (const identifier of bindingIdentifiers(node.name)) {
            addReason(symbolAt(checker, identifier), "destructured");
          }
        }
      }
      if (ts.isFunctionDeclaration(node) && node.name?.text === "normalizeQuality") {
        for (const parameter of node.parameters) {
          for (const identifier of bindingIdentifiers(parameter.name)) {
            addReason(symbolAt(checker, identifier), "normalizer-parameter");
          }
        }
      }
    });
  }

  const expressionTainted = (node, seen = new Set()) => {
    const value = unwrap(node);
    if (!value || seen.has(value)) return false;
    seen.add(value);
    if (ts.isIdentifier(value)) return taintedSymbols.has(symbolAt(checker, value));
    if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
      const name = staticMemberName(value, checker, staticStrings);
      if (QUALITY_SLOT_NAMES.has(name)) return true;
      const object = unwrap(value.expression);
      if (ts.isIdentifier(object) &&
          objectSymbolProperties.get(symbolAt(checker, object))?.has(name)) return true;
      return QUALITY_VALUE_MEMBER_NAMES.has(name) &&
        expressionTainted(value.expression, seen);
    }
    if (ts.isCallExpression(value) || ts.isNewExpression(value)) {
      const calleeSymbol = symbolAt(checker, value.expression);
      if (taintedFunctions.has(calleeSymbol)) return true;
      const calleeName = ts.isIdentifier(value.expression)
        ? value.expression.text
        : staticMemberName(value.expression, checker, staticStrings);
      if (QUALITY_RETURN_FUNCTION_NAMES.has(calleeName) &&
          (value.arguments || []).some((argument) => expressionTainted(argument, new Set(seen)))) {
        return true;
      }
      if ((ts.isPropertyAccessExpression(value.expression) || ts.isElementAccessExpression(value.expression)) &&
          QUALITY_NORMALIZER_METHODS.has(calleeName) &&
          expressionTainted(value.expression.expression, new Set(seen))) {
        return true;
      }
      return false;
    }
    if (ts.isAwaitExpression(value)) return expressionTainted(value.expression, seen);
    if (ts.isConditionalExpression(value)) {
      return expressionTainted(value.whenTrue, new Set(seen)) ||
        expressionTainted(value.whenFalse, new Set(seen));
    }
    if (ts.isBinaryExpression(value)) {
      return expressionTainted(value.left, new Set(seen)) ||
        expressionTainted(value.right, new Set(seen));
    }
    if (ts.isPrefixUnaryExpression(value)) return expressionTainted(value.operand, seen);
    return false;
  };

  const objectProperties = (node) => {
    let value = unwrap(node);
    while (ts.isAwaitExpression(value)) value = unwrap(value.expression);
    if (!value) return new Set();
    if (ts.isIdentifier(value)) {
      return new Set(objectSymbolProperties.get(symbolAt(checker, value)) || []);
    }
    if (ts.isCallExpression(value)) {
      const symbol = symbolAt(checker, value.expression);
      const name = ts.isIdentifier(value.expression)
        ? value.expression.text
        : staticMemberName(value.expression, checker, staticStrings);
      return new Set([
        ...(functionReturnProperties.get(symbol) || []),
        ...(KNOWN_QUALITY_OBJECT_PRODUCERS.get(name) || []),
      ]);
    }
    if (ts.isObjectLiteralExpression(value)) {
      const properties = new Set();
      for (const property of value.properties) {
        if (!ts.isPropertyAssignment(property) && !ts.isShorthandPropertyAssignment(property)) continue;
        const name = propertyNameText(property.name, checker, staticStrings);
        const initializer = ts.isShorthandPropertyAssignment(property)
          ? property.name
          : property.initializer;
        if (QUALITY_SLOT_NAMES.has(name) ||
            (QUALITY_VALUE_MEMBER_NAMES.has(name) && expressionTainted(initializer))) {
          properties.add(name);
        }
      }
      return properties;
    }
    return new Set();
  };

  let changed = true;
  while (changed) {
    changed = false;
    for (const sourceFile of sourceFiles) {
      walk(sourceFile, (node) => {
        if (ts.isVariableDeclaration(node) && node.initializer) {
          const properties = objectProperties(node.initializer);
          if (ts.isIdentifier(node.name)) {
            changed = mergeProperties(
              objectSymbolProperties, symbolAt(checker, node.name), properties,
            ) || changed;
          } else if (ts.isObjectBindingPattern(node.name)) {
            for (const element of node.name.elements) {
              const property = propertyNameText(element.propertyName ?? element.name, checker, staticStrings);
              if (!properties.has(property)) continue;
              for (const identifier of bindingIdentifiers(element.name)) {
                changed = addReason(symbolAt(checker, identifier), "destructured") || changed;
              }
            }
          }
        }
        if (ts.isVariableDeclaration(node) && node.initializer && expressionTainted(node.initializer)) {
          for (const identifier of bindingIdentifiers(node.name)) {
            changed = addReason(symbolAt(checker, identifier),
              ts.isObjectBindingPattern(node.name) || ts.isArrayBindingPattern(node.name)
                ? "destructured" : "local-propagation") || changed;
          }
        }
        if (ts.isBinaryExpression(node) &&
            node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
            expressionTainted(node.right)) {
          const left = unwrap(node.left);
          if (ts.isIdentifier(left)) {
            changed = addReason(symbolAt(checker, left), "assignment-alias") || changed;
          }
        }
        if (ts.isCallExpression(node)) {
          const callee = symbolAt(checker, node.expression);
          const declaration = callee?.valueDeclaration ?? callee?.declarations?.find(ts.isFunctionLike);
          if (declaration && ts.isFunctionLike(declaration)) {
            for (let i = 0; i < Math.min(node.arguments.length, declaration.parameters.length); i++) {
              const argumentProperties = objectProperties(node.arguments[i]);
              for (const identifier of bindingIdentifiers(declaration.parameters[i].name)) {
                changed = mergeProperties(
                  objectSymbolProperties, symbolAt(checker, identifier), argumentProperties,
                ) || changed;
              }
              if (!expressionTainted(node.arguments[i])) continue;
              for (const identifier of bindingIdentifiers(declaration.parameters[i].name)) {
                changed = addReason(symbolAt(checker, identifier), "call-parameter") || changed;
              }
            }
          }
        }
      });
    }
    for (const fn of functionLikes) {
      const symbol = functionSymbol(checker, fn);
      if (!symbol || taintedFunctions.has(symbol)) continue;
      let returnsQuality = false;
      const returnedProperties = new Set();
      if (ts.isBlock(fn.body)) {
        walk(fn.body, (node) => {
          if (ts.isReturnStatement(node) && node.expression) {
            if (expressionTainted(node.expression)) returnsQuality = true;
            for (const property of objectProperties(node.expression)) returnedProperties.add(property);
          }
        });
      } else if (fn.body && expressionTainted(fn.body)) {
        returnsQuality = true;
        for (const property of objectProperties(fn.body)) returnedProperties.add(property);
      }
      if (returnsQuality) {
        taintedFunctions.add(symbol);
        changed = true;
      }
      changed = mergeProperties(functionReturnProperties, symbol, returnedProperties) || changed;
    }
  }

  const staticStatus = (node) => {
    const value = unwrap(node);
    if (!value) return null;
    if (value.kind === ts.SyntaxKind.NullKeyword) return { status: "null", recognized: true };
    if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) {
      const status = value.text.toLowerCase();
      return { status, recognized: ALLOWED_QUALITY_STATUSES.has(status) };
    }
    if (ts.isIdentifier(value)) {
      if (value.text === "undefined") return { status: "undefined", recognized: true };
      const constant = staticStrings.get(symbolAt(checker, value));
      if (constant != null) {
        const status = constant.toLowerCase();
        return { status, recognized: ALLOWED_QUALITY_STATUSES.has(status) };
      }
    }
    if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
      const object = unwrap(value.expression);
      const member = staticMemberName(value, checker, staticStrings);
      if (ts.isIdentifier(object) && object.text === "SCAN_QUALITY" && member) {
        const status = member.toLowerCase();
        return { status, recognized: ALLOWED_QUALITY_STATUSES.has(status) };
      }
    }
    return null;
  };

  const accessKinds = (node) => {
    const kinds = new Set();
    walk(node, (candidate) => {
      if (ts.isPropertyAccessExpression(candidate) || ts.isElementAccessExpression(candidate)) {
        const name = staticMemberName(candidate, checker, staticStrings);
        if (QUALITY_SLOT_NAMES.has(name)) {
          kinds.add(ts.isElementAccessExpression(candidate) ? "computed" : "member");
        }
      }
      if (ts.isIdentifier(candidate)) {
        const symbol = symbolAt(checker, candidate);
        for (const reason of taintReasons.get(symbol) || []) kinds.add(reason);
      }
    });
    return sorted(kinds);
  };

  const comparisons = [];
  const unclassified = [];
  for (const sourceFile of sourceFiles) {
    walk(sourceFile, (node) => {
      if (ts.isBinaryExpression(node) && COMPARISON_OPERATORS.has(node.operatorToken.kind)) {
        const leftTainted = expressionTainted(node.left);
        const rightTainted = expressionTainted(node.right);
        if (!leftTainted && !rightTainted) return;
        const other = leftTainted && !rightTainted ? node.right
          : rightTainted && !leftTainted ? node.left
            : null;
        const status = staticStatus(other);
        const base = {
          file: rel(sourceFile.fileName),
          line: sourceLine(sourceFile, node),
          operator: ts.tokenToString(node.operatorToken.kind) || "comparison",
          snippet: normalizedSnippet(sourceFile, node),
          access: accessKinds(leftTainted ? node.left : node.right),
        };
        if (!other && leftTainted && rightTainted) {
          comparisons.push({
            ...base,
            statuses: ["dynamic-quality"],
            kind: "quality-parity",
            clusterStart: node.getStart(sourceFile),
            clusterEnd: node.getEnd(),
          });
          return;
        }
        if (!status || !status.recognized) {
          unclassified.push({
            ...base,
            reason: status ? `unknown-status:${status.status}` : "comparison-without-static-status",
          });
          return;
        }
        let cluster = node;
        while (cluster.parent && (
          ts.isParenthesizedExpression(cluster.parent) ||
          (ts.isBinaryExpression(cluster.parent) && [
            ts.SyntaxKind.BarBarToken,
            ts.SyntaxKind.AmpersandAmpersandToken,
          ].includes(cluster.parent.operatorToken.kind))
        )) cluster = cluster.parent;
        comparisons.push({
          ...base,
          statuses: [status.status],
          kind: "binary",
          clusterStart: cluster.getStart(sourceFile),
          clusterEnd: cluster.getEnd(),
        });
        return;
      }

      if (ts.isCallExpression(node) &&
          (ts.isPropertyAccessExpression(node.expression) || ts.isElementAccessExpression(node.expression)) &&
          ["includes", "has"].includes(staticMemberName(node.expression, checker, staticStrings))) {
        const receiver = unwrap(node.expression.expression);
        const taintedArgument = node.arguments.find((argument) => expressionTainted(argument));
        const receiverTainted = expressionTainted(receiver);
        if (!taintedArgument && !receiverTainted) return;
        const collectionStatuses = ts.isIdentifier(receiver)
          ? staticStatusCollections.get(symbolAt(checker, receiver))
          : null;
        const statusNodes = receiverTainted ? node.arguments :
          (ts.isArrayLiteralExpression(receiver) ? receiver.elements : []);
        const statuses = collectionStatuses
          ? collectionStatuses.map((status) => ({ status, recognized: true }))
          : statusNodes.map(staticStatus).filter(Boolean);
        const base = {
          file: rel(sourceFile.fileName),
          line: sourceLine(sourceFile, node),
          operator: staticMemberName(node.expression, checker, staticStrings),
          snippet: normalizedSnippet(sourceFile, node),
          access: accessKinds(taintedArgument ?? receiver),
        };
        if (statuses.length === 0 || statuses.some((status) => !status.recognized)) {
          unclassified.push({ ...base, reason: "membership-without-recognized-static-statuses" });
          return;
        }
        comparisons.push({
          ...base,
          statuses: sorted(new Set(statuses.map((status) => status.status))),
          kind: "membership",
          clusterStart: node.getStart(sourceFile),
          clusterEnd: node.getEnd(),
        });
      }

      if (ts.isCaseClause(node) && node.expression && ts.isSwitchStatement(node.parent?.parent) &&
          expressionTainted(node.parent.parent.expression)) {
        const status = staticStatus(node.expression);
        const base = {
          file: rel(sourceFile.fileName),
          line: sourceLine(sourceFile, node),
          operator: "case",
          snippet: normalizedSnippet(sourceFile, node),
          access: accessKinds(node.parent.parent.expression),
        };
        if (!status || !status.recognized) {
          unclassified.push({ ...base, reason: "switch-case-without-recognized-status" });
          return;
        }
        comparisons.push({
          ...base,
          statuses: [status.status],
          kind: "switch",
          clusterStart: node.parent.parent.getStart(sourceFile),
          clusterEnd: node.parent.parent.getEnd(),
        });
      }
    });
  }

  const comparisonSignature = (site) => [
    site.file, site.line, site.kind, site.operator,
    site.statuses.join("+"), site.access.join("+"),
    `${site.clusterStart}-${site.clusterEnd}`, site.snippet,
  ].join(":" );
  const runtime = comparisons.filter((site) => isRuntimeFile(path.join(root, site.file)));
  const governance = comparisons.filter((site) => !isRuntimeFile(path.join(root, site.file)));
  return {
    runtime,
    governance,
    unclassified,
    runtimeFingerprint: fingerprint(runtime.map(comparisonSignature)),
    governanceFingerprint: fingerprint(governance.map(comparisonSignature)),
  };
}

function staticText(node) {
  if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) return node.text;
  if (!ts.isTemplateExpression(node)) return null;
  return node.head.text + node.templateSpans.map((span) =>
    ` __EXPR__ ${span.literal.text}`).join("");
}

function callMemberName(expression) {
  if (ts.isPropertyAccessExpression(expression)) return expression.name.text;
  if (ts.isElementAccessExpression(expression)) {
    const argument = unwrap(expression.argumentExpression);
    return ts.isStringLiteral(argument) ? argument.text : null;
  }
  return null;
}

function sqlSinkFunctions(sourceFiles, checker) {
  const sinks = new Set();
  for (const sourceFile of sourceFiles) {
    walk(sourceFile, (node) => {
      if (!ts.isFunctionLike(node) || !node.body) return;
      const parameterSymbols = new Set(node.parameters.flatMap((parameter) =>
        bindingIdentifiers(parameter.name).map((identifier) => symbolAt(checker, identifier))));
      let consumesParameter = false;
      walk(node.body, (candidate) => {
        if (!ts.isCallExpression(candidate) ||
            !["prepare", "exec"].includes(callMemberName(candidate.expression))) return;
        if (candidate.arguments.some((argument) => {
          const value = unwrap(argument);
          return ts.isIdentifier(value) && parameterSymbols.has(symbolAt(checker, value));
        })) consumesParameter = true;
      });
      if (consumesParameter) {
        const symbol = functionSymbol(checker, node);
        if (symbol) sinks.add(symbol);
      }
    });
  }
  return sinks;
}

function isSqlContext(node, checker, sinks) {
  const parent = node.parent;
  if (ts.isCallExpression(parent) && parent.arguments.includes(node)) {
    return ["prepare", "exec"].includes(callMemberName(parent.expression)) ||
      sinks.has(symbolAt(checker, parent.expression));
  }
  if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
    return SQL_NAME.test(parent.name.text);
  }
  return false;
}

function sqlTokens(text) {
  const tokens = [];
  const matcher = /'(?:''|[^'])*'|"(?:""|[^"])*"|!=|<>|<=|>=|==|=|\?|[A-Za-z_][A-Za-z0-9_]*|[().,]|\S/g;
  let match;
  while ((match = matcher.exec(text)) !== null) {
    const raw = match[0];
    const quoted = raw.startsWith("'") && raw.endsWith("'");
    tokens.push({ raw, lower: raw.toLowerCase(), quoted, index: match.index });
  }
  return tokens;
}

function sqlStatus(token) {
  if (!token) return null;
  if (token.quoted) return token.raw.slice(1, -1).replace(/''/g, "'").toLowerCase();
  if (token.lower === "null") return "null";
  if (token.raw === "?") return "parameter";
  return null;
}

function sqlPredicates(text) {
  const tokens = sqlTokens(text);
  const predicates = [];
  const majorClauses = new Set([
    "select", "set", "where", "having", "when", "on", "values",
    "order", "group", "limit", "returning",
  ]);
  for (let i = 0; i < tokens.length; i++) {
    if (tokens[i].lower !== "scan_quality") continue;
    let clause = null;
    for (let j = i - 1; j >= 0; j--) {
      if (majorClauses.has(tokens[j].lower)) {
        clause = tokens[j].lower;
        break;
      }
    }
    // A dynamic template may carry its WHERE clause inside __EXPR__ (for
    // example current-posture's shared FROM fragment). A scan_quality
    // comparison remains a predicate unless the nearest major clause is SET.
    if (["set", "values", "returning"].includes(clause)) continue;

    let operator = null;
    let status = null;
    const next = tokens[i + 1];
    const previous = tokens[i - 1];
    if (["=", "==", "!=", "<>"].includes(next?.raw)) {
      operator = next.raw;
      status = sqlStatus(tokens[i + 2]);
    } else {
      // Reversed predicates may qualify the slot (`'complete' = s.scan_quality`),
      // so the comparison operator is three tokens back rather than adjacent.
      const reversedOperatorIndex = previous?.raw === "." ? i - 3 : i - 1;
      const reversedOperator = tokens[reversedOperatorIndex];
      if (["=", "==", "!=", "<>"].includes(reversedOperator?.raw)) {
        operator = `reversed-${reversedOperator.raw}`;
        status = sqlStatus(tokens[reversedOperatorIndex - 1]);
      }
    }
    if (!operator && next?.lower === "is") {
      const not = tokens[i + 2]?.lower === "not";
      operator = not ? "is-not" : "is";
      status = sqlStatus(tokens[i + (not ? 3 : 2)]);
    } else if (!operator && (next?.lower === "in" ||
        (next?.lower === "not" && tokens[i + 2]?.lower === "in"))) {
      const offset = next.lower === "not" ? 4 : 3;
      operator = next.lower === "not" ? "not-in" : "in";
      status = sqlStatus(tokens[i + offset]);
    }
    // A selected/projected scan_quality column is not a predicate. Once a
    // comparison operator exists, however, an unknown RHS is an unclassified
    // gate and must fail closed below.
    if (!operator) continue;
    predicates.push({ operator, status, index: tokens[i].index });
  }
  return predicates;
}

function analyseSql(sourceFiles, checker) {
  const sites = [];
  const unclassified = [];
  const sinks = sqlSinkFunctions(sourceFiles, checker);
  for (const sourceFile of sourceFiles.filter((file) => isRuntimeFile(file.fileName))) {
    walk(sourceFile, (node) => {
      const text = staticText(node);
      if (text == null || !/\bscan_quality\b/i.test(text) ||
          !isSqlContext(node, checker, sinks)) return;
      const predicates = sqlPredicates(text);
      if (predicates.length === 0) return;
      const site = {
        file: rel(sourceFile.fileName),
        line: sourceLine(sourceFile, node),
        predicates,
        snippet: text.replace(/\s+/g, " ").trim(),
      };
      sites.push(site);
      for (const predicate of predicates) {
        if (predicate.operator === "unclassified" ||
            !ALLOWED_QUALITY_STATUSES.has(predicate.status)) {
          unclassified.push({ ...site, predicate });
        }
      }
    });
  }
  const signature = (site) => [
    site.file, site.line,
    site.predicates.map((predicate) => `${predicate.operator}:${predicate.status}`).join("+"),
    site.snippet,
  ].join(":" );
  return {
    sites,
    unclassified,
    predicateOccurrences: sites.reduce((sum, site) => sum + site.predicates.length, 0),
    fingerprint: fingerprint(sites.map(signature)),
  };
}

const files = collectSourceFiles();
const compilerOptions = {
  allowJs: true,
  checkJs: false,
  jsx: ts.JsxEmit.Preserve,
  target: ts.ScriptTarget.Latest,
  module: ts.ModuleKind.ESNext,
  moduleResolution: ts.ModuleResolutionKind.Bundler,
  noEmit: true,
  skipLibCheck: true,
};
const host = ts.createCompilerHost(compilerOptions);
const program = ts.createProgram(files, compilerOptions, host);
const checker = program.getTypeChecker();
const sourceFiles = files.map((filename) => program.getSourceFile(filename)).filter(Boolean);
const parseFailures = [];
for (const filename of files) {
  const sourceText = fs.readFileSync(filename, "utf8");
  const parsed = ts.createSourceFile(
    filename, sourceText, ts.ScriptTarget.Latest, true, scriptKind(filename),
  );
  for (const diagnostic of parsed.parseDiagnostics) {
    parseFailures.push(`${rel(filename)}:${diagnostic.start ?? 0}:${String(diagnostic.messageText)}`);
  }
}

const semantic = analyseSemanticComparisons(sourceFiles, checker);
const sql = analyseSql(sourceFiles, checker);
const runtimeSemanticFiles = new Set(semantic.runtime.map((site) => site.file));
const governanceFiles = new Set(semantic.governance.map((site) => site.file));
const sqlFiles = new Set(sql.sites.map((site) => site.file));
const runtimeFiles = new Set([...runtimeSemanticFiles, ...sqlFiles]);
// A partial comparison is partial-only when its nearest boolean OR/AND cluster
// has no sibling degraded/complete comparison. This keeps ScanDetail's explicit
// partial+degraded branch and normalizeQuality's exhaustive three-way vocabulary
// distinct from the known ASM verification defect.
const runtimeClusters = new Map();
for (const site of semantic.runtime) {
  const key = `${site.file}:${site.clusterStart}:${site.clusterEnd}`;
  if (!runtimeClusters.has(key)) runtimeClusters.set(key, []);
  runtimeClusters.get(key).push(site);
}
const partialOnlyCandidates = [...runtimeClusters.values()]
  .filter((sites) => {
    const statuses = new Set(sites.flatMap((site) => site.statuses));
    return statuses.size === 1 && statuses.has("partial");
  })
  .flat();
const knownAsmPartial = partialOnlyCandidates.filter((site) =>
  site.file === "workers/scan-api/src/engines/asm-cases.js" &&
  site.snippet.includes('scanQuality?.status === "partial"'),
);

const current = {
  runtime: {
    comparison_occurrences: semantic.runtime.length,
    source_file_count: runtimeSemanticFiles.size,
    fingerprint: semantic.runtimeFingerprint,
    partial_only_fingerprint: fingerprint(partialOnlyCandidates.map((site) =>
      `${site.file}:${site.line}:${site.clusterStart}-${site.clusterEnd}:${site.snippet}`)),
  },
  sql: {
    predicate_occurrences: sql.predicateOccurrences,
    unique_query_sites: sql.sites.length,
    source_file_count: sqlFiles.size,
    fingerprint: sql.fingerprint,
  },
  governance: {
    comparison_occurrences: semantic.governance.length,
    source_file_count: governanceFiles.size,
    fingerprint: semantic.governanceFingerprint,
  },
  runtime_source_file_count: runtimeFiles.size,
};

function dumpInventory() {
  console.log(JSON.stringify({
    counts: current,
    runtime_comparisons: semantic.runtime,
    sql_sites: sql.sites,
    governance_comparisons: semantic.governance,
    unclassified: [...semantic.unclassified, ...sql.unclassified],
    parse_failures: parseFailures,
    known_partial_only_gate: knownAsmPartial,
  }, null, 2));
}

if (process.argv.includes("--dump-current")) {
  dumpInventory();
  process.exit(0);
}
if (process.argv.includes("--dump-counts")) {
  console.log(JSON.stringify({
    counts: current,
    unclassified: [...semantic.unclassified, ...sql.unclassified],
    known_partial_only_gate: knownAsmPartial,
    runtime_site_keys: semantic.runtime.map((site) =>
      `${site.file}:${site.line}:${site.snippet}`),
    sql_site_keys: sql.sites.map((site) => `${site.file}:${site.line}:${site.predicates.length}`),
  }, null, 2));
  process.exit(0);
}

console.log("Scan-quality inventory taxonomy (units are deliberately separate):");
console.log(`  runtime SQL predicate occurrences: ${current.sql.predicate_occurrences}`);
console.log(`  unique runtime SQL query sites: ${current.sql.unique_query_sites}`);
console.log(`  runtime source file count (SQL ∪ semantic): ${current.runtime_source_file_count}`);
console.log(`  JS/TS runtime semantic comparisons: ${current.runtime.comparison_occurrences}`);
console.log(`  validation/governance semantic comparisons: ${current.governance.comparison_occurrences}`);
console.log(`  runtime semantic source files: ${current.runtime.source_file_count}`);
console.log(`  runtime SQL source files: ${current.sql.source_file_count}`);
console.log(`  governance source files: ${current.governance.source_file_count}`);

const cleanParse = parseFailures.length === 0;
ok("AST: all governed JS/TS sources parse", cleanParse, parseFailures.join(" | "));

const runtimeMatches = JSON.stringify(current.runtime) === JSON.stringify(EXPECTED.runtime) &&
  current.runtime_source_file_count === EXPECTED.runtime_source_file_count;
ok(
  "runtime: semantic scan-quality comparison inventory is exact",
  cleanParse ? runtimeMatches : true,
  `got ${JSON.stringify({ ...current.runtime, runtime_source_file_count: current.runtime_source_file_count })}`,
);

const sqlMatches = JSON.stringify(current.sql) === JSON.stringify(EXPECTED.sql);
ok(
  "SQL: runtime scan-quality predicate inventory is exact",
  cleanParse ? sqlMatches : true,
  `got ${JSON.stringify(current.sql)}`,
);

const governanceMatches = JSON.stringify(current.governance) === JSON.stringify(EXPECTED.governance);
ok(
  "governance: validation scan-quality comparison inventory is exact",
  cleanParse ? governanceMatches : true,
  `got ${JSON.stringify(current.governance)}`,
);

const unclassified = [...semantic.unclassified, ...sql.unclassified];
ok(
  "classification: no scan-quality gate is unclassified or uses an unknown status",
  cleanParse ? unclassified.length === 0 : true,
  unclassified.map((site) => `${site.file}:${site.line}:${site.reason || site.predicate?.status}`).join(" | "),
);

ok(
  "taxonomy: occurrence, query-site and source-file units remain internally consistent",
  current.sql.predicate_occurrences >= current.sql.unique_query_sites &&
    current.sql.unique_query_sites >= current.sql.source_file_count &&
    current.runtime_source_file_count >= current.runtime.source_file_count &&
    current.runtime_source_file_count >= current.sql.source_file_count,
);

ok(
  "defect: asm-cases partial-only verification gate remains explicit and unfixed",
  cleanParse ? knownAsmPartial.length === 1 : true,
  `found ${knownAsmPartial.length}; PR-1 inventories this defect and must not fix it`,
);

const assertionTotal = passed + failed;
if (assertionTotal !== EXPECTED_ASSERTIONS) {
  console.log(`FAIL pinned assertion count — got ${assertionTotal}, want ${EXPECTED_ASSERTIONS}`);
  process.exit(1);
}
console.log(`\nScan-quality vocabulary inventory: ${passed} passed, ${failed} failed (${assertionTotal} total)`);
if (failed > 0) process.exit(1);
console.log("Scan-quality vocabulary inventory passed");
