#!/usr/bin/env node
// CT-R2 PR-1 — exhaustive statically-resolvable canonical-slot direct-read inventory.
//
// The JavaScript/TypeScript side is AST-backed. It follows the canonical
// scan_quality slot through dot/computed access, destructuring, aliases, local
// propagation, arbitrary object properties, arrays, Map/Set collections, helper
// returns and calls. Comments and string contents are not semantic JS callers.
// SQL is a separate taxonomy: static predicate fragments are name-independent,
// query-sink interpolation is resolved by data flow, and SET assignments are not
// misreported as predicates. Governance covers statically resolvable comparisons
// plus exact reviewed dynamic sites; it does not claim dynamic-program exhaustiveness.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const frontendRequire = createRequire(path.join(root, "frontend", "package.json"));
const ts = frontendRequire("typescript");

const EXPECTED_ASSERTIONS = 10;
const EXPECTED = Object.freeze({
  runtime: {
    // D1 SUCCESSION (FD-006/seq50 + seq126): 49 -> 48. The literal
    // `scanQuality?.status === "partial"` in asm-cases.js was replaced by the shared
    // `isNonAuthoritativeQuality(...)` predicate, which removes one literal status
    // comparison while WIDENING the protection to cover `degraded`. The
    // partial_only fingerprint changes for the same reason: there is no longer a
    // partial-only verification gate to fingerprint.
    // SEQ-151 SUCCESSION: counts UNCHANGED (48 across 22 files); only the
    // fingerprint moves, because the governed gate in asm-cases.js now also reads
    // the authoritative-quality predicate. No comparison was added or removed.
    comparison_occurrences: 48,
    source_file_count: 22,
    // SUCCESSOR-3: re-measured on the integrated tree (D1 + the #416 surface work).
    // Counts land at 48/22 exactly as the D1 succession above predicted.
    fingerprint: "abf2bc916921dbc00f75771947410e72497f9632b97cee11ce9264a4569bd951",
    partial_only_fingerprint: "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
  },
  sql: {
    predicate_occurrences: 35,
    unique_query_sites: 26,
    source_file_count: 15,
    fingerprint: "2127c44f4d47bd0833eaf37d054880d4fe37b3022b84de05b4c5210e7c6f8953",
    resolved_query_sink_count: 19,
    resolved_query_sink_fingerprint: "91325ab2b522e85a68d5e5e4906631b4ac3d5ebf8fc5c9c29afd33674e8b5a92",
  },
  governance: {
    // D1 SUCCESSION: 61 -> 63 across 21 -> 23 files. Purely ADDITIVE: the new D1
    // fixture/successor validators introduce governed comparisons. No governance
    // comparison was removed.
    // P1.1 SUCCESSION: 65 -> 67 across 25 -> 26 files. Purely ADDITIVE: the new
    // P1.1 serviceability validators introduce governed comparisons in their own
    // files. The RUNTIME sets are unchanged (48/22 and 92/34), which is the check
    // that matters — the product gained no new scan-quality comparison.
    comparison_occurrences: 67,
    source_file_count: 26,
    // SEQ-167 SUCCESSION: counts UNCHANGED (63 comparisons across 23 files); only the
    // fingerprint moves, because the type/value matrix adds governed comparisons in
    // the successor validator. Nothing was added to or removed from the runtime set.
    // SUCCESSOR-3: 63 -> 65 across 23 -> 25 files. Additive only: PR #414/#416 added
    // governed comparisons in their own validators. Nothing was removed.
    fingerprint: "d01804a1b66dd87da5618a544e0e49bc9680cd73dbdb96964d9d29702a49c62c",
  },
  runtime_source_file_count: 32,
  direct: {
    // D1 SUCCESSION: count unchanged at 92; fingerprint moves because the
    // asm-cases read now flows through the shared predicate.
    // SEQ-151 SUCCESSION: count UNCHANGED at 92; fingerprint moves for the same
    // reason as the runtime comparison set above.
    runtime: { occurrence_count: 92, source_file_count: 34, fingerprint: "d02621b3ca7905e55bb1a946ef6e8858825231f4ac6a0e4d3624bfd9aa676b27" },
    // D1 SUCCESSION: 89 -> 91, additive from the new D1 validators.
    // SUCCESSOR-3: 91 -> 104 across 34 -> 36 files, additive from the PR #414/#416 validators.
    // P1.1 SUCCESSION: 104 -> 108 across 36 -> 37 files, additive from the P1.1 validators.
    governance: { occurrence_count: 108, source_file_count: 37, fingerprint: "9649c7514d3fdea01df043d77eff8ab4fa8d2f0ec3d89e2ee8cde9833a1298fd" },
  },
  sql_reads: { projection_occurrences: 23, fingerprint: "11c0012aac9dfa1436907821901d393eb591e7d78921b2eabdfa4d73eb9543e8" },
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
const COMPARISON_OPERATORS = new Set([
  ts.SyntaxKind.EqualsEqualsToken,
  ts.SyntaxKind.EqualsEqualsEqualsToken,
  ts.SyntaxKind.ExclamationEqualsToken,
  ts.SyntaxKind.ExclamationEqualsEqualsToken,
]);
const QUALITY_RETURN_FUNCTION_NAMES = new Set([
  "normalizeQuality", "scanCompletionQualityDisclosure",
  "scanQualityStatus", "incompleteCustomerQuality",
]);
const QUALITY_PASSTHROUGH_FUNCTION_NAMES = new Set(["String"]);
const KNOWN_QUALITY_OBJECT_PRODUCERS = new Map([
  ["buildScanQuality", new Set(["status"])],
]);
const QUALITY_NORMALIZER_METHODS = new Set(["trim", "toLowerCase", "toString"]);
// These two comparisons consume JSON emitted by a fresh child process. Its
// runtime provenance cannot be statically joined to this process's AST, so the
// exact file/line/expression contract is reviewed and fingerprinted. This is not
// a property-name or regex allowlist: any move, rename or new site changes the
// governance inventory and requires review.
const REVIEWED_DYNAMIC_QUALITY_EXPRESSIONS = new Map([
  ["scripts/validate-phase5-evidence-honesty.js:193:engine.quality",
    "child-process runScanEngine quality projection"],
  ["scripts/validate-phase5-evidence-honesty.js:193:engine.reportQuality",
    "child-process runScanEngine report-quality projection"],
]);
const EXPECTED_UNRESOLVED_GOVERNANCE = Object.freeze([
  "scripts/validate-msp-portfolio-domains.js:436:detail.data?.phase5_assessment?.quality === listIncomplete?.phase5_assessment?.quality",
  "scripts/validate-partial-scan-honesty.js:232:stale.quality === \"unknown\"",
  "scripts/validate-phase5-evidence-honesty.js:220:presentation.quality === \"partial\"",
  "scripts/validate-signal-monitoring-state.js:257:degraded.quality === \"degraded\"",
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
  const collectionSymbols = new Set();
  const collectionReasons = new Map();
  const taintReasons = new Map();
  const reviewedDynamicSeen = new Set();
  const functionLikes = [];

  const addReason = (symbol, reason) => {
    if (!symbol) return false;
    const existed = taintedSymbols.has(symbol);
    taintedSymbols.add(symbol);
    if (!taintReasons.has(symbol)) taintReasons.set(symbol, new Set());
    taintReasons.get(symbol).add(reason);
    return !existed;
  };
  const addCollection = (symbol, reason) => {
    if (!symbol) return false;
    const existed = collectionSymbols.has(symbol);
    collectionSymbols.add(symbol);
    if (!collectionReasons.has(symbol)) collectionReasons.set(symbol, new Set());
    collectionReasons.get(symbol).add(reason);
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
  const reviewedDynamicExpression = (node) => {
    const value = unwrap(node);
    if (!value || (!ts.isPropertyAccessExpression(value) && !ts.isElementAccessExpression(value))) {
      return null;
    }
    const sourceFile = value.getSourceFile();
    const key = `${rel(sourceFile.fileName)}:${sourceLine(sourceFile, value)}:${normalizedSnippet(sourceFile, value)}`;
    return REVIEWED_DYNAMIC_QUALITY_EXPRESSIONS.has(key) ? key : null;
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

  let collectionTainted;
  const expressionTainted = (node, seen = new Set()) => {
    const value = unwrap(node);
    if (!value || seen.has(value)) return false;
    seen.add(value);
    if (ts.isIdentifier(value)) return taintedSymbols.has(symbolAt(checker, value));
    if (ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)) {
      const reviewedKey = reviewedDynamicExpression(value);
      if (reviewedKey) {
        reviewedDynamicSeen.add(reviewedKey);
        return true;
      }
      const name = staticMemberName(value, checker, staticStrings);
      if (QUALITY_SLOT_NAMES.has(name)) return true;
      const object = unwrap(value.expression);
      if (ts.isIdentifier(object) &&
          objectSymbolProperties.get(symbolAt(checker, object))?.has(name)) return true;
      if (ts.isElementAccessExpression(value) && collectionTainted(value.expression, new Set(seen))) {
        return true;
      }
      // A tainted object remains tainted through any property name. The
      // property spelling is data, not a semantic allowlist.
      return expressionTainted(value.expression, new Set(seen));
    }
    if (ts.isCallExpression(value) || ts.isNewExpression(value)) {
      const calleeSymbol = symbolAt(checker, value.expression);
      if (taintedFunctions.has(calleeSymbol)) return true;
      const calleeName = ts.isIdentifier(value.expression)
        ? value.expression.text
        : staticMemberName(value.expression, checker, staticStrings);
      if (QUALITY_RETURN_FUNCTION_NAMES.has(calleeName)) {
        return true;
      }
      if (QUALITY_PASSTHROUGH_FUNCTION_NAMES.has(calleeName) &&
          (value.arguments || []).some((argument) => expressionTainted(argument, new Set(seen)))) {
        return true;
      }
      if ((ts.isPropertyAccessExpression(value.expression) || ts.isElementAccessExpression(value.expression)) &&
          QUALITY_NORMALIZER_METHODS.has(calleeName) &&
          expressionTainted(value.expression.expression, new Set(seen))) {
        return true;
      }
      if ((ts.isPropertyAccessExpression(value.expression) || ts.isElementAccessExpression(value.expression)) &&
          calleeName === "get" && collectionTainted(value.expression.expression, new Set(seen))) {
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

  collectionTainted = (node, seen = new Set()) => {
    const value = unwrap(node);
    if (!value || seen.has(value)) return false;
    seen.add(value);
    if (ts.isIdentifier(value)) return collectionSymbols.has(symbolAt(checker, value));
    if (ts.isArrayLiteralExpression(value)) {
      return value.elements.some((element) => {
        const item = unwrap(element);
        return ts.isSpreadElement(item)
          ? collectionTainted(item.expression, new Set(seen))
          : expressionTainted(item, new Set(seen)) || collectionTainted(item, new Set(seen));
      });
    }
    if (ts.isNewExpression(value)) {
      const name = ts.isIdentifier(value.expression) ? value.expression.text : null;
      if (!["Array", "Map", "Set"].includes(name)) return false;
      return (value.arguments || []).some((argument) =>
        expressionTainted(argument, new Set(seen)) || collectionTainted(argument, new Set(seen)));
    }
    if (ts.isCallExpression(value)) {
      const member = staticMemberName(value.expression, checker, staticStrings);
      if (ts.isPropertyAccessExpression(value.expression) || ts.isElementAccessExpression(value.expression)) {
        const receiver = value.expression.expression;
        if (["values", "entries", "filter", "map", "flatMap", "slice", "concat"].includes(member) &&
            collectionTainted(receiver, new Set(seen))) return true;
        const receiverValue = unwrap(receiver);
        if (ts.isIdentifier(receiverValue) && receiverValue.text === "Array" && member === "from" &&
            value.arguments.some((argument) => collectionTainted(argument, new Set(seen)))) return true;
      }
    }
    if (ts.isConditionalExpression(value)) {
      return collectionTainted(value.whenTrue, new Set(seen)) ||
        collectionTainted(value.whenFalse, new Set(seen));
    }
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
        // Property names are not semantic authority. Any property whose
        // initializer carries scan-quality taint remains tainted through dot,
        // computed or renamed/destructured reads.
        if (QUALITY_SLOT_NAMES.has(name) || expressionTainted(initializer)) {
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
        if (ts.isVariableDeclaration(node) && node.initializer && collectionTainted(node.initializer)) {
          for (const identifier of bindingIdentifiers(node.name)) {
            changed = addCollection(symbolAt(checker, identifier), "collection-initializer") || changed;
          }
        }
        if (ts.isBinaryExpression(node) &&
            node.operatorToken.kind === ts.SyntaxKind.EqualsToken &&
            expressionTainted(node.right)) {
          const left = unwrap(node.left);
          if (ts.isIdentifier(left)) {
            changed = addReason(symbolAt(checker, left), "assignment-alias") || changed;
          } else if (ts.isElementAccessExpression(left)) {
            const receiver = unwrap(left.expression);
            if (ts.isIdentifier(receiver)) {
              changed = addCollection(symbolAt(checker, receiver), "collection-assignment") || changed;
            }
          }
        }
        if (ts.isForOfStatement(node) && collectionTainted(node.expression)) {
          const initializer = node.initializer;
          const binding = ts.isVariableDeclarationList(initializer)
            ? initializer.declarations[0]?.name
            : initializer;
          if (binding) {
            for (const identifier of bindingIdentifiers(binding)) {
              changed = addReason(symbolAt(checker, identifier), "collection-iteration") || changed;
            }
          }
        }
        if (ts.isCallExpression(node)) {
          const member = staticMemberName(node.expression, checker, staticStrings);
          if (ts.isPropertyAccessExpression(node.expression) || ts.isElementAccessExpression(node.expression)) {
            const receiver = unwrap(node.expression.expression);
            const mutationArguments = member === "set" ? node.arguments.slice(1, 2)
              : ["add", "push", "unshift"].includes(member) ? [...node.arguments]
                : [];
            if (ts.isIdentifier(receiver) && mutationArguments.some((argument) =>
              expressionTainted(argument) || collectionTainted(argument))) {
              changed = addCollection(
                symbolAt(checker, receiver), `collection-${member}`,
              ) || changed;
            }
            if (["filter", "map", "flatMap", "find", "findLast", "some", "every", "forEach"].includes(member) &&
                collectionTainted(receiver)) {
              const callback = unwrap(node.arguments[0]);
              if (callback && (ts.isArrowFunction(callback) || ts.isFunctionExpression(callback))) {
                const firstParameter = callback.parameters[0];
                if (firstParameter) {
                  for (const identifier of bindingIdentifiers(firstParameter.name)) {
                    changed = addReason(
                      symbolAt(checker, identifier), "collection-callback",
                    ) || changed;
                  }
                }
              }
            }
          }
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
        const object = unwrap(candidate.expression);
        if (ts.isIdentifier(object) &&
            objectSymbolProperties.get(symbolAt(checker, object))?.has(name)) {
          kinds.add(ts.isElementAccessExpression(candidate)
            ? "computed-object-property" : "object-property");
        }
        if (ts.isElementAccessExpression(candidate) && collectionTainted(candidate.expression)) {
          kinds.add("collection-index");
        }
        if (reviewedDynamicExpression(candidate)) kinds.add("reviewed-dynamic");
      }
      if (ts.isIdentifier(candidate)) {
        const symbol = symbolAt(checker, candidate);
        for (const reason of taintReasons.get(symbol) || []) kinds.add(reason);
        for (const reason of collectionReasons.get(symbol) || []) kinds.add(reason);
      }
    });
    return sorted(kinds);
  };

  const comparisons = [];
  const unclassified = [];
  const qualityComparisonCandidates = [];
  const isQualitySemantic = (base) => {
    if (base.snippet.includes("modules_skipped")) return false;
    if (base.access.some((kind) => [
      "object-property", "computed-object-property", "collection-index",
      "collection-initializer", "collection-assignment", "collection-iteration",
      "collection-callback", "collection-set", "collection-add", "collection-push",
      "reviewed-dynamic",
    ].includes(kind))) return true;
    return /\bscan[_]quality\b|\bscanQuality\b/.test(base.snippet);
  };
  for (const sourceFile of sourceFiles) {
    walk(sourceFile, (node) => {
      if (ts.isBinaryExpression(node) && COMPARISON_OPERATORS.has(node.operatorToken.kind)) {
        const qualityMember = [node.left, node.right].find((side) => {
          const value = unwrap(side);
          return ts.isPropertyAccessExpression(value) || ts.isElementAccessExpression(value)
            ? ["quality", "reportQuality"].includes(staticMemberName(value, checker, staticStrings))
            : false;
        });
        if (qualityMember) {
          qualityComparisonCandidates.push({
            file: rel(sourceFile.fileName),
            line: sourceLine(sourceFile, node),
            snippet: normalizedSnippet(sourceFile, node),
          });
        }
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
          if (isQualitySemantic(base)) {
            unclassified.push({
              ...base,
              reason: status ? `unknown-status:${status.status}` : "comparison-without-static-status",
            });
          }
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
          if (!isQualitySemantic(base)) return;
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
  const resolvedQualityKeys = new Set(comparisons.map((site) =>
    `${site.file}:${site.line}:${site.snippet}`));
  const unresolvedGovernance = qualityComparisonCandidates.filter((site) =>
    !isRuntimeFile(path.join(root, site.file)) &&
    !resolvedQualityKeys.has(`${site.file}:${site.line}:${site.snippet}`));
  return {
    runtime,
    governance,
    unclassified,
    reviewedDynamicOccurrences: reviewedDynamicSeen.size,
    unresolvedGovernance,
    runtimeFingerprint: fingerprint(runtime.map(comparisonSignature)),
    governanceFingerprint: fingerprint(governance.map(comparisonSignature)),
  };
}

// Primary authority: direct canonical-slot reads only. This deliberately does
// not attempt to prove arbitrary downstream value flow.
function analyseDirectReads(sourceFiles, checker) {
  const sites = [];
  const staticStrings = new Map();
  for (const sf of sourceFiles) walk(sf, (node) => {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      const value = unwrap(node.initializer);
      if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) {
        staticStrings.set(symbolAt(checker, node.name), value.text);
      }
    }
  });
  const add = (sf, node, kind, slot = "scan_quality") => {
    sites.push({ file: rel(sf.fileName), line: sourceLine(sf, node), kind, slot,
      snippet: normalizedSnippet(sf, node) });
  };
  for (const sf of sourceFiles) walk(sf, (node) => {
    if (ts.isPropertyAccessExpression(node) && QUALITY_SLOT_NAMES.has(node.name.text)) {
      const parent = node.parent;
      const writeOnly = ts.isBinaryExpression(parent) && parent.left === node &&
        parent.operatorToken.kind === ts.SyntaxKind.EqualsToken;
      if (!writeOnly) add(sf, node, "member-access");
    } else if (ts.isElementAccessExpression(node)) {
      const arg = unwrap(node.argumentExpression);
      const key = ts.isStringLiteral(arg) || ts.isNoSubstitutionTemplateLiteral(arg)
        ? arg.text : ts.isIdentifier(arg) ? staticStrings.get(symbolAt(checker, arg)) : null;
      const parent = node.parent;
      const writeOnly = ts.isBinaryExpression(parent) && parent.left === node &&
        parent.operatorToken.kind === ts.SyntaxKind.EqualsToken;
      if (!writeOnly && QUALITY_SLOT_NAMES.has(key)) add(sf, node, "computed-access", key);
    } else if (ts.isBindingElement(node)) {
      const key = propertyNameText(node.propertyName || node.name, checker, new Map());
      if (QUALITY_SLOT_NAMES.has(key)) add(sf, node, "destructuring", key);
    }
  });
  const signature = (site) => `${site.file}:${site.line}:${site.kind}:${site.slot}:${site.snippet}`;
  return { sites, fingerprint: fingerprint(sites.map(signature)) };
}

function staticText(node, checker, seenSymbols = new Set()) {
  const value = unwrap(node);
  if (!value) return null;
  if (ts.isStringLiteral(value) || ts.isNoSubstitutionTemplateLiteral(value)) {
    return { text: value.text, fullyResolved: true };
  }
  if (ts.isTemplateExpression(value)) {
    let text = value.head.text;
    let fullyResolved = true;
    for (const span of value.templateSpans) {
      const part = staticText(span.expression, checker, new Set(seenSymbols));
      if (part) {
        text += ` ${part.text} `;
        fullyResolved = fullyResolved && part.fullyResolved;
      } else {
        text += " __UNRESOLVED_EXPR__ ";
        fullyResolved = false;
      }
      text += span.literal.text;
    }
    return { text, fullyResolved };
  }
  if (ts.isIdentifier(value)) {
    const symbol = symbolAt(checker, value);
    if (!symbol || seenSymbols.has(symbol)) return null;
    seenSymbols.add(symbol);
    const declaration = symbol.valueDeclaration ?? symbol.declarations?.find((candidate) =>
      ts.isVariableDeclaration(candidate) || ts.isParameter(candidate));
    if (declaration && ts.isVariableDeclaration(declaration) && declaration.initializer) {
      return staticText(declaration.initializer, checker, seenSymbols);
    }
    return null;
  }
  if (ts.isArrayLiteralExpression(value)) {
    const parts = value.elements.map((element) => staticText(element, checker, new Set(seenSymbols)));
    return { text: parts.map((part) => part?.text ?? "__UNRESOLVED_EXPR__").join(","), fullyResolved: parts.every(Boolean) };
  }
  if (ts.isBinaryExpression(value) && value.operatorToken.kind === ts.SyntaxKind.PlusToken) {
    const left = staticText(value.left, checker, new Set(seenSymbols));
    const right = staticText(value.right, checker, new Set(seenSymbols));
    if (!left && !right) return null;
    return {
      text: `${left?.text ?? "__UNRESOLVED_EXPR__"}${right?.text ?? "__UNRESOLVED_EXPR__"}`,
      fullyResolved: Boolean(left?.fullyResolved && right?.fullyResolved),
    };
  }
  if (ts.isCallExpression(value) && callMemberName(value.expression) === "join") {
    const receiver = unwrap(value.expression.expression);
    const array = ts.isArrayLiteralExpression(receiver) ? receiver : null;
    if (array) {
      const separator = value.arguments[0] ? staticText(value.arguments[0], checker, new Set(seenSymbols))?.text ?? "" : ",";
      const parts = array.elements.map((element) => staticText(element, checker, new Set(seenSymbols)));
      return { text: parts.map((part) => part?.text ?? "__UNRESOLVED_EXPR__").join(separator), fullyResolved: parts.every(Boolean) };
    }
    if (ts.isIdentifier(receiver)) {
      const symbol = symbolAt(checker, receiver);
      if (symbol && !seenSymbols.has(symbol)) {
        const declaration = symbol.valueDeclaration ?? symbol.declarations?.find((candidate) => ts.isVariableDeclaration(candidate));
        const initializer = declaration?.initializer;
        if (initializer && ts.isArrayLiteralExpression(unwrap(initializer))) {
          seenSymbols.add(symbol);
          const arrayNode = unwrap(initializer);
          const separatorResult = value.arguments[0]
            ? staticText(value.arguments[0], checker, new Set(seenSymbols))
            : { text: ",", fullyResolved: true };
          const parts = arrayNode.elements.map((element) => staticText(element, checker, new Set(seenSymbols)));
          const fullyResolved = Boolean(separatorResult?.fullyResolved && parts.every((part) => part?.fullyResolved));
          if (!fullyResolved) return { text: "__UNRESOLVED_EXPR__", fullyResolved: false };
          return { text: parts.map((part) => part.text).join(separatorResult.text), fullyResolved: true };
        }
      }
    }
  }
  if (ts.isConditionalExpression(value)) {
    const whenTrue = staticText(value.whenTrue, checker, new Set(seenSymbols));
    const whenFalse = staticText(value.whenFalse, checker, new Set(seenSymbols));
    if (whenTrue && whenFalse && whenTrue.text === whenFalse.text) {
      return {
        text: whenTrue.text,
        fullyResolved: whenTrue.fullyResolved && whenFalse.fullyResolved,
      };
    }
  }
  return null;
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
  const sinks = new Map();
  for (const sourceFile of sourceFiles) {
    walk(sourceFile, (node) => {
      if (!ts.isFunctionLike(node) || !node.body) return;
      const parameterIndexes = new Map();
      node.parameters.forEach((parameter, index) => {
        for (const identifier of bindingIdentifiers(parameter.name)) {
          parameterIndexes.set(symbolAt(checker, identifier), index);
        }
      });
      const consumedIndexes = new Set();
      walk(node.body, (candidate) => {
        if (!ts.isCallExpression(candidate) ||
            !["prepare", "exec"].includes(callMemberName(candidate.expression))) return;
        for (const argument of candidate.arguments) {
          const value = unwrap(argument);
          if (ts.isIdentifier(value) && parameterIndexes.has(symbolAt(checker, value))) {
            consumedIndexes.add(parameterIndexes.get(symbolAt(checker, value)));
          }
        }
      });
      if (consumedIndexes.size > 0) {
        const symbol = functionSymbol(checker, node);
        if (symbol) sinks.set(symbol, consumedIndexes);
      }
    });
  }
  return sinks;
}

function sqlSourceBinding(node, sourceFile) {
  let current = node;
  while (current.parent && current.parent !== sourceFile) {
    const parent = current.parent;
    if (ts.isVariableDeclaration(parent)) return normalizedSnippet(sourceFile, parent.name);
    if (ts.isPropertyAssignment(parent)) return normalizedSnippet(sourceFile, parent.name);
    if (ts.isCallExpression(parent) && parent.arguments.includes(current)) {
      return `call:${callMemberName(parent.expression) ?? "function"}`;
    }
    if (ts.isStatement(parent)) break;
    current = parent;
  }
  return "inline";
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
    "order", "group", "limit", "returning", "from", "join", "union",
  ]);
  const depthBefore = [];
  let depth = 0;
  for (let i = 0; i < tokens.length; i++) {
    depthBefore[i] = depth;
    if (tokens[i].raw === "(") depth += 1;
    else if (tokens[i].raw === ")") depth = Math.max(0, depth - 1);
  }
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
    if (!operator && depthBefore[i] > 0) {
      // LOWER/TRIM/COALESCE and nested wrappers: walk out of the containing
      // expression and accept only the first top-level comparison before a new
      // major SQL clause. An unresolved RHS is retained with status=null so the
      // classification assertion fails closed.
      for (let j = i + 1; j < tokens.length; j++) {
        if (depthBefore[j] === 0 && majorClauses.has(tokens[j].lower)) break;
        if (depthBefore[j] === 0 && tokens[j].raw === ",") break;
        if (depthBefore[j] < depthBefore[i] && ["=", "==", "!=", "<>"].includes(tokens[j].raw)) {
          operator = `wrapped-${tokens[j].raw}`;
          status = sqlStatus(tokens[j + 1]);
          break;
        }
      }
    }
    // A selected/projected scan_quality column is not a predicate. Direct or
    // wrapped comparison operators are never discarded merely because their
    // status expression cannot be resolved statically.
    if (!operator) continue;
    predicates.push({ operator, status, index: tokens[i].index });
  }
  return predicates;
}

function analyseSql(sourceFiles, checker) {
  const staticSites = [];
  const querySites = [];
  const unclassified = [];
  const sinks = sqlSinkFunctions(sourceFiles, checker);
  const seenStatic = new Set();
  const seenQueries = new Set();
  const record = (collection, seen, sourceFile, node, resolved, kind) => {
    if (!resolved || !/\bscan_quality\b/i.test(resolved.text) || /===|!==/.test(resolved.text)) {
      return;
    }
    const predicates = sqlPredicates(resolved.text);
    if (predicates.length === 0) return;
    const key = `${rel(sourceFile.fileName)}:${node.getStart(sourceFile)}:${kind}`;
    if (seen.has(key)) return;
    seen.add(key);
    const site = {
      file: rel(sourceFile.fileName),
      line: sourceLine(sourceFile, node),
      kind,
      binding: sqlSourceBinding(node, sourceFile),
      fully_resolved: resolved.fullyResolved,
      predicates,
      source_snippet: normalizedSnippet(sourceFile, node),
      snippet: resolved.text.replace(/\s+/g, " ").trim(),
    };
    collection.push(site);
    for (const predicate of predicates) {
      if (!ALLOWED_QUALITY_STATUSES.has(predicate.status)) {
        unclassified.push({
          ...site,
          predicate,
          reason: predicate.status == null
            ? "sql-predicate-without-static-status"
            : `unknown-sql-status:${predicate.status}`,
        });
      }
    }
  };
  for (const sourceFile of sourceFiles.filter((file) => isRuntimeFile(file.fileName))) {
    walk(sourceFile, (node) => {
      if (ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) ||
          ts.isTemplateExpression(node)) {
        record(staticSites, seenStatic, sourceFile, node, staticText(node, checker), "static-text");
      }
      if (!ts.isCallExpression(node)) return;
      const directSink = ["prepare", "exec"].includes(callMemberName(node.expression));
      const helperIndexes = sinks.get(symbolAt(checker, node.expression));
      for (let index = 0; index < node.arguments.length; index++) {
        if (!directSink && !helperIndexes?.has(index)) continue;
        const argument = node.arguments[index];
        record(querySites, seenQueries, sourceFile, argument,
          staticText(argument, checker), directSink ? "query-sink" : "helper-query-sink");
      }
    });
  }
  const signature = (site) => [
    site.file, site.line, site.kind, site.binding, site.fully_resolved,
    site.predicates.map((predicate) => `${predicate.operator}:${predicate.status}`).join("+"),
    site.source_snippet, site.snippet,
  ].join(":" );
  return {
    staticSites,
    querySites,
    unclassified,
    predicateOccurrences: staticSites.reduce((sum, site) => sum + site.predicates.length, 0),
    fingerprint: fingerprint(staticSites.map(signature)),
    querySinkFingerprint: fingerprint(querySites.map(signature)),
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
const direct = analyseDirectReads(sourceFiles, checker);
const directRuntime = direct.sites.filter((site) => isRuntimeFile(path.join(root, site.file)));
const directGovernance = direct.sites.filter((site) => !isRuntimeFile(path.join(root, site.file)));
const sqlProjectionCandidates = [];
for (const sf of sourceFiles.filter((file) => isRuntimeFile(file.fileName))) walk(sf, (node) => {
  if (!(ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node) || ts.isTemplateExpression(node) || ts.isIdentifier(node) || ts.isCallExpression(node))) return;
  const resolved = staticText(node, checker);
  if (!resolved || !resolved.fullyResolved || !/\bscan_quality\b/i.test(resolved.text)) return;
  const lower = resolved.text.toLowerCase();
  const sqlShape = /\bselect\b/.test(lower) ||
    /(?:^|,)\s*(?:[a-z_][\w]*\.)scan_quality\s*(?:,|$)/.test(lower) ||
    /\b(cols|columns|projection|selectlist|fields?)\b/.test(lower);
  if (!sqlShape) return;
  sqlProjectionCandidates.push({ file: rel(sf.fileName), line: sourceLine(sf, node), kind: "static-read", snippet: resolved.text });
});
const sqlProjectionSites = sqlProjectionCandidates.filter((site) => {
  const text = site.snippet.toLowerCase();
  return ((/\bselect\b[\s\S]*\bscan_quality\b/.test(text) &&
    (!/\bwhere\b/.test(text) || text.indexOf("scan_quality") < text.indexOf("where"))) ||
    /(?:^|,)\s*(?:[a-z_][\w]*\.)?scan_quality\s*(?:,|$)/.test(text)) &&
    !/\bwhere\b[\s\S]*\bscan_quality\b/.test(text) &&
    !/\b(insert|update|set|delete)\b/i.test(text);
}).filter((site, index, all) => all.findIndex((other) =>
  other.file === site.file && other.line === site.line && other.snippet === site.snippet) === index);
const sqlReadFingerprint = fingerprint(sqlProjectionSites.map((site) =>
  `${site.file}:${site.line}:${site.kind}:${site.snippet}`));
const runtimeSemanticFiles = new Set(semantic.runtime.map((site) => site.file));
const governanceFiles = new Set(semantic.governance.map((site) => site.file));
// Every statically-resolved SQL-bearing string is a site. Query-sink analysis
// remains separately retained in analyseSql so interpolation/data-flow is
// exercised, but inventory authority is not gated on a fragment identifier or
// on whether a helper call was recognised.
const sqlSites = sql.staticSites;
const sqlFiles = new Set(sqlSites.map((site) => site.file));
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
    unique_query_sites: sqlSites.length,
    source_file_count: sqlFiles.size,
    fingerprint: sql.fingerprint,
    resolved_query_sink_count: sql.querySites.length,
    resolved_query_sink_fingerprint: sql.querySinkFingerprint,
  },
  governance: {
    comparison_occurrences: semantic.governance.length,
    source_file_count: governanceFiles.size,
    fingerprint: semantic.governanceFingerprint,
  },
  runtime_source_file_count: runtimeFiles.size,
  direct: {
    runtime: { occurrence_count: directRuntime.length, source_file_count: new Set(directRuntime.map((s) => s.file)).size, fingerprint: fingerprint(directRuntime.map((s) => `${s.file}:${s.line}:${s.kind}:${s.slot}:${s.snippet}`)) },
    governance: { occurrence_count: directGovernance.length, source_file_count: new Set(directGovernance.map((s) => s.file)).size, fingerprint: fingerprint(directGovernance.map((s) => `${s.file}:${s.line}:${s.kind}:${s.slot}:${s.snippet}`)) },
  },
  sql_reads: { projection_occurrences: sqlProjectionSites.length, fingerprint: sqlReadFingerprint },
};
const unresolvedGovernanceKeys = semantic.unresolvedGovernance.map((site) =>
  `${site.file}:${site.line}:${site.snippet}`,
).sort();

function dumpInventory() {
  console.log(JSON.stringify({
    counts: current,
    runtime_comparisons: semantic.runtime,
    direct_reads: direct.sites,
    sql_sites: sqlSites,
    sql_static_sites: sql.staticSites,
    sql_query_sink_sites: sql.querySites,
    sql_projection_sites: sqlProjectionSites,
    governance_comparisons: semantic.governance,
    unresolved_governance: semantic.unresolvedGovernance,
    unclassified: [...semantic.unclassified, ...sql.unclassified],
    parse_failures: parseFailures,
    known_partial_only_gate: knownAsmPartial,
    unresolved_governance: semantic.unresolvedGovernance,
    unresolved_governance: semantic.unresolvedGovernance,
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
    unresolved_governance: semantic.unresolvedGovernance,
    runtime_site_keys: semantic.runtime.map((site) =>
      `${site.file}:${site.line}:${site.snippet}`),
    direct_read_keys: direct.sites.map((site) => `${site.file}:${site.line}:${site.kind}:${site.slot}`),
    sql_site_keys: sqlSites.map((site) => `${site.file}:${site.line}:${site.predicates.length}`),
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
console.log(`  resolved SQL query-sink sites: ${current.sql.resolved_query_sink_count}`);
console.log(`  governance source files: ${current.governance.source_file_count}`);
console.log(`  runtime direct canonical reads: ${current.direct.runtime.occurrence_count}`);
console.log(`  governance direct canonical reads: ${current.direct.governance.occurrence_count}`);
console.log(`  SQL SELECT/projection direct reads: ${current.sql_reads.projection_occurrences}`);

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
  cleanParse ? governanceMatches &&
    JSON.stringify(unresolvedGovernanceKeys) === JSON.stringify([...EXPECTED_UNRESOLVED_GOVERNANCE].sort()) : true,
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

// D1 SUCCESSION of "defect: asm-cases partial-only verification gate remains
// explicit and unfixed" (old outcome: exactly 1 such gate MUST exist).
//
// That assertion deliberately PINNED the I11A-C3 defect open, waiting for exactly
// this work order. FD-006 (seq 50) declares the defect defective and requires it
// reversed, so the old expectation is D1-invalidated by founder decision. Its
// named active successor is `scripts/validate-d1-i11a-c3-successor.js`, which
// proves a `degraded` scan can never verify or resolve. This row now asserts the
// inverse of the pin: the partial-only verification gate must NO LONGER exist.
ok(
  "successor: asm-cases partial-only verification gate is REVERSED (successor: scripts/validate-d1-i11a-c3-successor.js)",
  cleanParse ? knownAsmPartial.length === 0 : true,
  `found ${knownAsmPartial.length}; FD-006/seq50 requires the degraded-verifies defect fixed, not preserved`,
);

ok("primary: runtime canonical direct-read inventory is exact", cleanParse && JSON.stringify(current.direct.runtime) === JSON.stringify(EXPECTED.direct.runtime), `got ${JSON.stringify(current.direct.runtime)}`);
ok("primary: governance canonical direct-read inventory is exact", cleanParse && JSON.stringify(current.direct.governance) === JSON.stringify(EXPECTED.direct.governance), `got ${JSON.stringify(current.direct.governance)}`);
ok("SQL: direct read/projection inventory is exact",
  cleanParse && JSON.stringify(current.sql_reads) === JSON.stringify(EXPECTED.sql_reads),
  JSON.stringify(current.sql_reads));

const assertionTotal = passed + failed;
if (assertionTotal !== EXPECTED_ASSERTIONS) {
  console.log(`FAIL pinned assertion count — got ${assertionTotal}, want ${EXPECTED_ASSERTIONS}`);
  process.exit(1);
}
console.log(`\nScan-quality vocabulary inventory: ${passed} passed, ${failed} failed (${assertionTotal} total)`);
if (failed > 0) process.exit(1);
console.log("Scan-quality vocabulary inventory passed");
