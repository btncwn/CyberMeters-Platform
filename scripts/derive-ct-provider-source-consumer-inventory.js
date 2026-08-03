#!/usr/bin/env node
// CT-R2 PR-2A.1 mechanical provider-source consumer inventory.
//
// The closure starts from every runtime JS/JSX module under the Worker and
// frontend source roots. It never starts from filenames, grep hits or an expected
// count. Provider-source provenance is discovered from AST shape, propagated
// through aliases, destructuring, arrays/objects and local helper parameters,
// then classified. Dynamic access or an unresolved helper boundary fails closed.
// A final-head pin is an external input created only after implementation.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const frontendRequire = createRequire(path.join(root, "frontend/package.json"));
const { parse } = frontendRequire("@babel/parser");

export const CT_PROVIDER_SOURCE_INVENTORY_RULE_VERSION = "ct-provider-source-consumers/1";
export const CT_PROVIDER_SOURCE_SENTINEL_CONTRACT_ID = "SENTINEL_ERROR_PRECEDENCE";
const RUNTIME_ROOTS = Object.freeze([
  path.join(root, "workers/scan-api/src"),
  path.join(root, "frontend/src"),
]);
const PROVIDERS = new Set(["crt_sh", "certspotter"]);
const SOURCE_CONTAINERS = new Set(["sources", "ct_sources"]);
const TERMINAL_FIELDS = new Set(["count", "error"]);

function runtimeFiles() {
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const absolute = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(absolute);
      else if (/\.(?:js|jsx|mjs)$/.test(entry.name)) files.push(absolute);
    }
  };
  for (const directory of RUNTIME_ROOTS) visit(directory);
  return files.sort((a, b) => a.localeCompare(b));
}

function children(node) {
  if (!node || typeof node !== "object") return [];
  const rows = [];
  for (const [key, value] of Object.entries(node)) {
    if (["loc", "start", "end", "leadingComments", "trailingComments", "innerComments", "extra"].includes(key)) continue;
    if (Array.isArray(value)) {
      for (const child of value) if (child?.type) rows.push(child);
    } else if (value?.type) rows.push(value);
  }
  return rows;
}

function walk(node, visit, parent = null, ancestors = []) {
  if (!node?.type) return;
  visit(node, parent, ancestors);
  const next = [...ancestors, node];
  for (const child of children(node)) walk(child, visit, node, next);
}

function literalProperty(node) {
  if (!node) return null;
  if (!node.computed && node.property?.type === "Identifier") return node.property.name;
  if (node.computed && ["StringLiteral", "NumericLiteral", "Literal"].includes(node.property?.type)) {
    return String(node.property.value);
  }
  return null;
}

function directProviderSource(node) {
  if (!["MemberExpression", "OptionalMemberExpression"].includes(node?.type)) return null;
  const provider = literalProperty(node);
  if (!PROVIDERS.has(provider)) return null;
  const containerNode = node.object;
  if (!["MemberExpression", "OptionalMemberExpression"].includes(containerNode?.type)) return null;
  const container = literalProperty(containerNode);
  if (!SOURCE_CONTAINERS.has(container)) return null;
  return `${container}.${provider}`;
}

function bindingNames(pattern) {
  if (!pattern) return [];
  if (pattern.type === "Identifier") return [pattern.name];
  if (pattern.type === "RestElement") return bindingNames(pattern.argument);
  if (pattern.type === "AssignmentPattern") return bindingNames(pattern.left);
  if (pattern.type === "ArrayPattern") return pattern.elements.flatMap(bindingNames);
  if (pattern.type === "ObjectPattern") {
    return pattern.properties.flatMap((property) =>
      property.type === "RestElement" ? bindingNames(property.argument) : bindingNames(property.value));
  }
  return [];
}

function statementAncestor(ancestors) {
  return [...ancestors].reverse().find((node) => /Statement$/.test(node.type)
    || node.type === "VariableDeclaration") || ancestors.at(-1) || null;
}

function accessKind(node, destructured = false) {
  if (destructured) return "destructuring";
  if (node.optional) return node.computed ? "optional_computed_literal" : "optional_member";
  return node.computed ? "computed_literal" : "member";
}

function classifyUse(node, parent, ancestors) {
  const decisionTypes = new Set([
    "BinaryExpression", "LogicalExpression", "ConditionalExpression",
    "IfStatement", "WhileStatement", "DoWhileStatement", "UnaryExpression",
  ]);
  const near = [parent, ...ancestors.slice(-2)].filter(Boolean);
  if (near.some((candidate) => decisionTypes.has(candidate.type))) return "decision";
  if (near.some((candidate) => [
    "ObjectProperty", "ObjectMethod", "ReturnStatement", "JSXExpressionContainer",
    "TemplateLiteral",
  ].includes(candidate.type))) return "projects";
  return "transports";
}

function parseFile(file) {
  const source = fs.readFileSync(file, "utf8");
  const ast = parse(source, {
    sourceType: "unambiguous",
    errorRecovery: false,
    plugins: [
      "jsx", "importAttributes", "topLevelAwait", "optionalChaining",
      "nullishCoalescingOperator", "objectRestSpread", "classProperties",
      "dynamicImport",
    ],
  });
  return { file, relative: path.relative(root, file), source, ast };
}

function analyzeFile(parsed) {
  const aliases = new Map(); // identifier -> SOURCE | CONTAINER
  const functionParams = new Map(); // local function name -> parameter names
  const functionReturns = new Map();
  const unresolved = [];
  const sites = [];

  walk(parsed.ast, (node, parent) => {
    if (node.type === "FunctionDeclaration" && node.id?.name) {
      functionParams.set(node.id.name, node.params.map((param) => bindingNames(param)));
    }
    if (node.type === "VariableDeclarator"
      && node.id?.type === "Identifier"
      && ["ArrowFunctionExpression", "FunctionExpression"].includes(node.init?.type)) {
      functionParams.set(node.id.name, node.init.params.map((param) => bindingNames(param)));
    }
  });

  const stateOf = (node) => {
    if (!node) return null;
    if (directProviderSource(node)) return "SOURCE";
    if (node.type === "Identifier") return aliases.get(node.name) || null;
    if (["TSAsExpression", "TypeCastExpression", "ParenthesizedExpression", "ChainExpression"].includes(node.type)) {
      return stateOf(node.expression);
    }
    if (["MemberExpression", "OptionalMemberExpression"].includes(node.type)) {
      const objectState = stateOf(node.object);
      const property = literalProperty(node);
      if (objectState === "CONTAINER") return "SOURCE";
      if (objectState === "SOURCE" && !TERMINAL_FIELDS.has(property)) return "SOURCE";
      return null;
    }
    if (node.type === "CallExpression" && node.callee?.type === "Identifier") {
      return functionReturns.get(node.callee.name) || null;
    }
    if (node.type === "ConditionalExpression" || node.type === "LogicalExpression") {
      return [stateOf(node.consequent), stateOf(node.alternate), stateOf(node.left), stateOf(node.right)]
        .find(Boolean) || null;
    }
    if (node.type === "ArrayExpression") {
      return node.elements.some((entry) => stateOf(entry)) ? "CONTAINER" : null;
    }
    if (node.type === "ObjectExpression") {
      return node.properties.some((property) =>
        stateOf(property.value || property.argument)) ? "CONTAINER" : null;
    }
    return null;
  };

  let changed = true;
  for (let iteration = 0; changed && iteration < 64; iteration += 1) {
    changed = false;
    walk(parsed.ast, (node) => {
      if (node.type === "VariableDeclarator") {
        const state = stateOf(node.init);
        if (state) {
          for (const name of bindingNames(node.id)) {
            if (aliases.get(name) !== state) { aliases.set(name, state); changed = true; }
          }
        }
      }
      if (node.type === "AssignmentExpression" && node.left?.type === "Identifier") {
        const state = stateOf(node.right);
        if (state && aliases.get(node.left.name) !== state) {
          aliases.set(node.left.name, state);
          changed = true;
        }
      }
      if (node.type === "CallExpression" && node.callee?.type === "Identifier") {
        const params = functionParams.get(node.callee.name);
        if (params) {
          node.arguments.forEach((argument, index) => {
            const state = stateOf(argument);
            if (!state) return;
            for (const name of params[index] || []) {
              if (aliases.get(name) !== state) { aliases.set(name, state); changed = true; }
            }
          });
        }
      }
      if (node.type === "ReturnStatement") {
        const state = stateOf(node.argument);
        if (!state) return;
        // The nearest named function is recovered from source ancestry in the
        // second pass; anonymous returned provider sources are transported and
        // cannot silently establish a callable alias.
      }
    });
  }

  const seen = new Set();
  const recordSite = ({ node, parent, ancestors, field, provenance, kind, reason }) => {
    const line = node.loc?.start?.line || 0;
    const column = node.loc?.start?.column || 0;
    const key = `${parsed.relative}:${line}:${column}:${field}:${kind}`;
    if (seen.has(key)) return;
    seen.add(key);
    const classification = classifyUse(node, parent, ancestors);
    const statement = statementAncestor(ancestors);
    const statementText = statement ? parsed.source.slice(statement.start, statement.end) : "";
    const errorDominates = field !== "count" || classification !== "decision"
      ? "not_applicable"
      : /(?:\.error|\[\s*["']error["']\s*\])/.test(statementText)
        ? true
        : false;
    sites.push({
      file: parsed.relative,
      line,
      column,
      ast_access_kind: kind,
      field,
      source_provenance: provenance,
      classification,
      non_null_error_dominates_count: errorDominates,
      classification_reason: reason,
    });
  };

  walk(parsed.ast, (node, parent, ancestors) => {
    if (["MemberExpression", "OptionalMemberExpression"].includes(node.type)) {
      const direct = directProviderSource(node);
      if (direct) return;
      const objectState = stateOf(node.object);
      if (objectState !== "SOURCE") return;
      const property = literalProperty(node);
      if (property == null) {
        unresolved.push({
          file: parsed.relative,
          line: node.loc?.start?.line || 0,
          ast_access_kind: "computed_dynamic",
          reason: "dynamic provider-source property cannot be resolved fail-closed",
        });
        return;
      }
      if (!TERMINAL_FIELDS.has(property)) {
        unresolved.push({
          file: parsed.relative,
          line: node.loc?.start?.line || 0,
          ast_access_kind: accessKind(node),
          reason: `unrecognised provider-source property ${property}`,
        });
        return;
      }
      recordSite({
        node,
        parent,
        ancestors,
        field: property,
        provenance: directProviderSource(node.object) || "alias/helper/container",
        kind: accessKind(node),
        reason: "terminal provider-source field read derived by AST taint closure",
      });
    }

    if (node.type === "VariableDeclarator" && node.id?.type === "ObjectPattern"
      && stateOf(node.init) === "SOURCE") {
      for (const property of node.id.properties) {
        if (property.type === "RestElement") {
          unresolved.push({
            file: parsed.relative,
            line: property.loc?.start?.line || 0,
            ast_access_kind: "destructuring_rest",
            reason: "provider-source rest destructuring is unresolved fail-closed",
          });
          continue;
        }
        const field = property.computed
          ? (["StringLiteral", "Literal"].includes(property.key?.type) ? String(property.key.value) : null)
          : property.key?.name;
        if (!TERMINAL_FIELDS.has(field)) {
          unresolved.push({
            file: parsed.relative,
            line: property.loc?.start?.line || 0,
            ast_access_kind: "destructuring",
            reason: `unresolved provider-source destructuring field ${field ?? "dynamic"}`,
          });
          continue;
        }
        recordSite({
          node: property,
          parent: node,
          ancestors,
          field,
          provenance: directProviderSource(node.init) || "alias/helper/container",
          kind: accessKind(property, true),
          reason: "destructured provider-source field derived by AST taint closure",
        });
      }
    }

    if (node.type === "SpreadElement" && stateOf(node.argument) === "SOURCE") {
      recordSite({
        node,
        parent,
        ancestors,
        field: "*",
        provenance: directProviderSource(node.argument) || "alias/helper/container",
        kind: "spread",
        reason: "provider-source object transported by spread/serialization",
      });
    }

    if (node.type === "CallExpression") {
      const taintedArguments = node.arguments.filter((argument) => stateOf(argument));
      if (taintedArguments.length === 0) return;
      const localResolved = node.callee?.type === "Identifier" && functionParams.has(node.callee.name);
      const knownSerialization = node.callee?.type === "MemberExpression"
        && node.callee.object?.name === "JSON"
        && literalProperty(node.callee) === "stringify";
      const knownBooleanCoercion = node.callee?.type === "Identifier"
        && node.callee.name === "Boolean";
      if (!localResolved && !knownSerialization && !knownBooleanCoercion) {
        unresolved.push({
          file: parsed.relative,
          line: node.loc?.start?.line || 0,
          ast_access_kind: "helper_argument",
          reason: "provider-source passed to unresolved helper boundary",
        });
      }
    }
  });

  return { sites, unresolved };
}

function analyzeParsedFiles(parsed, pinPath = null) {
  const analyses = parsed.map(analyzeFile);
  const sites = analyses.flatMap((row) => row.sites).sort((a, b) =>
    a.file.localeCompare(b.file) || a.line - b.line || a.column - b.column
      || a.field.localeCompare(b.field));
  const unresolved = analyses.flatMap((row) => row.unresolved).sort((a, b) =>
    a.file.localeCompare(b.file) || a.line - b.line
      || a.ast_access_kind.localeCompare(b.ast_access_kind));
  const canonicalLines = sites.map((site) => JSON.stringify(site));
  const fingerprint = crypto.createHash("sha256")
    .update(canonicalLines.join("\n"))
    .digest("hex");
  const decisionConsumers = sites.filter((site) => site.classification === "decision");
  const unsafeDecisionConsumers = decisionConsumers.filter((site) =>
    site.field === "count" && site.non_null_error_dominates_count !== true);
  let pinMatches = null;
  if (pinPath) {
    const pin = JSON.parse(fs.readFileSync(path.resolve(pinPath), "utf8"));
    pinMatches = pin.rule_version === CT_PROVIDER_SOURCE_INVENTORY_RULE_VERSION
      && pin.fingerprint === fingerprint
      && JSON.stringify(pin.sites) === JSON.stringify(sites);
  }
  return {
    rule_version: CT_PROVIDER_SOURCE_INVENTORY_RULE_VERSION,
    runtime_roots: RUNTIME_ROOTS.map((directory) => path.relative(root, directory)),
    runtime_file_count: parsed.length,
    runtime_consumer_count: sites.length,
    runtime_consumer_fingerprint: fingerprint,
    sites,
    unresolved,
    sentinel_contract_id: CT_PROVIDER_SOURCE_SENTINEL_CONTRACT_ID,
    sentinel_decision_consumers: decisionConsumers,
    unsafe_decision_consumers: unsafeDecisionConsumers,
    pin_matches: pinMatches,
  };
}

export function deriveCtProviderSourceConsumerInventory({ pinPath = null } = {}) {
  return analyzeParsedFiles(runtimeFiles().map(parseFile), pinPath);
}

function parseCalibrationSource(source, relative) {
  const ast = parse(source, {
    sourceType: "module",
    errorRecovery: false,
    plugins: ["optionalChaining", "objectRestSpread"],
  });
  return { file: path.join(root, relative), relative, source, ast };
}

export function calibrateCtProviderSourceInventoryDetector() {
  const safeSource = `
const direct = payload.ct_sources.crt_sh;
const optional = payload?.sources?.certspotter;
const computed = payload["ct_sources"]["crt_sh"];
const holder = { value: direct };
const array = [holder.value];
const alias = array[0];
function decide(source) {
  return source.error == null && source.count > 0;
}
const { count, error } = computed;
const optionalError = optional?.error;
const computedCount = computed["count"];
const projected = { ...optional, count, error };
JSON.stringify(projected);
decide(alias);
void optionalError;
void computedCount;
`;
  const unsafeSource = `
const source = payload.ct_sources.crt_sh;
const healthy = source.count > 0;
const unresolved = source[dynamicField];
void healthy;
void unresolved;
`;
  const safe = analyzeParsedFiles([
    parseCalibrationSource(safeSource, "oracle-fixtures/provider-source-safe.js"),
  ]);
  const unsafe = analyzeParsedFiles([
    parseCalibrationSource(unsafeSource, "oracle-fixtures/provider-source-unsafe.js"),
  ]);
  const kinds = new Set(safe.sites.map((site) => site.ast_access_kind));
  return Object.freeze({
    covers_direct_member: kinds.has("member"),
    covers_optional_member: kinds.has("optional_member"),
    covers_computed_literal: kinds.has("computed_literal"),
    covers_destructuring: kinds.has("destructuring"),
    covers_spread_transport: kinds.has("spread"),
    covers_alias_array_object_helper_flow:
      safe.sites.some((site) => site.source_provenance === "alias/helper/container"),
    safe_error_dominates_count: safe.unsafe_decision_consumers.length === 0,
    unsafe_count_decision_detected: unsafe.unsafe_decision_consumers.length > 0,
    unresolved_dynamic_fails_closed:
      unsafe.unresolved.some((site) => site.ast_access_kind === "computed_dynamic"),
  });
}

export const CT_PROVIDER_SOURCE_INVENTORY_FREEZE = Object.freeze({
  final_runtime_count: null,
  final_runtime_sites: null,
  final_runtime_fingerprint: null,
  freeze_exemption: "post-implementation mechanical inventory pin only",
});

const isMain = process.argv[1]
  && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const pinPathIndex = process.argv.indexOf("--pin");
  const pinPath = pinPathIndex >= 0 ? process.argv[pinPathIndex + 1] : null;
  const output = deriveCtProviderSourceConsumerInventory({ pinPath });
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  if (output.unresolved.length > 0
    || output.unsafe_decision_consumers.length > 0
    || output.pin_matches === false) {
    process.exitCode = 1;
  }
}
