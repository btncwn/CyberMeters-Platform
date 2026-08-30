import { register } from "node:module";
import { pathToFileURL } from "node:url";

const MUTANT_ID_PATTERN = /^[A-Za-z0-9._-]+$/;

let registeredFingerprint = null;
let registeredIds = null;

function normalizeMutations(mutations) {
  if (!Array.isArray(mutations) || mutations.length === 0) {
    throw new TypeError("mutations must be a non-empty array");
  }

  const seen = new Set();
  return mutations.map((mutation, index) => {
    if (!mutation || typeof mutation !== "object" || Array.isArray(mutation)) {
      throw new TypeError(`mutation at index ${index} must be an object`);
    }
    const { id, from, to } = mutation;
    if (typeof id !== "string" || !MUTANT_ID_PATTERN.test(id)) {
      throw new TypeError(`mutation at index ${index} has an invalid id`);
    }
    if (seen.has(id)) throw new TypeError(`duplicate mutation id: ${id}`);
    if (typeof from !== "string" || from.length === 0) {
      throw new TypeError(`mutation ${id} must have a non-empty from string`);
    }
    if (typeof to !== "string") throw new TypeError(`mutation ${id} must have a to string`);
    seen.add(id);
    return { id, from, to };
  });
}

export function registerMutants(mutations) {
  const normalized = normalizeMutations(mutations);
  const fingerprint = JSON.stringify(normalized);

  if (registeredFingerprint !== null) {
    if (registeredFingerprint !== fingerprint) {
      throw new Error("mutant loader is already registered with a different mutation table");
    }
    return;
  }

  register("./mutant-loader-hooks.mjs", import.meta.url, {
    data: { mutations: normalized },
  });
  registeredFingerprint = fingerprint;
  registeredIds = new Set(normalized.map(({ id }) => id));
}

export function importMutant(realAbsolutePath, id) {
  if (registeredIds === null) throw new Error("registerMutants() must be called before importMutant()");
  if (!registeredIds.has(id)) throw new Error(`unknown mutation id: ${id}`);
  if (typeof realAbsolutePath !== "string" || !realAbsolutePath.startsWith("/")) {
    throw new TypeError("realAbsolutePath must be an absolute path");
  }

  const url = pathToFileURL(realAbsolutePath);
  url.searchParams.set("cm_mutant", id);
  return import(url.href);
}
