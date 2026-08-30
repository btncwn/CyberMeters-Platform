import fs from "node:fs/promises";
import { fileURLToPath } from "node:url";

let mutationsById = null;

export function initialize(data) {
  const mutations = data?.mutations;
  if (!Array.isArray(mutations) || mutations.length === 0) {
    throw new TypeError("mutant loader requires a non-empty mutation table");
  }

  mutationsById = new Map();
  for (const mutation of mutations) {
    if (!mutation || typeof mutation.id !== "string"
        || typeof mutation.from !== "string" || mutation.from.length === 0
        || typeof mutation.to !== "string") {
      throw new TypeError("mutant loader received an invalid mutation entry");
    }
    if (mutationsById.has(mutation.id)) {
      throw new TypeError(`mutant loader received duplicate id: ${mutation.id}`);
    }
    mutationsById.set(mutation.id, mutation);
  }
}

function countExact(source, anchor) {
  let count = 0;
  let offset = 0;
  while (true) {
    const index = source.indexOf(anchor, offset);
    if (index === -1) return count;
    count += 1;
    offset = index + anchor.length;
  }
}

export async function load(url, context, nextLoad) {
  const parsed = new URL(url);
  const id = parsed.searchParams.get("cm_mutant");
  if (id === null) return nextLoad(url, context);

  if (parsed.protocol !== "file:") {
    throw new Error(`mutant loader only accepts file URLs: ${parsed.protocol}`);
  }
  const mutation = mutationsById?.get(id);
  if (!mutation) throw new Error(`unknown mutation id in loader: ${id}`);

  parsed.searchParams.delete("cm_mutant");
  parsed.hash = "";
  const source = await fs.readFile(fileURLToPath(parsed), "utf8");
  const anchorCount = countExact(source, mutation.from);
  if (anchorCount !== 1) {
    throw new Error(`MUTANT_ANCHOR_COUNT id=${id} count=${anchorCount} expected=1`);
  }

  return {
    format: "module",
    source: source.replace(mutation.from, mutation.to),
    shortCircuit: true,
  };
}
