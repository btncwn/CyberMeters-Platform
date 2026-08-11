#!/usr/bin/env node

import {
  installGovernedRoot,
  loadInstallScriptPolicy,
} from "./security/install-script-governance.js";

const rootIndex = process.argv.indexOf("--root");
const selectedRoot = rootIndex >= 0 ? process.argv[rootIndex + 1] : null;
if (!selectedRoot || rootIndex + 2 !== process.argv.length) {
  console.error("usage: node scripts/install-governed-dependencies.js --root <governed-package-root>");
  process.exit(2);
}

try {
  installGovernedRoot(loadInstallScriptPolicy(), selectedRoot);
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
