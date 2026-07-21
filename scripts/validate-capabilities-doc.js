#!/usr/bin/env node
// ── docs/CAPABILITIES.md drift guard ──────────────────────────────────────────
// CAPABILITIES.md is the canonical CURRENT-STATE capability register. This guard
// catches the drift that would quietly make it lie: a lost/added domain, a
// retired claim creeping back as live, an un-labelled capability, a missing
// hard-boundary section, or release-timeline content leaking in from the
// CHANGELOG. It does NOT assert "the file changed" (that would block every
// unrelated PR) — governance for that is a PR checklist, per the founder ruling.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const docPath = path.join(root, "docs", "CAPABILITIES.md");

let pass = 0, fail = 0;
const ok = (label, cond, detail = "") => {
  if (cond) { pass++; }
  else { fail++; console.error(`  ✘ ${label}${detail ? ` — ${detail}` : ""}`); }
};

ok("docs/CAPABILITIES.md exists", fs.existsSync(docPath));
const src = fs.existsSync(docPath) ? fs.readFileSync(docPath, "utf8") : "";

// 1) The eight canonical domains — exactly, by name, no ninth.
const CANONICAL_DOMAINS = [
  "Email Protection", "Brand Protection", "Attack Surface", "Certificates & Trust",
  "Cyber Essentials Readiness", "Website Security", "Identity Exposure",
  "Shadow IT & Unmanaged Technology",
];
for (const d of CANONICAL_DOMAINS) {
  ok(`domain present: ${d}`, new RegExp(`^###\\s*\\d+\\.\\s*${d.replace(/[.&]/g, "\\$&")}\\s*$`, "m").test(src));
}
const domainHeadings = [...src.matchAll(/^###\s*\d+\.\s+(.+?)\s*$/gm)].map((m) => m[1]);
ok("exactly eight domain headings (no ninth)", domainHeadings.length === 8, `found ${domainHeadings.length}: ${domainHeadings.join(" | ")}`);

// 2) Retired claims stay retired — Vendor Risk / Supply Chain must not be a live
//    domain/capability. If the strings appear at all, they must be in a
//    "Retired from customer-facing claims" context.
for (const claim of ["Vendor Risk", "Supply Chain Score"]) {
  if (src.includes(claim)) {
    // The retired label must appear in the doc, and the claim must not be a domain heading.
    ok(`retired claim "${claim}" is not a domain heading`,
      !new RegExp(`^###\\s*\\d+\\.\\s*${claim}`, "m").test(src));
  }
}
ok("retired-claim label is present when vendor/supply is mentioned",
  !(src.includes("Vendor Risk") || src.includes("Supply Chain"))
  || src.includes("Retired from customer-facing claims"));

// 3) Every capability carries a status label from the allowed set only.
const STATUS_LABELS = [
  "Live — production-verified",
  "Live — founder acceptance pending",
  "Engineering complete — deployment pending",
  "Partial / bounded coverage",
  "Planned",
  "Retired from customer-facing claims",
];
for (const label of STATUS_LABELS) ok(`status label defined: "${label}"`, src.includes(label));
// No em-dash-free "Live and production-verified" drift, and no vague bare "Supported"/"Available" as a status.
ok("no bare vague status word used as a label", !/\*\*(Supported|Available)\*\*/.test(src));

// 4) Hard-boundary section present with the core NOT-claims.
ok("hard-boundary section present", /Hard product boundaries/i.test(src));
for (const b of ["EDR", "SIEM", "NDR", "dark-web", "DAST", "penetration test"]) {
  ok(`hard boundary states: not ${b}`, new RegExp(b.replace(/[-]/g, "\\-"), "i").test(src));
}

// 5) Evidence-language taxonomy present (never conflated).
for (const term of ["Observed", "Derived", "Correlated", "Customer-declared", "Inferred"]) {
  ok(`evidence term defined: ${term}`, src.includes(term));
}

// 6) No release-timeline content — CHANGELOG must not be duplicated here.
ok("no release version tags (CHANGELOG content) in the register",
  !/v20\d{2}\.\d{2}\.\d{2}-\d/.test(src), "a vYYYY.MM.DD-n tag leaked in");

// 7) References the companion docs it must not duplicate.
for (const ref of ["CHANGELOG.md", "PUBLIC-CLAIMS-TRUTH-AUDIT.md"]) {
  ok(`references companion doc: ${ref}`, src.includes(ref));
}

console.log(`\nCapabilities-doc drift guard: ${pass}/${pass + fail} passed`);
if (fail > 0) { console.error("capabilities-doc validation FAILED"); process.exit(1); }
console.log("capabilities-doc validation passed");
