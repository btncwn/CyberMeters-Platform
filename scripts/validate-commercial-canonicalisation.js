#!/usr/bin/env node
//
// Commercial-document canonicalisation — one direction, honestly stated. CI-blocking.
//
// Written after an audit found FIVE June-2026 documents still carrying live-authority
// markers ("Approved — Active Commercial Direction", "Ready for implementation",
// "Current strategy") months after the founder decision of 2026-07-09 superseded them.
// The 2026-07-15 governance pass (PR #87) marked six *roadmap* documents Historical /
// Superseded and touched NO pricing document, so the commercial drift survived it.
//
// What that drift actually was: FOUR mutually incompatible price ladders in one repo —
// the adopted policy (£9/£29/£69 + MSP £29+£1/domain), the live legacy set
// (£29/£149/£399), a never-live £49 Starter in the Stripe architecture doc, and a
// never-adopted £29/£79/£199/£399 ladder in the Phase-0 audit. Any of them could be
// picked up and implemented by someone reading the newest-looking file. Rule 3 of the
// canonical policy is that a card charging a price Stripe does not charge is "a trust
// catastrophe" — this suite exists so that catastrophe cannot arrive via a stale doc.
//
// This asserts DOCUMENT STATUS AND HONESTY, never prices. It must never be used to
// pin a price: the founder owns pricing, and PRICING-POLICY.md owns the numbers. If
// pricing changes, this suite should still pass untouched.
//
// Node 24+.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const docs = path.join(root, "docs");

let pass = 0, fail = 0;
const ok = (n, c, d = "") => { c ? pass++ : fail++; if (!c) console.log(`FAIL ${n}${d ? " — " + d : ""}`); };
const read = (f) => fs.readFileSync(path.join(docs, f), "utf8");
const head = (f, n = 60) => read(f).split("\n").slice(0, n).join("\n");

// Prose in this repo is hard-wrapped, so a phrase like "Cyber Essentials Readiness"
// is routinely split across a newline. Match against a whitespace-collapsed view or
// the assertion silently tests line-wrapping instead of meaning.
const norm = (s) => s.replace(/\s+/g, " ");

const CANONICAL_PRICING = "PRICING-POLICY.md";
const CANONICAL_BATTLECARD = "competitive-battlecard-v2.md";

// Documents that state or imply pricing/packaging and are NO LONGER a direction.
// Each must carry a status banner near the top and must not read as current.
const SUPERSEDED = [
  "final-commercial-packaging-v1.md",
  "cyber-essentials-commercial-strategy-v1.md",
  "pricing-strategy-v1.md",
  "pricing-page-copy-v1.md",
  "commercial-packaging-strategy-v1.md",
  "stripe-billing-architecture-v1.md",
  "pricing-audit-current-state-v1.md",
  "entitlement-audit-v1.md",
  "PHASE-0-AUDIT.md",
  "strategic-review-board-level-june2026.md",
  "competitive-battlecard-v1.md",
];

// May legitimately print the LIVE legacy prices while describing them as legacy or
// as today's configuration. Everything else printing them must be banner-marked.
const LEGACY_PRICE_EXEMPT = new Set([
  CANONICAL_PRICING,              // §5 documents what is live today
  "stripe-env-setup-v1.md",       // the runbook for the live products, still accurate
  "ROADMAP-TO-FIRST-PAYING-CUSTOMER.md", // states the legacy set is NOT the adopted one
]);

const BANNER = /^>\s+\*\*Status:\s+(Historical|Current for the live)/m;

// ── 1. Exactly ONE canonical commercial/pricing authority ────────────────────
ok("the canonical pricing policy exists", fs.existsSync(path.join(docs, CANONICAL_PRICING)));

const allDocs = fs.readdirSync(docs).filter((f) => f.endsWith(".md"));
const claimsPricingAuthority = allDocs.filter((f) =>
  /single canonical pricing and packaging authority/i.test(read(f)));
ok("exactly one document declares itself the canonical pricing authority",
   claimsPricingAuthority.length === 1 && claimsPricingAuthority[0] === CANONICAL_PRICING,
   `claimants: ${claimsPricingAuthority.join(", ") || "none"}`);

// The canonical policy must name the decision that makes it authoritative.
ok("the canonical policy carries its founder decision date",
   /Status:\s*DECIDED 2026-07-09/.test(read(CANONICAL_PRICING)));

// ── 2. No superseded document may read as an active direction ────────────────
// A status line like "**Status:** Active Commercial Direction" is an instruction to
// engineering and marketing. After supersession it must survive only as "was: ...".
const ACTIVE_MARKERS = [
  "Approved — Active Commercial Direction",
  "Active Commercial Direction",
  "Ready for implementation",
  "Current strategy",
  "Active Operational Plan",
];

for (const f of SUPERSEDED) {
  const src = read(f);
  ok(`${f}: exists`, fs.existsSync(path.join(docs, f)));
  ok(`${f}: carries a status banner at the top`, BANNER.test(head(f)),
     "no `> **Status: Historical ...` banner in the first 60 lines");

  // Any surviving active marker must be neutralised — either inside a "was:" clause
  // or inside the banner's own explanation of what it used to say.
  for (const marker of ACTIVE_MARKERS) {
    const lines = src.split("\n")
      .filter((l) => l.includes(marker))
      .filter((l) => !/was:/.test(l))            // "Superseded (was: Active ...)"
      .filter((l) => !/^>/.test(l));             // banner prose explaining the history
    ok(`${f}: does not still assert "${marker}"`, lines.length === 0,
       `live marker on: ${lines.map((l) => l.trim()).join(" | ")}`);
  }
}

// A superseded doc must not be the one thing a reader treats as the baseline.
ok("final-commercial-packaging-v1.md no longer claims to be the approved baseline",
   /no longer the approved baseline/.test(norm(read("final-commercial-packaging-v1.md"))));
ok("final-commercial-packaging-v1.md's authority clause is explicitly discharged",
   /That condition has been met/.test(norm(read("final-commercial-packaging-v1.md"))));

// ── 3. No conflicting price ladder may be presented as current ───────────────
// Every document printing the live legacy ladder must be either an explicit exemption
// or banner-marked. This is what stops a fourth ladder being implemented by mistake.
const LEGACY = /£149|£399|£1,428|£3,828/;
const offenders = allDocs
  .filter((f) => !LEGACY_PRICE_EXEMPT.has(f))
  .filter((f) => LEGACY.test(read(f)))
  .filter((f) => !BANNER.test(head(f)));
ok("no unmarked document presents the legacy price ladder as current",
   offenders.length === 0, `unmarked: ${offenders.join(", ")}`);

// The never-live £49 Starter is the most dangerous number in the repo: it was never
// charged and never approved, so it can only ever be implemented in error.
ok("the never-live £49 Starter set is quarantined behind a banner",
   BANNER.test(head("stripe-billing-architecture-v1.md")) &&
   /never-live/.test(head("stripe-billing-architecture-v1.md")));

// ── 4. Exactly ONE canonical battlecard ──────────────────────────────────────
ok("the canonical battlecard exists", fs.existsSync(path.join(docs, CANONICAL_BATTLECARD)));
const canonicalBattlecards = allDocs
  .filter((f) => /battlecard/i.test(f))
  .filter((f) => /^>\s+\*\*Status:\s+CANONICAL/m.test(read(f)));
ok("exactly one battlecard is marked canonical",
   canonicalBattlecards.length === 1 && canonicalBattlecards[0] === CANONICAL_BATTLECARD,
   `canonical: ${canonicalBattlecards.join(", ") || "none"}`);
ok("the superseded battlecard points at the canonical one",
   /competitive-battlecard-v2\.md/.test(head("competitive-battlecard-v1.md")));

// ── 5. Implemented vs SELLABLE MSP capability must stay distinguishable ──────
// This block used to assert "MSP Portfolio has NOT started", coupled to CLAUDE.md, with
// the note: "If MSP Portfolio ships, this test fails loudly and the battlecard gets
// updated — which is the point." It shipped (v2026.07.16-5), the test fired, and this is
// that update.
//
// The invariant was never really "not started" — it was that the battlecard must not
// promise a portfolio surface a prospect cannot be shown. Shipping the code did not
// satisfy that; it only changed the REASON it is unsellable, from "it does not exist" to
// "it exists and nobody has ever used it":
//
//   • /api/portfolio/* is gated on portfolio_monitoring (business+) and production has
//     ZERO business/enterprise subscriptions — no account can reach it;
//   • cyber_mot_domain_states holds zero rows until a scan finalizes;
//   • no authenticated customer acceptance has been performed — the proof is a harness
//     driving the deployed code path, which is not a customer using the product.
//
// So the assertion now pins the thing that actually protects the founder — the sell
// verdict and the demo guardrail — instead of a roadmap word that was always going to
// go stale. It is deliberately NOT coupled to CLAUDE.md's roadmap row any more: the code
// being Live and the capability being unsellable are both true at once, and a guard that
// cannot express that forces one of them to be written down wrong.
const bc = read(CANONICAL_BATTLECARD);
ok("the battlecard does not present MSP Portfolio as sellable",
   /\*\*MSP Portfolio Per-Domain State and Trend\*\*\s*\|[^|]*\|\s*\*\*No\.\*\*/.test(bc),
   "the sell verdict for MSP Portfolio must remain **No.** until it is customer-accepted");
ok("the battlecard forbids demoing the unaccepted portfolio surface",
   /Do not demo, promise a trial of, or imply the existence of a portfolio/.test(bc));
ok("the battlecard separates shipped from planned in a table", /May we sell it\?/.test(bc));
// Built is not accepted. The battlecard must say why it is unsellable, not merely that
// it is — a bare "No" invites the next reader to overturn it from vibes.
ok("the battlecard names the reason MSP Portfolio is not sellable",
   /zero business or enterprise subscriptions/i.test(bc) &&
   /No authenticated customer acceptance has been performed/i.test(bc));
ok("the battlecard does not claim MSP Portfolio is customer-proven",
   !/portfolio[^.]*\b(proven with|validated by|in use by)\b/i.test(bc));

// The roadmap row and the sell verdict are now independently true, so assert the
// direction that can actually harm someone: if a future episode marks the portfolio
// sellable, it must ALSO have removed the demo guardrail deliberately, not by accident.
const claudeMd = fs.readFileSync(path.join(root, "CLAUDE.md"), "utf8");
ok("CLAUDE.md records MSP Portfolio's acceptance as outstanding while the battlecard says No",
   /MSP Portfolio Per-Domain State and Trend \| Live[^|]*acceptance outstanding/i.test(claudeMd) ||
   /MSP Portfolio Per-Domain State and Trend \| Planned/.test(claudeMd),
   "CLAUDE.md must either still be Planned, or record that customer acceptance is outstanding");

// ── 6. No live-event alerting proof may be claimed ───────────────────────────
ok("the battlecard carries the live-event alerting guardrail",
   /Genuine live-event acceptance is outstanding/.test(bc) &&
   /not\*\* describe alerting as\s*\n?production-proven|production-proven/.test(bc));

// ── 7. Cyber Essentials: no certification or compliance guarantee ────────────
const ce = read("cyber-essentials-readiness.md");
ok("the CE readiness doc states CyberMeters does not certify",
   /does not certify Cyber Essentials/.test(ce));
ok("the CE readiness doc states readiness is externally observable evidence only",
   /externally observable evidence only/i.test(ce));
ok("the CE readiness doc states the questionnaire is not an input",
   /never reads\s*\n?`cyber_essentials_answers`/.test(ce) || /questionnaire is \*not\* an input/i.test(ce));
ok("the CE readiness doc names the two controls it cannot observe",
   /access_control/.test(ce) && /malware_protection/.test(ce) && /external_coverage: none/.test(ce));
ok("the CE readiness doc forbids the pass/fail prediction",
   /would pass/.test(ce) && /Never claim/.test(ce));

ok("the battlecard states the CE evidence boundary",
   /cannot\*\* predict a certification outcome|cannot predict a certification outcome/.test(norm(bc)));
ok("the battlecard forbids the CE claims that exceed evidence",
   /Never say:/.test(norm(bc)) && /(would|you'd) pass Cyber Essentials/.test(norm(bc)));
ok("the superseded CE strategy warns its own messaging is unusable",
   /Do not reuse them/.test(head("cyber-essentials-commercial-strategy-v1.md", 60)));

// ── 8. The eight canonical domains must be represented correctly ─────────────
const EIGHT = [
  "Email Protection", "Brand Protection", "Attack Surface", "Certificates & Trust",
  "Cyber Essentials Readiness", "Website Security", "Identity Exposure",
  "Shadow IT & Unmanaged Technology",
];
for (const d of EIGHT) {
  ok(`the battlecard names the canonical domain "${d}"`, bc.includes(d));
}
// The battlecard may *explain* that v1 said "four services" — that is the correction
// being recorded. It may not make the claim in its own voice, so every surviving
// mention must be anchored to v1.
const fourServiceLines = bc.split("\n").filter((l) => /four[ -]service/i.test(l));
ok("the battlecard never sells a four-service story in its own voice",
   fourServiceLines.every((l) => /\bv1\b/.test(l)),
   `unanchored: ${fourServiceLines.filter((l) => !/\bv1\b/.test(l)).join(" | ")}`);

// The canonical pricing policy's bundle claim must enumerate the same eight domains
// and must not present "Cyber MOT" (the product) as if it were a ninth domain.
const pp = read(CANONICAL_PRICING);
const bundleClaim = norm((pp.match(/full external-security posture\*\*[\s\S]{0,500}/) || [""])[0]);
for (const d of EIGHT) {
  ok(`the pricing policy's bundle claim names "${d}"`, bundleClaim.includes(d));
}
ok("the pricing policy's bundle claim does not list Cyber MOT as a domain",
   !/·\s*Cyber MOT\s*·/.test(bundleClaim));

// ── 9. Docs-only: no secret, no runtime configuration ────────────────────────
// A commercial-docs pass must never carry a credential or move production config.
for (const f of [...SUPERSEDED, CANONICAL_PRICING, CANONICAL_BATTLECARD, "stripe-env-setup-v1.md"]) {
  const src = read(f);
  ok(`${f}: contains no live Stripe secret`, !/sk_live_[0-9a-zA-Z]{24}/.test(src));
  ok(`${f}: contains no live webhook signing secret`, !/whsec_[0-9a-zA-Z]{32}/.test(src));
  ok(`${f}: contains no private key block`, !/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(src));
}

console.log(`\ncommercial-canonicalisation: ${pass} passed, ${fail} failed`);
if (fail > 0) { console.error("commercial-canonicalisation validation FAILED"); process.exit(1); }
console.log("commercial-canonicalisation validation passed");
