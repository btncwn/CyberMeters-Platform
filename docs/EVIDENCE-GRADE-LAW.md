# Evidence-Grade Law (v2) — Defensibility Standard for CyberMeters Data

Canonical founder law (24 July 2026, v2 after adversarial review). Companion to and enforced
under the Detection Depth Law (`docs/DETECTION-QUALITY-ROADMAP.md`). NOT a second governance
system — the explicit **acceptance criterion** for the data CyberMeters shows customers.

## Founder directive
> The data in our reports, obtained from our scans, must be real, correct and provable to a
> standard that withstands independent expert scrutiny. This is the top priority.

The moat is NOT the cryptographic seal (any competitor buys the same QTSP seal in weeks). It
is that **every data point is true to a declared grade, cites its authority, and honestly
states what it does not prove** — a system a competitor cannot copy by buying a product.

## Two independent axes (do not conflate — v2 correction)
Every customer-facing data point carries BOTH:

### Axis 1 — Evidence Grade (L0–L5): depth of observation, derivation and validation
- **L0 — Asserted.** No observation, or customer attestation only. Labelled "attested — not
  externally verified", never "verified"/"healthy". **Hard ceiling for externally-unobservable
  internal signals** (CE `access_control`/`malware_protection`, internal patch state, endpoint
  MFA). Dressing an L0 up as observed is the core overclaim offence.
- **L1 — Observed (single).** One direct observation; raw evidence captured, not re-observed.
- **L2 — Retained & reproducible.** Append-only raw evidence + method + source + timestamps +
  parser/engine version recorded, so the method can be re-run. (`repeat_confirmed=false` here.)
  Actual re-observation is a separate attribute `repeat_confirmed=true`, NOT a higher grade.
- **L3 — Effective-state resolved.** The true effective state behind the root record is
  resolved (SPF include-chain expansion; full TLS chain build; DMARCbis org-domain DNS
  tree-walk; effective header/redirect state); derivation chain recorded and reproducible.
- **L4 — Standard-conformant + re-observed.** Validated clause-by-clause against the governing
  standard with fixtures + mutation proof, AND actually re-observed (`repeat_confirmed=true`).
  The verdict cites its authority (see source-type + standard-provenance below). **L4 does NOT
  require an independent second source** — corroboration is a separate axis, because some
  signals have no meaningful second oracle.
- **L5 — Forensically defensible / adjudication-ready.** L4 PLUS **both** provenance chains:
  (a) **engine-method-validation provenance** — the engine is proven correct (four proofs:
  fixture · mutation · e2e trace · founder controlled-domain live acceptance); AND (b)
  **signal-instance provenance** — a tamper-evident chain-of-custody for THIS finding
  (who/what/when/how/source, append-only) so "example.com had this exact effective state at
  time T" is itself evidenced. PLUS a time anchor (see levels below), an explicit statement of
  what the signal does NOT prove, and mutation proof the guard cannot silently degrade.
  **Naming is deliberate: "forensically defensible / adjudication-ready" — prepared for
  independent technical scrutiny, tamper-evident and reproducible. It is NOT a guarantee of
  legal admissibility** (that depends on jurisdiction, expert method, records-exception,
  custody execution). Never say "court-proof", "legally admissible", "legal-grade".

Engine-method validation NEVER auto-promotes a customer finding: a validated engine makes L5
*possible*, but each finding earns its grade from its OWN signal-instance provenance.

### Axis 2 — Corroboration Status (orthogonal; reported, not folded into the grade)
`none` · `repeated` (same method, re-run) · `independent-path` (e.g. second resolver — confirms
path, not owner intent) · `independent-source` (a genuinely different observation: SPF ↔ RUA,
cert ↔ Certificate Transparency) · `controlled-ground-truth` (Item 19 oracle on a controlled
domain — validates the ENGINE, not a customer instance). When two independent sources diverge,
**flag the conflict; never average or silently pick one.**

## Every verdict carries provenance metadata
- **`source_type`** (v2): `normative_protocol` (RFC) · `configuration_baseline` (CIS Benchmark,
  Mozilla TLS) · `assurance_scheme` (Cyber Essentials, NCSC) · `management_framework` (ISO
  27001) · `customer_attestation` · `product_policy` (CyberMeters' own stricter opinion —
  labelled as such, never dressed as a standard requirement).
- **Standard provenance**: `standard_id`, `standard_version`, `section`, `requirement_type`
  (MUST/SHOULD/MAY/benchmark), `interpretation_version`, `engine_version`. Marking a "MAY" as
  FAIL is `product_policy`, not standard-conformance — say so.
- **Time anchor** (three honest levels, do not overclaim): `application_timestamp` (D1 write
  time — what we have now) · `append_only_sequence` (tamper-evident ordering) ·
  `external_trusted_timestamp` (RFC 3161 / qualified TSA — only WITH the QTSP seal; absent
  today). Call it "trusted timestamp" ONLY at the third level.

## Per-signal grade CONTRACT (v2 — prevents infinite acceptance)
"Max honest grade" does NOT mean "never ship until the ceiling." Each signal pre-declares a
contract; acceptance tests it:
```yaml
signal: spf_effective_policy
observable_ceiling: L5          # epistemic max for this signal
beta_target: L4                 # what we commit to for beta
minimum_publishable: L2         # below this, do not publish the signal
degrade_behavior: show_degraded # honest degrade, never silent-drop / never fake-up
required_corroboration: independent-source
```
Delivered below `beta_target` → publish honestly degraded OR fail acceptance; never present
above the achieved grade.

## Non-negotiables
1. Grade every customer-facing data point; never present above its true grade. **Defensibility
   = accurate grading + cited provenance + honest limits, NOT universal L5.**
2. Push each signal to its contract's target, bounded by observability (unobservable → L0).
3. Cite the authority AND its `source_type`; distinguish standard-requirement from product_policy.
4. Divergence between sources is a defect to surface, never averaged.
5. Engine validation ≠ instance ground truth — keep the two provenance chains separate.

## Customer UX (v2)
Main Executive PDF: human-friendly — `Evidence confidence: High/Medium/Low · Basis: … ·
Limits: …`. The formal L-grade, corroboration status and provenance live in the technical
appendix / evidence export, not stamped on every line. "Explanation first, number second."

## Scope & retroactivity (all 8 domains — founder clarification 24 Jul 2026)
This law is UNIVERSAL across all eight canonical domains — including already-built and
live-accepted detection (SPF/DMARC, Certificates, ASM, Brand, Identity, Website, Shadow IT,
CE) and any customer-facing signal "not currently on the radar". "Eight domains" is only an
honest claim if the grading is uniform.
- **Scope boundary (v2):** the law governs **customer-visible OR customer-impacting
  assertions** — anything shown to a customer, or that drives a score / alert / case /
  report / coverage-state. It does NOT require grading of internal operational data (debug
  telemetry, latency/retry counters, parser diagnostics, operational metrics) that never
  becomes a customer claim. "Un-inventoried = a gap" applies to customer-facing outputs, not
  to every internal counter — otherwise the audit balloons needlessly.
- **Retroactive path = a systematic grading audit**, NOT "re-build everything to L5 first":
  inventory every customer-facing signal across all 8 domains → assign its CURRENT grade +
  declare its contract → produce a gap registry → remediate signals below their contract.
- **Honest grading now ≠ universal L5 now.** A signal ships today honestly labelled at its
  current grade (e.g. L3) and is upgraded per its contract later. Overclaiming is the only
  hard failure; an accurately-labelled lower grade is acceptable.
- The best-built signals have a strong STARTING POINT toward an L4 target — SPF/DMARC post
  items 3–4 have effective-state resolution (L3), RUA independent-source corroboration, live
  controlled acceptance (engine-method validation) and append-only evidence. **But a grade is
  NOT pre-assigned without a signal-level audit** (L5 still requires per-signal chain-of-custody,
  time anchor, limit statement and no-silent-degrade). Older blanket-verification signals (some
  ASM/Brand/Identity) have a larger gap.
- A new **9th customer-facing domain is founder-gated** because it changes navigation,
  coverage-state, reporting, pricing and positioning (a product-model decision) — NOT because of
  the separate four-service sidebar grouping.
- This audit OVERLAPS Item 19 (per-module source-fidelity across all 14 probe modules) and
  Item 13 (reachability — an un-inventoried customer-facing output is itself a gap). Sequence
  it with those; do not treat it as a separate parallel programme.
- **Adding a new scan module** ships WITH its grade contract from day one (a new signal in an
  existing domain is days of work against the canonical shared systems; a new 9th domain is a
  founder-gated product decision, not just engineering).

## Scope discipline
- **Competitor levels are an INTERNAL design hypothesis** ("aims to exceed typical snapshot-only
  evidence models"), NEVER a public claim — asserting "competitors are L2/L3" without auditing
  their architecture is itself an overclaim.
- **Backlog:** reframes (does NOT reorder) the acceptance bar for items 6–12 — accepted only
  when each customer-facing signal meets its declared grade contract. Item 19 = the L5
  engine-validation mechanism.
- **Seal** (queued): a Qualified Electronic Seal makes the *document* non-repudiable; this law
  makes the *data* defensible. Seal is Phase-N ON TOP of graded data — asset over L4/L5, liability
  over overclaimed data.

## Implementation discipline (v2 — anti-paralysis)
Adopt the full taxonomy as the north star, but implement the MINIMAL VIABLE subset first (grade
+ `source_type` + basis + limits + `repeat_confirmed`) on the item-6 Executive-PDF pilot; add
corroboration status, the full contract fields and standard-provenance fields as real signals
demand them. Rigor is not up-front over-engineering.

## Standards note
Pin the CURRENT standard version at implementation time (per CLAUDE.md): DMARCbis is **RFC 9989**
(with 9990/9991), obsoleting RFC 7489 — NOT RFC 9091 (an experimental PSD extension). Also SPF
7208, DKIM 6376(+Ed25519), MTA-STS 8461, TLS-RPT 8460, IDNA 5890–5895. Verify each at build time.

See [[detection-quality-roadmap-canonical]], [[module-source-fidelity-freshness-law]],
[[evidence-grade-legal-defensibility-law]], [[report-verification-episode-queued]],
[[pre-beta-execution-resequencing]].
