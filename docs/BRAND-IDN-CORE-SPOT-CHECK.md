# Item 8 — PR-A IDN/Homograph Core Post-Merge Spot-Check

Date: 26 July 2026

Review target: `workers/scan-api/src/engines/idn-homograph.js` as present on
post-PR-B `origin/main` (`ab32344ac98fe9a9c8577e5aff71965050766439`)

PR-A source commit: `4efe82c` (`feat(brand): add IDN homograph detection core (#315)`)

Mode: focused, read-only review of the PR-A runtime core under Item 19 /
no-module-assumed-correct. The review did not change the core mapping or runtime
algorithm.

## Decision

**PASS for the focused engineering spot-check, with the bounded product-policy
limits below retained as explicit limits.** This satisfies the additional
post-merge review gate. It does not make Item 8 live-accepted: PR-C review and
founder-controlled live acceptance remain separate gates.

The implementation is a deliberately bounded detector, not a complete Unicode
Security Mechanisms / UTS #39 implementation and not proof of full IDNA
conformance. Its customer-safe conclusion is:

> Visually confusable IDN lookalike — a lookalike signal, not proof of abuse.

It must not be rendered as confirmed phishing, maliciousness, compromise or
attacker attribution without stronger evidence.

## Findings against the mandatory criteria

### Bounded confusable mapping: over-match and under-match

- The map is visibly declared as bounded and product-policy-specific. It covers a
  small set of common Cyrillic, Greek and Armenian characters and requires both a
  mapped character and a skeleton-distance gate.
- Over-match risk is bounded but not zero. Some mappings are font-dependent
  approximations rather than universally identical glyphs, notably Cyrillic
  `в→b`, `м→m`, `т→t` and Greek `β→b`, `ε→e`, `μ→m`, `υ→y`. Exact skeleton
  equality, or one edit only for brand skeletons of at least five characters,
  prevents a raw non-Latin character from becoming a verdict by itself.
- Under-match is intentional: the table omits most Unicode confusables,
  multi-code-point skeleton transformations and many scripts. An omitted
  character is retained rather than deleted, so lack of coverage fails toward a
  miss instead of a fabricated match.
- Campaign membership must not be inferred from this mapping. PR-C groups only
  exact reappearance or observed shared infrastructure.

### NFC and A-label/U-label round-trip

- Input is NFC-normalised and lower-cased before conversion.
- `tr46` 6.0.0 is pinned with bidi, hyphen, joiner, STD3 and DNS-length checks,
  non-transitional processing and invalid-punycode rejection.
- Decode performs U-label conversion, re-encodes to the canonical A-label and
  compares that A-label with the submitted name's encoded form. Unicode and
  `xn--` inputs therefore converge on one canonical identity.
- Deterministic controls cover the canonical Cyrillic fixture and composed versus
  decomposed Unicode. This is the product's pinned UTS #46 profile; it is not
  presented as proof of complete RFC 5890–5895 conformance.

### Mixed-script and whole-script classification

- Script detection counts Unicode letters and ignores digits, punctuation and
  Common-script characters.
- More than one detected letter script is classified as mixed-script.
- A single non-Latin letter script on a successful confusable match is classified
  as whole-script-confusable.
- Fixtures cover mixed Latin/Cyrillic, mixed Latin/Greek and all-Cyrillic
  lookalikes.

### Malformed IDN fail-closed behaviour

- Empty names, empty labels, invalid A-labels, failed conversions, invalid
  round-trips and thrown conversion errors return `is_homograph: false` with an
  error where applicable.
- Invalid punycode is not ignored. Disallowed joiner input is also pinned as a
  negative control.
- A conversion failure never falls back to ASCII similarity as an IDN-positive
  result.

### Legitimate internationalised-domain negative controls

- Internationalisation alone is never a signal. A candidate must contain a
  mapped confusable and meet the brand skeleton gate.
- `bücher.de` and an unrelated all-IDN Cyrillic hostname remain negative for the
  `apple` brand.
- Unmapped international characters are retained in the skeleton and are not
  counted as confusables, preventing match-by-deletion.
- Customer-owned IDN exclusion is implemented and mutation-tested in PR-B's
  discovery boundary; the PR-A core intentionally has no tenant or ownership
  state.

### Short-brand false-positive controls

- One-edit near matches are refused below five skeleton characters.
- Deterministic generation and CT literal-query expansion refuse brand tokens
  shorter than three characters.
- An exact mapped skeleton remains detectable in the pure core even for a short
  brand. This is intentional and explicitly tested: exact mapped equivalence is a
  different contract from speculative generation or one-edit matching.

### Unicode/A-label canonical equivalence

- Direct Unicode `аpple.com` and A-label `xn--pple-43d.com` resolve to the same
  canonical A-label.
- NFC-composed and decomposed forms resolve to the same canonical A-label.
- Downstream persistence and dedupe use the canonical A-label; Unicode is a safe
  display/evidence form, not a second candidate identity.

### Mutation adequacy

The original suite killed removal of punycode decoding and removal of the entire
skeleton lookup. The focused review identified that as insufficient for
individual high-impact table entries.

The CI mutation suite now also kills:

1. removal of the individual Cyrillic `а→a` mapping;
2. changing that mapping from `а→a` to `а→o`;
3. removal of the individual Greek `ο→o` mapping; and
4. removal of Cyrillic `р→p` from a repeated whole-script fixture.

This detects accidental deletion or alteration of representative high-impact
mixed-script and whole-script mappings. It does not claim exhaustive mutation of
every table row.

### Claim and wording audit

- Runtime comments call the map “UTS #39-inspired” and “deliberately bounded.”
  No inspected runtime surface claims UTS #39 completeness.
- Brand candidate UI says “lookalike signal, not proof of abuse.”
- PR-C case alerts, portfolio copy and report finding copy retain the same
  boundary.
- `confirmed_abuse` remains a human classification/state-machine decision; the
  IDN detector itself never emits “confirmed phishing” or “malicious.”

## Acceptance criteria

This spot-check is accepted only while all of the following remain true:

- the core deterministic validator is green;
- the strengthened mutation validator is green;
- Unicode and A-label forms retain canonical equivalence;
- malformed input remains fail-closed;
- legitimate internationalised negative controls remain green;
- short-brand one-edit and generation controls remain green;
- no runtime or customer copy claims complete UTS #39/IDNA conformance;
- no lookalike-only surface says confirmed phishing, maliciousness or compromise;
- any future confusable-map expansion receives positive, negative and
  individual-entry mutation coverage.

Any failure reopens the Item 8 closure gate. It does not require revisiting
canonically closed Item 7.
