# Item 9 P4 — Certificate Trust-Policy Depth

Status: implementation candidate for Claude pre-merge review. Founder live
acceptance is not claimed and remains deferred to Item 14.

## Goal

Extend the existing Item 9 certificate completeness contract with independent,
evidence-graded trust-policy signals. Missing evidence in one family must not
erase an independently reliable observation in another family.

## Exact Pre-Change Map

- `ssl-scan.js` uses one per-scan CT cache for crt.sh and CertSpotter while
  HTTPS reachability runs concurrently. It declares that the Worker HTTP fetch
  surface does not expose the peer leaf, presented chain or trust-store result.
- `dns-scan.js` already retrieves CAA through Cloudflare and Google DoH. The
  certificate phase did not consume that existing evidence.
- `certificate-signal-completeness.js` v1 resolved nine independent P1 signals
  and rejected a chain trust result without a named and versioned trust store.
  CAA, hostname match, intermediate validity, algorithm observations,
  trust-store validation and revocation completeness were not separate signals.
- `cert-intel.js` is the production caller. `cert-events.js` persists the whole
  contract in `certificate_observations.evidence_json`, using the existing
  workspace fan-out and soft-delete filter.
- `cert-trust-l2.js` could infer `parallel_certificate` from multiple unexpired
  CT/history rows. Those rows do not prove simultaneous live serving.

## Design Decision

`certificate-signal-completeness-v2` retains the nine P1 keys and adds:

| Signal | Decisive evidence | Honest unavailable state |
| --- | --- | --- |
| `caa` | Existing DNS CAA RRset, independently cross-checked where available | DNS failure or insufficient negative corroboration |
| `hostname_match` | Match/mismatch against identifiers in the live-presented leaf | No live peer certificate |
| `intermediate_validity` | Validity periods of the completely observed presented intermediates, or a positively observed expired intermediate | Incomplete presented-chain evidence |
| `certificate_algorithm` | Live leaf public-key and signature metadata evaluated against declared observed predicates | Metadata absent or insufficient |
| `trust_store_validation` | RFC 5280 validation with a named and versioned trust-store context | No validation or undeclared context |
| `revocation_assurance` | Validated RFC 6960 response, including signature and time semantics | Missing/unvalidated OCSP or revocation evidence |

The existing `chain` signal carries `presented_complete` or
`presented_incomplete`. A completely collected observation of an incomplete
presentation is a reliable adverse state; a collector timeout remains
`evidence_incomplete`.

CT remains issuance evidence. `summary.ct_only` is true only when CT evidence is
present and no live leaf was observed. HTTPS reachability remains an independent
active-service observation and does not upgrade a certificate to live-serving.

Historical snapshots and D1 evidence remain immutable. New scans write v2 into
the existing JSON field; no row is rewritten and no schema migration is needed.
Readers of old v1 evidence continue to see only the fields that were recorded.

## Standards and Evidence Policy

- RFC 5280 (May 2008): certificate fields, intermediate validity and declared
  certification-path validation.
- RFC 8659 (November 2019): current CAA authority. RFC 6844 is obsoleted and is
  not cited as the current rule.
- RFC 6960 (June 2013): OCSP status, signature and time semantics.
- RFC 9162 (December 2021): current Certificate Transparency authority.
- CA/Browser Forum TLS Baseline Requirements v2.2.8, dated 16 June 2026,
  accessed 26 July 2026: CAA processing, public-key sizes and certificate
  signature requirements.

The CA/Browser Forum requirements govern publicly trusted certificate issuance
and management. CyberMeters reports observed predicates against that declared
baseline; it does not issue a blanket `compliant` result. External TLS evidence
does not establish private-key security, internal keystore health, complete
internal certificate inventory or absence of compromise.

## Scope Boundaries

P4 adds no route, canonical snapshot, report renderer, PDF or frontend change.
Those parity surfaces remain P5. It adds no renewal/case transition, migration,
deployment, DNS/TLS change, certificate issuance, CT fixture or live acceptance.

The false historical/CT parallel inference is removed. A parallel L2 observation
is eligible only when the canonical `parallel_certificate_set` signal contains a
bounded simultaneous live endpoint set; multiplicity alone has no risk verdict.

## Budget and Compatibility

P4 performs only derivation over the existing DNS, CT, HTTP and declared TLS
evidence. It adds:

- zero network probes;
- zero CT lookups;
- zero SSL subrequests;
- zero D1 queries.

The existing SSL allocation remains 9,000 ms and six subrequests; the whole-scan
deadline remains 19,000 ms. Provider failure degrades CT only. Missing OCSP
degrades revocation only.

## Proof Plan

- deterministic complete, weak/mismatched, incomplete and provider-timeout
  fixtures;
- temporary source mutants for CT-as-live, undeclared trust store, revocation
  bleed, CAA failure-as-absence and CT/history-as-parallel;
- a real `runScanEngine` trace proving the production caller, existing budgets,
  one shared CT lookup per provider, persisted v2 evidence and tenant/soft-delete
  isolation;
- founder-controlled live acceptance deferred to Item 14.
