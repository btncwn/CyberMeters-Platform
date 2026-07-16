# Verification Vocabulary — canonical, cross-domain

Status: **canonical** (founder-set, 16 July 2026, during M5.a PR2).
Scope: all eight Cyber MOT domains, every customer-facing surface.

This document is the single authority for how a verification outcome may be **worded**.
It does not decide *whether* something is verified — that is the Canonical Remediation
Registry (`verification_method` per finding) plus the universal case model
(`verificationSupportForCase`, PR #129). This decides what the customer is **told**.

---

## The rule

A managed case has ONE canonical phase `verified`, but it carries **two different customer
facts**. Calling both "Verified" is the difference between a claim CyberMeters can stand
behind and one it cannot.

| `verification_support` | What actually happened | Permitted customer wording |
| --- | --- | --- |
| `automated` | CyberMeters re-observed the fix itself (registry method `dns_recheck`, `https_recheck`, `certificate_recheck`, `rescan`, `receiver_reports`, `external`) | **"Verified by CyberMeters"** |
| `manual` | The registry says the product **cannot observe** this fix (`manual_attestation`). The case rests on the customer's word. | **"Attested by customer — not externally verifiable"** |
| `unsupported` | Nothing verifies it | Never "verified"; state the limitation |

### Reservations

- **"Verified"** and **"Confirmed"** are reserved **exclusively** for what CyberMeters itself
  observed. They must never appear in customer-facing state, labels, history, alerts, read
  surfaces or reports for a `manual_attestation` outcome.
- Tone carries meaning too. Green reads as "settled" at a glance, so an attestation is
  deliberately **not green**. Wording alone is not compliance.

### Fail-closed

A case that reaches `verified` without a resolvable support value is presented as an
**attestation**, never as CyberMeters' own observation. Inferring `automated` from silence is
the optimistic-healthy default the platform forbids; the honest fallback is the weaker claim.

### The frontend does not derive this

`verification_support` is computed by the backend from the canonical registry and travels on
the case (`GET /managed-cases` → `verification_support`). A screen that inferred it would be
independently deriving a verification verdict, which CLAUDE.md forbids.

---

## Why this is not a new product semantic

It is CLAUDE.md's standing rules read literally:

- "Customer assertion and CyberMeters external verification are different states."
- "Do not mark states 'Connected', 'Protected', 'Verified', 'Healthy' or 'Resolved' unless
  evidence supports the exact label."
- "Verification requires structured, **method-appropriate** evidence."

---

## Where it is enforced

| Surface | Enforcement |
| --- | --- |
| Case API | `verification_support` on every case (`routes/managed-cases.js`) |
| Frontend case display | `phaseMeta(phase, verification_support)` — `frontend/src/lib/caseDisplay.js`; `ATTESTED_LABEL` is the one wording |
| CI | `scripts/validate-verification-vocabulary.js` (mutation-tested) |

Per-domain today (from the registry, re-asserted in CI):

- **Website Security** — all 14 condition keys resolve to `https_recheck`. Every
  `website_case` is `automated`; an attestation can never conclude one.
- **Email Protection** — split *within* the domain: `dns_recheck` / `receiver_reports`
  conditions are `automated`; `hosted_rolled_back_auto`, `sender_unrecognised`,
  `sender_classification_worsened` are `manual_attestation` and must use the attested
  wording.

---

## Carry-forward (binding)

1. **M5.e parity matrix** — every domain row must state its `verification_support`
   distribution, not merely "verification: yes". A domain with mixed support is mixed, and
   the matrix must say so.
2. **Unified Reporting snapshot vocabulary (M5.c/M5.d)** — the snapshot must persist
   `verification_support` alongside any verification state, so both renderers render the
   distinction from one source rather than each re-deciding it. This extends the founder
   package's existing reservation ("'verified' AND 'confirmed' reserved exclusively for
   managed verification") with the sharper rule that managed verification **itself** splits,
   and only the observed half may use the word.
