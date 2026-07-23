# Q7 — DMARC / TLS-RPT public report address: trust-boundary disposition

**Status: P0 authority path contained by PR-5.5 Gate 1; Gate 2 formalizes honest
trust semantics. Inbound evidence remains observational.**

Machine-checked by `scripts/validate-q7-dmarc-report-trust.js` and
`scripts/validate-inbound-email-authority-containment.js`.

## The finding

DMARC aggregate (`rua=`) and TLS-RPT (`rua=`) addresses are public,
attacker-addressable inboxes by protocol. Anyone who reads a target's published
record can submit a forged report whose body names that target domain.

Cloudflare Email Routing does not expose a trusted `Authentication-Results`
value to this Worker. Header-From, envelope From, Authentication-Results, the
reporter organisation, and the report-body domain are therefore untrusted claims
at this boundary. Matching header-From against a recognised public-mail domain
does not authenticate the sender or report producer.

Before Gate 1, forged inbound DMARC records could reach authoritative consumers,
including hosted-DMARC automation that PATCHes a real Cloudflare TXT record.
That was a live P0 security-boundary defect, not a bounded P3 noise issue.

## Gate 1 containment and Gate 2 contract

`workers/scan-api/src/lib/dmarc-authority.js` is the single authority contract.
It separates:

- the authenticated submitting actor;
- the explicit ingestion source;
- inbound transport-sender authentication;
- the report body's claimed domain;
- bounded evidence confidence;
- authoritative eligibility; and
- the stricter eligibility required for destructive/external automation.

Inbound email is never authority-eligible. Missing or unknown source provenance
also fails closed. Recognised reporter-domain membership is metadata only and is
independent of every authority decision.

The existing authenticated and scoped customer-submission paths
(`manual_paste`, `signed_upload`) retain their internal-authority behavior, but
they do not authenticate the report producer or content. Destructive/external
automation additionally requires independent corroboration. That corroboration
model does not exist, so no aggregate-report source may currently drive
hosted-DMARC auto-rollback, autopilot advancement, or a Cloudflare TXT change.

## Authority disposition after containment

| Authority | Verdict | Why |
|---|---|---|
| Cross-tenant write | **NO** | Workspace and domain bindings come from the endpoint or authenticated route, never from the report body. |
| Producer or sender “verified” state | **NO** | Inbound transport authentication is unavailable. Legacy `verified` values are normalized to `sender_domain_claimed_recognised`, which is metadata only. |
| Hosted-DMARC DNS automation | **NO** | The external-automation contract has no eligible source until independent corroboration exists. |
| Case auto-verification or recovery from inbound | **NO** | Authoritative lifecycle consumers use the central source gate; inbound and unknown sources are excluded. |
| Authoritative readiness, business risk, or Executive evidence from inbound | **NO** | Every aggregate-report reader used by these consumers is source-gated. |
| Authoritative alerts from inbound | **NO** | Sender lifecycle, hosted impact, and SPF-corroboration consumers exclude inbound and unknown report sources. |
| Observational storage and display | **YES** | Reports remain ingested, deduplicated, stored, and shown as “reported to us” evidence with `authoritative: false`. |

The mutation validator removes each consumer gate and proves that attacker-chosen
pass/fail counts regain the prohibited outcome. With the gates present, the same
forged fixtures cause zero DNS change, case transition, authoritative score/risk
change, or authoritative alert.

## Bounded controls

The existing parser and ingestion controls remain separate from this Gate 2
change: XML unsafe-construct rejection, decoded-size and record caps, TLS-RPT
guarded JSON parsing and array caps, raw/compressed/decompressed email caps,
compression-ratio caps, bounded MIME selection, endpoint-derived tenant/domain
binding, natural-key dedupe, safe drop reasons, and audit metadata.

Gate 3A wires the same cycle-safe D1 limiter into both Worker entries. The
standalone `cybermeters-email` export now enforces the 120-message
per-endpoint/hour ceiling before reading message bodies; missing dependency
wiring is a hard failure and a CI mutation removes the injection to prove the
gate turns red. The limiter remains intentionally non-atomic and fail-open on a
rate-limit-store outage; Gate 3B does not change those Gate-3A limiter
semantics.

Gate 3B makes DMARC/TLS-RPT evidence persistence atomic and repairable. A
non-null, authority-vs-observational source-scoped claim moves
`pending → complete | failed`; report metadata, detail rows, sender rollups and
the complete transition commit in one D1 batch. Failed claims are repairable on
redelivery and are excluded from every evidence reader until complete. The
persisted-detail ceiling is 300 rows: the worst DMARC transaction is 604 D1
statements, leaving 396 of the 1,000-query invocation budget for claim/audit and
surrounding work. Larger reports and invalid base64 are required audited drops,
while transient persistence failure is a failed/quarantined claim plus
append-only audit rather than silent success.

Parser hardening remains separately founder-gated Gate 4 and is not evidence of
report authority.

## Residual limitation

Inbound aggregate reports remain unauthenticated observational claims. They may
create storage, parsing, and customer-noise risk, and a recognised public-mail
header-From still cannot establish producer authority. Reports are retained for
observational value, clearly labelled non-authoritative, while all
inbound-driven authoritative and external outcomes remain suspended.
