# Q7 — DMARC / TLS-RPT public report address: trust-boundary disposition

**Status: RECLASSIFIED to P3 — documented protocol trust limitation (not P2).**
Evidence-backed; the one missing bounded control (per-endpoint inbound rate limit) has been added.
Machine-checked by `scripts/validate-q7-dmarc-report-trust.js`.

## The finding

The DMARC aggregate (`rua=`) and TLS-RPT (`rua=`) addresses are, by protocol, **public
unauthenticated inboxes** — the customer publishes the address in their own DNS so that
mailbox providers worldwide (Google, Microsoft, Yahoo, …) can send reports. There is no
sender authentication the protocol itself provides: legitimate reports arrive from an
open set of providers. Anyone who reads a target's DMARC/TLS-RPT record can therefore
send a **forged report** to that endpoint. This cannot be "fixed" by inventing sender
authentication the protocol does not have.

The question for disposition is not "is the endpoint public?" (it must be) but "can a
forged report gain any **downstream authority**?"

## Why it is P3, not P2 — proof that a forged report has no authority

A forged report is bounded to **workspace+domain-scoped observed telemetry**. Every
authority question is NO (traced through the full ingest pipeline and every consumer):

| Authority | Verdict | Why |
|---|---|---|
| Cross-tenant write | **NO** | `workspace_id`+`domain` come *only* from the endpoint row (localpart→`dmarc_ingest_endpoints`, or token hash), never from the report body. Every INSERT binds that pair. `enforceDomainMatch` rejects a report whose policy domain ≠ the bound domain. |
| Trusted "verified" state | **NO** | `auth_verdict` is stored but **never read back for any decision** (0 `SELECT … auth_verdict`). The customer-facing "rua verified" derives from the **live DNS record**, not the ingest verdict. |
| Score / health / BRI credit | **NO** | No scoring/posture engine reads `dmarc_aggregate_*` / `email_sender_sources` / `tlsrpt_*`. A forged "all-passing" report cannot raise a score or turn a domain healthy — its novel source IPs enter as `classification='unknown'`, which *raises* findings, the opposite of the attacker's goal. |
| Case / remediation closure (attacker benefit) | **NO (bounded)** | Ingestion can open an "observed sender — needs review" case (noise in the victim's *own* workspace) and, only if the customer has already advanced a case to `awaiting_verification` on `automated` support and a clean window has aged in, mark that case verified. It changes **no external state** (no DNS, no enforcement, no score) and grants the attacker no capability. |
| Alert/workflow as trusted fact | **NO (bounded)** | Alerts are emitted as *"externally observed"* monitoring bookkeeping; nothing is treated as a verified fact. |

Because a forged report is **non-authoritative observed telemetry that cannot cross a
tenant boundary or create verified/healthy/score/closure authority**, the residual risk
is (a) monitoring noise in the victim's own workspace and (b) storage/parse volume — a
hostile-input/DoS surface, not an integrity or confidentiality breach. That is a P3.

## Bounded controls (verified present)

Parser safety (XXE: `<!DOCTYPE>`/`<!ENTITY>`/`<?xml-stylesheet>` rejected; regex parser,
no XML library, no entity expansion, no network I/O; TLS-RPT via guarded `JSON.parse`);
2 MB XML cap; 5000-record cap; 25 MB raw-email cap; 10 MB compressed/decompressed caps;
100× decompression-ratio (zip-bomb) cap; single-entry ZIP with magic-byte validation;
≤25 MIME parts; content-type/attachment selection; natural-key dedupe; endpoint-derived
tenant/domain binding on every write; append-only audit provenance; malformed input
fails closed; parser errors never leak internals (stable customer-safe drop reasons).

## The one control that was missing — now added

The **inbound-email path had no application-layer rate limit** (the token
`/api/dmarc-ingest` path already had one: 120/hr per endpoint, fail-closed). A per-endpoint
inbound rate limit (120/hr, keyed on the endpoint id) now bounds the cross-message forged
flood that per-message caps cannot. It **fails OPEN** — a rate-limit-store outage must
never drop legitimate customer evidence — and a limited drop is audited (append-only)
rather than surfaced as a misleading "malformed report" notification. Legitimate reporters
send a handful of reports/day per endpoint, far below the ceiling.

## Residual limitation (documented, accepted)

Sender authentication for DMARC/TLS-RPT aggregate reports does not exist at the protocol
level; a forged report from an attacker-controlled domain is ingested and recorded as
`unverified`. This is inherent and safe by the above: it is bounded, non-authoritative,
tenant-isolated telemetry. No further code change is warranted.
