# Phase C — Hosted Records Engine expansion (design)

> Status: **DESIGN** (not yet built). Owner: Claude (integrate) / Codex (build).
> Extends the existing Hosted Records Engine (`workers/scan-api/src/engines/hosted-dmarc.js`,
> table `hosted_dns_records`, write-ahead saga + hourly sweep + autopilot + managed
> name `hd-<12hex>`). Email-wedge parity step 3 ("Hosted Records Engine") per the
> Red Sift gap-closing plan.

## Goal

Today the engine hosts **one** record type on the customer's behalf: the DMARC
`rua` reporting TXT (via CNAME delegation to a managed `hd-…` name). Phase C
generalises the same proven saga to the remaining email-authentication records a
customer would otherwise hand-edit in their DNS — so CyberMeters can *host and
keep correct* the full email-auth surface, not just RUA.

The value promise stays honest: we host records the customer **delegates to us**
(CNAME) or explicitly asks us to publish. We never silently mutate their zone.

## What already exists (do not rebuild)

- `hosted_dns_records` already carries `record_type` — the schema is generalised.
- Write-ahead saga: **Prepare → Execute (CF create) → Verify (both sides) → Commit**,
  `failure_count` / `last_error`, pending/committed states.
- Hourly sweep reconciler retries CF creation, re-verifies, auto-rolls-back
  under autopilot, deletes on removal.
- Autopilot is **OFF by default**; changes are staged (`pending_value`,
  `pending_since`) until verified.
- `REMEDIATION_REGISTRY` maps findings → guided fixes (shared by index.js +
  email-protection route).

## Sequence (easiest → hardest)

### 1. TLS-RPT (`record_type = 'TLSRPT'`) — *easiest, ship first*
A single TXT at `_smtp._tls.<domain>` naming a reporting mailbox — structurally
identical to the RUA TXT we already host. **Reuse `cfCreateHostedTxt` verbatim.**
- Value: `v=TLSRPT1; rua=mailto:<hosted-report-address>` (same ingestion path as RUA).
- Delegation: CNAME `_smtp._tls.<domain>` → `hd-…` managed name, same as DMARC.
- New: a `verifyHostedTlsRptRecord` sibling of `verifyHostedDmarcRecord` (same
  two-sided check: customer CNAME resolves + managed TXT present).
- Ingestion: TLS-RPT reports are JSON (not XML) — a separate, small parser; do
  **not** touch the DMARC XML path.

### 2. MTA-STS (`record_type = 'MTASTS'`) — *medium; needs a hosted policy file*
Two parts:
- **DNS TXT** at `_mta-sts.<domain>`: `v=STSv1; id=<version>` — hostable exactly
  like TLS-RPT.
- **HTTPS policy file** at `https://mta-sts.<domain>/.well-known/mta-sts.txt` —
  this is the new capability. The customer CNAMEs `mta-sts.<domain>` → a managed
  host we serve the policy from (a Worker route returning the policy text).
- Start policy in **`mode: testing`** (report-only, never bounces mail) — only
  advance to `enforce` on explicit customer action. This mirrors the DMARC
  none→quarantine→reject discipline: never break mail flow automatically.
- The `id` must bump whenever the policy changes; store it in `current_value`.

### 3. Remediation Registry extension — *low risk, high UX value*
Extend `REMEDIATION_REGISTRY` with guided fixes for the new signals (missing
TLS-RPT, missing/`testing` MTA-STS, no MTA-STS policy file) so each shows the
same "here's exactly what to publish / let us host it" CTA the DMARC flow has.
Can land alongside #1 without waiting for #2.

### 4. Dynamic SPF (`record_type = 'SPF'`) — *hardest; sequencing/flattening risk*
SPF hosted via delegation (`include:` or macro to a managed name whose TXT we
keep current). Hard because:
- SPF has a **10-DNS-lookup limit** — flattening/optimisation must be correct or
  we break sending.
- Changing SPF wrongly **blocks legitimate mail** — highest blast radius of all.
- Requires source-of-truth for the customer's legitimate senders (we can seed
  from observed RUA sender intelligence, but must confirm before publishing).
Gate behind explicit review; **autopilot must stay off for SPF** even when the
customer enables it elsewhere.

## Cross-cutting rules

- **One saga, many types.** Each type adds a `verifyHosted<Type>Record` + a
  `cfCreate…` (TXT reuse where possible); the sweep loop branches on
  `record_type`. No second reconciler.
- **Never break mail flow.** MTA-STS starts in `testing`, SPF stays manual-review,
  autopilot off for anything that can bounce mail.
- **Honest state.** "Hosted & verified" requires the two-sided check (customer
  delegation resolves **and** managed record present) — same bar as DMARC today.
- **Tenant isolation.** All rows scoped by `workspace_id`; managed names are
  opaque `hd-…` so one tenant's name never reveals another's.
- **Validation.** Each type ships a `validate-hosted-<type>.js` harness mirroring
  the DMARC one (saga states, two-sided verify, sweep rollback, isolation).

## Build order recommendation

1. Remediation Registry entries + TLS-RPT hosting (reuses everything) — smallest, shippable.
2. MTA-STS DNS TXT + hosted policy-file Worker route (testing mode only).
3. Dynamic SPF — separate, gated, manual-review, its own approval.

Each is an independent PR with its own harness; none blocks the white-label or
copy work.
