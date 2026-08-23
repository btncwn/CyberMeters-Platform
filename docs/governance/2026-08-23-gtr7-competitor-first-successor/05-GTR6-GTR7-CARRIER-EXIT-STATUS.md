# GTR-6 / GTR-7 and Founder Carrier-Exit Status

**Status ID:** `CM-STATUS-GTR6-GTR7-2026-08-23-001`<br>
**Measured through:** canonical transport sequence `330`<br>
**Production consequence:** none; `HOLD` remains controlling

## 1. Executive status

| Scope | Measured state | Consequence |
|---|---|---|
| GTR-4 successor instrument | Successor-5 candidate exists; Left zero-credit verification is queued | Install held |
| GTR-6 | **NOT ACCEPTED** after nine attempted cycles | Cycle 10 not armed; GTR-7 locked |
| GTR-7 | **NOT OPENED**; zero canonical GTR-7 artifacts | No GTR-7 comparison workorder/dispatch/report/ruling; no subsequent founder selection or GTR-7B authority exists |
| Founder carrier exit | **NOT ACHIEVED** | Founder remains control/transport bridge under the current local route |

## 2. Current byte identities

| Evidence | Identity / status |
|---|---|
| Ledger | SHA-256 `475fd4037dd68c368a5e05cd69f56cd0deff15717fc755189ef2828a49c78d4b`; head seq330 |
| Successor-5 candidate | `GTR4-SUCCESSOR5-HARNESS-CORRECTION-CANDIDATE-BYTES-001`; bundle `19602efa3469d111142e8d844d14d9cca3e385d86821b6312b9207f9f473418b`; independently verified PASS |
| Left dispatch | `GTR4-SUCCESSOR5-LEFT-MODE2-DISPATCH-001`; bundle `3ea0d800cab89788fb213f065bbe84b9e838585603d40b47dcb60633ec9c462e`; entry `3a886052c002aa05d6d37b8d1a34d6e2f92f8ada8ed5070f2508cb1570bbbde8`; independently verified PASS |
| Dispatch state | `OPEN_QUEUED_ZERO_CREDIT_INSTALL_HELD` |
| Planning product head | `83d31e12d1e5d77f2d56dfb760d604c901a64676`; clean at measurement time |

## 3. Why successor-5 exists

Successor-4 candidate bytes were accepted at seq326, but activation measurement seq328 proved the accepted activation harness still contained a stale `cm-artifact 1.3.4` literal. Bar 1 passed; Bar 2 failed; Bars 3–12 were not reached. Successor-5 corrects that harness and currently has zero execution credit.

Installed baseline remains:

- `cm-artifact 1.3.2` — `c6304e11cc29618b35a606d11459d2130a318ae7d9cbc9f97558452595945650`;
- `governance-attest 1.0.2` — `ec99a603b7c71a44c4a57114f2f178999c9c50c3b7d074e161678d258a71d18a`.

Proposed successor set is:

- `cm-artifact 1.3.5` — `ca0ff98035f7f897fb9b7854160d79c9c51c7f0926ff5fd336ee9a972812a173`;
- `governance-attest 1.0.4` — `47c4f21e1d6ff3027631081b2548b5641a0678a05d86c2e288115cecad4a2156`.

## 4. Serial gates still required before GTR-7

1. Fresh zero-credit Left verification of the exact seq329 candidate.
2. Governance acceptance of the exact successor-5 bytes.
3. Refilled activation package and all 12 activation bars.
4. Fresh whole-package verification.
5. Two separate real-launcher `RECOMPUTED_AND_CONSUMED/PASS` attestations.
6. Governance protocol acceptance.
7. Separate atomic versioned install and rollback proof.
8. Frozen target-host 4/4 real-acquisition preflight, with no in-cycle retry.
9. Fresh Cycle-10 C2, dispatch, START, and complete real cycle.
10. Independent Right observation and PMO reconciliation.
11. Separate FINAL Class-S GTR-6 route-acceptance ruling.
12. Distinct founder live-acceptance record.
13. Only then may GTR-7 open.

Priority cannot collapse or infer any of these gates.

## 5. GTR-6 history in one line per cycle

| Cycle | Terminal fact |
|---|---|
| 1 | Failed currentness before payload consumption |
| 2 | Valid ruling, but prohibited same-cycle retry after wrapper failure |
| 3 | Valid matter `FINAL_ACCEPT`, but return bridge carried prohibited hash/size metadata |
| 4 | Malformed STOP; no ruling or Right observation |
| 5 | Route and zero-founder-byte condition worked; matter was `FINAL_REJECT`; no qualifying GTR-6 acceptance |
| 6 | Batched commands; no attestation/ruling |
| 7 | Freshness guard self-tripped before acquisition |
| 8 | Stale/non-started dispatch sequence, then over-scoped guard; no ruling |
| 9 | Four acquisitions started, three completed, all failed on the `/dev/fd/5` implementation defect |
| 10 | `NOT_ARMED`; four-real-acquisition preflight remains held |

The history shows material progress and useful fail-closed behaviour. It does not support an acceptance or near-completion claim.

## 6. GTR-7 scope gap

Through sequence 330 there is no canonical GTR-7 comparison workorder, dispatch, report, or ruling. There is also no subsequent separate founder architecture selection and no separately authorised GTR-7B implementation, verification, or ruling. GTR-7's only accepted scope description is the transport-options ruling: after GTR-6, perform a zero-founder cloud/remote architecture comparison.

That scope has a gap relative to the founder's intended outcome:

- comparison is not selection;
- selection is not implementation;
- a read-only evidence path addresses only the outbound leg;
- Governance also writes rulings, so the inbound publication leg must be authenticated and append-only;
- the founder currently supplies human separation/receipt control, which must be replaced rather than removed silently.

## 7. Carrier-Exit Gate

The founder exits routine carrier/operator work only after a real two-direction exercise proves:

| Direction/control | Required result |
|---|---|
| Evidence submission | Canonical exact bytes reach Governance without founder payload transport |
| Ruling return | Authenticated exact ruling bytes reach the canonical append-only transport without founder payload transport |
| Freshness/currentness | Stale, superseded, malformed, unknown, or wrong-subject material fails closed |
| Principal separation | Author/verifier/governance roles are bound to authenticated principals, not only declared actor strings |
| Least privilege | Evidence leg is read-only; ruling publication is narrowly write-scoped and cannot rewrite history |
| Failure behaviour | Network, auth, stale pointer, partial write, duplicate, rollback, and recovery cases are tested |
| Auditability | Immutable logs and hashes permit independent replay |
| Acceptance | Independent verifier PASS + FINAL Governance acceptance + distinct founder outcome acceptance |

Founder architecture decisions and approvals remain required. The eliminated role is routine byte transport, not governance authority.

## 8. Next executable action

Do not open a GTR-7B implementation lane. Complete the already-queued successor-5 Left verification and GTR-6 first. If successor-5 passes, follow the serial gate list without shortcut; if it fails, repair under a new exact candidate and repeat zero-credit verification. GTR-7 comparison planning may be prepared read-only, but it receives no completion credit before GTR-6 acceptance.
