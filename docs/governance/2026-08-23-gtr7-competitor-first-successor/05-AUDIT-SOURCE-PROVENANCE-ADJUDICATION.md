# Audit Source-Provenance Adjudication

**Ruling ID:** `CM-GOV-2026-08-23-AUDIT-PROVENANCE-001`<br>
**Issued:** 2026-08-23<br>
**Authority:** Independent Governance & Assurance Authority<br>
**Scope:** original Claude audit, Codex adversarial verification, first Claude author rebuttal, and second Claude rebuttal to Codex<br>
**Pre-amendment successor-package manifest:** `663659f98cd1f6853fcb1e1d16c76e52c853da6cc4eb7ba49294c8b656dfe612`<br>
**Decision:** **PROVENANCE ACCEPT WITH BOUNDED EXCLUSIONS; NO GLOBAL TAINT; PRODUCTION HOLD UNCHANGED**

## 1. Question adjudicated

The iCloud-managed old primary checkout demonstrated a real stale-source hazard: a nominally successful fetch could leave the working tree materially behind the source intended for release. This ruling determines whether that hazard invalidates the two audits and two rebuttals, and which record governs recovery planning.

It does not regrade every finding, accept remediation, lift the Phase-3 `HOLD`, or authorise deployment/customer activation.

## 2. Exact package identities

All four checksum manifests were re-run successfully. The original audit manifest contains one improperly formatted non-record line, but all 16 well-formed entries verify.

| Package | Primary report SHA-256 | Matrix / ledger SHA-256 | Command log SHA-256 | Manifest SHA-256 |
|---|---|---|---|---|
| Original Claude audit | `9ff416961c84a1e5a81d86f2e03276f485747adc7296c6b9c322ab39a6e05818` | `4e4128b58706661729602b09170239ab7cb4debb0e643871c97f991178d8fab9` | `16de117ce66d1653f432604d0022ee0c855dd08af628676d6428abd783153657` | `639c67be12db43299d34778362cfb33466ab5fc5fc04c1b2a11e99e44dbeca82` |
| Codex adversarial verification | `1d07b0f80e7650931b91e1313582961e821406623bd97ef74f8f0568cf2eb1c9` | `71c2f0eda4a060f9571418d635539ef3b7cf7dce41a6bc5a1d0e470920c654f5` | `f48cca878f5ad79b6a56c189be129489c17cb3752291eaf55df41a0827ad0825` | `90a8a231991c07d9813d762f76313a53657254077d5f5795af3a99d298d4f6e8` |
| First Claude author rebuttal | `c36ebc4cdf5a7cee5c27a6e50f3f98bb771603b94391aaa739cebaea22f2c74c` | `96f77e4461fe22f95f46170bd1c9fbcbaf6583f7cf6d6893a9b4932de7bfe752` | `69404e9621d1e617ee6b547e3d93199b5a5136d2db2e1772abd273bafeffdda7` | `7e9ad737dcea43e23c5b3de7819ee74dcb7b4093360eb67a0ff9614583fa281a` |
| Second Claude rebuttal to Codex | `12b3a48781bdc44a309a000873045ccca6bb6c7a3636748a271b1d91d312149d` | `6db02337c5d11fa57bd43ba2fa07aa8a88f951c5b036bbb767f22b295ed65493` | `3b14b4bfef3b1ab16b02423b45311e651e95b46e19b1d8065ec2b899ef4272f0` | `4a481fa325e3fe3dadbfc89ae64f67b457fc29781b65771333644f36ca7645b4` |

## 3. Source-binding findings

### Original audit

Its load-bearing product-code source was the clean detached checkout `/Users/turhanacar/cybermeters-work/claude-cli-i11`, not the iCloud-managed primary:

- commit `35a3cd6e5fbcce4222235d4cf6958f02a668774f`;
- tree `0820e0d7269d6e5fd10c8a9d289fbdafabd666ab`;
- shallow `true`, clean and detached;
- the same commit and exact tree reproduce in the later full, non-shallow audited worktree.

The shallow boundary limits history, ref-topology, and repository-health claims. It does not alter the audited working-tree bytes. The old iCloud checkout was load-bearing only for bounded local machine/repository observations and secondary comparison evidence, principally `F-001`, `F-002`, `F-005`, `F-012`, supporting `F-029`/`B-12`, and one non-decisive schema comparison. Therefore the code audit is not globally tainted.

### Codex verification and both Claude rebuttals

Their load-bearing code conclusions were reproduced against two clean, detached, full worktrees:

- audited: commit `35a3cd6e5fbcce4222235d4cf6958f02a668774f`, tree `0820e0d7269d6e5fd10c8a9d289fbdafabd666ab`;
- then-current: commit `83d31e12d1e5d77f2d56dfb760d604c901a64676`, tree `9d4d37d616906ab1906f272d49f58c9e2972058d`.

The old iCloud checkout was not accepted as product source truth. Codex used it only for bounded local metadata; the second Claude rebuttal used it for the point-in-time tag-ref measurement. The first rebuttal's disputed `F-002` treatment is handled expressly below.

## 4. Governing hierarchy

For recovery planning, use this hierarchy:

1. **Codex verification matrix/report** as the primary reconciled finding ledger.
2. **Second Claude rebuttal to Codex** as the authoritative challenge/correction layer, subject to final Governance adjudication.
3. **Original Claude audit** as historical discovery and evidence at the exact `35a3cd6...` pin, not as an unqualified statement about later production/current-main state.
4. **First Claude author rebuttal** only where it does not conflict with the exclusions below or the later, better-grounded records.

No finding is accepted merely because multiple agents repeated it. The exact evidence and the newest valid correction govern.

## 5. Bounded exclusions and corrections

| Matter | Adjudication |
|---|---|
| `F-012` tag refs | **REJECT the original count/conclusion.** Point-in-time measurement was 148 tag refs: 79 readable and 69 dataless; the audit inverted the result. |
| `F-001` | Retain only as evidence of local-checkout availability/source-integrity harm. Reject unsupported remote-history-loss or production-impact expansion and reject “eviction” as a proven cause; measured facts support zero iCloud quota/file-provider stalls and stale-source risk. |
| `F-002` | The original work copy really was shallow, one-commit and without remote refs at audit time. Reject/supersede the first Claude rebuttal's contrary measurement because it inspected different repositories. Treat this as workstation/source-provenance state, not a deployable-product blocker. The independent source-integrity relocation gate nevertheless remains open. |
| `F-005` / `F-029` | Local operational hygiene/topology observations only; no product-byte consequence may be inferred. |
| `B-12` author-history count | Treat as a partial sample, not complete repository authorship history. Separate documentary bus-factor evidence may stand on its own. |
| `F-026` | The decisive files changed between audited and then-current trees. Re-baseline against the exact intended recovery/current pin before severity, remediation, or closure credit. |
| `F-035` | Remains usable: its validator behaviour was reproduced directly on the pinned audited tree; the old schema comparison was supporting, not load-bearing. |
| First rebuttal's broad `F-001`/`F-002` blocker release | Not governing. Source-integrity consequences remain open until the fresh-clone cutover and independent backup gate close. |

## 6. Consequences

- A full rerun of all four exercises is **not required** solely because of the iCloud hazard.
- The principal code findings remain admissible at their exact source pins, including the surviving confidentiality/privacy blockers `F-009` and `F-021`.
- The Phase-3 production/customer `HOLD` remains unchanged. Provenance acceptance is not remediation acceptance.
- Audit-recovery work may begin only after the carrier, operational shame-table, and source-integrity join gate closes.
- The recovery candidate must be assembled and tested from the new full clone at `/Users/turhanacar/dev/CyberMeters-Platform`, rebound to an exact remote commit/tree and clean object database.
- Before a new Governance recovery ruling, re-run affected-path analysis against that exact candidate, re-baseline `F-026`, reproduce `F-009`, `F-021`, and every surviving blocker, and prove that no cited closure depends on the old iCloud checkout.

## 7. Fail-closed conditions

Set the audit provenance state to `HOLD/OPEN` and deny recovery-candidate credit if any of the following occurs:

- a listed report, matrix/ledger, command log, or manifest hash does not match;
- an audited/current/recovery commit or tree cannot be reproduced from a full clean clone;
- the old iCloud checkout or its local refs are used as current product-source authority;
- source drift touches a load-bearing finding path without re-analysis;
- `F-012`, the first rebuttal's `F-002` rebuttal, or unsupported “eviction” causation re-enters the governing ledger;
- `F-026` is closed without exact-candidate re-baselining;
- the `/Users/turhanacar/dev` cutover, independent external-disk backup, manifest verification, or restore-to-scratch proof is missing/degraded;
- a remediation claim is promoted from implemented/merged to accepted without its exact independent retest and Governance ruling.

## 8. Final ruling

**ACCEPT the four packages as a usable evidence corpus under the hierarchy and bounded exclusions above. There is no global iCloud taint and no justification for discarding the audit work. REJECT the identified local-topology overclaims and the first rebuttal's wrong-repository `F-002` rebuttal. Keep production/customer activation on HOLD, and require exact-candidate re-binding after the verified `/Users/turhanacar/dev` cutover before audit recovery can receive Governance acceptance.**
