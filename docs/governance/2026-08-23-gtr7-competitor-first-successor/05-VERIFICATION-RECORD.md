# Verification Record — GTR7/Competitor-First Successor Package

**Record ID:** `CM-VERIFY-2026-08-23-GTR7-COMP-FIRST-001`<br>
**Mode:** read-only evidence verification plus output-document creation<br>
**Protected source mutation:** none<br>
**Production/network mutation:** none

## 1. Transport-state reproduction

| Check | Reproduced result |
|---|---|
| Canonical ledger SHA-256 | `475fd4037dd68c368a5e05cd69f56cd0deff15717fc755189ef2828a49c78d4b` |
| Canonical head | sequence `330`; `GTR4-SUCCESSOR5-LEFT-MODE2-DISPATCH-001` |
| Head bundle / entry | bundle `3ea0d800cab89788fb213f065bbe84b9e838585603d40b47dcb60633ec9c462e`; entry `3a886052c002aa05d6d37b8d1a34d6e2f92f8ada8ed5070f2508cb1570bbbde8` |
| Head status | `OPEN_QUEUED_ZERO_CREDIT_INSTALL_HELD` |
| GTR-6 artifact-ID count | `38` |
| GTR-7 artifact-ID count | `0` |

The candidate and dispatch were verified through the transport verifier:

- `GTR4-SUCCESSOR5-HARNESS-CORRECTION-CANDIDATE-BYTES-001` — `PASS`, bundle `19602efa3469d111142e8d844d14d9cca3e385d86821b6312b9207f9f473418b`, current subject, zero subject-graph issues.
- `GTR4-SUCCESSOR5-LEFT-MODE2-DISPATCH-001` — `PASS`, bundle `3ea0d800cab89788fb213f065bbe84b9e838585603d40b47dcb60633ec9c462e`, current subject, zero subject-graph issues.
- `FOUNDER-DECISION-008-ATTACK-SURFACE-DEPTH` — `PASS`, seq276 bundle `e9c183ffaefea184d308beb0888efab1d403c04101974fae4f59cb0586497c18`, current subject, zero subject-graph issues.

These are byte/transport verification results. They do not promote the queued successor-5 dispatch or either local AS handoff to technical acceptance.

## 2. Product-source reproduction

| Check | Result |
|---|---|
| Planning checkout | clean; exact `HEAD` `83d31e12d1e5d77f2d56dfb760d604c901a64676` |
| Audited checkout | clean; exact audited snapshot remains `35a3cd6e5fbcce4222235d4cf6958f02a668774f` |
| PR #419 merge | object `94283bc1d5b5b33744687b59c41bb8657308af1f` exists and is an ancestor of release tree |
| `v2026.08.21-1` | resolves to `60420ae18302692da9a10e75a5b0ce820966a3a9` |
| Academy false claim | absent; replacement states HTTP/HTTPS response and technology fingerprinting |
| `admin_surface.ip_address` claim-only emission | absent at the measured current head |
| KEV/CVE score impacts | both remain `score_impact: 0` in `asset-intel.js` at the measured head |
| Reserved orchestration | default remains legacy/flag-gated in source; exact deployed configuration is not proven here |

## 3. Source-integrity reproduction

| Check | Reproduced result |
|---|---|
| iCloud path identity | `~/Documents` reports `com.apple.CloudDocs.iCloudDriveFileProvider/39E3E824-50F9-4613-A188-FF134EB37DAA` |
| Old/new primary paths | old primary exists; `/Users/turhanacar/dev` absent |
| Old root condition | branch behind 3; two observed modified paths; status indexing reported `Operation timed out` |
| Nested project worktrees | 11 under `.worktrees/` |
| Old registered worktrees | 67 total; 53 marked prunable; 14 not marked prunable |
| Path-keyed Claude hazard memory | present; SHA-256 `4e31eea464ac88ebba4f829c3ce33a75008bd64eafc1d357ad739691a94e950a` |
| 20-Aug live-acceptance incident record | SHA-256 `1fc3d5e8f1463710a573dfd8dc5f913a42672a0d03a4005cf79c96bcf9ac4477` |
| Current transport corpus | approximately 105 MiB; 3,869 files |
| Current ledger | sequence 330; SHA-256 `475fd4037dd68c368a5e05cd69f56cd0deff15717fc755189ef2828a49c78d4b` |
| 22-Aug local ledger copy | sequence 307; SHA-256 `a6b129e36deb7ec64e7092d97ed51a0898a295fa7b72227ef1006f2430153843` |
| 23-Aug local ledger copy | sequence 327; SHA-256 `3384bcde68f6a1c7e93f8d519873281703f277f235f23344d3936affc6d78763` |
| Storage failure domains | live ledger and both dated copies resolve to `/dev/disk3s5`; no independent current copy demonstrated |
| External target | founder-owned disk selected; not mounted during this verification |

The user's “single copy” concern is materially valid at the failure-domain level but was narrowed factually: dated local copies exist. They are neither current to sequence 330 nor independent of the host disk. A full-transport external snapshot and restore proof remain open.

No repository move, worktree prune/removal, path rewrite, external-disk copy, or other destructive action was performed during this update.

## 4. Source-evidence hashes reproduced

| Evidence | SHA-256 |
|---|---|
| Attack Surface competitor-depth report | `46ec94a97cf6c75db147a121a4f5dce5bb013a1b3dc6f5c88e7fc8004bdfa59c` |
| FD-008 payload | `f69cf4c55596e583ce821ef095d4855fb08eae58cf68175e075e88763d4c289b` |
| Historical pre-Item-12 Board | `bfedb40f2dcfa96215706ee743924b409073b4cfdf8a457fa1523aba8f0b1910` |
| AS-B2 pre-change map | `eb8890d093df7a4c4251a11a60c7342c86e8a01b7d20e61ac62a7e88d293e276` |
| AS-B2 accepted policy | `626862f6e6f9dd19fd8bf42053c0d7317b04fc9398496fd07eaab415404cc7a8` |
| AS-B6 pre-change map | `79a5999c35beef059c2925e816bf0ee2a69f602480944cb9ccaa4f3fe6b357a0` |
| AS-B6 accepted policy | `fd19a23b8ae52ae7bfbdf8d66007ae9840efc7752954b23290451363ceb2f3ce` |
| New local AS-B2 workorder | `31e63293773d8d115f07bde5bc3d351fcc8e7412b12f25c01049b28ad2eb1c19` |
| New local AS-B6 read-only re-dispatch | `f354e93353fc9902e82fe3d6c3e98d14189fa09cca40c410bea0804a68e831a5` |
| Transport-options analysis | `67fce79008038a192e1d89f9fd922474d41b0ed405c108e5f50aab07a6a14b29` |
| Transport-options ruling payload | `680ecfde7d9c2854db3ed8264f6d8419d269395c573add11712c3aa25e92fd6a` |
| Canonical battlecard v2 | `51c1b4356a949fe24b9cac7db0348283ec9ee1e774d65434755290145e3e69a4` |
| Detection-depth audit | `63fed2d14cd51c948a1ef5f9a9097db82334f1744c68450df0e9dc0ad80673c1` |
| Detection-quality roadmap | `c3f943dc57b55d7f0ab46516e41ec51632cd566aa7c5a163e09d4b5dcc2f8415` |

The two new AS handoffs were absent from the canonical ledger through seq330. They exist as operational local dispatches; absence from the ledger means zero canonical execution/acceptance credit, not nonexistence.

## 5. Audit-source provenance reproduction

The four protected audit/rebuttal packages remained byte-identical and their checksum manifests were re-run successfully:

| Package | Report SHA-256 | Matrix / ledger SHA-256 | Manifest SHA-256 | Source disposition |
|---|---|---|---|---|
| Original Claude audit | `9ff416961c84a1e5a81d86f2e03276f485747adc7296c6b9c322ab39a6e05818` | `4e4128b58706661729602b09170239ab7cb4debb0e643871c97f991178d8fab9` | `639c67be12db43299d34778362cfb33466ab5fc5fc04c1b2a11e99e44dbeca82` | Code findings use clean detached `35a3cd6...` / tree `0820e0d...`; shallow history boundary and local-topology exclusions recorded. |
| Codex verification | `1d07b0f80e7650931b91e1313582961e821406623bd97ef74f8f0568cf2eb1c9` | `71c2f0eda4a060f9571418d635539ef3b7cf7dce41a6bc5a1d0e470920c654f5` | `90a8a231991c07d9813d762f76313a53657254077d5f5795af3a99d298d4f6e8` | Clean full audited/current worktrees; primary governing matrix. |
| First Claude rebuttal | `c36ebc4cdf5a7cee5c27a6e50f3f98bb771603b94391aaa739cebaea22f2c74c` | `96f77e4461fe22f95f46170bd1c9fbcbaf6583f7cf6d6893a9b4932de7bfe752` | `7e9ad737dcea43e23c5b3de7819ee74dcb7b4093360eb67a0ff9614583fa281a` | Safe with narrow exception: `F-002` rebuttal and broad source-integrity release excluded. |
| Second Claude rebuttal | `12b3a48781bdc44a309a000873045ccca6bb6c7a3636748a271b1d91d312149d` | `6db02337c5d11fa57bd43ba2fa07aa8a88f951c5b036bbb767f22b295ed65493` | `4a481fa325e3fe3dadbfc89ae64f67b457fc29781b65771333644f36ca7645b4` | Clean full audited/current worktrees; accepted challenge/correction layer. |

The old iCloud checkout was not used as load-bearing product-byte authority. Its uses were bounded local metadata/topology questions plus one non-decisive schema comparison. The original audit's decisive product source was `/Users/turhanacar/cybermeters-work/claude-cli-i11` at commit `35a3cd6e5fbcce4222235d4cf6958f02a668774f`, tree `0820e0d7269d6e5fd10c8a9d289fbdafabd666ab`; the same bytes reproduce in the full audited worktree. Later code conclusions used clean full worktrees at that pin and at `83d31e12d1e5d77f2d56dfb760d604c901a64676`, tree `9d4d37d616906ab1906f272d49f58c9e2972058d`.

The resulting ruling is `CM-GOV-2026-08-23-AUDIT-PROVENANCE-001`: no global taint, bounded exclusions, `F-026` exact-candidate re-baseline required, and production `HOLD` unchanged. The pre-amendment seven-file successor manifest was `663659f98cd1f6853fcb1e1d16c76e52c853da6cc4eb7ba49294c8b656dfe612`.

## 6. Predecessor preservation

The sealed predecessor package was not edited. Its identities still reproduce:

- roadmap `1b500037d1d758909001fc1bb1f123103c8abd05e8478c167bc9bed804698702`;
- governance addendum `c9a0fe26e2b810e289b701e273d3358f38baeca95d2d1de5fac378e1a9ad843e`;
- Item 12/13 register `c82d000a22be5cb916b47e546042696a190bd6705f50c6b12dd446120724c098`;
- predecessor manifest `d699d6c0c6b606a32bba6deb3055a692e08d97f1fc440a72f4f36540d88ce829`.

## 7. Independent review

Three independent review lanes checked this successor package:

1. factual evidence review;
2. governance/authority review;
3. internal-integrity and hash review.

Material corrections incorporated before sealing:

- changed the false serial model to parallel GTR/carrier, shame-preparation, and source-integrity lanes with a mandatory join before audit;
- formalised the comparison/implementation gap as `GTR-7B / Carrier-Exit Gate`;
- split the historical combined honesty obligation into an operational four-row table (`2/4` closed);
- distinguished non-canonical operational dispatch from canonical execution/acceptance credit;
- stopped the unsafe AS-B2 instruction pending amendment while allowing corrected isolated preparation/authoring;
- allowed the AS-B6 read-only map to run now without activation authority;
- retained the full 22-axis commitment outside the narrow four-row pre-audit gate;
- added source relocation and independent transport backup as a third prerequisite lane;
- rejected a blind filesystem move in favour of a verified fresh-clone cutover;
- corrected “one ledger file” to “multiple local copies, one physical failure domain, latest copy behind current head”;
- treated the daily sealed local-ledger job as a control to establish/schedule/monitor, not an already-proven cadence;
- recorded the founder-owned external disk and a maximum seven-day verified full-transport cadence, with missed-run fail-closed behaviour;
- retained 2026-09-01 as a reforecast checkpoint rather than a candidate promise.
- independently classified the four audit/rebuttal source instruments, retained their code evidence, and quarantined the exact local-topology overclaims and wrong-repository `F-002` rebuttal;
- made audit provenance a completed subcontrol without falsely closing the source-relocation/backup or recovery gates.

No reviewer found a broken cited external hash after recomputation.

## 8. Seal rule

`05-SHA256SUMS.txt` covers all eight Markdown deliverables in this directory, including this verification record and the audit-source provenance adjudication, and excludes itself. It must pass `shasum -a 256 -c 05-SHA256SUMS.txt`. The manifest's own SHA-256 is reported separately so there is no self-referential row.
