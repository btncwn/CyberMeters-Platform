# Source-Integrity Relocation and Independent Backup Gate

**Gate ID:** `CM-SRCINT-2026-08-23-RELOCATION-001`<br>
**Hazard record:** `primary-repo-icloud-stale-source-hazard`<br>
**Audit provenance ruling:** `CM-GOV-2026-08-23-AUDIT-PROVENANCE-001`<br>
**Decision:** **REQUIRED BEFORE AUDIT RECOVERY; CUTOVER NOT YET STARTED**<br>
**Current protection:** fresh detached local-disk clone discipline remains mandatory

## 1. Why this is a release-integrity gate

The old primary checkout is under the iCloud-managed `~/Documents` tree. The file-provider identity was reproduced as `com.apple.CloudDocs.iCloudDriveFileProvider/39E3E824-50F9-4613-A188-FF134EB37DAA`. The 20-Aug incident record shows that Git could exit successfully without refreshing the checkout, leaving roughly fifteen merged PRs of silent source drift. A production trace was consequently performed against pre-fix code before a discriminating negative exposed the mistake.

This is not ordinary workstation housekeeping. It creates two direct failure modes:

1. an audit finding can be “fixed” or verified against source that is not the source intended for release; and
2. a working-directory deployment can publish stale bytes even when the operator believes the checkout is current.

Process armour has prevented a known recurrence: obtain the intended/deployed commit identity independently of the old local refs, create a fresh detached clone on local disk, prove the object exists, and bind the source with a discriminating marker. That armour remains compulsory, but it depends on perfect operator discipline and is not permanent closure.

The completed audit-provenance review demonstrates the distinction. The principal code audit used clean pinned bytes outside the old checkout and survives; bounded local-topology claims required correction. This prevents a wasteful full rerun, but it also proves why every future source-bearing conclusion must log its exact path, commit, tree, cleanliness, and selection rationale.

## 2. Reproduced current state

| Check | Reproduced result |
|---|---|
| Old primary path | `/Users/turhanacar/Documents/GitHub/CyberMeters-Platform` still exists |
| New primary path | `/Users/turhanacar/dev` does not yet exist |
| Cloud management | `~/Documents` has the iCloud file-provider domain identity above |
| Old root Git state | branch `docs/item5-closure-governance`, behind its recorded upstream by 3; at least `.claude/launch.json` and `docs/security/ENTRY-POINT-INVENTORY.md` modified |
| Instrument health | status indexing itself returned `Operation timed out` on `.claude/launch.json` |
| Nested project worktrees | 11 directories under `.worktrees/` |
| Registered worktree state | 67 registered in old Git metadata: 53 marked prunable and 14 not marked prunable |
| Path-keyed Claude memory | old-path project memory exists, including the named hazard record |
| Canonical transport ledger | `/Users/turhanacar/cybermeters-ops/transport/index/ledger.jsonl`, sequence 330, SHA-256 `475fd4037dd68c368a5e05cd69f56cd0deff15717fc755189ef2828a49c78d4b` |
| Local ledger copies | dated 22-Aug and 23-Aug copies exist, but both are on `/dev/disk3s5`; the newest contains sequence 327, not current sequence 330 |
| Independent failure-domain backup | not demonstrated |
| Founder-selected backup target | founder-owned external disk, to be attached on request during the maintenance boundary; not currently mounted |
| Current transport corpus size | approximately 105 MiB across 3,869 files; small enough for a full transport snapshot rather than ledger-only copying |

The correct backup finding is therefore not “only one ledger file exists.” Multiple local copies exist. The unresolved risk is that the live ledger and dated copies share one machine and one physical failure domain, and the newest reproduced copy lags the current ledger.

## 3. Timing boundary

Do not relocate the repository while E's full gate, a release, a deploy, or another old-path-bound session is running. The declared earliest maintenance boundary is after MERGE 8, the associated release/two-Worker deployment, and MERGE 9 are complete, reconciled, and no process still depends on the old path.

Until that boundary:

- no analysis, implementation, verification, build, or deployment may treat the old primary checkout or its local refs as current;
- every source-bearing job must use a fresh detached clone outside `~/Documents`, independently bind the intended commit, run `git cat-file` object existence checks, and use a discriminating source marker;
- no new worktree or long-lived session may be anchored to the old primary path unless it is strictly necessary to finish an already-running authorised lane;
- any ambiguity about source identity fails closed.
- audit/shame outputs must apply `05-AUDIT-SOURCE-PROVENANCE-ADJUDICATION.md`; the first Claude rebuttal's wrong-repository `F-002` rebuttal and broad source-integrity release are inadmissible.

## 4. Safe cutover procedure

The permanent fix is a verified fresh-clone cutover, not a blind filesystem move of the stale `.git` object store.

1. **Freeze the old path.** Stop creation of new old-path sessions and record every process, branch, worktree, dirty path, unpushed commit, stash, submodule, hook, launch entry, and seat script that refers to it.
2. **Preserve and prepare a later disposition.** Reconcile the 11 nested project worktrees and all 67 registered entries. Record the branch/commit identity and any intended evidence for the 53 entries already marked prunable and for every live entry. This document does not authorise `git worktree prune`, worktree removal, or deletion; those actions require later explicit authority after the inventory is independently reviewed. A live worktree is not disposable merely because it is old.
3. **Resolve dirty root state.** Classify and preserve the two currently observed modified paths and any additional changes found by a healthy clone-side comparison. The old root must not be declared clean merely because indexing times out.
4. **Create the new primary.** Create `/Users/turhanacar/dev/CyberMeters-Platform` as a fresh full clone from the independently confirmed canonical remote. Do not copy the old `.git` directory into it.
5. **Verify repository identity.** Require a complete object/ref check, non-shallow state unless explicitly authorised otherwise, a clean worktree, exact remote identity, independently obtained current commit availability, and a discriminating marker bind.
6. **Replay only intentional local state additively.** Copy/replay reviewed local-only commits or changes into the new clone via explicit verified bundles/patches or fresh branches, each with an identity record. Preserve the source state until cutover acceptance. Do not inherit stale remote-tracking refs or cloud-managed pack files.
7. **Migrate path-keyed operating state.** Copy and hash-verify the Claude project memory into the new path key; update `.claude/launch.json`, seat launchers, workorder templates, scripts, and other active absolute-path references. Preserve the old memory as a read-only archive until acceptance.
8. **Exercise the new path.** Run a fresh-clone/source-bind proof and the non-mutating preflight needed to show that analysis, build, test, and deploy tooling resolve from the new path. No production deployment is authorised by this gate.
9. **Back up the transport corpus independently.** The founder has selected a founder-owned external disk and will attach it when requested at the maintenance boundary. Copy the full `cybermeters-ops/transport` corpus—not only `ledger.jsonl`—plus the dated ledger backup metadata to an encrypted destination on that disk. Record the volume identity, snapshot date, accepted ledger head, file count, byte count, and SHA-256 manifest; verify every transferred file; and complete a restore-to-scratch verification. Do not overwrite the only prior external generation.
10. **Quarantine, then retire.** Keep the old checkout read-only until the new path, memory, launchers, and backup restore all pass. Removal of the old tree is a later explicit destructive action and is not authorised by this document.

## 5. Exit criteria

This gate closes only when all of the following are evidenced on exact identities:

- no active or scheduled source-bearing process resolves through the old `~/Documents/GitHub/CyberMeters-Platform` path;
- every old worktree, dirty path, local-only commit, and memory record has a recorded disposition;
- `/Users/turhanacar/dev/CyberMeters-Platform` is a clean, healthy, independently bound full clone;
- active Claude memory, launch configuration, seat scripts, and workorder templates resolve through the new path;
- stale absolute-path scans have no unexplained active hit;
- a source-bind/build/test preflight from the new path passes without reading the old checkout;
- a current transport ledger snapshot, including sequence 330 or its accepted successor, exists in a physically independent failure domain;
- transferred bytes and a restore-to-scratch run verify successfully; and
- an independent reviewer signs the cutover evidence.

## 6. Fail-closed conditions

The gate remains open if any active job still depends on the old path, a live/dirty worktree is unaccounted, the new clone cannot independently obtain or verify current objects, path-keyed memory is missing, an active launcher retains the old path, the backup is only another directory on `/dev/disk3s5`, the backup lags the accepted ledger head, or restore verification has not passed. Any product-source conclusion without an absolute source path, exact commit/tree, clean-state proof, and drift check receives zero credit. Any use of the old checkout or its refs as current product/build/verification/deploy authority taints that result and requires a fresh-clone rerun. This document grants no prune, worktree-removal, old-tree-deletion, blind-move, or deployment authority.

Until closure, audit-recovery candidate assembly is prohibited. Ongoing authorised GTR and shame preparation may continue only under the fresh-detached-clone armour stated above.

## 7. Ongoing backup cadence

After the initial cutover snapshot passes:

- establish, schedule, monitor, and verify a daily sealed local-ledger snapshot job as short-latency protection; the two existing dated copies do not prove an operating daily schedule and remain in the same failure domain;
- request that the founder attach the selected external disk often enough that no more than seven calendar days elapse between verified external generations;
- write a new dated full-transport generation and verify its manifest on every weekly run;
- take an additional event-driven generation after a major accepted transport/governance milestone or before destructive maintenance rather than waiting for the weekly date;
- retain multiple dated generations subject to measured disk capacity; and
- perform a restore-to-scratch test on the initial generation and periodically thereafter.

The backup job must fail closed if the wrong volume is attached, encryption/access control is absent, the source ledger changes during capture without a consistent snapshot, any checksum fails, or the restored verifier cannot reproduce the recorded head.

If seven calendar days elapse without a new verified external generation, mark the backup gate `DEGRADED/OPEN`. Until a verified generation and required restore check recover it, prohibit destructive maintenance and audit-recovery candidate assembly, progression, and acceptance. Disk absence or a missed verification is not silently carried as a warning.
