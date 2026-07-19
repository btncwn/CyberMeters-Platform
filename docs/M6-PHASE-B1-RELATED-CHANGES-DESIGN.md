# M6 Phase B1 — Deterministic Related Changes (Pre-Public-Beta Design)

> **Status:** design note (no code). Founder-approved scope; read-only parity audit
> evidence embedded. **Last updated:** 2026-07-19. **Author:** Lead Engineer.
>
> This note is the single authoritative design for the pre-beta Related Changes
> feature. It supersedes the loose "correlation across all eight domains" framing.

---

## 0. Phase split (naming lock)

The word "M6 Phase B" was overloaded. Canonical split:

| Phase | Scope | Timing |
|---|---|---|
| **B1 — Deterministic Related Changes** | same-entity + same-window correlation over eligible evidence producers, deterministic rules, evidence pointers, managed feedback, manual case link | **pre-public-beta (this note)** |
| **B2 — Behaviour Baselines & Unusualness** | per-workspace baselines, historical rarity as an *enriching* factor | post-beta, real-data gated |
| **B3 — Statistical / AI Behaviour Intelligence** | statistical anomaly, MSP-wide correlation, AI-explained behaviour | post-revenue, founder-gated |

**Locked founder decision:** *Pre-beta M6 Phase B1 correlates all commercially
important eligible signal families, not merely hostname events. It includes Attack
Surface, Certificates, app-probe/login/admin, Identity Exposure, Email configuration,
one bounded Email sender-behaviour rule, Brand Protection, and independent Shadow IT
evidence. Cyber Essentials Readiness, Website Security summaries and already-derived
aggregate records are outputs, not independent correlation inputs. Correlation requires
meaningful rule pairing, a bounded time window and independent signal families; same
root domain alone is insufficient. The first release supports customer expected/unrelated
feedback and manual case linking, but no automatic case creation or unsupported attack
claims. Full behaviour intelligence (B2/B3) remains post-beta and real-data gated.*

---

## 1. Correct technical model

**We do NOT correlate the eight customer-facing domains.** We correlate the raw
**evidence producers / signal sources**, then MAP the resulting cluster onto the
affected customer-facing Cyber MOT areas.

```
Attack Surface events   ┐
Certificate events      │
Identity events         │
Email-config events     ├─► canonical event adapter ─► canonical entity keys ─►
Brand candidate events  │        (no physical table move)       │
Shadow IT (independent) │                                        ▼
app-probe/login events  ┘                          deterministic correlation rules
                                                                 │
                                                                 ▼
                                                     Related Change Cluster
                                                                 │
                                                                 ▼
                                        Affected customer-facing Cyber MOT areas
                                        (CE Readiness / Website Security = OUTPUTS)
```

**Adapter, not migration.** Sources keep their tables; a read-only adapter projects
them into a common event shape `{ producer_family, entity_key, event_type, direction,
observed_at, source_table, source_record_id, evidence_ref }`.

---

## 2. Substrate audit — what already exists (evidence)

| Producer | Substrate | Change signal already present? | Entity key |
|---|---|---|---|
| Attack Surface | `asset_events` (`exposed_service_detected/_resolved`, asset appear/disappear) | ✅ yes | `hostname` |
| Certificates | `asset_events` (via `cert-events.js`) + `certificate_lifecycle_events` | ✅ yes | `hostname` / SAN |
| **Email config** | **`asset_events`** (`email_dmarc_policy_changed`, `email_spf_changed`, `email_dkim_changed`, written by `posture-events.js`) | ✅ **yes — already event-ified**, keyed by `hostname = root domain` | `domain` |
| Identity | `identity_assets.hostname` (+ `identity_exposure_events`) | ✅ yes | `hostname` |
| Email sender | `email_sender_sources` (`domain`,`source_ip`,`provider_guess`,`first_seen`,`last_seen`) | ✅ new-sender via `first_seen`; **not** in asset_events | `domain` + `sender-source` |
| Brand | `workspace_brand_assets` (`candidate_domain`,`dns_resolves`,`https_available`,`status`,`first_seen`) + `brand_abuse_campaigns` | ✅ yes (dns/https/status transitions) | `brand-target` / `campaign` |
| Shadow IT | `shadow_it_inventory` (`source_table`,`source_type`,`observed_hostnames_json`) | ✅ but derived — see §5 provenance rule | `technology_key` / hostnames |

**Key finding:** Attack Surface + Certificates + Identity + **Email-config** all already
emit change events into ONE stream (`asset_events`) or a hostname/domain-joinable table.
The correlation substrate is ~50–60% present; the correlation *product* layer is not.

---

## 3. Entity model + canonical keys

Two tiers, nested by registrable domain:

- **host tier:** `host:login.example.com` — ASM, certs, identity, app-probe.
- **domain tier:** `domain:example.com` — email config, email sender, DNS.
- **brand tier:** `brand-target:example.com`, `domain:lookalike-example.com`, `campaign:<id>` — brand (separate family; NOT forced onto host tier).

Cross-tier join happens **only** at the registrable domain: `host:login.example.com`
resolves to `domain:example.com`.

### 3a. Registrable-domain resolver — KNOWN LIMITATION (evidence)
`whois-scan.js` has a `UK_SECOND_LEVELS` set (`.co.uk/.org.uk/.ac.uk/…`), so
`app.blackbullbarbers.co.uk → blackbullbarbers.co.uk` is correct. **But it is UK-hardcoded,
not full Public Suffix List** — `.com.au/.co.jp/.com.br/.co.za` etc. would be mis-cut.
- **v1 (UK private beta: cybermeters.com + blackbullbarbers.co.uk): sufficient.**
- **Before any non-UK customer: full-PSL resolver is a bounded prerequisite.** Documented, not a v1 blocker.

---

## 4. Correlation contract (honesty-critical)

A cluster is produced only when ALL hold:

1. **Same entity** (same registrable domain; host events resolved to their domain).
2. **Bounded time window** — deterministic, defined as *same scan or adjacent scans*
   (scans are periodic, not continuous). No statistical windowing.
3. **≥2 INDEPENDENT signal families** — not merely ≥2 events. Three distinct counters:
   - `event_count` (raw)
   - `signal_family_count` (email-config, cert, asset, identity, brand, sender, shadow-it…)
   - `independent_producer_count` (a producer's two events ≠ two producers; a cert seen
     in both `asset_events` and `certificate_lifecycle_events` counts once)
   Rule requires **≥2 independent signal families**.
4. **Meaningful rule pairing** — the pair must match a registered rule (§6), not just co-occur.
5. **Consistent direction** — appeared / changed / degraded (not mixed noise).
6. **No customer "expected/planned" declaration** covering the change.
7. **Minimum evidence completeness** — each contributing signal must itself be
   evidence-complete (reuses the existing completeness/evidence-honesty substrate).

**Same eTLD+1 + same window alone only produces a CANDIDATE**, never a shipped cluster.

---

## 5. Provenance / double-count guards (evidence-backed)

**Shadow IT (from founder):** a Shadow IT observation counts as an independent
corroborating signal **only if** its `source_type` is NOT already represented by another
producer in the cluster. `shadow-it-inventory.js` tags every observation with
`source_table`/`source_type` (`cloud_asset`←workspace_assets, `identity_provider`←identity_assets,
`email_sender`←email_sender_sources, `vendor`, `saas_portal`). So a `cloud_asset` Shadow IT
row is NOT independent when the cluster already has an asset event; only genuinely
independent provenance (`vendor`, `saas_portal`) corroborates.

**Brand (added — same principle, evidence `brand_abuse_campaigns`):** `brand_abuse_campaigns`
already correlates candidates via `linked_domains/linked_ips/shared_certs/shared_favicon_hashes`.
When a candidate belongs to a campaign, **the campaign is the unit** — Related Changes must
consume it, not re-correlate the same shared-cert/IP evidence.

**Derived outputs are NEVER independent inputs:** Cyber Essentials Readiness, Website
Security summary, aggregate scores. Raw HTTP/TLS/header signals may enter; the result maps
back to Website Security as an OUTPUT (no double-count of the same signal).

---

## 6. Candidate rule families (acceptance standard, not a fixed count)

Rules ship **only** when each is: evidence-backed · fixture-proven · ≥2 independent
families · mutation-tested (remove one signal → cluster breaks) · double-count-free ·
honest-language. Number is an output of that bar, not a target (7–8 clean rules expected).

1. New hostname + certificate issuance/change
2. New hostname + login/IdP surface
3. Login/admin surface + certificate change
4. Email-config change (DMARC/SPF/DKIM) + new hostname/certificate on same registrable domain
5. New sender source + SPF/DMARC change (same root-domain window) *(bounded sender rule)*
6. Unapproved technology (independent provenance) + new hostname/certificate
7. Brand candidate + active DNS + HTTP/impersonation evidence
8. Reappeared brand candidate + renewed active evidence

---

## 7. Persistence — `related_changes` (additive migration, next number after 097)

`related_changes` (cluster):
`id, workspace_id, registrable_domain, rule_id, direction, signal_family_count,
independent_producer_count, confidence, completeness, customer_state
(new|expected|unrelated|unexpected_confirmed), first_seen, last_seen, recurrence_count,
linked_case_id (nullable), created_at, updated_at`.

`related_change_evidence` (pointer — NO raw evidence copy):
`id, related_change_id, producer_family, source_table, source_record_id, source_event_type,
entity_key, observed_at, evidence_ref (immutable id/hash where available)`.

Contract: the cluster references evidence by **pointer**; it never copies raw evidence
(prevents drift/duplication). Append-only recurrence, like the rest of the platform.

---

## 8. Surfaces

- **Minimal managed feedback UI** (NOT read-only): view a cluster + its evidence pointers;
  customer actions: **mark expected / mark unrelated / confirm unexpected / add note**.
  These change `customer_state` — the real signal that trains rule quality for B2.
- **Manual case actions:** *Link existing case* and *Create case from related change*
  (user-initiated). **No automatic case or alert creation** in v1.
- **PDF:** short "Related Changes observed in this period" summary section (both PDFs),
  frozen into the snapshot like the rest of the report.

---

## 9. Vocabulary lock (customer-facing)

**Use:** related changes · related evidence · change cluster · observed in the same period ·
may be connected · confirm whether planned.
**Never (without proof):** attack chain · compromise sequence · malicious campaign ·
behavioural threat · incident · anomalous / statistically unusual.

Deterministic decides; wording stays "material / correlated / requires verification".
Change ≠ compromise.

---

## 10. Tests

- Deterministic **code fixtures** (historical event sequences) per rule — kept.
- **Mutation tests:** removing any one contributing signal must break the cluster
  (proves it is genuine multi-source correlation, not coincidence).
- Provenance tests: a derived Shadow IT / campaign-member brand signal must NOT count as
  independent corroboration.
- Tenant-isolation + purge: `related_changes`/`related_change_evidence` are workspace_id
  scoped → must enter `WORKSPACE_PURGE_TABLES` and the isolation matrix (the assurance
  gates will block otherwise — as they did for `workspace_branding`).
- **Dropped:** separate fake-customer onboarding / long test-company programme. Two
  founder-controlled domains + harmless test subdomains suffice for live acceptance.

---

## 11. Known limitations (honest)

- Registrable-domain resolver is UK-multi-level, not full-PSL (§3a) — non-UK needs upgrade.
- v1 email correlation is **configuration-change** (DMARC/SPF/DKIM records) + one bounded
  **sender-source** rule; the full selector/include/provider sender graph is B1.1.
- Correlation is same-entity + same-window; it does not (yet) span related-but-distinct
  entities (that is B2 baseline territory).

---

## 12. Honest effort estimate

| Work | Days |
|---|---|
| design/inventory finalisation | 1–2 |
| adapters + entity keys + rules | 4–7 |
| persistence + API + managed-feedback UI | 3–5 |
| case/PDF integration | 2–3 |
| controlled tests / mutations / regression / migration / deploy | 3–5 |
| **Total** | **~10–17 working days** |

Faster is possible at current velocity, but this note commits to the honest range, not 6.
