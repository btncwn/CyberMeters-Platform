# Scenario Detection Feasibility Programme — founder-directed investigation

**Status: RECORDED, NOT STARTED.** Founder-directed 28 July 2026 so the question is not lost.
This is an **investigation with a GO/NO-GO gate**, not a commitment to build and not a claim that
any of it works today.

**It does not jump the frozen pre-beta backlog** (`docs/PRE-BETA-EXECUTION-BACKLOG.md`). Like the
candidate pool it is post-backlog work; unlike the candidate pool it evaluates **whole attack
scenarios against the sensors we already have**, rather than proposing new individual signals.

Related: `docs/DETECTION-QUALITY-ROADMAP.md` (the Detection Depth Law this must obey),
`docs/DETECTION-SIGNAL-CANDIDATE-POOL.md` (signal-level research queue — different question).

---

## The question

> With the sensors CyberMeters **already runs**, can we credibly detect a named attack scenario
> **end to end** — and prove it, rather than assert it?

The founder's thesis, which is the reason this is worth investigating: individually weak signals
become a credible scenario claim **when correlated**.

```
Lookalike domain observed
  + certificate issued for it (CT)
  + DNS made active
  + a login form served on it
  = credible impersonation INFRASTRUCTURE

  + a matching inbound email observed
  = phishing DELIVERY observed
```

Each ingredient already exists as a sensor. The programme asks whether the **chain** holds, at
what confidence, and with what false-positive cost.

## The sequence (each step gates the next)

### 1. Complete sensor / evidence inventory — on `origin/main`

For **every** live sensor, record what it actually produces today: the evidence fields, their
declared evidence grade (L0–L5), freshness/cache behaviour, failure modes, and what it provably
CANNOT see. Live probe modules as of this writing: `dns` · `ssl` · `headers` · `email_security` ·
`dmarc_core` · `dmarc_external_rua` · `subdomains` · `technology_detection` · `whois_intelligence` ·
`dns_bruteforce` · `subdomain_takeover` · `asset_exposure` · `cve_intelligence` ·
`known_exploited_vulnerabilities` · `email_security_intelligence` · `cloud_storage_discovery`,
plus derived phases (historical changes, identity correlation) and the Brand/IDN engines.

This inventory is the foundation for Item 19 (source-fidelity) too — **do not duplicate that
work; produce one inventory both consume.**

### 2. Phishing scenario feasibility

Can the chain above be assembled from real evidence, and what does each link actually prove?

**Known hard questions that must be answered honestly, not assumed:**
- **The "matching inbound email" link is the weakest and must be scoped precisely.** Our email
  telemetry is **DMARC RUA aggregate data about mail claiming to be FROM the customer's domain**,
  ingested at `reports.cybermeters.com`. A lookalike domain sending impersonation mail is a
  *different* domain — its traffic does **not** appear in the customer's RUA. RUA sees spoofing of
  the customer's own domain. **So "phishing delivery observed" is only defensible for the
  domain-spoofing variant, not the lookalike variant, unless a separate evidence source is
  identified.** Resolve this before anything is claimed.
- Login-form detection already exists in `brand-http-enrichment.js` (`detectLoginSurface`) — assess
  its true accuracy, not its presence.
- CT gives issuance, not usage. DNS-active gives resolution, not intent.

**Wording law (non-negotiable, from the Detection Depth Law):** `detection ≠ maliciousness`.
"Credible impersonation infrastructure observed" is sayable when the evidence supports it.
"Attack in progress", "phishing campaign", "the attacker" are **not**, absent evidence. Use
"observed / correlated / requires verification", never "confirmed malicious".

### 3. Ransomware entry-path feasibility

Which externally observable precursors do we already capture, and does their combination reach a
defensible statement? Candidate ingredients from existing sensors: exposed admin/remote-access
surfaces (`asset_exposure`), KEV-listed vulnerabilities on exposed services
(`known_exploited_vulnerabilities`, `cve_intelligence`), exposed cloud storage
(`cloud_storage_discovery`), takeover candidates, and certificate/DNS change correlation.

**The honest ceiling must be stated up front:** we see the external attack *surface*, never the
internal compromise. The deliverable is "entry-path exposure", never "ransomware detected".

### 4. Historical backtest

Replay the scenario logic over the evidence we already hold (D1 findings/conditions/events + the
R2 immutable snapshots) and measure what it *would* have said.

**Known constraint — state it, do not hide it:** the corpus is small (≈169 scans, two founder
domains, a few months). That is enough to falsify a scenario ("it would never have fired"), and
NOT enough to establish a rate. Any statistic from this corpus is directional, never a claim.

### 5. False-positive measurement

Not hypothetical — we already have a **proven live false positive** to anchor the method: the
28 July `ssl_not_available` alert that told a domain with a valid GoDaddy certificate to install
one (see `docs/runbooks/` and the Item 14 evidence register). Measure FP rate per scenario link
and for the composite, and record the harm class of each FP (a false accusation on a scenario
claim is more damaging than on a single finding — an evidence-led product loses trust faster to a
false alarm than to a missed finding).

### 6. Founder GO / NO-GO

**GO requires all of:**
- the chain is provable end to end on real evidence (Detection Depth Law: a missing link is
  `PARTIAL` / `FAIL` / `NOT TESTED`, never `PASS`);
- every claim's wording matches its evidence grade;
- the false-positive cost is measured and acceptable;
- the honest ceiling is written into the customer-facing claim before it ships;
- it does not displace the frozen backlog.

**NO-GO is a legitimate, expected outcome** and must be recorded with its reason — exactly as the
M6.0-B viability gate produced a RESCOPE rather than a build. A scenario that cannot be proven is
not a scenario we may market.

## What this programme is NOT

- Not a commitment to build a phishing or ransomware detection feature.
- Not a new (ninth) customer-facing domain — every candidate must fit the existing eight.
- Not a licence to claim scenario-level detection before the GO gate.
- Not a replacement for Item 19 source-fidelity work — it consumes the same inventory.
