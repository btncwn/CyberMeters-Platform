# Founder Manual Production Acceptance Package

Status: **NO acceptance below has been executed. Nothing here is PASS.** This document is the checklist for founder-controlled manual production acceptance of four engineering-complete deliverables. Use founder-owned workspaces/domains only; every step is side-effect-safe or founder-triggered.

Engineering baselines (all deployed): Brand PR-A/B/C (`v2026.07.20-1..3`), Shadow IT Alert Trust (`v2026.07.20-4/-5`), Weekly Digest Truth (`v2026.07.20-6`), trust & UX closure (`v2026.07.20-7`). Current live Worker at time of writing: `b6b52726`.

## 1. Brand Protection (PR-A/B/C chain)

Controlled scenario: a founder-owned lookalike of a founder domain (register or reuse a harmless controlled domain — never a live suspicious domain).

- [ ] TLD-substitution candidate generated for the monitored domain (PR-A output present).
- [ ] Credential-themed nested hostname on the controlled lookalike is discovered passively via CT (PR-B; e.g. a `login.`/`password.`-style host on the controlled cert) — `ct_observed`, HIGH not critical while DNS-dead.
- [ ] After the hourly `brand_dns` tick: DNS tri-state moves to live for the controlled host.
- [ ] After the 04:00 UTC `http_enrichment` tick: `https_available` set; a real login form on the controlled page yields live `looks_like_login`.
- [ ] DNS-live + HTTPS + login-form candidate is priority **critical**; without the login form it stays high.
- [ ] Wording throughout is evidence-bounded (no "malicious", no takedown claims the product didn't make).
- [ ] Re-running scans does not duplicate the candidate (dedupe) and does not flood alerts.
- [ ] A second founder workspace cannot see the candidate (tenant isolation).

## 2. Shadow IT Alert Trust

Controlled scenario: in a founder workspace with exactly one monitored domain, take an **approved** inventory item and clear its owner (or approve an unowned one). Wait for the hourly evaluator.

- [ ] One email arrives; Workspace shows the workspace **name** (never the UUID).
- [ ] "Affected Service: <name>" — the service is never labelled a domain; "Monitored Domain" is a separate row.
- [ ] "What Changed" states the approved-service-without-owner fact; "Recommended Next Action" instructs owner assignment — two different sentences; no sanction-review wording; nothing implies unauthorised/malicious.
- [ ] "How this was observed" shows the bounded evidence (e.g. Content-Security-Policy source) with no internal table names.
- [ ] Footer is Shadow IT & Unmanaged Technology (not ASM).
- [ ] CTA opens `/ws/shadow-it?item=<id>` in the digest workspace, highlights the item; in-app bell card carries the same link and a distinct recommendation line.
- [ ] The next unchanged evaluator pass sends nothing (suppression/dedupe).

## 3. Weekly Digest Truth

Observe the next real Monday digest on founder workspaces (do not trigger sends manually).

- [ ] Headline counts **distinct** changes; a condition observed by several scans appears once, optionally "(observed N times this week)"; no repeated identical rows.
- [ ] A workspace with a completed `complete`-quality scan and no changes gets the honest "all quiet / stable" wording.
- [ ] A workspace with only partial or no completed scans gets "No completed assessment was available for this digest period…" — never "stable".
- [ ] CTA opens `/exposure?ws=<digest workspace>` — the digest's own workspace, even if another was last selected.
- [ ] Exactly one digest per workspace for the ISO week.

## 4. A6 Related Changes Phase 2

Controlled scenario (founder-executed, not automated): create founder-owned `status.cybermeters.com` as a harmless Cloudflare Pages surface with its own certificate, then run/await a scan. Engineering for the scenario is already regression-proven (`new_host_with_cert` rule, 47-check suite).

- [ ] A Related Change cluster appears with rule `new_host_with_cert` on cybermeters.com.
- [ ] Both expected signal families are present: Attack Surface (new host) and Certificates & Trust (new certificate).
- [ ] Evidence pointers link to the underlying observations; no internal storage names shown.
- [ ] Explanation carries the honest causality note ("correlated observations that may be connected. Change is not compromise") — correlation is never presented as proven causation.
- [ ] "Confirm whether planned" review works for a manager; a viewer sees no review/case controls (read-only note instead).
- [ ] Linking/creating a managed case works and the linked case renders as a working link to the case detail.
- [ ] Re-scanning does not mint a second cluster (occurrence dedupe) and produces no alert flood.
- [ ] Rollback safety: no migration was required by any of this; Worker rollback IDs are in `CHANGELOG.md` per release.

## After acceptance

Record PASS/FAIL per section in `CHANGELOG.md` with dates and evidence. Only after all four PASS may the corresponding public-beta blockers be marked cleared. Remaining non-engineering gates: legal/contracting-entity closure, pricing lockstep (M7), founder acceptance testing, final public-beta gate.
