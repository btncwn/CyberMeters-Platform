# CyberMeters — Engineering & Production Excellence Roadmap (Track B)

> **The second constitution.** The [Product & Growth Roadmap](CyberMeters-Yol-Haritasi.docx)
> (Track A) answers *"what will we build, and how do we go to market?"*. This
> document answers *"how do we keep it trustworthy, reliable, and operable at
> world-class standard?"*. The two run in parallel; neither is complete without
> the other.
>
> Temmuz 2026 · Internal · Owner: Lead Engineer

---

## 0. The thesis we operate by

Track B's job is to **prove maturity and earn trust** — not to become an
endless polishing list that outranks shipping the product.

Three rules keep it honest:

1. **Track B never blocks a Faz 0 product bet.** The revenue proof (10–15 beta
   users, 3 unconditional "yes I'd pay") comes from Exposure Timeline, MSP
   Portfolio, and the weekly digest — Track A work. Track B keeps the lights on
   and the trust intact while that ships.
2. **Do the risky structural work pre-revenue, on purpose.** Backups, monitoring,
   test harnesses, refactors, incident tooling are cheapest and safest to build
   *now*, at zero stakes, before a paying customer's data and the founder's
   liability are on the line. This is why Track B is already ~80% built.
3. **Sequence by what actually gates the next milestone**, not by a wishlist.
   Most of ChatGPT-style "someday" items (SOC2, chaos testing, KPI dashboards)
   are Faz 1+ — after revenue signal, not before.

Status legend: ✅ done (with evidence) · 🟡 in progress / partial · 🔴 open ·
Owner: **E** = engineering (Claude/Codex) · **F** = founder/human (Turhan).

---

## 1. Engineering Quality & Architecture — ✅ strong

| Item | Status | Evidence |
|---|---|---|
| Monolith → modules | ✅ | 36.3k monolith → 2.2k core + 55 engines + 18 route modules + 13 lib (Phase 1+2 deployed) |
| Code review discipline | ✅ | 4-way model: Codex builds · Claude reviews/integrates · founder decides; every PR reviewed before merge |
| Uniform API contract (errors) | ✅ | `normalizeApiResponseData` — every error `{ error, code, message }`, no `detail`/`stack` leak (`v2026.07.11-2`) |
| Dead code / naming / TODO hygiene | 🟡 (E) | ongoing per-module; success-response envelope `{success,data,meta}` still a Codex task |
| Structured, redacted logging | ✅ | `src/lib/redact.js` + `[request-error]`/`[cron-error]` with request_id |

## 2. Security — Application & SDLC — ✅ strong (one external gap)

| Item | Status | Evidence |
|---|---|---|
| Threat model (STRIDE) | ✅ | `docs/THREAT-MODEL.md` — 16 critical flows |
| OWASP ASVS L2 gap assessment | ✅ | `docs/ASVS-GAP-ASSESSMENT.md` |
| Security playbook | ✅ | `docs/04-SECURITY-PLAYBOOK.md` |
| SAST in CI | ✅ | Semgrep (p/security-audit + p/owasp-top-ten + p/javascript), CI-blocking |
| Cross-tenant isolation tests | ✅ | `validate-tenant-isolation.js` (57), `validate-integration.js` (18) |
| Secret + log redaction | ✅ | secret-scan (CI) + `redact.js` + `sanitizeAuditMetadata` |
| Rate limits fail-closed on cost paths | ✅ | signup/login/MFA/invite/scan; global per-IP guard |
| Dependency audit + SBOM + license policy | ✅ | `npm audit` (0), CycloneDX SBOMs, `validate-licenses.js` (permissive allowlist) |
| Pinned CI action SHAs | ✅ | checkout/setup-node/setup-python/upload-artifact |
| Internal red-team + fix + verify | ✅ | authenticated + black-box passes; findings fixed at root, re-verified vs HEAD |
| **Independent external pentest + retest + letter** | 🔴 (F) | **the one real security gate before commercial scale** |

## 3. Testing & Verification — ✅ strong

| Item | Status | Evidence |
|---|---|---|
| Regression / accuracy fixtures | ✅ | `validate-regression-fixtures.js` (227) |
| Auth / MFA / RBAC / billing contracts | ✅ | `validate-security-contracts.js` (45) |
| Request pipeline (fetch→auth→RBAC→D1) | ✅ | `validate-pipeline.js` |
| Billing entitlement state machine | ✅ | `validate-billing-lifecycle.js` (16) |
| Stripe webhook per-event + idempotency | ✅ | `validate-stripe-events.js` (14) + replay guard in pipeline |
| Email lifecycle + retry | ✅ | `validate-email-lifecycle.js` (21) |
| Cron orchestration + isolation | ✅ | `validate-cron.js` (23) |
| Error contract / ops-health / maintenance | ✅ | `validate-error-contract.js` (116), `validate-ops-health.js` (29), `validate-maintenance-mode.js` (29) |
| Migration additivity + convergence | ✅ | `validate-migrations.js` (79) |
| Purge completeness (tenant delete) | ✅ | `validate-purge-completeness.js` (10) |
| Frontend unit coverage (80%) | ✅ | Vitest coverage gate (focused include), CI-blocking |
| E2E (customer lifecycle) | ✅ | Playwright `customer-lifecycle.spec.js` |
| Load / stress | ✅ (manual) | `scripts/load/` — DMARC parse cost + concurrent HTTP |
| Chaos testing | 🔴 (E) | Faz 1+ — not warranted at current scale |

**18 CI-blocking harnesses** in total. Every security/reliability fix ships with
a regression that locks it in — the core Secure-SDLC principle.

## 4. Operations & Reliability — ✅ strong

| Item | Status | Evidence |
|---|---|---|
| Liveness + readiness probes | ✅ | `/health` + `/ready` (D1+R2) |
| Monitoring (3-layer) | ✅ | `docs/MONITORING.md` — probes · `http_5xx` metric + redacted logs · daily ops-health heartbeat |
| Incident response plan | ✅ | `docs/INCIDENT-RESPONSE-PLAN.md` — SEV1-3, 12 playbooks, break-glass |
| Runbooks | ✅ | incident · backup/restore · release · monitoring |
| Backup + proven restore drill | ✅ | `docs/BACKUP-RESTORE-DRILL.md` — RTO 1.57s, integrity verified |
| Secrets / key rotation runbook | ✅ | INCIDENT-RESPONSE §4 |
| Maintenance mode | ✅ | `MAINTENANCE_MODE` → clean 503, auto-recovering overlay (`v2026.07.12-1`) |
| Disaster recovery (full) | 🟡 (E) | restore drill = foundation; full DR runbook + Option-A staging restore = follow-up |
| **Automated daily backup to off-CF store** | 🔴 (F+E) | founder picks store + creds; engineering wires the job |
| **Cloudflare Notification policy + uptime monitor on `/ready`** | 🔴 (F) | dashboard config — the alerting layer's last mile |

## 5. Release & Change Management — ✅ done

| Item | Status | Evidence |
|---|---|---|
| Manual-deploy discipline | ✅ | Workers Builds disconnected (probe-verified); push ≠ deploy |
| Executable release checklist | ✅ | `docs/07-RELEASE-CHECKLIST.md` v2.0 — risk-tier gate + validation gate + smoke test + rollback |
| Versioned releases + rollback IDs | ✅ | git tags `vYYYY.MM.DD-n` + CHANGELOG with live + rollback Version IDs |
| CI/CD quality gates | ✅ | `validate` + `sast` jobs; merge-blocking |

## 6. Trust & Compliance — 🟡 the weakest pillar (and, for a security vendor, the most leveraged)

A customer's first question in 2026 is *"why should I trust you?"* — and we sell
security, so this pillar earns revenue, not just comfort. Most-leveraged Track B
investment right now.

| Item | Status | Owner |
|---|---|---|
| `security.txt` (RFC 9116) + responsible disclosure | ✅ | E |
| Customer-facing Security page | 🟡 | E — `SecurityPage.jsx` exists; needs the trust content below |
| **Trust Center** (consolidated: security posture, infra, encryption, data residency, subprocessors, availability) | 🔴 | E (build) |
| **Status page** (public uptime) | 🔴 | F (account) + E (wire `/ready`) |
| **Terms / Privacy / Cookie / DPA — legal sign-off + publish** | 🟡 | pages exist (`TermsPage`/`PrivacyPage`/`CookiePolicyPage`/`DpaPage`); **F: solicitor review** |
| **External pen-test letter / summary** | 🔴 | F (after §2 pentest) |
| SOC 2 / ISO 27001 roadmap | 🔴 | Faz 1+ — premature pre-revenue; state the *intent*, don't pursue yet |

## 7. Customer Success & Support — 🟡 partial

| Item | Status | Owner |
|---|---|---|
| Onboarding / first-run | ✅ | `/services` command center + first-run checklist |
| Support entry point | ✅ | Support page + "Contact support" widget |
| Knowledge base / Academy | 🟡 | Academy scaffold exists; content thin |
| Support SLA + ticketing | 🔴 | F (tool) — Faz 1 as first paying customers land |
| Customer health score / feature adoption / NPS | 🔴 | Faz 1+ — needs real users first |

## 8. Observability & Engineering KPIs — 🟡 signals exist, not yet tracked as KPIs

We have the raw signals; we don't yet report them as a dashboard. Lightweight,
using data we already emit — not a new platform.

| KPI | Source we already have | Status |
|---|---|---|
| Deploy frequency / lead time | CHANGELOG + git tags | 🟡 derivable, not charted |
| Rollback rate / MTTR | release history + incident log | 🟡 |
| Availability / error rate | `http_5xx` metric (Analytics Engine) + `/ready` monitor | 🟡 (needs the §4 monitor) |
| Test coverage | Vitest coverage gate + harness counts | ✅ enforced |
| API latency (p50/p95/p99) | `scripts/load/concurrent-requests.js` | 🟡 on-demand |
| Critical vulns / security findings | SAST + audit + SBOM/license | ✅ 0 open |

**Recommendation:** a single `docs/METRICS.md` snapshot updated per release — not
a real-time dashboard — until scale justifies more.

## 9. AI (optional differentiator, Faz 1 — not a gap)

The product roadmap deliberately keeps scope tight; AI is not a Faz 0 blocker.
One cheap, high-leverage option worth holding on the table: an **AI Executive
Report / remediation summary** that turns the MOT findings into plain-English
business language — a genuine MSP differentiator, reusing the Claude access we
already have. Decide in Faz 1, alongside white-label reporting.

---

## 10. Sequencing — what gates what

| Gate | Track B items that must be true | Owner |
|---|---|---|
| **Faz 0 (now) — invite beta** | ✅ already met: monitoring, backups+restore, incident plan, release checklist, test suite, error/trust sanitisation | — |
| **Before taking money (Faz 1)** | External pentest + retest · legal sign-off (Terms/Privacy/DPA) · Trust Center basics + status page | **mostly F** |
| **Faz 1+ (post-revenue signal)** | Support SLA/ticketing · engineering KPI snapshot · success metrics/NPS · full DR runbook · AI exec report | E + F |
| **Faz 2–3 (scale)** | SOC2/ISO roadmap · chaos testing · rate-limit/quota tuning under real MSP load | E + F |

**The honest read:** Track B is *not* the bottleneck to beta — it's largely done.
The bottleneck to **revenue** is three founder-gated items (external pentest,
legal, Trust Center/status) plus the Track A product bets. Engineering's job now
shifts back to Track A (Exposure Timeline → MSP Portfolio → digest), keeping
Track B on the standing cadence below.

## 11. Standing cadence (the part that never ends — but disciplined)

Every sprint, regardless of feature work:
- Review + integrate all changes (no unreviewed merges to main).
- Keep CI green; every fix ships with a regression test.
- Monthly: dependency updates + `npm audit` + SBOM refresh + license check (all automated in CI).
- Per release: run the release checklist; record Version ID + rollback target.
- Quarterly: restore drill re-run (record RTO); revisit ops-health thresholds against real traffic; review the KPI snapshot.
- Annually: external pentest + retest.

---

## Scorecard — document vs reality

ChatGPT scored the *product document* (Track A): Operational Readiness 7.5,
Engineering Excellence 7, Trust 7. Those reflect what was *written there*, not
what is *built*. Grounded in the evidence above:

| Axis | Real state |
|---|---|
| Engineering Quality & Architecture | 9 |
| Security (AppSec/SDLC) | 9 — internal; external pentest is the ceiling |
| Testing & Verification | 9 |
| Operations & Reliability | 9 — pending the alerting last mile (F) |
| Release & Change Management | 9 |
| **Trust & Compliance** | **6** — the real gap, and the highest-leverage next investment |
| Customer Success & Support | 6 — appropriate pre-revenue |
| Observability / KPIs | 7 — signals present, reporting light |

Track B is real, mostly built, and CI-enforced. The remaining work is narrow,
mostly founder-gated, and must not delay the Faz 0 product proof.
