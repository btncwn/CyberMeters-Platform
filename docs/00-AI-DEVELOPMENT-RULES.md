# CyberMeters AI Development Rules

> **Status: HISTORICAL TECHNICAL REFERENCE — not active governance or
> onboarding.** Current roles, authority and minimum assurance live only in
> `docs/AI-EXECUTIVE-OPERATING-MODEL.md`; current order lives in
> `docs/PRE-BETA-EXECUTION-BACKLOG.md`. `AGENTS.md` / `CLAUDE.md` contain the
> current engineering bootstrap. No session is required to read the former
> six-document chain below, and any conflict loses to the current sources.

---

## Rule 1 — Search Before Building

Do not build anything new until you have verified whether CyberMeters already contains equivalent or partial functionality.

Search for:

- Existing endpoints
- Existing Worker routes
- Existing React components
- Existing database tables
- Existing migrations
- Existing utilities
- Existing scanning engines
- Existing scoring logic
- Existing report generation
- Existing UI pages

If equivalent functionality exists, improve, complete, consolidate, or refactor it instead of creating a duplicate.

---

## Rule 2 — Reuse Before Rewrite

Prefer extending existing code over introducing parallel implementations.

Avoid:

- Duplicate APIs
- Duplicate database tables
- Duplicate scoring engines
- Duplicate report generators
- Duplicate UI components
- Duplicate business logic

---

## Rule 3 — Report Existing Capability First

Before implementation, state one of:

- Already implemented
- Partially implemented
- Requires improvement
- Not implemented

Then explain what will be changed.

---

## Rule 4 — Follow the Current Sprint Only

Only work on the current sprint objective.

Do not introduce unrelated features.

If future work is discovered, document it separately instead of implementing it immediately.

---

## Rule 5 — Smallest Valuable Change

Do not redesign working systems.

Implement the smallest production-safe change that improves:

- Security
- Reliability
- Maintainability
- Performance
- Customer experience

---

## Rule 6 — Constitution Compliance

Every change must comply with the Engineering Constitution, Product Constitution, Philosophy, Security Playbook, and Product Roadmap.

If a requested task conflicts with these documents, stop and explain the conflict before writing code.

---

## Rule 7 — Security First

Every change must preserve or improve CyberMeters security posture.

Do not weaken:

- Authentication
- Authorization
- Workspace isolation
- Tenant isolation
- Session security
- API security
- Logging
- Auditability

---

## Rule 8 — Evidence Required

Do not claim something is fixed without evidence.

At the end of every task provide:

- Files changed
- What was verified
- Tests or checks run
- Remaining risks
- Next recommended action
