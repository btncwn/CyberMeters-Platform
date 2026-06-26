# CyberMeters AI Development Rules

These rules apply to every AI-assisted engineering task on CyberMeters.

Before writing code, every AI engineer must read and follow:

- docs/01-ENGINEERING-CONSTITUTION-v2.md
- docs/02-PRODUCT-CONSTITUTION-v1.md
- docs/03-CYBERMETERS-PHILOSOPHY.md
- docs/04-SECURITY-PLAYBOOK.md
- docs/05-PRODUCT-ROADMAP.md

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

