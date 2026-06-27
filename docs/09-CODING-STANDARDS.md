# CyberMeters Coding Standards v1.0

## Philosophy

Write code for the next engineer.

That engineer may be another AI or a human.

---

# General Principles

Prefer:

- Simple
- Readable
- Maintainable
- Explicit
- Reusable

Avoid:

- Clever code
- Deep nesting
- Duplication
- Large rewrites
- Premature abstraction

---

# Existing Code

Improve existing code before creating new code.

Search before building.

Reuse before rewriting.

---

# Architecture

Respect the existing architecture.

Do not introduce new patterns unless there is a clear benefit.

---

# Naming

Use clear, descriptive names.

Avoid abbreviations unless industry standard.

Consistency is more important than personal preference.

---

# Functions

Functions should have one responsibility.

Keep them small.

Avoid hidden side effects.

---

# Comments

Comment why.

Do not comment what obvious code already explains.

---

# Error Handling

Handle errors gracefully.

Never leak sensitive information.

Log useful diagnostics.

---

# Security

Never trust input.

Validate everything.

Encode output.

Protect authentication.

Protect authorization.

Protect tenant isolation.

---

# Performance

Optimise when necessary.

Measure before optimising.

Readability comes first.

---

# Git

Small commits.

Clear commit messages.

One logical change per commit.

---

# Final Rule

The best code is not the most clever.

The best code is the code that future engineers immediately understand.
