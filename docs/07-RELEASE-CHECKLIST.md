# CyberMeters Release Checklist v1.0

## Purpose

Every release must satisfy this checklist before deployment.

No shortcuts.

---

# Product

- Feature matches Product Constitution
- Feature aligns with Roadmap
- No duplicate functionality introduced
- Existing capabilities reviewed before implementation

---

# Engineering

- Code reviewed
- Minimal change set
- No unnecessary complexity
- No dead code introduced
- Consistent naming
- Documentation updated

---

# Security

- Security Playbook followed
- Authentication verified
- Authorization verified
- Tenant isolation verified
- Input validation reviewed
- Secrets protected
- No sensitive information exposed

---

# Testing

- Manual testing completed
- Regression testing completed
- Existing functionality verified
- Edge cases checked
- Error handling verified

---

# Deployment

- Build successful
- Worker deployment successful
- Frontend deployment successful
- Database migrations verified
- Environment variables validated

---

# Validation

- Application loads correctly
- Authentication works
- Dashboard works
- Scanning works
- Reports work
- Billing unaffected
- No console errors
- No API errors

---

# Final Rule

Never deploy code you would not confidently demonstrate to a paying customer.
