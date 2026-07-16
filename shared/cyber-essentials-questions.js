// ── Cyber Essentials readiness questionnaire — THE shared question set ───────
//
// This file is the ONE source of the CE questions. Both surfaces import it at BUILD time:
//
//   • the paid/authenticated set  → workers/scan-api/src/lib/cyber-essentials.js re-exports
//     it, so every Worker engine and route keeps its existing import path;
//   • the public self-check page  → frontend/src/pages/CyberEssentialsReadinessPage.jsx
//     imports it directly and adds only its own icons.
//
// It is deliberately PURE DATA: no imports, no React, no Worker bindings. That is what lets
// both sides bundle it, and it is why no new anonymous public API is needed to serve the
// public page its questions — the questions ship in the bundle.
//
// ── WHY THIS EXISTS ──
// The two sets were maintained independently and drifted: 14 of the 20 questions carried a
// DIFFERENT KEY on each side for the same question (`open_services_documented` vs
// `documented_inbound_services`, `endpoint_av_enabled` vs `endpoint_protection_enabled`, …),
// and 4 of the 6 shared keys had different wording. A visitor answering the public check and
// then subscribing was answering a different questionnaire, and nothing could have told us.
//
// ── WHAT THIS IS, AND IS NOT ──
// This is a CyberMeters-authored READINESS set of 20 questions. It is NOT the official IASME
// Cyber Essentials application form, and it must never be presented as one. It is written to
// help a small business understand the five control areas in plain English and see where it
// stands. CyberMeters does not certify Cyber Essentials.
//
// ── KEYS ARE LOAD-BEARING — DO NOT RENAME ──
// `question_key` is persisted in `cyber_essentials_answers`. Renaming a key ORPHANS every
// stored answer for that question. The canonical keys are therefore the ones the paid set
// already stored; the public page was the side that had to move. If a key must ever change,
// that is a data migration, not an edit.
//
// ── VERSIONING ──
// Any wording change to any question requires a CE_QUESTION_SET_VERSION bump. Answers persist
// the version they were given under (`cyber_essentials_answers.question_set_version`, mig
// 092) and KEEP it — an answer to an older wording is evidence about the question that was
// actually asked, and rewriting it would be rewriting history.
export const CE_QUESTION_SET_VERSION = "2026-07-16";

// Provenance for the readiness set. Reviewed against the published IASME control areas on
// the date below; this records WHEN we last looked and WHEN we look again, so "is this still
// current?" has an answer that is not a guess.
export const CE_QUESTION_SET_PROVENANCE = Object.freeze({
  authored_by: "CyberMeters",
  set_type: "readiness_self_check",
  is_official_application_form: false,
  official_set_aligned_on: "2026-07-16",
  review_cadence_months: 6,
  next_review_due: "2027-01-16",
  note: "CyberMeters-authored readiness questions covering the five Cyber Essentials control "
      + "areas in plain English. Not the official IASME application form, and not a "
      + "certification assessment.",
});

// `external_coverage` is the platform's honesty metadata and is AUTHORITATIVE — it is read by
// the readiness scorer (ce-readiness.js) and the managed lifecycle (ce-lifecycle.js) alike.
//   partial → CyberMeters can observe SOME of this control from outside. Never all of it.
//   none    → CyberMeters cannot observe this control at all. Self-attestation only; it is
//             never scored, never banded, and never "Verified by CyberMeters".
export const CE_QUESTIONS = [
  {
    control_key: "boundary_protection",
    external_coverage: "partial",
    label: "Firewalls & Boundary Protection",
    public_title: "Boundary protection",
    description: "Checks whether your business has basic protection between your devices, services and the internet.",
    why: "Firewalls and boundary controls help block unwanted access to business devices, admin pages and services.",
    recommended_action: "Confirm your router, firewall and admin access settings with your IT provider. Remove or restrict any access that is not required.",
    questions: [
      // "router, firewall or built-in security control" — the clearer wording. A small
      // business on a consumer ISP router, or relying on the firewall built into Windows or
      // macOS, still HAS this control; the old "router/firewall" phrasing invited them to
      // answer "no" because they own no box called a firewall.
      { key: "default_inbound_block", text: "Do all business devices connect to the internet through a router, firewall or built-in security control that blocks unwanted inbound access by default?", why: "A firewall between your business and the internet is one of the five Cyber Essentials controls." },
      { key: "open_services_documented", text: "Are any open inbound services documented with a clear business reason?", why: "Unnecessary open access increases risk and should not exist without a genuine need." },
      { key: "boundary_default_creds", text: "Have default admin passwords been changed on routers, firewalls and internet-facing services?", why: "Default passwords are one of the easiest ways for attackers to gain access." },
      { key: "admin_pages_protected", text: "Are firewall or router admin pages protected from public internet access unless there is a clear, controlled business need?", why: "Management pages should not be casually reachable from outside the business." },
    ],
  },
  {
    control_key: "secure_configuration",
    external_coverage: "partial",
    label: "Secure Configuration",
    public_title: "Secure configuration",
    description: "Checks whether devices, accounts and services are set up safely rather than left in risky default settings.",
    why: "Poor default settings, unused services and weak configurations make avoidable cyber incidents more likely.",
    recommended_action: "Review default settings, remove unused services and confirm that business devices follow a standard secure setup.",
    questions: [
      { key: "default_passwords_changed", text: "Have default passwords been changed on laptops, routers, cloud services and business applications?", why: "Secure configuration means systems are set up safely rather than left in risky default states." },
      { key: "unused_removed", text: "Are unused apps, services, browser extensions and accounts removed when they are no longer needed?", why: "The fewer unnecessary parts you run, the fewer opportunities there are for mistakes or compromise." },
      { key: "device_hardening", text: "Are staff devices configured with screen lock, encryption where available and automatic security updates?", why: "Basic device settings reduce the chance that a lost or unattended device becomes a business incident." },
      { key: "asset_inventory", text: "Do you keep a basic list of business devices and important cloud services?", why: "You cannot secure what you do not know you use." },
    ],
  },
  {
    control_key: "access_control",
    external_coverage: "none",
    label: "User Access Control",
    public_title: "Access control",
    description: "Checks whether users only have the access they need and whether important accounts are protected with MFA.",
    why: "Strong access control reduces the damage caused by stolen passwords, compromised accounts or unnecessary admin access.",
    recommended_action: "Enable MFA for important services, separate admin accounts from daily accounts and review user access regularly.",
    questions: [
      { key: "mfa_enabled", text: "Is multi-factor authentication enabled for important cloud services such as Microsoft 365, Google Workspace, accounting tools, CRM and admin portals?", why: "MFA reduces the risk of password-only compromise." },
      { key: "admin_separation", text: "Do admin users have separate admin accounts rather than using admin privileges for everyday email and web browsing?", why: "Separating admin activity reduces the damage if a normal working account is compromised." },
      { key: "joiner_leaver_process", text: "Are new starters, leavers and role changes handled with a clear access process?", why: "Old or excessive access creates avoidable risk." },
      { key: "least_privilege", text: "Are staff only given access to the systems and data they need for their role?", why: "Least privilege limits mistakes, misuse and the impact of compromise." },
    ],
  },
  {
    control_key: "malware_protection",
    external_coverage: "none",
    label: "Malware Protection",
    public_title: "Malware protection",
    description: "Checks whether business devices are protected against malicious software and unapproved installs.",
    why: "Malware protection reduces the chance that a malicious file, link or download turns into a business incident.",
    recommended_action: "Confirm malware protection is enabled and updating on every business device, and limit who can install unapproved software.",
    questions: [
      { key: "endpoint_av_enabled", text: "Do all business laptops and desktops have malware protection enabled?", why: "Malware protection is one of the five Cyber Essentials controls." },
      { key: "av_auto_update", text: "Is malware protection kept up to date automatically?", why: "Outdated protection may miss newer threats." },
      { key: "software_install_control", text: "Are users prevented from installing unapproved software where practical?", why: "Limiting unapproved software reduces the chance of malicious tools being installed." },
      { key: "mobile_protection", text: "Are mobile devices protected via approved app stores, device settings or management controls?", why: "Phones and tablets often hold business email and customer data." },
    ],
  },
  {
    control_key: "patch_management_readiness",
    external_coverage: "partial",
    label: "Security Update Management",
    public_title: "Security update management",
    description: "Checks whether software and devices receive security updates promptly and whether unsupported items are removed.",
    why: "Criminals routinely exploit known vulnerabilities for which a fix already exists.",
    recommended_action: "Turn on automatic updates where possible, replace unsupported software and devices, and apply critical updates within 14 days.",
    questions: [
      { key: "auto_updates", text: "Are operating systems, browsers and business apps set to update automatically where possible?", why: "Updates prevent criminals using known software vulnerabilities as a way in." },
      { key: "unsupported_removed", text: "Do you remove or replace software and devices that no longer receive security updates?", why: "Unsupported systems become harder to defend as known issues are never fixed." },
      { key: "update_review_process", text: "Do you have a regular process to check important business software is up to date?", why: "Auto-updates help, but someone still needs to confirm nothing is missed." },
      // The 14-day expectation, stated. "Applied quickly" is not a standard a business can
      // answer honestly — it invites a yes from anyone who patches eventually. Cyber
      // Essentials expects critical and high-severity updates within 14 days of release, so
      // the question asks the actual question.
      { key: "urgent_patch_process", text: "Are critical or high-severity security updates applied within 14 days of release?", why: "Cyber Essentials expects critical and high-severity updates to be applied within 14 days. Known high-risk issues are exploited precisely because an available fix was not applied." },
    ],
  },
];

// Every question key in the set, flattened. Used by the drift guard and by consumers that
// need to validate a submitted answer key without walking the tree themselves.
export const CE_QUESTION_KEYS = Object.freeze(
  CE_QUESTIONS.flatMap((c) => c.questions.map((q) => `${c.control_key}.${q.key}`)),
);
