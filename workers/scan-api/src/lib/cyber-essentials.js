// ── Cyber Essentials Readiness — questionnaire + merge logic ─────────────────
// Cyber Essentials readiness = PARTIALLY-verified, transparently-labelled.
// HONEST BOUNDARY: we can corroborate answers ONLY for controls with an
// externally-observable footprint (boundary/secure-config/patch — partial).
// Internal controls (access control / MFA, endpoint malware protection) have
// NO external footprint → they stay pure self-attestation, clearly labelled as
// such. We never call self-attested answers "verified". Where an external scan
// contradicts an optimistic answer on an observable control, we flag it — that
// contradiction, plus honest per-control evidence labelling, is the edge over
// pure-questionnaire and pure-scanner tools. Readiness/gap only, not certification.
//
// Question wording authored for the current IASME control set; keep in sync if
// IASME revises it. control_key mirrors cyberEssentialsCategory() in index.js.

export const CE_QUESTION_SET_VERSION = "2026-07";

export const CE_QUESTIONS = [
  { control_key: "boundary_protection", external_coverage: "partial", label: "Firewalls & Boundary Protection", questions: [
    { key: "default_inbound_block", text: "Do all business devices reach the internet through a router/firewall that blocks unwanted inbound access by default?", why: "A firewall between your business and the internet is one of the five Cyber Essentials controls." },
    { key: "open_services_documented", text: "Are any open inbound services documented with a clear business reason?", why: "Unnecessary open access increases risk and should not exist without a genuine need." },
    { key: "boundary_default_creds", text: "Have default admin passwords been changed on routers, firewalls and internet-facing services?", why: "Default passwords are one of the easiest ways for attackers to get in." },
    { key: "admin_pages_protected", text: "Are firewall/router admin pages blocked from public internet access unless there is a controlled business need?", why: "Management interfaces should not be casually reachable from outside." },
  ]},
  { control_key: "secure_configuration", external_coverage: "partial", label: "Secure Configuration", questions: [
    { key: "default_passwords_changed", text: "Have default passwords been changed on laptops, cloud services and business applications?", why: "Secure configuration means systems are set up safely, not left in risky defaults." },
    { key: "unused_removed", text: "Are unused apps, services, browser extensions and accounts removed when no longer needed?", why: "Fewer unnecessary parts means fewer opportunities for compromise." },
    { key: "device_hardening", text: "Are staff devices set with screen lock, encryption where available and automatic updates?", why: "Basic device settings reduce the chance a lost device becomes an incident." },
    { key: "asset_inventory", text: "Do you keep a basic list of business devices and important cloud services?", why: "You cannot secure what you do not know you use." },
  ]},
  { control_key: "access_control", external_coverage: "none", label: "User Access Control", questions: [
    { key: "mfa_enabled", text: "Is multi-factor authentication enabled for important cloud services (Microsoft 365, Google Workspace, accounting, CRM, admin portals)?", why: "MFA reduces the risk of password-only compromise." },
    { key: "admin_separation", text: "Do admins use separate admin accounts rather than admin privileges for everyday email/browsing?", why: "Separating admin activity limits damage if a working account is compromised." },
    { key: "joiner_leaver_process", text: "Are new starters, leavers and role changes handled with a clear access process?", why: "Old or excessive access creates avoidable risk." },
    { key: "least_privilege", text: "Are staff given access only to the systems and data they need for their role?", why: "Least-privilege limits mistakes, misuse and the impact of compromise." },
  ]},
  { control_key: "malware_protection", external_coverage: "none", label: "Malware Protection", questions: [
    { key: "endpoint_av_enabled", text: "Do all business laptops and desktops have malware protection enabled?", why: "Malware protection is one of the five Cyber Essentials controls." },
    { key: "av_auto_update", text: "Is malware protection kept up to date automatically?", why: "Outdated protection may miss newer threats." },
    { key: "software_install_control", text: "Are users prevented from installing unapproved software where practical?", why: "Limiting unapproved software reduces the chance of malicious tools being installed." },
    { key: "mobile_protection", text: "Are mobile devices protected via approved app stores, device settings or management controls?", why: "Phones and tablets often hold business email and customer data." },
  ]},
  { control_key: "patch_management_readiness", external_coverage: "partial", label: "Security Update Management", questions: [
    { key: "auto_updates", text: "Are operating systems, browsers and business apps set to update automatically where possible?", why: "Updates prevent criminals using known software vulnerabilities as a way in." },
    { key: "unsupported_removed", text: "Do you remove or replace software/devices that no longer receive security updates?", why: "Unsupported systems become harder to defend as known issues are never fixed." },
    { key: "update_review_process", text: "Do you have a regular process to check important business software is up to date?", why: "Auto-updates help, but someone still needs to confirm nothing is missed." },
    { key: "urgent_patch_process", text: "Are urgent security updates applied quickly when flagged as important?", why: "Known high-risk issues are often exploited because an available fix was not applied." },
  ]},
];

const OPTIMISTIC = new Set(["yes"]);
const GAP_ANSWERS = new Set(["no", "partial"]);

/**
 * Merge measured external signal with self-attestation answers into a readiness
 * view. Measured wins on contradiction.
 * @param {Array<{control_key:string, measured_score:number, measured_gaps:string[]}>} measured
 *        one entry per control (measured_score 0-100; measured_gaps = observed problems)
 * @param {Record<string, Record<string,string>>} answers
 *        { [control_key]: { [question_key]: 'yes'|'partial'|'no'|'unknown' } }
 * @returns {Array<object>} per-control readiness with contradictions flagged
 */
export function mergeReadiness(measured, answers = {}) {
  const measuredByKey = new Map((measured || []).map((m) => [m.control_key, m]));
  return CE_QUESTIONS.map((ctrl) => {
    const m = measuredByKey.get(ctrl.control_key) || { measured_score: null, measured_gaps: [] };
    const ans = answers[ctrl.control_key] || {};
    const answered = ctrl.questions.filter((q) => ans[q.key] && ans[q.key] !== "unknown");
    const selfGaps = ctrl.questions.filter((q) => GAP_ANSWERS.has(ans[q.key]));
    const allOptimistic = ctrl.questions.length > 0 && ctrl.questions.every((q) => OPTIMISTIC.has(ans[q.key]));
    const measuredGaps = Array.isArray(m.measured_gaps) ? m.measured_gaps : [];
    const measuredHasGap = measuredGaps.length > 0 || (typeof m.measured_score === "number" && m.measured_score < 70);

    // The killer feature: claimed OK but observed otherwise.
    const contradiction = allOptimistic && measuredHasGap;

    let readiness;
    if (measuredHasGap) readiness = "gaps";                 // measured wins — not ready
    else if (selfGaps.length > 0) readiness = "gaps";       // self-declared gaps
    else if (answered.length < ctrl.questions.length) readiness = "incomplete";
    else readiness = "ready";

    const externalCoverage = ctrl.external_coverage || "none";
    // Honest evidence status — never label self-attestation as "verified".
    let evidence;
    if (externalCoverage === "none") evidence = "self_attested_only";
    else if (contradiction) evidence = "contradicted_by_scan";
    else if (measuredHasGap) evidence = "externally_confirmed_gap";
    else evidence = "externally_corroborated";

    return {
      control_key: ctrl.control_key,
      label: ctrl.label,
      external_coverage: externalCoverage,
      evidence,
      readiness,
      measured_score: m.measured_score ?? null,
      measured_gaps: measuredGaps,
      self_attestation: { answered: answered.length, total: ctrl.questions.length, gaps: selfGaps.map((q) => q.key) },
      contradiction: contradiction
        ? { message: "Self-assessment says this control is met, but external checks observed a gap. External evidence takes precedence.", measured_gaps: measuredGaps }
        : null,
    };
  });
}
