// Shared API mock and seeded session for browser checks of the signed-in app.
// Every /api call is answered locally (no network, no real account): a
// workspace with one domain, one completed scan, eight resolved domain states
// covering every chip tone, cases, reports and notifications. Unmocked paths
// answer 404 with a customer-safe body so a page renders its honest error
// state rather than hanging.
export const API_BASE = 'http://127.0.0.1:8787/api'

const now = '2026-10-16T09:12:00.000Z'
export const user = { id: 'usr_e2e', email: 'owner@example.co.uk', name: 'Taylor Owner', plan: 'professional' }
export const workspace = { id: 'ws_e2e', name: 'Black Bull Barbers', role: 'owner', created_at: '2026-07-08T09:00:00.000Z' }
export const domain = { id: 'dom_e2e', domain_id: 'dom_e2e', name: 'blackbullbarbers.co.uk', domain: 'blackbullbarbers.co.uk', verification_status: 'verified', created_at: '2026-07-08T09:05:00.000Z' }
export const scan = { id: 'scan_e2e', scan_id: 'scan_e2e', domain: domain.domain, status: 'completed', score: 82, rating: 'good', scan_quality: 'complete', created_at: '2026-10-16T09:10:00.000Z', completed_at: now }

const D = (domain_key, display_name, state, coverage, summary, extra = {}) => ({
  domain_key, display_name, state, coverage, summary, description: '', finding_count: 0, evidence_count: 1,
  highest_severity: null, limitations: [], evidence_freshness: 'current', last_assessed_at: now, source_scan_id: scan.id, ...extra,
})
export const motDomains = [
  D('email_protection', 'Email Protection', 'provisional', 'partial', "No material issue observed, but this scan's coverage was provisional."),
  D('brand_protection', 'Brand Protection', 'provisional', 'partial', '12 lookalike candidates on the watchlist; none has a DNS result yet.'),
  D('attack_surface', 'Attack Surface', 'evidence_insufficient', 'degraded', 'Some names have no address in DNS. HTTP was not tested for those names.'),
  D('certificates_trust', 'Certificates & Trust', 'assessed_healthy', 'complete', 'Assessed — no material issue observed.'),
  D('cyber_essentials_readiness', 'Cyber Essentials Readiness', 'customer_input_required', 'complete', 'Complete the Cyber Essentials questionnaire to assess readiness.'),
  D('website_security', 'Website Security', 'issue_detected', 'complete', '2 issues detected.', { finding_count: 2, highest_severity: 'medium' }),
  D('identity_exposure', 'Identity Exposure', 'evidence_insufficient', 'partial', 'Inventory evidence: 2 provider relationships, 3 possible identity-facing hostnames. Account compromise and sign-in controls were not evaluated.'),
  D('shadow_it_unmanaged_technology', 'Shadow IT & Unmanaged Technology', 'monitoring_only', 'complete', '14 externally observed technologies/services; compare against your approved inventory in Shadow IT.'),
]
const findings = [
  { id: 'header_missing_strict_transport_security', title: 'HSTS header not sent', severity: 'medium', module: 'headers', finding_type: 'finding', score_impact: -4, confidence: 90, description: 'The site does not tell browsers to insist on HTTPS.', recommendation: 'Send a Strict-Transport-Security header.', evidence: [] },
  { id: 'csp_weak_policy', title: 'Content Security Policy allows inline scripts', severity: 'medium', module: 'headers', finding_type: 'finding', score_impact: -3, confidence: 90, description: 'The policy permits inline script execution.', recommendation: 'Move inline scripts to nonced or hashed sources.', evidence: [] },
]
export const report = {
  scan_id: scan.id, domain: domain.domain, status: 'completed', cyber_metrics_score: 82, score: 82, risk_level: 'good',
  started_at: scan.created_at, completed_at: now, findings, recommendations: [], scan_quality: { status: 'complete', modules_skipped: [] },
  cyber_mot_domains: motDomains, modules: { email_security: { dmarc_state: { enforcement_level: 'quarantine_enforced' } } },
}
export const notifications = (count = 4) => {
  const base = [
    { id: 'n1', type: 'dmarc_policy_changed', severity: 'medium', title: 'DMARC moved to p=quarantine', message: 'Hosted record updated and verified by re-observation.', status: 'unread', created_at: '2026-10-16T07:00:00.000Z', metadata: { domain_key: 'email_protection' } },
    { id: 'n2', type: 'brand_candidate_active', severity: 'high', title: 'New lookalike domain observed', message: 'A lookalike name now resolves; review and classify.', status: 'unread', created_at: '2026-10-15T09:00:00.000Z', metadata: { domain_key: 'brand_protection' } },
    { id: 'n3', type: 'certificate_expiring', severity: 'low', title: 'Certificate expires in 21 days', message: 'Renewal not yet observed.', status: 'unread', created_at: '2026-10-14T09:00:00.000Z', metadata: { domain_key: 'certificates_trust' } },
    { id: 'n4', type: 'scan_completed', severity: 'info', title: 'Scheduled assessment finished', message: '3 new hostnames, 0 new exposed services.', status: 'read', created_at: '2026-10-13T09:00:00.000Z', metadata: { domain_key: 'attack_surface', scan_id: scan.id } },
  ]
  const extra = Array.from({ length: Math.max(0, count - base.length) }, (_, i) => ({
    id: `n${i + 10}`, type: 'scan_completed', severity: ['medium', 'low', 'info', 'high'][i % 4], title: `Scheduled assessment finished (${i + 1})`,
    message: 'Changes between scans are listed on the Attack Surface timeline.', status: i % 3 ? 'read' : 'unread',
    created_at: new Date(Date.UTC(2026, 9, 12 - (i % 10), 9)).toISOString(), metadata: { domain_key: 'attack_surface' },
  }))
  const list = [...base, ...extra]
  return { workspace_id: workspace.id, unread_count: count >= 30 ? 120 : 3, count: list.length, notifications: list }
}
export const cases = { cases: [
  { id: 'case_1', case_type: 'website_case', domain_key: 'website_security', domain: domain.domain, finding_id: 'header_missing_strict_transport_security', title: 'Send the HSTS header', severity: 'medium', status: 'assigned', owner_ref: 'Taylor Owner', canonical_phase: 'assigned', verification_support: 'automated', owner_type: 'customer_it', created_at: '2026-10-10T09:00:00.000Z', updated_at: now },
  { id: 'case_2', case_type: 'email_case', domain_key: 'email_protection', domain: domain.domain, finding_id: 'email_dmarc_policy_none', title: 'Move DMARC to enforcement', severity: 'high', status: 'awaiting_verification', canonical_phase: 'awaiting_verification', verification_support: 'automated', owner_type: 'customer_it', created_at: '2026-10-01T09:00:00.000Z', updated_at: now },
  { id: 'case_3', case_type: 'certificate_case', domain_key: 'certificates_trust', domain: domain.domain, finding_id: 'certificate_expiring_soon', title: 'Renew the certificate', severity: 'medium', status: 'verified', canonical_phase: 'verified', verification_support: 'automated', owner_type: 'customer_it', created_at: '2026-09-20T09:00:00.000Z', updated_at: now },
] }
export const reports = { reports: [
  { id: 'rep_1', workspace_id: workspace.id, report_type: 'scan_snapshot', report_period: 'scan-v2-scan_e2e-snap_1-0123456789abcdef0123456789abcdef', status: 'completed', generated_at: now, created_at: scan.created_at },
  { id: 'rep_2', workspace_id: workspace.id, report_type: 'monthly_executive', report_period: '2026-09', status: 'completed', generated_at: '2026-10-01T06:00:00Z', created_at: '2026-10-01T06:00:00Z' },
] }

const json = (body, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })

export const shadowItInventory = {
  items: ['Mailchimp', 'Typeform', 'Calendly', 'Trello', 'Hotjar', 'Intercom'].map((name, i) => ({
    inventory_item_id: `inv_${i}`, display_name: name, category: 'saas_tool', classification: 'unreviewed',
    monitoring_status: 'observed', last_seen_at: '2026-10-16T08:00:00Z',
  })),
  counts: { unreviewed: 6, approved: 0, rejected: 0, exception: 0, retired: 0 },
  // A manager's view: classification is offered where each item is listed.
  actions: ['approve', 'reject', 'mark_exception'],
  can_manage: true,
}
export const ceAnswers = {
  questions: [{ control_key: 'firewalls', label: 'Firewalls', questions: [
    { key: 'fw_boundary', text: 'Do you have a boundary firewall?', label: 'Do you have a boundary firewall?', question: 'Do you have a boundary firewall?' },
    { key: 'fw_default_pw', text: 'Have default firewall passwords been changed?', label: 'Have default firewall passwords been changed?', question: 'Have default firewall passwords been changed?' },
  ] }],
  answers: {},
}

export async function installAppMock(page, { notificationCount = 4 } = {}) {
  await page.route(`${API_BASE}/**`, (route) => {
    const u = new URL(route.request().url())
    const p = u.pathname.replace(/^\/api/, '')
    const m = route.request().method()
    if (p === '/auth/me') return route.fulfill(json(user))
    if (p === '/workspaces' && m === 'GET') return route.fulfill(json({ workspaces: [workspace], default_workspace_id: workspace.id }))
    if (p === '/account/usage') return route.fulfill(json({ plan: 'professional', features: ['scheduled_scans', 'alerts', 'pdf_reports'], usage: {}, limits: {} }))
    if (p === `/workspaces/${workspace.id}/domains`) return route.fulfill(json({ domains: [domain] }))
    if (p === '/scans' && u.searchParams.get('workspace_id') === workspace.id) return route.fulfill(json({ scans: [scan] }))
    if (p === `/workspaces/${workspace.id}/security-domains`) return route.fulfill(json({ workspace_id: workspace.id, source_scan_id: scan.id, cyber_mot_domains: motDomains }))
    if (p === `/scans/${scan.id}/report`) return route.fulfill(json(report))
    if (p === `/scans/${scan.id}`) return route.fulfill(json({ scan, report_availability: { status: 'report_ready' } }))
    if (p.endsWith('/cases')) return route.fulfill(json(cases))
    if (p === `/workspaces/${workspace.id}/reports`) return route.fulfill(json(reports))
    if (p === `/workspaces/${workspace.id}/scheduled-reports`) return route.fulfill(json({ scheduled_reports: [] }))
    if (p.includes('/notifications')) return route.fulfill(json(notifications(notificationCount)))
    // Area pages (PR-C): Shadow IT with six unclassified items, Identity empty, CE unanswered.
    if (p === `/workspaces/${workspace.id}/shadow-it/inventory`) return route.fulfill(json(shadowItInventory))
    if (p === `/workspaces/${workspace.id}/certificates`) return route.fulfill(json({ certificates: [] }))
    if (p === `/workspaces/${workspace.id}/certificates/timeline`) return route.fulfill(json({ timeline: [] }))
    if (p === `/workspaces/${workspace.id}/identity-surfaces`) return route.fulfill(json({ items: [], counts: {} }))
    if (p === `/workspaces/${workspace.id}/cyber-essentials/answers`) return route.fulfill(json(ceAnswers))
    if (p === `/workspaces/${workspace.id}/cyber-essentials-readiness`) return route.fulfill(json({ status: 'not_assessed', self_assessment: { controls: [] } }))
    return route.fulfill(json({ error: 'Not available in this check.' }, 404))
  })
}

export async function seedSession(context) {
  await context.addInitScript(({ user, workspace }) => {
    localStorage.setItem('cybermeters_auth_token', 'token_e2e')
    localStorage.setItem('cybermeters_auth_user', JSON.stringify(user))
    localStorage.setItem('cybermeters_workspace_id', workspace.id)
    localStorage.setItem('cybermeters_workspace_name', workspace.name)
  }, { user, workspace })
}
