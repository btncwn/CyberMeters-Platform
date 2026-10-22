import { scan, domain } from './app-mock.js'

// Every customer route of the signed-in app, against the local API mock. One
// list for the contrast pass and the 390px mobile + accessibility pass.
export const APP_ROUTES = [
  '/dashboard', '/onboarding', '/portfolio', '/portfolio/risk', '/portfolio/domains', '/workspaces',
  `/workspaces/${'ws_e2e'}`, '/intelligence', '/scans', '/scans/new', `/scans/${scan.id}`, `/domain/${domain.domain}/history`,
  '/assets', '/exposure', '/reports', '/schedules', '/accuracy', '/account', '/account/company', '/account/mcp', '/account/security', '/account/notifications', '/account/billing', '/ws/active-checks/permission',
  '/account/privacy', '/billing', '/ws/domains', '/ws/scorecard', '/ws/third-parties', '/ws/saas-exposure',
  '/ws/shadow-it', '/ws/cloud-assets', '/ws/admin-surfaces', '/ws/certificates', '/ws/certificates/lifecycle',
  '/ws/website-security', '/ws/identity-exposure', '/ws/brand-monitoring', '/ws/identity-assets', '/ws/email-protection',
  '/ws/reports', '/ws/executive-dashboard', '/ws/business-risk', '/ws/cyber-essentials', '/ws/audit-log',
  '/ws/members', '/ws/cases', '/ws/cases/case_1', '/ws/related-changes', '/ws/alerts', '/ws/retention', '/guide', '/academy',
  '/notifications',
]
