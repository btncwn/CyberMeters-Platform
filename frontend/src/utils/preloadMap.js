/**
 * Maps sidebar and application route paths directly to their dynamic Vite lazy imports.
 * This lets the hover preloader cleanly fetch files before React Router switches views.
 */
export const routePreloadMap = {
  // Primary Services
  '/ws/email-protection': () => import('../pages/ws/WorkspaceEmailProtectionPage'),
  '/ws/brand-monitoring': () => import('../pages/ws/BrandMonitoringPage'),
  '/assets': () => import('../pages/AssetsPage'),
  '/ws/certificates': () => import('../pages/ws/CertificatesPage'),

  // Sub-items & Tools
  '/scans': () => import('../pages/ScansPage'),
  '/schedules': () => import('../pages/SchedulesPage'),
  '/ws/admin-surfaces': () => import('../pages/ws/AdminSurfacesPage'),
  '/ws/cloud-assets': () => import('../pages/ws/CloudAssetsPage'),
  '/ws/saas-exposure': () => import('../pages/ws/SaasExposurePage'),
  '/ws/third-parties': () => import('../pages/ws/ThirdPartiesPage'),
  '/ws/reports': () => import('../pages/ws/WorkspaceReportsPage'),

  // Secondary Tools Dropdown
  '/ws/domains': () => import('../pages/ws/WorkspaceDomainsPage'),
  '/ws/scorecard': () => import('../pages/ws/WorkspaceScorecard'),
  '/ws/executive-dashboard': () => import('../pages/ws/WorkspaceExecutiveDashboard'),
  '/ws/audit-log': () => import('../pages/ws/WorkspaceAuditLogPage'),
  '/ws/members': () => import('../pages/ws/WorkspaceMembersPage'),
  '/ws/cases': () => import('../pages/ws/WorkspaceCasesPage'),
  '/ws/related-changes': () => import('../pages/ws/WorkspaceRelatedChangesPage'),
  '/ws/retention': () => import('../pages/ws/WorkspaceRetentionPage'),
  '/account': () => import('../pages/AccountPage'),
};
