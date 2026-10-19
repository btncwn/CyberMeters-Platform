import { lazy, Suspense, useEffect } from 'react'
import { safeInvitationPath } from './lib/invitationFlow'
import { BrowserRouter, Routes, Route, Navigate, useLocation, useParams } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import ChunkErrorBoundary from './components/ChunkErrorBoundary'
import MaintenanceOverlay from './components/MaintenanceOverlay'
import MailtoAssist from './components/MailtoAssist'
import { isPreviewHost, isMarketingHost as isMarketingHostname } from './utils/siteLinks'
import { preloadableLazy } from './lib/preloadableLazy'
import NewVersionBanner from './components/NewVersionBanner'
import PublicPageMeta from './components/PublicPageMeta'
import ProtectedRoute from './components/ProtectedRoute'

// ── Fallback Spinner Component ───────────────────────────────────────────
const RouteLoader = () => (
  <div className="p-8 flex items-center justify-center min-h-[50vh]">
    <div className="w-6 h-6 border-2 border-brand-700 border-t-transparent rounded-full animate-spin" />
  </div>
)

// ── Lazy-Loaded Auth & Public Pages ──────────────────────────────────────
const LoginPage                 = lazy(() => import('./pages/LoginPage'))
const SignupPage                = lazy(() => import('./pages/SignupPage'))
const ForgotPasswordPage        = lazy(() => import('./pages/ForgotPasswordPage'))
const ResetPasswordPage         = lazy(() => import('./pages/ResetPasswordPage'))
const MicrosoftCallbackPage     = lazy(() => import('./pages/MicrosoftCallbackPage'))
const EmailVerificationPage     = lazy(() => import('./pages/EmailVerificationPage'))
const McpConnectPage            = lazy(() => import('./pages/McpConnectPage'))
const McpConnectionsPage        = lazy(() => import('./pages/McpConnectionsPage'))
const PricingPage               = lazy(() => import('./pages/PricingPage'))
const PublicLandingPage         = preloadableLazy(() => import('./pages/PublicLandingPage'))
const CheckoutSuccessPage       = lazy(() => import('./pages/CheckoutSuccessPage'))
const CheckoutCancelPage        = lazy(() => import('./pages/CheckoutCancelPage'))
const TermsPage                 = lazy(() => import('./pages/TermsPage'))
const PrivacyPage               = lazy(() => import('./pages/PrivacyPage'))
const DpaPage                   = lazy(() => import('./pages/DpaPage'))
const CookiePolicyPage          = lazy(() => import('./pages/CookiePolicyPage'))
const SupportPage               = lazy(() => import('./pages/SupportPage'))
const TrustPage                 = lazy(() => import('./pages/TrustPage'))
const AboutPage                 = lazy(() => import('./pages/AboutPage'))
const StatusPage                = lazy(() => import('./pages/StatusPage'))
const InvitationLandingPage     = lazy(() => import('./pages/InvitationLandingPage'))
const FreeScanPage              = preloadableLazy(() => import('./pages/FreeScanPage'))
const CyberEssentialsReadinessPage = lazy(() => import('./pages/CyberEssentialsReadinessPage'))

// ── Lazy-Loaded Core Protected App Pages ─────────────────────────────────
// The signed-in shell is lazy too: it carries the top-bar globe and its map
// data, which the public pages (homepage, free scan) never show but used to
// download before their first paint.
const Layout                    = lazy(() => import('./components/Layout'))
const Dashboard                 = lazy(() => import('./pages/Dashboard'))
const NewScan                   = lazy(() => import('./pages/NewScan'))
const ScanDetail                = lazy(() => import('./pages/ScanDetail'))
const DomainHistory             = lazy(() => import('./pages/DomainHistory'))
const ScansPage                 = lazy(() => import('./pages/ScansPage'))
const AssetsPage                = lazy(() => import('./pages/AssetsPage'))
const ExposureTimelinePage      = lazy(() => import('./pages/ExposureTimelinePage'))
const ReportsPage               = lazy(() => import('./pages/ReportsPage'))
const SchedulesPage             = lazy(() => import('./pages/SchedulesPage'))
const AccuracyPage              = lazy(() => import('./pages/AccuracyPage'))
const WorkspacesPage            = lazy(() => import('./pages/WorkspacesPage'))
const OnboardingPage            = lazy(() => import('./pages/OnboardingPage'))
const WorkspaceDetailPage       = lazy(() => import('./pages/WorkspaceDetailPage'))
const IntelligencePage          = lazy(() => import('./pages/IntelligencePage'))
const PortfolioPage             = lazy(() => import('./pages/PortfolioPage'))
const PortfolioRiskPage         = lazy(() => import('./pages/PortfolioRiskPage'))
const PortfolioDomainsPage      = lazy(() => import('./pages/PortfolioDomainsPage'))
const AccountPage               = lazy(() => import('./pages/AccountPage'))
const AccountPrivacyPage        = lazy(() => import('./pages/AccountPrivacyPage'))
const ThirdPartiesPage         = lazy(() => import('./pages/ws/ThirdPartiesPage'))
const WorkspaceDomainsPage      = lazy(() => import('./pages/ws/WorkspaceDomainsPage'))
const SecurityPage              = lazy(() => import('./pages/SecurityPage'))
const SubscriptionPage          = lazy(() => import('./pages/SubscriptionPage'))
const DomainVerifyPage          = lazy(() => import('./pages/DomainVerifyPage'))
const DomainConnectReturnPage   = lazy(() => import('./pages/DomainConnectReturnPage'))
const AcademyPage               = lazy(() => import('./pages/AcademyPage'))
function LegacyAcademyRedirect() {
  const { slug } = useParams()
  return <Navigate to={`/guide/${slug}`} replace />
}
const GuideEntryPage            = lazy(() => import('./pages/GuideEntryPage'))
const NotificationsPage         = lazy(() => import('./pages/NotificationsPage'))

// ── Lazy-Loaded Workspace Intelligent Subsections ───────────────────────
const WorkspaceScorecard            = lazy(() => import('./pages/ws/WorkspaceScorecard'))
const SaasExposurePage              = lazy(() => import('./pages/ws/SaasExposurePage'))
const ShadowItInventoryPage         = lazy(() => import('./pages/ws/ShadowItInventoryPage'))
const CloudAssetsPage               = lazy(() => import('./pages/ws/CloudAssetsPage'))
const AdminSurfacesPage             = lazy(() => import('./pages/ws/AdminSurfacesPage'))
const CertificatesPage              = lazy(() => import('./pages/ws/CertificatesPage'))
const CertificateLifecyclePage      = lazy(() => import('./pages/ws/CertificateLifecyclePage'))
const WebsiteSecurityPage           = lazy(() => import('./pages/ws/WebsiteSecurityPage'))
const IdentityExposurePage          = lazy(() => import('./pages/ws/IdentityExposurePage'))
const BrandMonitoringPage           = lazy(() => import('./pages/ws/BrandMonitoringPage'))
const WorkspaceIdentityPage         = lazy(() => import('./pages/ws/WorkspaceIdentityPage'))
const WorkspaceEmailProtectionPage  = lazy(() => import('./pages/ws/WorkspaceEmailProtectionPage'))
const WorkspaceReportsPage          = lazy(() => import('./pages/ws/WorkspaceReportsPage'))
const WorkspaceExecutiveDashboard   = lazy(() => import('./pages/ws/WorkspaceExecutiveDashboard'))
const WorkspaceAlertsPage           = lazy(() => import('./pages/ws/WorkspaceAlertsPage'))
const WorkspaceBusinessRiskPage     = lazy(() => import('./pages/ws/WorkspaceBusinessRiskPage'))
const WorkspaceCyberEssentialsPage  = lazy(() => import('./pages/ws/WorkspaceCyberEssentialsPage'))
const WorkspaceAuditLogPage         = lazy(() => import('./pages/ws/WorkspaceAuditLogPage'))
const WorkspaceMembersPage          = lazy(() => import('./pages/ws/WorkspaceMembersPage'))
const WorkspaceCasesPage            = lazy(() => import('./pages/ws/WorkspaceCasesPage'))
const WorkspaceCaseDetailPage       = lazy(() => import('./pages/ws/WorkspaceCaseDetailPage'))
const WorkspaceRelatedChangesPage   = lazy(() => import('./pages/ws/WorkspaceRelatedChangesPage'))
const WorkspaceRelatedChangeDetailPage = lazy(() => import('./pages/ws/WorkspaceRelatedChangeDetailPage'))
const WorkspaceRetentionPage        = lazy(() => import('./pages/ws/WorkspaceRetentionPage'))


// The page a first visit opens on, loaded before the first render (see
// lib/preloadableLazy.jsx). Only the two public pages most visits start on;
// every other route loads lazily as before. Null when there is nothing to wait for.
export function preloadOpeningRoute(hostname, pathname) {
  const path = String(pathname || '/').replace(/\/+$/, '') || '/'
  if (path === '/' && isMarketingHostname(hostname)) return PublicLandingPage.load()
  if (path === '/landing' && isPreviewHost(hostname)) return PublicLandingPage.load()
  if (path === '/free-scan' && !isMarketingHostname(hostname)) return FreeScanPage.load()
  return null
}

function PublicOnlyRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth()
  const location = useLocation()
  if (isLoading) return null
  // A signed-in visitor leaves /login and /signup — for the invitation they came
  // for when there is one (allow-listed path only), otherwise for Overview. Without
  // this, signing in after email verification raced past the invitation (P1).
  if (isAuthenticated) return <Navigate to={safeInvitationPath(location.state?.from) || '/dashboard'} replace />
  return children
}

function isMarketingHost() {
  if (typeof window === 'undefined') return false
  const h = window.location.hostname.toLowerCase()
  return h === 'cybermeters.com' || h === 'www.cybermeters.com'
}

// Marketing host serves only landing/legal/CE-readiness. Auth and app routes
// live on the app subdomain — a react-router <Navigate> cannot cross hosts, so
// without this, links like "Sign in" or "Run your Cyber MOT" on cybermeters.com
// silently bounced back to the landing page via the catch-all route.
function AppHostRedirect() {
  const location = useLocation()
  useEffect(() => {
    window.location.replace(`https://app.cybermeters.com${location.pathname}${location.search}`)
  }, [location])
  return <RouteLoader />
}

// App-host paths reachable from marketing pages or typed by users.
const APP_HOST_PATHS = ['/login', '/signup', '/free-scan', '/pricing', '/dashboard', '/forgot-password', '/reset-password', '/verify-email', '/mcp/connect', '/account/mcp']

function AppRoutes() {
  if (isMarketingHost()) {
    return (
      <Suspense fallback={<RouteLoader />}>
        <Routes>
          <Route path="/"        element={<PublicLandingPage />} />
          <Route path="/privacy" element={<PrivacyPage />} />
          <Route path="/terms"   element={<TermsPage />} />
          <Route path="/dpa"     element={<DpaPage />} />
          <Route path="/cookies" element={<CookiePolicyPage />} />
          <Route path="/support" element={<SupportPage />} />
          <Route path="/trust"   element={<TrustPage />} />
          <Route path="/about"   element={<AboutPage />} />
          <Route path="/status"  element={<StatusPage />} />
          <Route path="/cyber-essentials-readiness" element={<CyberEssentialsReadinessPage />} />
          {APP_HOST_PATHS.map(p => (
            <Route key={p} path={p} element={<AppHostRedirect />} />
          ))}
          <Route path="*"        element={<Navigate to="/" replace />} />
        </Routes>
      </Suspense>
    )
  }

  return (
    <Suspense fallback={<RouteLoader />}>
      <Routes>
        {/* ── Public auth pages ─────────────────────────────────────────── */}
        <Route path="/login" element={<PublicOnlyRoute><LoginPage /></PublicOnlyRoute>} />
        <Route path="/signup" element={<PublicOnlyRoute><SignupPage /></PublicOnlyRoute>} />
        <Route path="/forgot-password"        element={<ForgotPasswordPage />} />
        <Route path="/reset-password"         element={<ResetPasswordPage />} />
        <Route path="/auth/microsoft/callback" element={<MicrosoftCallbackPage />} />
        <Route path="/verify-email"           element={<EmailVerificationPage />} />
        <Route path="/pricing"                element={<PricingPage />} />
        <Route path="/checkout/success"       element={<CheckoutSuccessPage />} />
        <Route path="/checkout/cancel"        element={<CheckoutCancelPage />} />
        <Route path="/billing/success"        element={<CheckoutSuccessPage />} />
        <Route path="/billing/cancel"         element={<CheckoutCancelPage />} />
        <Route path="/terms"                  element={<TermsPage />} />
        <Route path="/privacy"                element={<PrivacyPage />} />
        <Route path="/dpa"                    element={<DpaPage />} />
        <Route path="/cookies"                element={<CookiePolicyPage />} />
        <Route path="/support"                element={<SupportPage />} />
        <Route path="/trust"                  element={<TrustPage />} />
        <Route path="/about"                  element={<AboutPage />} />
        <Route path="/status"                 element={<StatusPage />} />
        <Route path="/invitations/:token"     element={<InvitationLandingPage />} />
        <Route path="/free-scan"              element={<FreeScanPage />} />
        {/* Pull-request previews have no marketing host; show the public page here. */}
        {isPreviewHost() && <Route path="/landing" element={<PublicLandingPage />} />}
        <Route path="/cyber-essentials-readiness" element={<CyberEssentialsReadinessPage />} />
        <Route path="/mcp/connect" element={<ProtectedRoute><McpConnectPage /></ProtectedRoute>} />

        {/* ── Protected app ───────────────────────────────────────────── */}
        <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard"               element={<Dashboard />} />
          {/* /services dissolved (17 Oct 2026): its setup steps live on Overview. */}
          <Route path="services"                element={<Navigate to="/dashboard" replace />} />
          <Route path="onboarding"              element={<OnboardingPage />} />
          <Route path="portfolio"               element={<PortfolioPage />} />
          <Route path="portfolio/risk"          element={<PortfolioRiskPage />} />
          <Route path="portfolio/domains"       element={<PortfolioDomainsPage />} />
          <Route path="workspaces"              element={<WorkspacesPage />} />
          <Route path="workspaces/:id"          element={<WorkspaceDetailPage />} />
          <Route path="intelligence"            element={<IntelligencePage />} />
          <Route path="scans"                   element={<ScansPage />} />
          <Route path="scans/new"               element={<NewScan />} />
          <Route path="scans/:id"               element={<ScanDetail />} />
          <Route path="domain/:domain/history"  element={<DomainHistory />} />
          <Route path="assets"                  element={<AssetsPage />} />
          <Route path="exposure"                element={<ExposureTimelinePage />} />
          <Route path="reports"                 element={<ReportsPage />} />
          <Route path="schedules"               element={<SchedulesPage />} />
          <Route path="accuracy"                element={<AccuracyPage />} />
          {/* /settings merged into /account (17 Oct 2026): one page with sub-tabs. */}
          <Route path="settings"                element={<Navigate to="/account" replace />} />
          <Route path="account"                 element={<AccountPage />} />
          <Route path="account/company"         element={<AccountPage />} />
          <Route path="account/security"        element={<AccountPage />} />
          <Route path="account/notifications"   element={<AccountPage />} />
          <Route path="account/billing"         element={<AccountPage />} />
          <Route path="account/privacy"         element={<AccountPage />} />
          <Route path="account/mcp"             element={<McpConnectionsPage />} />
          <Route path="billing"                 element={<SubscriptionPage />} />
          <Route path="domains/:id/verify"      element={<DomainVerifyPage />} />
          <Route path="domains/verify-return"   element={<DomainConnectReturnPage />} />

          {/* Workspace intelligence subpages */}
          {/* "Workspace administration" dissolved (17 Oct 2026): members at /ws/members,
              the activity feed under the audit log, domains at /ws/domains. */}
          <Route path="ws/dashboard"        element={<Navigate to="/ws/members" replace />} />
          <Route path="ws/domains"          element={<WorkspaceDomainsPage />} />
          <Route path="ws/scorecard"        element={<WorkspaceScorecard />} />
          {/* Third parties is one home (17 Oct 2026); the three old routes redirect. */}
          <Route path="ws/third-parties"    element={<ThirdPartiesPage />} />
          <Route path="ws/vendors"          element={<Navigate to="/ws/third-parties" replace />} />
          <Route path="ws/third-party"      element={<Navigate to="/ws/third-parties" replace />} />
          <Route path="ws/saas-exposure"    element={<SaasExposurePage />} />
          <Route path="ws/shadow-it"        element={<ShadowItInventoryPage />} />
          <Route path="ws/cloud-assets"     element={<CloudAssetsPage />} />
          <Route path="ws/admin-surfaces"   element={<AdminSurfacesPage />} />
          <Route path="ws/certificates"     element={<CertificatesPage />} />
          <Route path="ws/certificates/lifecycle" element={<CertificateLifecyclePage />} />
          {/* Website Security had no route at all until now — mig 089's records were
              written, alerted on, and unreachable. Alert deep links land here as
              /ws/website-security?condition=<id>. */}
          <Route path="ws/website-security" element={<WebsiteSecurityPage />} />
          <Route path="ws/identity-exposure" element={<IdentityExposurePage />} />
          <Route path="ws/brand-monitoring" element={<BrandMonitoringPage />} />
          <Route path="ws/identity-assets"  element={<WorkspaceIdentityPage />} />
          <Route path="ws/email-protection" element={<WorkspaceEmailProtectionPage />} />
          <Route path="ws/reports"              element={<WorkspaceReportsPage />} />
          <Route path="ws/executive-dashboard" element={<WorkspaceExecutiveDashboard />} />
          <Route path="ws/business-risk"       element={<WorkspaceBusinessRiskPage />} />
          <Route path="ws/cyber-essentials"    element={<WorkspaceCyberEssentialsPage />} />
          <Route path="ws/supply-chain"        element={<Navigate to="/ws/third-parties" replace />} />
          <Route path="ws/audit-log"            element={<WorkspaceAuditLogPage />} />
          <Route path="ws/members"              element={<WorkspaceMembersPage />} />
          <Route path="ws/cases"                element={<WorkspaceCasesPage />} />
          <Route path="ws/cases/:caseId"        element={<WorkspaceCaseDetailPage />} />
          <Route path="ws/related-changes"      element={<WorkspaceRelatedChangesPage />} />
          <Route path="ws/related-changes/:id"  element={<WorkspaceRelatedChangeDetailPage />} />
          <Route path="ws/alerts"               element={<WorkspaceAlertsPage />} />
          <Route path="ws/retention"            element={<WorkspaceRetentionPage />} />

          <Route path="guide"               element={<AcademyPage />} />
          <Route path="guide/:slug"         element={<GuideEntryPage />} />
          {/* The Field Guide was the Academy; old links keep working. */}
          <Route path="academy"             element={<Navigate to="/guide" replace />} />
          <Route path="academy/:slug"       element={<LegacyAcademyRedirect />} />
          <Route path="notifications"       element={<NotificationsPage />} />
          <Route path="*"                   element={<Navigate to="/dashboard" replace />} />
        </Route>
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    </Suspense>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ChunkErrorBoundary>
          <AppRoutes />
        </ChunkErrorBoundary>
        <MaintenanceOverlay />
        <MailtoAssist />
        <NewVersionBanner />
        <PublicPageMeta />
      </AuthProvider>
    </BrowserRouter>
  )
}
