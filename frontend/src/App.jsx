import { lazy, Suspense, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import Layout from './components/Layout'
import ChunkErrorBoundary from './components/ChunkErrorBoundary'
import MaintenanceOverlay from './components/MaintenanceOverlay'
import ProtectedRoute from './components/ProtectedRoute'

// ── Fallback Spinner Component ───────────────────────────────────────────
const RouteLoader = () => (
  <div className="p-8 flex items-center justify-center min-h-[50vh]">
    <div className="w-6 h-6 border-2 border-brand-600 border-t-transparent rounded-full animate-spin" />
  </div>
)

// ── Lazy-Loaded Auth & Public Pages ──────────────────────────────────────
const LoginPage                 = lazy(() => import('./pages/LoginPage'))
const SignupPage                = lazy(() => import('./pages/SignupPage'))
const ForgotPasswordPage        = lazy(() => import('./pages/ForgotPasswordPage'))
const ResetPasswordPage         = lazy(() => import('./pages/ResetPasswordPage'))
const MicrosoftCallbackPage     = lazy(() => import('./pages/MicrosoftCallbackPage'))
const EmailVerificationPage     = lazy(() => import('./pages/EmailVerificationPage'))
const PricingPage               = lazy(() => import('./pages/PricingPage'))
const PublicLandingPage         = lazy(() => import('./pages/PublicLandingPage'))
const CheckoutSuccessPage       = lazy(() => import('./pages/CheckoutSuccessPage'))
const CheckoutCancelPage        = lazy(() => import('./pages/CheckoutCancelPage'))
const TermsPage                 = lazy(() => import('./pages/TermsPage'))
const PrivacyPage               = lazy(() => import('./pages/PrivacyPage'))
const DpaPage                   = lazy(() => import('./pages/DpaPage'))
const CookiePolicyPage          = lazy(() => import('./pages/CookiePolicyPage'))
const SupportPage               = lazy(() => import('./pages/SupportPage'))
const TrustPage                 = lazy(() => import('./pages/TrustPage'))
const StatusPage                = lazy(() => import('./pages/StatusPage'))
const InvitationLandingPage     = lazy(() => import('./pages/InvitationLandingPage'))
const FreeScanPage              = lazy(() => import('./pages/FreeScanPage'))
const CyberEssentialsReadinessPage = lazy(() => import('./pages/CyberEssentialsReadinessPage'))

// ── Lazy-Loaded Core Protected App Pages ─────────────────────────────────
const Dashboard                 = lazy(() => import('./pages/Dashboard'))
const NewScan                   = lazy(() => import('./pages/NewScan'))
const ScanDetail                = lazy(() => import('./pages/ScanDetail'))
const DomainHistory             = lazy(() => import('./pages/DomainHistory'))
const ScansPage                 = lazy(() => import('./pages/ScansPage'))
const AssetsPage                = lazy(() => import('./pages/AssetsPage'))
const ExposureTimelinePage      = lazy(() => import('./pages/ExposureTimelinePage'))
const ReportsPage               = lazy(() => import('./pages/ReportsPage'))
const SchedulesPage             = lazy(() => import('./pages/SchedulesPage'))
const SettingsPage              = lazy(() => import('./pages/SettingsPage'))
const AccuracyPage              = lazy(() => import('./pages/AccuracyPage'))
const WorkspacesPage            = lazy(() => import('./pages/WorkspacesPage'))
const OnboardingPage            = lazy(() => import('./pages/OnboardingPage'))
const WorkspaceDetailPage       = lazy(() => import('./pages/WorkspaceDetailPage'))
const IntelligencePage          = lazy(() => import('./pages/IntelligencePage'))
const ServiceLauncher           = lazy(() => import('./components/ServiceLauncher'))
const PortfolioPage             = lazy(() => import('./pages/PortfolioPage'))
const PortfolioRiskPage         = lazy(() => import('./pages/PortfolioRiskPage'))
const AccountPage               = lazy(() => import('./pages/AccountPage'))
const AccountPrivacyPage        = lazy(() => import('./pages/AccountPrivacyPage'))
const SecurityPage              = lazy(() => import('./pages/SecurityPage'))
const SubscriptionPage          = lazy(() => import('./pages/SubscriptionPage'))
const DomainVerifyPage          = lazy(() => import('./pages/DomainVerifyPage'))
const AcademyPage               = lazy(() => import('./pages/AcademyPage'))
const AcademyArticlePage        = lazy(() => import('./pages/AcademyArticlePage'))
const NotificationsPage         = lazy(() => import('./pages/NotificationsPage'))

// ── Lazy-Loaded Workspace Intelligent Subsections ───────────────────────
const WorkspaceDashboard            = lazy(() => import('./pages/ws/WorkspaceDashboard'))
const WorkspaceScorecard            = lazy(() => import('./pages/ws/WorkspaceScorecard'))
const VendorsPage                   = lazy(() => import('./pages/ws/VendorsPage'))
const ThirdPartyPage                = lazy(() => import('./pages/ws/ThirdPartyPage'))
const SaasExposurePage              = lazy(() => import('./pages/ws/SaasExposurePage'))
const ShadowItInventoryPage         = lazy(() => import('./pages/ws/ShadowItInventoryPage'))
const CloudAssetsPage               = lazy(() => import('./pages/ws/CloudAssetsPage'))
const AdminSurfacesPage             = lazy(() => import('./pages/ws/AdminSurfacesPage'))
const CertificatesPage              = lazy(() => import('./pages/ws/CertificatesPage'))
const CertificateLifecyclePage      = lazy(() => import('./pages/ws/CertificateLifecyclePage'))
const BrandMonitoringPage           = lazy(() => import('./pages/ws/BrandMonitoringPage'))
const WorkspaceIdentityPage         = lazy(() => import('./pages/ws/WorkspaceIdentityPage'))
const WorkspaceEmailProtectionPage  = lazy(() => import('./pages/ws/WorkspaceEmailProtectionPage'))
const WorkspaceReportsPage          = lazy(() => import('./pages/ws/WorkspaceReportsPage'))
const WorkspaceExecutiveDashboard   = lazy(() => import('./pages/ws/WorkspaceExecutiveDashboard'))
const WorkspaceAlertsPage           = lazy(() => import('./pages/ws/WorkspaceAlertsPage'))
const WorkspaceBusinessRiskPage     = lazy(() => import('./pages/ws/WorkspaceBusinessRiskPage'))
const WorkspaceCyberEssentialsPage  = lazy(() => import('./pages/ws/WorkspaceCyberEssentialsPage'))
const WorkspaceSupplyChainPage      = lazy(() => import('./pages/ws/WorkspaceSupplyChainPage'))
const WorkspaceAuditLogPage         = lazy(() => import('./pages/ws/WorkspaceAuditLogPage'))
const WorkspaceMembersPage          = lazy(() => import('./pages/ws/WorkspaceMembersPage'))
const WorkspaceRetentionPage        = lazy(() => import('./pages/ws/WorkspaceRetentionPage'))


function PublicOnlyRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth()
  if (isLoading) return null
  if (isAuthenticated) return <Navigate to="/dashboard" replace />
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
const APP_HOST_PATHS = ['/login', '/signup', '/free-scan', '/pricing', '/dashboard', '/forgot-password', '/reset-password', '/verify-email']

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
        <Route path="/status"                 element={<StatusPage />} />
        <Route path="/invitations/:token"     element={<InvitationLandingPage />} />
        <Route path="/free-scan"              element={<FreeScanPage />} />
        <Route path="/cyber-essentials-readiness" element={<CyberEssentialsReadinessPage />} />

        {/* ── Protected app ───────────────────────────────────────────── */}
        <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard"               element={<Dashboard />} />
          <Route path="services"                element={<ServiceLauncher />} />
          <Route path="onboarding"              element={<OnboardingPage />} />
          <Route path="portfolio"               element={<PortfolioPage />} />
          <Route path="portfolio/risk"          element={<PortfolioRiskPage />} />
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
          <Route path="settings"                element={<SettingsPage />} />
          <Route path="account"                 element={<AccountPage />} />
          <Route path="account/security"        element={<SecurityPage />} />
          <Route path="account/privacy"         element={<AccountPrivacyPage />} />
          <Route path="billing"                 element={<SubscriptionPage />} />
          <Route path="domains/:id/verify"      element={<DomainVerifyPage />} />

          {/* Workspace intelligence subpages */}
          <Route path="ws/dashboard"        element={<WorkspaceDashboard />} />
          <Route path="ws/scorecard"        element={<WorkspaceScorecard />} />
          <Route path="ws/vendors"          element={<VendorsPage />} />
          <Route path="ws/third-party"      element={<ThirdPartyPage />} />
          <Route path="ws/saas-exposure"    element={<SaasExposurePage />} />
          <Route path="ws/shadow-it"        element={<ShadowItInventoryPage />} />
          <Route path="ws/cloud-assets"     element={<CloudAssetsPage />} />
          <Route path="ws/admin-surfaces"   element={<AdminSurfacesPage />} />
          <Route path="ws/certificates"     element={<CertificatesPage />} />
          <Route path="ws/certificates/lifecycle" element={<CertificateLifecyclePage />} />
          <Route path="ws/brand-monitoring" element={<BrandMonitoringPage />} />
          <Route path="ws/identity-assets"  element={<WorkspaceIdentityPage />} />
          <Route path="ws/email-protection" element={<WorkspaceEmailProtectionPage />} />
          <Route path="ws/reports"              element={<WorkspaceReportsPage />} />
          <Route path="ws/executive-dashboard" element={<WorkspaceExecutiveDashboard />} />
          <Route path="ws/business-risk"       element={<WorkspaceBusinessRiskPage />} />
          <Route path="ws/cyber-essentials"    element={<WorkspaceCyberEssentialsPage />} />
          <Route path="ws/supply-chain"        element={<WorkspaceSupplyChainPage />} />
          <Route path="ws/audit-log"            element={<WorkspaceAuditLogPage />} />
          <Route path="ws/members"              element={<WorkspaceMembersPage />} />
          <Route path="ws/alerts"               element={<WorkspaceAlertsPage />} />
          <Route path="ws/retention"            element={<WorkspaceRetentionPage />} />

          <Route path="academy"             element={<AcademyPage />} />
          <Route path="academy/:slug"       element={<AcademyArticlePage />} />
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
      </AuthProvider>
    </BrowserRouter>
  )
}
