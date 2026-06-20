import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import Layout from './components/Layout'
import LoginPage  from './pages/LoginPage'
import SignupPage from './pages/SignupPage'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanDetail from './pages/ScanDetail'
import DomainHistory from './pages/DomainHistory'
import ScansPage from './pages/ScansPage'
import AssetsPage from './pages/AssetsPage'
import ReportsPage from './pages/ReportsPage'
import SchedulesPage from './pages/SchedulesPage'
import SettingsPage from './pages/SettingsPage'
import AccuracyPage from './pages/AccuracyPage'
import WorkspacesPage from './pages/WorkspacesPage'
import WorkspaceDetailPage from './pages/WorkspaceDetailPage'
import IntelligencePage from './pages/IntelligencePage'
import WorkspaceDashboard   from './pages/ws/WorkspaceDashboard'
import WorkspaceScorecard   from './pages/ws/WorkspaceScorecard'
import VendorsPage          from './pages/ws/VendorsPage'
import ThirdPartyPage       from './pages/ws/ThirdPartyPage'
import SaasExposurePage     from './pages/ws/SaasExposurePage'
import CloudAssetsPage      from './pages/ws/CloudAssetsPage'
import AdminSurfacesPage    from './pages/ws/AdminSurfacesPage'
import CertificatesPage     from './pages/ws/CertificatesPage'
import BrandMonitoringPage    from './pages/ws/BrandMonitoringPage'
import WorkspaceIdentityPage  from './pages/ws/WorkspaceIdentityPage'
import WorkspaceReportsPage        from './pages/ws/WorkspaceReportsPage'
import WorkspaceExecutiveDashboard from './pages/ws/WorkspaceExecutiveDashboard'
import WorkspaceBusinessRiskPage   from './pages/ws/WorkspaceBusinessRiskPage'
import WorkspaceCyberEssentialsPage from './pages/ws/WorkspaceCyberEssentialsPage'
import WorkspaceSupplyChainPage    from './pages/ws/WorkspaceSupplyChainPage'
import PortfolioPage         from './pages/PortfolioPage'
import PortfolioRiskPage     from './pages/PortfolioRiskPage'
import AcceptInvitationPage  from './pages/AcceptInvitationPage'
import AccountPage           from './pages/AccountPage'
import BillingPage           from './pages/BillingPage'
import DomainVerifyPage      from './pages/DomainVerifyPage'

/**
 * ProtectedRoute — blocks unauthenticated users from accessing the app.
 *
 * Three states:
 *  1. isLoading  — token exists in localStorage but hasn't been validated yet.
 *                  Show a full-page spinner so protected content never flashes.
 *  2. !isAuthenticated — no token or token was rejected by the server.
 *                  Redirect to /login, preserving the intended path in state.from
 *                  so LoginPage can send the user back after a successful login.
 *  3. Authenticated — render children normally.
 *
 * Does NOT rely on Cloudflare Access identity. Only cybermeters_auth_token
 * in localStorage counts as authentication.
 */
function ProtectedRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="w-8 h-8 border-4 border-brand-600 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  return children
}

/**
 * PublicOnlyRoute — redirects already-authenticated users away from /login and /signup.
 * Waits for session validation to complete before deciding (prevents premature redirect
 * during the initial validateSession() call).
 */
function PublicOnlyRoute({ children }) {
  const { isAuthenticated, isLoading } = useAuth()
  if (isLoading) return null   // wait silently — login page will flash in momentarily
  if (isAuthenticated) return <Navigate to="/dashboard" replace />
  return children
}

function AppRoutes() {
  return (
    <Routes>
      {/* ── Public auth pages (no Layout shell) ─────────────────────────── */}
      <Route
        path="/login"
        element={<PublicOnlyRoute><LoginPage /></PublicOnlyRoute>}
      />
      <Route
        path="/signup"
        element={<PublicOnlyRoute><SignupPage /></PublicOnlyRoute>}
      />

      {/* ── Protected app (with Layout shell) ───────────────────────────── */}
      <Route
        path="/"
        element={<ProtectedRoute><Layout /></ProtectedRoute>}
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard"               element={<Dashboard />}           />
        <Route path="portfolio"               element={<PortfolioPage />}        />
        <Route path="portfolio/risk"          element={<PortfolioRiskPage />}    />
        <Route path="workspaces"              element={<WorkspacesPage />}      />
        <Route path="workspaces/:id"          element={<WorkspaceDetailPage />} />
        <Route path="intelligence"            element={<IntelligencePage />}    />
        <Route path="scans"                   element={<ScansPage />}           />
        <Route path="scans/new"               element={<NewScan />}             />
        <Route path="scans/:id"               element={<ScanDetail />}          />
        <Route path="domain/:domain/history"  element={<DomainHistory />}       />
        <Route path="assets"                  element={<AssetsPage />}          />
        <Route path="reports"                 element={<ReportsPage />}         />
        <Route path="schedules"               element={<SchedulesPage />}       />
        <Route path="accuracy"                element={<AccuracyPage />}        />
        <Route path="settings"                element={<SettingsPage />}        />
        <Route path="account"                 element={<AccountPage />}          />
        <Route path="billing"                 element={<BillingPage />}          />
        <Route path="domains/:id/verify"      element={<DomainVerifyPage />}     />
        <Route path="invitations/:token"      element={<AcceptInvitationPage />} />
        {/* Workspace intelligence pages */}
        <Route path="ws/dashboard"        element={<WorkspaceDashboard />}  />
        <Route path="ws/scorecard"        element={<WorkspaceScorecard />}  />
        <Route path="ws/vendors"          element={<VendorsPage />}         />
        <Route path="ws/third-party"      element={<ThirdPartyPage />}      />
        <Route path="ws/saas-exposure"    element={<SaasExposurePage />}    />
        <Route path="ws/cloud-assets"     element={<CloudAssetsPage />}     />
        <Route path="ws/admin-surfaces"   element={<AdminSurfacesPage />}   />
        <Route path="ws/certificates"     element={<CertificatesPage />}    />
        <Route path="ws/brand-monitoring" element={<BrandMonitoringPage />} />
        <Route path="ws/identity-assets"  element={<WorkspaceIdentityPage />} />
        <Route path="ws/reports"              element={<WorkspaceReportsPage />}        />
        <Route path="ws/executive-dashboard" element={<WorkspaceExecutiveDashboard />} />
        <Route path="ws/business-risk"       element={<WorkspaceBusinessRiskPage />}   />
        <Route path="ws/cyber-essentials"    element={<WorkspaceCyberEssentialsPage />} />
        <Route path="ws/supply-chain"         element={<WorkspaceSupplyChainPage />}      />
        <Route path="*"                   element={<Navigate to="/dashboard" replace />} />
      </Route>

      {/* Catch-all → login */}
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  )
}
