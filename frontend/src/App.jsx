import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanDetail from './pages/ScanDetail'
import DomainHistory from './pages/DomainHistory'
import ScansPage from './pages/ScansPage'
import AssetsPage from './pages/AssetsPage'
import ReportsPage from './pages/ReportsPage'
import SchedulesPage from './pages/SchedulesPage'
import SettingsPage from './pages/SettingsPage'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard"               element={<Dashboard />}    />
          <Route path="scans"                   element={<ScansPage />}    />
          <Route path="scans/new"               element={<NewScan />}      />
          <Route path="scans/:id"               element={<ScanDetail />}   />
          <Route path="domain/:domain/history"  element={<DomainHistory />} />
          <Route path="assets"                  element={<AssetsPage />}   />
          <Route path="reports"                 element={<ReportsPage />}   />
          <Route path="schedules"              element={<SchedulesPage />} />
          <Route path="settings"               element={<SettingsPage />}  />
          <Route path="*"                       element={<Navigate to="/dashboard" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
