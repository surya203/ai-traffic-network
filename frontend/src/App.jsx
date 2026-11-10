import { Navigate, Route, Routes } from "react-router-dom"
import { useAuth } from "./auth/AuthProvider"
import { AppShell } from "./components/AppShell"
import { LoginPage } from "./pages/LoginPage"
import { RegisterPage } from "./pages/RegisterPage"
import { DashboardPage } from "./pages/DashboardPage"
import { UploadsPage } from "./pages/UploadsPage"
import { AlertsPage, InvestigationsPage, ReportsPage, ThreatsPage } from "./pages/RecordPages"
import { MapPage } from "./pages/MapPage"
import { SettingsPage } from "./pages/AccountPages"
import { AssistantPage } from "./pages/AssistantPage"

function Protected() {
  const { ready, session } = useAuth()
  if (!ready) return <p className="p-8 text-sm text-[#93a4c3]">Checking session…</p>
  if (!session) return <Navigate to="/login" replace />
  return <AppShell />
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route element={<Protected />}>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/uploads" element={<UploadsPage />} />
        <Route path="/investigations" element={<InvestigationsPage />} />
        <Route path="/threats" element={<ThreatsPage />} />
        <Route path="/map" element={<MapPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/assistant" element={<AssistantPage />} />
        <Route path="/settings" element={<SettingsPage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
