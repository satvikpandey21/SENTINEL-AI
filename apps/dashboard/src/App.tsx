import { Component, lazy, Suspense, type ReactNode } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router';
import { AuthProvider } from './auth/AuthProvider';
import { ProtectedRoute, AdminRoute } from './auth/ProtectedRoute';
import type { Session } from './auth/session';
import { LoadingState } from './components/States';
import AppLayout from './layouts/AppLayout';
import LoginPage from './pages/LoginPage';
const Overview = lazy(() => import('./pages/OverviewPage'));
const Events = lazy(() => import('./pages/EventsPage'));
const Threats = lazy(() => import('./pages/ThreatsPage'));
const Clients = lazy(() => import('./pages/ClientsPage'));
const Policies = lazy(() => import('./pages/PoliciesPage'));
const Audit = lazy(() => import('./pages/AuditPage'));
const Settings = lazy(() => import('./pages/SettingsPage'));
class AppErrorBoundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() {
    return { failed: true };
  }
  render() {
    return this.state.failed ? (
      <div className="screen-center">
        <div className="state-box">
          <strong>The console could not render this view.</strong>
          <span>Reload the application to restore your session and try again.</span>
          <button className="button primary" onClick={() => window.location.reload()}>
            Reload console
          </button>
        </div>
      </div>
    ) : (
      this.props.children
    );
  }
}
export function AppRoutes() {
  return (
    <Suspense fallback={<LoadingState label="Opening workspace" />}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<AppLayout />}>
            <Route index element={<Overview />} />
            <Route path="events" element={<Events />} />
            <Route path="threats" element={<Threats />} />
            <Route path="clients" element={<Clients />} />
            <Route path="policies" element={<Policies />} />
            <Route path="settings" element={<Settings />} />
            <Route element={<AdminRoute />}>
              <Route path="audit" element={<Audit />} />
            </Route>
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Route>
      </Routes>
    </Suspense>
  );
}
export default function App({ session }: { session: Session }) {
  return (
    <AppErrorBoundary>
      <AuthProvider session={session}>
        <BrowserRouter>
          <AppRoutes />
        </BrowserRouter>
      </AuthProvider>
    </AppErrorBoundary>
  );
}
