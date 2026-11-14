import { Navigate, Outlet, useLocation } from 'react-router';
import { useAuth } from './AuthProvider';
import { LoadingState } from '../components/States';
export function ProtectedRoute() {
  const { state } = useAuth();
  const location = useLocation();
  if (state.status === 'restoring')
    return (
      <div className="screen-center">
        <LoadingState label="Restoring secure session" />
      </div>
    );
  return state.status === 'authenticated' ? (
    <Outlet />
  ) : (
    <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />
  );
}
export function AdminRoute() {
  const { state } = useAuth();
  return state.account?.role === 'ADMIN' ? <Outlet /> : <Navigate to="/" replace />;
}
