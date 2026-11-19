import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import { RealtimeProvider } from '../realtime/RealtimeProvider';
import { DashboardApi } from '../api/client';
import type { AuthState, Session } from './session';
type AuthValue = { state: AuthState; session: Session; api: DashboardApi };
const AuthContext = createContext<AuthValue | null>(null);
export function AuthProvider({ session, children }: { session: Session; children: ReactNode }) {
  const state = useSyncExternalStore(session.subscribe, session.getSnapshot);
  const api = useMemo(() => new DashboardApi(session), [session]);
  useEffect(() => {
    void session.start();
    return session.watchVisibility();
  }, [session]);
  return (
    <AuthContext.Provider value={{ state, session, api }}>
      <RealtimeProvider session={session}>{children}</RealtimeProvider>
    </AuthContext.Provider>
  );
}
export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error('AuthProvider is required');
  return value;
}
