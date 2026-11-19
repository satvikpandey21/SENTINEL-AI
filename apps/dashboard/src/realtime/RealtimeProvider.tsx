import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useSyncExternalStore,
  type ReactNode,
} from 'react';
import type { Session } from '../auth/session';
import { SecurityStream } from './stream';
const Context = createContext<SecurityStream | null>(null);
export function RealtimeProvider({ session, children }: { session: Session; children: ReactNode }) {
  const stream = useMemo(() => new SecurityStream(session), [session]);
  useEffect(() => stream.start(), [stream]);
  return <Context.Provider value={stream}>{children}</Context.Provider>;
}
export function useRealtime() {
  const stream = useContext(Context);
  if (!stream) throw new Error('RealtimeProvider is required');
  const state = useSyncExternalStore(stream.subscribe, stream.getSnapshot);
  return { state, stream };
}
