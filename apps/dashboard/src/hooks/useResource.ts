import { useCallback, useEffect, useRef, useState } from 'react';
import { isAbort } from '../api/http';
export function useResource<T>(
  key: string,
  load: (signal: AbortSignal) => Promise<T>,
  options: { pollMs?: number; enabled?: boolean } = {},
) {
  const loader = useRef(load);
  loader.current = load;
  const [retry, setRetry] = useState(0);
  const [state, setState] = useState<{
    key: string;
    data: T | null;
    error: unknown;
    loading: boolean;
    updatedAt: Date | null;
  }>({ key, data: null, error: null, loading: true, updatedAt: null });
  const lastKey = useRef(key);
  const enabled = options.enabled !== false;
  const pollMs = options.pollMs ?? 0;
  useEffect(() => {
    if (!enabled) {
      setState({ key, data: null, error: null, loading: false, updatedAt: null });
      return;
    }
    let disposed = false;
    let pending = false;
    let controller: AbortController | undefined;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const changed = key !== lastKey.current;
    lastKey.current = key;
    if (changed) setState({ key, data: null, error: null, loading: true, updatedAt: null });
    const run = async () => {
      if (pending || disposed) return;
      pending = true;
      controller = new AbortController();
      setState((old) => ({ ...old, loading: true, error: null }));
      try {
        const data = await loader.current(controller.signal);
        if (!disposed) setState({ key, data, error: null, loading: false, updatedAt: new Date() });
      } catch (error) {
        if (!disposed && !isAbort(error)) setState((old) => ({ ...old, error, loading: false }));
      } finally {
        pending = false;
        if (!disposed && pollMs)
          timer = setTimeout(() => {
            if (document.visibilityState === 'visible') void run();
            else schedule();
          }, pollMs);
      }
    };
    const schedule = () => {
      if (!disposed && pollMs)
        timer = setTimeout(() => {
          if (document.visibilityState === 'visible') void run();
          else schedule();
        }, pollMs);
    };
    const onVisible = () => {
      if (pollMs && document.visibilityState === 'visible') {
        clearTimeout(timer);
        void run();
      }
    };
    void run();
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      disposed = true;
      controller?.abort();
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [key, retry, enabled, pollMs]);
  const refresh = useCallback(() => setRetry((value) => value + 1), []);
  // Hide the previous query's snapshot during the render before effect cleanup.
  const visible =
    state.key === key && enabled
      ? state
      : { data: null, error: null, loading: enabled, updatedAt: null };
  return { ...visible, refresh };
}
