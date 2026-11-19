import { useEffect, useRef, useState } from 'react';
import { useRealtime } from './RealtimeProvider';
/** Reconcile on every ready, including first connection, to close fetch/subscribe races. */
export function useLiveRefresh(refresh: () => void, automatic = false, assessments = false) {
  const { state } = useRealtime();
  const callback = useRef(refresh);
  callback.current = refresh;
  const version = assessments ? state.assessmentVersion : state.activityVersion;
  const [ack, setAck] = useState(version);
  useEffect(() => {
    if (state.resyncVersion) callback.current();
  }, [state.resyncVersion]);
  useEffect(() => {
    if (automatic && version) callback.current();
  }, [version, automatic]);
  return { pending: version > ack, acknowledge: () => setAck(version) };
}
export function NewActivity({
  pending,
  refresh,
  assessments = false,
}: {
  pending: boolean;
  refresh: () => void;
  assessments?: boolean;
}) {
  return pending ? (
    <div className="notice live-activity" role="status" aria-live="polite">
      <p>
        New {assessments ? 'assessments' : 'security activity'} available. Your investigation view
        is preserved.
      </p>
      <button className="button small secondary" onClick={refresh}>
        Refresh selected window
      </button>
    </div>
  ) : null;
}
