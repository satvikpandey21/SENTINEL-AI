import { useState } from 'react';
import { Bell, Radio } from 'lucide-react';
import { Link } from 'react-router';
import { useRealtime } from './RealtimeProvider';
import { Badge } from '../components/UI';
import { Modal } from '../components/Modal';
import { dateTime, label } from '../utils/format';
const labels = {
  connected: 'Connected',
  connecting: 'Connecting',
  reconnecting: 'Reconnecting',
  disconnected: 'Disconnected',
  unavailable: 'Temporarily unavailable',
};
export function NotificationCenter() {
  const { state, stream } = useRealtime();
  const [open, setOpen] = useState(false);
  const unread = state.notices.filter((n) => !n.read).length;
  return (
    <div className="live-controls">
      <span
        className={'connection-status ' + state.status}
        role="status"
        aria-label={`Security stream: ${labels[state.status]}`}
        aria-live="polite"
        title={'Last activity: ' + dateTime(state.lastNotification)}
      >
        <Radio size={15} />
        <span>{labels[state.status]}</span>
      </span>
      <button
        className="button icon-only ghost notification-toggle"
        aria-label={`Notifications, ${unread} unread`}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen(true)}
      >
        <Bell size={19} />
        {unread > 0 && <span className="unread-count">{unread}</span>}
      </button>
      {open && (
        <Modal title="Security notifications" onClose={() => setOpen(false)}>
          <p className="muted">
            {labels[state.status]} · Last activity: {dateTime(state.lastNotification)}
          </p>
          <p className="data-note">
            Delivery hints are best effort. PostgreSQL-backed views contain historical records. Read
            state and history are local to this tab and cleared on sign-out. Background tabs keep
            receiving while online; browser suspension or disconnection can still lose hints.
          </p>
          <div className="notification-actions">
            <button className="button small secondary" onClick={stream.markRead}>
              Mark all as read
            </button>
            <button className="button small secondary" onClick={stream.clear}>
              Clear history
            </button>
            {state.status !== 'connected' && (
              <button className="button small secondary" onClick={stream.retry}>
                Retry connection
              </button>
            )}
          </div>
          <label className="notification-policy">
            <input
              type="checkbox"
              checked={state.includeInformational}
              onChange={(e) => stream.informational(e.target.checked)}
            />{' '}
            Include informational activity
          </label>
          <p className="data-note">
            Alerts show rate restrictions, authentication-failure evidence, and High/Critical risk.
            Identical categories per service and endpoint are grouped for 30 seconds. No routine
            popups. Informational opt-in applies to new activity; reconnecting or refreshing does
            not replay historical notifications.
          </p>
          <ul className="notification-list" aria-label="Recent security notifications">
            {!state.notices.length && (
              <li className="muted">No notifications received in this tab.</li>
            )}
            {state.notices.map((n) => (
              <li key={n.notification_id} className={n.read ? 'read' : 'unread'}>
                <div>
                  <Badge value={n.severity ?? 'neutral'}>
                    {n.actionable ? 'Alert' : 'Information'} · {n.severity ?? 'activity'}
                  </Badge>
                  {!n.read && <span className="muted">Unread</span>}
                </div>
                <strong>
                  {n.security_action
                    ? label(n.security_action)
                    : n.classifications.length
                      ? n.classifications.map(label).join(', ')
                      : 'Persisted API activity'}
                </strong>
                <code>
                  {n.service} · {n.endpoint}
                </code>
                <span className="muted">
                  HTTP {n.status_code}
                  {n.risk_score !== null ? ` · Risk ${n.risk_score}/100` : ''}
                </span>
                {n.experimental && (
                  <small>Includes experimental ML evidence; ML does not block requests.</small>
                )}
                <time dateTime={n.committed_at}>{dateTime(n.committed_at)}</time>
                <div>
                  <Link
                    to={'/events?event=' + n.event_id}
                    onClick={() => {
                      stream.markRead();
                      setOpen(false);
                    }}
                  >
                    Inspect event
                  </Link>
                  {n.assessment_id && (
                    <Link
                      to={'/threats?assessment=' + n.assessment_id}
                      onClick={() => {
                        stream.markRead();
                        setOpen(false);
                      }}
                    >
                      View assessment
                    </Link>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Modal>
      )}
    </div>
  );
}
