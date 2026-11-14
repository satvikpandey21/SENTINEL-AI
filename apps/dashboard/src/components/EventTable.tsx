import { Link } from 'react-router';
import type { SecurityEvent } from '../api/types';
import { Badge } from './UI';
import { compactId, dateTime, label } from '../utils/format';
export function EventTable({
  events,
  onSelect,
  compact = false,
}: {
  events: SecurityEvent[];
  onSelect?: (event: SecurityEvent) => void;
  compact?: boolean;
}) {
  return (
    <div className="table-scroll" tabIndex={0} role="region" aria-label="Security events">
      <table>
        <thead>
          <tr>
            <th>Observed / service</th>
            <th>Request / endpoint</th>
            <th>Status</th>
            <th>Severity</th>
            {!compact && (
              <>
                <th>Decision</th>
                <th>Correlation</th>
                <th>Client</th>
              </>
            )}
            <th>
              <span className="sr-only">Details</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.event_id}>
              <td>
                <time dateTime={event.occurred_at}>{dateTime(event.occurred_at)}</time>
                <small>{event.service}</small>
              </td>
              <td>
                <span className="method">{event.method}</span>
                <code className="route">{event.endpoint}</code>
                <small>
                  {event.schema_version === 1 ? 'HTTP completion · v1' : 'Security decision · v2'}
                </small>
              </td>
              <td>
                <span className={event.status_code >= 400 ? 'status-error' : 'status-ok'}>
                  {event.status_code}
                </span>
              </td>
              <td>
                <Badge value={event.severity} />
              </td>
              {!compact && (
                <>
                  <td>
                    <span>{label(event.security_action)}</span>
                    <small>{event.rule_id ?? 'No decision emitted'}</small>
                  </td>
                  <td>
                    <Link
                      className="mono"
                      to={'/events?request_id=' + event.request_id}
                      title={event.request_id}
                    >
                      {compactId(event.request_id)}
                    </Link>
                  </td>
                  <td>
                    <Link
                      className="mono"
                      to={'/clients?client=' + event.client_identifier}
                      title={event.client_identifier}
                    >
                      {compactId(event.client_identifier)}
                    </Link>
                  </td>
                </>
              )}
              <td>
                {onSelect ? (
                  <button
                    className="text-button"
                    aria-label={'Inspect event ' + event.event_id}
                    onClick={() => onSelect(event)}
                  >
                    Inspect<span className="sr-only"> event {event.event_id}</span>
                  </button>
                ) : (
                  <Link to={'/events?request_id=' + event.request_id}>Inspect</Link>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
