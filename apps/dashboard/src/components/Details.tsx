import { Link } from 'react-router';
import { useAuth } from '../auth/AuthProvider';
import { useResource } from '../hooks/useResource';
import { dateTime, label } from '../utils/format';
import { Modal } from './Modal';
import { Badge, KeyValues } from './UI';
import { ErrorState, LoadingState } from './States';
import { RiskMeter } from './AssessmentTable';
export function EventDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { api } = useAuth();
  const result = useResource('event:' + id, (signal) => api.event(id, signal));
  const event = result.data;
  return (
    <Modal
      wide
      title="Event inspection"
      description="Sanitized request and enforcement metadata from the event store."
      onClose={onClose}
    >
      {!!result.error && <ErrorState error={result.error} retry={result.refresh} />}{' '}
      {!event && result.loading && <LoadingState />}
      {event && (
        <>
          <div className="detail-banner">
            <Badge value={event.severity} />
            <span>{event.event_type}</span>
            <code>v{event.schema_version}</code>
          </div>
          <KeyValues
            values={[
              ['Event ID', <code>{event.event_id}</code>],
              ['Observed', dateTime(event.occurred_at)],
              ['Service', event.service],
              [
                'Request',
                <code>
                  {event.method} {event.endpoint}
                </code>,
              ],
              ['HTTP status', event.status_code],
              ['Duration', `${event.duration_ms.toFixed(2)} ms`],
              [
                'Request ID',
                <Link
                  className="mono"
                  to={'/events?request_id=' + event.request_id}
                  onClick={onClose}
                >
                  {event.request_id}
                </Link>,
              ],
              [
                'Client identifier',
                <Link
                  className="mono break"
                  to={'/clients?client=' + event.client_identifier}
                  onClick={onClose}
                >
                  {event.client_identifier}
                </Link>,
              ],
              ['Authentication', label(event.authentication_outcome)],
              ['Response completed', event.response_completed ? 'Yes' : 'No'],
              ['Security action', label(event.security_action)],
              ['Rule', event.rule_id],
              [
                'Counter / threshold',
                event.counter_value === null
                  ? 'Not applicable'
                  : `${event.counter_value} / ${event.threshold ?? '—'}`,
              ],
              [
                'Window',
                event.window_seconds === null ? 'Not applicable' : `${event.window_seconds}s`,
              ],
              [
                'Retry after',
                event.retry_after_seconds === null
                  ? 'Not applicable'
                  : `${event.retry_after_seconds}s`,
              ],
              ['Historical restriction expiry', dateTime(event.restriction_expires_at)],
              [
                'Degraded at observation',
                event.degraded === null ? 'Not applicable' : event.degraded ? 'Yes' : 'No',
              ],
            ]}
          />
          <div className="modal-actions">
            <Link
              className="button secondary"
              to={'/threats?event_id=' + event.event_id}
              onClick={onClose}
            >
              Related assessments
            </Link>
          </div>
        </>
      )}
    </Modal>
  );
}
export function AssessmentDetail({ id, onClose }: { id: string; onClose: () => void }) {
  const { api } = useAuth();
  const result = useResource('assessment:' + id, (signal) => api.assessment(id, signal));
  const assessment = result.data;
  return (
    <Modal
      wide
      title="Threat evidence"
      description="Persisted analysis, with deterministic and experimental signals kept separate."
      onClose={onClose}
    >
      {!!result.error && <ErrorState error={result.error} retry={result.refresh} />}{' '}
      {!assessment && result.loading && <LoadingState />}
      {assessment && (
        <>
          <div className="detail-banner">
            <RiskMeter score={assessment.risk_score} />
            <Badge value={assessment.severity} />
            <span>{assessment.service}</span>
          </div>
          <KeyValues
            values={[
              ['Assessment ID', <code>{assessment.assessment_id}</code>],
              ['Analyzed', dateTime(assessment.analyzed_at)],
              [
                'Event',
                <Link
                  className="mono"
                  to={'/events?event=' + assessment.event_id}
                  onClick={onClose}
                >
                  {assessment.event_id}
                </Link>,
              ],
              ['Rule version', assessment.rule_version],
              ['Feature schema', assessment.feature_schema],
              ['Model version', assessment.model_version ?? 'Not applied'],
              ['Aggregation', label(assessment.evidence.aggregation_status)],
              [
                'Client',
                <Link
                  className="mono break"
                  to={'/clients?client=' + assessment.client_identifier}
                  onClick={onClose}
                >
                  {assessment.client_identifier}
                </Link>,
              ],
            ]}
          />
          <h3 className="section-title">Risk contributions</h3>
          <div className="contribution-grid">
            {Object.entries(assessment.evidence.contributions ?? {}).map(([key, value]) => (
              <div key={key}>
                <span>{label(key)}</span>
                <strong>{value}</strong>
                <small>score contribution</small>
              </div>
            ))}
          </div>
          <h3 className="section-title">Classified evidence</h3>
          {(assessment.evidence.threats ?? []).length === 0 ? (
            <p className="muted">No threat was classified for this observation.</p>
          ) : (
            (assessment.evidence.threats ?? []).map((threat, index) => (
              <article className="evidence-card" key={index}>
                <div className="evidence-heading">
                  <h4>{label(threat.category)}</h4>
                  <Badge
                    value={
                      threat.detection_method === 'isolation_forest'
                        ? 'experimental'
                        : threat.severity
                    }
                  >
                    {threat.detection_method === 'isolation_forest'
                      ? 'Experimental ML'
                      : label(threat.detection_method)}
                  </Badge>
                </div>
                <div className="rule-list">
                  {threat.rule_ids.map((rule) => (
                    <code key={rule}>{rule}</code>
                  ))}
                </div>
                <KeyValues
                  values={Object.entries(threat.evidence)
                    .filter(
                      ([key, value]) => value !== null && value !== undefined && key !== 'flags',
                    )
                    .map(([key, value]) => [
                      label(key),
                      typeof value === 'boolean' ? (value ? 'Yes' : 'No') : String(value),
                    ])}
                />
                {threat.model_version && <small>Model {threat.model_version}</small>}
              </article>
            ))
          )}
          <h3 className="section-title">Statistical analysis</h3>
          <p className="muted">
            {label(assessment.evidence.statistics.status)} ·{' '}
            {assessment.evidence.statistics.baseline_windows ?? 0} baseline windows
          </p>
          {(assessment.evidence.statistics.flags ?? []).length > 0 && (
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Feature</th>
                    <th>Observed</th>
                    <th>Median</th>
                    <th>Scale</th>
                    <th>Robust z</th>
                  </tr>
                </thead>
                <tbody>
                  {(assessment.evidence.statistics.flags ?? []).map((flag) => (
                    <tr key={flag.rule_id}>
                      <td>
                        {label(flag.feature)}
                        <small>{flag.rule_id}</small>
                      </td>
                      <td>{flag.observed.toFixed(3)}</td>
                      <td>{flag.median.toFixed(3)}</td>
                      <td>{flag.scale.toFixed(3)}</td>
                      <td>{flag.robust_z.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="notice experimental">
            <div>
              <strong>Experimental ML evidence</strong>
              <p>
                Status: {label(assessment.evidence.ml.status)}
                {assessment.evidence.ml.anomaly_score !== null &&
                assessment.evidence.ml.anomaly_score !== undefined
                  ? ` · Anomaly score: ${assessment.evidence.ml.anomaly_score.toFixed(4)}`
                  : ''}
                . This score is not an attack probability. ML does not raise risk scores or
                automatically block traffic.
              </p>
            </div>
          </div>
        </>
      )}
    </Modal>
  );
}
