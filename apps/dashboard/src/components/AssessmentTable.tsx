import { Link } from 'react-router';
import type { Assessment } from '../api/types';
import { Badge } from './UI';
import { compactId, dateTime, label } from '../utils/format';
export function RiskMeter({ score }: { score: number }) {
  return (
    <div className="risk-meter">
      <strong>
        {score.toFixed(0)}
        <small>/100</small>
      </strong>
      <span
        role="meter"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={score}
      >
        <i
          style={{ width: `${Math.min(100, Math.max(0, score))}%` }}
          className={
            score >= 75 ? 'critical' : score >= 50 ? 'high' : score >= 25 ? 'moderate' : 'low'
          }
        />
      </span>
    </div>
  );
}
export function AssessmentTable({
  assessments,
  onSelect,
}: {
  assessments: Assessment[];
  onSelect?: (assessment: Assessment) => void;
}) {
  return (
    <div className="table-scroll" tabIndex={0} role="region" aria-label="Threat assessments">
      <table>
        <thead>
          <tr>
            <th>Risk</th>
            <th>Severity</th>
            <th>Classification / method</th>
            <th>Client / service</th>
            <th>Analyzed</th>
            <th>
              <span className="sr-only">Details</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {assessments.map((assessment) => (
            <tr key={assessment.assessment_id}>
              <td>
                <RiskMeter score={assessment.risk_score} />
              </td>
              <td>
                <Badge value={assessment.severity} />
              </td>
              <td>
                {(assessment.evidence.threats ?? []).length ? (
                  (assessment.evidence.threats ?? []).slice(0, 2).map((threat) => (
                    <div className="threat-label" key={threat.category}>
                      <span>{label(threat.category)}</span>
                      <small
                        className={
                          threat.detection_method === 'isolation_forest' ? 'text-purple' : ''
                        }
                      >
                        {threat.detection_method === 'isolation_forest'
                          ? 'Experimental ML'
                          : label(threat.detection_method)}
                      </small>
                    </div>
                  ))
                ) : (
                  <span className="muted">No threat classified</span>
                )}
              </td>
              <td>
                <Link
                  className="mono"
                  to={'/clients?client=' + assessment.client_identifier}
                  title={assessment.client_identifier}
                >
                  {compactId(assessment.client_identifier)}
                </Link>
                <small>{assessment.service}</small>
              </td>
              <td>
                <time dateTime={assessment.analyzed_at}>{dateTime(assessment.analyzed_at)}</time>
              </td>
              <td>
                {onSelect ? (
                  <button
                    className="text-button"
                    aria-label={'Evidence for ' + assessment.assessment_id}
                    onClick={() => onSelect(assessment)}
                  >
                    Evidence<span className="sr-only"> for {assessment.assessment_id}</span>
                  </button>
                ) : (
                  <Link to={'/threats?assessment=' + assessment.assessment_id}>Evidence</Link>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
